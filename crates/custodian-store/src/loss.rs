//! Explicit acceptance of a restore loss (R-1, ADR 0130).
//!
//! A store restored from a backup older than the private ledger's checkpoint,
//! with no newer copy anywhere, is write-blocked and cannot be repaired from
//! inside: every state change is refused and `clear_reconcile` refuses while
//! the store is behind the ledger. This module is the one reviewed way out.
//! The rules, in the order they bind:
//!
//! 1. **Nothing is invented and nothing is lowered.** The store adopts the
//!    ledger's acknowledged audit tail as rows of its own outbox, byte for
//!    byte: every payload must hash to its recorded digest and every chain
//!    value must be the one the chain construction produces from the store's
//!    own last row. A tail that does not extend the store's chain (a diverged
//!    store, a forged tail) is refused and nothing is written.
//! 2. **Budgets only rise.** For each scope the ledger shows consumed, the
//!    store's consumed units are raised to the ledger's figure; a scope the
//!    ledger shows consumed beyond the limit saturates (no headroom, flagged),
//!    never exceeds it. A scope the store has never heard of is recorded and
//!    its budget, if ever provisioned, starts with those units consumed.
//! 3. **Standing only tightens.** Epoch standing is raised to what the ledger
//!    states (`Report` takes the maximum) and affected epochs are retired,
//!    through the same transaction and the same audited path as an ordinary
//!    change.
//! 4. **Audited and idempotent.** One `store.loss_accepted` event (and one
//!    `budget.recovered` event per scope) is written in the same transaction
//!    and exported like any other; the same plan again changes nothing.
//! 5. The write block is cleared in that same transaction, so there is no
//!    window in which the store is unblocked and unreconciled.
//!
//! What this cannot recover is stated in ADR 0130: spend that was never
//! exported, feed obligations (their targets are not in the ledger) and the
//! requests and attempts of the lost window (no rows are invented; the
//! budgets carry their cost).

use std::collections::BTreeMap;

use custodian_core::standing::EpochChange;
use custodian_core::{ActorId, Contamination, EpochStanding};
use rusqlite::OptionalExtension;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::lifecycle::{apply_epoch_change_tx, load_standing, EpochEventCommand};
use crate::migrations::hex;
use crate::outbox::{chain_of, outbox_append, GENESIS_CHAIN};
use crate::store::{sql_time, SqliteStore};

/// Most events one acceptance may adopt.
pub const MAX_ADOPTED_EVENTS: usize = 100_000;

/// One acknowledged ledger audit record, as the store needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LossEvent {
    pub seq: u64,
    pub event_id: String,
    pub kind: String,
    pub request_id: Option<String>,
    pub attempt_id: Option<String>,
    /// The store's payload text, reconstructed from the ledger record. It must
    /// hash to `payload_digest`.
    pub payload: String,
    pub payload_digest: String,
    pub chain: String,
    pub created_at: u64,
    /// `ledger/<record id>`: how the ledger acknowledges the event.
    pub export_ref: String,
}

/// What to do to one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LossEpoch {
    pub epoch_id: String,
    pub corpus_id: String,
    pub family_id: Option<String>,
    /// Raise the epoch to at least this contamination.
    pub floor: Option<Contamination>,
    /// Retire the epoch.
    pub retire: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct LossAcceptCommand<'a> {
    /// Digest of the plan the operator confirmed (`sha256:` plus 64 hex).
    pub plan_digest: &'a str,
    /// The ledger tail the store lacks, contiguous from the store's last
    /// sequence plus one.
    pub events: &'a [LossEvent],
    /// Consumed units per budget scope over the whole ledger.
    pub ledger_consumed: &'a BTreeMap<String, u64>,
    pub epochs: &'a [LossEpoch],
    pub actor: &'a ActorId,
    pub now: u64,
}

/// Why an acceptance was refused. Nothing was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LossRefusal {
    /// No events, too many, or a malformed digest.
    InvalidPlan,
    /// The tail does not start right after the store's last event.
    NotContiguous,
    /// A payload does not hash to its digest, or a chain value is not the one
    /// the store's own chain produces: the store and the ledger diverge.
    ChainMismatch,
    /// An adopted event id already exists in the store.
    EventConflict,
}

impl LossRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidPlan => "loss_invalid_plan",
            Self::NotContiguous => "loss_not_contiguous",
            Self::ChainMismatch => "loss_chain_mismatch",
            Self::EventConflict => "loss_event_conflict",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LossReport {
    pub acceptance_id: String,
    pub adopted_events: u64,
    pub from_seq: u64,
    pub to_seq: u64,
    pub recovered_scopes: u64,
    pub recovered_units: u64,
    pub saturated_scopes: u64,
    pub epochs_flagged: u64,
    pub epochs_retired: u64,
    /// The same plan was already accepted: nothing changed.
    pub replay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LossOutcome {
    Accepted(LossReport),
    Refused(LossRefusal),
}

/// A budget row as the operator tooling needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetOverview {
    pub scope_key: String,
    pub kind: String,
    pub scope_json: String,
    pub limit: u64,
    pub held: u64,
    pub consumed: u64,
}

fn is_sha256_token(s: &str) -> bool {
    s.len() == 71
        && s.strip_prefix("sha256:")
            .is_some_and(|h| h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn acceptance_id(plan_digest: &str) -> String {
    format!("lac_{}", &plan_digest[7..39])
}

fn from_i64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl SqliteStore {
    /// Every budget with its scope document and counters. Read-only.
    pub fn budgets_overview(&self) -> Result<Vec<BudgetOverview>, StoreError> {
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT scope_key, kind, scope_json, limit_units, held_units, consumed_units \
                 FROM budgets ORDER BY scope_key",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(BudgetOverview {
                    scope_key: r.get(0)?,
                    kind: r.get(1)?,
                    scope_json: r.get(2)?,
                    limit: from_i64(r.get(3)?),
                    held: from_i64(r.get(4)?),
                    consumed: from_i64(r.get(5)?),
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Whether this plan was already accepted. Read-only.
    pub fn loss_accepted(&self, plan_digest: &str) -> Result<bool, StoreError> {
        if !is_sha256_token(plan_digest) {
            return Err(StoreError::InvalidInput);
        }
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM loss_acceptances WHERE plan_digest = ?1",
                [plan_digest],
                |r| r.get(0),
            )?;
            Ok(n == 1)
        })
    }

    /// Accept the loss and continue (module documentation). Runs while the
    /// store is write-blocked: it is the audited way out, like
    /// [`SqliteStore::clear_reconcile`], and clears the block itself.
    pub fn accept_ledger_loss(
        &self,
        cmd: &LossAcceptCommand<'_>,
    ) -> Result<LossOutcome, StoreError> {
        if cmd.events.is_empty()
            || cmd.events.len() > MAX_ADOPTED_EVENTS
            || !is_sha256_token(cmd.plan_digest)
        {
            return Ok(LossOutcome::Refused(LossRefusal::InvalidPlan));
        }
        let now = sql_time(cmd.now)?;
        let actor = cmd.actor.as_str();
        let acc = acceptance_id(cmd.plan_digest);
        self.write(FaultOp::Reconcile, |tx| {
            // Replay: the same plan was accepted before.
            let prior: Option<(i64, i64, i64, i64, i64, i64)> = tx
                .query_row(
                    "SELECT adopted_events, ledger_from_seq, ledger_to_seq, recovered_scopes, \
                     recovered_units, store_seq_before FROM loss_acceptances \
                     WHERE plan_digest = ?1",
                    [cmd.plan_digest],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((events, from, to, scopes, units, _)) = prior {
                // A repeat also makes sure the block is clear: a crash cannot
                // leave the acceptance recorded and the block set, because
                // both commit together, but a manual block may have been set
                // since. It is not cleared by a replay.
                return Ok(LossOutcome::Accepted(LossReport {
                    acceptance_id: acc.clone(),
                    adopted_events: from_i64(events),
                    from_seq: from_i64(from),
                    to_seq: from_i64(to),
                    recovered_scopes: from_i64(scopes),
                    recovered_units: from_i64(units),
                    saturated_scopes: 0,
                    epochs_flagged: 0,
                    epochs_retired: 0,
                    replay: true,
                }));
            }

            // 1. The tail must extend the store's own chain, exactly.
            let (last_seq, last_chain): (i64, String) = tx
                .query_row(
                    "SELECT seq, chain FROM outbox ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .unwrap_or((0, GENESIS_CHAIN.to_owned()));
            let first = &cmd.events[0];
            if i64::try_from(first.seq).ok() != Some(last_seq + 1) {
                return Ok(LossOutcome::Refused(LossRefusal::NotContiguous));
            }
            let mut prev = last_chain;
            for (expected, e) in (last_seq + 1..).zip(cmd.events.iter()) {
                if i64::try_from(e.seq).ok() != Some(expected) {
                    return Ok(LossOutcome::Refused(LossRefusal::NotContiguous));
                }
                let digest = hex(&Sha256::digest(e.payload.as_bytes()));
                if digest != e.payload_digest || chain_of(&prev, expected, &digest) != e.chain {
                    return Ok(LossOutcome::Refused(LossRefusal::ChainMismatch));
                }
                prev.clone_from(&e.chain);
            }
            for e in cmd.events {
                let exists: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM outbox WHERE event_id = ?1",
                    [&e.event_id],
                    |r| r.get(0),
                )?;
                if exists != 0 {
                    return Ok(LossOutcome::Refused(LossRefusal::EventConflict));
                }
            }
            for e in cmd.events {
                tx.execute(
                    "INSERT INTO outbox (seq, event_id, kind, request_id, attempt_id, payload, \
                     payload_digest, chain, created_at, exported_at, export_ref) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    (
                        sql_time(e.seq)?,
                        &e.event_id,
                        &e.kind,
                        &e.request_id,
                        &e.attempt_id,
                        &e.payload,
                        &e.payload_digest,
                        &e.chain,
                        sql_time(e.created_at)?,
                        now,
                        &e.export_ref,
                    ),
                )?;
            }
            let to_seq = cmd.events[cmd.events.len() - 1].seq;

            // 2. Budgets only rise. Decide everything first, then write.
            struct Recovery {
                scope: String,
                units: u64,
                saturated: bool,
                on_row: bool,
            }
            let mut plan: Vec<Recovery> = Vec::new();
            for (scope, ledger_units) in cmd.ledger_consumed {
                let row: Option<(i64, i64, i64)> = tx
                    .query_row(
                        "SELECT limit_units, held_units, consumed_units FROM budgets \
                         WHERE scope_key = ?1",
                        [scope],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                match row {
                    Some((limit, held, consumed)) => {
                        let deficit = ledger_units.saturating_sub(from_i64(consumed));
                        if deficit == 0 {
                            continue;
                        }
                        let take = deficit.min(from_i64(limit - held - consumed));
                        plan.push(Recovery {
                            scope: scope.clone(),
                            units: take,
                            saturated: take < deficit,
                            on_row: true,
                        });
                    }
                    None => {
                        // Known to the ledger only: recorded, and applied when
                        // the budget is provisioned. Units an earlier
                        // acceptance already recorded for this scope count.
                        let already: i64 = tx.query_row(
                            "SELECT COALESCE(SUM(units), 0) FROM budget_recoveries \
                             WHERE scope_key = ?1",
                            [scope],
                            |r| r.get(0),
                        )?;
                        let deficit = ledger_units.saturating_sub(from_i64(already));
                        if deficit == 0 {
                            continue;
                        }
                        plan.push(Recovery {
                            scope: scope.clone(),
                            units: deficit,
                            saturated: false,
                            on_row: false,
                        });
                    }
                }
            }
            let recovered_scopes = plan.len() as u64;
            let recovered_units: u64 = plan.iter().map(|r| r.units).sum();
            let saturated_scopes = plan.iter().filter(|r| r.saturated).count() as u64;
            tx.execute(
                "INSERT INTO loss_acceptances (acceptance_id, plan_digest, store_seq_before, \
                 ledger_from_seq, ledger_to_seq, adopted_events, recovered_scopes, \
                 recovered_units, accepted_by, accepted_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                (
                    &acc,
                    cmd.plan_digest,
                    last_seq,
                    sql_time(first.seq)?,
                    sql_time(to_seq)?,
                    i64::try_from(cmd.events.len()).map_err(|_| StoreError::InvalidInput)?,
                    sql_time(recovered_scopes)?,
                    sql_time(recovered_units)?,
                    actor,
                    now,
                ),
            )?;
            for r in &plan {
                if r.on_row && r.units > 0 {
                    tx.execute(
                        "UPDATE budgets SET consumed_units = consumed_units + ?1 \
                         WHERE scope_key = ?2",
                        (sql_time(r.units)?, &r.scope),
                    )?;
                }
                tx.execute(
                    "INSERT INTO budget_recoveries (acceptance_id, scope_key, units, saturated) \
                     VALUES (?1, ?2, ?3, ?4)",
                    (&acc, &r.scope, sql_time(r.units)?, i64::from(r.saturated)),
                )?;
            }

            // 3. Standing only tightens.
            let mut flagged = 0u64;
            let mut retired = 0u64;
            for ep in cmd.epochs {
                let current =
                    load_standing(tx, &ep.epoch_id)?.map_or(EpochStanding::CLEAN, |c| c.standing);
                let auth_ref = format!("loss-accept:{acc}");
                if let Some(floor) = ep.floor {
                    if floor > Contamination::Unaffected && floor > current.contamination {
                        apply_epoch_change_tx(
                            tx,
                            &EpochEventCommand {
                                epoch_id: &ep.epoch_id,
                                corpus_id: &ep.corpus_id,
                                family_id: ep.family_id.as_deref(),
                                idempotency_key: &format!("loss-{acc}-{}-report", ep.epoch_id),
                                change: EpochChange::Report(floor),
                                reason: "restore_loss",
                                actor,
                                actor_kind: "human",
                                authorization_ref: &auth_ref,
                                now: cmd.now,
                            },
                        )?;
                        flagged += 1;
                    }
                }
                let after =
                    load_standing(tx, &ep.epoch_id)?.map_or(EpochStanding::CLEAN, |c| c.standing);
                if ep.retire && !after.retired {
                    apply_epoch_change_tx(
                        tx,
                        &EpochEventCommand {
                            epoch_id: &ep.epoch_id,
                            corpus_id: &ep.corpus_id,
                            family_id: ep.family_id.as_deref(),
                            idempotency_key: &format!("loss-{acc}-{}-retire", ep.epoch_id),
                            change: EpochChange::Retire,
                            reason: "restore_loss",
                            actor,
                            actor_kind: "human",
                            authorization_ref: &auth_ref,
                            now: cmd.now,
                        },
                    )?;
                    retired += 1;
                }
            }

            // 4. Audit, in the same transaction.
            for r in &plan {
                outbox_append(
                    tx,
                    &format!(
                        "budget-recovered:{acc}:{}",
                        &r.scope[..16.min(r.scope.len())]
                    ),
                    "budget.recovered",
                    None,
                    None,
                    &json!({
                        "event": "budget.recovered", "scope_key": r.scope,
                        "units": r.units, "saturated": i64::from(r.saturated),
                        "actor": actor, "at": now,
                    }),
                    now,
                )?;
            }
            outbox_append(
                tx,
                &format!("loss-accepted:{acc}"),
                "store.loss_accepted",
                None,
                None,
                &json!({
                    "event": "store.loss_accepted", "actor": actor, "at": now,
                    "adopted_from": first.seq, "adopted_to": to_seq,
                    "adopted_events": cmd.events.len(),
                    "recovered_scopes": recovered_scopes, "units": recovered_units,
                    "document_digest": cmd.plan_digest,
                }),
                now,
            )?;

            // 5. The block is cleared in the same transaction.
            tx.execute(
                "UPDATE meta SET value = '0' WHERE key = 'needs_reconcile'",
                [],
            )?;
            Ok(LossOutcome::Accepted(LossReport {
                acceptance_id: acc.clone(),
                adopted_events: cmd.events.len() as u64,
                from_seq: first.seq,
                to_seq,
                recovered_scopes,
                recovered_units,
                saturated_scopes,
                epochs_flagged: flagged,
                epochs_retired: retired,
                replay: false,
            }))
        })
    }
}
