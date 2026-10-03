//! Release and query budgets, and the history of what past releases revealed
//! (C8, ADR 0060 to 0062).
//!
//! The store does not decide disclosure policy. It makes two things durable
//! and atomic:
//!
//! * **Charges.** One release or query attempt draws units from every budget
//!   scope it names (population, candidate lineage, requester) in one
//!   transaction: all scopes have room and are charged, or none is. A charge is
//!   final. There is no refund path: a withheld or failed attempt that got past
//!   validation has still shown the requester something about the system. The
//!   charge id makes a retry of the same attempt a replay, not a second charge.
//!   Each charge writes an outbox event, so the charge is exported to the
//!   private ledger like every other state change.
//! * **History.** An append-only, per-series list of what each release made
//!   public. The caller passes the sequence it read; an append after any
//!   concurrent append fails with [`StoreError::Conflict`], so two releases
//!   cannot both be checked against the same stale history.

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{BudgetKind, BudgetScope};
use custodian_contracts::MAX_DOCUMENT_BYTES;
use custodian_core::ActorId;
use rusqlite::OptionalExtension;
use serde_json::json;

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::model::BudgetStatus;
use crate::ops::{budget_scope_key, kind_str, scope_key_of};
use crate::outbox::outbox_append;
use crate::store::*;

const MAX_ID_LEN: usize = 128;

fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// One budget a release or query attempt draws on.
#[derive(Clone, Debug)]
pub enum ReleaseScope<'a> {
    /// A population-epoch or candidate-lineage scope (the same scope types as
    /// run budgets, under budget kind `release_query`).
    Budget(&'a BudgetScope),
    /// Everything one authenticated requester may ever draw.
    Requester(&'a str),
}

impl ReleaseScope<'_> {
    fn canonical(&self) -> Result<Vec<u8>, StoreError> {
        match self {
            Self::Budget(s) => Ok(to_canonical_bytes(*s)?),
            Self::Requester(actor) => {
                if !safe_id(actor) {
                    return Err(StoreError::InvalidInput);
                }
                Ok(to_canonical_bytes(
                    &json!({"scope": "requester", "actor": actor}),
                )?)
            }
        }
    }

    /// The budget scope key (`budgets.scope_key`).
    pub fn key(&self) -> Result<String, StoreError> {
        match self {
            Self::Budget(s) => budget_scope_key(BudgetKind::ReleaseQuery, s),
            Self::Requester(_) => Ok(scope_key_of(
                kind_str(BudgetKind::ReleaseQuery),
                &self.canonical()?,
            )),
        }
    }
}

/// A release or query attempt's charge.
#[derive(Clone, Debug)]
pub struct ReleaseCharge<'a> {
    /// Idempotency identity of the attempt. A retry reuses it.
    pub charge_id: &'a str,
    pub scopes: &'a [ReleaseScope<'a>],
    pub units: u64,
    pub actor: &'a ActorId,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChargeOutcome {
    /// Units were drawn from every scope.
    Charged,
    /// The same charge id was already recorded; nothing was drawn again.
    Replayed,
    /// At least one scope lacked room. Nothing was drawn. A denial is
    /// recorded in the outbox.
    Exhausted,
    /// At least one scope has no budget row. Nothing was drawn. Release
    /// budgets must be provisioned from a reviewed disclosure policy.
    NotProvisioned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisclosureHistoryEntry {
    pub seq: u64,
    pub release_id: String,
    pub payload: String,
    pub recorded_at: u64,
}

fn event_id(charge_id: &str, key: &str) -> String {
    format!("disclosure-charge:{charge_id}:{}", &key[..16])
}

impl SqliteStore {
    /// Provision or raise a release/query budget. Same rules as
    /// [`SqliteStore::provision_budget`]: a limit only rises and consumption
    /// is never reset.
    pub fn provision_release_budget(
        &self,
        scope: &ReleaseScope<'_>,
        limit: u64,
        actor: &ActorId,
        now: u64,
    ) -> Result<BudgetStatus, StoreError> {
        let bytes = scope.canonical()?;
        let key = scope.key()?;
        let json = String::from_utf8(bytes).map_err(|_| StoreError::InvalidInput)?;
        self.provision_raw(
            kind_str(BudgetKind::ReleaseQuery),
            &key,
            &json,
            limit,
            actor,
            now,
        )
    }

    pub fn release_budget_status(
        &self,
        scope: &ReleaseScope<'_>,
    ) -> Result<Option<BudgetStatus>, StoreError> {
        self.budget_status_by_key(&scope.key()?)
    }

    /// Check room in every scope and charge all of them in one transaction.
    pub fn charge_release_query(
        &self,
        charge: &ReleaseCharge<'_>,
    ) -> Result<ChargeOutcome, StoreError> {
        if !safe_id(charge.charge_id) || charge.units == 0 || charge.scopes.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let units = sql_time(charge.units)?;
        let now = sql_time(charge.now)?;
        let mut keys: Vec<String> = charge
            .scopes
            .iter()
            .map(ReleaseScope::key)
            .collect::<Result<_, _>>()?;
        keys.sort();
        keys.dedup();
        self.write(FaultOp::ChargeRelease, |tx| {
            let existing: Vec<(String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT scope_key, units FROM disclosure_charges WHERE charge_id = ?1 \
                     ORDER BY scope_key",
                )?;
                let rows = stmt.query_map([charge.charge_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            if !existing.is_empty() {
                let same = existing.len() == keys.len()
                    && existing
                        .iter()
                        .zip(&keys)
                        .all(|((k, u), want)| k == want && *u == units);
                return if same {
                    Ok(ChargeOutcome::Replayed)
                } else {
                    Err(StoreError::IdentityConflict)
                };
            }
            let mut room_ok = true;
            for key in &keys {
                let row: Option<(i64, i64, i64, String)> = tx
                    .query_row(
                        "SELECT limit_units, held_units, consumed_units, kind FROM budgets \
                         WHERE scope_key = ?1",
                        [key],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                match row {
                    Some((limit, held, consumed, kind)) if kind == "release_query" => {
                        if limit - held - consumed < units {
                            room_ok = false;
                        }
                    }
                    _ => return Ok(ChargeOutcome::NotProvisioned),
                }
            }
            if !room_ok {
                outbox_append(
                    tx,
                    &format!("disclosure-denied:{}", charge.charge_id),
                    "disclosure.denied",
                    None,
                    None,
                    &json!({
                        "event": "disclosure.denied", "kind": "release_query",
                        "units": units, "reason": "budget_exhausted",
                        "actor": charge.actor.as_str(), "at": now,
                    }),
                    now,
                )?;
                return Ok(ChargeOutcome::Exhausted);
            }
            for key in &keys {
                tx.execute(
                    "UPDATE budgets SET consumed_units = consumed_units + ?1 WHERE scope_key = ?2",
                    (units, key),
                )?;
                tx.execute(
                    "INSERT INTO disclosure_charges (charge_id, scope_key, units, actor, charged_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    (charge.charge_id, key, units, charge.actor.as_str(), now),
                )?;
                outbox_append(
                    tx,
                    &event_id(charge.charge_id, key),
                    "disclosure.charged",
                    None,
                    None,
                    &json!({
                        "event": "disclosure.charged", "scope_key": key,
                        "kind": "release_query", "units": units,
                        "actor": charge.actor.as_str(), "at": now,
                    }),
                    now,
                )?;
            }
            Ok(ChargeOutcome::Charged)
        })
    }

    /// True when the charge exists and every outbox event it wrote has been
    /// acknowledged as durably exported to the private ledger.
    pub fn charge_audit_exported(&self, charge_id: &str) -> Result<bool, StoreError> {
        if !safe_id(charge_id) {
            return Err(StoreError::InvalidInput);
        }
        self.read(|tx| {
            let keys: Vec<String> = {
                let mut stmt =
                    tx.prepare("SELECT scope_key FROM disclosure_charges WHERE charge_id = ?1")?;
                let rows = stmt.query_map([charge_id], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            if keys.is_empty() {
                return Ok(false);
            }
            for key in keys {
                let exported: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM outbox WHERE event_id = ?1 AND exported_at IS NOT NULL",
                    [event_id(charge_id, &key)],
                    |r| r.get(0),
                )?;
                if exported != 1 {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }

    /// Everything recorded for a series, oldest first.
    pub fn disclosure_history(
        &self,
        series_key: &str,
    ) -> Result<Vec<DisclosureHistoryEntry>, StoreError> {
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT seq, release_id, payload, recorded_at FROM disclosure_history \
                 WHERE series_key = ?1 ORDER BY seq",
            )?;
            let rows = stmt.query_map([series_key], |r| {
                Ok(DisclosureHistoryEntry {
                    seq: from_sql(r.get(0)?),
                    release_id: r.get(1)?,
                    payload: r.get(2)?,
                    recorded_at: from_sql(r.get(3)?),
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Append one entry after `expected_seq` (the highest sequence the caller
    /// read; 0 for an empty series). Returns the new sequence. A different
    /// highest sequence is [`StoreError::Conflict`]. Repeating an identical
    /// append (same release id and payload) returns the existing sequence.
    pub fn append_disclosure_history(
        &self,
        series_key: &str,
        expected_seq: u64,
        release_id: &str,
        payload: &str,
        now: u64,
    ) -> Result<u64, StoreError> {
        if !safe_id(series_key) || !safe_id(release_id) || payload.len() > MAX_DOCUMENT_BYTES {
            return Err(StoreError::InvalidInput);
        }
        let now = sql_time(now)?;
        let expected = sql_time(expected_seq)?;
        self.write(FaultOp::AppendDisclosureHistory, |tx| {
            let same: Option<(i64, String)> = tx
                .query_row(
                    "SELECT seq, payload FROM disclosure_history \
                     WHERE series_key = ?1 AND release_id = ?2",
                    (series_key, release_id),
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((seq, existing)) = same {
                return if existing == payload {
                    Ok(from_sql(seq))
                } else {
                    Err(StoreError::IdentityConflict)
                };
            }
            let head: i64 = tx.query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM disclosure_history WHERE series_key = ?1",
                [series_key],
                |r| r.get(0),
            )?;
            if head != expected {
                return Err(StoreError::Conflict);
            }
            tx.execute(
                "INSERT INTO disclosure_history (series_key, seq, release_id, payload, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (series_key, head + 1, release_id, payload, now),
            )?;
            Ok(from_sql(head + 1))
        })
    }
}
