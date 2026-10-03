//! Legacy consumption import (HG-3, ADR 0102, ADR 0115).
//!
//! The bridge's legacy importer produces immutable records saying how many
//! units each legacy scope consumed. This module writes those units into the
//! runtime budget store, and nothing else does. The rules, in the order they
//! bind:
//!
//! 1. It can only add. Consumed units rise by a non-negative amount; a limit
//!    may be raised to the declared legacy limit but never lowered; nothing is
//!    reset or refunded. A record that would lower anything is refused.
//! 2. All or none. One `BEGIN IMMEDIATE` transaction either applies every
//!    item of a call, or applies none and records a refusal in the outbox.
//! 3. Idempotent by `(import_id, record_digest)`. The same pair again changes
//!    nothing. The same id with other bytes is a conflict: refused, recorded.
//! 4. Ambiguity is consumption. The records already count ambiguous or silent
//!    legacy rows as consumed; a record that declares its budget exhausted
//!    (unknown or reached limit) leaves no headroom here either, even when the
//!    runtime budget was provisioned larger.
//! 5. A newer record for a known legacy scope applies only the difference to
//!    the one it supersedes. The budget row stays the only counter; the
//!    `budget_imports` table records what was added and why, and
//!    `verify_invariants` requires the two to agree.
//!
//! This crate does not decode legacy records (it does not depend on the
//! bridge). The operator CLI converts reviewed records into
//! [`LegacyImportItem`]s after the handoff gates have been checked.

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{BudgetKind, BudgetScope};
use custodian_core::ActorId;
use rusqlite::{OptionalExtension, Transaction};
use serde_json::json;

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::ops::{kind_str, provision_tx, scope_key_of};
use crate::outbox::outbox_append;
use crate::store::{sql_time, SqliteStore};

/// Most items one call may apply (the importer bounds an extract at 256).
pub const MAX_IMPORT_ITEMS: usize = 256;

/// One reviewed legacy record, reduced to what the store needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyImportItem {
    /// The importer's facts-only identity: `lgi_` plus 32 lowercase hex.
    pub import_id: String,
    /// `sha256:` plus 64 hex of the full canonical record. The same id with a
    /// different digest is a conflict.
    pub record_digest: String,
    /// The legacy scope's deterministic key (opaque here).
    pub source_scope_key: String,
    /// The custodian budget the units are recorded against (from the handoff
    /// entry). Imported consumption always lands in a `run` budget.
    pub scope: BudgetScope,
    /// The legacy scope's total consumed units, as the record states them.
    pub consumed: u64,
    /// The legacy limit, if stated.
    pub declared_limit: Option<u64>,
    /// The record says no headroom remains (unknown limit, or consumed at or
    /// over the limit).
    pub exhausted: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyImportCommand<'a> {
    pub items: &'a [LegacyImportItem],
    /// Digest of the reviewed handoff record the operator confirmed.
    pub handoff_digest: &'a str,
    /// Digest of the dry-run report the handoff binds to.
    pub report_digest: &'a str,
    pub actor: &'a ActorId,
    pub now: u64,
}

/// Why an import was refused. Fixed vocabulary; nothing else is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportRefusal {
    /// The same id arrived with different bytes.
    DigestConflict,
    /// A newer record would lower the consumed total of the one before it.
    WouldReduceConsumption,
    /// A newer record changes a stated legacy limit.
    WouldChangeLimit,
    /// The legacy scope is already bound to another custodian budget, or the
    /// custodian budget to another legacy scope.
    ScopeBindingConflict,
    /// The runtime budget has no room for the legacy units.
    ExceedsLimit,
    /// Two different items name one custodian budget in one call.
    DuplicateInBatch,
    /// An item is malformed (identity, digest, or scope shape).
    InvalidItem,
}

impl ImportRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::DigestConflict => "digest_conflict",
            Self::WouldReduceConsumption => "would_reduce_consumption",
            Self::WouldChangeLimit => "would_change_limit",
            Self::ScopeBindingConflict => "scope_binding_conflict",
            Self::ExceedsLimit => "exceeds_limit",
            Self::DuplicateInBatch => "duplicate_in_batch",
            Self::InvalidItem => "invalid_item",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// First record for a scope.
    pub created: usize,
    /// A newer record that added the difference to an earlier one.
    pub superseded: usize,
    /// The same id and digest were already applied: nothing changed.
    pub already_applied: usize,
    /// Units this call added to budgets, in total.
    pub applied_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    Applied(ImportReport),
    /// Nothing was applied. The refusal is recorded in the outbox.
    Refused {
        reason: ImportRefusal,
        import_id: String,
    },
}

fn is_sha256_token(s: &str) -> bool {
    s.len() == 71
        && s.strip_prefix("sha256:")
            .is_some_and(|h| h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn is_import_id(s: &str) -> bool {
    s.len() == 36
        && s.strip_prefix("lgi_")
            .is_some_and(|h| h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

struct Planned {
    item_index: usize,
    scope_key: String,
    scope_json: String,
    new_limit: i64,
    budget_exists: bool,
    delta: i64,
    topup: i64,
    supersedes: Option<String>,
}

enum Step {
    Noop,
    Apply(Planned),
    Refuse(ImportRefusal, String),
}

struct Latest {
    import_id: String,
    source_scope_key: String,
    legacy_units: i64,
    declared_limit: Option<i64>,
    exhausted: bool,
}

fn to_i64(v: u64) -> Result<i64, StoreError> {
    sql_time(v)
}

fn plan_item(
    tx: &Transaction<'_>,
    index: usize,
    item: &LegacyImportItem,
) -> Result<Step, StoreError> {
    let id = item.import_id.clone();
    let refuse = |r: ImportRefusal| Ok(Step::Refuse(r, id.clone()));
    if !is_import_id(&item.import_id)
        || !is_sha256_token(&item.record_digest)
        || item.source_scope_key.is_empty()
        || item.source_scope_key.len() > 600
        || (item.exhausted && item.declared_limit.is_some_and(|l| item.consumed < l))
    {
        return refuse(ImportRefusal::InvalidItem);
    }
    let consumed = to_i64(item.consumed)?;
    let declared = item.declared_limit.map(to_i64).transpose()?;

    if let Some(digest) = tx
        .query_row(
            "SELECT record_digest FROM budget_imports WHERE import_id = ?1",
            [&item.import_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        return if digest == item.record_digest {
            Ok(Step::Noop)
        } else {
            refuse(ImportRefusal::DigestConflict)
        };
    }

    let scope_bytes = to_canonical_bytes(&item.scope)?;
    let scope_key = scope_key_of(kind_str(BudgetKind::Run), &scope_bytes);
    let scope_json = String::from_utf8(scope_bytes).map_err(|_| StoreError::InvalidInput)?;

    // The legacy scope and the custodian budget are bound one to one.
    let other_target: i64 = tx.query_row(
        "SELECT COUNT(*) FROM budget_imports WHERE source_scope_key = ?1 AND scope_key <> ?2",
        (&item.source_scope_key, &scope_key),
        |r| r.get(0),
    )?;
    if other_target != 0 {
        return refuse(ImportRefusal::ScopeBindingConflict);
    }
    let latest: Option<Latest> = tx
        .query_row(
            "SELECT import_id, source_scope_key, legacy_units, declared_limit, exhausted \
             FROM budget_imports WHERE scope_key = ?1 AND import_id NOT IN \
             (SELECT supersedes FROM budget_imports WHERE supersedes IS NOT NULL)",
            [&scope_key],
            |r| {
                Ok(Latest {
                    import_id: r.get(0)?,
                    source_scope_key: r.get(1)?,
                    legacy_units: r.get(2)?,
                    declared_limit: r.get(3)?,
                    exhausted: r.get::<_, i64>(4)? != 0,
                })
            },
        )
        .optional()?;
    let (prior_units, supersedes) = match &latest {
        None => (0, None),
        Some(l) => {
            if l.source_scope_key != item.source_scope_key {
                return refuse(ImportRefusal::ScopeBindingConflict);
            }
            if consumed < l.legacy_units || (l.exhausted && !item.exhausted) {
                return refuse(ImportRefusal::WouldReduceConsumption);
            }
            if l.declared_limit.is_some() && l.declared_limit != declared {
                return refuse(ImportRefusal::WouldChangeLimit);
            }
            (l.legacy_units, Some(l.import_id.clone()))
        }
    };
    let delta = consumed - prior_units;

    let budget: Option<(i64, i64, i64)> = tx
        .query_row(
            "SELECT limit_units, held_units, consumed_units FROM budgets WHERE scope_key = ?1",
            [&scope_key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (budget_exists, new_limit, held, now_consumed) = match budget {
        None => {
            // A new budget is created at the declared limit, or exactly at
            // the consumed units when the record says nothing remains.
            let limit = if item.exhausted {
                consumed
            } else {
                declared.unwrap_or(consumed).max(consumed)
            };
            (false, limit, 0, 0)
        }
        Some((limit, held, cons)) => {
            let raised = match declared {
                Some(d) if !item.exhausted && d > limit => d,
                _ => limit,
            };
            (true, raised, held, cons)
        }
    };
    let headroom = new_limit - held - now_consumed;
    if delta > headroom {
        return refuse(ImportRefusal::ExceedsLimit);
    }
    // A budget the record declares exhausted keeps no headroom.
    let topup = if item.exhausted { headroom - delta } else { 0 };
    Ok(Step::Apply(Planned {
        item_index: index,
        scope_key,
        scope_json,
        new_limit,
        budget_exists,
        delta,
        topup,
        supersedes,
    }))
}

impl SqliteStore {
    /// Write reviewed legacy consumption into the runtime budget store, all
    /// or none, idempotently and monotonically (module documentation). Every
    /// applied item and every refusal is audited in the outbox, in the same
    /// transaction, so a restore behind the ledger is detected like any other
    /// state change and the dispatch gate stays closed until it is exported.
    pub fn apply_legacy_imports(
        &self,
        cmd: &LegacyImportCommand<'_>,
    ) -> Result<ImportOutcome, StoreError> {
        if cmd.items.is_empty()
            || cmd.items.len() > MAX_IMPORT_ITEMS
            || !is_sha256_token(cmd.handoff_digest)
            || !is_sha256_token(cmd.report_digest)
        {
            return Err(StoreError::InvalidInput);
        }
        let now_i = sql_time(cmd.now)?;
        let actor = cmd.actor.as_str();
        self.write(FaultOp::ApplyLegacyImport, |tx| {
            // Phase 1: decide everything without writing.
            let mut steps = Vec::with_capacity(cmd.items.len());
            let mut seen: Vec<(String, &LegacyImportItem)> = Vec::new();
            for (i, item) in cmd.items.iter().enumerate() {
                let key = to_canonical_bytes(&item.scope)
                    .map(|b| scope_key_of(kind_str(BudgetKind::Run), &b))?;
                if let Some((_, prev)) = seen.iter().find(|(k, _)| *k == key) {
                    if **prev != *item {
                        steps.push(Step::Refuse(
                            ImportRefusal::DuplicateInBatch,
                            item.import_id.clone(),
                        ));
                        break;
                    }
                    steps.push(Step::Noop);
                    continue;
                }
                seen.push((key, item));
                let step = plan_item(tx, i, item)?;
                let stop = matches!(step, Step::Refuse(..));
                steps.push(step);
                if stop {
                    break;
                }
            }
            if let Some(Step::Refuse(reason, import_id)) =
                steps.iter().find(|s| matches!(s, Step::Refuse(..)))
            {
                let digest = cmd
                    .items
                    .iter()
                    .find(|i| &i.import_id == import_id)
                    .map(|i| i.record_digest.as_str())
                    .filter(|d| is_sha256_token(d))
                    .unwrap_or(cmd.handoff_digest);
                let tag = digest.get(7..23).unwrap_or("-");
                let safe_id = if is_import_id(import_id) {
                    import_id.as_str()
                } else {
                    "invalid"
                };
                outbox_append(
                    tx,
                    &format!("import-refused:{safe_id}:{}:{tag}", reason.code()),
                    "budget.import_refused",
                    None,
                    None,
                    &json!({
                        "event": "budget.import_refused", "import_id": safe_id,
                        "reason": reason.code(), "document_digest": digest,
                        "handoff_digest": cmd.handoff_digest, "actor": actor, "at": now_i,
                    }),
                    now_i,
                )?;
                return Ok(ImportOutcome::Refused {
                    reason: *reason,
                    import_id: safe_id.to_owned(),
                });
            }

            // Phase 2: every item is acceptable; apply them all.
            let mut report = ImportReport::default();
            for step in steps {
                match step {
                    Step::Noop => report.already_applied += 1,
                    Step::Refuse(..) => return Err(StoreError::Corrupt),
                    Step::Apply(p) => {
                        let item = &cmd.items[p.item_index];
                        let applied = p.delta + p.topup;
                        let kind = kind_str(BudgetKind::Run);
                        if !p.budget_exists || p.new_limit_changed(tx)? {
                            provision_tx(
                                tx,
                                kind,
                                &p.scope_key,
                                &p.scope_json,
                                p.new_limit,
                                actor,
                                now_i,
                            )?;
                        }
                        let n = tx.execute(
                            "UPDATE budgets SET consumed_units = consumed_units + ?1 \
                             WHERE scope_key = ?2",
                            (applied, &p.scope_key),
                        )?;
                        if n != 1 {
                            return Err(StoreError::Corrupt);
                        }
                        tx.execute(
                            "INSERT INTO budget_imports (import_id, record_digest, \
                             source_scope_key, scope_key, legacy_units, applied_units, \
                             exhausted, declared_limit, supersedes, handoff_digest, \
                             report_digest, applied_by, applied_at) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                            (
                                &item.import_id,
                                &item.record_digest,
                                &item.source_scope_key,
                                &p.scope_key,
                                to_i64(item.consumed)?,
                                applied,
                                i64::from(item.exhausted),
                                item.declared_limit.map(to_i64).transpose()?,
                                &p.supersedes,
                                cmd.handoff_digest,
                                cmd.report_digest,
                                actor,
                                now_i,
                            ),
                        )?;
                        outbox_append(
                            tx,
                            &format!("import:{}", item.import_id),
                            "budget.imported",
                            None,
                            None,
                            &json!({
                                "event": "budget.imported", "import_id": item.import_id,
                                "scope_key": p.scope_key, "scope_kind": scope_kind(&item.scope),
                                "units": applied, "limit": p.new_limit,
                                "document_digest": item.record_digest,
                                "handoff_digest": cmd.handoff_digest,
                                "report_digest": cmd.report_digest,
                                "actor": actor, "at": now_i,
                            }),
                            now_i,
                        )?;
                        if p.supersedes.is_some() {
                            report.superseded += 1;
                        } else {
                            report.created += 1;
                        }
                        report.applied_units += u64::try_from(applied).unwrap_or(0);
                    }
                }
            }
            Ok(ImportOutcome::Applied(report))
        })
    }

    /// Units written into `scope`'s budget by legacy imports, and the number
    /// of import rows. Read-only.
    pub fn imported_units(&self, scope: &BudgetScope) -> Result<(u64, u64), StoreError> {
        let key = scope_key_of(kind_str(BudgetKind::Run), &to_canonical_bytes(scope)?);
        self.read(|tx| {
            let (units, rows): (i64, i64) = tx.query_row(
                "SELECT COALESCE(SUM(applied_units), 0), COUNT(*) FROM budget_imports \
                 WHERE scope_key = ?1",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((
                u64::try_from(units).unwrap_or(0),
                u64::try_from(rows).unwrap_or(0),
            ))
        })
    }
}

impl Planned {
    fn new_limit_changed(&self, tx: &Transaction<'_>) -> Result<bool, StoreError> {
        let cur: i64 = tx.query_row(
            "SELECT limit_units FROM budgets WHERE scope_key = ?1",
            [&self.scope_key],
            |r| r.get(0),
        )?;
        Ok(cur != self.new_limit)
    }
}

fn scope_kind(scope: &BudgetScope) -> &'static str {
    match scope {
        BudgetScope::PopulationEpoch { .. } => "population_epoch",
        BudgetScope::CandidateLineageEpoch { .. } => "candidate_lineage_epoch",
    }
}
