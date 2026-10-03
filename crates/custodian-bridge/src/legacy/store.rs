//! Applying import records to an import store, idempotently and monotonically.
//!
//! Records are immutable. Importing the same record again changes nothing.
//! A record for a scope that already has one is accepted only if it cannot
//! reset anything: consumption does not go down, the limit does not change,
//! a contamination mark is not dropped, the independence statement is not
//! changed or removed, and the budget semantics do not change. It is then
//! stored as a new record linked to the one it supersedes; the older record is
//! kept.
//!
//! The store is a port. The in-memory implementation is for tests and for the
//! dry-run tooling. Writing consumed units into the runtime budget store is
//! part of the reviewed cutover, which this crate does not perform (ADR 0092).

use std::collections::BTreeMap;

use super::import::{ContaminationStanding, ImportId, LegacyImportRecord, ScopeKey};

pub trait ImportStore {
    fn contains(&self, id: &ImportId) -> bool;
    /// The newest record for a scope.
    fn latest(&self, key: &ScopeKey) -> Option<LegacyImportRecord>;
    /// Append a record. Never replaces or removes one.
    fn insert(&mut self, record: LegacyImportRecord, supersedes: Option<ImportId>);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredImport {
    pub record: LegacyImportRecord,
    pub supersedes: Option<ImportId>,
}

#[derive(Default)]
pub struct MemoryImportStore {
    rows: Vec<StoredImport>,
    latest: BTreeMap<ScopeKey, usize>,
}

impl MemoryImportStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn rows(&self) -> &[StoredImport] {
        &self.rows
    }
}

impl ImportStore for MemoryImportStore {
    fn contains(&self, id: &ImportId) -> bool {
        self.rows.iter().any(|r| r.record.import_id == *id)
    }
    fn latest(&self, key: &ScopeKey) -> Option<LegacyImportRecord> {
        self.latest.get(key).map(|i| self.rows[*i].record.clone())
    }
    fn insert(&mut self, record: LegacyImportRecord, supersedes: Option<ImportId>) {
        let key = record.body.scope_key.clone();
        self.rows.push(StoredImport { record, supersedes });
        self.latest.insert(key, self.rows.len() - 1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApplyRefusal {
    /// Would lower consumed units: a spent attempt would be forgotten.
    WouldReduceConsumption,
    WouldChangeLimit,
    /// Would drop a contamination mark.
    WouldClearContamination,
    /// Would change or remove the legacy independence statement.
    WouldChangeIndependence,
    /// Would change the budget semantics of a scope.
    WouldChangeScopeKind,
    /// Two different records for one scope in a single call.
    DuplicateInBatch,
}

impl ApplyRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::WouldReduceConsumption => "would_reduce_consumption",
            Self::WouldChangeLimit => "would_change_limit",
            Self::WouldClearContamination => "would_clear_contamination",
            Self::WouldChangeIndependence => "would_change_independence",
            Self::WouldChangeScopeKind => "would_change_scope_kind",
            Self::DuplicateInBatch => "duplicate_in_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Created,
    AlreadyImported,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyReport {
    pub created: usize,
    pub already_imported: usize,
    pub superseded: usize,
}

fn check_monotone(old: &LegacyImportRecord, new: &LegacyImportRecord) -> Result<(), ApplyRefusal> {
    let (o, n) = (&old.body, &new.body);
    if o.budget.scope_kind != n.budget.scope_kind
        || o.scope != n.scope
        || o.lifecycle != n.lifecycle
    {
        return Err(ApplyRefusal::WouldChangeScopeKind);
    }
    if n.budget.consumed < o.budget.consumed {
        return Err(ApplyRefusal::WouldReduceConsumption);
    }
    if o.budget.limit.is_some() && o.budget.limit != n.budget.limit {
        return Err(ApplyRefusal::WouldChangeLimit);
    }
    if matches!(o.contamination, ContaminationStanding::Contaminated { .. })
        && !matches!(n.contamination, ContaminationStanding::Contaminated { .. })
    {
        return Err(ApplyRefusal::WouldClearContamination);
    }
    if let Some(oi) = &o.independence {
        match &n.independence {
            Some(ni) if ni.claim == oi.claim => {}
            _ => return Err(ApplyRefusal::WouldChangeIndependence),
        }
    }
    Ok(())
}

/// Apply all records or none: every record is checked against the store (and
/// the earlier records of the same call) before anything is written.
pub fn apply(
    records: &[LegacyImportRecord],
    store: &mut dyn ImportStore,
) -> Result<ApplyReport, ApplyRefusal> {
    let mut plan: Vec<(&LegacyImportRecord, Option<ImportId>, ApplyOutcome)> = Vec::new();
    let mut seen: BTreeMap<&ScopeKey, &ImportId> = BTreeMap::new();
    for r in records {
        if seen
            .insert(&r.body.scope_key, &r.import_id)
            .is_some_and(|prev| *prev != r.import_id)
        {
            return Err(ApplyRefusal::DuplicateInBatch);
        }
        if store.contains(&r.import_id) {
            plan.push((r, None, ApplyOutcome::AlreadyImported));
            continue;
        }
        match store.latest(&r.body.scope_key) {
            None => plan.push((r, None, ApplyOutcome::Created)),
            Some(old) => {
                check_monotone(&old, r)?;
                plan.push((r, Some(old.import_id), ApplyOutcome::Superseded));
            }
        }
    }
    let mut report = ApplyReport {
        created: 0,
        already_imported: 0,
        superseded: 0,
    };
    for (r, sup, outcome) in plan {
        match outcome {
            ApplyOutcome::AlreadyImported => report.already_imported += 1,
            ApplyOutcome::Created => {
                store.insert(r.clone(), None);
                report.created += 1;
            }
            ApplyOutcome::Superseded => {
                store.insert(r.clone(), sup);
                report.superseded += 1;
            }
        }
    }
    Ok(report)
}
