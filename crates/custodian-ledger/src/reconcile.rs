//! Outbox-versus-ledger reconciliation (ADR 0053).
//!
//! Compares every outbox event with the ledger and reports four conditions:
//! events the store believes exported but the ledger lacks, events the ledger
//! holds but the store still lists as pending (crash between write and ack),
//! ledger records whose content differs from the store's event, and the
//! consistent remainder. With `repair`, the first two are fixed by the same
//! idempotent steps the exporter uses (re-write identical bytes; ack). A
//! conflicting record is never repaired automatically.

use custodian_store::OutboxEvent;

use crate::backend::LedgerPath;
use crate::exporter::{ExportError, Exporter, WriteOutcome};
use crate::record::{LedgerRecord, ReconcileOutcome, ReconciliationBody, SignedLedgerRecord};
use crate::source::OutboxSource;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileReport {
    pub outcome: ReconcileOutcome,
    pub store_events: u64,
    /// Acknowledged in the store, absent from the ledger.
    pub missing_in_ledger: Vec<u64>,
    /// Present in the ledger, still pending in the store.
    pub unacked_in_ledger: Vec<u64>,
    /// Ledger record exists but differs from (or cannot be derived from) the
    /// store event, or its signature does not verify.
    pub conflicting: Vec<u64>,
    pub repaired: Vec<u64>,
}

impl Exporter<'_> {
    /// Reconcile the whole outbox against the ledger. When `record_outcome`
    /// is set, a reconciliation record is appended to the ledger (its id is
    /// derived from `now` and the counts, so a repeat is idempotent).
    pub fn reconcile(
        &self,
        source: &dyn OutboxSource,
        now: u64,
        repair: bool,
        record_outcome: bool,
    ) -> Result<ReconcileReport, ExportError> {
        self.backend.refresh().map_err(ExportError::Backend)?;
        let last = source
            .latest_checkpoint()
            .map_err(ExportError::Source)?
            .map_or(0, |c| c.seq);
        let mut report = ReconcileReport {
            outcome: ReconcileOutcome::Consistent,
            store_events: 0,
            missing_in_ledger: Vec::new(),
            unacked_in_ledger: Vec::new(),
            conflicting: Vec::new(),
            repaired: Vec::new(),
        };
        let mut ledger_records = 0u64;
        for seq in 1..=last {
            let Some(ev) = source.event(seq).map_err(ExportError::Source)? else {
                continue;
            };
            report.store_events += 1;
            let Ok(expected) = LedgerRecord::audit_event(&ev) else {
                report.conflicting.push(seq);
                continue;
            };
            let path = LedgerPath::parse(&expected.path()).map_err(ExportError::Backend)?;
            match self.backend.get(&path).map_err(ExportError::Backend)? {
                Some(bytes) => {
                    ledger_records += 1;
                    let matches = SignedLedgerRecord::decode_canonical(&bytes)
                        .ok()
                        .is_some_and(|r| {
                            r.payload == expected && self.verifier.verify_ledger_record(&r).is_ok()
                        });
                    if !matches {
                        report.conflicting.push(seq);
                    } else if ev.exported_at.is_none() {
                        report.unacked_in_ledger.push(seq);
                        if repair {
                            self.ack_for(source, &ev, &expected, now)?;
                            report.repaired.push(seq);
                        }
                    }
                }
                None => {
                    if ev.exported_at.is_some() {
                        report.missing_in_ledger.push(seq);
                        if repair {
                            match self.write_record(&expected)? {
                                WriteOutcome::Created | WriteOutcome::Identical => {
                                    report.repaired.push(seq);
                                }
                                WriteOutcome::Quarantined { .. } => report.conflicting.push(seq),
                                WriteOutcome::Deferred { .. } => {}
                            }
                        }
                    }
                }
            }
        }
        let unresolved = |all: &[u64]| all.iter().any(|s| !report.repaired.contains(s));
        report.outcome = if !report.conflicting.is_empty()
            || unresolved(&report.missing_in_ledger)
            || unresolved(&report.unacked_in_ledger)
        {
            ReconcileOutcome::Divergent
        } else if !report.repaired.is_empty() {
            ReconcileOutcome::Repaired
        } else {
            ReconcileOutcome::Consistent
        };
        if record_outcome {
            let body = ReconciliationBody {
                outcome: report.outcome,
                store_events: report.store_events,
                ledger_records,
                missing_in_ledger: report.missing_in_ledger.len() as u64,
                unacked_in_ledger: report.unacked_in_ledger.len() as u64,
                conflicting: report.conflicting.len() as u64,
            };
            let rec = LedgerRecord::reconciliation(body, now).map_err(ExportError::Record)?;
            self.write_record(&rec)?;
        }
        Ok(report)
    }

    fn ack_for(
        &self,
        source: &dyn OutboxSource,
        ev: &OutboxEvent,
        record: &LedgerRecord,
        now: u64,
    ) -> Result<(), ExportError> {
        source
            .ack(ev.seq, &format!("ledger/{}", record.record_id), now)
            .map(|_| ())
            .map_err(|e| match e {
                custodian_store::StoreError::IdentityConflict => ExportError::AckConflict,
                other => ExportError::Source(other),
            })
    }
}
