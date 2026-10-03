//! Outbox exporter (ADR 0053).
//!
//! Drains the store outbox in sequence order. For each event it builds a
//! ledger record, has it signed, writes it create-if-absent, and only then
//! acknowledges the event in the store. Every step is idempotent:
//!
//! * the record id and bytes are functions of the event, so a retry after a
//!   crash between write and ack finds identical bytes and just acks;
//! * different bytes under an existing id are quarantined, never overwritten,
//!   and the event stays pending (disclosure stays closed);
//! * an unavailable ledger is retried with bounded exponential backoff and
//!   then reported as deferred; nothing is acked and nothing is lost.
//!
//! The exporter reaches the store only through [`OutboxSource`]. It cannot
//! reserve, settle or run anything, so a retry never re-measures or charges
//! budget.

use std::sync::atomic::{AtomicU32, Ordering};

use custodian_contracts::types::DocumentDigest;
use custodian_corpus::registry::RegistryView;
use custodian_store::StoreError;
use sha2::{Digest, Sha256};

use crate::b64::hex;
use crate::backend::{BackendError, LedgerBackend, LedgerPath, PutOutcome};
use crate::keys::{Verifier, VerifyError};
use crate::record::{LedgerRecord, RecordError, SignedLedgerRecord};
use crate::signer::{ApprovedPayload, SignRefusal, Signer};
use crate::source::OutboxSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFaultPoint {
    /// After signing, before the ledger write.
    BeforeWrite,
    /// After the ledger write is durable, before the store ack. The crash
    /// window the design must survive.
    AfterWrite,
    /// After the store ack.
    AfterAck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportError {
    Source(StoreError),
    Sign(SignRefusal),
    Backend(BackendError),
    /// The exporter's own signature did not verify under its keyring
    /// (misconfigured key, wrong purpose, retired or revoked key).
    SelfCheck(VerifyError),
    Record(RecordError),
    /// The store holds a different export reference for this event.
    AckConflict,
    /// Fault injection (tests only).
    InjectedCrash(ExportFaultPoint),
}

impl ExportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Source(_) => "export_store_error",
            Self::Sign(r) => r.code(),
            Self::Backend(b) => b.code(),
            Self::SelfCheck(_) => "export_self_check_failed",
            Self::Record(r) => r.code(),
            Self::AckConflict => "export_ack_conflict",
            Self::InjectedCrash(_) => "export_injected_crash",
        }
    }
}

impl core::fmt::Display for ExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ExportError {}

pub trait ExportFault: Send + Sync {
    fn at(&self, point: ExportFaultPoint) -> Result<(), ExportError>;
}

pub struct NoExportFault;

impl ExportFault for NoExportFault {
    fn at(&self, _: ExportFaultPoint) -> Result<(), ExportError> {
        Ok(())
    }
}

/// Crash (return `InjectedCrash`) on the `nth` (1-based) time `point` is hit.
pub struct CrashOnce {
    point: ExportFaultPoint,
    remaining: AtomicU32,
    fired: AtomicU32,
}

impl CrashOnce {
    pub fn new(point: ExportFaultPoint) -> Self {
        Self::nth(point, 1)
    }

    pub fn nth(point: ExportFaultPoint, nth: u32) -> Self {
        Self {
            point,
            remaining: AtomicU32::new(nth.max(1)),
            fired: AtomicU32::new(0),
        }
    }

    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst) > 0
    }
}

impl ExportFault for CrashOnce {
    fn at(&self, point: ExportFaultPoint) -> Result<(), ExportError> {
        if point != self.point {
            return Ok(());
        }
        if self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.fired.fetch_add(1, Ordering::SeqCst);
            return Err(ExportError::InjectedCrash(point));
        }
        Ok(())
    }
}

pub trait Sleeper: Send + Sync {
    fn sleep(&self, secs: u64);
}

pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

/// Does not wait (tests, and callers that schedule retries themselves).
pub struct NoSleep;

impl Sleeper for NoSleep {
    fn sleep(&self, _: u64) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Backend attempts per write, including the first. At least 1.
    pub max_attempts: u32,
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_secs: 1,
            max_delay_secs: 60,
        }
    }
}

impl RetryPolicy {
    /// Deterministic exponential delay before retry number `n` (0-based).
    /// Callers that want jitter add it when scheduling the next run.
    pub fn delay(&self, n: u32) -> u64 {
        self.base_delay_secs
            .saturating_mul(1u64 << n.min(32))
            .min(self.max_delay_secs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExporterConfig {
    /// Events fetched from the outbox per round (1..=1000).
    pub batch: u32,
    pub retry: RetryPolicy,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            batch: 100,
            retry: RetryPolicy::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Created,
    /// Identical bytes, or the same record already stored under a signature
    /// that verifies (for example after a key rotation between retries).
    Identical,
    /// Different content under an existing id: the new bytes were placed in
    /// quarantine and nothing was overwritten.
    Quarantined {
        record_id: String,
    },
    /// The ledger stayed unavailable through every retry.
    Deferred {
        retry_after_secs: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportStatus {
    /// Every pending event was exported and acknowledged.
    Drained,
    /// The ledger was unavailable after retries. Events remain pending.
    Deferred { retry_after_secs: u64 },
    /// An event was refused or quarantined; later events were not attempted
    /// so the ledger keeps a gap-free prefix. Needs operator attention.
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReport {
    pub status: ExportStatus,
    /// Newly written and acked.
    pub exported: Vec<u64>,
    /// Already in the ledger with identical content; acked now.
    pub already_present: Vec<u64>,
    pub quarantined: Vec<(u64, String)>,
    pub refused: Vec<(u64, RecordError)>,
    /// Total backoff delay requested from the sleeper.
    pub backoff_secs: u64,
}

pub struct Exporter<'a> {
    pub(crate) backend: &'a dyn LedgerBackend,
    signer: &'a dyn Signer,
    pub(crate) verifier: &'a Verifier,
    cfg: ExporterConfig,
    sleeper: &'a dyn Sleeper,
    fault: &'a dyn ExportFault,
}

static NO_SLEEP: NoSleep = NoSleep;
static NO_FAULT: NoExportFault = NoExportFault;

fn quarantine_path(record_id: &str, bytes: &[u8]) -> Result<LedgerPath, BackendError> {
    LedgerPath::parse(&format!(
        "quarantine/{}/{}.json",
        record_id,
        hex(&Sha256::digest(bytes))
    ))
}

impl<'a> Exporter<'a> {
    pub fn new(
        backend: &'a dyn LedgerBackend,
        signer: &'a dyn Signer,
        verifier: &'a Verifier,
    ) -> Self {
        Self {
            backend,
            signer,
            verifier,
            cfg: ExporterConfig::default(),
            sleeper: &NO_SLEEP,
            fault: &NO_FAULT,
        }
    }

    pub fn with_config(mut self, cfg: ExporterConfig) -> Self {
        self.cfg = cfg;
        self
    }

    pub fn with_sleeper(mut self, sleeper: &'a dyn Sleeper) -> Self {
        self.sleeper = sleeper;
        self
    }

    pub fn with_fault(mut self, fault: &'a dyn ExportFault) -> Self {
        self.fault = fault;
        self
    }

    /// Run `op` against the backend, retrying retryable failures with
    /// backoff. `Ok(Err(delay))` means every attempt failed.
    fn with_backoff<T>(
        &self,
        backoff_total: &mut u64,
        mut op: impl FnMut() -> Result<T, BackendError>,
    ) -> Result<Result<T, u64>, ExportError> {
        let attempts = self.cfg.retry.max_attempts.max(1);
        for n in 0..attempts {
            match op() {
                Ok(v) => return Ok(Ok(v)),
                Err(e) if e.is_retryable() => {
                    if n + 1 < attempts {
                        let d = self.cfg.retry.delay(n);
                        *backoff_total = backoff_total.saturating_add(d);
                        self.sleeper.sleep(d);
                    }
                }
                Err(e) => return Err(ExportError::Backend(e)),
            }
        }
        Ok(Err(self.cfg.retry.delay(attempts)))
    }

    /// Sign and write one record, idempotently.
    pub fn write_record(&self, record: &LedgerRecord) -> Result<WriteOutcome, ExportError> {
        let mut backoff = 0;
        self.write_record_inner(record, &mut backoff)
    }

    fn write_record_inner(
        &self,
        record: &LedgerRecord,
        backoff: &mut u64,
    ) -> Result<WriteOutcome, ExportError> {
        let approved = ApprovedPayload::ledger_record(record).map_err(ExportError::Sign)?;
        let signature = self.signer.sign(&approved).map_err(ExportError::Sign)?;
        let signed = SignedLedgerRecord {
            payload: record.clone(),
            signature,
        };
        self.verifier
            .verify_ledger_record(&signed)
            .map_err(ExportError::SelfCheck)?;
        let bytes = signed.canonical_bytes().map_err(ExportError::Record)?;
        let path = LedgerPath::parse(&record.path()).map_err(ExportError::Backend)?;

        self.fault.at(ExportFaultPoint::BeforeWrite)?;
        let outcome = match self.with_backoff(backoff, || self.backend.put_new(&path, &bytes))? {
            Ok(o) => o,
            Err(retry_after_secs) => return Ok(WriteOutcome::Deferred { retry_after_secs }),
        };
        let result = match outcome {
            PutOutcome::Created => WriteOutcome::Created,
            PutOutcome::Identical => WriteOutcome::Identical,
            PutOutcome::Conflict => return self.resolve_conflict(record, &path, &bytes, backoff),
        };
        self.fault.at(ExportFaultPoint::AfterWrite)?;
        Ok(result)
    }

    /// Different bytes exist at this id. Same record under a different but
    /// valid signature (key rotation between retries) is idempotent success;
    /// anything else is quarantined.
    fn resolve_conflict(
        &self,
        record: &LedgerRecord,
        path: &LedgerPath,
        bytes: &[u8],
        backoff: &mut u64,
    ) -> Result<WriteOutcome, ExportError> {
        let existing = match self.with_backoff(backoff, || self.backend.get(path))? {
            Ok(Some(b)) => b,
            Ok(None) => return Err(ExportError::Backend(BackendError::Corrupt)),
            Err(retry_after_secs) => return Ok(WriteOutcome::Deferred { retry_after_secs }),
        };
        if let Ok(prior) = SignedLedgerRecord::decode_canonical(&existing) {
            if prior.payload == *record && self.verifier.verify_ledger_record(&prior).is_ok() {
                self.fault.at(ExportFaultPoint::AfterWrite)?;
                return Ok(WriteOutcome::Identical);
            }
        }
        let qpath = quarantine_path(&record.record_id, bytes).map_err(ExportError::Backend)?;
        match self.with_backoff(backoff, || self.backend.put_new(&qpath, bytes))? {
            Ok(_) => Ok(WriteOutcome::Quarantined {
                record_id: record.record_id.clone(),
            }),
            Err(retry_after_secs) => Ok(WriteOutcome::Deferred { retry_after_secs }),
        }
    }

    /// Export every pending outbox event and acknowledge it after its record
    /// is durable. Stops at the first event that cannot be exported.
    pub fn export_pending(
        &self,
        source: &dyn OutboxSource,
        now: u64,
    ) -> Result<ExportReport, ExportError> {
        let mut report = ExportReport {
            status: ExportStatus::Drained,
            exported: Vec::new(),
            already_present: Vec::new(),
            quarantined: Vec::new(),
            refused: Vec::new(),
            backoff_secs: 0,
        };
        let batch = self.cfg.batch.clamp(1, 1000);
        loop {
            let pending = source.pending(batch).map_err(ExportError::Source)?;
            if pending.is_empty() {
                return Ok(report);
            }
            for ev in &pending {
                let record = match LedgerRecord::audit_event(ev) {
                    Ok(r) => r,
                    Err(e) => {
                        report.refused.push((ev.seq, e));
                        report.status = ExportStatus::Blocked;
                        return Ok(report);
                    }
                };
                let mut backoff = report.backoff_secs;
                let outcome = self.write_record_inner(&record, &mut backoff)?;
                report.backoff_secs = backoff;
                match outcome {
                    WriteOutcome::Created => report.exported.push(ev.seq),
                    WriteOutcome::Identical => report.already_present.push(ev.seq),
                    WriteOutcome::Quarantined { record_id } => {
                        report.quarantined.push((ev.seq, record_id));
                        report.status = ExportStatus::Blocked;
                        return Ok(report);
                    }
                    WriteOutcome::Deferred { retry_after_secs } => {
                        report.status = ExportStatus::Deferred { retry_after_secs };
                        return Ok(report);
                    }
                }
                let export_ref = format!("ledger/{}", record.record_id);
                source.ack(ev.seq, &export_ref, now).map_err(|e| match e {
                    StoreError::IdentityConflict => ExportError::AckConflict,
                    other => ExportError::Source(other),
                })?;
                self.fault.at(ExportFaultPoint::AfterAck)?;
            }
        }
    }

    /// Record the store's current outbox position in the ledger. Returns the
    /// outcome, or `None` when the outbox is empty.
    pub fn record_store_checkpoint(
        &self,
        source: &dyn OutboxSource,
        now: u64,
    ) -> Result<Option<WriteOutcome>, ExportError> {
        let Some(cp) = source.latest_checkpoint().map_err(ExportError::Source)? else {
            return Ok(None);
        };
        let rec = LedgerRecord::store_checkpoint(&cp, now).map_err(ExportError::Record)?;
        self.write_record(&rec).map(Some)
    }

    /// Record the corpus registry head and event count. `None` for an empty
    /// registry.
    pub fn record_registry_checkpoint(
        &self,
        view: &RegistryView,
        now: u64,
    ) -> Result<Option<WriteOutcome>, ExportError> {
        if view.event_count() == 0 {
            return Ok(None);
        }
        let rec = LedgerRecord::registry_checkpoint(view.head(), view.event_count(), now)
            .map_err(ExportError::Record)?;
        self.write_record(&rec).map(Some)
    }

    /// Record an already-computed head (for callers without a registry view).
    pub fn record_registry_head(
        &self,
        head: &DocumentDigest,
        event_count: u64,
        now: u64,
    ) -> Result<WriteOutcome, ExportError> {
        let rec = LedgerRecord::registry_checkpoint(head, event_count, now)
            .map_err(ExportError::Record)?;
        self.write_record(&rec)
    }
}
