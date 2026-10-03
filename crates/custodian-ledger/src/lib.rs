//! Signed receipts, ledger record layout and idempotent private-ledger export
//! (C7).
//!
//! * [`domain`], [`signer`], [`keys`]: signing domains, the approved-payload
//!   gate, `Signer` implementations (software, remote/isolated) and a
//!   public-key-only [`keys::Verifier`] with key rotation and revocation.
//! * [`record`]: the closed, bounded, canonical ledger record layout.
//! * [`backend`], [`git`]: the create-if-absent storage port, an in-memory
//!   fake, and a conflict-aware local-Git backend.
//! * [`exporter`], [`reconcile`]: the outbox drain that acks only after a
//!   durable ledger write, backoff, quarantine, checkpoints, reconciliation.
//! * [`walk`], [`startup`]: whole-ledger verification and the startup /
//!   post-restore rollback check.
//!
//! Design: `docs/ledger.md` and ADRs 0050 to 0054. Status: implemented and
//! tested with synthetic data and test-generated keys; not deployed. The
//! private-ledger repository does not exist yet, no signing key exists, and
//! this crate holds no key material and no network code beyond invoking `git`
//! on a configured local clone.

#![forbid(unsafe_code)]

mod b64;
pub mod backend;
pub mod domain;
pub mod exporter;
pub mod git;
pub mod keys;
pub mod reconcile;
pub mod record;
pub mod signer;
pub mod source;
pub mod startup;
pub mod walk;

pub use backend::{BackendError, LedgerBackend, LedgerPath, MemoryBackend, PutOutcome};
pub use domain::SignDomain;
pub use exporter::{
    CrashOnce, ExportError, ExportFault, ExportFaultPoint, ExportReport, ExportStatus, Exporter,
    ExporterConfig, NoExportFault, NoSleep, RetryPolicy, Sleeper, ThreadSleeper, WriteOutcome,
};
pub use git::{GitBackend, GitConfig, HistoryViolation};
pub use keys::{KeyEntry, Keyring, KeyringError, Verifier, VerifyError};
pub use reconcile::ReconcileReport;
pub use record::{LedgerRecord, RecordBody, RecordError, RecordKind, SignedLedgerRecord};
pub use signer::{
    ApprovedPayload, RemoteSigner, SignRefusal, Signer, SignerService, SignerTransport,
    SoftwareSigner,
};
pub use source::OutboxSource;
pub use startup::{startup_check, StartupRefusal, StartupReport};
pub use walk::{walk_ledger, Finding, FindingCode, WalkReport};
