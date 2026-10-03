//! SQLite runtime store for the private custodian (C4).
//!
//! Implements transactional budgets, durable run state, leases, settlement
//! and the audit outbox behind the vendor-neutral `custodian_core` ports.
//! Policy lives in `custodian-core` and `custodian-contracts` (transition
//! table, refund rule, binding checks); this crate only makes it durable and
//! atomic. See `docs/state-store.md` for the schema, the accounting policy,
//! recovery and migration rules, and ADRs 0020 to 0022 for the decisions.
//!
//! Status: implemented and tested with synthetic data; not deployed. It
//! holds no protected data, no keys and no network code.

#![forbid(unsafe_code)]

pub mod clock;
mod disclosure;
pub mod error;
pub mod fault;
mod integrity;
mod lifecycle;
pub mod migrations;
pub mod model;
mod ops;
mod outbox;
mod port;
pub mod secure_fs;
mod store;

pub use clock::{Clock, ManualClock, SystemClock};
pub use disclosure::{ChargeOutcome, DisclosureHistoryEntry, ReleaseCharge, ReleaseScope};
pub use error::StoreError;
pub use fault::{CrashOnce, FaultInjector, FaultOp, FaultPhase, FaultPoint, NoFault};
pub use lifecycle::{
    EpochEventCommand, EpochEventOutcome, EpochEventRecord, EpochStandingRecord, FeedAppend,
    FeedEnvelopeRecord, FeedHead, ObligationAction, ObligationCommand, ObligationRecord,
    ObligationTarget, RotationCommand, PUBLIC_REASONS,
};
pub use model::{
    AckOutcome, AttemptRecord, BudgetStatus, Checkpoint, Lease, OutboxEvent, RecoveryReport,
    ReserveCommand, ReserveOutcome, RetryCommand, Settlement, StartCommand, TransitionRecord,
};
pub use ops::budget_scope_key;
pub use store::{SqliteStore, StoreConfig};
