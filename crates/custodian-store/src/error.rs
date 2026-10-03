//! Fixed-vocabulary store errors. No variant carries SQL text, paths, request
//! content or any input value, so an error can be logged or returned without
//! echoing protected or hostile data (CONVENTIONS.md, "Execution and logging").

use core::fmt;

use custodian_contracts::{BindingError, ContractError};
use custodian_core::ports::Refusal;
use custodian_core::ReasonCode;

use crate::fault::FaultPoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Another writer held the lock past the busy timeout. Nothing was
    /// changed; every operation is idempotent, so the caller may retry.
    Busy,
    /// Filesystem failure while preparing the database location.
    Io,
    /// Directory or file permissions are wider than owner-only, or the path
    /// is a symlink. The store refuses to open.
    Permissions,
    /// SQLite reported corruption or an integrity check failed.
    Corrupt,
    /// The file is not a custodian store.
    NotAStore,
    /// The database was written by a newer schema than this binary knows.
    SchemaTooNew,
    /// An applied migration's recorded checksum or order differs from this
    /// binary's. Possible tampering or a divergent build.
    MigrationChecksum,
    /// A migration failed and was rolled back.
    MigrationFailed,
    /// The store was found older than an externally held checkpoint (for
    /// example after a restore) and is blocked until reconciled.
    NeedsReconcile,
    /// A contract binding check failed (plan, approval, activation, ...).
    Binding(BindingError),
    /// A contract document failed validation or canonicalization.
    Contract(ContractError),
    /// Idempotency key reused with a different request.
    IdempotencyConflict,
    /// Request or approval identity reused with different content.
    IdentityConflict,
    NotFound,
    /// The caller does not hold the current lease (never acquired, expired,
    /// or fenced by cancellation or recovery).
    LeaseLost,
    /// The requested transition is not in the transition table, or a
    /// compare-and-swap lost against a concurrent change.
    InvalidTransition,
    /// A retry was refused: attempts exhausted or the prior attempt is not
    /// in a retryable state.
    RetryRefused,
    /// An append raced a concurrent writer (expected sequence changed).
    /// Nothing was written; re-read and decide again.
    Conflict,
    /// A write violated a database constraint (budget, append-only, ...).
    Constraint,
    /// An integrity invariant check failed; names the failed check.
    Invariant(&'static str),
    /// A value is outside the representable or allowed range.
    InvalidInput,
    /// The epoch the request draws on is contaminated, possibly changed or
    /// retired (C9). Nothing was changed.
    EpochBlocked,
    /// A submission already has a decision (approved elsewhere, approved
    /// before, or cancelled). Repeat approvals are refused, never re-applied.
    AlreadyDecided,
    /// The approver is the requester. Nobody approves their own request.
    SelfApproval,
    /// Dispatch refused: budget-affecting audit events are not yet
    /// acknowledged by the ledger export (R-2, ADR 0116). Nothing was
    /// changed; export, then retry. Never cleared by editing a budget.
    ExportPending,
    /// Fault injection fired (tests only; never produced without an injector).
    InjectedCrash(FaultPoint),
    /// Any other SQLite failure.
    Database,
}

impl StoreError {
    /// The fixed core reason code a refusal over the `StateStore` port carries.
    pub fn reason(&self) -> ReasonCode {
        match self {
            Self::Binding(BindingError::ApprovalExpired) => ReasonCode::AuthorizationExpired,
            Self::Binding(BindingError::PlanMismatch) | Self::IdempotencyConflict => {
                ReasonCode::PlanMismatch
            }
            Self::Binding(_) => ReasonCode::AuthorizationDenied,
            Self::InvalidTransition | Self::LeaseLost | Self::NotFound | Self::RetryRefused => {
                ReasonCode::InvalidTransition
            }
            Self::IdentityConflict => ReasonCode::DuplicateRequest,
            Self::EpochBlocked | Self::SelfApproval => ReasonCode::AuthorizationDenied,
            Self::AlreadyDecided => ReasonCode::DuplicateRequest,
            _ => ReasonCode::StoreUnavailable,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Busy => "store_busy",
            Self::Io => "store_io",
            Self::Permissions => "store_permissions",
            Self::Corrupt => "store_corrupt",
            Self::NotAStore => "store_not_a_store",
            Self::SchemaTooNew => "store_schema_too_new",
            Self::MigrationChecksum => "store_migration_checksum",
            Self::MigrationFailed => "store_migration_failed",
            Self::NeedsReconcile => "store_needs_reconcile",
            Self::Binding(_) => "store_binding_rejected",
            Self::Contract(_) => "store_contract_rejected",
            Self::IdempotencyConflict => "store_idempotency_conflict",
            Self::IdentityConflict => "store_identity_conflict",
            Self::NotFound => "store_not_found",
            Self::LeaseLost => "store_lease_lost",
            Self::InvalidTransition => "store_invalid_transition",
            Self::RetryRefused => "store_retry_refused",
            Self::Conflict => "store_conflict",
            Self::Constraint => "store_constraint",
            Self::Invariant(_) => "store_invariant",
            Self::InvalidInput => "store_invalid_input",
            Self::EpochBlocked => "store_epoch_blocked",
            Self::AlreadyDecided => "store_already_decided",
            Self::SelfApproval => "store_self_approval",
            Self::ExportPending => "store_export_pending",
            Self::InjectedCrash(_) => "store_injected_crash",
            Self::Database => "store_database",
        };
        f.write_str(s)
    }
}

impl std::error::Error for StoreError {}

impl From<StoreError> for Refusal {
    fn from(e: StoreError) -> Self {
        Refusal(e.reason())
    }
}

impl From<BindingError> for StoreError {
    fn from(e: BindingError) -> Self {
        Self::Binding(e)
    }
}

impl From<ContractError> for StoreError {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        use rusqlite::ffi::ErrorCode as C;
        match e.sqlite_error_code() {
            Some(C::DatabaseBusy | C::DatabaseLocked) => Self::Busy,
            Some(C::DatabaseCorrupt | C::NotADatabase) => Self::Corrupt,
            Some(C::ConstraintViolation) => Self::Constraint,
            _ => Self::Database,
        }
    }
}
