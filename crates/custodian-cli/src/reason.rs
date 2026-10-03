//! Fixed reason codes and the stable exit-code classes.
//!
//! Every refusal the CLI can print is one of these variants. None carries a
//! path, a name, a digest, a worker message or any free text, so output built
//! from them cannot leak protected detail (CONVENTIONS.md, "Execution and
//! logging"). The exit code is a function of the class, and the classes are
//! part of the documented interface (docs/operator-runbook.md): changing a
//! class is a breaking change.

use custodian_contracts::BindingError;
use custodian_ledger::StartupRefusal;
use custodian_lifecycle::LifecycleReason;
use custodian_store::StoreError;

/// Exit-code classes. The numeric values are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExitClass {
    /// 0: the command did what was asked (or, with `--dry-run`, would have).
    Success,
    /// 1: an internal error. The command may or may not have taken effect;
    /// re-run status before retrying.
    Internal,
    /// 2: the command line or an input document is malformed.
    Usage,
    /// 3: the caller could not be authenticated.
    Unauthenticated,
    /// 4: the caller is authenticated but not permitted (role, separation of
    /// duties, automation identity).
    Forbidden,
    /// 5: a policy or state rule refused the request (stale policy, exhausted
    /// budget, already decided, blocked epoch, confirmation mismatch). A
    /// refusal changes nothing, except a recorded budget denial.
    Refused,
    /// 6: the named object does not exist (or is not visible to the caller).
    NotFound,
    /// 7: a dependency is unavailable (store busy, ledger, signer, feed
    /// destination). Nothing was changed; retrying may succeed.
    Unavailable,
    /// 8: an integrity or consistency check failed (verification findings,
    /// startup refusal, store awaiting reconciliation). Writes are refused
    /// until a human resolves it.
    Integrity,
}

impl ExitClass {
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Internal => 1,
            Self::Usage => 2,
            Self::Unauthenticated => 3,
            Self::Forbidden => 4,
            Self::Refused => 5,
            Self::NotFound => 6,
            Self::Unavailable => 7,
            Self::Integrity => 8,
        }
    }

    pub const ALL: [ExitClass; 9] = [
        Self::Success,
        Self::Internal,
        Self::Usage,
        Self::Unauthenticated,
        Self::Forbidden,
        Self::Refused,
        Self::NotFound,
        Self::Unavailable,
        Self::Integrity,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CliReason {
    // -- usage and input
    UsageError,
    InvalidDocument,
    DocumentTooLarge,
    ActorMismatch,
    ConfirmationMissing,
    // -- authentication and authorization
    Unauthenticated,
    OperatorPolicyInvalid,
    OperatorPolicyExpired,
    Forbidden,
    AgentNotPermitted,
    AutomationNotPermitted,
    SelfApproval,
    // -- refusals by rule
    ConfirmationMismatch,
    AlreadyDecided,
    IdempotencyConflict,
    BudgetExhausted,
    StalePolicy,
    PolicyNotCurrent,
    ApprovalExpired,
    ApprovalNotBound,
    EpochBlocked,
    NotClearable,
    InvalidChange,
    RotationInvalid,
    StoreBehindLedger,
    // -- lookup
    NotFound,
    // -- availability
    StoreUnavailable,
    LedgerUnavailable,
    SignerUnavailable,
    DestinationUnavailable,
    PendingObligations,
    FeedConflict,
    NotConfigured,
    // -- integrity
    StoreNeedsReconcile,
    LedgerUntrusted,
    StoreRolledBack,
    RegistryRolledBack,
    VerificationFailed,
    DestinationConflict,
    Unpublishable,
    // -- internal
    Internal,
}

impl CliReason {
    pub const ALL: [CliReason; 41] = [
        Self::UsageError,
        Self::InvalidDocument,
        Self::DocumentTooLarge,
        Self::ActorMismatch,
        Self::ConfirmationMissing,
        Self::Unauthenticated,
        Self::OperatorPolicyInvalid,
        Self::OperatorPolicyExpired,
        Self::Forbidden,
        Self::AgentNotPermitted,
        Self::AutomationNotPermitted,
        Self::SelfApproval,
        Self::ConfirmationMismatch,
        Self::AlreadyDecided,
        Self::IdempotencyConflict,
        Self::BudgetExhausted,
        Self::StalePolicy,
        Self::PolicyNotCurrent,
        Self::ApprovalExpired,
        Self::ApprovalNotBound,
        Self::EpochBlocked,
        Self::NotClearable,
        Self::InvalidChange,
        Self::RotationInvalid,
        Self::StoreBehindLedger,
        Self::NotFound,
        Self::StoreUnavailable,
        Self::LedgerUnavailable,
        Self::SignerUnavailable,
        Self::DestinationUnavailable,
        Self::PendingObligations,
        Self::FeedConflict,
        Self::NotConfigured,
        Self::StoreNeedsReconcile,
        Self::LedgerUntrusted,
        Self::StoreRolledBack,
        Self::RegistryRolledBack,
        Self::VerificationFailed,
        Self::DestinationConflict,
        Self::Unpublishable,
        Self::Internal,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::UsageError => "usage_error",
            Self::InvalidDocument => "invalid_document",
            Self::DocumentTooLarge => "document_too_large",
            Self::ActorMismatch => "actor_mismatch",
            Self::ConfirmationMissing => "confirmation_missing",
            Self::Unauthenticated => "unauthenticated",
            Self::OperatorPolicyInvalid => "operator_policy_invalid",
            Self::OperatorPolicyExpired => "operator_policy_expired",
            Self::Forbidden => "forbidden",
            Self::AgentNotPermitted => "agent_not_permitted",
            Self::AutomationNotPermitted => "automation_not_permitted",
            Self::SelfApproval => "self_approval",
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::AlreadyDecided => "already_decided",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::BudgetExhausted => "budget_exhausted",
            Self::StalePolicy => "stale_policy",
            Self::PolicyNotCurrent => "policy_not_current",
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalNotBound => "approval_not_bound",
            Self::EpochBlocked => "epoch_blocked",
            Self::NotClearable => "not_clearable",
            Self::InvalidChange => "invalid_change",
            Self::RotationInvalid => "rotation_invalid",
            Self::StoreBehindLedger => "store_behind_ledger",
            Self::NotFound => "not_found",
            Self::StoreUnavailable => "store_unavailable",
            Self::LedgerUnavailable => "ledger_unavailable",
            Self::SignerUnavailable => "signer_unavailable",
            Self::DestinationUnavailable => "destination_unavailable",
            Self::PendingObligations => "pending_obligations",
            Self::FeedConflict => "feed_conflict",
            Self::NotConfigured => "not_configured",
            Self::StoreNeedsReconcile => "store_needs_reconcile",
            Self::LedgerUntrusted => "ledger_untrusted",
            Self::StoreRolledBack => "store_rolled_back",
            Self::RegistryRolledBack => "registry_rolled_back",
            Self::VerificationFailed => "verification_failed",
            Self::DestinationConflict => "destination_conflict",
            Self::Unpublishable => "unpublishable",
            Self::Internal => "internal_error",
        }
    }

    pub fn class(self) -> ExitClass {
        use CliReason::*;
        match self {
            UsageError | InvalidDocument | DocumentTooLarge | ActorMismatch
            | ConfirmationMissing => ExitClass::Usage,
            Unauthenticated | OperatorPolicyInvalid | OperatorPolicyExpired => {
                ExitClass::Unauthenticated
            }
            Forbidden | AgentNotPermitted | AutomationNotPermitted | SelfApproval => {
                ExitClass::Forbidden
            }
            ConfirmationMismatch | AlreadyDecided | IdempotencyConflict | BudgetExhausted
            | StalePolicy | PolicyNotCurrent | ApprovalExpired | ApprovalNotBound
            | EpochBlocked | NotClearable | InvalidChange | RotationInvalid | StoreBehindLedger
            | PendingObligations => ExitClass::Refused,
            NotFound => ExitClass::NotFound,
            StoreUnavailable
            | LedgerUnavailable
            | SignerUnavailable
            | DestinationUnavailable
            | FeedConflict
            | NotConfigured => ExitClass::Unavailable,
            StoreNeedsReconcile | LedgerUntrusted | StoreRolledBack | RegistryRolledBack
            | VerificationFailed | DestinationConflict | Unpublishable => ExitClass::Integrity,
            Internal => ExitClass::Internal,
        }
    }

    pub fn exit_code(self) -> u8 {
        self.class().code()
    }
}

impl core::fmt::Display for CliReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CliReason {}

impl From<BindingError> for CliReason {
    fn from(e: BindingError) -> Self {
        use BindingError::*;
        match e {
            ApprovalNotYetValid | ApprovalExpired => Self::ApprovalExpired,
            StateStale => Self::StalePolicy,
            ActivationRevoked
            | ActivationSuperseded
            | ActivationNotYetActive
            | ActivationExpired
            | ActivationMismatch => Self::PolicyNotCurrent,
            ApproverNotPermitted => Self::AgentNotPermitted,
            _ => Self::ApprovalNotBound,
        }
    }
}

impl From<StoreError> for CliReason {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Binding(b) => b.into(),
            StoreError::IdempotencyConflict | StoreError::IdentityConflict => {
                Self::IdempotencyConflict
            }
            StoreError::AlreadyDecided => Self::AlreadyDecided,
            StoreError::SelfApproval => Self::SelfApproval,
            StoreError::EpochBlocked => Self::EpochBlocked,
            StoreError::NotFound => Self::NotFound,
            StoreError::NeedsReconcile => Self::StoreNeedsReconcile,
            StoreError::Contract(_) | StoreError::InvalidInput => Self::InvalidDocument,
            StoreError::Corrupt | StoreError::Invariant(_) => Self::VerificationFailed,
            StoreError::InvalidTransition | StoreError::LeaseLost | StoreError::RetryRefused => {
                Self::AlreadyDecided
            }
            StoreError::Busy | StoreError::Io | StoreError::Database | StoreError::Conflict => {
                Self::StoreUnavailable
            }
            _ => Self::StoreUnavailable,
        }
    }
}

impl From<LifecycleReason> for CliReason {
    fn from(e: LifecycleReason) -> Self {
        use LifecycleReason::*;
        match e {
            Unauthorized => Self::Forbidden,
            AgentNotPermitted => Self::AgentNotPermitted,
            UnknownEpoch => Self::NotFound,
            EpochMismatch | InvalidChange => Self::InvalidChange,
            NotClearable => Self::NotClearable,
            RotationInvalid => Self::RotationInvalid,
            InvalidInput => Self::InvalidDocument,
            IdempotencyConflict => Self::IdempotencyConflict,
            StoreUnavailable | RegistryUnavailable => Self::StoreUnavailable,
            FeedConflict => Self::FeedConflict,
            FeedNotInitialized => Self::NotConfigured,
            PendingObligations => Self::PendingObligations,
            Unpublishable => Self::Unpublishable,
            ClockSkew => Self::Internal,
            SigningRefused | SignerUnavailable => Self::SignerUnavailable,
            DestinationUnavailable => Self::DestinationUnavailable,
            DestinationConflict => Self::DestinationConflict,
            InjectedCrash => Self::Internal,
        }
    }
}

impl From<&StartupRefusal> for CliReason {
    fn from(e: &StartupRefusal) -> Self {
        match e {
            StartupRefusal::LedgerUnavailable => Self::LedgerUnavailable,
            StartupRefusal::LedgerUntrusted(_) => Self::LedgerUntrusted,
            StartupRefusal::StoreRolledBack => Self::StoreRolledBack,
            StartupRefusal::StoreBlocked => Self::StoreNeedsReconcile,
            StartupRefusal::RegistryRolledBack => Self::RegistryRolledBack,
            StartupRefusal::StoreError(s) => (*s).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_snake_case_and_exit_codes_are_stable() {
        let mut seen = std::collections::BTreeSet::new();
        for r in CliReason::ALL {
            assert!(seen.insert(r.code()), "{}", r.code());
            assert!(r
                .code()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!((1..=8).contains(&r.exit_code()));
        }
        let classes: Vec<u8> = ExitClass::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(classes, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
