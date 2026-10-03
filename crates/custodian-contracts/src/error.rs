//! Fixed-vocabulary errors. No variant carries input text, so an error can be
//! logged or returned without echoing a hostile or protected payload.

use core::fmt;

/// Failure to parse, bound or canonicalize a contract document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContractError {
    /// The payload exceeds `MAX_DOCUMENT_BYTES`.
    Oversized,
    /// Not valid JSON for the expected type (includes unknown fields,
    /// duplicate fields, wrong schema tag, wrong type).
    Malformed,
    /// A field is outside its allowlisted shape or bound.
    FieldRejected,
    /// A value cannot be canonically encoded (float, null, non-ASCII, ...).
    NotCanonicalizable,
    /// The bytes parse but are not byte-identical to the canonical encoding.
    NonCanonical,
    /// Cross-field consistency inside one document failed.
    Inconsistent,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Oversized => "contract_oversized",
            Self::Malformed => "contract_malformed",
            Self::FieldRejected => "contract_field_rejected",
            Self::NotCanonicalizable => "contract_not_canonicalizable",
            Self::NonCanonical => "contract_non_canonical",
            Self::Inconsistent => "contract_inconsistent",
        })
    }
}

impl std::error::Error for ContractError {}

/// A document is well formed but does not bind to the thing it is being used
/// for. Every variant is a rejection; there is no "warning".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingError {
    RequestMismatch,
    PlanMismatch,
    CandidateMismatch,
    DomainMismatch,
    PopulationMismatch,
    BudgetScopeMismatch,
    ReservationMismatch,
    ExecutionMismatch,
    ProjectionMismatch,
    PolicyMismatch,
    OperationMismatch,
    ActivationMismatch,
    ActivationSuperseded,
    ActivationNotYetActive,
    ActivationExpired,
    ActivationRevoked,
    /// The activation state used for the check is older than allowed.
    StateStale,
    ApprovalNotYetValid,
    ApprovalExpired,
    ApproverNotPermitted,
    NotReleasable,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RequestMismatch => "request_mismatch",
            Self::PlanMismatch => "plan_mismatch",
            Self::CandidateMismatch => "candidate_mismatch",
            Self::DomainMismatch => "domain_mismatch",
            Self::PopulationMismatch => "population_mismatch",
            Self::BudgetScopeMismatch => "budget_scope_mismatch",
            Self::ReservationMismatch => "reservation_mismatch",
            Self::ExecutionMismatch => "execution_mismatch",
            Self::ProjectionMismatch => "projection_mismatch",
            Self::PolicyMismatch => "policy_mismatch",
            Self::OperationMismatch => "operation_mismatch",
            Self::ActivationMismatch => "activation_mismatch",
            Self::ActivationSuperseded => "activation_superseded",
            Self::ActivationNotYetActive => "activation_not_yet_active",
            Self::ActivationExpired => "activation_expired",
            Self::ActivationRevoked => "activation_revoked",
            Self::StateStale => "state_stale",
            Self::ApprovalNotYetValid => "approval_not_yet_valid",
            Self::ApprovalExpired => "approval_expired",
            Self::ApproverNotPermitted => "approver_not_permitted",
            Self::NotReleasable => "not_releasable",
        };
        f.write_str(s)
    }
}

impl std::error::Error for BindingError {}
