//! Fixed disclosure reason codes.
//!
//! Every refusal in this crate is one of these fieldless variants. None
//! carries input text, a value, a path or an identity, so a hostile or
//! protected input cannot travel through an error, a log line or a Check
//! update. [`DisclosureReason::as_str`] is the stable machine-readable code;
//! [`DisclosureReason::to_core`] maps onto the closed
//! `custodian_core::ReasonCode` vocabulary, which is all a GitHub Check ever
//! shows (`custodian_intake::checks`).

use core::fmt;

use custodian_core::ReasonCode;
use custodian_intake::checks::{CheckReason, CheckState};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DisclosureReason {
    // Preconditions and audit.
    PreconditionNotMet,
    AuditNotAcknowledged,
    StoreUnavailable,
    LedgerUnavailable,
    LedgerConflict,
    // Internal artifact validation (before anything is built).
    ReceiptInvalid,
    ReceiptNotReleasable,
    RosterIncomplete,
    BindingMismatch,
    ProvenanceMismatch,
    ArtifactMalformed,
    ArtifactMismatch,
    ArtifactIncomplete,
    ArtifactInconsistent,
    StratumNotAllowed,
    MetricNotAllowed,
    // Policy and activation.
    PolicyInvalid,
    PolicyMismatch,
    PolicyStale,
    ActivationStale,
    ActivationNotCurrent,
    // Approval and destination.
    ApprovalNotBound,
    ApprovalWrongScope,
    ApprovalExpired,
    ApproverNotPermitted,
    DestinationNotAllowed,
    DestinationMismatch,
    DigestMismatch,
    // Budgets and composition.
    BudgetExhausted,
    BudgetNotProvisioned,
    CompositionUnresolvable,
    MeasurementConflict,
    HistoryConflict,
    // Eligibility hook (C9), signing and delivery.
    EligibilityDenied,
    SigningRefused,
    SignerUnavailable,
    DeliveryFailed,
    // Verification of a released envelope.
    EnvelopeInvalid,
    SignatureInvalid,
}

impl DisclosureReason {
    pub const ALL: [DisclosureReason; 39] = [
        Self::PreconditionNotMet,
        Self::AuditNotAcknowledged,
        Self::StoreUnavailable,
        Self::LedgerUnavailable,
        Self::LedgerConflict,
        Self::ReceiptInvalid,
        Self::ReceiptNotReleasable,
        Self::RosterIncomplete,
        Self::BindingMismatch,
        Self::ProvenanceMismatch,
        Self::ArtifactMalformed,
        Self::ArtifactMismatch,
        Self::ArtifactIncomplete,
        Self::ArtifactInconsistent,
        Self::StratumNotAllowed,
        Self::MetricNotAllowed,
        Self::PolicyInvalid,
        Self::PolicyMismatch,
        Self::PolicyStale,
        Self::ActivationStale,
        Self::ActivationNotCurrent,
        Self::ApprovalNotBound,
        Self::ApprovalWrongScope,
        Self::ApprovalExpired,
        Self::ApproverNotPermitted,
        Self::DestinationNotAllowed,
        Self::DestinationMismatch,
        Self::DigestMismatch,
        Self::BudgetExhausted,
        Self::BudgetNotProvisioned,
        Self::CompositionUnresolvable,
        Self::MeasurementConflict,
        Self::HistoryConflict,
        Self::EligibilityDenied,
        Self::SigningRefused,
        Self::SignerUnavailable,
        Self::DeliveryFailed,
        Self::EnvelopeInvalid,
        Self::SignatureInvalid,
    ];

    /// Stable machine-readable code. Lowercase ASCII and underscores only.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreconditionNotMet => "precondition_not_met",
            Self::AuditNotAcknowledged => "audit_not_acknowledged",
            Self::StoreUnavailable => "store_unavailable",
            Self::LedgerUnavailable => "ledger_unavailable",
            Self::LedgerConflict => "ledger_conflict",
            Self::ReceiptInvalid => "receipt_invalid",
            Self::ReceiptNotReleasable => "receipt_not_releasable",
            Self::RosterIncomplete => "roster_incomplete",
            Self::BindingMismatch => "binding_mismatch",
            Self::ProvenanceMismatch => "provenance_mismatch",
            Self::ArtifactMalformed => "artifact_malformed",
            Self::ArtifactMismatch => "artifact_mismatch",
            Self::ArtifactIncomplete => "artifact_incomplete",
            Self::ArtifactInconsistent => "artifact_inconsistent",
            Self::StratumNotAllowed => "stratum_not_allowed",
            Self::MetricNotAllowed => "metric_not_allowed",
            Self::PolicyInvalid => "policy_invalid",
            Self::PolicyMismatch => "policy_mismatch",
            Self::PolicyStale => "policy_stale",
            Self::ActivationStale => "activation_stale",
            Self::ActivationNotCurrent => "activation_not_current",
            Self::ApprovalNotBound => "approval_not_bound",
            Self::ApprovalWrongScope => "approval_wrong_scope",
            Self::ApprovalExpired => "approval_expired",
            Self::ApproverNotPermitted => "approver_not_permitted",
            Self::DestinationNotAllowed => "destination_not_allowed",
            Self::DestinationMismatch => "destination_mismatch",
            Self::DigestMismatch => "digest_mismatch",
            Self::BudgetExhausted => "budget_exhausted",
            Self::BudgetNotProvisioned => "budget_not_provisioned",
            Self::CompositionUnresolvable => "composition_unresolvable",
            Self::MeasurementConflict => "measurement_conflict",
            Self::HistoryConflict => "history_conflict",
            Self::EligibilityDenied => "eligibility_denied",
            Self::SigningRefused => "signing_refused",
            Self::SignerUnavailable => "signer_unavailable",
            Self::DeliveryFailed => "delivery_failed",
            Self::EnvelopeInvalid => "envelope_invalid",
            Self::SignatureInvalid => "signature_invalid",
        }
    }

    /// The core reason code. Deliberately coarse: a Check or a requester sees
    /// `budget_exhausted`, `store_unavailable` or `disclosure_not_permitted`,
    /// never which internal binding or composition rule refused.
    pub fn to_core(self) -> ReasonCode {
        match self {
            Self::BudgetExhausted | Self::BudgetNotProvisioned => ReasonCode::BudgetExhausted,
            Self::StoreUnavailable
            | Self::LedgerUnavailable
            | Self::LedgerConflict
            | Self::SignerUnavailable
            | Self::DeliveryFailed => ReasonCode::StoreUnavailable,
            _ => ReasonCode::DisclosureNotPermitted,
        }
    }

    /// The Check state a refusal renders as: infrastructure trouble is a
    /// failure, a policy refusal is a denial.
    pub fn check_state(self) -> CheckState {
        match self.to_core() {
            ReasonCode::StoreUnavailable => CheckState::Failed,
            _ => CheckState::Denied,
        }
    }

    pub fn check_reason(self) -> CheckReason {
        CheckReason::Core(self.to_core())
    }
}

impl fmt::Display for DisclosureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for DisclosureReason {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_lowercase_and_exhaustive() {
        let mut seen = std::collections::BTreeSet::new();
        for r in DisclosureReason::ALL {
            let c = r.as_str();
            assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!(seen.insert(c));
        }
        assert_eq!(seen.len(), DisclosureReason::ALL.len());
    }
}
