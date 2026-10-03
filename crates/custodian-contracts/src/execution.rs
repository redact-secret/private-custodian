//! Execution record and internal receipt (private; never public).

use custodian_core::RunState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{Contract, DomainTag};
use crate::common::*;
use crate::error::{BindingError, ContractError};
use crate::policy::{check_current, ObservedActivation};
use crate::request::EvaluationRequest;
use crate::reservation::Reservation;
use crate::types::*;

schema_tag!(
    /// Schema tag for `ExecutionRecord` v1.
    ExecutionSchema,
    "private-custodian.execution/1"
);
schema_tag!(
    /// Schema tag for `InternalReceipt` v1.
    InternalReceiptSchema,
    "private-custodian.internal-receipt/1"
);

/// Terminal result of one execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Every authorized input was measured and the artifact validated.
    Success,
    /// Some inputs were measured, not all. Never releasable.
    Partial,
    Failed,
    Cancelled,
    Expired,
    /// The result artifact failed validation (roster, version, counters,
    /// bindings or schema).
    Rejected,
}

impl ExecutionOutcome {
    /// The core lifecycle state this outcome corresponds to.
    pub fn terminal_run_state(self) -> RunState {
        match self {
            Self::Success => RunState::Completed,
            Self::Partial | Self::Failed | Self::Rejected => RunState::Failed,
            Self::Cancelled => RunState::Cancelled,
            Self::Expired => RunState::Expired,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub schema: ExecutionSchema,
    pub execution_id: ExecutionId,
    pub request_id: RequestId,
    pub approval_id: ApprovalId,
    pub reservation_id: ReservationId,
    pub plan_digest: PlanDigest,
    pub activation: ActivationRef,
    pub frozen: FrozenIdentities,
    /// 1-based attempt number. A retry is a new attempt with a new execution id.
    pub attempt: Count<16>,
    pub outcome: ExecutionOutcome,
    pub exposure: ExposureState,
    pub reason: Reason,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
}

impl Contract for ExecutionRecord {
    const DOMAIN: DomainTag = DomainTag::Execution;

    fn validate(&self) -> Result<(), ContractError> {
        use ExecutionOutcome::*;
        if self.attempt.get() == 0 || self.finished_at < self.started_at {
            return Err(ContractError::Inconsistent);
        }
        // A measured result implies protected bytes were acquired.
        if matches!(self.outcome, Success | Partial) && self.exposure != ExposureState::Exposed {
            return Err(ContractError::Inconsistent);
        }
        if (self.outcome == Success) != (self.reason == Reason::Completed) {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }
}

impl ExecutionRecord {
    /// Only a fully successful execution can feed a projection.
    pub fn is_releasable(&self) -> bool {
        self.outcome == ExecutionOutcome::Success
    }

    /// Whether the reservation may be refunded for this execution.
    pub fn refund_allowed(&self) -> bool {
        Reservation::settled_state(self.exposure, self.outcome)
            == crate::reservation::ReservationState::Refunded
    }

    /// Check frozen identities and ids against the request, approval and
    /// reservation this execution claims to run under.
    pub fn check_binding(
        &self,
        request: &EvaluationRequest,
        reservation: &Reservation,
    ) -> Result<(), BindingError> {
        let plan = &request.plan;
        if self.request_id != request.request_id {
            return Err(BindingError::RequestMismatch);
        }
        if self.reservation_id != reservation.reservation_id
            || self.approval_id != reservation.approval_id
        {
            return Err(BindingError::ReservationMismatch);
        }
        let digest = plan.plan_digest().map_err(|_| BindingError::PlanMismatch)?;
        if self.plan_digest != digest || reservation.plan_digest != digest {
            return Err(BindingError::PlanMismatch);
        }
        if self.frozen.domain != plan.domain {
            return Err(BindingError::DomainMismatch);
        }
        if self.frozen.candidate != plan.candidate {
            return Err(BindingError::CandidateMismatch);
        }
        if self.frozen.population_digest != plan.population.population_digest {
            return Err(BindingError::PopulationMismatch);
        }
        if self.frozen != plan.frozen_identities() {
            return Err(BindingError::PlanMismatch);
        }
        if self.activation != plan.policy_activation {
            return Err(BindingError::ActivationMismatch);
        }
        Ok(())
    }
}

/// Reference to a private result artifact. The artifact itself stays in
/// protected storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateArtifactRef {
    pub digest: ResultDigest,
    pub size_bytes: Count<1_099_511_627_776>,
    /// Protocol the artifact claims to follow; must equal the frozen protocol.
    pub protocol: ProtocolRef,
}

/// Aggregate roster counters (no case identities).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RosterCounts {
    pub expected: Count<100_000_000>,
    pub observed: Count<100_000_000>,
    pub failed: Count<100_000_000>,
}

/// Internal receipt for a measured execution. Private: it names internal
/// plan identities and the private result artifact. Signing (C7) uses
/// `Contract::signing_input` under `DomainTag::InternalReceipt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InternalReceipt {
    pub schema: InternalReceiptSchema,
    pub receipt_id: ReceiptId,
    pub execution_id: ExecutionId,
    pub plan_digest: PlanDigest,
    pub activation: ActivationRef,
    pub frozen: FrozenIdentities,
    pub outcome: ExecutionOutcome,
    pub result: PrivateArtifactRef,
    pub roster: RosterCounts,
    pub attestation: Attestation,
    pub issued_at: Timestamp,
}

impl Contract for InternalReceipt {
    const DOMAIN: DomainTag = DomainTag::InternalReceipt;

    fn validate(&self) -> Result<(), ContractError> {
        let r = &self.roster;
        let ok = match self.outcome {
            ExecutionOutcome::Success => r.observed == r.expected,
            ExecutionOutcome::Partial => r.observed < r.expected,
            _ => false,
        };
        if !ok || r.failed > r.observed || self.result.protocol != self.frozen.protocol {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }
}

impl InternalReceipt {
    /// A receipt is evidence of a past run, not a standing permission.
    /// Any reuse (release preparation, caching, re-projection) must pass the
    /// current activation check; a revoked or superseded activation rejects it
    /// no matter how successful the original run was.
    pub fn check_still_valid(
        &self,
        current: &ObservedActivation,
        now: Timestamp,
        max_state_age_secs: u64,
    ) -> Result<(), BindingError> {
        if self.outcome != ExecutionOutcome::Success {
            return Err(BindingError::NotReleasable);
        }
        check_current(&self.activation, current, now, max_state_age_secs)
    }
}
