//! Budget reservation records. The store (C4) owns atomicity; this fixes what
//! is recorded and which bindings must hold.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{Contract, DomainTag};
use crate::common::*;
use crate::error::{BindingError, ContractError};
use crate::execution::ExecutionOutcome;
use crate::request::EvaluationRequest;
use crate::types::*;

schema_tag!(
    /// Schema tag for `Reservation` v1.
    ReservationSchema,
    "private-custodian.reservation/1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Reserved; execution not finished.
    Held,
    /// Spent. The default once protected bytes were acquired.
    Consumed,
    /// Returned. Only possible when no protected bytes were acquired.
    Refunded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub schema: ReservationSchema,
    pub reservation_id: ReservationId,
    pub request_id: RequestId,
    pub approval_id: ApprovalId,
    pub plan_digest: PlanDigest,
    pub kind: BudgetKind,
    pub budget: BudgetScope,
    pub units: Count<16>,
    pub state: ReservationState,
    pub exposure: ExposureState,
    pub reserved_at: Timestamp,
    pub lease_expires_at: Timestamp,
}

impl Contract for Reservation {
    const DOMAIN: DomainTag = DomainTag::Reservation;

    fn validate(&self) -> Result<(), ContractError> {
        if self.units.get() == 0 || self.lease_expires_at <= self.reserved_at {
            return Err(ContractError::Inconsistent);
        }
        if self.state == ReservationState::Refunded && self.exposure == ExposureState::Exposed {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }
}

impl Reservation {
    /// The state a held reservation settles to. Applies the core refund rule
    /// (`custodian_core::budget_refundable`); an adapter must not use its own.
    pub fn settled_state(exposure: ExposureState, outcome: ExecutionOutcome) -> ReservationState {
        if custodian_core::budget_refundable(exposure.into(), outcome.terminal_run_state()) {
            ReservationState::Refunded
        } else {
            ReservationState::Consumed
        }
    }

    /// Check this reservation before an execution starts under it.
    pub fn check_for_execution(
        &self,
        request: &EvaluationRequest,
        approval_id: &ApprovalId,
        now: Timestamp,
    ) -> Result<(), BindingError> {
        if self.request_id != request.request_id || self.approval_id != *approval_id {
            return Err(BindingError::ReservationMismatch);
        }
        let digest = request
            .plan
            .plan_digest()
            .map_err(|_| BindingError::PlanMismatch)?;
        if self.plan_digest != digest {
            return Err(BindingError::PlanMismatch);
        }
        if self.budget != request.plan.accounting.budget
            || self.kind != request.plan.accounting.kind
        {
            return Err(BindingError::BudgetScopeMismatch);
        }
        if self.state != ReservationState::Held || now >= self.lease_expires_at {
            return Err(BindingError::ReservationMismatch);
        }
        Ok(())
    }
}
