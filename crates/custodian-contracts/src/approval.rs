//! Approval records. Execution approval and release approval are separate
//! scopes: completing an execution never authorizes release.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{Contract, DomainTag};
use crate::common::*;
use crate::error::{BindingError, ContractError};
use crate::policy::{check_current, ObservedActivation};
use crate::request::EvaluationRequest;
use crate::types::*;

schema_tag!(
    /// Schema tag for `Approval` v1.
    ApprovalSchema,
    "private-custodian.approval/1"
);

/// Longest lifetime an approval may be issued for.
pub const MAX_APPROVAL_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// What the approval authorizes, bound to exact identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalScope {
    /// Run exactly this plan against exactly this population and budget.
    Execute {
        request_id: RequestId,
        plan_digest: PlanDigest,
        candidate: CandidateDigest,
        population: PopulationBinding,
        budget: BudgetScope,
    },
    /// Release exactly this projection, produced by this execution, under
    /// this disclosure policy.
    Release {
        execution_id: ExecutionId,
        projection_digest: ProjectionDigest,
        disclosure_policy: PolicyRef,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub schema: ApprovalSchema,
    pub approval_id: ApprovalId,
    pub scope: ApprovalScope,
    pub activation: ActivationRef,
    pub proposer: ActorRef,
    pub approver: ActorRef,
    pub approver_kind: ActorKind,
    pub role_separation: RoleSeparation,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

impl Contract for Approval {
    const DOMAIN: DomainTag = DomainTag::Approval;

    fn validate(&self) -> Result<(), ContractError> {
        if self.expires_at <= self.issued_at
            || self.expires_at.secs() - self.issued_at.secs() > MAX_APPROVAL_TTL_SECS
        {
            return Err(ContractError::Inconsistent);
        }
        // An agent never approves, and the stated separation must match the
        // actual principals.
        if self.approver_kind == ActorKind::Agent {
            return Err(ContractError::Inconsistent);
        }
        let same = self.proposer == self.approver;
        let expected = if same {
            RoleSeparation::SingleOperatorProcedural
        } else {
            RoleSeparation::DistinctPrincipalsProcedural
        };
        if self.role_separation != expected {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }
}

impl Approval {
    fn check_time(&self, now: Timestamp) -> Result<(), BindingError> {
        if now < self.issued_at {
            return Err(BindingError::ApprovalNotYetValid);
        }
        if now >= self.expires_at {
            return Err(BindingError::ApprovalExpired);
        }
        Ok(())
    }

    /// Check this approval before reserving or starting an execution.
    /// Structural bindings first, then time, then current activation state.
    /// Returns the verified plan digest.
    pub fn check_for_execution(
        &self,
        request: &EvaluationRequest,
        current: &ObservedActivation,
        now: Timestamp,
        max_state_age_secs: u64,
    ) -> Result<PlanDigest, BindingError> {
        let ApprovalScope::Execute {
            request_id,
            plan_digest,
            candidate,
            population,
            budget,
        } = &self.scope
        else {
            return Err(BindingError::OperationMismatch);
        };
        let plan = &request.plan;
        if *request_id != request.request_id || self.proposer != request.asserted_actor {
            return Err(BindingError::RequestMismatch);
        }
        if self.approver_kind == ActorKind::Agent {
            return Err(BindingError::ApproverNotPermitted);
        }
        let actual = plan.plan_digest().map_err(|_| BindingError::PlanMismatch)?;
        if *plan_digest != actual {
            return Err(BindingError::PlanMismatch);
        }
        if *candidate != plan.candidate {
            return Err(BindingError::CandidateMismatch);
        }
        if population.domain != plan.domain {
            return Err(BindingError::DomainMismatch);
        }
        if *population != plan.population {
            return Err(BindingError::PopulationMismatch);
        }
        if *budget != plan.accounting.budget {
            return Err(BindingError::BudgetScopeMismatch);
        }
        if self.activation != plan.policy_activation {
            return Err(BindingError::ActivationMismatch);
        }
        self.check_time(now)?;
        check_current(&self.activation, current, now, max_state_age_secs)?;
        Ok(actual)
    }

    /// Check this approval before releasing a projection.
    pub fn check_for_release(
        &self,
        execution_id: &ExecutionId,
        projection_digest: &ProjectionDigest,
        disclosure_policy: &PolicyRef,
        current: &ObservedActivation,
        now: Timestamp,
        max_state_age_secs: u64,
    ) -> Result<(), BindingError> {
        let ApprovalScope::Release {
            execution_id: e,
            projection_digest: p,
            disclosure_policy: pol,
        } = &self.scope
        else {
            return Err(BindingError::OperationMismatch);
        };
        if self.approver_kind == ActorKind::Agent {
            return Err(BindingError::ApproverNotPermitted);
        }
        if e != execution_id {
            return Err(BindingError::ExecutionMismatch);
        }
        if p != projection_digest {
            return Err(BindingError::ProjectionMismatch);
        }
        if pol != disclosure_policy {
            return Err(BindingError::PolicyMismatch);
        }
        self.check_time(now)?;
        check_current(&self.activation, current, now, max_state_age_secs)
    }
}
