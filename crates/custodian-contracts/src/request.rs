//! Request and evaluation plan.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{domain_digest, to_canonical_bytes, Contract, DomainTag};
use crate::common::*;
use crate::error::ContractError;
use crate::types::*;

schema_tag!(
    /// Schema tag for `EvaluationRequest` v1.
    RequestSchema,
    "private-custodian.request/1"
);

/// The exact frozen plan an approval binds to. Its digest is the plan
/// identity; any change to any field is a different plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationPlan {
    pub domain: EvaluationDomain,
    pub purpose: Purpose,
    pub candidate: CandidateDigest,
    pub engine: ArtifactIdentity,
    pub adapter: ArtifactIdentity,
    pub scanners: BoundedVec<ArtifactIdentity, 8>,
    pub protocol: ProtocolRef,
    pub config_digest: ConfigDigest,
    /// Activation of the approval/execution policy this plan runs under.
    pub policy_activation: ActivationRef,
    pub population: PopulationBinding,
    pub accounting: AccountingSettings,
    pub seed_policy: SeedPolicy,
    pub limits: ResourceLimits,
    pub disclosure_policy: PolicyRef,
}

impl EvaluationPlan {
    /// Cross-field rules: one domain everywhere, correct policy kinds, and a
    /// budget scope that draws on this plan's population.
    pub fn validate(&self) -> Result<(), ContractError> {
        let d = self.domain;
        if self.protocol.domain != d
            || self.population.domain != d
            || self.disclosure_policy.domain != d
            || self.policy_activation.policy.domain != d
        {
            return Err(ContractError::Inconsistent);
        }
        if self.disclosure_policy.kind != PolicyKind::Disclosure
            || self.policy_activation.policy.kind != PolicyKind::Approval
        {
            return Err(ContractError::Inconsistent);
        }
        if !self.accounting.budget.covers(&self.population)
            || self.accounting.units.get() == 0
            || self.accounting.kind != BudgetKind::Run
        {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }

    /// Domain-separated plan digest.
    pub fn plan_digest(&self) -> Result<PlanDigest, ContractError> {
        Ok(PlanDigest::from_raw(domain_digest(
            DomainTag::Plan,
            &to_canonical_bytes(self)?,
        )))
    }

    /// The identities that are frozen for execution.
    pub fn frozen_identities(&self) -> FrozenIdentities {
        FrozenIdentities {
            domain: self.domain,
            candidate: self.candidate.clone(),
            engine: self.engine.clone(),
            adapter: self.adapter.clone(),
            scanners: self.scanners.clone(),
            config_digest: self.config_digest.clone(),
            protocol: self.protocol.clone(),
            population_digest: self.population.population_digest.clone(),
        }
    }
}

/// A request to evaluate one frozen plan. Authority is never read from it:
/// `asserted_actor` is what the intake edge claims after authentication, and
/// the control service re-derives permission from stored authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRequest {
    pub schema: RequestSchema,
    pub request_id: RequestId,
    pub idempotency_key: IdempotencyKey,
    pub asserted_actor: ActorRef,
    pub requested_at: Timestamp,
    pub plan: EvaluationPlan,
}

impl Contract for EvaluationRequest {
    const DOMAIN: DomainTag = DomainTag::Request;

    fn validate(&self) -> Result<(), ContractError> {
        self.plan.validate()
    }
}
