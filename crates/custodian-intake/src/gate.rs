//! Execution gate: the second stage after the webhook edge.
//!
//! Queued intake means "an allowlisted human asked, about this commit". It is
//! not permission to run anything. The gate turns a queued request into an
//! [`AuthorizedExecution`] only when all of these hold at the time of the
//! call:
//!
//! - the installation, repository and actor are still allowed and not removed;
//! - the request document decodes strictly (`EvaluationRequest::decode`);
//! - the request's `asserted_actor` equals the actor derived at intake from
//!   the verified sender (the assertion is checked, never trusted);
//! - the pull request head is still the commit the event named (stale-commit
//!   check) and the staged candidate was staged from that commit;
//! - the plan's candidate and configuration digests equal the staged bytes;
//! - a distinct, explicit execution [`Approval`] exists, names an approver who
//!   holds the approver role, and binds the exact request, plan digest,
//!   candidate, population, budget and a current policy activation.
//!
//! GitHub App access (a valid webhook, an installation token, an allowlisted
//! requester) is never an input to the approval decision: the only approval
//! input is the `Approval` contract record, which no webhook can create.

use std::sync::Arc;

use custodian_contracts::approval::Approval;
use custodian_contracts::policy::{ObservedActivation, MAX_STATE_AGE_SECS};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::{
    ApprovalId, CandidateDigest, ConfigDigest, DocumentDigest, PlanDigest, RequestId, Timestamp,
};
use custodian_contracts::{BindingError, Contract};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::IntakeConfig;
use crate::ids::{HeadSha, RepositoryId};
use crate::ports::{InstallationRegistry, PullRequestSource, QueuedRequest};
use crate::reason::IntakeReason;

/// Domain string for the intake binding digest. It is local to the edge
/// adapter; promoting it to a `DomainTag` is a contracts change (new tag).
const BINDING_DOMAIN: &str = "private-custodian/v1/intake-binding";

/// The candidate and configuration bytes as staged by the control plane,
/// identified by digest and by the commit they were staged from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedCandidate {
    pub head_sha: HeadSha,
    pub candidate: CandidateDigest,
    pub config_digest: ConfigDigest,
}

/// Immutable binding of a request to one commit, one candidate digest, one
/// configuration digest and one plan. No setters; the digest changes if any
/// field would.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IntakeBinding {
    repository: RepositoryId,
    head_sha: HeadSha,
    candidate: CandidateDigest,
    config_digest: ConfigDigest,
    plan_digest: PlanDigest,
    request_id: RequestId,
}

impl IntakeBinding {
    pub fn repository(&self) -> RepositoryId {
        self.repository
    }
    pub fn head_sha(&self) -> &HeadSha {
        &self.head_sha
    }
    pub fn candidate(&self) -> &CandidateDigest {
        &self.candidate
    }
    pub fn config_digest(&self) -> &ConfigDigest {
        &self.config_digest
    }
    pub fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Domain-separated digest over the canonical encoding of the binding.
    pub fn digest(&self) -> Result<DocumentDigest, IntakeReason> {
        let bytes = custodian_contracts::canonical::to_canonical_bytes(self)
            .map_err(|_| IntakeReason::RequestInvalid)?;
        let mut h = Sha256::new();
        h.update(BINDING_DOMAIN.as_bytes());
        h.update([0u8]);
        h.update(&bytes);
        Ok(DocumentDigest::from_raw(h.finalize().into()))
    }

    /// True only if `staged` is exactly the bytes this binding froze.
    pub fn matches_staged(&self, staged: &StagedCandidate) -> bool {
        staged.head_sha == self.head_sha
            && staged.candidate == self.candidate
            && staged.config_digest == self.config_digest
    }
}

/// The result of a successful gate: proof, produced only by [`ExecutionGate`],
/// that every check above passed. It carries identities, not authority tokens:
/// the control service still re-derives authorization before reserving.
#[derive(Clone, Debug)]
pub struct AuthorizedExecution {
    binding: IntakeBinding,
    approval_id: ApprovalId,
}

impl AuthorizedExecution {
    pub fn binding(&self) -> &IntakeBinding {
        &self.binding
    }
    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }
}

pub struct ExecutionGate {
    config: IntakeConfig,
    registry: Arc<dyn InstallationRegistry>,
    pulls: Arc<dyn PullRequestSource>,
}

impl ExecutionGate {
    pub fn new(
        config: IntakeConfig,
        registry: Arc<dyn InstallationRegistry>,
        pulls: Arc<dyn PullRequestSource>,
    ) -> Self {
        Self {
            config,
            registry,
            pulls,
        }
    }

    /// Decide whether a queued request may proceed to reservation.
    pub fn authorize(
        &self,
        queued: &QueuedRequest,
        request_bytes: &[u8],
        staged: &StagedCandidate,
        approval: Option<&Approval>,
        activation: &ObservedActivation,
        now: Timestamp,
    ) -> Result<AuthorizedExecution, IntakeReason> {
        self.recheck_scope(queued)?;

        let request =
            EvaluationRequest::decode(request_bytes).map_err(|_| IntakeReason::RequestInvalid)?;
        if request.asserted_actor != queued.actor {
            return Err(IntakeReason::ActorMismatch);
        }

        let current =
            self.pulls
                .current_head(queued.installation, queued.repository, queued.pull_request)?;
        if current != queued.head_sha || staged.head_sha != queued.head_sha {
            return Err(IntakeReason::StaleCommit);
        }
        if request.plan.candidate != staged.candidate {
            return Err(IntakeReason::CandidateMismatch);
        }
        if request.plan.config_digest != staged.config_digest {
            return Err(IntakeReason::ConfigMismatch);
        }

        // Approval is separate from App access and from queued intake.
        let approval = approval.ok_or(IntakeReason::ApprovalRequired)?;
        if !self.config.is_approver(&approval.approver) {
            return Err(IntakeReason::ApproverNotAuthorized);
        }
        let plan_digest = approval
            .check_for_execution(&request, activation, now, MAX_STATE_AGE_SECS)
            .map_err(map_binding)?;

        Ok(AuthorizedExecution {
            binding: IntakeBinding {
                repository: queued.repository,
                head_sha: queued.head_sha.clone(),
                candidate: staged.candidate.clone(),
                config_digest: staged.config_digest.clone(),
                plan_digest,
                request_id: request.request_id.clone(),
            },
            approval_id: approval.approval_id.clone(),
        })
    }

    fn recheck_scope(&self, q: &QueuedRequest) -> Result<(), IntakeReason> {
        if !self.config.installation_allowed(q.installation) {
            return Err(IntakeReason::InstallationNotAllowed);
        }
        if self.registry.installation_removed(q.installation)? {
            return Err(IntakeReason::InstallationRemoved);
        }
        if !self.config.repository_allowed(q.installation, q.repository) {
            return Err(IntakeReason::RepositoryNotAllowed);
        }
        if self
            .registry
            .repository_removed(q.installation, q.repository)?
        {
            return Err(IntakeReason::RepositoryRemoved);
        }
        match self.config.requester(q.github_user) {
            Some(a) if *a == q.actor => Ok(()),
            _ => Err(IntakeReason::ActorNotAuthorized),
        }
    }
}

fn map_binding(e: BindingError) -> IntakeReason {
    use BindingError::*;
    match e {
        ApprovalNotYetValid | ApprovalExpired => IntakeReason::ApprovalExpired,
        StateStale
        | ActivationMismatch
        | ActivationSuperseded
        | ActivationNotYetActive
        | ActivationExpired
        | ActivationRevoked => IntakeReason::ActivationNotCurrent,
        ApproverNotPermitted => IntakeReason::ApproverNotAuthorized,
        _ => IntakeReason::ApprovalNotBound,
    }
}
