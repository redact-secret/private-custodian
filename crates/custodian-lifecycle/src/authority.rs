//! Who may do what. The deterministic gate in front of every state-changing
//! lifecycle operation (ARCHITECTURE.md, "Agent boundary").
//!
//! The deployment supplies an [`OperatorAuthority`]; there is deliberately no
//! default. Whatever it answers, an agent can only ever *report* a possible
//! contamination (a conservative act that blocks use); clearing, retiring,
//! rotating and publishing are operator-only.

use custodian_contracts::common::ActorKind;
use custodian_contracts::types::{ActorRef, ApprovalId};

use crate::reason::{LifecycleReason, Result};

/// The operator-only actions, in the order docs/lifecycle-and-revocation.md
/// lists them for the C10 CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperatorAction {
    /// Record a possible or confirmed contamination. Conservative.
    ReportContamination,
    /// Clear an `unreviewed_change` after review. Humans only.
    ClearUnreviewedChange,
    /// End an epoch's use for good.
    RetireEpoch,
    /// Retire, link a successor, provision its budgets, activate it.
    RotateEpoch,
    /// Record a revocation, supersession or contamination entry for a
    /// candidate, projection, receipt or policy.
    RecordRevocation,
    /// Sign and publish the next feed envelope (including freshness renewal).
    PublishFeed,
}

impl OperatorAction {
    pub const ALL: [OperatorAction; 6] = [
        Self::ReportContamination,
        Self::ClearUnreviewedChange,
        Self::RetireEpoch,
        Self::RotateEpoch,
        Self::RecordRevocation,
        Self::PublishFeed,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Self::ReportContamination => "report_contamination",
            Self::ClearUnreviewedChange => "clear_unreviewed_change",
            Self::RetireEpoch => "retire_epoch",
            Self::RotateEpoch => "rotate_epoch",
            Self::RecordRevocation => "record_revocation",
            Self::PublishFeed => "publish_feed",
        }
    }

    /// An agent may only report. Reporting can only block use.
    pub fn agent_may_perform(self) -> bool {
        self == Self::ReportContamination
    }

    /// Clearing needs a human reviewer, not a service identity.
    pub fn requires_human(self) -> bool {
        self == Self::ClearUnreviewedChange
    }
}

/// The acting principal and the reference to the authorization or review
/// that permits the act (recorded with every transition).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorAuthorization {
    pub actor: ActorRef,
    pub kind: ActorKind,
    pub authorization: ApprovalId,
}

impl OperatorAuthorization {
    pub(crate) fn kind_str(&self) -> &'static str {
        match self.kind {
            ActorKind::Human => "human",
            ActorKind::Service => "service",
            ActorKind::Agent => "agent",
        }
    }
}

/// Deployment policy: is this actor, acting under this authorization,
/// permitted to perform this action. Implemented by the control service (C10)
/// over its authenticated identities; the library never decides it alone.
pub trait OperatorAuthority: Send + Sync {
    fn permits(&self, who: &OperatorAuthorization, action: OperatorAction) -> bool;
}

/// The check every operation runs first. The kind rules are not
/// configurable: they apply whatever the authority answers.
pub fn authorize(
    authority: &dyn OperatorAuthority,
    who: &OperatorAuthorization,
    action: OperatorAction,
) -> Result<()> {
    if who.kind == ActorKind::Agent && !action.agent_may_perform() {
        return Err(LifecycleReason::AgentNotPermitted);
    }
    if action.requires_human() && who.kind != ActorKind::Human {
        return Err(LifecycleReason::Unauthorized);
    }
    if authority.permits(who, action) {
        Ok(())
    } else {
        Err(LifecycleReason::Unauthorized)
    }
}
