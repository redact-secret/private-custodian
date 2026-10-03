//! Ports of the request edge. Each is a small typed seam where a durable
//! adapter (C4) or a GitHub transport plugs in, and where an in-memory double
//! replaces it for offline tests. Errors are fixed [`IntakeReason`]s.
//!
//! Semantics every implementation must keep:
//! - `DeliveryStore::claim` is one atomic check-and-insert: of any number of
//!   concurrent claims for one id, exactly one gets `Claim::New`.
//! - A store that cannot answer returns `StoreUnavailable`. The caller fails
//!   closed; it never treats "unknown" as "new" or as "allowed".
//! - `IntakeQueue::enqueue` only records a request for later processing. It
//!   performs no evaluation and no network call.

use custodian_contracts::types::{ActorRef, Timestamp};

use crate::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use crate::reason::IntakeReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// First time this delivery id was seen.
    New,
    /// Already claimed: a replay or a redelivery.
    Seen,
}

/// Delivery-id replay and idempotency record.
pub trait DeliveryStore: Send + Sync {
    fn claim(&self, id: &DeliveryId) -> Result<Claim, IntakeReason>;
    /// Forget a claim so GitHub's redelivery of the same id can be processed.
    /// Called only when an otherwise accepted delivery could not be enqueued.
    fn release(&self, id: &DeliveryId) -> Result<(), IntakeReason>;
}

/// Record of installations and repositories GitHub has told us were removed.
/// It can only restrict further than the static allowlist; there is no
/// operation that re-enables an installation.
pub trait InstallationRegistry: Send + Sync {
    fn installation_removed(&self, installation: InstallationId) -> Result<bool, IntakeReason>;
    fn repository_removed(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<bool, IntakeReason>;
    fn mark_installation_removed(&self, installation: InstallationId) -> Result<(), IntakeReason>;
    fn mark_repository_removed(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<(), IntakeReason>;
}

/// A request accepted at the edge. It carries identifiers only: no title,
/// body, branch name, label, comment or file name from the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedRequest {
    pub delivery: DeliveryId,
    pub installation: InstallationId,
    pub repository: RepositoryId,
    pub pull_request: PullRequestNumber,
    /// Head commit named by the event. The gate re-checks it is still current.
    pub head_sha: HeadSha,
    /// Actor derived from the verified sender and the allowlist.
    pub actor: ActorRef,
    pub github_user: GithubUserId,
    pub received_at: Timestamp,
}

/// Hand-off to the control plane. Intake validates and enqueues; everything
/// expensive happens on the other side of this trait.
pub trait IntakeQueue: Send + Sync {
    fn enqueue(&self, request: QueuedRequest) -> Result<(), IntakeReason>;
}

/// Current state of a pull request, read through the App with a scoped
/// installation token. Used for the stale-commit check.
pub trait PullRequestSource: Send + Sync {
    fn current_head(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
        pull_request: PullRequestNumber,
    ) -> Result<HeadSha, IntakeReason>;
}
