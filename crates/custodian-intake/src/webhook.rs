//! Webhook intake: validate and enqueue, nothing else.
//!
//! Order of checks (cheapest and least informative first, every refusal is a
//! fixed [`IntakeReason`]):
//!
//! 1. body size cap (before any hashing or parsing);
//! 2. `X-Hub-Signature-256` HMAC, constant time;
//! 3. content type is `application/json`;
//! 4. `X-GitHub-Delivery` is a UUID;
//! 5. event is on the allowlist (comment, workflow and dispatch events are
//!    refused by name; unknown events are refused);
//! 6. delivery id claimed atomically (replay and redelivery are refused);
//! 7. typed payload parse, then installation, repository, fork and
//!    cross-repository, sender kind and actor allowlist checks;
//! 8. enqueue. If the queue refuses, the claim is released so GitHub's
//!    redelivery can succeed, and the delivery is refused.
//!
//! The handler performs no evaluation, opens no network connection and reads
//! nothing from the pull request except identifiers. Nothing a pull request
//! author controls (title, body, branch, labels, comments, workflow files)
//! reaches the queue or any decision.

use std::sync::Arc;

use custodian_contracts::types::Timestamp;
use serde::Deserialize;

use crate::config::{IntakeConfig, WebhookSecret};
use crate::ids::{
    DeliveryId, EventName, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use crate::ports::{Claim, DeliveryStore, InstallationRegistry, IntakeQueue, QueuedRequest};
use crate::reason::IntakeReason;
use crate::signature::verify_signature;

/// Pull request actions that may cause a request to be queued. Labels,
/// edits, comments and reviews are not triggers.
const PR_ACTIONS: [&str; 4] = ["opened", "synchronize", "reopened", "ready_for_review"];

/// Events that look like triggers but must never reach privileged work.
const COMMENT_EVENTS: [&str; 7] = [
    "issue_comment",
    "pull_request_review_comment",
    "pull_request_review",
    "commit_comment",
    "discussion_comment",
    "discussion",
    "issues",
];
const WORKFLOW_EVENTS: [&str; 6] = [
    "workflow_run",
    "workflow_job",
    "workflow_dispatch",
    "repository_dispatch",
    "pull_request_target",
    "schedule",
];

/// A raw delivery as received by the HTTP listener (not part of this crate).
/// All fields are untrusted until [`Intake::handle`] accepts them.
#[derive(Clone, Copy, Debug)]
pub struct Delivery<'a> {
    pub signature: Option<&'a str>,
    pub event: Option<&'a str>,
    pub delivery_id: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

/// What an accepted delivery did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A request was enqueued for the control plane.
    Queued,
    /// Authenticated, no effect (for example `ping`).
    Ignored,
    /// The installation was recorded as removed.
    InstallationRevoked,
    /// One or more repositories were recorded as removed.
    RepositoryRevoked,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Ignored => "ignored",
            Self::InstallationRevoked => "installation_revoked",
            Self::RepositoryRevoked => "repository_revoked",
        }
    }
    pub fn http_status(self) -> u16 {
        match self {
            Self::Queued => 202,
            _ => 200,
        }
    }
}

/// HTTP response for a handled delivery: a status and a fixed code, never
/// payload text.
pub fn response(result: &Result<Outcome, IntakeReason>) -> (u16, &'static str) {
    match result {
        Ok(o) => (o.http_status(), o.as_str()),
        Err(r) => (r.http_status(), r.as_str()),
    }
}

#[derive(Deserialize)]
struct InstallationRef {
    id: InstallationId,
}

#[derive(Deserialize)]
struct RepoRef {
    id: RepositoryId,
    #[serde(default)]
    fork: Option<bool>,
}

#[derive(Deserialize)]
struct Sender {
    id: GithubUserId,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct GitRef {
    sha: HeadSha,
    repo: Option<RepoRef>,
}

#[derive(Deserialize)]
struct PullRequest {
    number: PullRequestNumber,
    head: GitRef,
    base: GitRef,
}

#[derive(Deserialize)]
struct PullRequestPayload {
    action: String,
    installation: InstallationRef,
    repository: RepoRef,
    sender: Sender,
    pull_request: PullRequest,
}

#[derive(Deserialize)]
struct InstallationPayload {
    action: String,
    installation: InstallationRef,
}

#[derive(Deserialize)]
struct RepoListPayload {
    action: String,
    installation: InstallationRef,
    #[serde(default)]
    repositories_removed: Vec<RepoId>,
}

#[derive(Deserialize)]
struct RepoId {
    id: RepositoryId,
}

/// The webhook handler.
pub struct Intake {
    config: IntakeConfig,
    secret: WebhookSecret,
    deliveries: Arc<dyn DeliveryStore>,
    registry: Arc<dyn InstallationRegistry>,
    queue: Arc<dyn IntakeQueue>,
}

impl Intake {
    pub fn new(
        config: IntakeConfig,
        secret: WebhookSecret,
        deliveries: Arc<dyn DeliveryStore>,
        registry: Arc<dyn InstallationRegistry>,
        queue: Arc<dyn IntakeQueue>,
    ) -> Self {
        Self {
            config,
            secret,
            deliveries,
            registry,
            queue,
        }
    }

    pub fn config(&self) -> &IntakeConfig {
        &self.config
    }

    /// Validate one delivery and, if it is acceptable, enqueue it.
    pub fn handle(&self, d: &Delivery<'_>, now: Timestamp) -> Result<Outcome, IntakeReason> {
        if d.body.len() > self.config.max_body_bytes() {
            return Err(IntakeReason::BodyTooLarge);
        }
        verify_signature(&self.secret, d.body, d.signature)?;

        let is_json = d.content_type.is_some_and(|c| {
            let media = c.split(';').next().unwrap_or("").trim();
            media.eq_ignore_ascii_case("application/json")
        });
        if !is_json {
            return Err(IntakeReason::ContentTypeInvalid);
        }
        let delivery = DeliveryId::parse(d.delivery_id.ok_or(IntakeReason::DeliveryIdInvalid)?)?;

        let event = EventName::parse(d.event.ok_or(IntakeReason::EventNotAllowed)?)?;
        if !self.config.event_enabled(event.as_str()) {
            return Err(classify_denied_event(event.as_str()));
        }

        match self.deliveries.claim(&delivery)? {
            Claim::New => {}
            Claim::Seen => return Err(IntakeReason::DeliveryReplay),
        }

        match event.as_str() {
            "ping" => Ok(Outcome::Ignored),
            "pull_request" => self.pull_request(delivery, d.body, now),
            "installation" => self.installation(d.body),
            "installation_repositories" => self.installation_repositories(d.body),
            // Unreachable: configuration validation only admits supported
            // events. Fail closed regardless.
            _ => Err(IntakeReason::EventNotAllowed),
        }
    }

    fn pull_request(
        &self,
        delivery: DeliveryId,
        body: &[u8],
        now: Timestamp,
    ) -> Result<Outcome, IntakeReason> {
        let p: PullRequestPayload =
            serde_json::from_slice(body).map_err(|_| IntakeReason::PayloadMalformed)?;

        if !PR_ACTIONS.contains(&p.action.as_str()) {
            return Err(IntakeReason::ActionNotAllowed);
        }
        let installation = p.installation.id;
        self.check_scope(installation, p.repository.id)?;

        // Fork and cross-repository denial. The base repository must be the
        // repository of the event, and the head must live in that same
        // repository. A deleted fork (null head repository) is a fork.
        match &p.pull_request.base.repo {
            Some(base) if base.id == p.repository.id => {}
            _ => return Err(IntakeReason::CrossRepositoryDenied),
        }
        match &p.pull_request.head.repo {
            None => return Err(IntakeReason::ForkDenied),
            Some(head) if head.id != p.repository.id => {
                return Err(if head.fork == Some(true) {
                    IntakeReason::ForkDenied
                } else {
                    IntakeReason::CrossRepositoryDenied
                });
            }
            Some(_) => {}
        }

        // Only a human GitHub user can request. Bots, apps and organizations
        // cannot, so an automation (or an agent acting through a bot account)
        // cannot start a request.
        if p.sender.kind != "User" {
            return Err(IntakeReason::ActorKindDenied);
        }
        let actor = self
            .config
            .requester(p.sender.id)
            .ok_or(IntakeReason::ActorNotAuthorized)?
            .clone();

        let request = QueuedRequest {
            delivery: delivery.clone(),
            installation,
            repository: p.repository.id,
            pull_request: p.pull_request.number,
            head_sha: p.pull_request.head.sha,
            actor,
            github_user: p.sender.id,
            received_at: now,
        };
        if let Err(e) = self.queue.enqueue(request) {
            // Allow GitHub's redelivery of this id. If the release itself
            // fails the claim stays and the delivery stays refused.
            let _ = self.deliveries.release(&delivery);
            return Err(e);
        }
        Ok(Outcome::Queued)
    }

    fn check_scope(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<(), IntakeReason> {
        if !self.config.installation_allowed(installation) {
            return Err(IntakeReason::InstallationNotAllowed);
        }
        if self.registry.installation_removed(installation)? {
            return Err(IntakeReason::InstallationRemoved);
        }
        if !self.config.repository_allowed(installation, repository) {
            return Err(IntakeReason::RepositoryNotAllowed);
        }
        if self.registry.repository_removed(installation, repository)? {
            return Err(IntakeReason::RepositoryRemoved);
        }
        Ok(())
    }

    fn installation(&self, body: &[u8]) -> Result<Outcome, IntakeReason> {
        let p: InstallationPayload =
            serde_json::from_slice(body).map_err(|_| IntakeReason::PayloadMalformed)?;
        if !self.config.installation_allowed(p.installation.id) {
            return Err(IntakeReason::InstallationNotAllowed);
        }
        match p.action.as_str() {
            // Removal or suspension is always honored. Creation, unsuspension
            // and permission changes never re-enable anything: re-enabling is
            // an operator configuration change.
            "deleted" | "suspend" => {
                self.registry.mark_installation_removed(p.installation.id)?;
                Ok(Outcome::InstallationRevoked)
            }
            _ => Err(IntakeReason::ActionNotAllowed),
        }
    }

    fn installation_repositories(&self, body: &[u8]) -> Result<Outcome, IntakeReason> {
        let p: RepoListPayload =
            serde_json::from_slice(body).map_err(|_| IntakeReason::PayloadMalformed)?;
        if !self.config.installation_allowed(p.installation.id) {
            return Err(IntakeReason::InstallationNotAllowed);
        }
        match p.action.as_str() {
            "removed" => {
                for r in &p.repositories_removed {
                    self.registry
                        .mark_repository_removed(p.installation.id, r.id)?;
                }
                Ok(Outcome::RepositoryRevoked)
            }
            // Added repositories are never allowlisted automatically.
            _ => Err(IntakeReason::ActionNotAllowed),
        }
    }
}

fn classify_denied_event(event: &str) -> IntakeReason {
    if COMMENT_EVENTS.contains(&event) {
        IntakeReason::CommentTriggerDenied
    } else if WORKFLOW_EVENTS.contains(&event) {
        IntakeReason::WorkflowTriggerDenied
    } else {
        IntakeReason::EventNotAllowed
    }
}
