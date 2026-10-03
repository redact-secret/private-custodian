//! Scoped, sanitized Check updates.
//!
//! A Check run is the only thing the App writes back to GitHub. Its text is
//! built here from fixed strings and one fixed reason code. There is no field
//! that accepts a string from a worker, scanner, candidate or pull request, so
//! free text cannot reach a Check by construction. Results never appear in a
//! Check: `Completed` renders as a neutral conclusion that says only that the
//! run finished; release of any result is a separate, approved disclosure.
//!
//! Scope: an update may name only an allowlisted installation and repository
//! that has not been removed, and a commit the caller already holds.

use std::sync::{Arc, Mutex};

use custodian_contracts::common::Reason;
use custodian_core::ReasonCode;

use crate::config::IntakeConfig;
use crate::ids::{HeadSha, InstallationId, RepositoryId};
use crate::ports::InstallationRegistry;
use crate::reason::IntakeReason;

/// Check run name. Fixed.
pub const CHECK_NAME: &str = "private-custodian";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckState {
    Queued,
    InProgress,
    Denied,
    Failed,
    Completed,
}

/// The only reasons a Check can display: an intake refusal or a control-plane
/// reason code. Both are closed, fieldless vocabularies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckReason {
    Intake(IntakeReason),
    Core(ReasonCode),
}

impl CheckReason {
    pub fn code(self) -> String {
        match self {
            Self::Intake(r) => r.as_str().to_owned(),
            Self::Core(c) => serde_json::to_value(Reason::from(c))
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unspecified".to_owned()),
        }
    }
}

/// What a caller asks to be shown. No string fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckUpdate {
    pub installation: InstallationId,
    pub repository: RepositoryId,
    pub head_sha: HeadSha,
    pub state: CheckState,
    pub reason: Option<CheckReason>,
}

/// GitHub `status` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GithubStatus {
    Queued,
    InProgress,
    Completed,
}

/// GitHub `conclusion` value. `Success` is deliberately absent: a green
/// check must not be readable as a pass of the evaluated candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GithubConclusion {
    Failure,
    Neutral,
}

/// A fully rendered Check, ready for a transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckPost {
    pub installation: InstallationId,
    pub repository: RepositoryId,
    pub head_sha: HeadSha,
    pub name: &'static str,
    pub status: GithubStatus,
    pub conclusion: Option<GithubConclusion>,
    pub title: &'static str,
    pub summary: String,
}

impl CheckPost {
    pub fn render(update: &CheckUpdate) -> Self {
        let (status, conclusion, title, state_word) = match update.state {
            CheckState::Queued => (GithubStatus::Queued, None, "Request queued", "queued"),
            CheckState::InProgress => (
                GithubStatus::InProgress,
                None,
                "Request in progress",
                "in_progress",
            ),
            CheckState::Denied => (
                GithubStatus::Completed,
                Some(GithubConclusion::Failure),
                "Request denied",
                "denied",
            ),
            CheckState::Failed => (
                GithubStatus::Completed,
                Some(GithubConclusion::Failure),
                "Request failed",
                "failed",
            ),
            CheckState::Completed => (
                GithubStatus::Completed,
                Some(GithubConclusion::Neutral),
                "Request finished",
                "completed",
            ),
        };
        let reason = update
            .reason
            .map(|r| r.code())
            .unwrap_or_else(|| "none".to_owned());
        Self {
            installation: update.installation,
            repository: update.repository,
            head_sha: update.head_sha.clone(),
            name: CHECK_NAME,
            status,
            conclusion,
            title,
            summary: format!(
                "State: {state_word}. Reason: {reason}. This check reports process state only; \
                 it is not a measurement result or approval."
            ),
        }
    }
}

/// Transport seam: posts one rendered Check using an installation token
/// scoped to the named repository. The real implementation uses
/// `InstallationTokenProvider`; tests use [`RecordingCheckSink`].
pub trait CheckSink: Send + Sync {
    fn post(&self, check: &CheckPost) -> Result<(), IntakeReason>;
}

/// Validates scope, renders, and forwards.
pub struct CheckReporter {
    config: IntakeConfig,
    registry: Arc<dyn InstallationRegistry>,
    sink: Arc<dyn CheckSink>,
}

impl CheckReporter {
    pub fn new(
        config: IntakeConfig,
        registry: Arc<dyn InstallationRegistry>,
        sink: Arc<dyn CheckSink>,
    ) -> Self {
        Self {
            config,
            registry,
            sink,
        }
    }

    pub fn report(&self, update: &CheckUpdate) -> Result<(), IntakeReason> {
        if !self.config.installation_allowed(update.installation) {
            return Err(IntakeReason::InstallationNotAllowed);
        }
        if self.registry.installation_removed(update.installation)? {
            return Err(IntakeReason::InstallationRemoved);
        }
        if !self
            .config
            .repository_allowed(update.installation, update.repository)
        {
            return Err(IntakeReason::RepositoryNotAllowed);
        }
        if self
            .registry
            .repository_removed(update.installation, update.repository)?
        {
            return Err(IntakeReason::RepositoryRemoved);
        }
        self.sink
            .post(&CheckPost::render(update))
            .map_err(|_| IntakeReason::CheckUpdateFailed)
    }
}

/// Test sink that records posts.
#[derive(Debug, Default)]
pub struct RecordingCheckSink {
    posts: Mutex<Vec<CheckPost>>,
}

impl RecordingCheckSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn posts(&self) -> Vec<CheckPost> {
        self.posts.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

impl CheckSink for RecordingCheckSink {
    fn post(&self, check: &CheckPost) -> Result<(), IntakeReason> {
        self.posts
            .lock()
            .map_err(|_| IntakeReason::CheckUpdateFailed)?
            .push(check.clone());
        Ok(())
    }
}
