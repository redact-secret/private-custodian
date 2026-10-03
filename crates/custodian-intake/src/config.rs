//! Validated intake configuration: event, installation, repository and actor
//! allowlists. The configuration is the only source of "who and what may
//! reach the queue". Nothing in a payload, label, comment or branch name adds
//! to it. Anything not listed is denied.
//!
//! The configuration file holds identifiers only. The webhook secret is a
//! separate [`WebhookSecret`] supplied by the deployment's secret store and is
//! never part of this file.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::types::ActorRef;
use serde::Deserialize;

use crate::ids::{GithubUserId, InstallationId, RepositoryId};
use crate::reason::ConfigError;

/// Events the intake knows how to handle. A configuration may enable a subset;
/// it can never enable anything else (comment, workflow and dispatch events
/// are not handled, so they cannot be switched on by configuration).
pub const SUPPORTED_EVENTS: [&str; 4] = [
    "ping",
    "pull_request",
    "installation",
    "installation_repositories",
];

/// Default webhook body cap in bytes.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;
/// Hard ceiling a configuration may raise the cap to.
pub const HARD_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Smallest accepted webhook secret length in bytes.
pub const MIN_SECRET_BYTES: usize = 32;
/// Largest accepted configuration file.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// What an allowlisted actor may do through the request edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// May cause a request to be queued.
    Requester,
    /// May be named as approver on an execution approval. Holding this role
    /// approves nothing by itself.
    Approver,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationEntry {
    installation_id: InstallationId,
    repository_ids: Vec<RepositoryId>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorEntry {
    github_user_id: GithubUserId,
    actor: ActorRef,
    roles: Vec<Role>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    events: Vec<String>,
    installations: Vec<InstallationEntry>,
    actors: Vec<ActorEntry>,
    #[serde(default)]
    max_body_bytes: Option<usize>,
}

#[derive(Clone, Debug)]
struct ActorGrant {
    actor: ActorRef,
    requester: bool,
    approver: bool,
}

/// Validated allowlists. Only constructible through [`IntakeConfig::from_json`].
#[derive(Clone, Debug)]
pub struct IntakeConfig {
    events: BTreeSet<String>,
    installations: BTreeMap<InstallationId, BTreeSet<RepositoryId>>,
    actors: BTreeMap<GithubUserId, ActorGrant>,
    approvers: BTreeSet<ActorRef>,
    max_body_bytes: usize,
}

impl IntakeConfig {
    /// Parse and validate. Fails closed: unknown fields, empty allowlists,
    /// duplicates, unsupported events and out-of-range limits are rejected.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Malformed);
        }
        let file: ConfigFile = serde_json::from_slice(bytes).map_err(|_| ConfigError::Malformed)?;

        if file.events.is_empty() {
            return Err(ConfigError::NoEvents);
        }
        let mut events = BTreeSet::new();
        for e in &file.events {
            if !SUPPORTED_EVENTS.contains(&e.as_str()) {
                return Err(ConfigError::UnsupportedEvent);
            }
            if !events.insert(e.clone()) {
                return Err(ConfigError::Duplicate);
            }
        }

        if file.installations.is_empty() {
            return Err(ConfigError::NoInstallations);
        }
        let mut installations = BTreeMap::new();
        for entry in &file.installations {
            if entry.repository_ids.is_empty() {
                return Err(ConfigError::NoRepositories);
            }
            let mut repos = BTreeSet::new();
            for r in &entry.repository_ids {
                if !repos.insert(*r) {
                    return Err(ConfigError::Duplicate);
                }
            }
            if installations.insert(entry.installation_id, repos).is_some() {
                return Err(ConfigError::Duplicate);
            }
        }

        if file.actors.is_empty() {
            return Err(ConfigError::NoActors);
        }
        let mut actors = BTreeMap::new();
        let mut approvers = BTreeSet::new();
        let mut refs = BTreeSet::new();
        for entry in &file.actors {
            if entry.roles.is_empty() {
                return Err(ConfigError::ActorRoleMissing);
            }
            let grant = ActorGrant {
                actor: entry.actor.clone(),
                requester: entry.roles.contains(&Role::Requester),
                approver: entry.roles.contains(&Role::Approver),
            };
            if !refs.insert(entry.actor.clone()) {
                return Err(ConfigError::Duplicate);
            }
            if grant.approver {
                approvers.insert(entry.actor.clone());
            }
            if actors.insert(entry.github_user_id, grant).is_some() {
                return Err(ConfigError::Duplicate);
            }
        }

        let max_body_bytes = file.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES);
        if max_body_bytes == 0 || max_body_bytes > HARD_MAX_BODY_BYTES {
            return Err(ConfigError::BodyLimitOutOfRange);
        }

        Ok(Self {
            events,
            installations,
            actors,
            approvers,
            max_body_bytes,
        })
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn event_enabled(&self, event: &str) -> bool {
        self.events.contains(event)
    }

    pub fn installation_allowed(&self, id: InstallationId) -> bool {
        self.installations.contains_key(&id)
    }

    /// True only if the repository is listed under exactly this installation.
    pub fn repository_allowed(&self, installation: InstallationId, repo: RepositoryId) -> bool {
        self.installations
            .get(&installation)
            .is_some_and(|r| r.contains(&repo))
    }

    /// The actor reference for a GitHub user holding the requester role.
    /// Authority is derived here, from the verified sender id and the
    /// allowlist, never from a field the payload or the request asserts.
    pub fn requester(&self, user: GithubUserId) -> Option<&ActorRef> {
        self.actors
            .get(&user)
            .filter(|g| g.requester)
            .map(|g| &g.actor)
    }

    /// Whether this actor reference may be named as an approver.
    pub fn is_approver(&self, actor: &ActorRef) -> bool {
        self.approvers.contains(actor)
    }
}

/// HMAC key for `X-Hub-Signature-256`. Not `Clone`, no `Display`, redacted
/// `Debug`; compared only through [`crate::signature`].
pub struct WebhookSecret {
    bytes: Vec<u8>,
}

impl WebhookSecret {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ConfigError> {
        if bytes.len() < MIN_SECRET_BYTES {
            return Err(ConfigError::SecretTooShort);
        }
        Ok(Self { bytes })
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}
