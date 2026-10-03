//! Where the daemon finds the things a queued pull request refers to but does
//! not carry: the request document, the candidate staged for the commit, and
//! the pinned artifacts a plan names.
//!
//! The webhook delivers identifiers only. A requester provides the
//! `EvaluationRequest` document for a commit out of band, the control plane's
//! staging step records which candidate and configuration bytes it staged from
//! that commit, and the engine, adapter, scanners, candidate and configuration
//! are files named by their digest. All of it is read from directories the
//! deployment owns, never from anything in the webhook, and every file is a
//! regular, non-symlink, bounded, not-group-or-other-writable file. A pull
//! request author controls none of it.
//!
//! The content of a pinned artifact is verified against the plan's digest by
//! the dispatcher before any protected input is touched (twice more after);
//! this module only finds the file.

use std::path::{Path, PathBuf};

use custodian_contracts::request::EvaluationPlan;
use custodian_contracts::types::{CandidateDigest, ConfigDigest};
use custodian_intake::gate::StagedCandidate;
use custodian_intake::ids::HeadSha;
use custodian_intake::ports::QueuedRequest;
use custodian_worker::ArtifactSources;
use serde::Deserialize;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_STAGED_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// A file exists but is not acceptable (symlink, wrong type, too large,
    /// group- or other-writable, malformed). Not a transient condition.
    Rejected,
    /// Reading failed for a reason that may pass.
    Unavailable,
}

pub trait RequestSource: Send + Sync {
    /// The canonical request document for the commit a queued item names, or
    /// `None` if none has been provided yet.
    fn request_for(&self, queued: &QueuedRequest) -> Result<Option<Vec<u8>>, SourceError>;
}

pub trait CandidateStager: Send + Sync {
    /// The candidate and configuration the control plane staged from the
    /// commit, or `None` if nothing is staged for it.
    fn staged(&self, queued: &QueuedRequest) -> Result<Option<StagedCandidate>, SourceError>;
}

/// Read a file the deployment owns; `None` if it does not exist.
fn read_optional(path: &Path, max: usize) -> Result<Option<Vec<u8>>, SourceError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => custodian_cli::deploy::read_checked(path, max, 0o022)
            .map(Some)
            .map_err(|_| SourceError::Rejected),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SourceError::Unavailable),
    }
}

/// `requests_dir/<repository id>-<pull request>-<head sha>.json`.
pub struct DirRequestSource {
    dir: PathBuf,
}

impl DirRequestSource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The file name a requester places the document under.
    pub fn file_name(q: &QueuedRequest) -> String {
        format!(
            "{}-{}-{}.json",
            q.repository.get(),
            q.pull_request.get(),
            q.head_sha.as_str()
        )
    }
}

impl RequestSource for DirRequestSource {
    fn request_for(&self, q: &QueuedRequest) -> Result<Option<Vec<u8>>, SourceError> {
        read_optional(&self.dir.join(Self::file_name(q)), MAX_REQUEST_BYTES)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedFile {
    schema: String,
    head_sha: String,
    candidate: CandidateDigest,
    config_digest: ConfigDigest,
}

pub const STAGED_SCHEMA: &str = "private-custodian.staged-candidate/1";

/// `artifacts_dir/commits/<head sha>.json`, written by the staging step.
pub struct DirStager {
    dir: PathBuf,
}

impl DirStager {
    pub fn new(artifacts_dir: &Path) -> Self {
        Self {
            dir: artifacts_dir.join("commits"),
        }
    }
}

impl CandidateStager for DirStager {
    fn staged(&self, q: &QueuedRequest) -> Result<Option<StagedCandidate>, SourceError> {
        let path = self.dir.join(format!("{}.json", q.head_sha.as_str()));
        let Some(bytes) = read_optional(&path, MAX_STAGED_BYTES)? else {
            return Ok(None);
        };
        let f: StagedFile = serde_json::from_slice(&bytes).map_err(|_| SourceError::Rejected)?;
        let head = HeadSha::parse(&f.head_sha).map_err(|_| SourceError::Rejected)?;
        if f.schema != STAGED_SCHEMA || head != q.head_sha {
            return Err(SourceError::Rejected);
        }
        Ok(Some(StagedCandidate {
            head_sha: head,
            candidate: f.candidate,
            config_digest: f.config_digest,
        }))
    }
}

/// Finds the pinned artifacts of a plan by digest: `artifacts_dir/<64 hex>`.
pub struct DirArtifacts {
    dir: PathBuf,
}

impl DirArtifacts {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn find(&self, digest: &str) -> Result<PathBuf, SourceError> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or(SourceError::Rejected)?;
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(SourceError::Rejected);
        }
        let p = self.dir.join(hex);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_file() => Ok(p),
            Ok(_) => Err(SourceError::Rejected),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SourceError::Unavailable),
            Err(_) => Err(SourceError::Unavailable),
        }
    }

    /// Where each artifact of `plan` lives. `Unavailable` if any is missing.
    pub fn sources_for(&self, plan: &EvaluationPlan) -> Result<ArtifactSources, SourceError> {
        let mut scanners = Vec::new();
        for s in plan.scanners.as_slice() {
            scanners.push(self.find(s.digest.as_str())?);
        }
        Ok(ArtifactSources {
            engine: self.find(plan.engine.digest.as_str())?,
            adapter: self.find(plan.adapter.digest.as_str())?,
            scanners,
            candidate: self.find(plan.candidate.as_str())?,
            config: self.find(plan.config_digest.as_str())?,
        })
    }
}
