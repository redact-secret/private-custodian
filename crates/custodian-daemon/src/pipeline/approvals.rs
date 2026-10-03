//! Where a release approval comes from: a file a human placed.
//!
//! A release approval is the second, distinct human decision: it binds one
//! execution, one projection digest and one disclosure policy
//! (`Approval::check_for_release`). The daemon has no way to create one and no
//! setting that waives it. It reads `approvals_dir/<request id>.json`, a
//! regular, non-symlink file that is not group- or other-writable, strictly
//! decoded as an `Approval`. Whether the document is the right one (scope,
//! digest, approver kind, time window, current policy activation) is decided
//! by `DisclosureService::release` and the signer, not here; a document that
//! fails there is kept waiting (the human may replace it), never trusted.
//!
//! The human learns the execution id and the projection digest to bind from
//! the run's status (`custodiand status`).

use std::path::PathBuf;

use custodian_contracts::approval::Approval;
use custodian_contracts::Contract;

const MAX_APPROVAL_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalFile {
    /// The file exists but is not acceptable (symlink, wrong type, too large,
    /// writable by others, not a valid approval document).
    Rejected,
}

pub trait ReleaseApprovals: Send + Sync {
    fn approval_for(&self, request_id: &str) -> Result<Option<Approval>, ApprovalFile>;
}

pub struct DirApprovals {
    dir: PathBuf,
}

impl DirApprovals {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path_of(&self, request_id: &str) -> PathBuf {
        self.dir.join(format!("{request_id}.json"))
    }
}

impl ReleaseApprovals for DirApprovals {
    fn approval_for(&self, request_id: &str) -> Result<Option<Approval>, ApprovalFile> {
        // The id becomes a file name: only the contract's own id shape.
        if custodian_contracts::types::RequestId::parse(request_id).is_err() {
            return Err(ApprovalFile::Rejected);
        }
        let path = self.path_of(request_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ApprovalFile::Rejected),
        }
        let bytes = custodian_cli::deploy::read_checked(&path, MAX_APPROVAL_BYTES, 0o022)
            .map_err(|_| ApprovalFile::Rejected)?;
        Approval::decode(&bytes)
            .map(Some)
            .map_err(|_| ApprovalFile::Rejected)
    }
}
