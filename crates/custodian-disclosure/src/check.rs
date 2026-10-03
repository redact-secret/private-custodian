//! GitHub Check rendering for a disclosure outcome.
//!
//! The Check text is built by `custodian_intake::checks::CheckPost::render`
//! from fixed strings and one core reason code; there is no field for a
//! string from this crate, a worker or a requester. A successful release
//! renders as the neutral "finished" state, which says only that the process
//! ended; the released result itself is never in a Check.

use custodian_intake::checks::{CheckReason, CheckState, CheckUpdate};
use custodian_intake::ids::{HeadSha, InstallationId, RepositoryId};

use crate::reason::DisclosureReason;

pub fn check_update(
    installation: InstallationId,
    repository: RepositoryId,
    head_sha: HeadSha,
    outcome: &Result<(), DisclosureReason>,
) -> CheckUpdate {
    let (state, reason): (CheckState, Option<CheckReason>) = match outcome {
        Ok(()) => (CheckState::Completed, None),
        Err(r) => (r.check_state(), Some(r.check_reason())),
    };
    CheckUpdate {
        installation,
        repository,
        head_sha,
        state,
        reason,
    }
}
