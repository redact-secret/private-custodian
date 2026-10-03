//! Worker protocol v1: the job document the engine receives and the single
//! result document it may print on stdout. Both are versioned, strict and
//! bounded. Worker output is untrusted: this module accepts only the exact
//! shape below and discards everything else, including free-form text.
//!
//! Job (`/job/job.json`, read-only): schema tag, domain, protocol, the
//! authorized roster size and the opaque entry names under `/input`.
//!
//! Result (stdout, at most `MAX_RESULT_BYTES`):
//! `{"schema":"private-custodian.worker-result/1","domain":..,"protocol":
//! {"name":..,"version":..},"status":"complete"|"partial","roster":
//! {"expected":N,"observed":N,"failed":N}}`
//!
//! Engines compute measurements; this module only checks that the claim is
//! well-formed, bound to the frozen domain/protocol, and consistent with the
//! authorized roster. It never interprets a score.

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::{ExecutionOutcome, PrivateArtifactRef, RosterCounts};
use custodian_contracts::types::{Count, ProtocolName, ResultDigest, VersionLabel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reason::{Result, WorkerReason as R};

pub const JOB_SCHEMA: &str = "private-custodian.worker-job/1";
pub const RESULT_SCHEMA: &str = "private-custodian.worker-result/1";
/// Hard cap on the result document, whatever the plan's output limit says.
pub const MAX_RESULT_BYTES: u64 = 64 * 1024;
/// Cap on discarded stderr volume, whatever the plan's output limit says.
pub const MAX_STDERR_BYTES: u64 = 1024 * 1024;

#[derive(Serialize)]
struct WireProtocolOut<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct JobDoc<'a> {
    schema: &'static str,
    domain: EvaluationDomain,
    protocol: WireProtocolOut<'a>,
    roster: u64,
    entries: &'a [String],
}

pub fn job_document(
    domain: EvaluationDomain,
    protocol: &ProtocolRef,
    entries: &[String],
) -> Result<Vec<u8>> {
    serde_json::to_vec(&JobDoc {
        schema: JOB_SCHEMA,
        domain,
        protocol: WireProtocolOut {
            name: protocol.name.as_str(),
            version: protocol.version.as_str(),
        },
        roster: entries.len() as u64,
        entries,
    })
    .map_err(|_| R::StagingFailed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProtocol {
    name: ProtocolName,
    version: VersionLabel,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireStatus {
    Complete,
    Partial,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoster {
    expected: u64,
    observed: u64,
    failed: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResult {
    schema: String,
    domain: EvaluationDomain,
    protocol: WireProtocol,
    status: WireStatus,
    roster: WireRoster,
}

/// A result that passed every check. `raw` is the private artifact and must be
/// stored privately; it is never logged or propagated.
pub struct ValidatedResult {
    pub outcome: ExecutionOutcome,
    pub reason: R,
    pub roster: RosterCounts,
    pub artifact: PrivateArtifactRef,
    raw: Vec<u8>,
}

impl ValidatedResult {
    /// The exact bytes the worker printed, for private storage by the caller.
    pub fn private_bytes(&self) -> &[u8] {
        &self.raw
    }
}

impl core::fmt::Debug for ValidatedResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedResult")
            .field("outcome", &self.outcome)
            .field("roster", &self.roster)
            .finish()
    }
}

/// Validate worker stdout against the frozen domain and protocol and the
/// authorized roster size. Errors are `ResultOversized`, `ResultMalformed`,
/// `ResultMismatch` or `RosterMismatch`; the caller maps all of them to
/// `ExecutionOutcome::Rejected`.
pub fn validate_result(
    stdout: &[u8],
    domain: EvaluationDomain,
    protocol: &ProtocolRef,
    authorized_roster: u64,
) -> Result<ValidatedResult> {
    if stdout.len() as u64 > MAX_RESULT_BYTES {
        return Err(R::ResultOversized);
    }
    let w: WireResult = serde_json::from_slice(stdout).map_err(|_| R::ResultMalformed)?;
    if w.schema != RESULT_SCHEMA {
        return Err(R::ResultMalformed);
    }
    if w.domain != domain
        || w.protocol.name != protocol.name
        || w.protocol.version != protocol.version
    {
        return Err(R::ResultMismatch);
    }
    let r = &w.roster;
    // The roster the engine claims must be exactly the one authorized, and
    // the counters must be internally consistent.
    if r.expected != authorized_roster
        || r.observed > r.expected
        || r.failed > r.observed
        || authorized_roster == 0
    {
        return Err(R::RosterMismatch);
    }
    let complete = r.observed == r.expected;
    match (&w.status, complete) {
        (WireStatus::Complete, true) | (WireStatus::Partial, false) => {}
        _ => return Err(R::RosterMismatch),
    }
    let roster = RosterCounts {
        expected: Count::new(r.expected).map_err(|_| R::RosterMismatch)?,
        observed: Count::new(r.observed).map_err(|_| R::RosterMismatch)?,
        failed: Count::new(r.failed).map_err(|_| R::RosterMismatch)?,
    };
    let (outcome, reason) = if complete && r.failed == 0 {
        (ExecutionOutcome::Success, R::Completed)
    } else {
        // Any shortfall or any failed item is a partial result: recorded,
        // never releasable.
        (ExecutionOutcome::Partial, R::EnginePartial)
    };
    let artifact = PrivateArtifactRef {
        digest: ResultDigest::from_raw(Sha256::digest(stdout).into()),
        size_bytes: Count::new(stdout.len() as u64).map_err(|_| R::ResultOversized)?,
        protocol: protocol.clone(),
    };
    Ok(ValidatedResult {
        outcome,
        reason,
        roster,
        artifact,
        raw: stdout.to_vec(),
    })
}
