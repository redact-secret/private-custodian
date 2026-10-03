//! Offline remote result binding experiment. No AWS client, authorization,
//! exposure, accounting or isolation authority is implemented here.
//! An authenticated control-plane transport must provide the current binding;
//! worker-supplied identities alone never constitute trusted attestation.

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::types::{
    ApprovalId, ArtifactDigest, BoundedVec, CandidateDigest, ConfigDigest, Count, ExecutionId,
    PlanDigest, RequestId, ReservationId, Seq, VersionLabel,
};
use custodian_worker::result::{validate_result, ValidatedResult, MAX_RESULT_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RESULT_ENVELOPE_SCHEMA: &str = "private-custodian.remote-result/1";
// JSON byte arrays can expand one byte into four characters plus a comma.
pub const MAX_ENVELOPE_BYTES: usize = MAX_RESULT_BYTES as usize * 5 + 4096;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBinding {
    pub request: RequestId,
    pub approval: ApprovalId,
    pub reservation: ReservationId,
    pub execution: ExecutionId,
    pub attempt: Count<16>,
    pub fence: Seq,
    pub plan_digest: PlanDigest,
    pub candidate_digest: CandidateDigest,
    pub image_digest: ArtifactDigest,
    pub image_version: VersionLabel,
    pub engine_digest: ArtifactDigest,
    pub adapter_digest: ArtifactDigest,
    pub config_digest: ConfigDigest,
    pub scanner_digests: BoundedVec<ArtifactDigest, 8>,
    pub job_digest: ArtifactDigest,
}

impl AttemptBinding {
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.attempt.get() == 0 || self.fence.get() == 0 || self.scanner_digests.is_empty() {
            return Err(Refusal::BindingInvalid);
        }
        Ok(())
    }

    /// Check the exact staged job bytes, never a reserialized substitute.
    pub fn check_job(&self, bytes: &[u8]) -> Result<(), Refusal> {
        self.validate()?;
        if bytes.is_empty() || bytes.len() > MAX_RESULT_BYTES as usize {
            return Err(Refusal::Oversized);
        }
        if self.job_digest.as_str() != sha256(bytes) {
            return Err(Refusal::BindingMismatch);
        }
        Ok(())
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultEnvelope {
    pub schema: String,
    pub binding: AttemptBinding,
    /// Exact stdout bytes; bounded and private, never logged.
    pub stdout: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Oversized,
    Malformed,
    BindingInvalid,
    BindingMismatch,
    WorkerResultInvalid,
}

/// Transport authentication and a live fenced lease are prerequisites supplied
/// by the caller, not established by this parser. This function cannot release
/// a projection, charge/refund a budget or mark isolation as verified.
pub fn decode_result(
    bytes: &[u8],
    expected: &AttemptBinding,
    domain: EvaluationDomain,
    protocol: &ProtocolRef,
    roster: u64,
) -> Result<ValidatedResult, Refusal> {
    expected.validate()?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Refusal::Oversized);
    }
    let envelope: ResultEnvelope = serde_json::from_slice(bytes).map_err(|_| Refusal::Malformed)?;
    if envelope.schema != RESULT_ENVELOPE_SCHEMA {
        return Err(Refusal::Malformed);
    }
    envelope.binding.validate()?;
    if &envelope.binding != expected {
        return Err(Refusal::BindingMismatch);
    }
    if envelope.stdout.len() as u64 > MAX_RESULT_BYTES {
        return Err(Refusal::Oversized);
    }
    // Reuse the existing result/aggregate transport. No second validator,
    // canonicalization, metric calculation or scratch-file collector.
    validate_result(&envelope.stdout, domain, protocol, roster)
        .map_err(|_| Refusal::WorkerResultInvalid)
}
