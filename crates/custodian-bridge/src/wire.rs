//! The bridge wire contract: a request from benchmarks and the response
//! manifest (ADR 0090).
//!
//! Both are closed, bounded, allowlisted and canonical (the same
//! `custodian-canonical-json/1` the contracts use), and both are versioned by
//! their schema tag. A reader of major 1 accepts exactly major 1.
//!
//! The request names what benchmarks froze, in public terms only: the
//! evaluation domain, the candidate digest, the digest of the frozen
//! configuration, the revocation feed it pins, how far it has read that feed
//! and, optionally, the public population references it is willing to accept.
//! There is no free text, no path, no internal identity and no credential.
//!
//! The response is a manifest plus separately canonical documents (released
//! projection envelopes and revocation envelopes). The manifest is unsigned
//! and untrusted: it routes the answer to the request that asked for it.
//! Everything a consumer relies on is a document with its own signature.

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::EvaluationDomain;
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::types::{
    BoundedVec, CandidateDigest, ConfigDigest, DestinationId, DocumentDigest, FeedId,
    ProjectionDigest, Seq,
};
use custodian_contracts::ContractError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tag::schema_tag;

schema_tag!(
    /// Schema tag for `BridgeRequest` v1.
    BridgeRequestSchema,
    "private-custodian.bridge-request/1"
);
schema_tag!(
    /// Schema tag for `BridgeManifest` v1.
    BridgeManifestSchema,
    "private-custodian.bridge-response/1"
);

/// Domain-separation string for bridge digests. Bridge documents are not
/// signed; the digest only binds a response to the request it answers.
pub const BRIDGE_DOMAIN: &str = "private-custodian/v1/bridge";

/// Largest request, in bytes. Smaller than the contract cap on purpose: a
/// request is a handful of digests.
pub const MAX_REQUEST_BYTES: usize = 4_096;
/// Largest manifest, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 8_192;
/// Most population references a request may list.
pub const MAX_POPULATION_FILTER: usize = 8;
/// Most projections one response may carry.
pub const MAX_PROJECTIONS: usize = 16;
/// Most revocation envelopes one response may carry.
pub const MAX_REVOCATIONS: usize = 32;
/// Largest single document inside a response (the contract cap).
pub const MAX_DOCUMENT_BYTES: usize = custodian_contracts::MAX_DOCUMENT_BYTES;

/// What benchmarks asks the custodian for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeRequest {
    pub schema: BridgeRequestSchema,
    pub domain: EvaluationDomain,
    /// The frozen candidate: SHA-256 of the exact candidate bytes.
    pub candidate: CandidateDigest,
    /// The frozen configuration digest benchmarks holds for that candidate.
    /// The custodian uses it to find the approved release; it is not in the
    /// public projection, so a consumer cannot check it there.
    pub config: ConfigDigest,
    /// The revocation feed benchmarks has pinned.
    pub feed_id: FeedId,
    /// The last feed sequence benchmarks has verified (0 for none).
    pub known_sequence: Seq,
    /// Public population references benchmarks will accept. Empty means any
    /// population the product pins on its own side.
    pub populations: BoundedVec<PublicPopulationRef, MAX_POPULATION_FILTER>,
}

impl BridgeRequest {
    /// Strict parse of untrusted bytes: size cap, closed schema, canonical
    /// form, consistency.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ContractError::Oversized);
        }
        let req: Self = serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        req.validate()?;
        if req.canonical_bytes()? != bytes {
            return Err(ContractError::NonCanonical);
        }
        Ok(req)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let mut seen = Vec::new();
        for p in self.populations.as_slice() {
            if seen.contains(&p) {
                return Err(ContractError::Inconsistent);
            }
            seen.push(p);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let bytes = to_canonical_bytes(self)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ContractError::Oversized);
        }
        Ok(bytes)
    }

    /// Domain-separated digest of the canonical request: what a response says
    /// it answers.
    pub fn digest(&self) -> Result<DocumentDigest, ContractError> {
        bridge_digest(&self.canonical_bytes()?)
    }
}

/// How the custodian answered, as an index. Unsigned and untrusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeManifest {
    pub schema: BridgeManifestSchema,
    /// Digest of the request this answers.
    pub request_digest: DocumentDigest,
    pub feed_id: FeedId,
    /// The channel this answer was prepared for. An unsigned routing label,
    /// not a proof. A v2 projection proves its own destination inside its
    /// signed payload (ADR 0119); a v1 projection proves none.
    pub destination: DestinationId,
    /// Digests of the projection payloads included, in order.
    pub projections: BoundedVec<ProjectionDigest, MAX_PROJECTIONS>,
    /// First and last feed sequence included. Both 0 when none is.
    pub first_sequence: Seq,
    pub last_sequence: Seq,
}

impl BridgeManifest {
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ContractError::Oversized);
        }
        let m: Self = serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        m.validate()?;
        if m.canonical_bytes()? != bytes {
            return Err(ContractError::NonCanonical);
        }
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let (a, b) = (self.first_sequence.get(), self.last_sequence.get());
        if (a == 0) != (b == 0) || a > b {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let bytes = to_canonical_bytes(self)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ContractError::Oversized);
        }
        Ok(bytes)
    }
}

fn bridge_digest(canonical: &[u8]) -> Result<DocumentDigest, ContractError> {
    let mut h = Sha256::new();
    h.update(BRIDGE_DOMAIN.as_bytes());
    h.update([0u8]);
    h.update(canonical);
    Ok(DocumentDigest::from_raw(h.finalize().into()))
}

/// A response as it travels: the manifest and the canonical bytes of each
/// document. Nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeResponse {
    pub manifest: BridgeManifest,
    /// Canonical projection envelope bytes (major 1 or 2, see
    /// `AnyProjectionEnvelope`), one per manifest entry.
    pub projections: Vec<Vec<u8>>,
    /// Canonical `SignedRevocationEnvelope` bytes, ascending sequence.
    pub revocations: Vec<Vec<u8>>,
}

impl BridgeResponse {
    /// Assemble a response from the bytes received: the manifest is strictly
    /// decoded, the documents are kept as bytes for the consumer to verify.
    pub fn from_wire(
        manifest: &[u8],
        projections: Vec<Vec<u8>>,
        revocations: Vec<Vec<u8>>,
    ) -> Result<Self, ContractError> {
        let r = Self {
            manifest: BridgeManifest::decode(manifest)?,
            projections,
            revocations,
        };
        r.check_bounds()?;
        Ok(r)
    }

    /// Size and count bounds. A response over any bound is not parsed further.
    pub fn check_bounds(&self) -> Result<(), ContractError> {
        if self.projections.len() > MAX_PROJECTIONS
            || self.revocations.len() > MAX_REVOCATIONS
            || self.projections.len() != self.manifest.projections.len()
        {
            return Err(ContractError::Oversized);
        }
        if self
            .projections
            .iter()
            .chain(self.revocations.iter())
            .any(|d| d.len() > MAX_DOCUMENT_BYTES)
        {
            return Err(ContractError::Oversized);
        }
        Ok(())
    }
}
