//! Public projection envelope: the only receipt-like contract that leaves the
//! private boundary.
//!
//! Everything here is an allowlist. There is no free-form string, no list of
//! case or file identities, no value-level hash, no seed, no internal plan or
//! corpus identity, and no raw range or error text. A field not declared here
//! cannot be added without a new schema version. Counts are integers; ratios
//! are computed downstream. See `docs/contracts.md` for the leakage rules.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{
    domain_digest, to_canonical_bytes, Contract, DomainTag, MAX_DOCUMENT_BYTES,
};
use crate::common::*;
use crate::error::ContractError;
use crate::types::*;

schema_tag!(
    /// Schema tag for `PublicProjection` v1. v1 carries no destination: see
    /// `public_v2` for the major that does (ADR 0119).
    PublicProjectionSchema,
    "private-custodian.public-projection/1"
);

/// Longest freshness window a projection may carry.
pub const MAX_PROJECTION_FRESHNESS_SECS: u64 = 30 * 24 * 60 * 60;

/// Disclosure-safe population identity. Either a random opaque reference or a
/// keyed commitment; never a plain hash of population content.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicPopulationRef {
    Opaque {
        id: PublicPopulationId,
    },
    KeyedCommitment {
        key_id: KeyId,
        commitment: KeyedCommitment,
    },
}

/// Which budget semantics produced the run, without any internal identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    PopulationEpoch,
    CandidateLineageEpoch,
}

/// Where a consumer finds revocation state for this projection, and the
/// oldest feed state it must have seen to rely on it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedRef {
    pub feed_id: FeedId,
    pub min_sequence: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CellValue {
    Reported {
        numerator: Seq,
        denominator: Seq,
    },
    /// Withheld by the disclosure policy (small cell or composition rule).
    /// Carries no value, bound or hint.
    Suppressed {},
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AggregateCell {
    pub stratum: StratumId,
    pub metric: MetricId,
    pub value: CellValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicProjection {
    pub schema: PublicProjectionSchema,
    pub projection_id: ProjectionId,
    /// Public receipt identity (random, unrelated to internal ids).
    pub receipt_id: ReceiptId,
    pub domain: EvaluationDomain,
    pub population: PublicPopulationRef,
    pub candidate: CandidateDigest,
    pub engine: ArtifactIdentity,
    pub protocol: ProtocolRef,
    pub scope_kind: ScopeKind,
    pub disclosure_policy: PolicyRef,
    pub attestation: Attestation,
    pub cells: BoundedVec<AggregateCell, 256>,
    pub issued_at: Timestamp,
    /// The projection is not to be relied on after this time even if no
    /// revocation was published.
    pub fresh_until: Timestamp,
    pub revocation_feed: FeedRef,
}

impl Contract for PublicProjection {
    const DOMAIN: DomainTag = DomainTag::PublicProjection;

    fn validate(&self) -> Result<(), ContractError> {
        validate_common(
            self.domain,
            &self.protocol,
            &self.disclosure_policy,
            self.issued_at,
            self.fresh_until,
            &self.cells,
        )
    }
}

/// Cross-field checks shared by every projection major, so v1 and v2 can
/// never drift apart on what a well-formed projection is.
pub(crate) fn validate_common(
    domain: EvaluationDomain,
    protocol: &ProtocolRef,
    disclosure_policy: &PolicyRef,
    issued_at: Timestamp,
    fresh_until: Timestamp,
    cells: &BoundedVec<AggregateCell, 256>,
) -> Result<(), ContractError> {
    if protocol.domain != domain || disclosure_policy.domain != domain {
        return Err(ContractError::Inconsistent);
    }
    if disclosure_policy.kind != PolicyKind::Disclosure {
        return Err(ContractError::Inconsistent);
    }
    if fresh_until <= issued_at
        || fresh_until.secs() - issued_at.secs() > MAX_PROJECTION_FRESHNESS_SECS
    {
        return Err(ContractError::Inconsistent);
    }
    let mut seen = std::collections::BTreeSet::new();
    for cell in cells.as_slice() {
        if !seen.insert((cell.stratum.as_str(), cell.metric.as_str())) {
            return Err(ContractError::Inconsistent);
        }
        if let CellValue::Reported {
            numerator,
            denominator,
        } = &cell.value
        {
            if numerator > denominator {
                return Err(ContractError::Inconsistent);
            }
        }
    }
    Ok(())
}

impl PublicProjection {
    /// Domain-separated digest of this payload. This is what a release
    /// approval binds to.
    pub fn projection_digest(&self) -> Result<ProjectionDigest, ContractError> {
        Ok(ProjectionDigest::from_raw(domain_digest(
            DomainTag::PublicProjection,
            &to_canonical_bytes(self)?,
        )))
    }
}

/// Signed public projection: payload plus signature over
/// `payload.signing_input()` (domain `public-projection`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicProjectionEnvelope {
    pub payload: PublicProjection,
    pub signature: Signature,
}

impl PublicProjectionEnvelope {
    /// Strict parse of an untrusted envelope (size cap, no unknown fields,
    /// payload validation). Signature verification is C7.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::Oversized);
        }
        let env: Self = serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        env.payload.validate()?;
        Ok(env)
    }
}
