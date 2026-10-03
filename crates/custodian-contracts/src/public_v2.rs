//! Public projection major 2: the destination is inside the signed payload.
//!
//! v1 (`public::PublicProjection`) has no destination field, so a consumer
//! holding only the envelope cannot tell which destination a projection was
//! approved for. v2 adds `destination` (a bounded label from the disclosure
//! policy's allowlisted vocabulary, never a URL) under schema tag
//! `private-custodian.public-projection/2` and domain tag
//! `private-custodian/v2/public-projection`, so v1 and v2 documents can never
//! share a digest or a signing input, and relabelling one as the other breaks
//! decoding and the signature (ADR 0119, `docs/contracts.md` section 8).
//!
//! v1 is never reinterpreted: it stays decodable and verifiable under its own
//! rules, and [`AnyProjectionEnvelope`] reports it as having no destination
//! binding. Nothing here converts a stored v1 record into a v2 record.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{
    domain_digest, to_canonical_bytes, Contract, DomainTag, MAX_DOCUMENT_BYTES,
};
use crate::common::*;
use crate::error::ContractError;
use crate::public::{
    validate_common, AggregateCell, FeedRef, PublicPopulationRef, PublicProjection,
    PublicProjectionEnvelope, PublicProjectionSchema, ScopeKind,
};
use crate::types::*;

schema_tag!(
    /// Schema tag for `PublicProjectionV2`.
    PublicProjectionSchemaV2,
    "private-custodian.public-projection/2"
);

/// Public projection v2: every v1 field plus the signed `destination`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicProjectionV2 {
    pub schema: PublicProjectionSchemaV2,
    pub projection_id: ProjectionId,
    /// Public receipt identity (random, unrelated to internal ids).
    pub receipt_id: ReceiptId,
    /// The destination this projection was approved for. A bounded label
    /// from the disclosure policy's destination allowlist. Covered by the
    /// signature and by the projection digest the release approval binds.
    pub destination: DestinationId,
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

impl Contract for PublicProjectionV2 {
    const DOMAIN: DomainTag = DomainTag::PublicProjectionV2;

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

impl PublicProjectionV2 {
    /// Build a v2 projection from the version-neutral fields of a freshly
    /// built projection and the destination it is being prepared for. Used
    /// when producing new releases; it never touches a stored v1 record.
    pub fn bind(fields: &PublicProjection, destination: DestinationId) -> Self {
        Self {
            schema: PublicProjectionSchemaV2,
            projection_id: fields.projection_id.clone(),
            receipt_id: fields.receipt_id.clone(),
            destination,
            domain: fields.domain,
            population: fields.population.clone(),
            candidate: fields.candidate.clone(),
            engine: fields.engine.clone(),
            protocol: fields.protocol.clone(),
            scope_kind: fields.scope_kind,
            disclosure_policy: fields.disclosure_policy.clone(),
            attestation: fields.attestation.clone(),
            cells: fields.cells.clone(),
            issued_at: fields.issued_at,
            fresh_until: fields.fresh_until,
            revocation_feed: fields.revocation_feed.clone(),
        }
    }

    /// The version-neutral fields, in the v1 shape. A derived *view* for code
    /// that only needs the common fields (revocation matching, feed
    /// tracking). It is not a signable or digestible document of the v2
    /// projection: its schema tag is the v1 tag and its digest is not the
    /// projection digest. Use [`Self::projection_digest`] for that.
    pub fn common_fields(&self) -> PublicProjection {
        PublicProjection {
            schema: PublicProjectionSchema,
            projection_id: self.projection_id.clone(),
            receipt_id: self.receipt_id.clone(),
            domain: self.domain,
            population: self.population.clone(),
            candidate: self.candidate.clone(),
            engine: self.engine.clone(),
            protocol: self.protocol.clone(),
            scope_kind: self.scope_kind,
            disclosure_policy: self.disclosure_policy.clone(),
            attestation: self.attestation.clone(),
            cells: self.cells.clone(),
            issued_at: self.issued_at,
            fresh_until: self.fresh_until,
            revocation_feed: self.revocation_feed.clone(),
        }
    }

    /// Domain-separated digest of this payload under the v2 tag. This is
    /// what a release approval binds to, destination included.
    pub fn projection_digest(&self) -> Result<ProjectionDigest, ContractError> {
        Ok(ProjectionDigest::from_raw(domain_digest(
            DomainTag::PublicProjectionV2,
            &to_canonical_bytes(self)?,
        )))
    }
}

/// Signed v2 projection: payload plus signature over `payload.signing_input()`
/// (domain `private-custodian/v2/public-projection`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicProjectionEnvelopeV2 {
    pub payload: PublicProjectionV2,
    pub signature: Signature,
}

impl PublicProjectionEnvelopeV2 {
    /// Strict parse of an untrusted v2 envelope. Accepts exactly major 2.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::Oversized);
        }
        let env: Self = serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        env.payload.validate()?;
        Ok(env)
    }
}

/// Whether a verified projection proves which destination it was approved for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DestinationBinding {
    /// v2: the destination is in the signed payload.
    Bound,
    /// v1: the envelope carries no destination. Authentic and unchanged, but
    /// the destination cannot be verified from it. Never treat as bound.
    Unbound,
}

impl DestinationBinding {
    /// Stable machine code for an unbound release, shared by consumers.
    pub const UNBOUND_CODE: &'static str = "destination_unbound";

    pub fn is_bound(self) -> bool {
        self == Self::Bound
    }
}

/// A projection envelope of either supported major. The enum never merges the
/// two: each arm is decoded, hashed and verified under its own rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyProjectionEnvelope {
    V1(PublicProjectionEnvelope),
    V2(PublicProjectionEnvelopeV2),
}

impl AnyProjectionEnvelope {
    /// Strict parse that picks the decoder from the payload's schema tag and
    /// then applies that major's closed decoder. Any other tag, an unknown
    /// field, a missing field (a v1 body relabelled v2) or an extra field (a
    /// v2 body relabelled v1) is rejected. The error never echoes input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::Oversized);
        }
        let v: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        let tag = v
            .pointer("/payload/schema")
            .and_then(serde_json::Value::as_str)
            .ok_or(ContractError::Malformed)?;
        if tag == PublicProjectionSchema::VALUE {
            PublicProjectionEnvelope::decode(bytes).map(Self::V1)
        } else if tag == PublicProjectionSchemaV2::VALUE {
            PublicProjectionEnvelopeV2::decode(bytes).map(Self::V2)
        } else {
            Err(ContractError::Malformed)
        }
    }

    pub fn major(&self) -> u32 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }

    pub fn binding(&self) -> DestinationBinding {
        match self {
            Self::V1(_) => DestinationBinding::Unbound,
            Self::V2(_) => DestinationBinding::Bound,
        }
    }

    /// The signed destination; `None` for v1, which has none.
    pub fn destination(&self) -> Option<&DestinationId> {
        match self {
            Self::V1(_) => None,
            Self::V2(e) => Some(&e.payload.destination),
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            Self::V1(e) => &e.signature,
            Self::V2(e) => &e.signature,
        }
    }

    /// The version-neutral fields (see [`PublicProjectionV2::common_fields`]).
    pub fn common_fields(&self) -> PublicProjection {
        match self {
            Self::V1(e) => e.payload.clone(),
            Self::V2(e) => e.payload.common_fields(),
        }
    }

    /// The digest under this envelope's own domain tag.
    pub fn projection_digest(&self) -> Result<ProjectionDigest, ContractError> {
        match self {
            Self::V1(e) => e.payload.projection_digest(),
            Self::V2(e) => e.payload.projection_digest(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(e) => to_canonical_bytes(e),
            Self::V2(e) => to_canonical_bytes(e),
        }
    }
}
