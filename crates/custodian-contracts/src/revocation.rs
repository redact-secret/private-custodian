//! Public revocation and supersession envelope, and the consumer-side
//! standing check.
//!
//! Benchmarks cannot read the private ledger. It holds a signed, chained,
//! freshness-bounded feed of these envelopes instead. A projection is usable
//! only if the consumer holds a fresh enough feed that does not revoke it.
//! Possession of a valid signed projection never overrides the feed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{Contract, DomainTag, MAX_DOCUMENT_BYTES};
use crate::common::{PolicyRef, Signature};
use crate::error::ContractError;
use crate::public::{PublicPopulationRef, PublicProjection};
use crate::types::*;

schema_tag!(
    /// Schema tag for `RevocationEnvelope` v1.
    RevocationSchema,
    "private-custodian.revocation-envelope/1"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationTarget {
    Projection {
        projection_id: ProjectionId,
    },
    Receipt {
        receipt_id: ReceiptId,
    },
    /// Every projection of this candidate digest.
    Candidate {
        candidate: CandidateDigest,
    },
    /// Every projection of this public population (for example a
    /// contaminated epoch).
    Population {
        population: PublicPopulationRef,
    },
    /// Every projection released under this disclosure policy version.
    Policy {
        policy: PolicyRef,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationAction {
    Revoked {},
    /// Evidence from a contaminated epoch. Stays invalid for independent
    /// qualification; it is never cleared by a later entry.
    Contaminated {},
    Superseded {
        superseded_by: ProjectionId,
    },
}

/// Fixed reasons only. Free-form text is not representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicRevocationReason {
    Contamination,
    EpochRotation,
    KeyCompromise,
    PolicyRevoked,
    ErrorCorrection,
    NewerEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    pub target: RevocationTarget,
    pub action: RevocationAction,
    pub reason: PublicRevocationReason,
    pub effective_at: Timestamp,
}

/// One link of the feed. Entries are cumulative across the chain; an entry is
/// never removed by a later envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationEnvelope {
    pub schema: RevocationSchema,
    pub feed_id: FeedId,
    /// 1-based, strictly increasing by one.
    pub sequence: Seq,
    /// Digest of the previous envelope (`Contract::document_digest`); absent
    /// exactly when `sequence` is 1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::some_only"
    )]
    pub previous: Option<DocumentDigest>,
    pub issued_at: Timestamp,
    /// Consumers must treat the feed as stale after this time. An issuer
    /// publishes an empty envelope to renew freshness.
    pub fresh_until: Timestamp,
    pub entries: BoundedVec<RevocationEntry, 128>,
}

impl Contract for RevocationEnvelope {
    const DOMAIN: DomainTag = DomainTag::RevocationEnvelope;

    fn validate(&self) -> Result<(), ContractError> {
        if self.sequence.get() == 0
            || (self.sequence.get() == 1) != self.previous.is_none()
            || self.fresh_until <= self.issued_at
        {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocationEnvelope {
    pub payload: RevocationEnvelope,
    pub signature: Signature,
}

impl SignedRevocationEnvelope {
    /// Strict parse of an untrusted envelope. Signature verification is C7.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::Oversized);
        }
        let env: Self = serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        env.payload.validate()?;
        Ok(env)
    }
}

/// Whether a projection may be relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Standing {
    Valid,
    /// Past its own `fresh_until`.
    Expired,
    /// The consumer's feed state is missing, too old or for another feed.
    /// Fails closed: unknown is not valid.
    Stale,
    Superseded,
    Revoked,
}

impl Standing {
    pub fn is_usable(self) -> bool {
        self == Self::Valid
    }
}

/// Consumer-side accumulated feed state. The caller must have verified each
/// envelope's signature before `apply`; this type checks chain integrity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationLog {
    feed_id: FeedId,
    sequence: u64,
    head: Option<DocumentDigest>,
    fresh_until: Timestamp,
    entries: Vec<RevocationEntry>,
}

impl RevocationLog {
    pub fn new(feed_id: FeedId) -> Self {
        Self {
            feed_id,
            sequence: 0,
            head: None,
            fresh_until: Timestamp::ZERO,
            entries: Vec::new(),
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Append the next envelope. Rejects another feed, a gap, a replay and a
    /// broken `previous` link.
    pub fn apply(&mut self, env: &RevocationEnvelope) -> Result<(), ContractError> {
        env.validate()?;
        if env.feed_id != self.feed_id
            || env.sequence.get() != self.sequence + 1
            || env.previous != self.head
        {
            return Err(ContractError::Inconsistent);
        }
        self.head = Some(env.document_digest()?);
        self.sequence = env.sequence.get();
        self.fresh_until = env.fresh_until;
        self.entries.extend(env.entries.as_slice().iter().cloned());
        Ok(())
    }

    fn matches(target: &RevocationTarget, p: &PublicProjection) -> bool {
        match target {
            RevocationTarget::Projection { projection_id } => *projection_id == p.projection_id,
            RevocationTarget::Receipt { receipt_id } => *receipt_id == p.receipt_id,
            RevocationTarget::Candidate { candidate } => *candidate == p.candidate,
            RevocationTarget::Population { population } => *population == p.population,
            RevocationTarget::Policy { policy } => *policy == p.disclosure_policy,
        }
    }

    /// Standing of `p` at `now`. Revocation and contamination are decided
    /// first and from whatever feed state is held, so a stale feed can still
    /// revoke but never validate.
    pub fn standing(&self, p: &PublicProjection, now: Timestamp) -> Standing {
        let hits = || {
            self.entries
                .iter()
                .filter(|e| e.effective_at <= now && Self::matches(&e.target, p))
        };
        if hits().any(|e| !matches!(e.action, RevocationAction::Superseded { .. })) {
            return Standing::Revoked;
        }
        if hits().any(|e| matches!(e.action, RevocationAction::Superseded { .. })) {
            return Standing::Superseded;
        }
        if self.feed_id != p.revocation_feed.feed_id
            || self.sequence < p.revocation_feed.min_sequence.get()
            || now > self.fresh_until
            || now < p.issued_at
        {
            return Standing::Stale;
        }
        if now >= p.fresh_until {
            return Standing::Expired;
        }
        Standing::Valid
    }
}
