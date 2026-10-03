//! The seal record: what a sealed epoch binds (ADR 0031).
//!
//! A seal binds the population binding (including the exact corpus
//! commitment), the frozen configuration digest, the budget scope, the
//! provenance of the data, and the review attestation, in one canonical
//! document whose digest is recorded in the registry. It attests origin and
//! binding. It does not prove that expectations are true or that review was
//! independent: the attestation vocabulary is the C2 one and organizational
//! independence stays `not_claimed`.

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{Attestation, BudgetScope, PopulationBinding, ReviewStatus};
use custodian_contracts::types::{
    ActorRef, ComponentName, ConfigDigest, DocumentDigest, Timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reason::{Result, StorageReason as R};

pub const SEAL_DOMAIN: &str = "private-custodian/v1/corpus-seal";
pub const SEAL_VERSION: u32 = 1;
pub const MAX_SEAL_DOC_BYTES: usize = 65_536;

/// Where the data comes from. Only synthetic or documented-public values are
/// representable; there is deliberately no "real" variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceOrigin {
    SyntheticAuthored,
    SyntheticGenerated,
    PublicTestValues,
    AuthorityReservedSynthetic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub origin: ProvenanceOrigin,
    /// Name of the generator or authoring procedure, if any.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "custodian_contracts::types::some_only"
    )]
    pub generator: Option<ComponentName>,
    /// When the provenance claim was observed.
    pub observed_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRecord {
    pub reviewer: ActorRef,
    pub reviewed_at: Timestamp,
    pub attestation: Attestation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRecord {
    pub seal_version: u32,
    pub binding: PopulationBinding,
    pub config_digest: ConfigDigest,
    pub budget: BudgetScope,
    pub provenance: Provenance,
    pub review: ReviewRecord,
    pub sealed_by: ActorRef,
    pub sealed_at: Timestamp,
    pub entry_count: u64,
    pub total_bytes: u64,
}

impl SealRecord {
    /// Cross-field rules that types cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.seal_version != SEAL_VERSION {
            return Err(R::SealInvalid);
        }
        if self.review.attestation.review == ReviewStatus::NotReviewed {
            return Err(R::ReviewMissing);
        }
        if !self.budget.covers(&self.binding) {
            return Err(R::BindingMismatch);
        }
        if self.entry_count == 0 {
            return Err(R::EmptyCorpus);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let b = to_canonical_bytes(self).map_err(|_| R::SealInvalid)?;
        if b.len() > MAX_SEAL_DOC_BYTES {
            return Err(R::TooLarge);
        }
        Ok(b)
    }

    /// Strict parse: typed (unknown fields rejected), valid, and
    /// byte-identical to the canonical encoding.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SEAL_DOC_BYTES {
            return Err(R::TooLarge);
        }
        let s: Self = serde_json::from_slice(bytes).map_err(|_| R::SealInvalid)?;
        s.validate()?;
        if s.canonical_bytes()? != bytes {
            return Err(R::SealInvalid);
        }
        Ok(s)
    }
}

/// Domain-separated digest of canonical seal bytes.
pub fn seal_digest(canonical: &[u8]) -> DocumentDigest {
    let mut h = Sha256::new();
    h.update(SEAL_DOMAIN.as_bytes());
    h.update([0u8]);
    h.update(canonical);
    DocumentDigest::from_raw(h.finalize().into())
}
