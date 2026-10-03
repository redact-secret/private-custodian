//! Signing domains. One domain per document type (ADR 0050, ADR 0004).
//!
//! Contract domains reuse the exact tags from `custodian-contracts`; ledger
//! record domains are added here under `private-custodian/v1/ledger/`. The
//! signing input is always `domain || 0x00 || canonical_bytes`, so a signature
//! over one document type is never valid for another, even for byte-identical
//! payloads. A tag is never edited; a new rule is a new tag.

use custodian_contracts::canonical::{signing_input, DomainTag};
use custodian_contracts::types::DocumentDigest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SignDomain {
    /// `PublicProjection` payloads (contracts).
    PublicProjection,
    /// `RevocationEnvelope` payloads (contracts).
    RevocationEnvelope,
    LedgerAuditEvent,
    LedgerStoreCheckpoint,
    LedgerRegistryCheckpoint,
    LedgerPolicy,
    LedgerPublication,
    LedgerReconciliation,
    LedgerKeyEvent,
}

impl SignDomain {
    pub const ALL: [SignDomain; 9] = [
        Self::PublicProjection,
        Self::RevocationEnvelope,
        Self::LedgerAuditEvent,
        Self::LedgerStoreCheckpoint,
        Self::LedgerRegistryCheckpoint,
        Self::LedgerPolicy,
        Self::LedgerPublication,
        Self::LedgerReconciliation,
        Self::LedgerKeyEvent,
    ];

    /// The exact domain bytes mixed into the signing input.
    pub fn tag(self) -> &'static str {
        match self {
            Self::PublicProjection => DomainTag::PublicProjection.as_str(),
            Self::RevocationEnvelope => DomainTag::RevocationEnvelope.as_str(),
            Self::LedgerAuditEvent => "private-custodian/v1/ledger/audit-event",
            Self::LedgerStoreCheckpoint => "private-custodian/v1/ledger/store-checkpoint",
            Self::LedgerRegistryCheckpoint => "private-custodian/v1/ledger/registry-checkpoint",
            Self::LedgerPolicy => "private-custodian/v1/ledger/policy",
            Self::LedgerPublication => "private-custodian/v1/ledger/publication",
            Self::LedgerReconciliation => "private-custodian/v1/ledger/reconciliation",
            Self::LedgerKeyEvent => "private-custodian/v1/ledger/key-event",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.tag() == tag)
    }

    /// `domain || 0x00 || canonical`. For the contract domains this is
    /// byte-identical to `custodian_contracts::canonical::signing_input`.
    pub fn signing_input(self, canonical: &[u8]) -> Vec<u8> {
        match self {
            Self::PublicProjection => signing_input(DomainTag::PublicProjection, canonical),
            Self::RevocationEnvelope => signing_input(DomainTag::RevocationEnvelope, canonical),
            other => {
                let mut out = Vec::with_capacity(other.tag().len() + 1 + canonical.len());
                out.extend_from_slice(other.tag().as_bytes());
                out.push(0);
                out.extend_from_slice(canonical);
                out
            }
        }
    }

    /// Domain-separated SHA-256 of the canonical bytes.
    pub fn digest(self, canonical: &[u8]) -> DocumentDigest {
        DocumentDigest::from_raw(Sha256::digest(self.signing_input(canonical)).into())
    }
}

impl Serialize for SignDomain {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.tag())
    }
}

impl<'de> Deserialize<'de> for SignDomain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_tag(&s).ok_or_else(|| serde::de::Error::custom("unknown_domain"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_unique_nul_free_and_ledger_tags_never_collide_with_contract_tags() {
        let mut seen = std::collections::BTreeSet::new();
        for d in SignDomain::ALL {
            assert!(!d.tag().contains('\0'));
            assert!(seen.insert(d.tag()));
            assert_eq!(SignDomain::from_tag(d.tag()), Some(d));
        }
        for d in SignDomain::ALL
            .iter()
            .filter(|d| d.tag().contains("/ledger/"))
        {
            assert!(DomainTag::ALL.iter().all(|c| c.as_str() != d.tag()));
        }
    }

    #[test]
    fn contract_domains_match_the_contracts_signing_input() {
        let c = b"{\"a\":1}";
        assert_eq!(
            SignDomain::PublicProjection.signing_input(c),
            signing_input(DomainTag::PublicProjection, c)
        );
    }
}
