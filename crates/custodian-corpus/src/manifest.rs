//! Canonical corpus manifest and the exact corpus commitment (ADR 0031).
//!
//! The manifest lists every entry (name, size, SHA-256) sorted by name. Its
//! canonical bytes follow the same rules as `custodian-canonical-json/1`
//! (ADR 0004) but are written here because `custodian-contracts` caps
//! documents at 64 KiB and a manifest scales with the corpus. The population
//! digest is `SHA-256(domain || 0x00 || canonical_manifest)`; that is the
//! exact commitment to every byte and name in the corpus.

use custodian_contracts::types::PopulationDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reason::{Result, StorageReason as R};
use crate::secret::{hex, unhex};
use crate::store::{EntryName, MAX_ENTRIES, MAX_ENTRY_BYTES};

pub const MANIFEST_DOMAIN: &str = "private-custodian/v1/corpus-manifest";
pub const MANIFEST_VERSION: u32 = 1;
/// Upper bound for a stored manifest document.
pub const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub name: EntryName,
    /// Lowercase hex SHA-256 of the entry bytes.
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: u32,
    pub entries: Vec<ManifestEntry>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

impl Manifest {
    /// Build from entries; sorts by name and rejects duplicates and bounds.
    pub fn new(mut entries: Vec<ManifestEntry>) -> Result<Self> {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let m = Self {
            manifest_version: MANIFEST_VERSION,
            entries,
        };
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> Result<()> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(R::ManifestInvalid);
        }
        if self.entries.is_empty() {
            return Err(R::EmptyCorpus);
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(R::TooLarge);
        }
        for w in self.entries.windows(2) {
            if w[0].name >= w[1].name {
                return Err(R::ManifestInvalid);
            }
        }
        for e in &self.entries {
            let h = &e.sha256;
            if h.len() != 64 || unhex(h).is_none() || e.size > MAX_ENTRY_BYTES {
                return Err(R::ManifestInvalid);
            }
        }
        Ok(())
    }

    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    pub fn find(&self, name: &EntryName) -> Option<&ManifestEntry> {
        self.entries
            .binary_search_by(|e| e.name.cmp(name))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Canonical bytes: compact, keys sorted (`entries`, `manifest_version`;
    /// `name`, `sha256`, `size`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::from("{\"entries\":[");
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"name\":\"{}\",\"sha256\":\"{}\",\"size\":{}}}",
                e.name.as_str(),
                e.sha256,
                e.size
            ));
        }
        out.push_str(&format!(
            "],\"manifest_version\":{}}}",
            self.manifest_version
        ));
        out.into_bytes()
    }

    /// Strict parse of stored bytes: size cap, typed parse (unknown fields
    /// rejected), validation, and byte-identity with the canonical encoding.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(R::TooLarge);
        }
        let m: Self = serde_json::from_slice(bytes).map_err(|_| R::ManifestInvalid)?;
        m.validate()?;
        if m.canonical_bytes() != bytes {
            return Err(R::ManifestInvalid);
        }
        Ok(m)
    }

    /// The exact corpus commitment.
    pub fn population_digest(&self) -> PopulationDigest {
        let mut h = Sha256::new();
        h.update(MANIFEST_DOMAIN.as_bytes());
        h.update([0u8]);
        h.update(self.canonical_bytes());
        PopulationDigest::from_raw(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: &str, data: &[u8]) -> ManifestEntry {
        ManifestEntry {
            name: EntryName::parse(n).unwrap(),
            sha256: sha256_hex(data),
            size: data.len() as u64,
        }
    }

    #[test]
    fn digest_is_order_independent_and_content_sensitive() {
        let a = Manifest::new(vec![entry("b", b"2"), entry("a", b"1")]).unwrap();
        let b = Manifest::new(vec![entry("a", b"1"), entry("b", b"2")]).unwrap();
        assert_eq!(a.population_digest(), b.population_digest());
        let c = Manifest::new(vec![entry("a", b"1"), entry("b", b"3")]).unwrap();
        assert_ne!(a.population_digest(), c.population_digest());
        let d = Manifest::new(vec![entry("a", b"1"), entry("c", b"2")]).unwrap();
        assert_ne!(a.population_digest(), d.population_digest());
    }

    #[test]
    fn decode_requires_canonical_form() {
        let m = Manifest::new(vec![entry("a", b"1")]).unwrap();
        let bytes = m.canonical_bytes();
        assert_eq!(Manifest::decode_canonical(&bytes).unwrap(), m);
        let mut spaced = bytes.clone();
        spaced.insert(1, b' ');
        assert_eq!(Manifest::decode_canonical(&spaced), Err(R::ManifestInvalid));
    }

    #[test]
    fn rejects_duplicates_empty_and_unknown_fields() {
        assert_eq!(
            Manifest::new(vec![entry("a", b"1"), entry("a", b"1")]),
            Err(R::ManifestInvalid)
        );
        assert_eq!(Manifest::new(vec![]), Err(R::EmptyCorpus));
        let bad = br#"{"entries":[],"manifest_version":1,"x":1}"#;
        assert!(Manifest::decode_canonical(bad).is_err());
    }
}
