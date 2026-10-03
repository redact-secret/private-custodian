//! Untrusted inputs: the bundle directory, the pinned keys file and the
//! expectations file.
//!
//! Every read is bounded before it happens, every document is parsed strictly
//! (closed schemas, no unknown fields), and nothing here ever puts a path, a
//! file name or file content into an error. A symbolic link, a device, a
//! directory where a file is expected, an extra entry or an over-limit count
//! is refused rather than followed or skipped.
//!
//! Bundle layout (all names fixed):
//!
//! ```text
//! manifest.json                 bridge manifest (private-custodian.bridge-response/1)
//! projections/NNNN.json         released projection envelopes, canonical bytes
//! revocations/NNNN.json         revocation feed envelopes, ascending sequence
//! ```

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

use custodian_bridge::wire::{
    BridgeResponse, MAX_DOCUMENT_BYTES, MAX_MANIFEST_BYTES, MAX_POPULATION_FILTER, MAX_PROJECTIONS,
    MAX_REVOCATIONS,
};
use custodian_contracts::common::{EvaluationDomain, PolicyRef};
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::types::{
    CandidateDigest, ConfigDigest, DestinationId, FeedId, KeyId, Timestamp,
};
use custodian_ledger::{KeyEntry, Keyring, SignDomain};
use serde::Deserialize;

/// Largest pins or expectations file, in bytes.
pub const MAX_PINS_BYTES: u64 = 65_536;
/// Most keys a pinned keys file may list.
pub const MAX_KEYS: usize = 16;
/// Most accepted policies an expectations file may list.
pub const MAX_POLICIES: usize = 8;

pub const KEYS_SCHEMA: &str = "private-custodian.verify-keys/1";
pub const EXPECTATIONS_SCHEMA: &str = "private-custodian.verify-expectations/1";

/// Why an input was refused. Fixed vocabulary; carries no input text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InputError {
    /// The command line is not one of the accepted forms.
    Usage,
    /// A required file or directory is missing, not a regular file or
    /// directory, a link, or cannot be read.
    Unreadable,
    /// A file is over its size bound, or there are more documents than the
    /// bridge allows.
    TooLarge,
    /// The bundle holds an entry that is not part of the layout.
    UnexpectedEntry,
    /// The manifest is missing or not a strict bridge manifest, or the
    /// documents do not agree with it in number.
    BundleMalformed,
    /// The keys file is not a strict, bounded keys document.
    KeysInvalid,
    /// The expectations file is not a strict, bounded expectations document.
    ExpectationsInvalid,
    /// The pinned feed id is not a feed id.
    FeedIdInvalid,
}

impl InputError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Unreadable => "input_unreadable",
            Self::TooLarge => "input_too_large",
            Self::UnexpectedEntry => "bundle_unexpected_entry",
            Self::BundleMalformed => "bundle_malformed",
            Self::KeysInvalid => "keys_invalid",
            Self::ExpectationsInvalid => "expectations_invalid",
            Self::FeedIdInvalid => "feed_id_invalid",
        }
    }
}

impl core::fmt::Display for InputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for InputError {}

/// Read one regular file of at most `limit` bytes. Links are refused.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, InputError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| InputError::Unreadable)?;
    if !meta.is_file() {
        return Err(InputError::Unreadable);
    }
    if meta.len() > limit {
        return Err(InputError::TooLarge);
    }
    let mut buf = Vec::new();
    File::open(path)
        .map_err(|_| InputError::Unreadable)?
        .take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|_| InputError::Unreadable)?;
    if buf.len() as u64 > limit {
        return Err(InputError::TooLarge);
    }
    Ok(buf)
}

fn is_real_dir(meta: &Metadata) -> bool {
    meta.is_dir() && !meta.file_type().is_symlink()
}

/// The pinned public keys: no secret, only what a verifier needs.
#[derive(Clone, Debug)]
pub struct Pins {
    pub keyring: Keyring,
    pub feed_id: FeedId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    schema: String,
    keys: Vec<KeyRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRow {
    key_id: String,
    /// 64 lowercase hex characters: the Ed25519 public key.
    public_key: String,
    /// Any of `projection` (major 1), `projection_v2` (major 2, the
    /// destination-bound projection the daemon releases, ADR 0119) and
    /// `revocation`. No ledger purpose is accepted.
    purposes: Vec<String>,
    valid_from: u64,
    #[serde(default)]
    retired_at: Option<u64>,
    #[serde(default)]
    revoked_at: Option<u64>,
}

impl Pins {
    pub fn load(keys_path: &Path, feed_id: &str) -> Result<Self, InputError> {
        let feed_id = FeedId::parse(feed_id).map_err(|_| InputError::FeedIdInvalid)?;
        let bytes = read_bounded(keys_path, MAX_PINS_BYTES)?;
        Ok(Self {
            keyring: parse_keys(&bytes)?,
            feed_id,
        })
    }
}

fn parse_keys(bytes: &[u8]) -> Result<Keyring, InputError> {
    let file: KeysFile = serde_json::from_slice(bytes).map_err(|_| InputError::KeysInvalid)?;
    if file.schema != KEYS_SCHEMA || file.keys.is_empty() || file.keys.len() > MAX_KEYS {
        return Err(InputError::KeysInvalid);
    }
    let mut ring = Keyring::new();
    for row in file.keys {
        let mut purposes = Vec::new();
        for p in &row.purposes {
            purposes.push(match p.as_str() {
                "projection" => SignDomain::PublicProjection,
                "projection_v2" => SignDomain::PublicProjectionV2,
                "revocation" => SignDomain::RevocationEnvelope,
                _ => return Err(InputError::KeysInvalid),
            });
        }
        if purposes.is_empty() {
            return Err(InputError::KeysInvalid);
        }
        let key_id = KeyId::parse(&row.key_id).map_err(|_| InputError::KeysInvalid)?;
        if ring.get(&key_id).is_some() {
            return Err(InputError::KeysInvalid);
        }
        let ts = |s: u64| Timestamp::new(s).map_err(|_| InputError::KeysInvalid);
        let mut entry = KeyEntry::root(key_id, &row.public_key, purposes, ts(row.valid_from)?)
            .ok_or(InputError::KeysInvalid)?;
        entry.retired_at = row.retired_at.map(ts).transpose()?;
        entry.revoked_at = row.revoked_at.map(ts).transpose()?;
        ring = ring.with_root(entry);
    }
    Ok(ring)
}

/// What the caller expects the bundle to be about, out of band.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectations {
    #[serde(rename = "schema")]
    schema: String,
    pub domain: EvaluationDomain,
    pub candidate: CandidateDigest,
    pub config: ConfigDigest,
    /// The channel label the answer must have been prepared for.
    pub destination: DestinationId,
    /// Public populations the caller relies on. At least one.
    pub populations: Vec<PublicPopulationRef>,
    /// Disclosure policy versions the caller accepts. At least one.
    pub policies: Vec<PolicyRef>,
}

impl Expectations {
    pub fn load(path: &Path) -> Result<Self, InputError> {
        Self::parse(&read_bounded(path, MAX_PINS_BYTES)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, InputError> {
        let e: Self = serde_json::from_slice(bytes).map_err(|_| InputError::ExpectationsInvalid)?;
        if e.schema != EXPECTATIONS_SCHEMA
            || e.populations.is_empty()
            || e.populations.len() > MAX_POPULATION_FILTER
            || e.policies.is_empty()
            || e.policies.len() > MAX_POLICIES
        {
            return Err(InputError::ExpectationsInvalid);
        }
        Ok(e)
    }
}

/// A parsed bundle: the bridge response it carries. Nothing in it is trusted
/// yet.
#[derive(Debug)]
pub struct Bundle {
    pub response: BridgeResponse,
}

impl Bundle {
    pub fn load(dir: &Path) -> Result<Self, InputError> {
        let meta = std::fs::symlink_metadata(dir).map_err(|_| InputError::Unreadable)?;
        if !is_real_dir(&meta) {
            return Err(InputError::Unreadable);
        }
        let mut have_manifest = false;
        for entry in std::fs::read_dir(dir).map_err(|_| InputError::Unreadable)? {
            let entry = entry.map_err(|_| InputError::Unreadable)?;
            match entry.file_name().to_str() {
                Some("manifest.json") => have_manifest = true,
                Some("projections") | Some("revocations") => {}
                _ => return Err(InputError::UnexpectedEntry),
            }
        }
        if !have_manifest {
            return Err(InputError::BundleMalformed);
        }
        let manifest = read_bounded(&dir.join("manifest.json"), MAX_MANIFEST_BYTES as u64)?;
        let projections = read_documents(&dir.join("projections"), MAX_PROJECTIONS)?;
        let revocations = read_documents(&dir.join("revocations"), MAX_REVOCATIONS)?;
        let response = BridgeResponse::from_wire(&manifest, projections, revocations)
            .map_err(|_| InputError::BundleMalformed)?;
        Ok(Self { response })
    }
}

/// `NNNN.json` (1 to 8 ASCII digits), ordered by number. A missing directory
/// is an empty list; anything else in it is refused.
fn read_documents(dir: &Path, max: usize) -> Result<Vec<Vec<u8>>, InputError> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(InputError::Unreadable),
    };
    if !is_real_dir(&meta) {
        return Err(InputError::Unreadable);
    }
    let mut files: Vec<(u64, std::path::PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|_| InputError::Unreadable)? {
        let entry = entry.map_err(|_| InputError::Unreadable)?;
        let name = entry.file_name();
        let number = name
            .to_str()
            .and_then(|n| n.strip_suffix(".json"))
            .filter(|n| (1..=8).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or(InputError::UnexpectedEntry)?;
        if files.len() >= max {
            return Err(InputError::TooLarge);
        }
        files.push((number, entry.path()));
    }
    files.sort();
    if files.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(InputError::UnexpectedEntry);
    }
    files
        .iter()
        .map(|(_, p)| read_bounded(p, MAX_DOCUMENT_BYTES as u64))
        .collect()
}
