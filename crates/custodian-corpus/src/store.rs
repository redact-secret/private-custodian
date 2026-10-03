//! The storage adapter contract (ADR 0030). The filesystem adapter is the
//! first implementation; an object-store adapter must implement the same
//! trait and pass [`crate::conformance::run`].
//!
//! The adapter is deliberately dumb: it stores named byte entries per epoch,
//! publishes an epoch atomically and immutably, and returns what it holds.
//! It is never trusted for integrity. Commitment, seal and registry checks
//! happen above it in [`crate::populations::ProtectedPopulations`], on every
//! read.

use custodian_contracts::types::EpochId;
use serde::{Deserialize, Serialize};

use crate::reason::{Result, StorageReason};
use crate::secret::ProtectedBytes;

/// Maximum size of one entry.
pub const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum entries per epoch.
pub const MAX_ENTRIES: usize = 100_000;

/// Allowlisted entry name: `[a-z0-9][a-z0-9._-]{0,63}`, no `..`. Names are
/// opaque to the custodian and must not be case text or meaningful case IDs;
/// they live only in the protected manifest, never in the registry.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EntryName(String);

impl EntryName {
    pub fn parse(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 64
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
            })
            && !s.contains("..");
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(StorageReason::NameInvalid)
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EntryName {
    type Error = StorageReason;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}
impl From<EntryName> for String {
    fn from(n: EntryName) -> String {
        n.0
    }
}

impl core::fmt::Debug for EntryName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EntryName(<redacted>)")
    }
}

/// Which copy of an epoch an operation addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Writable, unsealed, never usable for evaluation.
    Staging,
    /// Immutable, published by `finalize`.
    Sealed,
}

/// The two metadata documents published with a sealed epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedDoc {
    Manifest,
    Seal,
}

/// Adapter contract. All methods must:
/// - fail closed: any uncertainty is an error, never a partial success;
/// - never include entry names, bytes, paths or backend messages in errors;
/// - be safe to call concurrently for different epochs.
///
/// Semantics every adapter must give (checked by the conformance suite):
/// - `create_staging` fails with `AlreadyExists` if the epoch exists in
///   either stage.
/// - `put_entry` writes a new entry to staging only. It never overwrites
///   (`AlreadyExists`), and fails with `EpochSealed` after `finalize`, and
///   `NotFound` for an unknown epoch.
/// - `finalize` publishes entries plus the manifest and seal documents
///   atomically: a reader sees either no sealed epoch or the complete one.
///   After it, no entry or document can be created, replaced or removed
///   through the adapter. A second `finalize` fails with `EpochSealed`.
/// - `list_entries`, `read_entry` and `read_doc` on `Stage::Sealed` before
///   finalize fail with `EpochNotSealed`/`NotFound`; `read_doc` is sealed only.
/// - Epochs are isolated: an operation on one epoch never reads or changes
///   another.
pub trait EpochBlobStore: Send + Sync {
    fn create_staging(&self, epoch: &EpochId) -> Result<()>;
    fn put_entry(&self, epoch: &EpochId, name: &EntryName, bytes: &[u8]) -> Result<()>;
    fn list_entries(&self, epoch: &EpochId, stage: Stage) -> Result<Vec<EntryName>>;
    fn read_entry(&self, epoch: &EpochId, stage: Stage, name: &EntryName)
        -> Result<ProtectedBytes>;
    fn finalize(&self, epoch: &EpochId, manifest: &[u8], seal: &[u8]) -> Result<()>;
    fn read_doc(&self, epoch: &EpochId, doc: SealedDoc) -> Result<Vec<u8>>;
    /// Remove an unsealed epoch. A sealed epoch is never removed here
    /// (`EpochSealed`); deletion of sealed material is an operator retention
    /// procedure (docs/protected-storage.md).
    fn discard_staging(&self, epoch: &EpochId) -> Result<()>;
    fn is_sealed(&self, epoch: &EpochId) -> Result<bool>;
}
