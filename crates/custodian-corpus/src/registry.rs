//! Restricted registry metadata store (ADR 0030).
//!
//! An append-only, hash-chained event log in a 0600 file under the protected
//! root. Rows hold only identities, digests, counts and lifecycle state:
//! never case text, case IDs, seeds, labels, ranges, entry names or raw
//! outputs. The chain makes edits, deletion of interior events and
//! reordering detectable; it is tamper-evident, not tamper-proof, and an
//! attacker who can rewrite the whole file and the seal can forge a history
//! (checkpointing the head digest outside the writer's control is a later
//! concern, see docs/protected-storage.md).
//!
//! Lifecycle: `sealed -> active -> retired`, and `sealed -> retired`.
//! Nothing returns to an earlier state; a changed corpus is a new epoch.
//! Contamination handling (C9) extends this through [`LifecycleObserver`]
//! and a reviewed addition of states; it is not implemented here.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::EvaluationDomain;
use custodian_contracts::types::{
    ConfigDigest, CorpusId, DocumentDigest, EpochId, FamilyId, PopulationDigest, Timestamp, Version,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsguard::{self as g, FILE_PRIVATE};
use crate::reason::{Result, StorageReason as R};

pub const REGISTRY_DOMAIN: &str = "private-custodian/v1/corpus-registry-event";
const MAX_REGISTRY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochState {
    Sealed,
    Active,
    Retired,
}

impl EpochState {
    pub fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Sealed, Self::Active)
                | (Self::Sealed, Self::Retired)
                | (Self::Active, Self::Retired)
        )
    }
}

/// Hook for contamination handling (C9) and audit export (C12). Called after
/// a transition is durably recorded. Must not receive or return protected
/// data; it gets identities only.
pub trait LifecycleObserver: Send + Sync {
    fn on_transition(&self, _epoch: &EpochId, _from: Option<EpochState>, _to: EpochState) {}
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRow {
    pub corpus_id: CorpusId,
    pub epoch_id: EpochId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "custodian_contracts::types::some_only"
    )]
    pub family_id: Option<FamilyId>,
    pub domain: EvaluationDomain,
    pub custody_version: Version,
    pub population_digest: PopulationDigest,
    pub config_digest: ConfigDigest,
    pub seal_digest: DocumentDigest,
    pub entry_count: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
enum Event {
    Sealed { row: RegistryRow },
    Activated { epoch_id: EpochId },
    Retired { epoch_id: EpochId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    seq: u64,
    prev: DocumentDigest,
    at: Timestamp,
    event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    body: Body,
    digest: DocumentDigest,
}

fn body_digest(body: &Body) -> Result<DocumentDigest> {
    let canonical = to_canonical_bytes(body).map_err(|_| R::RegistryInvalid)?;
    let mut h = Sha256::new();
    h.update(REGISTRY_DOMAIN.as_bytes());
    h.update([0u8]);
    h.update(canonical);
    Ok(DocumentDigest::from_raw(h.finalize().into()))
}

fn genesis() -> DocumentDigest {
    DocumentDigest::from_raw([0u8; 32])
}

/// Folded state of the log.
#[derive(Clone, Debug)]
pub struct RegistryView {
    entries: BTreeMap<EpochId, (RegistryRow, EpochState)>,
    head: DocumentDigest,
    next_seq: u64,
}

impl RegistryView {
    fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            head: genesis(),
            next_seq: 0,
        }
    }

    pub fn get(&self, epoch: &EpochId) -> Option<(&RegistryRow, EpochState)> {
        self.entries.get(epoch).map(|(r, s)| (r, *s))
    }

    pub fn epochs(&self) -> impl Iterator<Item = (&RegistryRow, EpochState)> {
        self.entries.values().map(|(r, s)| (r, *s))
    }

    /// Digest of the latest event; the value to checkpoint externally.
    pub fn head(&self) -> &DocumentDigest {
        &self.head
    }

    /// Apply an event, enforcing the lifecycle. Returns the transition.
    fn apply(&mut self, event: &Event) -> Result<(EpochId, Option<EpochState>, EpochState)> {
        match event {
            Event::Sealed { row } => {
                if self.entries.contains_key(&row.epoch_id) {
                    return Err(R::InvalidTransition);
                }
                self.entries
                    .insert(row.epoch_id.clone(), (row.clone(), EpochState::Sealed));
                Ok((row.epoch_id.clone(), None, EpochState::Sealed))
            }
            Event::Activated { epoch_id } => {
                let (row, state) = self.entries.get(epoch_id).ok_or(R::UnknownEpoch)?;
                if !state.can_transition(EpochState::Active) {
                    return Err(R::InvalidTransition);
                }
                // One active epoch per corpus and family at a time.
                let clash = self.entries.values().any(|(r, s)| {
                    *s == EpochState::Active
                        && r.corpus_id == row.corpus_id
                        && r.family_id == row.family_id
                });
                if clash {
                    return Err(R::InvalidTransition);
                }
                let from = *state;
                if let Some(e) = self.entries.get_mut(epoch_id) {
                    e.1 = EpochState::Active;
                }
                Ok((epoch_id.clone(), Some(from), EpochState::Active))
            }
            Event::Retired { epoch_id } => {
                let (_, state) = self.entries.get_mut(epoch_id).ok_or(R::UnknownEpoch)?;
                if !state.can_transition(EpochState::Retired) {
                    return Err(R::InvalidTransition);
                }
                let from = *state;
                *state = EpochState::Retired;
                Ok((epoch_id.clone(), Some(from), EpochState::Retired))
            }
        }
    }
}

pub struct Registry {
    path: PathBuf,
    uid: u32,
    lock: Mutex<()>,
}

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Registry(<redacted>)")
    }
}

impl Registry {
    /// Open the registry file in `dir` (an existing 0700 directory owned by
    /// `uid`), creating an empty 0600 log on first use.
    pub fn open(dir: &Path, uid: u32) -> Result<Self> {
        g::check_dir(dir, uid, g::DIR_PRIVATE)?;
        let path = dir.join("events.jsonl");
        if !g::exists(&path)? {
            g::create_file(&path, b"", FILE_PRIVATE)?;
        }
        let r = Self {
            path,
            uid,
            lock: Mutex::new(()),
        };
        r.view()?; // fail at open if the existing log is invalid
        Ok(r)
    }

    /// Read and verify the whole log (chain, canonical form, lifecycle).
    pub fn view(&self) -> Result<RegistryView> {
        let bytes = g::read_checked(&self.path, self.uid, FILE_PRIVATE, MAX_REGISTRY_BYTES)?;
        let mut view = RegistryView::empty();
        if bytes.is_empty() {
            return Ok(view);
        }
        if bytes.last() != Some(&b'\n') {
            return Err(R::RegistryInvalid);
        }
        for raw in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
            let line: Line = serde_json::from_slice(raw).map_err(|_| R::RegistryInvalid)?;
            let canonical = to_canonical_bytes(&line).map_err(|_| R::RegistryInvalid)?;
            if canonical != raw
                || line.body.seq != view.next_seq
                || line.body.prev != view.head
                || body_digest(&line.body)? != line.digest
            {
                return Err(R::RegistryInvalid);
            }
            view.apply(&line.body.event)
                .map_err(|_| R::RegistryInvalid)?;
            view.head = line.digest;
            view.next_seq += 1;
        }
        Ok(view)
    }

    fn append(
        &self,
        event: Event,
        at: Timestamp,
        observer: Option<&dyn LifecycleObserver>,
    ) -> Result<()> {
        let _guard = self.lock.lock().map_err(|_| R::Io)?;
        let mut view = self.view()?;
        let transition = view.apply(&event)?;
        let body = Body {
            seq: view.next_seq,
            prev: view.head.clone(),
            at,
            event,
        };
        let digest = body_digest(&body)?;
        let mut line =
            to_canonical_bytes(&Line { body, digest }).map_err(|_| R::RegistryInvalid)?;
        line.push(b'\n');

        let before = g::check_file(&self.path, self.uid, FILE_PRIVATE)?;
        let mut f = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| g::io_reason(&e))?;
        let after = f.metadata().map_err(|_| R::Io)?;
        if after.dev() != before.dev() || after.ino() != before.ino() {
            return Err(R::PathEscape);
        }
        f.write_all(&line).map_err(|_| R::Io)?;
        f.sync_all().map_err(|_| R::Io)?;
        if let Some(o) = observer {
            o.on_transition(&transition.0, transition.1, transition.2);
        }
        Ok(())
    }

    pub fn append_sealed(
        &self,
        row: RegistryRow,
        at: Timestamp,
        observer: Option<&dyn LifecycleObserver>,
    ) -> Result<()> {
        self.append(Event::Sealed { row }, at, observer)
    }

    pub fn activate(
        &self,
        epoch: &EpochId,
        at: Timestamp,
        observer: Option<&dyn LifecycleObserver>,
    ) -> Result<()> {
        self.append(
            Event::Activated {
                epoch_id: epoch.clone(),
            },
            at,
            observer,
        )
    }

    pub fn retire(
        &self,
        epoch: &EpochId,
        at: Timestamp,
        observer: Option<&dyn LifecycleObserver>,
    ) -> Result<()> {
        self.append(
            Event::Retired {
                epoch_id: epoch.clone(),
            },
            at,
            observer,
        )
    }
}
