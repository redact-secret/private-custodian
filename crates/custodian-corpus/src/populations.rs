//! Sealing, verification and authorized access over any [`EpochBlobStore`].
//!
//! Integrity rules (ADR 0031), applied on every access, never cached as
//! trust:
//! 1. the registry row for the epoch exists (and is `active` for use);
//! 2. the seal bytes are canonical and valid, and name this very epoch
//!    (wrong-epoch swap detection);
//! 3. their digest equals the digest recorded in the registry and the seal
//!    agrees with the registry row;
//! 4. the manifest bytes are canonical and their commitment equals the
//!    population digest in the seal;
//! 5. the entry list in storage equals the manifest list;
//! 6. before returning bytes, `len` and SHA-256 of those exact bytes equal
//!    the manifest entry. A mismatch is `integrity_mismatch`, never "use
//!    anyway".

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use custodian_contracts::common::{BudgetScope, EvaluationDomain, PopulationBinding, ReviewStatus};
use custodian_contracts::types::{
    ActorRef, ConfigDigest, CorpusId, DocumentDigest, EpochId, FamilyId, KeyedCommitment,
    Timestamp, Version,
};
use custodian_core::ports::{Authorization, CorpusAccess, CorpusHandle, Refusal};

use crate::fs_store::FsEpochStore;
use crate::fsguard as g;
use crate::manifest::{sha256_hex, Manifest, ManifestEntry};
use crate::reason::{Result, StorageReason as R};
use crate::registry::{EpochState, LifecycleObserver, Registry, RegistryRow};
use crate::seal::{seal_digest, Provenance, ReviewRecord, SealRecord, SEAL_VERSION};
use crate::secret::{hex, random_bytes, CommitmentKey, ProtectedBytes};
use crate::store::{EntryName, EpochBlobStore, SealedDoc, Stage, MAX_ENTRIES};

/// An unsealed epoch being assembled. Consumed by `seal` or `abandon`;
/// carries identities only.
#[derive(Debug)]
pub struct EpochWriter {
    corpus_id: CorpusId,
    epoch_id: EpochId,
    domain: EvaluationDomain,
    family_id: Option<FamilyId>,
}

impl EpochWriter {
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }
    pub fn corpus_id(&self) -> &CorpusId {
        &self.corpus_id
    }
    pub fn family_id(&self) -> Option<&FamilyId> {
        self.family_id.as_ref()
    }
}

/// Everything the sealer attests and freezes besides the bytes.
#[derive(Clone, Debug)]
pub struct SealInputs {
    pub custody_version: Version,
    pub config_digest: ConfigDigest,
    pub budget: BudgetScope,
    pub provenance: Provenance,
    pub review: ReviewRecord,
    pub sealed_by: ActorRef,
    pub sealed_at: Timestamp,
}

/// Result of sealing. Identities and digests only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedEpoch {
    pub binding: PopulationBinding,
    pub seal_digest: DocumentDigest,
    pub entry_count: u64,
    pub total_bytes: u64,
}

struct Verified {
    seal: SealRecord,
    manifest: Manifest,
    seal_digest: DocumentDigest,
    state: EpochState,
}

pub struct ProtectedPopulations<S: EpochBlobStore> {
    store: S,
    registry: Registry,
    key: CommitmentKey,
    observer: Option<Arc<dyn LifecycleObserver>>,
    handles: Mutex<HashMap<u64, EpochId>>,
    next_handle: AtomicU64,
}

impl<S: EpochBlobStore> core::fmt::Debug for ProtectedPopulations<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProtectedPopulations(<redacted>)")
    }
}

impl ProtectedPopulations<FsEpochStore> {
    /// Open the filesystem deployment rooted at an operator-provisioned
    /// directory (0700, outside any Git working tree). Loads or creates the
    /// commitment key at `<root>/keys/commitment.key` (0600).
    pub fn open_fs(root: &Path) -> Result<Self> {
        let store = FsEpochStore::open(root)?;
        let registry = Registry::open(&store.root().join("registry"), store.uid())?;
        let key_path = store.root().join("keys").join("commitment.key");
        let key = if g::exists(&key_path)? {
            let bytes = g::read_checked(&key_path, store.uid(), g::FILE_PRIVATE, 256)?;
            CommitmentKey::from_hex(std::str::from_utf8(&bytes).map_err(|_| R::KeyInvalid)?)?
        } else {
            let k = CommitmentKey::generate()?;
            g::create_file(&key_path, k.to_hex().as_bytes(), g::FILE_PRIVATE)?;
            k
        };
        Ok(Self::new(store, registry, key))
    }
}

impl<S: EpochBlobStore> ProtectedPopulations<S> {
    pub fn new(store: S, registry: Registry, key: CommitmentKey) -> Self {
        Self {
            store,
            registry,
            key,
            observer: None,
            handles: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn LifecycleObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // ---- writing ---------------------------------------------------------

    /// Start a new epoch with a fresh opaque ID. Never reuses or edits an
    /// existing epoch: a changed corpus is always a new epoch and seal.
    pub fn begin_epoch(
        &self,
        corpus_id: CorpusId,
        domain: EvaluationDomain,
        family_id: Option<FamilyId>,
    ) -> Result<EpochWriter> {
        let id = format!("epo_{}", hex(&random_bytes(16)?));
        let epoch_id = EpochId::parse(&id).map_err(|_| R::NameInvalid)?;
        self.store.create_staging(&epoch_id)?;
        Ok(EpochWriter {
            corpus_id,
            epoch_id,
            domain,
            family_id,
        })
    }

    pub fn add_entry(&self, writer: &EpochWriter, name: &EntryName, bytes: &[u8]) -> Result<()> {
        self.store.put_entry(&writer.epoch_id, name, bytes)
    }

    /// Discard an unsealed epoch.
    pub fn abandon(&self, writer: EpochWriter) -> Result<()> {
        self.store.discard_staging(&writer.epoch_id)
    }

    /// Seal: commit to the exact corpus, bind configuration, budget,
    /// provenance and review, publish immutably, and register. On any
    /// failure before publication the staging epoch is discarded.
    pub fn seal(&self, writer: EpochWriter, inputs: SealInputs) -> Result<SealedEpoch> {
        let result = self.seal_inner(&writer, &inputs);
        if result.is_err() {
            let _ = self.store.discard_staging(&writer.epoch_id);
        }
        result
    }

    fn seal_inner(&self, w: &EpochWriter, inputs: &SealInputs) -> Result<SealedEpoch> {
        if inputs.review.attestation.review == ReviewStatus::NotReviewed {
            return Err(R::ReviewMissing);
        }
        let names = self.store.list_entries(&w.epoch_id, Stage::Staging)?;
        if names.is_empty() {
            return Err(R::EmptyCorpus);
        }
        if names.len() > MAX_ENTRIES {
            return Err(R::TooLarge);
        }
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let bytes = self.store.read_entry(&w.epoch_id, Stage::Staging, &name)?;
            entries.push(ManifestEntry {
                sha256: sha256_hex(bytes.expose()),
                size: bytes.len() as u64,
                name,
            });
        }
        let manifest = Manifest::new(entries)?;
        let binding = PopulationBinding {
            domain: w.domain,
            corpus_id: w.corpus_id.clone(),
            epoch_id: w.epoch_id.clone(),
            family_id: w.family_id.clone(),
            population_digest: manifest.population_digest(),
            custody_version: inputs.custody_version,
        };
        let record = SealRecord {
            seal_version: SEAL_VERSION,
            binding: binding.clone(),
            config_digest: inputs.config_digest.clone(),
            budget: inputs.budget.clone(),
            provenance: inputs.provenance.clone(),
            review: inputs.review.clone(),
            sealed_by: inputs.sealed_by.clone(),
            sealed_at: inputs.sealed_at,
            entry_count: manifest.entries.len() as u64,
            total_bytes: manifest.total_bytes(),
        };
        record.validate()?;
        let seal_bytes = record.canonical_bytes()?;
        let digest = seal_digest(&seal_bytes);

        self.store
            .finalize(&w.epoch_id, &manifest.canonical_bytes(), &seal_bytes)?;
        // From here the epoch is immutable and published, but unusable until
        // registered (reads require a registry row). A failure below leaves an
        // inert sealed epoch that an operator can reconcile; it is never
        // silently usable.
        let row = RegistryRow {
            corpus_id: w.corpus_id.clone(),
            epoch_id: w.epoch_id.clone(),
            family_id: w.family_id.clone(),
            domain: w.domain,
            custody_version: inputs.custody_version,
            population_digest: binding.population_digest.clone(),
            config_digest: inputs.config_digest.clone(),
            seal_digest: digest.clone(),
            entry_count: record.entry_count,
            total_bytes: record.total_bytes,
        };
        self.registry
            .append_sealed(row, inputs.sealed_at, self.observer.as_deref())?;
        self.verify_structure(&w.epoch_id)?;
        Ok(SealedEpoch {
            binding,
            seal_digest: digest,
            entry_count: record.entry_count,
            total_bytes: record.total_bytes,
        })
    }

    // ---- lifecycle -------------------------------------------------------

    pub fn activate(&self, epoch: &EpochId, at: Timestamp) -> Result<()> {
        self.verify_structure(epoch)?;
        self.registry.activate(epoch, at, self.observer.as_deref())
    }

    pub fn retire(&self, epoch: &EpochId, at: Timestamp) -> Result<()> {
        self.registry.retire(epoch, at, self.observer.as_deref())
    }

    pub fn state(&self, epoch: &EpochId) -> Result<EpochState> {
        self.registry
            .view()?
            .get(epoch)
            .map(|(_, s)| s)
            .ok_or(R::UnknownEpoch)
    }

    /// Disclosure-safe keyed commitment for the epoch's population. Needs the
    /// custodian-held key; returns no content-derived guessable hash.
    pub fn public_commitment(&self, epoch: &EpochId) -> Result<KeyedCommitment> {
        let v = self.verify_structure(epoch)?;
        self.key.commit(v.seal.binding.population_digest.as_str())
    }

    // ---- verification and reads -------------------------------------------

    /// Rules 1 to 5. Does not hash entry bytes.
    fn verify_structure(&self, epoch: &EpochId) -> Result<Verified> {
        let view = self.registry.view()?;
        let (row, state) = view.get(epoch).ok_or(R::UnknownEpoch)?;
        let seal_bytes = self.store.read_doc(epoch, SealedDoc::Seal)?;
        let seal = SealRecord::decode_canonical(&seal_bytes)?;
        if seal.binding.epoch_id != *epoch {
            return Err(R::WrongEpoch);
        }
        let digest = seal_digest(&seal_bytes);
        if digest != row.seal_digest {
            return Err(R::IntegrityMismatch);
        }
        if seal.binding.corpus_id != row.corpus_id
            || seal.binding.family_id != row.family_id
            || seal.binding.domain != row.domain
            || seal.binding.custody_version != row.custody_version
            || seal.binding.population_digest != row.population_digest
            || seal.config_digest != row.config_digest
            || seal.entry_count != row.entry_count
            || seal.total_bytes != row.total_bytes
        {
            return Err(R::IntegrityMismatch);
        }
        let manifest_bytes = self.store.read_doc(epoch, SealedDoc::Manifest)?;
        let manifest = Manifest::decode_canonical(&manifest_bytes)?;
        if manifest.population_digest() != seal.binding.population_digest
            || manifest.entries.len() as u64 != seal.entry_count
            || manifest.total_bytes() != seal.total_bytes
        {
            return Err(R::IntegrityMismatch);
        }
        let listed = self.store.list_entries(epoch, Stage::Sealed)?;
        let expected: Vec<&EntryName> = manifest.entries.iter().map(|e| &e.name).collect();
        if listed.iter().collect::<Vec<_>>() != expected {
            return Err(R::IntegrityMismatch);
        }
        Ok(Verified {
            seal,
            manifest,
            seal_digest: digest,
            state,
        })
    }

    /// Rule 6 for one entry.
    fn read_verified(
        &self,
        v: &Verified,
        epoch: &EpochId,
        name: &EntryName,
    ) -> Result<ProtectedBytes> {
        let want = v.manifest.find(name).ok_or(R::NotFound)?;
        let bytes = self.store.read_entry(epoch, Stage::Sealed, name)?;
        if bytes.len() as u64 != want.size || sha256_hex(bytes.expose()) != want.sha256 {
            return Err(R::IntegrityMismatch);
        }
        Ok(bytes)
    }

    /// Full verification of a sealed epoch (rules 1 to 6 for every entry).
    /// Returns the seal digest. Use for audits and restore checks.
    pub fn verify_epoch(&self, epoch: &EpochId) -> Result<DocumentDigest> {
        let v = self.verify_structure(epoch)?;
        for e in &v.manifest.entries {
            self.read_verified(&v, epoch, &e.name)?;
        }
        Ok(v.seal_digest)
    }

    /// Verified read of one entry from an open handle. Re-verifies the seal
    /// chain and requires the epoch to still be `active`.
    pub fn read_entry(&self, handle: &CorpusHandle, name: &EntryName) -> Result<ProtectedBytes> {
        let epoch = self.epoch_of(handle)?;
        let v = self.verify_structure(&epoch)?;
        if v.state != EpochState::Active {
            return Err(R::NotActive);
        }
        self.read_verified(&v, &epoch, name)
    }

    /// Entry names of the epoch behind a handle, from the verified manifest.
    pub fn entry_names(&self, handle: &CorpusHandle) -> Result<Vec<EntryName>> {
        let epoch = self.epoch_of(handle)?;
        let v = self.verify_structure(&epoch)?;
        if v.state != EpochState::Active {
            return Err(R::NotActive);
        }
        Ok(v.manifest.entries.iter().map(|e| e.name.clone()).collect())
    }

    /// The population binding behind a handle (for C6 plan checks).
    pub fn binding(&self, handle: &CorpusHandle) -> Result<PopulationBinding> {
        let epoch = self.epoch_of(handle)?;
        Ok(self.verify_structure(&epoch)?.seal.binding)
    }

    pub fn close(&self, handle: CorpusHandle) {
        if let Ok(mut h) = self.handles.lock() {
            h.remove(&handle.token());
        }
    }

    fn epoch_of(&self, handle: &CorpusHandle) -> Result<EpochId> {
        self.handles
            .lock()
            .map_err(|_| R::Io)?
            .get(&handle.token())
            .cloned()
            .ok_or(R::InvalidHandle)
    }

    /// `CorpusAccess::open` with the precise storage reason (for the
    /// control service's private audit record; the port itself exposes only
    /// the coarse core reason code).
    pub fn open_verified(&self, authorization: &Authorization) -> Result<CorpusHandle> {
        // The authorization's population is the opaque epoch ID. Anything
        // else is a wrong-epoch request.
        let epoch = EpochId::parse(authorization.population.as_str()).map_err(|_| R::WrongEpoch)?;
        let v = self.verify_structure(&epoch)?;
        if v.state != EpochState::Active {
            return Err(R::NotActive);
        }
        for e in &v.manifest.entries {
            self.read_verified(&v, &epoch, &e.name)?;
        }
        let token = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().map_err(|_| R::Io)?.insert(token, epoch);
        Ok(CorpusHandle::new(token))
    }
}

impl<S: EpochBlobStore> CorpusAccess for ProtectedPopulations<S> {
    /// Opening is the exposure event. It verifies the full commitment (every
    /// entry) before issuing a handle, and refuses anything but an `active`,
    /// intact epoch. Failures are fixed reason codes.
    fn open(&self, authorization: &Authorization) -> core::result::Result<CorpusHandle, Refusal> {
        self.open_verified(authorization).map_err(Refusal::from)
    }
}

/// Convenience used by tests and C6: the PopulationId string for an epoch.
pub fn population_id_for(epoch: &EpochId) -> custodian_core::PopulationId {
    custodian_core::PopulationId::new(epoch.as_str())
}
