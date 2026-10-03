//! Test support: a private temporary root, an in-memory adapter and a
//! fault-injecting wrapper. Synthetic only. Nothing here is a deployment
//! option; the in-memory adapter enforces no permissions and exists to prove
//! that the layers above the adapter do not depend on the filesystem.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use custodian_contracts::types::EpochId;

use crate::fsguard::{create_dir, DIR_PRIVATE};
use crate::reason::{Result, StorageReason as R};
use crate::secret::{hex, random_bytes, ProtectedBytes};
use crate::store::{EntryName, EpochBlobStore, SealedDoc, Stage, MAX_ENTRY_BYTES};

/// A 0700 temporary directory under the OS temp dir, removed on drop (sealed
/// read-only modes are relaxed first). Tests must never place one inside a
/// Git working tree.
pub struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    pub fn new() -> Self {
        let name = hex(&random_bytes(8).expect("urandom"));
        let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
        let path = base.join(format!("custodian-corpus-test-{name}"));
        create_dir(&path, DIR_PRIVATE).expect("create temp root");
        Self { path }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for TempRoot {
    fn default() -> Self {
        Self::new()
    }
}

fn relax(path: &Path) {
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.is_dir() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(rd) = fs::read_dir(path) {
                for c in rd.flatten() {
                    relax(&c.path());
                }
            }
        } else if m.is_file() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        relax(&self.path);
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Default)]
struct MemEpoch {
    sealed: bool,
    entries: BTreeMap<String, Vec<u8>>,
    manifest: Vec<u8>,
    seal: Vec<u8>,
}

/// In-memory adapter with the same semantics as the filesystem adapter.
#[derive(Default)]
pub struct MemoryEpochStore {
    epochs: Mutex<HashMap<String, MemEpoch>>,
}

impl MemoryEpochStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Test hook: overwrite a sealed entry to simulate backend corruption.
    pub fn corrupt_entry(&self, epoch: &EpochId, name: &EntryName, bytes: &[u8]) {
        if let Ok(mut m) = self.epochs.lock() {
            if let Some(e) = m.get_mut(epoch.as_str()) {
                e.entries.insert(name.as_str().to_owned(), bytes.to_vec());
            }
        }
    }
}

impl EpochBlobStore for MemoryEpochStore {
    fn create_staging(&self, epoch: &EpochId) -> Result<()> {
        let mut m = self.epochs.lock().map_err(|_| R::Io)?;
        if m.contains_key(epoch.as_str()) {
            return Err(R::AlreadyExists);
        }
        m.insert(epoch.as_str().to_owned(), MemEpoch::default());
        Ok(())
    }

    fn put_entry(&self, epoch: &EpochId, name: &EntryName, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(R::TooLarge);
        }
        let mut m = self.epochs.lock().map_err(|_| R::Io)?;
        let e = m.get_mut(epoch.as_str()).ok_or(R::NotFound)?;
        if e.sealed {
            return Err(R::EpochSealed);
        }
        if e.entries.contains_key(name.as_str()) {
            return Err(R::AlreadyExists);
        }
        e.entries.insert(name.as_str().to_owned(), bytes.to_vec());
        Ok(())
    }

    fn list_entries(&self, epoch: &EpochId, stage: Stage) -> Result<Vec<EntryName>> {
        let m = self.epochs.lock().map_err(|_| R::Io)?;
        let e = m.get(epoch.as_str()).ok_or(R::NotFound)?;
        if stage == Stage::Sealed && !e.sealed {
            return Err(R::EpochNotSealed);
        }
        if stage == Stage::Staging && e.sealed {
            return Err(R::NotFound);
        }
        e.entries.keys().map(|k| EntryName::parse(k)).collect()
    }

    fn read_entry(
        &self,
        epoch: &EpochId,
        stage: Stage,
        name: &EntryName,
    ) -> Result<ProtectedBytes> {
        let m = self.epochs.lock().map_err(|_| R::Io)?;
        let e = m.get(epoch.as_str()).ok_or(R::NotFound)?;
        if stage == Stage::Sealed && !e.sealed {
            return Err(R::EpochNotSealed);
        }
        if stage == Stage::Staging && e.sealed {
            return Err(R::NotFound);
        }
        e.entries
            .get(name.as_str())
            .map(|b| ProtectedBytes::new(b.clone()))
            .ok_or(R::NotFound)
    }

    fn finalize(&self, epoch: &EpochId, manifest: &[u8], seal: &[u8]) -> Result<()> {
        let mut m = self.epochs.lock().map_err(|_| R::Io)?;
        let e = m.get_mut(epoch.as_str()).ok_or(R::NotFound)?;
        if e.sealed {
            return Err(R::EpochSealed);
        }
        e.manifest = manifest.to_vec();
        e.seal = seal.to_vec();
        e.sealed = true;
        Ok(())
    }

    fn read_doc(&self, epoch: &EpochId, doc: SealedDoc) -> Result<Vec<u8>> {
        let m = self.epochs.lock().map_err(|_| R::Io)?;
        let e = m.get(epoch.as_str()).ok_or(R::EpochNotSealed)?;
        if !e.sealed {
            return Err(R::EpochNotSealed);
        }
        Ok(match doc {
            SealedDoc::Manifest => e.manifest.clone(),
            SealedDoc::Seal => e.seal.clone(),
        })
    }

    fn discard_staging(&self, epoch: &EpochId) -> Result<()> {
        let mut m = self.epochs.lock().map_err(|_| R::Io)?;
        match m.get(epoch.as_str()) {
            None => Err(R::NotFound),
            Some(e) if e.sealed => Err(R::EpochSealed),
            Some(_) => {
                m.remove(epoch.as_str());
                Ok(())
            }
        }
    }

    fn is_sealed(&self, epoch: &EpochId) -> Result<bool> {
        let m = self.epochs.lock().map_err(|_| R::Io)?;
        Ok(m.get(epoch.as_str()).is_some_and(|e| e.sealed))
    }
}

/// Wraps an adapter and fails every call from the `n`-th onward with
/// `StorageReason::Io`, simulating an unavailable backend. `n = 0` fails
/// immediately.
pub struct FaultyStore<S> {
    inner: S,
    healthy_calls: AtomicUsize,
}

impl<S> FaultyStore<S> {
    pub fn new(inner: S, healthy_calls: usize) -> Self {
        Self {
            inner,
            healthy_calls: AtomicUsize::new(healthy_calls),
        }
    }
    pub fn heal(&self, calls: usize) {
        self.healthy_calls.store(calls, Ordering::SeqCst);
    }
    fn gate(&self) -> Result<()> {
        loop {
            let n = self.healthy_calls.load(Ordering::SeqCst);
            if n == 0 {
                return Err(R::Io);
            }
            if n == usize::MAX {
                return Ok(());
            }
            if self
                .healthy_calls
                .compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

impl<S: EpochBlobStore> EpochBlobStore for FaultyStore<S> {
    fn create_staging(&self, e: &EpochId) -> Result<()> {
        self.gate()?;
        self.inner.create_staging(e)
    }
    fn put_entry(&self, e: &EpochId, n: &EntryName, b: &[u8]) -> Result<()> {
        self.gate()?;
        self.inner.put_entry(e, n, b)
    }
    fn list_entries(&self, e: &EpochId, s: Stage) -> Result<Vec<EntryName>> {
        self.gate()?;
        self.inner.list_entries(e, s)
    }
    fn read_entry(&self, e: &EpochId, s: Stage, n: &EntryName) -> Result<ProtectedBytes> {
        self.gate()?;
        self.inner.read_entry(e, s, n)
    }
    fn finalize(&self, e: &EpochId, m: &[u8], s: &[u8]) -> Result<()> {
        self.gate()?;
        self.inner.finalize(e, m, s)
    }
    fn read_doc(&self, e: &EpochId, d: SealedDoc) -> Result<Vec<u8>> {
        self.gate()?;
        self.inner.read_doc(e, d)
    }
    fn discard_staging(&self, e: &EpochId) -> Result<()> {
        self.gate()?;
        self.inner.discard_staging(e)
    }
    fn is_sealed(&self, e: &EpochId) -> Result<bool> {
        self.gate()?;
        self.inner.is_sealed(e)
    }
}
