//! Filesystem adapter (ADR 0030).
//!
//! Layout under the protected root (all owned by the service identity):
//!
//! ```text
//! <root>/                       0700
//!   staging/<epoch>/entries/<name>        dirs 0700, files 0600
//!   sealed/<epoch>/entries/<name>         dirs 0500, files 0400
//!   sealed/<epoch>/MANIFEST, SEAL         files 0400
//!   registry/events.jsonl                 0600 (see registry.rs)
//!   keys/commitment.key                   0600
//! ```
//!
//! `finalize` writes the documents, makes everything read-only and publishes
//! with one directory `rename` from `staging/` to `sealed/`, so a sealed epoch
//! appears whole or not at all. The root must exist, be owned by the process
//! owner, have mode 0700 and not be inside a Git working tree.

use std::fs;
use std::path::{Path, PathBuf};

use custodian_contracts::types::EpochId;

use crate::fsguard::{self as g, DIR_PRIVATE, DIR_SEALED, FILE_PRIVATE, FILE_SEALED};
use crate::manifest::MAX_MANIFEST_BYTES;
use crate::reason::{Result, StorageReason as R};
use crate::secret::ProtectedBytes;
use crate::store::{EntryName, EpochBlobStore, SealedDoc, Stage, MAX_ENTRIES, MAX_ENTRY_BYTES};

const MAX_SEAL_BYTES: u64 = 65_536;
const MANIFEST_FILE: &str = "MANIFEST";
const SEAL_FILE: &str = "SEAL";

pub struct FsEpochStore {
    root: PathBuf,
    uid: u32,
}

impl core::fmt::Debug for FsEpochStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FsEpochStore(<redacted>)")
    }
}

impl FsEpochStore {
    /// Open an existing, operator-provisioned protected root.
    ///
    /// Refuses: relative path, symlink root, non-directory, root inside a Git
    /// working tree (the root or any ancestor containing `.git`), wrong
    /// owner, mode other than 0700. Creates the fixed sub-directories (0700)
    /// if absent and verifies them if present.
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err(R::RootInvalid);
        }
        let meta = g::lstat(root).map_err(|_| R::RootInvalid)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(R::RootInvalid);
        }
        let canonical = fs::canonicalize(root).map_err(|_| R::RootInvalid)?;
        g::refuse_git_tree(&canonical)?;
        if std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777 != DIR_PRIVATE {
            return Err(R::PermissionViolation);
        }
        let uid = g::probe_owner(&canonical)?;
        g::check_dir(&canonical, uid, DIR_PRIVATE)?;
        let store = Self {
            root: canonical,
            uid,
        };
        for d in ["staging", "sealed", "registry", "keys"] {
            let p = store.root.join(d);
            if g::exists(&p)? {
                g::check_dir(&p, uid, DIR_PRIVATE)?;
            } else {
                g::create_dir(&p, DIR_PRIVATE)?;
            }
        }
        Ok(store)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    fn stage_dir(&self, stage: Stage) -> PathBuf {
        self.root.join(match stage {
            Stage::Staging => "staging",
            Stage::Sealed => "sealed",
        })
    }

    fn epoch_dir(&self, stage: Stage, epoch: &EpochId) -> PathBuf {
        self.stage_dir(stage).join(epoch.as_str())
    }

    fn modes(stage: Stage) -> (u32, u32) {
        match stage {
            Stage::Staging => (DIR_PRIVATE, FILE_PRIVATE),
            Stage::Sealed => (DIR_SEALED, FILE_SEALED),
        }
    }

    /// Verify root, stage dir, epoch dir and entries dir (no symlinks, owner,
    /// exact modes) and return `(epoch_dir, entries_dir)`.
    fn checked_dirs(&self, stage: Stage, epoch: &EpochId) -> Result<(PathBuf, PathBuf)> {
        let (dir_mode, _) = Self::modes(stage);
        g::check_dir(&self.root, self.uid, DIR_PRIVATE)?;
        g::check_dir(&self.stage_dir(stage), self.uid, DIR_PRIVATE)?;
        let ed = self.epoch_dir(stage, epoch);
        g::check_dir(&ed, self.uid, dir_mode).map_err(|r| match r {
            R::NotFound if stage == Stage::Sealed => R::EpochNotSealed,
            r => r,
        })?;
        let entries = ed.join("entries");
        g::check_dir(&entries, self.uid, dir_mode)?;
        Ok((ed, entries))
    }
}

impl EpochBlobStore for FsEpochStore {
    fn create_staging(&self, epoch: &EpochId) -> Result<()> {
        if g::exists(&self.epoch_dir(Stage::Sealed, epoch))? {
            return Err(R::AlreadyExists);
        }
        let ed = self.epoch_dir(Stage::Staging, epoch);
        g::create_dir(&ed, DIR_PRIVATE)?;
        g::create_dir(&ed.join("entries"), DIR_PRIVATE)
    }

    fn put_entry(&self, epoch: &EpochId, name: &EntryName, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 > MAX_ENTRY_BYTES {
            return Err(R::TooLarge);
        }
        if g::exists(&self.epoch_dir(Stage::Sealed, epoch))? {
            return Err(R::EpochSealed);
        }
        let (_, entries) = self.checked_dirs(Stage::Staging, epoch)?;
        g::create_file(&entries.join(name.as_str()), bytes, FILE_PRIVATE)
    }

    fn list_entries(&self, epoch: &EpochId, stage: Stage) -> Result<Vec<EntryName>> {
        let (ed, entries) = self.checked_dirs(stage, epoch)?;
        if stage == Stage::Sealed {
            // Nothing but the layout we wrote may exist in a sealed epoch.
            let mut seen = Vec::new();
            for child in fs::read_dir(&ed).map_err(|_| R::Io)? {
                let child = child.map_err(|_| R::Io)?;
                seen.push(child.file_name().to_string_lossy().into_owned());
            }
            seen.sort();
            if seen != ["MANIFEST", "SEAL", "entries"] {
                return Err(R::LayoutInvalid);
            }
        }
        let mut names = Vec::new();
        for child in fs::read_dir(&entries).map_err(|_| R::Io)? {
            let child = child.map_err(|_| R::Io)?;
            let raw = child.file_name();
            let name = raw
                .to_str()
                .and_then(|s| EntryName::parse(s).ok())
                .ok_or(R::LayoutInvalid)?;
            names.push(name);
            if names.len() > MAX_ENTRIES {
                return Err(R::TooLarge);
            }
        }
        names.sort();
        Ok(names)
    }

    fn read_entry(
        &self,
        epoch: &EpochId,
        stage: Stage,
        name: &EntryName,
    ) -> Result<ProtectedBytes> {
        let (_, entries) = self.checked_dirs(stage, epoch)?;
        let (_, file_mode) = Self::modes(stage);
        g::read_checked(
            &entries.join(name.as_str()),
            self.uid,
            file_mode,
            MAX_ENTRY_BYTES,
        )
        .map(ProtectedBytes::new)
    }

    fn finalize(&self, epoch: &EpochId, manifest: &[u8], seal: &[u8]) -> Result<()> {
        let sealed = self.epoch_dir(Stage::Sealed, epoch);
        if g::exists(&sealed)? {
            return Err(R::EpochSealed);
        }
        let (ed, entries) = self.checked_dirs(Stage::Staging, epoch)?;
        if manifest.len() as u64 > MAX_MANIFEST_BYTES || seal.len() as u64 > MAX_SEAL_BYTES {
            return Err(R::TooLarge);
        }
        // Every staged entry must be a plain private file before it is frozen.
        let names = self.list_entries(epoch, Stage::Staging)?;
        for n in &names {
            g::check_file(&entries.join(n.as_str()), self.uid, FILE_PRIVATE)?;
        }
        g::create_file(&ed.join(MANIFEST_FILE), manifest, FILE_SEALED)?;
        g::create_file(&ed.join(SEAL_FILE), seal, FILE_SEALED)?;
        for n in &names {
            g::set_mode(&entries.join(n.as_str()), FILE_SEALED)?;
        }
        g::set_mode(&entries, DIR_SEALED)?;
        // One rename publishes the whole epoch. Moving a directory between
        // parents needs write permission on it, so the epoch directory is
        // made read-only right after the move; until then readers refuse it
        // (their mode check requires 0500), which fails closed.
        if g::exists(&sealed)? {
            return Err(R::EpochSealed);
        }
        fs::rename(&ed, &sealed).map_err(|_| R::Io)?;
        g::set_mode(&sealed, DIR_SEALED)?;
        g::sync_dir(&self.stage_dir(Stage::Sealed));
        g::sync_dir(&self.stage_dir(Stage::Staging));
        Ok(())
    }

    fn read_doc(&self, epoch: &EpochId, doc: SealedDoc) -> Result<Vec<u8>> {
        let (ed, _) = self.checked_dirs(Stage::Sealed, epoch)?;
        let (file, max) = match doc {
            SealedDoc::Manifest => (MANIFEST_FILE, MAX_MANIFEST_BYTES),
            SealedDoc::Seal => (SEAL_FILE, MAX_SEAL_BYTES),
        };
        g::read_checked(&ed.join(file), self.uid, FILE_SEALED, max)
    }

    fn discard_staging(&self, epoch: &EpochId) -> Result<()> {
        if g::exists(&self.epoch_dir(Stage::Sealed, epoch))? {
            return Err(R::EpochSealed);
        }
        let ed = self.epoch_dir(Stage::Staging, epoch);
        let meta = g::lstat(&ed)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(R::SymlinkRefused);
        }
        // A failed `finalize` can leave read-only modes behind; restore them
        // so the removal can proceed. Never follow symlinks.
        let entries = ed.join("entries");
        if let Ok(rd) = fs::read_dir(&entries) {
            let _ = g::set_mode(&entries, DIR_PRIVATE);
            for c in rd.flatten() {
                if let Ok(m) = fs::symlink_metadata(c.path()) {
                    if m.is_file() {
                        let _ = g::set_mode(&c.path(), FILE_PRIVATE);
                    }
                }
            }
        }
        let _ = g::set_mode(&ed, DIR_PRIVATE);
        fs::remove_dir_all(&ed).map_err(|_| R::Io)
    }

    fn is_sealed(&self, epoch: &EpochId) -> Result<bool> {
        g::exists(&self.epoch_dir(Stage::Sealed, epoch))
    }
}
