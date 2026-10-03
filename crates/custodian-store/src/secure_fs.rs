//! Owner-only file handling for the runtime database.
//!
//! The directory must be 0700 and the database file 0600, neither a symlink.
//! The store creates what is missing with those modes and refuses to open
//! anything wider: it never silently chmods an existing path, because a wider
//! mode may mean the file was already exposed (an incident, not a nuisance).
//! SQLite creates `-wal` and `-shm` with the database file's mode.

use std::fs;
use std::path::Path;

use crate::error::StoreError;

#[cfg(unix)]
mod imp {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    pub const DIR_MODE: u32 = 0o700;
    pub const FILE_MODE: u32 = 0o600;

    fn owner_only(mode: u32) -> bool {
        mode & 0o077 == 0
    }

    fn check_dir(dir: &Path) -> Result<(), StoreError> {
        let meta = fs::symlink_metadata(dir).map_err(|_| StoreError::Io)?;
        if !meta.is_dir() || !owner_only(meta.mode()) {
            return Err(StoreError::Permissions);
        }
        Ok(())
    }

    /// Create the parent directory (0700) if missing and the database file
    /// (0600) if missing; verify both otherwise.
    pub fn prepare(db: &Path) -> Result<(), StoreError> {
        let dir = db
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(StoreError::Io)?;
        match fs::symlink_metadata(dir) {
            Ok(_) => check_dir(dir)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(DIR_MODE)
                    .create(dir)
                    .map_err(|_| StoreError::Io)?;
                check_dir(dir)?;
            }
            Err(_) => return Err(StoreError::Io),
        }
        match fs::symlink_metadata(db) {
            Ok(meta) => {
                if !meta.is_file() || !owner_only(meta.mode()) {
                    return Err(StoreError::Permissions);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(FILE_MODE)
                    .open(db)
                    .map_err(|_| StoreError::Io)?;
            }
            Err(_) => return Err(StoreError::Io),
        }
        Ok(())
    }

    /// Mode bits of a path (tests and diagnostics).
    pub fn mode_of(path: &Path) -> Result<u32, StoreError> {
        fs::symlink_metadata(path)
            .map(|m| m.mode() & 0o777)
            .map_err(|_| StoreError::Io)
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    /// Owner-only modes are not enforceable here; refuse rather than run
    /// with an unverified boundary.
    pub fn prepare(_db: &Path) -> Result<(), StoreError> {
        Err(StoreError::Permissions)
    }
    pub fn mode_of(_path: &Path) -> Result<u32, StoreError> {
        Err(StoreError::Permissions)
    }
}

pub(crate) use imp::prepare;

/// Mode bits of `path` (lower 9 bits). Unix only; other platforms refuse.
pub fn mode_of(path: &Path) -> Result<u32, StoreError> {
    imp::mode_of(path)
}
