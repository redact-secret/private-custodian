//! Filesystem controls shared by the storage adapter and the registry.
//!
//! Every read of protected material goes through [`read_checked`]: the path
//! is `lstat`-ed (no symlink, regular file, single link, expected owner and
//! exact mode), opened, and the opened descriptor is compared with the
//! `lstat` result (device and inode) so a swap between check and open is
//! detected. The owner is the owner of a probe file the process itself just
//! created, so no `unsafe`/`libc` call is needed to learn the effective uid.

use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::reason::{Result, StorageReason as R};
use crate::secret::{hex, random_bytes};

pub const DIR_PRIVATE: u32 = 0o700;
pub const FILE_PRIVATE: u32 = 0o600;
pub const DIR_SEALED: u32 = 0o500;
pub const FILE_SEALED: u32 = 0o400;

pub fn io_reason(e: &std::io::Error) -> R {
    match e.kind() {
        std::io::ErrorKind::NotFound => R::NotFound,
        std::io::ErrorKind::AlreadyExists => R::AlreadyExists,
        std::io::ErrorKind::PermissionDenied => R::PermissionViolation,
        _ => R::Io,
    }
}

pub fn lstat(path: &Path) -> Result<Metadata> {
    fs::symlink_metadata(path).map_err(|e| io_reason(&e))
}

pub fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(R::Io),
    }
}

fn common_checks(m: &Metadata, uid: u32, mode: u32) -> Result<()> {
    if m.uid() != uid {
        return Err(R::OwnerMismatch);
    }
    if m.mode() & 0o7777 != mode {
        return Err(R::PermissionViolation);
    }
    Ok(())
}

/// Directory must be a real directory (not a symlink), owned by `uid`, with
/// exactly `mode`.
pub fn check_dir(path: &Path, uid: u32, mode: u32) -> Result<()> {
    let m = lstat(path)?;
    let ft = m.file_type();
    if ft.is_symlink() {
        return Err(R::SymlinkRefused);
    }
    if !ft.is_dir() {
        return Err(R::SpecialFileRefused);
    }
    common_checks(&m, uid, mode)
}

pub fn check_file_meta(m: &Metadata, uid: u32, mode: u32) -> Result<()> {
    let ft = m.file_type();
    if ft.is_symlink() {
        return Err(R::SymlinkRefused);
    }
    if !ft.is_file() {
        return Err(R::SpecialFileRefused);
    }
    if m.nlink() != 1 {
        return Err(R::HardlinkRefused);
    }
    common_checks(m, uid, mode)
}

pub fn check_file(path: &Path, uid: u32, mode: u32) -> Result<Metadata> {
    let m = lstat(path)?;
    check_file_meta(&m, uid, mode)?;
    Ok(m)
}

/// Read a regular file that passed [`check_file`], bounded by `max` bytes.
pub fn read_checked(path: &Path, uid: u32, mode: u32, max: u64) -> Result<Vec<u8>> {
    let before = check_file(path, uid, mode)?;
    if before.len() > max {
        return Err(R::TooLarge);
    }
    let file = File::open(path).map_err(|e| io_reason(&e))?;
    let after = file.metadata().map_err(|_| R::Io)?;
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(R::PathEscape);
    }
    check_file_meta(&after, uid, mode)?;
    let mut buf = Vec::with_capacity(usize::try_from(before.len()).map_err(|_| R::TooLarge)?);
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|_| R::Io)?;
    if buf.len() as u64 > max {
        return Err(R::TooLarge);
    }
    Ok(buf)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| io_reason(&e))
}

/// Create one directory (not recursive) with exactly `mode`.
pub fn create_dir(path: &Path, mode: u32) -> Result<()> {
    DirBuilder::new()
        .mode(mode)
        .create(path)
        .map_err(|e| io_reason(&e))?;
    set_mode(path, mode)
}

/// Create a new file (never overwrite) with exactly `mode` and sync it.
pub fn create_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| io_reason(&e))?;
    f.write_all(bytes).map_err(|_| R::Io)?;
    f.sync_all().map_err(|_| R::Io)?;
    drop(f);
    set_mode(path, mode)
}

/// Best-effort durability of directory entries.
pub fn sync_dir(path: &Path) {
    if let Ok(d) = File::open(path) {
        let _ = d.sync_all();
    }
}

/// Learn the owner uid of the process by creating (and removing) a probe file
/// in `dir`, and require it to own `dir` too.
pub fn probe_owner(dir: &Path) -> Result<u32> {
    let name = hex(&random_bytes(8)?);
    let probe = dir.join(format!(".owner-probe-{name}"));
    create_file(&probe, b"", FILE_PRIVATE)?;
    let uid = lstat(&probe).map(|m| m.uid());
    let _ = fs::remove_file(&probe);
    let uid = uid?;
    if lstat(dir)?.uid() != uid {
        return Err(R::OwnerMismatch);
    }
    Ok(uid)
}

/// Refuse a path that is, or sits under, a Git working tree: `.git` (a
/// directory, or a file for worktrees and submodules) in the path or any
/// ancestor. Protected storage must never be creatable inside a checkout.
pub fn refuse_git_tree(canonical: &Path) -> Result<()> {
    for ancestor in canonical.ancestors() {
        if exists(&ancestor.join(".git"))? {
            return Err(R::RootInsideGitTree);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_reason_maps_without_text() {
        let e = std::io::Error::other("secret-path");
        assert_eq!(io_reason(&e), R::Io);
    }
}
