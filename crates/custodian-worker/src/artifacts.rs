//! Allowlisted pinned artifacts and immutable staging.
//!
//! Engines, adapters, scanners, candidates and configuration are files whose
//! SHA-256 is frozen in the approved plan. They are never imported as source.
//! Each is copied once, hashing the exact bytes copied, into a private staging
//! directory that the sandbox mounts read-only. The staged copy is re-hashed
//! after staging and again after execution.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use custodian_contracts::types::ArtifactDigest;
use sha2::{Digest, Sha256};

use crate::reason::{Result, WorkerReason as R};

/// Largest single artifact the worker will stage.
pub const MAX_ARTIFACT_BYTES: u64 = 1 << 30;
/// Largest single protected input entry (matches the corpus adapter limit).
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

pub fn digest_string(raw: [u8; 32]) -> String {
    ArtifactDigest::from_raw(raw).as_str().to_owned()
}

/// SHA-256 of a regular file, streamed. Refuses non-regular files.
pub fn hash_file(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path).map_err(|_| R::ArtifactInvalid)?;
    if !meta.file_type().is_file() || meta.len() > MAX_ARTIFACT_BYTES {
        return Err(R::ArtifactInvalid);
    }
    let mut f = File::open(path).map_err(|_| R::ArtifactInvalid)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|_| R::ArtifactInvalid)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(digest_string(h.finalize().into()))
}

/// Directories from which pinned artifacts may be taken. Roots must be
/// absolute, exist, and be writable by nobody but their owner.
#[derive(Clone, Debug)]
pub struct ArtifactAllowlist {
    roots: Vec<PathBuf>,
}

impl ArtifactAllowlist {
    pub fn new(roots: &[PathBuf]) -> Result<Self> {
        if roots.is_empty() {
            return Err(R::ArtifactNotAllowlisted);
        }
        let mut out = Vec::new();
        for r in roots {
            if !r.is_absolute() {
                return Err(R::ArtifactNotAllowlisted);
            }
            let c = fs::canonicalize(r).map_err(|_| R::ArtifactNotAllowlisted)?;
            let m = fs::metadata(&c).map_err(|_| R::ArtifactNotAllowlisted)?;
            if !m.is_dir() || m.permissions().mode() & 0o022 != 0 {
                return Err(R::ArtifactNotAllowlisted);
            }
            out.push(c);
        }
        Ok(Self { roots: out })
    }

    /// Resolve a candidate path to a regular, unaliased file under a root.
    /// Symlinks (final component or any ancestor), hard-link aliases and
    /// group/other-writable files or parents are refused.
    pub fn resolve(&self, path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            return Err(R::ArtifactNotAllowlisted);
        }
        let link = fs::symlink_metadata(path).map_err(|_| R::ArtifactInvalid)?;
        if link.file_type().is_symlink() || !link.file_type().is_file() || link.nlink() != 1 {
            return Err(R::ArtifactInvalid);
        }
        if link.permissions().mode() & 0o022 != 0 {
            return Err(R::ArtifactInvalid);
        }
        let canon = fs::canonicalize(path).map_err(|_| R::ArtifactInvalid)?;
        if !self.roots.iter().any(|r| canon.starts_with(r)) {
            return Err(R::ArtifactNotAllowlisted);
        }
        // Every directory between the root and the file must be owner-writable only.
        let mut dir = canon.parent();
        while let Some(d) = dir {
            let m = fs::metadata(d).map_err(|_| R::ArtifactInvalid)?;
            if m.permissions().mode() & 0o022 != 0 {
                return Err(R::ArtifactInvalid);
            }
            if self.roots.iter().any(|r| r == d) {
                break;
            }
            dir = d.parent();
        }
        Ok(canon)
    }
}

/// Reject a member path that could escape its directory when materialized:
/// absolute, `..`, empty components, backslashes, control characters,
/// overlong or too deep. Applies to any future archive reader as well.
pub fn validate_member_path(p: &str) -> Result<()> {
    if p.is_empty() || p.len() > 255 || p.starts_with('/') || p.contains('\\') {
        return Err(R::PathRejected);
    }
    if p.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(R::PathRejected);
    }
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() > 8
        || parts
            .iter()
            .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        return Err(R::PathRejected);
    }
    Ok(())
}

/// A single flat file name: `[a-z0-9][a-z0-9._-]{0,63}`, no `..`.
pub fn validate_flat_name(s: &str) -> Result<()> {
    validate_member_path(s)?;
    let b = s.as_bytes();
    let ok = b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
        && !s.contains("..");
    if ok {
        Ok(())
    } else {
        Err(R::PathRejected)
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct Staged {
    path: PathBuf,
    digest: String,
}

/// One run's staging directory: `stage/` (pinned artifacts, read-only),
/// `input/` (protected inputs, read-only to the worker) and `job/`. Mode 0700,
/// removed on drop. Removal is cleanup, not secure erasure.
#[derive(Debug)]
pub struct Staging {
    root: PathBuf,
    staged: Vec<Staged>,
}

impl Staging {
    pub fn create(base: &Path) -> Result<Self> {
        let meta = fs::metadata(base).map_err(|_| R::StagingFailed)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(R::StagingFailed);
        }
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = base.join(format!("run-{}-{n}-{nanos}", std::process::id()));
        let mut b = DirBuilder::new();
        b.mode(0o700);
        b.create(&root).map_err(|_| R::StagingFailed)?;
        for sub in ["stage", "input", "job"] {
            b.create(root.join(sub)).map_err(|_| R::StagingFailed)?;
        }
        Ok(Self {
            root,
            staged: Vec::new(),
        })
    }

    pub fn stage_dir(&self) -> PathBuf {
        self.root.join("stage")
    }
    pub fn input_dir(&self) -> PathBuf {
        self.root.join("input")
    }
    pub fn job_dir(&self) -> PathBuf {
        self.root.join("job")
    }

    fn write_new(path: &Path, mode: u32, bytes: &[u8]) -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| R::StagingFailed)?;
        f.write_all(bytes).map_err(|_| R::StagingFailed)?;
        f.sync_all().map_err(|_| R::StagingFailed)?;
        drop(f);
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| R::StagingFailed)?;
        let m = fs::symlink_metadata(path).map_err(|_| R::StagingFailed)?;
        if !m.file_type().is_file() || m.nlink() != 1 {
            return Err(R::StagingFailed);
        }
        Ok(())
    }

    /// Copy `source` into `stage/<name>`, hashing the bytes actually copied,
    /// and require the digest to equal the frozen `expected`. A mismatch
    /// removes the copy.
    pub fn stage_pinned(
        &mut self,
        name: &str,
        source: &Path,
        expected: &str,
        executable: bool,
    ) -> Result<()> {
        validate_flat_name(name)?;
        let meta = fs::symlink_metadata(source).map_err(|_| R::ArtifactInvalid)?;
        if !meta.file_type().is_file() || meta.len() > MAX_ARTIFACT_BYTES {
            return Err(R::ArtifactInvalid);
        }
        let mut src = File::open(source).map_err(|_| R::ArtifactInvalid)?;
        let dest = self.stage_dir().join(name);
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dest)
            .map_err(|_| R::StagingFailed)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = src.read(&mut buf).map_err(|_| R::ArtifactInvalid)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_ARTIFACT_BYTES {
                let _ = fs::remove_file(&dest);
                return Err(R::ArtifactInvalid);
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(|_| R::StagingFailed)?;
        }
        out.sync_all().map_err(|_| R::StagingFailed)?;
        drop(out);
        let got = digest_string(h.finalize().into());
        if got != expected {
            let _ = fs::remove_file(&dest);
            return Err(R::IdentityMismatch);
        }
        let mode = if executable { 0o500 } else { 0o400 };
        fs::set_permissions(&dest, fs::Permissions::from_mode(mode))
            .map_err(|_| R::StagingFailed)?;
        self.staged.push(Staged {
            path: dest,
            digest: got,
        });
        Ok(())
    }

    /// Re-hash every staged artifact from disk. Any difference fails closed.
    pub fn verify(&self, on_change: R) -> Result<()> {
        for s in &self.staged {
            match hash_file(&s.path) {
                Ok(d) if d == s.digest => {}
                _ => return Err(on_change),
            }
        }
        Ok(())
    }

    /// Materialize one protected input entry as a new read-only regular file.
    /// Never overwrites, never follows a link, never creates directories.
    pub fn materialize_input(&self, name: &str, bytes: &[u8]) -> Result<()> {
        validate_flat_name(name)?;
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(R::StagingFailed);
        }
        Self::write_new(&self.input_dir().join(name), 0o400, bytes)
    }

    pub fn write_job(&self, bytes: &[u8]) -> Result<()> {
        Self::write_new(&self.job_dir().join("job.json"), 0o400, bytes)
    }

    /// Every entry directly under `input/` must still be a regular file with
    /// one link. Run after staging and after execution.
    pub fn verify_input_shape(&self, expected: usize) -> Result<()> {
        let mut n = 0;
        for e in fs::read_dir(self.input_dir()).map_err(|_| R::StagingFailed)? {
            let e = e.map_err(|_| R::StagingFailed)?;
            let m = fs::symlink_metadata(e.path()).map_err(|_| R::StagingFailed)?;
            if !m.file_type().is_file() || m.nlink() != 1 {
                return Err(R::StagingFailed);
            }
            n += 1;
        }
        if n == expected {
            Ok(())
        } else {
            Err(R::StagingFailed)
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_paths() {
        for ok in ["a", "a/b", "name.v1"] {
            assert!(validate_member_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/etc/x",
            "../x",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
            "a\0b",
            "a\nb",
            "./a",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert!(validate_member_path(bad).is_err(), "{bad:?}");
        }
        assert!(validate_member_path(&"a".repeat(256)).is_err());
    }

    #[test]
    fn flat_names() {
        assert!(validate_flat_name("entry-1.txt").is_ok());
        for bad in ["A", "a/b", "..", "a..b", ".hidden", "a b", "é"] {
            assert!(validate_flat_name(bad).is_err(), "{bad:?}");
        }
    }
}
