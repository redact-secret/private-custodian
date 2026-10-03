//! Key providers (ADR 0112).
//!
//! A provider hands the signer process its secret seed. The only provider in
//! this repository is [`FileKeyProvider`], used with test keys generated inside
//! tests. Production provisioning is manual and happens on the signer host
//! only; a KMS or HSM provider is a future implementation of the same trait.

use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;

use zeroize::Zeroize;

use crate::secret::SecretSeed;

/// Why a key could not be loaded. Fixed vocabulary; never names a path and
/// never carries key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyProviderError {
    NotFound,
    /// The containing directory is a symlink, not a directory, not owned by
    /// the signer's effective uid, or accessible to group or other.
    InsecureDirectory,
    /// The key path is a symlink, not a regular file, or a socket/device.
    NotRegularFile,
    /// More than one hard link points at the key file.
    HardLinked,
    /// Not owned by the signer's effective uid.
    WrongOwner,
    /// Accessible to group or other, or executable.
    InsecurePermissions,
    /// The file changed between the path check and the open.
    Raced,
    /// Not exactly 64 lowercase hex characters (one trailing newline allowed).
    Malformed,
    /// A provider outside this crate could not reach its backend.
    Unavailable,
}

impl KeyProviderError {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotFound => "key_not_found",
            Self::InsecureDirectory => "key_directory_insecure",
            Self::NotRegularFile => "key_not_regular_file",
            Self::HardLinked => "key_hard_linked",
            Self::WrongOwner => "key_wrong_owner",
            Self::InsecurePermissions => "key_permissions_insecure",
            Self::Raced => "key_file_raced",
            Self::Malformed => "key_malformed",
            Self::Unavailable => "key_provider_unavailable",
        }
    }
}

impl core::fmt::Display for KeyProviderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for KeyProviderError {}

/// Supplies the signer process with its secret seed. Implementations must not
/// log, print or persist the seed and must fail closed.
pub trait KeyProvider {
    fn load_seed(&self) -> Result<SecretSeed, KeyProviderError>;
}

/// The effective uid of this process.
pub fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Reads a hex-encoded seed from an owner-only file in an owner-only
/// directory. Checks, in order: the directory is a real directory (not a
/// symlink) owned by the effective uid with no group/other access; the key path
/// is a regular file (not a symlink) with one link, owned by the effective uid,
/// with no group/other access and no execute bit; the opened file is the same
/// file that was checked (device and inode); the content is exactly the format.
/// Ancestors above the immediate directory are not checked (ADR 0112).
pub struct FileKeyProvider {
    path: PathBuf,
}

impl FileKeyProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl core::fmt::Debug for FileKeyProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FileKeyProvider(<path omitted>)")
    }
}

const SEED_HEX_LEN: usize = 64;

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl KeyProvider for FileKeyProvider {
    fn load_seed(&self) -> Result<SecretSeed, KeyProviderError> {
        let euid = effective_uid();
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(KeyProviderError::InsecureDirectory)?;
        let dmeta = std::fs::symlink_metadata(dir).map_err(|_| KeyProviderError::NotFound)?;
        if !dmeta.file_type().is_dir() || dmeta.uid() != euid || dmeta.mode() & 0o077 != 0 {
            return Err(KeyProviderError::InsecureDirectory);
        }
        let lmeta =
            std::fs::symlink_metadata(&self.path).map_err(|_| KeyProviderError::NotFound)?;
        let ft = lmeta.file_type();
        if ft.is_symlink() || !ft.is_file() || ft.is_socket() {
            return Err(KeyProviderError::NotRegularFile);
        }
        let mut file = std::fs::File::open(&self.path).map_err(|_| KeyProviderError::NotFound)?;
        let fmeta = file.metadata().map_err(|_| KeyProviderError::NotFound)?;
        if !fmeta.file_type().is_file() || fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino()
        {
            return Err(KeyProviderError::Raced);
        }
        if fmeta.nlink() != 1 {
            return Err(KeyProviderError::HardLinked);
        }
        if fmeta.uid() != euid {
            return Err(KeyProviderError::WrongOwner);
        }
        if fmeta.mode() & 0o177 != 0 {
            return Err(KeyProviderError::InsecurePermissions);
        }
        if fmeta.len() as usize > SEED_HEX_LEN + 1 {
            return Err(KeyProviderError::Malformed);
        }
        let mut buf = Vec::with_capacity(SEED_HEX_LEN + 2);
        let read = (&mut file)
            .take(SEED_HEX_LEN as u64 + 2)
            .read_to_end(&mut buf);
        let result = match read {
            Ok(_) => decode_seed(&buf),
            Err(_) => Err(KeyProviderError::NotFound),
        };
        buf.zeroize();
        result
    }
}

fn decode_seed(buf: &[u8]) -> Result<SecretSeed, KeyProviderError> {
    let body = match buf.len() {
        SEED_HEX_LEN => buf,
        n if n == SEED_HEX_LEN + 1 && buf[n - 1] == b'\n' => &buf[..SEED_HEX_LEN],
        _ => return Err(KeyProviderError::Malformed),
    };
    let mut seed = [0u8; 32];
    for (i, pair) in body.chunks_exact(2).enumerate() {
        match (hex_val(pair[0]), hex_val(pair[1])) {
            (Some(h), Some(l)) => seed[i] = (h << 4) | l,
            _ => {
                seed.zeroize();
                return Err(KeyProviderError::Malformed);
            }
        }
    }
    let out = SecretSeed::from_provider_bytes(seed);
    seed.zeroize();
    Ok(out)
}
