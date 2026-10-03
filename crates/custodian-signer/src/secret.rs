//! Key bytes in a type that cannot be printed, cloned or compared by accident.

use zeroize::Zeroize;

/// A 32-byte Ed25519 secret seed. No `Debug` contents, no `Display`, no
/// `Clone`, no `Serialize`; the bytes are zeroized on drop and are reachable
/// only inside this crate.
pub struct SecretSeed([u8; 32]);

impl SecretSeed {
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Build a seed from raw bytes. For key providers outside this crate (a
    /// future KMS adapter) and for tests that generate a key in memory.
    pub fn from_provider_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretSeed(<redacted>)")
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
