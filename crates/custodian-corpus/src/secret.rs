//! Types that hold protected bytes or key material. None implements
//! `Display`, `Clone` or `Serialize`; `Debug` is redacting; memory is
//! overwritten on drop (best effort, not secure erasure).

use std::fs::File;
use std::io::Read;

use custodian_contracts::types::KeyedCommitment;
use sha2::{Digest, Sha256};

use crate::reason::{Result, StorageReason};

/// Domain separation for the public population commitment (ADR 0031).
pub const COMMITMENT_DOMAIN: &str = "private-custodian/v1/public-population-commitment";

/// Protected corpus bytes. Reachable only through [`ProtectedBytes::expose`].
pub struct ProtectedBytes(Vec<u8>);

impl ProtectedBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for ProtectedBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProtectedBytes(<redacted>)")
    }
}

impl Drop for ProtectedBytes {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Cryptographically secure random bytes from the OS (`/dev/urandom`).
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|_| StorageReason::Io)?;
    Ok(buf)
}

/// HMAC-SHA-256 (RFC 2104) over sha2. Checked against RFC 4231 vectors.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Custodian-held key for public population commitments. Never published,
/// never logged, never in the registry.
pub struct CommitmentKey([u8; 32]);

impl CommitmentKey {
    pub fn generate() -> Result<Self> {
        let v = random_bytes(32)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(&v);
        Ok(Self(k))
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let v = unhex(s.trim()).ok_or(StorageReason::KeyInvalid)?;
        let k: [u8; 32] = v.try_into().map_err(|_| StorageReason::KeyInvalid)?;
        if k == [0u8; 32] {
            return Err(StorageReason::KeyInvalid);
        }
        Ok(Self(k))
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// `hmac-sha256:` commitment over the internal population digest string.
    pub fn commit(&self, population_digest: &str) -> Result<KeyedCommitment> {
        let mut msg = Vec::new();
        msg.extend_from_slice(COMMITMENT_DOMAIN.as_bytes());
        msg.push(0);
        msg.extend_from_slice(population_digest.as_bytes());
        let mac = hmac_sha256(&self.0, &msg);
        KeyedCommitment::parse(&format!("hmac-sha256:{}", hex(&mac)))
            .map_err(|_| StorageReason::KeyInvalid)
    }
}

impl core::fmt::Debug for CommitmentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CommitmentKey(<redacted>)")
    }
}

impl Drop for CommitmentKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case_1() {
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_case_6_long_key() {
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn key_rejects_bad_hex_and_zero() {
        assert!(CommitmentKey::from_hex("zz").is_err());
        assert!(CommitmentKey::from_hex(&"00".repeat(32)).is_err());
        assert!(CommitmentKey::from_hex(&"ab".repeat(31)).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let k = CommitmentKey::generate().unwrap();
        assert_eq!(format!("{k:?}"), "CommitmentKey(<redacted>)");
        let b = ProtectedBytes::new(b"x".to_vec());
        assert_eq!(format!("{b:?}"), "ProtectedBytes(<redacted>)");
    }
}
