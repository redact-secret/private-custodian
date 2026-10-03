//! RS256 signing of the GitHub App JWT (RSASSA-PKCS1-v1_5 with SHA-256) with
//! `ring` (ADR 0124).
//!
//! The private key is read from a regular, non-symlink file readable only by
//! its owner (`0600`: no group or other bits at all), parsed once, and kept
//! inside `ring`'s key pair. The file bytes and the decoded DER are zeroized
//! after parsing. The type has a redacted `Debug`, no `Display`, no `Clone`,
//! no `Serialize`, and its only operation is signing a JWT signing input.
//! Errors are fixed words and never name the path or echo any key text.
//!
//! GitHub hands out PKCS#1 PEM (`BEGIN RSA PRIVATE KEY`); PKCS#8
//! (`BEGIN PRIVATE KEY`) is accepted too. Encrypted keys and every other type
//! are refused, as are keys outside `ring`'s 2048 to 8192 bit range.

use std::path::Path;

use custodian_intake::credentials::AppJwtSigner;
use custodian_intake::IntakeReason;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use zeroize::Zeroize;

/// Largest key file read. An RSA-8192 PEM is under 7 KiB.
const MAX_KEY_FILE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Missing, unreadable, a symlink, not a regular file, too large, or
    /// readable by anyone but its owner.
    Unreadable,
    /// Not exactly one PEM block with valid base64.
    NotPem,
    /// A PEM label other than a plain RSA private key (for example an
    /// encrypted or elliptic-curve key).
    Unsupported,
    /// A well-formed block that is not an RSA private key `ring` accepts.
    Rejected,
}

impl KeyError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "key_unreadable",
            Self::NotPem => "key_not_pem",
            Self::Unsupported => "key_unsupported",
            Self::Rejected => "key_rejected",
        }
    }
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for KeyError {}

/// The App's signing key. See the module documentation.
pub struct Rs256Signer {
    pair: RsaKeyPair,
    rng: SystemRandom,
}

impl core::fmt::Debug for Rs256Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rs256Signer(<redacted>)")
    }
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding; whitespace is skipped. Strict about
/// everything else.
fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(s.len());
    let mut pad = 0usize;
    for &c in s {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'=' => pad += 1,
            _ if pad > 0 => return None,
            _ => vals.push(u8::try_from(STD.iter().position(|&x| x == c)?).ok()?),
        }
    }
    // A final quantum is 4 symbols, or 2 symbols and "==", or 3 and "=".
    if !matches!((vals.len() % 4, pad), (0, 0) | (2, 2) | (3, 1)) {
        return None;
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let mut n = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            n |= u32::from(*v) << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..chunk.len()]);
    }
    Some(out)
}

/// Extract the single PEM block: its label and decoded bytes.
fn pem_block(text: &str) -> Result<(String, Vec<u8>), KeyError> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let begin = lines.next().ok_or(KeyError::NotPem)?;
    let label = begin
        .strip_prefix("-----BEGIN ")
        .and_then(|r| r.strip_suffix("-----"))
        .ok_or(KeyError::NotPem)?
        .to_owned();
    let mut b64 = String::new();
    let mut ended = false;
    for l in lines.by_ref() {
        if let Some(e) = l.strip_prefix("-----END ") {
            if e.strip_suffix("-----") != Some(label.as_str()) {
                return Err(KeyError::NotPem);
            }
            ended = true;
            break;
        }
        // Headers (`Proc-Type`, `DEK-Info`) mark an encrypted legacy key.
        if l.contains(':') {
            b64.zeroize();
            return Err(KeyError::Unsupported);
        }
        b64.push_str(l);
    }
    if !ended || lines.next().is_some() {
        b64.zeroize();
        return Err(KeyError::NotPem);
    }
    let der = b64_decode(b64.as_bytes());
    b64.zeroize();
    Ok((label, der.ok_or(KeyError::NotPem)?))
}

impl Rs256Signer {
    /// Parse a PEM private key. The input is not retained.
    pub fn from_pem(pem: &[u8]) -> Result<Self, KeyError> {
        let text = std::str::from_utf8(pem).map_err(|_| KeyError::NotPem)?;
        let (label, mut der) = pem_block(text)?;
        let pair = match label.as_str() {
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
            _ => {
                der.zeroize();
                return Err(KeyError::Unsupported);
            }
        };
        der.zeroize();
        Ok(Self {
            pair: pair.map_err(|_| KeyError::Rejected)?,
            rng: SystemRandom::new(),
        })
    }

    /// Read the key from `path`: a regular file, not a symlink, no group or
    /// other permission bits, at most 16 KiB. The bytes are zeroized after
    /// parsing.
    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        let mut bytes = custodian_cli::deploy::read_checked(path, MAX_KEY_FILE_BYTES, 0o077)
            .map_err(|_| KeyError::Unreadable)?;
        let out = Self::from_pem(&bytes);
        bytes.zeroize();
        out
    }

    /// The public half, as the DER `RSAPublicKey` GitHub shows as the App's
    /// key. Public by definition; tests verify signatures with it.
    pub fn public_key_der(&self) -> Vec<u8> {
        self.pair.public().as_ref().to_vec()
    }

    /// Key size in bits.
    pub fn bits(&self) -> usize {
        self.pair.public().modulus_len() * 8
    }
}

impl AppJwtSigner for Rs256Signer {
    fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, IntakeReason> {
        let mut sig = vec![0u8; self.pair.public().modulus_len()];
        self.pair
            .sign(&RSA_PKCS1_SHA256, &self.rng, signing_input, &mut sig)
            .map_err(|_| IntakeReason::AppAuthFailed)?;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decoding_is_strict() {
        assert_eq!(b64_decode(b"TWFu").unwrap(), b"Man");
        assert_eq!(b64_decode(b"TWE=").unwrap(), b"Ma");
        assert_eq!(b64_decode(b"TQ==").unwrap(), b"M");
        assert_eq!(b64_decode(b"TW\nFu\r\n").unwrap(), b"Man");
        assert_eq!(b64_decode(b"").unwrap(), b"");
        for bad in [
            &b"T"[..],
            b"TWF",
            b"TW=u",
            b"TWFu=",
            b"TQ=",
            b"TQ===",
            b"T!Fu",
            b"=TWF",
            b"TWFuTQ=A",
            b"TWFu\xff",
        ] {
            assert!(b64_decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn only_one_plain_rsa_private_key_block_is_accepted() {
        let junk = "AAAA";
        for (pem, want) in [
            ("", KeyError::NotPem),
            ("not pem", KeyError::NotPem),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n",
                KeyError::NotPem,
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                KeyError::NotPem,
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\n!!!!\n-----END RSA PRIVATE KEY-----\n",
                KeyError::NotPem,
            ),
            (
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
                KeyError::Unsupported,
            ),
            (
                "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
                KeyError::Unsupported,
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n",
                KeyError::Unsupported,
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
                KeyError::NotPem,
            ),
            (
                // Well-formed block, not a key.
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
                KeyError::Rejected,
            ),
        ] {
            assert_eq!(Rs256Signer::from_pem(pem.as_bytes()).err(), Some(want), "{pem}");
        }
        let _ = junk;
    }

    #[test]
    fn debug_never_prints_key_material() {
        // A key cannot be built here without a real one; the redaction is
        // asserted by the integration test that builds a throwaway key. The
        // error type must not carry text at all.
        assert_eq!(KeyError::Rejected.to_string(), "key_rejected");
    }
}
