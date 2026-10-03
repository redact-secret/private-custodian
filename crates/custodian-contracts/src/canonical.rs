//! Canonical serialization, digests and signing-input construction (ADR 0004).
//!
//! `custodian-canonical-json/1` is a strict subset of RFC 8785 (JCS):
//! compact JSON, object members sorted by key (ASCII, so byte order equals
//! UTF-16 order), unsigned integers up to 2^53 - 1, strings restricted to
//! printable ASCII without `"` or `\`, and no floats, nulls or absent-versus-
//! null ambiguity (optional fields are omitted). Within that subset the output
//! is byte-identical to JCS, so any RFC 8785 implementation reproduces it.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::types::{DocumentDigest, MAX_SAFE_INT};

/// Largest accepted contract document, in bytes. Larger input is rejected
/// before parsing.
pub const MAX_DOCUMENT_BYTES: usize = 65_536;

/// Domain-separation strings. A digest or signature produced under one tag is
/// never valid under another, even for byte-identical payloads. Tags are
/// versioned independently of schemas; changing a tag is a new tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DomainTag {
    Request,
    Plan,
    Approval,
    Reservation,
    Execution,
    InternalReceipt,
    PublicProjection,
    /// Public projection major 2 (destination inside the signed payload).
    /// A separate tag, so a v1 and a v2 document never share a digest or a
    /// signing input (ADR 0119).
    PublicProjectionV2,
    RevocationEnvelope,
    PolicyActivation,
}

impl DomainTag {
    pub const ALL: [DomainTag; 10] = [
        Self::Request,
        Self::Plan,
        Self::Approval,
        Self::Reservation,
        Self::Execution,
        Self::InternalReceipt,
        Self::PublicProjection,
        Self::PublicProjectionV2,
        Self::RevocationEnvelope,
        Self::PolicyActivation,
    ];

    /// The exact bytes mixed into a digest or signature input.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "private-custodian/v1/request",
            Self::Plan => "private-custodian/v1/plan",
            Self::Approval => "private-custodian/v1/approval",
            Self::Reservation => "private-custodian/v1/reservation",
            Self::Execution => "private-custodian/v1/execution",
            Self::InternalReceipt => "private-custodian/v1/internal-receipt",
            Self::PublicProjection => "private-custodian/v1/public-projection",
            Self::PublicProjectionV2 => "private-custodian/v2/public-projection",
            Self::RevocationEnvelope => "private-custodian/v1/revocation-envelope",
            Self::PolicyActivation => "private-custodian/v1/policy-activation",
        }
    }
}

/// `domain || 0x00 || canonical_bytes`. This is both the digest preimage and
/// the byte string a signer signs. Domain tags contain no NUL, so the
/// concatenation is unambiguous.
pub fn signing_input(domain: DomainTag, canonical: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.as_str().len() + 1 + canonical.len());
    out.extend_from_slice(domain.as_str().as_bytes());
    out.push(0);
    out.extend_from_slice(canonical);
    out
}

/// SHA-256 of `signing_input(domain, canonical)`.
pub fn domain_digest(domain: DomainTag, canonical: &[u8]) -> [u8; 32] {
    Sha256::digest(signing_input(domain, canonical)).into()
}

/// SHA-256 of raw bytes with no domain prefix (candidate and artifact bytes,
/// so the value can be checked with any SHA-256 tool).
pub fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn write_string(s: &str, out: &mut Vec<u8>) -> Result<(), ContractError> {
    if !s
        .bytes()
        .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    {
        return Err(ContractError::NotCanonicalizable);
    }
    out.push(b'"');
    out.extend_from_slice(s.as_bytes());
    out.push(b'"');
    Ok(())
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), ContractError> {
    match v {
        Value::Null => Err(ContractError::NotCanonicalizable),
        Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
            Ok(())
        }
        Value::Number(n) => match n.as_u64() {
            Some(u) if u <= MAX_SAFE_INT => {
                out.extend_from_slice(u.to_string().as_bytes());
                Ok(())
            }
            _ => Err(ContractError::NotCanonicalizable),
        },
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
            Ok(())
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out)?;
                out.push(b':');
                if let Some(value) = map.get(k) {
                    write_value(value, out)?;
                }
            }
            out.push(b'}');
            Ok(())
        }
    }
}

/// Canonical bytes of any serializable contract value.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let v = serde_json::to_value(value).map_err(|_| ContractError::NotCanonicalizable)?;
    let mut out = Vec::new();
    write_value(&v, &mut out)?;
    if out.len() > MAX_DOCUMENT_BYTES {
        return Err(ContractError::Oversized);
    }
    Ok(out)
}

/// A versioned contract document.
pub trait Contract: Serialize + DeserializeOwned {
    /// Domain-separation tag for digests and signatures over this document.
    const DOMAIN: DomainTag;

    /// Cross-field consistency that types alone cannot express.
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        to_canonical_bytes(self)
    }

    /// Domain-separated digest of the canonical bytes.
    fn document_digest(&self) -> Result<DocumentDigest, ContractError> {
        Ok(DocumentDigest::from_raw(domain_digest(
            Self::DOMAIN,
            &self.canonical_bytes()?,
        )))
    }

    /// The exact bytes a signer signs for this document (C7 supplies the
    /// signature algorithm and key provider; this fixes the input).
    fn signing_input(&self) -> Result<Vec<u8>, ContractError> {
        Ok(signing_input(Self::DOMAIN, &self.canonical_bytes()?))
    }

    /// Parse untrusted bytes: size cap first, then strict typed parse
    /// (unknown or duplicate fields, wrong schema tag and out-of-bound values
    /// are rejected), then `validate`. The error never echoes input.
    fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::Oversized);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| ContractError::Malformed)?;
        value.validate()?;
        Ok(value)
    }

    /// `decode`, additionally requiring the input to already be the canonical
    /// encoding. Use for anything that will be hashed or verified.
    fn decode_canonical(bytes: &[u8]) -> Result<Self, ContractError> {
        let value = Self::decode(bytes)?;
        if value.canonical_bytes()? != bytes {
            return Err(ContractError::NonCanonical);
        }
        Ok(value)
    }
}
