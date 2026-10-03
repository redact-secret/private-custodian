//! `X-Hub-Signature-256` verification.
//!
//! HMAC-SHA256 over the exact raw body bytes, compared in constant time by
//! `hmac::Mac::verify_slice`. The header must be exactly `sha256=` followed by
//! 64 hex characters; any other shape (including the legacy SHA-1 header
//! scheme, a missing header or odd casing of the prefix) is rejected without
//! computing anything secret-dependent. All failures return the same code.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::WebhookSecret;
use crate::reason::IntakeReason;

type HmacSha256 = Hmac<Sha256>;

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_signature(header: &str) -> Option<[u8; 32]> {
    let hex = header.strip_prefix("sha256=")?;
    let b = hex.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (hex_val(b[2 * i])? << 4) | hex_val(b[2 * i + 1])?;
    }
    Some(out)
}

/// Verify the signature over `body`. `header` is the raw header value, or
/// `None` if the header was absent.
pub fn verify_signature(
    secret: &WebhookSecret,
    body: &[u8],
    header: Option<&str>,
) -> Result<(), IntakeReason> {
    let expected = header
        .and_then(decode_signature)
        .ok_or(IntakeReason::SignatureInvalid)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.expose()).map_err(|_| IntakeReason::SignatureInvalid)?;
    mac.update(body);
    mac.verify_slice(&expected)
        .map_err(|_| IntakeReason::SignatureInvalid)
}

/// Compute the header value for `body`. Used by tests and by synthetic
/// delivery tooling; production never signs webhooks.
pub fn sign_body(secret: &WebhookSecret, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.expose()).unwrap_or_else(|_| {
        // Unreachable: HMAC accepts any key length.
        HmacSha256::new_from_slice(&[0u8; 32]).expect("fixed key")
    });
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut s = String::from("sha256=");
    for b in tag {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}
