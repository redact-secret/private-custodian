//! Public key registry, key lifecycle and signature verification (ADR 0050).
//!
//! Verification needs only public keys. A verifier starts from one or more
//! pinned root keys obtained out of band (never from the ledger it is
//! checking) and extends its keyring only with key-event records that verify
//! under the keys it already trusts.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::canonical::Contract;
use custodian_contracts::common::{Signature, SignatureAlgorithm};
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::revocation::SignedRevocationEnvelope;
use custodian_contracts::types::{KeyId, Timestamp};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};

use crate::b64;
use crate::domain::SignDomain;
use crate::record::{KeyAction, RecordBody, SignedLedgerRecord};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub key_id: KeyId,
    pub public_key: [u8; 32],
    pub purposes: BTreeSet<SignDomain>,
    pub valid_from: Timestamp,
    /// Signatures issued at or after this time are not valid. A retired key's
    /// earlier signatures stay valid.
    pub retired_at: Option<Timestamp>,
    /// Every signature by this key is rejected, whenever issued.
    pub revoked_at: Option<Timestamp>,
}

impl KeyEntry {
    /// A pinned root: public key as 64 lowercase hex, obtained out of band.
    pub fn root(
        key_id: KeyId,
        public_key_hex: &str,
        purposes: impl IntoIterator<Item = SignDomain>,
        valid_from: Timestamp,
    ) -> Option<Self> {
        Some(Self {
            key_id,
            public_key: b64::unhex32(public_key_hex)?,
            purposes: purposes.into_iter().collect(),
            valid_from,
            retired_at: None,
            revoked_at: None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyError {
    UnsupportedAlgorithm,
    UnknownKey,
    KeyRevoked,
    /// The key was not yet valid, or already retired, at the signing time.
    KeyNotValidAtTime,
    /// The key is not authorized for this document domain.
    WrongDomain,
    MalformedSignature,
    BadSignature,
    /// The payload does not decode as the document type of the domain.
    PayloadInvalid,
}

impl VerifyError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm => "verify_unsupported_algorithm",
            Self::UnknownKey => "verify_unknown_key",
            Self::KeyRevoked => "verify_key_revoked",
            Self::KeyNotValidAtTime => "verify_key_not_valid_at_time",
            Self::WrongDomain => "verify_wrong_domain",
            Self::MalformedSignature => "verify_malformed_signature",
            Self::BadSignature => "verify_bad_signature",
            Self::PayloadInvalid => "verify_payload_invalid",
        }
    }
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for VerifyError {}

/// Why a key-event record was not applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyringError {
    /// The record's signature did not verify under the current keyring.
    NotAuthorized(VerifyError),
    NotAKeyEvent,
    KeyAlreadyKnown,
    UnknownTarget,
    BadPublicKey,
}

#[derive(Clone, Debug, Default)]
pub struct Keyring {
    keys: BTreeMap<KeyId, KeyEntry>,
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pinned root key (out-of-band trust anchor).
    pub fn with_root(mut self, entry: KeyEntry) -> Self {
        self.keys.insert(entry.key_id.clone(), entry);
        self
    }

    pub fn get(&self, key_id: &KeyId) -> Option<&KeyEntry> {
        self.keys.get(key_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Apply a key-event record (publish, retire, revoke). The record must
    /// verify under a key this keyring already trusts for `LedgerKeyEvent`,
    /// so rotation is a chain of trust from the pinned roots.
    pub fn apply_key_event(&mut self, signed: &SignedLedgerRecord) -> Result<(), KeyringError> {
        Verifier::new(self.clone())
            .verify_ledger_record(signed)
            .map_err(KeyringError::NotAuthorized)?;
        let RecordBody::KeyEvent(ev) = &signed.payload.body else {
            return Err(KeyringError::NotAKeyEvent);
        };
        match ev.action {
            KeyAction::Published => {
                if self.keys.contains_key(&ev.key_id) {
                    return Err(KeyringError::KeyAlreadyKnown);
                }
                let pk = ev
                    .public_key
                    .as_deref()
                    .and_then(b64::unhex32)
                    .ok_or(KeyringError::BadPublicKey)?;
                // Reject invalid and small-order keys now, not at first use.
                let vk = VerifyingKey::from_bytes(&pk).map_err(|_| KeyringError::BadPublicKey)?;
                if vk.is_weak() {
                    return Err(KeyringError::BadPublicKey);
                }
                self.keys.insert(
                    ev.key_id.clone(),
                    KeyEntry {
                        key_id: ev.key_id.clone(),
                        public_key: pk,
                        purposes: ev.purposes.iter().copied().collect(),
                        valid_from: ev.effective_at,
                        retired_at: None,
                        revoked_at: None,
                    },
                );
            }
            KeyAction::Retired => {
                let e = self
                    .keys
                    .get_mut(&ev.key_id)
                    .ok_or(KeyringError::UnknownTarget)?;
                e.retired_at = Some(
                    e.retired_at
                        .map_or(ev.effective_at, |t| t.min(ev.effective_at)),
                );
            }
            KeyAction::Revoked => {
                let e = self
                    .keys
                    .get_mut(&ev.key_id)
                    .ok_or(KeyringError::UnknownTarget)?;
                e.revoked_at = Some(
                    e.revoked_at
                        .map_or(ev.effective_at, |t| t.min(ev.effective_at)),
                );
            }
        }
        Ok(())
    }
}

/// Verifies signatures with public keys only.
#[derive(Clone, Debug)]
pub struct Verifier {
    keyring: Keyring,
}

impl Verifier {
    pub fn new(keyring: Keyring) -> Self {
        Self { keyring }
    }

    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// Verify `sig` over `domain || 0x00 || canonical`, where the document
    /// was issued at `signed_at` (its own `issued_at`).
    pub fn verify_bytes(
        &self,
        domain: SignDomain,
        canonical: &[u8],
        sig: &Signature,
        signed_at: Timestamp,
    ) -> Result<(), VerifyError> {
        if sig.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(VerifyError::UnsupportedAlgorithm);
        }
        let entry = self
            .keyring
            .get(&sig.key_id)
            .ok_or(VerifyError::UnknownKey)?;
        if entry.revoked_at.is_some() {
            return Err(VerifyError::KeyRevoked);
        }
        if !entry.purposes.contains(&domain) {
            return Err(VerifyError::WrongDomain);
        }
        if signed_at < entry.valid_from || entry.retired_at.is_some_and(|t| signed_at >= t) {
            return Err(VerifyError::KeyNotValidAtTime);
        }
        let raw = b64::decode(sig.value.as_str()).ok_or(VerifyError::MalformedSignature)?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| VerifyError::MalformedSignature)?;
        let signature = DalekSignature::from_bytes(&raw);
        let key = VerifyingKey::from_bytes(&entry.public_key)
            .map_err(|_| VerifyError::MalformedSignature)?;
        // `verify_strict` rejects small-order keys and non-canonical encodings.
        key.verify_strict(&domain.signing_input(canonical), &signature)
            .map_err(|_| VerifyError::BadSignature)
    }

    pub fn verify_ledger_record(&self, signed: &SignedLedgerRecord) -> Result<(), VerifyError> {
        signed
            .payload
            .validate()
            .map_err(|_| VerifyError::PayloadInvalid)?;
        let canonical = signed
            .payload
            .canonical_bytes()
            .map_err(|_| VerifyError::PayloadInvalid)?;
        self.verify_bytes(
            signed.payload.domain(),
            &canonical,
            &signed.signature,
            signed.payload.issued_at,
        )
    }

    pub fn verify_projection(&self, env: &PublicProjectionEnvelope) -> Result<(), VerifyError> {
        env.payload
            .validate()
            .map_err(|_| VerifyError::PayloadInvalid)?;
        let canonical = env
            .payload
            .canonical_bytes()
            .map_err(|_| VerifyError::PayloadInvalid)?;
        self.verify_bytes(
            SignDomain::PublicProjection,
            &canonical,
            &env.signature,
            env.payload.issued_at,
        )
    }

    pub fn verify_revocation(&self, env: &SignedRevocationEnvelope) -> Result<(), VerifyError> {
        env.payload
            .validate()
            .map_err(|_| VerifyError::PayloadInvalid)?;
        let canonical = env
            .payload
            .canonical_bytes()
            .map_err(|_| VerifyError::PayloadInvalid)?;
        self.verify_bytes(
            SignDomain::RevocationEnvelope,
            &canonical,
            &env.signature,
            env.payload.issued_at,
        )
    }
}
