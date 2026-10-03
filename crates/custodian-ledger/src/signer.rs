//! Signing: the approved-payload gate, the `Signer` trait, a software signer,
//! and the wire protocol for an isolated signer process (ADR 0050).
//!
//! A signer never receives a free-form byte string. It receives an
//! [`ApprovedPayload`], which can only be built by a constructor that has
//! decoded the canonical bytes as the document type of the claimed domain,
//! run that type's validation, and (for a public projection) matched the
//! release approval. The isolated signer process rebuilds the same value from
//! the wire with [`ApprovedPayload::from_wire`], so it does not rely on the
//! caller having validated anything.

use std::collections::BTreeSet;

use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::{Signature, SignatureAlgorithm};
use custodian_contracts::policy::ObservedActivation;
use custodian_contracts::public::PublicProjection;
use custodian_contracts::public_v2::PublicProjectionV2;
use custodian_contracts::revocation::RevocationEnvelope;
use custodian_contracts::types::{ExecutionId, KeyId, ProjectionDigest, SignatureValue, Timestamp};
use custodian_contracts::ContractError;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::domain::SignDomain;
use crate::record::LedgerRecord;

/// Largest request the signer service parses.
pub const MAX_WIRE_BYTES: usize = 262_144;

/// Why a signer declined. Fixed vocabulary; never carries payload text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignRefusal {
    /// The key is not authorized for this document domain, or the payload
    /// decodes as a different document type than the domain claims.
    WrongDomain,
    UnknownDomain,
    /// Not canonical, not valid for its type, or inconsistent.
    PayloadInvalid,
    /// Wrong schema tag or version.
    SchemaMismatch,
    /// No matching, current release approval.
    NotApproved,
    /// The signer or its key provider could not be reached or used.
    SignerUnavailable,
}

impl SignRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::WrongDomain => "sign_wrong_domain",
            Self::UnknownDomain => "sign_unknown_domain",
            Self::PayloadInvalid => "sign_payload_invalid",
            Self::SchemaMismatch => "sign_schema_mismatch",
            Self::NotApproved => "sign_not_approved",
            Self::SignerUnavailable => "sign_signer_unavailable",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::WrongDomain,
            Self::UnknownDomain,
            Self::PayloadInvalid,
            Self::SchemaMismatch,
            Self::NotApproved,
            Self::SignerUnavailable,
        ]
        .into_iter()
        .find(|r| r.code() == code)
    }
}

impl core::fmt::Display for SignRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SignRefusal {}

fn map_contract(e: ContractError) -> SignRefusal {
    match e {
        ContractError::Malformed => SignRefusal::SchemaMismatch,
        _ => SignRefusal::PayloadInvalid,
    }
}

/// A payload that has been decoded as the document type of its domain and
/// validated. The only input a [`Signer`] accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedPayload {
    domain: SignDomain,
    canonical: Vec<u8>,
    release_digest: Option<ProjectionDigest>,
}

impl ApprovedPayload {
    pub fn domain(&self) -> SignDomain {
        self.domain
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub fn release_digest(&self) -> Option<&ProjectionDigest> {
        self.release_digest.as_ref()
    }

    /// `domain || 0x00 || canonical`, the bytes that are signed.
    pub fn signing_input(&self) -> Vec<u8> {
        self.domain.signing_input(&self.canonical)
    }

    /// A ledger record produced by the control service from validated state.
    pub fn ledger_record(record: &LedgerRecord) -> Result<Self, SignRefusal> {
        record.validate().map_err(|e| match e {
            crate::record::RecordError::SchemaMismatch => SignRefusal::SchemaMismatch,
            _ => SignRefusal::PayloadInvalid,
        })?;
        Ok(Self {
            domain: record.domain(),
            canonical: record
                .canonical_bytes()
                .map_err(|_| SignRefusal::PayloadInvalid)?,
            release_digest: None,
        })
    }

    /// A public projection, only with a release approval that binds exactly
    /// this projection, execution and disclosure policy and is current
    /// (`Approval::check_for_release`: time window, activation freshness,
    /// non-agent approver).
    pub fn projection(
        payload: &PublicProjection,
        approval: &Approval,
        execution_id: &ExecutionId,
        current: &ObservedActivation,
        now: Timestamp,
        max_state_age_secs: u64,
    ) -> Result<Self, SignRefusal> {
        payload.validate().map_err(map_contract)?;
        let digest = payload.projection_digest().map_err(map_contract)?;
        approval
            .check_for_release(
                execution_id,
                &digest,
                &payload.disclosure_policy,
                current,
                now,
                max_state_age_secs,
            )
            .map_err(|_| SignRefusal::NotApproved)?;
        Ok(Self {
            domain: SignDomain::PublicProjection,
            canonical: payload.canonical_bytes().map_err(map_contract)?,
            release_digest: Some(digest),
        })
    }

    /// A v2 public projection (destination inside the payload), only with a
    /// release approval that binds exactly this v2 digest, so the approval
    /// covers the destination (ADR 0119).
    pub fn projection_v2(
        payload: &PublicProjectionV2,
        approval: &Approval,
        execution_id: &ExecutionId,
        current: &ObservedActivation,
        now: Timestamp,
        max_state_age_secs: u64,
    ) -> Result<Self, SignRefusal> {
        payload.validate().map_err(map_contract)?;
        let digest = payload.projection_digest().map_err(map_contract)?;
        approval
            .check_for_release(
                execution_id,
                &digest,
                &payload.disclosure_policy,
                current,
                now,
                max_state_age_secs,
            )
            .map_err(|_| SignRefusal::NotApproved)?;
        Ok(Self {
            domain: SignDomain::PublicProjectionV2,
            canonical: payload.canonical_bytes().map_err(map_contract)?,
            release_digest: Some(digest),
        })
    }

    /// A revocation envelope. Authorization of the revocation decision itself
    /// belongs to the caller (operator CLI, C10); the signer enforces shape,
    /// validity and domain.
    pub fn revocation(envelope: &RevocationEnvelope) -> Result<Self, SignRefusal> {
        envelope.validate().map_err(map_contract)?;
        Ok(Self {
            domain: SignDomain::RevocationEnvelope,
            canonical: envelope.canonical_bytes().map_err(map_contract)?,
            release_digest: None,
        })
    }

    /// Rebuild an approved payload from untrusted wire input. Used by the
    /// isolated signer process: it re-decodes the canonical bytes as the type
    /// the domain names, so a payload of another type, a non-canonical
    /// encoding or an invalid document is refused here regardless of what the
    /// caller claimed. For `PublicProjection` the caller must supply the
    /// release digest of an approval it already checked; the signer confirms
    /// it equals the payload's digest.
    pub fn from_wire(
        domain_tag: &str,
        canonical: &[u8],
        release_digest: Option<&ProjectionDigest>,
    ) -> Result<Self, SignRefusal> {
        let domain = SignDomain::from_tag(domain_tag).ok_or(SignRefusal::UnknownDomain)?;
        let mut release = None;
        match domain {
            SignDomain::PublicProjection => {
                let p = PublicProjection::decode_canonical(canonical).map_err(map_contract)?;
                let digest = p.projection_digest().map_err(map_contract)?;
                if release_digest != Some(&digest) {
                    return Err(SignRefusal::NotApproved);
                }
                release = Some(digest);
            }
            SignDomain::PublicProjectionV2 => {
                let p = PublicProjectionV2::decode_canonical(canonical).map_err(map_contract)?;
                let digest = p.projection_digest().map_err(map_contract)?;
                if release_digest != Some(&digest) {
                    return Err(SignRefusal::NotApproved);
                }
                release = Some(digest);
            }
            SignDomain::RevocationEnvelope => {
                RevocationEnvelope::decode_canonical(canonical).map_err(map_contract)?;
            }
            _ => {
                let r = LedgerRecord::decode_canonical(canonical).map_err(|e| match e {
                    crate::record::RecordError::SchemaMismatch
                    | crate::record::RecordError::Malformed => SignRefusal::SchemaMismatch,
                    _ => SignRefusal::PayloadInvalid,
                })?;
                if r.domain() != domain {
                    return Err(SignRefusal::WrongDomain);
                }
            }
        }
        Ok(Self {
            domain,
            canonical: canonical.to_vec(),
            release_digest: release,
        })
    }
}

/// Produces signatures over approved payloads. Implementations hold or reach
/// a private key; verification never needs one.
pub trait Signer: Send + Sync {
    fn key_id(&self) -> &KeyId;
    fn sign(&self, payload: &ApprovedPayload) -> Result<Signature, SignRefusal>;
}

/// Ed25519 signer holding its key in process memory. For tests and for the
/// isolated signer process only: the control service, workers and agents must
/// reach signing through [`RemoteSigner`], never hold a key (ADR 0050).
pub struct SoftwareSigner {
    key_id: KeyId,
    key: SigningKey,
    purposes: BTreeSet<SignDomain>,
}

impl core::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SoftwareSigner(<redacted>)")
    }
}

impl SoftwareSigner {
    /// `seed` is the 32-byte Ed25519 secret from a key provider (or, in
    /// tests, random bytes generated in the test). It is not stored anywhere
    /// by this crate.
    pub fn from_seed(
        key_id: KeyId,
        seed: &[u8; 32],
        purposes: impl IntoIterator<Item = SignDomain>,
    ) -> Self {
        Self {
            key_id,
            key: SigningKey::from_bytes(seed),
            purposes: purposes.into_iter().collect(),
        }
    }

    /// 64 lowercase hex characters; what a key-event record publishes.
    pub fn public_key_hex(&self) -> String {
        b64::hex(self.key.verifying_key().as_bytes())
    }

    pub fn purposes(&self) -> Vec<SignDomain> {
        self.purposes.iter().copied().collect()
    }
}

impl Signer for SoftwareSigner {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn sign(&self, payload: &ApprovedPayload) -> Result<Signature, SignRefusal> {
        if !self.purposes.contains(&payload.domain) {
            return Err(SignRefusal::WrongDomain);
        }
        let sig = self.key.sign(&payload.signing_input());
        let value = SignatureValue::parse(&b64::encode(&sig.to_bytes()))
            .map_err(|_| SignRefusal::SignerUnavailable)?;
        Ok(Signature {
            key_id: self.key_id.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            value,
        })
    }
}

// --- Wire protocol for the isolated signer process -----------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    domain: String,
    /// Canonical payload bytes, base64url without padding.
    payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release_digest: Option<ProjectionDigest>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refused: Option<String>,
}

/// The request handler an isolated signer process runs around its key. It
/// owns the key; its only input is bytes from the control service's
/// authenticated channel, and it re-validates everything.
pub struct SignerService<S: Signer> {
    signer: S,
}

impl<S: Signer> SignerService<S> {
    pub fn new(signer: S) -> Self {
        Self { signer }
    }

    pub fn handle(&self, request: &[u8]) -> Vec<u8> {
        let result = self.try_handle(request);
        let resp = match result {
            Ok(sig) => WireResponse {
                signature: Some(sig),
                refused: None,
            },
            Err(r) => WireResponse {
                signature: None,
                refused: Some(r.code().to_owned()),
            },
        };
        serde_json::to_vec(&resp).unwrap_or_default()
    }

    fn try_handle(&self, request: &[u8]) -> Result<Signature, SignRefusal> {
        if request.len() > MAX_WIRE_BYTES {
            return Err(SignRefusal::PayloadInvalid);
        }
        let req: WireRequest =
            serde_json::from_slice(request).map_err(|_| SignRefusal::PayloadInvalid)?;
        let canonical = b64::decode(&req.payload).ok_or(SignRefusal::PayloadInvalid)?;
        let approved =
            ApprovedPayload::from_wire(&req.domain, &canonical, req.release_digest.as_ref())?;
        self.signer.sign(&approved)
    }
}

/// Carries one request to the signer process and returns its response bytes.
/// An implementation over a local socket belongs to deployment (C12); tests
/// use an in-process loopback to a [`SignerService`].
pub trait SignerTransport: Send + Sync {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, SignRefusal>;
}

/// Client side: a `Signer` that holds no key.
pub struct RemoteSigner<T: SignerTransport> {
    key_id: KeyId,
    transport: T,
}

impl<T: SignerTransport> RemoteSigner<T> {
    pub fn new(key_id: KeyId, transport: T) -> Self {
        Self { key_id, transport }
    }
}

impl<T: SignerTransport> Signer for RemoteSigner<T> {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn sign(&self, payload: &ApprovedPayload) -> Result<Signature, SignRefusal> {
        let req = WireRequest {
            domain: payload.domain().tag().to_owned(),
            payload: b64::encode(payload.canonical_bytes()),
            release_digest: payload.release_digest().cloned(),
        };
        let bytes = serde_json::to_vec(&req).map_err(|_| SignRefusal::PayloadInvalid)?;
        let resp = self.transport.call(&bytes)?;
        if resp.len() > MAX_WIRE_BYTES {
            return Err(SignRefusal::SignerUnavailable);
        }
        let resp: WireResponse =
            serde_json::from_slice(&resp).map_err(|_| SignRefusal::SignerUnavailable)?;
        match (resp.signature, resp.refused) {
            (Some(sig), None) if sig.key_id == self.key_id => Ok(sig),
            (None, Some(code)) => {
                Err(SignRefusal::from_code(&code).unwrap_or(SignRefusal::SignerUnavailable))
            }
            _ => Err(SignRefusal::SignerUnavailable),
        }
    }
}
