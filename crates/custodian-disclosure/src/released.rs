//! The released envelope and its verification (ADR 0063).
//!
//! # Type-level separation
//!
//! [`ReleasedEnvelope`] has private fields and a crate-private constructor.
//! Only a completed [`crate::DisclosureService::release`] can produce one, and
//! the only way bytes reach a destination is `Sink::deliver(&ReleasedEnvelope)`.
//! An internal record (receipt, execution, request, approval, aggregate
//! artifact) has no conversion into it, so it cannot be handed to a sink:
//!
//! ```compile_fail
//! use custodian_contracts::execution::InternalReceipt;
//! use custodian_disclosure::{ReleasedEnvelope, Sink};
//!
//! fn deliver(sink: &dyn Sink, receipt: &InternalReceipt) {
//!     // An internal receipt is not a released envelope.
//!     let _ = sink.deliver(receipt);
//! }
//! ```
//!
//! and a released envelope cannot be built outside this crate:
//!
//! ```compile_fail
//! use custodian_disclosure::ReleasedEnvelope;
//! fn forge() -> ReleasedEnvelope {
//!     ReleasedEnvelope { envelope: todo!(), destination: todo!() }
//! }
//! ```
//!
//! # What a verifier can and cannot check
//!
//! `PublicProjection` has no destination field (adding one is a new schema
//! major). The destination binding therefore lives in the signed `publication`
//! ledger record. Anyone holding that record (operators, auditors, the
//! publisher gate in front of a destination) can verify that this exact
//! envelope was approved for this destination. A public consumer without the
//! ledger can verify the signature and digest only.

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::types::{DestinationId, ProjectionDigest};
use custodian_ledger::record::RecordBody;
use custodian_ledger::{SignedLedgerRecord, Verifier};

use crate::reason::DisclosureReason;

/// A signed projection approved for one destination.
#[derive(Clone, PartialEq, Eq)]
pub struct ReleasedEnvelope {
    envelope: PublicProjectionEnvelope,
    destination: DestinationId,
}

impl core::fmt::Debug for ReleasedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReleasedEnvelope")
            .field("destination", &self.destination.as_str())
            .finish()
    }
}

impl ReleasedEnvelope {
    pub(crate) fn new(envelope: PublicProjectionEnvelope, destination: DestinationId) -> Self {
        Self {
            envelope,
            destination,
        }
    }

    pub fn envelope(&self) -> &PublicProjectionEnvelope {
        &self.envelope
    }

    pub fn destination(&self) -> &DestinationId {
        &self.destination
    }

    /// Canonical bytes of the envelope: what a destination serves.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DisclosureReason> {
        to_canonical_bytes(&self.envelope).map_err(|_| DisclosureReason::EnvelopeInvalid)
    }
}

/// A release whose signature, digest and destination all checked out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub projection_digest: ProjectionDigest,
    pub destination: DestinationId,
}

/// Verify a released envelope against its signed publication decision.
///
/// Checks, in order: strict canonical parse of the envelope; its signature;
/// the decision's signature; that the decision is a publication decision; the
/// projection digest; the identity of the projection and receipt; the signing
/// key; the disclosure policy; and finally that the decision approved exactly
/// `expected_destination`. Every failure is a fixed reason.
pub fn verify_release(
    envelope_bytes: &[u8],
    decision: &SignedLedgerRecord,
    expected_destination: &DestinationId,
    verifier: &Verifier,
) -> Result<VerifiedRelease, DisclosureReason> {
    let env = PublicProjectionEnvelope::decode(envelope_bytes)
        .map_err(|_| DisclosureReason::EnvelopeInvalid)?;
    if to_canonical_bytes(&env).map_err(|_| DisclosureReason::EnvelopeInvalid)? != envelope_bytes {
        return Err(DisclosureReason::EnvelopeInvalid);
    }
    verifier
        .verify_projection(&env)
        .map_err(|_| DisclosureReason::SignatureInvalid)?;
    verifier
        .verify_ledger_record(decision)
        .map_err(|_| DisclosureReason::SignatureInvalid)?;
    let RecordBody::Publication(body) = &decision.payload.body else {
        return Err(DisclosureReason::EnvelopeInvalid);
    };
    let Some(d) = &body.decision else {
        return Err(DisclosureReason::EnvelopeInvalid);
    };
    let digest = env
        .payload
        .projection_digest()
        .map_err(|_| DisclosureReason::EnvelopeInvalid)?;
    if digest != body.projection_digest {
        return Err(DisclosureReason::DigestMismatch);
    }
    if body.projection_id != env.payload.projection_id
        || body.receipt_id != env.payload.receipt_id
        || body.signature_key_id != env.signature.key_id
    {
        return Err(DisclosureReason::BindingMismatch);
    }
    if d.disclosure_policy != env.payload.disclosure_policy {
        return Err(DisclosureReason::PolicyMismatch);
    }
    if d.destination != *expected_destination {
        return Err(DisclosureReason::DestinationMismatch);
    }
    Ok(VerifiedRelease {
        projection_digest: digest,
        destination: d.destination.clone(),
    })
}
