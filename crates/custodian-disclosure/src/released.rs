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
//! A public projection v2 carries the destination inside the signed payload
//! (ADR 0119), so [`verify_release`] and any public consumer check the
//! binding from the envelope alone. A v1 projection has no destination field;
//! for it the binding lives only in the signed `publication` ledger record,
//! and [`verify_release`] reports it as
//! [`DestinationBinding::Unbound`](custodian_contracts::public_v2::DestinationBinding)
//! even when the ledger decision names the destination. A public consumer
//! without the ledger can verify a v1 signature and digest only.

use custodian_contracts::public_v2::{AnyProjectionEnvelope, DestinationBinding};
use custodian_contracts::types::{DestinationId, ProjectionDigest};
use custodian_ledger::record::RecordBody;
use custodian_ledger::{SignedLedgerRecord, Verifier};

use crate::reason::DisclosureReason;

/// A signed projection approved for one destination.
#[derive(Clone, PartialEq, Eq)]
pub struct ReleasedEnvelope {
    envelope: AnyProjectionEnvelope,
    destination: DestinationId,
}

impl core::fmt::Debug for ReleasedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReleasedEnvelope")
            .field("destination", &self.destination.as_str())
            .field("major", &self.envelope.major())
            .finish()
    }
}

impl ReleasedEnvelope {
    pub(crate) fn new(envelope: AnyProjectionEnvelope, destination: DestinationId) -> Self {
        Self {
            envelope,
            destination,
        }
    }

    pub fn envelope(&self) -> &AnyProjectionEnvelope {
        &self.envelope
    }

    /// Whether the envelope proves its destination (v2) or not (v1).
    pub fn binding(&self) -> DestinationBinding {
        self.envelope.binding()
    }

    pub fn destination(&self) -> &DestinationId {
        &self.destination
    }

    /// Canonical bytes of the envelope: what a destination serves.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DisclosureReason> {
        self.envelope
            .canonical_bytes()
            .map_err(|_| DisclosureReason::EnvelopeInvalid)
    }
}

/// A release whose signature, digest and destination all checked out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub projection_digest: ProjectionDigest,
    pub destination: DestinationId,
    /// `Bound` for a v2 envelope (the destination was also checked inside the
    /// signed payload); `Unbound` for v1, where only the ledger decision
    /// names the destination.
    pub binding: DestinationBinding,
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
    let env = AnyProjectionEnvelope::decode(envelope_bytes)
        .map_err(|_| DisclosureReason::EnvelopeInvalid)?;
    if env
        .canonical_bytes()
        .map_err(|_| DisclosureReason::EnvelopeInvalid)?
        != envelope_bytes
    {
        return Err(DisclosureReason::EnvelopeInvalid);
    }
    verifier
        .verify_any_projection(&env)
        .map_err(|_| DisclosureReason::SignatureInvalid)?;
    let common = env.common_fields();
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
        .projection_digest()
        .map_err(|_| DisclosureReason::EnvelopeInvalid)?;
    if digest != body.projection_digest {
        return Err(DisclosureReason::DigestMismatch);
    }
    if body.projection_id != common.projection_id
        || body.receipt_id != common.receipt_id
        || body.signature_key_id != env.signature().key_id
    {
        return Err(DisclosureReason::BindingMismatch);
    }
    if d.disclosure_policy != common.disclosure_policy {
        return Err(DisclosureReason::PolicyMismatch);
    }
    if d.destination != *expected_destination {
        return Err(DisclosureReason::DestinationMismatch);
    }
    // v2: the signed payload must name the same destination as the decision
    // and as the one the caller expects. v1 has nothing to compare.
    if let Some(signed) = env.destination() {
        if signed != expected_destination || *signed != d.destination {
            return Err(DisclosureReason::DestinationMismatch);
        }
    }
    Ok(VerifiedRelease {
        projection_digest: digest,
        destination: d.destination.clone(),
        binding: env.binding(),
    })
}
