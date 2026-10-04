//! Shape/contract prototype for ADR 0134's "Signer Transport" section
//! (issue #46; tracked separately from the sandbox work in #54/#55/#56 and
//! from #42/#44).
//!
//! ADR 0134 states that a network `SignerTransport` "must authenticate
//! caller role, bind freshness and purpose, preserve Ed25519
//! domain-separated bytes, enforce bounded frames and verify returned
//! signatures with pinned public keys," and that "a worker never invokes
//! it." This module proves that those five properties compose into one
//! boundary and are each independently testable with disposable,
//! in-test-generated Ed25519 keys. It is a shape prototype only. It is
//! explicitly **not**:
//!
//! * a deployed or Lambda-reachable transport: no network I/O, no AWS SDK,
//!   no KMS or IAM client is introduced anywhere in this module;
//! * a replacement for [`custodian_ledger::SignerTransport`] /
//!   [`crate::UnixSocketTransport`], which remain the only signer path this
//!   repository runs or tests end to end today (ADR 0111). Nothing here
//!   changes `RemoteSigner`, `UnixSocketTransport` or the local-socket
//!   frame protocol in [`crate::frame`];
//! * a new wire framing. `custodian_ledger::signer`'s `WireRequest`/
//!   `WireResponse` JSON and the Unix-socket header in [`crate::frame`]
//!   stay private to the local-socket design. This module composes at the
//!   already-decoded `ApprovedPayload`/`Signer` boundary instead, which is
//!   the same vocabulary ADR 0134's properties are stated in (domain,
//!   purpose, caller, freshness, signature), and is the boundary any real
//!   network transport would also have to preserve once bytes are decoded
//!   on the signer side.
//!
//! What remains unimplemented after this prototype: an actual
//! Lambda-reachable transport, caller-role authentication from a real
//! identity (an API Gateway authorizer, mTLS client identity, or similar),
//! and any KMS/IAM integration. None of those exist in this repository.
//! Do not read the existence of this module as "the signer transport is
//! now implemented for Lambda" — it is not.

use custodian_contracts::common::Signature;
use custodian_contracts::types::Timestamp;
use custodian_ledger::{ApprovedPayload, SignRefusal, Signer, Verifier};

/// Caller roles a network signer transport must keep separate (ADR 0134:
/// "Keep signer permission separate from request-facing intake and ledger
/// writer," and "A worker never invokes it.").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallerRole {
    /// The control service's export/signing path. The only role this shape
    /// ever permits to obtain a signature.
    LedgerWriter,
    /// Request-facing intake. A legitimate control-plane role, but not
    /// signer permission.
    Intake,
    /// A remote worker. Always refused by [`ShapeOnlyTransport::call`],
    /// regardless of payload, freshness, or which role the instance was
    /// configured to permit.
    Worker,
}

/// Why a shape-only network signer call was refused. This never widens or
/// redefines [`SignRefusal`]: `Inner` carries that fixed vocabulary
/// unchanged for an actual signing refusal from the wrapped [`Signer`]; the
/// other variants are the additional properties ADR 0134 names for the
/// network boundary itself, which the existing local Unix-socket path does
/// not need because it has no network caller-role or pinned-verification
/// requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeRefusal {
    /// ADR 0134: "A worker never invokes it."
    CallerRoleNotPermitted,
    /// The call's claimed `issued_at` is outside the configured skew of the
    /// shape's clock.
    Stale,
    /// The payload's canonical bytes exceed the bounded-frame limit shared
    /// with the existing local signer protocol
    /// (`custodian_ledger::signer::MAX_WIRE_BYTES`).
    TooLarge,
    /// The wrapped signer refused; carries its fixed `sign_*` code
    /// unchanged.
    Inner(SignRefusal),
    /// The wrapped signer returned a signature that did not verify under a
    /// pinned public key for this payload's domain. Fails closed: a
    /// transport whose answer cannot be checked against a pinned key is
    /// treated as having produced nothing, exactly as ADR 0134 requires.
    SignatureNotPinned,
}

impl core::fmt::Display for ShapeRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CallerRoleNotPermitted => f.write_str("shape_caller_role_not_permitted"),
            Self::Stale => f.write_str("shape_stale"),
            Self::TooLarge => f.write_str("shape_too_large"),
            Self::Inner(r) => core::fmt::Display::fmt(r, f),
            Self::SignatureNotPinned => f.write_str("shape_signature_not_pinned"),
        }
    }
}

impl std::error::Error for ShapeRefusal {}

/// Shape/contract prototype of a network `SignerTransport` (ADR 0134). See
/// the module doc for what this does and does not prove. `issued_at` is the
/// caller's claimed request time, unix seconds, checked against the
/// implementation's own clock and configured skew before anything is
/// signed.
pub trait NetworkSignerTransport: Send + Sync {
    fn call(
        &self,
        role: CallerRole,
        payload: &ApprovedPayload,
        issued_at: u64,
    ) -> Result<Signature, ShapeRefusal>;
}

/// The one offline implementation in this repository: an in-process
/// [`Signer`] plus the properties ADR 0134 adds around it. No socket, no
/// network namespace, no remote process. `inner` is typically a test
/// `SoftwareSigner`, or (unchanged) the existing
/// `RemoteSigner<UnixSocketTransport>` — this type does not care which, so
/// wrapping the real local-socket path in a future network-aware caller
/// does not require reimplementing the properties proven here.
pub struct ShapeOnlyTransport<S: Signer> {
    inner: S,
    verifier: Verifier,
    /// The single caller role this instance ever answers, fixed at
    /// construction — the same way a real deployment would bind one
    /// signer-facing endpoint to one authenticated identity rather than
    /// trust a role claimed on the request.
    permitted: CallerRole,
    now: u64,
    max_skew_secs: u64,
}

impl<S: Signer> ShapeOnlyTransport<S> {
    pub fn new(
        inner: S,
        verifier: Verifier,
        permitted: CallerRole,
        now: u64,
        max_skew_secs: u64,
    ) -> Self {
        Self {
            inner,
            verifier,
            permitted,
            now,
            max_skew_secs,
        }
    }
}

impl<S: Signer> NetworkSignerTransport for ShapeOnlyTransport<S> {
    fn call(
        &self,
        role: CallerRole,
        payload: &ApprovedPayload,
        issued_at: u64,
    ) -> Result<Signature, ShapeRefusal> {
        // Caller role (ADR 0134: "a worker never invokes it"; permission is
        // separate from request-facing intake). Checked before anything
        // else: a worker claiming the ledger-writer role is still refused.
        if role == CallerRole::Worker || role != self.permitted {
            return Err(ShapeRefusal::CallerRoleNotPermitted);
        }
        // Bounded frames, at the same limit the local-socket protocol uses
        // (already exercised at that layer: ADR 0111,
        // `custodian-ledger/tests/signing.rs`; `within_frame_bound` below
        // unit-tests the threshold this shape applies).
        if !within_frame_bound(payload.canonical_bytes().len()) {
            return Err(ShapeRefusal::TooLarge);
        }
        // Freshness of the call itself, independent of any freshness the
        // signed document type already carries (e.g. a release approval's
        // own window, which `ApprovedPayload::projection` already checked).
        if self.now.abs_diff(issued_at) > self.max_skew_secs {
            return Err(ShapeRefusal::Stale);
        }
        // Purpose and Ed25519 domain separation are preserved unchanged:
        // `inner.sign` enforces key purpose and signs
        // `domain || 0x00 || canonical` exactly as the local path does.
        let sig = self.inner.sign(payload).map_err(ShapeRefusal::Inner)?;
        // Verify the returned signature under a pinned public key before
        // trusting it, rather than trusting the transport call to have
        // reached the real signer.
        let signed_at = Timestamp::new(self.now).map_err(|_| ShapeRefusal::Stale)?;
        self.verifier
            .verify_bytes(payload.domain(), payload.canonical_bytes(), &sig, signed_at)
            .map_err(|_| ShapeRefusal::SignatureNotPinned)?;
        Ok(sig)
    }
}

/// Whether `canonical_len` fits the bounded-frame limit this shape shares
/// with the local-socket protocol
/// (`custodian_ledger::signer::MAX_WIRE_BYTES`). A free function so the
/// threshold itself is unit-testable without building a payload that is
/// actually that large.
fn within_frame_bound(canonical_len: usize) -> bool {
    canonical_len <= custodian_ledger::signer::MAX_WIRE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_bound_matches_the_shared_local_socket_limit() {
        assert!(within_frame_bound(custodian_ledger::signer::MAX_WIRE_BYTES));
        assert!(!within_frame_bound(
            custodian_ledger::signer::MAX_WIRE_BYTES + 1
        ));
    }
}
