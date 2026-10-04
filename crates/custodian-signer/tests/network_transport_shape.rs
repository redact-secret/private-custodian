//! Tests for the ADR 0134 "Signer Transport" shape/contract prototype
//! (issue #46, `src/network_transport_shape.rs`). Every key here is
//! generated inside the test from operating-system randomness and never
//! written anywhere; nothing here is a deployed transport.

mod common;

use std::io::Read;

use common::{cc, checkpoint_record, NOW};
use custodian_contracts::types::KeyId;
use custodian_ledger::{
    ApprovedPayload, KeyEntry, Keyring, SignDomain, SignRefusal, SoftwareSigner, Verifier,
};
use custodian_signer::{CallerRole, NetworkSignerTransport, ShapeOnlyTransport, ShapeRefusal};

/// 32 random bytes from the OS, generated in the test; never written
/// anywhere.
fn random_seed() -> [u8; 32] {
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    let mut b = [0u8; 32];
    f.read_exact(&mut b).expect("read");
    b
}

fn key_id(n: u32) -> KeyId {
    KeyId::parse(&cc::id("key_", n)).unwrap()
}

/// An all-purpose synthetic key plus a verifier pinned to its real public
/// key.
fn ledger_writer_signer_and_verifier() -> (SoftwareSigner, Verifier) {
    let signer = SoftwareSigner::from_seed(key_id(1), &random_seed(), SignDomain::ALL);
    let entry = KeyEntry::root(
        key_id(1),
        &signer.public_key_hex(),
        SignDomain::ALL,
        cc::ts(NOW - 1_000),
    )
    .unwrap();
    let verifier = Verifier::new(Keyring::new().with_root(entry));
    (signer, verifier)
}

fn record_payload() -> ApprovedPayload {
    ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap()
}

#[test]
fn permitted_role_fresh_and_valid_signs_and_the_signature_verifies_under_the_pinned_key() {
    let (signer, verifier) = ledger_writer_signer_and_verifier();
    let transport = ShapeOnlyTransport::new(signer, verifier, CallerRole::LedgerWriter, NOW, 120);

    let sig = transport
        .call(CallerRole::LedgerWriter, &record_payload(), NOW)
        .unwrap();
    assert_eq!(sig.key_id, key_id(1));
}

#[test]
fn worker_role_is_refused_even_though_the_payload_and_timing_are_otherwise_valid() {
    let (signer, verifier) = ledger_writer_signer_and_verifier();
    // Even configured (by mistake) to permit `Worker`, the role is refused:
    // ADR 0134 "a worker never invokes it" is not conditional on
    // configuration.
    let transport = ShapeOnlyTransport::new(signer, verifier, CallerRole::Worker, NOW, 120);

    assert_eq!(
        transport.call(CallerRole::Worker, &record_payload(), NOW),
        Err(ShapeRefusal::CallerRoleNotPermitted)
    );
}

#[test]
fn intake_role_is_refused_when_ledger_writer_is_the_permitted_role() {
    let (signer, verifier) = ledger_writer_signer_and_verifier();
    let transport = ShapeOnlyTransport::new(signer, verifier, CallerRole::LedgerWriter, NOW, 120);

    // Signer permission stays separate from the request-facing intake role,
    // even though intake is otherwise a legitimate control-plane caller.
    assert_eq!(
        transport.call(CallerRole::Intake, &record_payload(), NOW),
        Err(ShapeRefusal::CallerRoleNotPermitted)
    );
}

#[test]
fn a_request_outside_the_skew_window_is_refused_as_stale() {
    let (signer, verifier) = ledger_writer_signer_and_verifier();
    let transport = ShapeOnlyTransport::new(signer, verifier, CallerRole::LedgerWriter, NOW, 120);

    assert_eq!(
        transport.call(CallerRole::LedgerWriter, &record_payload(), NOW + 121),
        Err(ShapeRefusal::Stale)
    );
    assert_eq!(
        transport.call(CallerRole::LedgerWriter, &record_payload(), NOW - 121),
        Err(ShapeRefusal::Stale)
    );
    // Exactly at the configured skew is still fresh.
    transport
        .call(CallerRole::LedgerWriter, &record_payload(), NOW + 120)
        .unwrap();
}

#[test]
fn a_key_without_the_domain_purpose_is_refused_by_the_wrapped_signer_wrong_domain() {
    // Key-purpose separation is preserved unchanged: a key scoped away from
    // this record's domain still refuses to sign it, exactly as the local
    // Unix-socket signer does.
    let signer =
        SoftwareSigner::from_seed(key_id(2), &random_seed(), [SignDomain::LedgerAuditEvent]);
    let entry = KeyEntry::root(
        key_id(2),
        &signer.public_key_hex(),
        [SignDomain::LedgerAuditEvent],
        cc::ts(NOW - 1_000),
    )
    .unwrap();
    let verifier = Verifier::new(Keyring::new().with_root(entry));
    let transport = ShapeOnlyTransport::new(signer, verifier, CallerRole::LedgerWriter, NOW, 120);

    assert_eq!(
        transport.call(CallerRole::LedgerWriter, &record_payload(), NOW),
        Err(ShapeRefusal::Inner(SignRefusal::WrongDomain))
    );
}

#[test]
fn a_signature_that_does_not_verify_under_the_pinned_key_is_refused_closed() {
    // The signer actually holds key A, but the verifier is pinned (under
    // the same key id, as a misconfigured or stale pin would be) to key B's
    // public key. The returned signature does not verify, and the shape
    // must fail closed rather than trust that the call reached the real
    // signer.
    let real = SoftwareSigner::from_seed(key_id(1), &random_seed(), SignDomain::ALL);
    let pinned_elsewhere = SoftwareSigner::from_seed(key_id(1), &random_seed(), SignDomain::ALL);
    let wrong_pin = KeyEntry::root(
        key_id(1),
        &pinned_elsewhere.public_key_hex(),
        SignDomain::ALL,
        cc::ts(NOW - 1_000),
    )
    .unwrap();
    let verifier = Verifier::new(Keyring::new().with_root(wrong_pin));
    let transport = ShapeOnlyTransport::new(real, verifier, CallerRole::LedgerWriter, NOW, 120);

    assert_eq!(
        transport.call(CallerRole::LedgerWriter, &record_payload(), NOW),
        Err(ShapeRefusal::SignatureNotPinned)
    );
}
