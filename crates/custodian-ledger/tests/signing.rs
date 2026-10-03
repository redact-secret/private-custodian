//! Signing, verification, domain separation, key lifecycle and the isolated
//! signer wire protocol. Keys are generated inside each test.

mod common;

use common::cc::{self, projection, release_approval_json};
use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::{Signature, SignatureAlgorithm};
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::revocation::SignedRevocationEnvelope;
use custodian_contracts::types::{ExecutionId, SignatureValue};
use custodian_ledger::record::{KeyAction, KeyEventBody};
use custodian_ledger::{
    ApprovedPayload, KeyEntry, Keyring, KeyringError, LedgerRecord, RemoteSigner, SignDomain,
    SignRefusal, SignedLedgerRecord, Signer, SignerService, SignerTransport, SoftwareSigner,
    Verifier, VerifyError,
};
use custodian_store::Checkpoint;
use serde_json::{json, Value};

fn exe() -> ExecutionId {
    ExecutionId::parse(&cc::id("exe_", 1)).unwrap()
}

fn release_approval() -> Approval {
    cc::parse(&release_approval_json())
}

fn approved_projection() -> ApprovedPayload {
    ApprovedPayload::projection(
        &projection(),
        &release_approval(),
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    )
    .unwrap()
}

fn checkpoint_record(at: u64) -> LedgerRecord {
    LedgerRecord::store_checkpoint(
        &Checkpoint {
            seq: 3,
            chain: "b".repeat(64),
        },
        at,
    )
    .unwrap()
}

fn sign_record(s: &SoftwareSigner, r: &LedgerRecord) -> SignedLedgerRecord {
    let sig = s.sign(&ApprovedPayload::ledger_record(r).unwrap()).unwrap();
    SignedLedgerRecord {
        payload: r.clone(),
        signature: sig,
    }
}

#[test]
fn ledger_record_round_trips_through_sign_and_verify() {
    let s = setup();
    let rec = checkpoint_record(NOW);
    let signed = sign_record(&s.key.signer, &rec);
    s.verifier.verify_ledger_record(&signed).unwrap();
    let bytes = signed.canonical_bytes().unwrap();
    let again = SignedLedgerRecord::decode_canonical(&bytes).unwrap();
    s.verifier.verify_ledger_record(&again).unwrap();
    // Ed25519 is deterministic: identical input, identical bytes.
    assert_eq!(
        sign_record(&s.key.signer, &rec).canonical_bytes().unwrap(),
        bytes
    );
}

#[test]
fn projection_and_revocation_sign_and_verify_with_public_keys_only() {
    let s = setup();
    let sig = s.key.signer.sign(&approved_projection()).unwrap();
    let env = PublicProjectionEnvelope {
        payload: projection(),
        signature: sig,
    };
    // The verifier is built from the public entry alone.
    s.verifier.verify_projection(&env).unwrap();

    let rev = ApprovedPayload::revocation(&cc::revocation()).unwrap();
    let env = SignedRevocationEnvelope {
        payload: cc::revocation(),
        signature: s.key.signer.sign(&rev).unwrap(),
    };
    s.verifier.verify_revocation(&env).unwrap();
}

#[test]
fn tampered_payload_fails_verification() {
    let s = setup();
    let sig = s.key.signer.sign(&approved_projection()).unwrap();
    let mut v = cc::projection_json();
    v["cells"][0]["value"]["numerator"] = json!(10);
    let tampered: custodian_contracts::public::PublicProjection = cc::parse(&v);
    let env = PublicProjectionEnvelope {
        payload: tampered,
        signature: sig,
    };
    assert_eq!(
        s.verifier.verify_projection(&env),
        Err(VerifyError::BadSignature)
    );

    let rec = checkpoint_record(NOW);
    let mut signed = sign_record(&s.key.signer, &rec);
    let other = checkpoint_record(NOW + 1);
    signed.payload = other;
    assert_eq!(
        s.verifier.verify_ledger_record(&signed),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn invalid_and_foreign_signatures_are_rejected() {
    let s = setup();
    let rec = checkpoint_record(NOW);
    let mut signed = sign_record(&s.key.signer, &rec);
    signed.signature.value = SignatureValue::parse(&"A".repeat(86)).unwrap();
    assert_eq!(
        s.verifier.verify_ledger_record(&signed),
        Err(VerifyError::BadSignature)
    );

    // A different key with the same id (an attacker's) does not verify.
    let attacker = SoftwareSigner::from_seed(key_id(1), &random_seed(), all_domains());
    let forged = sign_record(&attacker, &rec);
    assert_eq!(
        s.verifier.verify_ledger_record(&forged),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn unknown_key_id_is_rejected() {
    let s = setup();
    let stranger = SoftwareSigner::from_seed(key_id(77), &random_seed(), all_domains());
    let signed = sign_record(&stranger, &checkpoint_record(NOW));
    assert_eq!(
        s.verifier.verify_ledger_record(&signed),
        Err(VerifyError::UnknownKey)
    );
}

#[test]
fn wrong_domain_is_rejected_by_signer_key_scope_and_by_verifier() {
    // A key scoped to audit events refuses to sign a projection.
    let narrow = test_key(5, &[SignDomain::LedgerAuditEvent], NOW - 100);
    assert_eq!(
        narrow.signer.sign(&approved_projection()),
        Err(SignRefusal::WrongDomain)
    );

    // A key that may sign projections only is not accepted for ledger records.
    let proj_only = test_key(6, &[SignDomain::PublicProjection], NOW - 100);
    let ring = Keyring::new().with_root(proj_only.entry.clone());
    let v = Verifier::new(ring);
    let sig = proj_only.signer.sign(&approved_projection()).unwrap();
    let canonical = projection().canonical_bytes().unwrap();
    v.verify_bytes(
        SignDomain::PublicProjection,
        &canonical,
        &sig,
        cc::ts(cc::NOW + 40),
    )
    .unwrap();
    assert_eq!(
        v.verify_bytes(
            SignDomain::RevocationEnvelope,
            &canonical,
            &sig,
            cc::ts(cc::NOW + 40)
        ),
        Err(VerifyError::WrongDomain)
    );

    // Even an all-purpose key: the same bytes under another domain do not verify.
    let s = setup();
    let sig = s.key.signer.sign(&approved_projection()).unwrap();
    assert_eq!(
        s.verifier.verify_bytes(
            SignDomain::RevocationEnvelope,
            &canonical,
            &sig,
            cc::ts(cc::NOW + 40)
        ),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        s.verifier.verify_bytes(
            SignDomain::LedgerPolicy,
            &canonical,
            &sig,
            cc::ts(cc::NOW + 40)
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn signer_refuses_unapproved_or_mismatched_projections() {
    // An execution approval never authorizes release.
    let exec_approval: Approval = cc::approval();
    let r = ApprovedPayload::projection(
        &projection(),
        &exec_approval,
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    );
    assert_eq!(r.unwrap_err(), SignRefusal::NotApproved);

    // Expired release approval.
    let r = ApprovedPayload::projection(
        &projection(),
        &release_approval(),
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 100_000),
        cc::MAX_AGE,
    );
    assert_eq!(r.unwrap_err(), SignRefusal::NotApproved);

    // Approval for a different execution.
    let r = ApprovedPayload::projection(
        &projection(),
        &release_approval(),
        &ExecutionId::parse(&cc::id("exe_", 2)).unwrap(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    );
    assert_eq!(r.unwrap_err(), SignRefusal::NotApproved);

    // A modified projection no longer matches the digest the approval binds.
    let mut v = cc::projection_json();
    v["cells"][0]["value"]["numerator"] = json!(10);
    let changed: custodian_contracts::public::PublicProjection = cc::parse(&v);
    let r = ApprovedPayload::projection(
        &changed,
        &release_approval(),
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    );
    assert_eq!(r.unwrap_err(), SignRefusal::NotApproved);
}

#[test]
fn from_wire_refuses_wrong_schema_domain_encoding_and_missing_approval() {
    let p = projection();
    let canonical = p.canonical_bytes().unwrap();
    let digest = p.projection_digest().unwrap();
    let tag = SignDomain::PublicProjection.tag();
    assert!(ApprovedPayload::from_wire(tag, &canonical, Some(&digest)).is_ok());

    // No approval, wrong approval.
    assert_eq!(
        ApprovedPayload::from_wire(tag, &canonical, None).unwrap_err(),
        SignRefusal::NotApproved
    );
    let other = custodian_contracts::types::ProjectionDigest::from_raw([9; 32]);
    assert_eq!(
        ApprovedPayload::from_wire(tag, &canonical, Some(&other)).unwrap_err(),
        SignRefusal::NotApproved
    );

    // Wrong schema version.
    let mut v = cc::projection_json();
    v["schema"] = json!("private-custodian.public-projection/2");
    let bytes = serde_json::to_vec(&v).unwrap();
    assert_eq!(
        ApprovedPayload::from_wire(tag, &bytes, Some(&digest)).unwrap_err(),
        SignRefusal::SchemaMismatch
    );

    // Non-canonical encoding (pretty-printed) is refused.
    let pretty = serde_json::to_vec_pretty(&cc::projection_json()).unwrap();
    assert_eq!(
        ApprovedPayload::from_wire(tag, &pretty, Some(&digest)).unwrap_err(),
        SignRefusal::PayloadInvalid
    );

    // Unknown domain tag.
    assert_eq!(
        ApprovedPayload::from_wire("private-custodian/v1/nope", &canonical, Some(&digest))
            .unwrap_err(),
        SignRefusal::UnknownDomain
    );

    // A projection claimed under the revocation domain decodes as the wrong type.
    assert_eq!(
        ApprovedPayload::from_wire(SignDomain::RevocationEnvelope.tag(), &canonical, None)
            .unwrap_err(),
        SignRefusal::SchemaMismatch
    );

    // A ledger record claimed under another ledger domain.
    let rec = checkpoint_record(NOW);
    let rec_bytes = rec.canonical_bytes().unwrap();
    assert_eq!(
        ApprovedPayload::from_wire(SignDomain::LedgerPolicy.tag(), &rec_bytes, None).unwrap_err(),
        SignRefusal::WrongDomain
    );
    assert!(
        ApprovedPayload::from_wire(SignDomain::LedgerStoreCheckpoint.tag(), &rec_bytes, None)
            .is_ok()
    );
}

#[test]
fn ledger_record_wrong_schema_and_non_canonical_are_rejected() {
    let rec = checkpoint_record(NOW);
    let mut v: Value = serde_json::from_slice(&rec.canonical_bytes().unwrap()).unwrap();
    v["schema"] = json!("private-custodian.ledger-record/2");
    let bytes = serde_json::to_vec(&v).unwrap();
    assert_eq!(
        LedgerRecord::decode_canonical(&bytes).unwrap_err(),
        custodian_ledger::RecordError::SchemaMismatch
    );
    let pretty = serde_json::to_vec_pretty(&rec).unwrap();
    assert_eq!(
        LedgerRecord::decode_canonical(&pretty).unwrap_err(),
        custodian_ledger::RecordError::NonCanonical
    );
    // Unknown field: closed schema.
    let mut v: Value = serde_json::from_slice(&rec.canonical_bytes().unwrap()).unwrap();
    v["extra"] = json!("x");
    assert_eq!(
        LedgerRecord::decode_canonical(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
        custodian_ledger::RecordError::Malformed
    );
    // A record id that does not derive from the content cannot claim a path.
    let mut v: Value = serde_json::from_slice(&rec.canonical_bytes().unwrap()).unwrap();
    v["record_id"] = json!(format!("rec-store-checkpoint-{}", "0".repeat(32)));
    assert_eq!(
        LedgerRecord::decode_canonical(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
        custodian_ledger::RecordError::Inconsistent
    );
}

#[test]
fn revoked_key_signatures_are_rejected_and_retired_keys_keep_old_signatures() {
    let root = test_key(1, &all_domains(), NOW - 10_000);
    let old = test_key(2, &LEDGER_DOMAINS, NOW - 10_000);
    let mut ring = Keyring::new()
        .with_root(root.entry.clone())
        .with_root(old.entry.clone());
    let early = sign_record(&old.signer, &checkpoint_record(NOW - 500));
    let late = sign_record(&old.signer, &checkpoint_record(NOW + 500));
    Verifier::new(ring.clone())
        .verify_ledger_record(&early)
        .unwrap();

    // Retire key 2 at NOW: signatures issued before stay valid, after do not.
    let retire = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id(2),
            action: KeyAction::Retired,
            public_key: None,
            purposes: vec![],
            effective_at: cc::ts(NOW),
        },
        NOW,
    )
    .unwrap();
    ring.apply_key_event(&sign_record(&root.signer, &retire))
        .unwrap();
    let v = Verifier::new(ring.clone());
    v.verify_ledger_record(&early).unwrap();
    assert_eq!(
        v.verify_ledger_record(&late),
        Err(VerifyError::KeyNotValidAtTime)
    );

    // Revoke it: every signature fails, early ones too.
    let revoke = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id(2),
            action: KeyAction::Revoked,
            public_key: None,
            purposes: vec![],
            effective_at: cc::ts(NOW),
        },
        NOW + 1,
    )
    .unwrap();
    ring.apply_key_event(&sign_record(&root.signer, &revoke))
        .unwrap();
    let v = Verifier::new(ring);
    assert_eq!(v.verify_ledger_record(&early), Err(VerifyError::KeyRevoked));
}

#[test]
fn key_rotation_is_a_chain_of_trust_from_the_pinned_root() {
    let root = test_key(1, &all_domains(), NOW - 10_000);
    let next = test_key(2, &LEDGER_DOMAINS, NOW);
    let mut ring = Keyring::new().with_root(root.entry.clone());

    let publish = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id(2),
            action: KeyAction::Published,
            public_key: Some(next.signer.public_key_hex()),
            purposes: LEDGER_DOMAINS.to_vec(),
            effective_at: cc::ts(NOW),
        },
        NOW,
    )
    .unwrap();

    // Signed by an unknown key: refused, the keyring does not grow.
    let stranger = SoftwareSigner::from_seed(key_id(9), &random_seed(), all_domains());
    assert_eq!(
        ring.apply_key_event(&sign_record(&stranger, &publish)),
        Err(KeyringError::NotAuthorized(VerifyError::UnknownKey))
    );
    assert_eq!(ring.len(), 1);

    // Signed by the pinned root: accepted.
    ring.apply_key_event(&sign_record(&root.signer, &publish))
        .unwrap();
    assert_eq!(ring.len(), 2);
    // Publishing the same key id again is refused.
    assert_eq!(
        ring.apply_key_event(&sign_record(&root.signer, &publish)),
        Err(KeyringError::KeyAlreadyKnown)
    );

    let v = Verifier::new(ring);
    v.verify_ledger_record(&sign_record(&next.signer, &checkpoint_record(NOW + 5)))
        .unwrap();
    // The new key was not valid before its start.
    assert_eq!(
        v.verify_ledger_record(&sign_record(&next.signer, &checkpoint_record(NOW - 5))),
        Err(VerifyError::KeyNotValidAtTime)
    );
    // A key without the key-event purpose cannot extend the keyring.
    // The key itself can sign anything; the keyring only trusts it for audit events.
    let weak = test_key(3, &all_domains(), NOW);
    let mut ring2 = Keyring::new().with_root(root.entry.clone());
    let publish_weak = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id(3),
            action: KeyAction::Published,
            public_key: Some(weak.signer.public_key_hex()),
            purposes: vec![SignDomain::LedgerAuditEvent],
            effective_at: cc::ts(NOW),
        },
        NOW,
    )
    .unwrap();
    ring2
        .apply_key_event(&sign_record(&root.signer, &publish_weak))
        .unwrap();
    let publish4 = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id(4),
            action: KeyAction::Published,
            public_key: Some(next.signer.public_key_hex()),
            purposes: vec![SignDomain::LedgerAuditEvent],
            effective_at: cc::ts(NOW),
        },
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        ring2.apply_key_event(&sign_record(&weak.signer, &publish4)),
        Err(KeyringError::NotAuthorized(VerifyError::WrongDomain))
    );
}

#[test]
fn unsupported_algorithm_and_bad_public_key_are_rejected() {
    // The contract enum has one algorithm today; a future one must be a new
    // schema. A malformed published key is refused at publication.
    let root = test_key(1, &all_domains(), NOW - 10_000);
    let mut ring = Keyring::new().with_root(root.entry.clone());
    let bad = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id(4),
            action: KeyAction::Published,
            public_key: Some(format!("01{}", "00".repeat(31))),
            purposes: vec![SignDomain::LedgerAuditEvent],
            effective_at: cc::ts(NOW),
        },
        NOW,
    )
    .unwrap();
    let r = ring.apply_key_event(&sign_record(&root.signer, &bad));
    // The identity point is a weak (small-order) key and is refused.
    assert_eq!(r, Err(KeyringError::BadPublicKey));
}

#[test]
fn software_signer_debug_output_never_shows_key_material() {
    let seed = random_seed();
    let s = SoftwareSigner::from_seed(key_id(1), &seed, all_domains());
    let text = format!("{s:?}");
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&seed_hex));
    assert!(!text.contains(&s.public_key_hex()));
    assert!(text.contains("redacted"));
}

struct Loopback<'a>(&'a SignerService<SoftwareSigner>);

impl SignerTransport for Loopback<'_> {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, SignRefusal> {
        Ok(self.0.handle(request))
    }
}

struct Swap(Vec<u8>);

impl SignerTransport for Swap {
    fn call(&self, _: &[u8]) -> Result<Vec<u8>, SignRefusal> {
        Ok(self.0.clone())
    }
}

#[test]
fn isolated_signer_protocol_signs_validated_payloads_and_refuses_the_rest() {
    // The service owns the key; the client holds only a key id.
    let svc = SignerService::new(SoftwareSigner::from_seed(
        key_id(1),
        &random_seed(),
        all_domains(),
    ));
    let client = RemoteSigner::new(key_id(1), Loopback(&svc));

    let rec = checkpoint_record(NOW);
    let sig = client
        .sign(&ApprovedPayload::ledger_record(&rec).unwrap())
        .unwrap();
    assert_eq!(sig.key_id, key_id(1));
    assert_eq!(sig.algorithm, SignatureAlgorithm::Ed25519);

    // Projection needs its release digest to cross the wire.
    client.sign(&approved_projection()).unwrap();

    // Garbage and oversized requests are refused with a fixed code.
    let resp = svc.handle(b"not json");
    assert!(String::from_utf8(resp)
        .unwrap()
        .contains("sign_payload_invalid"));
    let big = vec![b'x'; custodian_ledger::signer::MAX_WIRE_BYTES + 1];
    assert!(String::from_utf8(svc.handle(&big))
        .unwrap()
        .contains("sign_payload_invalid"));

    // A service whose key lacks the domain refuses with a fixed reason.
    let narrow = SignerService::new(SoftwareSigner::from_seed(
        key_id(1),
        &random_seed(),
        [SignDomain::LedgerAuditEvent],
    ));
    let client = RemoteSigner::new(key_id(1), Loopback(&narrow));
    assert_eq!(
        client.sign(&approved_projection()).unwrap_err(),
        SignRefusal::WrongDomain
    );

    // A response naming another key is not accepted.
    let other = RemoteSigner::new(key_id(2), Loopback(&svc));
    assert_eq!(
        other
            .sign(&ApprovedPayload::ledger_record(&rec).unwrap())
            .unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    let junk = RemoteSigner::new(key_id(1), Swap(b"{}".to_vec()));
    assert_eq!(
        junk.sign(&ApprovedPayload::ledger_record(&rec).unwrap())
            .unwrap_err(),
        SignRefusal::SignerUnavailable
    );
}

#[test]
fn remote_signature_verifies_under_the_service_public_key() {
    let seed = random_seed();
    let svc_signer = SoftwareSigner::from_seed(key_id(1), &seed, all_domains());
    let entry = KeyEntry::root(
        key_id(1),
        &svc_signer.public_key_hex(),
        all_domains(),
        cc::ts(NOW - 100),
    )
    .unwrap();
    let svc = SignerService::new(svc_signer);
    let client = RemoteSigner::new(key_id(1), Loopback(&svc));
    let rec = checkpoint_record(NOW);
    let sig: Signature = client
        .sign(&ApprovedPayload::ledger_record(&rec).unwrap())
        .unwrap();
    let signed = SignedLedgerRecord {
        payload: rec,
        signature: sig,
    };
    Verifier::new(Keyring::new().with_root(entry))
        .verify_ledger_record(&signed)
        .unwrap();
}
