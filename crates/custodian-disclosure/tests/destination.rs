//! Destination binding in the public projection (ADR 0119, 0120): prepare for
//! a destination, release, verify from the envelope alone, and every way the
//! binding must refuse. Synthetic data only.

mod common;

use common::*;
use custodian_contracts::public_v2::{AnyProjectionEnvelope, DestinationBinding};
use custodian_disclosure::testing::RecordingSink;
use custodian_disclosure::{verify_release, DisclosureReason as R};
use custodian_ledger::record::{PublicationBody, PublicationDecision};
use custodian_ledger::{LedgerBackend, LedgerPath, LedgerRecord, SignedLedgerRecord};
use serde_json::{json, Value};

const BOUND: &str = "benchmarks-feed";
const OTHER: &str = "site-preview";

fn prepared_bound(w: &World, n: u32, dest: &str) -> custodian_disclosure::PreparedRelease {
    let p = with_default_service(w, |svc| {
        w.provision(svc);
        let key = w.release_key(n);
        svc.prepare_bound(&w.input(&key), &w.destination(dest), now(PREPARE_AT))
            .unwrap()
    });
    w.export();
    p
}

fn prepared_legacy(w: &World, n: u32) -> custodian_disclosure::PreparedRelease {
    let p = with_default_service(w, |svc| {
        w.provision(svc);
        let key = w.release_key(n);
        svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap()
    });
    w.export();
    p
}

fn release_to(
    w: &World,
    p: &custodian_disclosure::PreparedRelease,
    dest: &str,
    sink: &RecordingSink,
) -> Result<custodian_disclosure::ReleasedEnvelope, R> {
    let approval = w.release_approval(p);
    let d = w.destination(dest);
    let obs = disclosure_activation(RELEASE_AT, "active");
    with_default_service(w, |svc| {
        svc.release(
            p,
            &w.release_request(&approval, &d, &obs),
            sink,
            now(RELEASE_AT),
        )
    })
}

fn decision_record(w: &World, bytes: &[u8], dest: &str) -> SignedLedgerRecord {
    let env = AnyProjectionEnvelope::decode(bytes).unwrap();
    let c = env.common_fields();
    let probe = LedgerRecord::publication(
        PublicationBody {
            projection_id: c.projection_id.clone(),
            receipt_id: c.receipt_id.clone(),
            projection_digest: env.projection_digest().unwrap(),
            signature_key_id: env.signature().key_id.clone(),
            decision: Some(PublicationDecision {
                destination: w.destination(dest),
                disclosure_policy: c.disclosure_policy.clone(),
                execution_id: w.execution.execution_id.clone(),
                approval_id: custodian_contracts::types::ApprovalId::parse(&cc::id("apr_", 2))
                    .unwrap(),
                approver: custodian_contracts::types::ActorRef::parse(&cc::id("act_", 2)).unwrap(),
                approver_kind: custodian_contracts::common::ActorKind::Human,
            }),
        },
        c.issued_at.secs(),
    )
    .unwrap();
    let raw = w
        .backend
        .get(&LedgerPath::parse(&probe.path()).unwrap())
        .unwrap()
        .expect("decision record is in the ledger");
    SignedLedgerRecord::decode_canonical(&raw).unwrap()
}

fn with_json(bytes: &[u8], f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(bytes).unwrap();
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn bound_release_carries_the_destination_and_verifies_from_the_envelope() {
    let w = World::new(Opts::default());
    let p = prepared_bound(&w, 1, BOUND);
    assert_eq!(p.destination().unwrap().as_str(), BOUND);
    assert_eq!(p.projection_v2().unwrap().destination.as_str(), BOUND);

    let sink = RecordingSink::new();
    let released = release_to(&w, &p, BOUND, &sink).unwrap();
    assert_eq!(released.binding(), DestinationBinding::Bound);
    let delivered = sink.delivered();
    assert_eq!(delivered[0].1, released.to_bytes().unwrap());

    // A consumer with no ledger reads the destination out of the envelope.
    let env = AnyProjectionEnvelope::decode(&delivered[0].1).unwrap();
    assert_eq!(env.major(), 2);
    assert_eq!(env.destination().unwrap().as_str(), BOUND);
    assert_eq!(env.projection_digest().unwrap(), *p.digest());
    w.verifier
        .verify_any_projection(&env)
        .expect("signature covers the destination");

    // With the ledger decision as well (operators, auditors).
    let decision = decision_record(&w, &delivered[0].1, BOUND);
    let v = verify_release(
        &delivered[0].1,
        &decision,
        &w.destination(BOUND),
        &w.verifier,
    )
    .unwrap();
    assert_eq!(v.binding, DestinationBinding::Bound);
    assert_eq!(v.projection_digest, *p.digest());
}

#[test]
fn verifier_rejects_a_different_expected_destination() {
    let w = World::new(Opts::default());
    let p = prepared_bound(&w, 1, BOUND);
    let sink = RecordingSink::new();
    release_to(&w, &p, BOUND, &sink).unwrap();
    let bytes = sink.delivered()[0].1.clone();
    let decision = decision_record(&w, &bytes, BOUND);
    assert_eq!(
        verify_release(&bytes, &decision, &w.destination(OTHER), &w.verifier).unwrap_err(),
        R::DestinationMismatch
    );
}

#[test]
fn release_to_another_destination_than_prepared_is_refused_and_delivers_nothing() {
    let w = World::new(Opts::default());
    let p = prepared_bound(&w, 1, BOUND);
    let sink = RecordingSink::new();
    // The policy allows OTHER, but this projection was prepared for BOUND.
    assert_eq!(
        release_to(&w, &p, OTHER, &sink).unwrap_err(),
        R::DestinationMismatch
    );
    assert!(sink.delivered().is_empty());
    // The intended destination still works afterwards.
    release_to(&w, &p, BOUND, &sink).unwrap();
}

#[test]
fn prepare_for_a_destination_off_the_allowlist_is_refused_before_any_charge() {
    let w = World::new(Opts::default());
    let r = with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        svc.prepare_bound(
            &w.input(&key),
            &w.destination("not-on-the-allowlist"),
            now(PREPARE_AT),
        )
        .err()
    });
    assert_eq!(r, Some(R::DestinationNotAllowed));
    // No charge was made: the same key prepares normally afterwards.
    with_default_service(&w, |svc| {
        let key = w.release_key(1);
        svc.prepare_bound(&w.input(&key), &w.destination(BOUND), now(PREPARE_AT))
            .unwrap();
    });
}

#[test]
fn an_approval_for_another_digest_cannot_release_the_bound_projection() {
    let w = World::new(Opts::default());
    let p = prepared_bound(&w, 1, BOUND);
    // An approval that bound the *legacy* digest of the same fields.
    let legacy_digest = p.projection().projection_digest().unwrap();
    let mut v = w.release_approval_json(&p);
    v["scope"]["projection_digest"] = json!(legacy_digest.as_str());
    let approval: custodian_contracts::approval::Approval = cc::parse(&v);
    let d = w.destination(BOUND);
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let r = with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &d, &obs),
            &sink,
            now(RELEASE_AT),
        )
    });
    assert_eq!(r.unwrap_err(), R::ApprovalNotBound);
    assert!(sink.delivered().is_empty());
}

#[test]
fn legacy_v1_release_still_works_and_is_reported_unbound() {
    let w = World::new(Opts::default());
    let p = prepared_legacy(&w, 1);
    assert!(p.destination().is_none() && p.projection_v2().is_none());
    let sink = RecordingSink::new();
    let released = release_to(&w, &p, BOUND, &sink).unwrap();
    assert_eq!(released.binding(), DestinationBinding::Unbound);
    let bytes = sink.delivered()[0].1.clone();
    let env = AnyProjectionEnvelope::decode(&bytes).unwrap();
    assert_eq!(env.major(), 1);
    assert!(env.destination().is_none());
    // Verifies exactly as before, with the limit stated in the outcome.
    let decision = decision_record(&w, &bytes, BOUND);
    let v = verify_release(&bytes, &decision, &w.destination(BOUND), &w.verifier).unwrap();
    assert_eq!(v.binding, DestinationBinding::Unbound);
    assert_eq!(DestinationBinding::UNBOUND_CODE, "destination_unbound");
}

#[test]
fn tampered_downgraded_and_upgraded_envelopes_are_refused() {
    let w = World::new(Opts::default());
    let p = prepared_bound(&w, 1, BOUND);
    let sink = RecordingSink::new();
    release_to(&w, &p, BOUND, &sink).unwrap();
    let bytes = sink.delivered()[0].1.clone();
    let decision = decision_record(&w, &bytes, BOUND);
    let expected = w.destination(BOUND);

    // Destination changed to another valid label: the signature fails.
    let tampered = with_json(&bytes, |v| v["payload"]["destination"] = json!(OTHER));
    assert_eq!(
        verify_release(&tampered, &decision, &expected, &w.verifier).unwrap_err(),
        R::SignatureInvalid
    );
    // Same, even when the caller expects the swapped destination.
    assert_eq!(
        verify_release(&tampered, &decision, &w.destination(OTHER), &w.verifier).unwrap_err(),
        R::SignatureInvalid
    );

    // v2 re-labelled as v1 (unknown field for v1), and the destination
    // stripped under the v2 tag (missing field).
    let relabelled = with_json(&bytes, |v| {
        v["payload"]["schema"] = json!("private-custodian.public-projection/1");
    });
    assert_eq!(
        verify_release(&relabelled, &decision, &expected, &w.verifier).unwrap_err(),
        R::EnvelopeInvalid
    );
    let stripped = with_json(&bytes, |v| {
        v["payload"].as_object_mut().unwrap().remove("destination");
    });
    assert_eq!(
        verify_release(&stripped, &decision, &expected, &w.verifier).unwrap_err(),
        R::EnvelopeInvalid
    );
    // Stripped and re-labelled v1: well formed, but the signature was made
    // under the v2 domain over different bytes.
    let downgraded = with_json(&bytes, |v| {
        v["payload"].as_object_mut().unwrap().remove("destination");
        v["payload"]["schema"] = json!("private-custodian.public-projection/1");
    });
    assert_eq!(
        verify_release(&downgraded, &decision, &expected, &w.verifier).unwrap_err(),
        R::SignatureInvalid
    );

    // A genuine v1 envelope passed off as v2.
    let w2 = World::new(Opts::default());
    let p1 = prepared_legacy(&w2, 1);
    let sink1 = RecordingSink::new();
    release_to(&w2, &p1, BOUND, &sink1).unwrap();
    let v1_bytes = sink1.delivered()[0].1.clone();
    let d1 = decision_record(&w2, &v1_bytes, BOUND);
    let upgraded = with_json(&v1_bytes, |v| {
        v["payload"]["schema"] = json!("private-custodian.public-projection/2");
    });
    assert_eq!(
        verify_release(&upgraded, &d1, &expected, &w2.verifier).unwrap_err(),
        R::EnvelopeInvalid
    );
    let upgraded_with_dest = with_json(&v1_bytes, |v| {
        v["payload"]["schema"] = json!("private-custodian.public-projection/2");
        v["payload"]["destination"] = json!(BOUND);
    });
    assert_eq!(
        verify_release(&upgraded_with_dest, &d1, &expected, &w2.verifier).unwrap_err(),
        R::SignatureInvalid
    );
}

#[test]
fn unknown_fields_and_oversize_are_refused() {
    let w = World::new(Opts::default());
    let p = prepared_bound(&w, 1, BOUND);
    let sink = RecordingSink::new();
    release_to(&w, &p, BOUND, &sink).unwrap();
    let bytes = sink.delivered()[0].1.clone();
    let decision = decision_record(&w, &bytes, BOUND);
    let extra = with_json(&bytes, |v| v["payload"]["note"] = json!("x"));
    assert_eq!(
        verify_release(&extra, &decision, &w.destination(BOUND), &w.verifier).unwrap_err(),
        R::EnvelopeInvalid
    );
    let big = vec![b' '; custodian_contracts::MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        verify_release(&big, &decision, &w.destination(BOUND), &w.verifier).unwrap_err(),
        R::EnvelopeInvalid
    );
    // The destination is a bounded label, never a URL.
    let url = with_json(&bytes, |v| {
        v["payload"]["destination"] = json!("https://example.invalid/hook");
    });
    assert_eq!(
        verify_release(&url, &decision, &w.destination(BOUND), &w.verifier).unwrap_err(),
        R::EnvelopeInvalid
    );
}
