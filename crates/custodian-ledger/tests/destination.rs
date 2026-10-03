//! Signing and verifying public projection major 2 (ADR 0119): the v2 domain,
//! the destination inside the signed bytes, and refusal of cross-major reuse.
//! Keys are generated inside each test; data is synthetic.

mod common;

use common::cc::{self, projection, projection_v2, release_approval_json};
use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::public_v2::{
    AnyProjectionEnvelope, PublicProjectionEnvelopeV2, PublicProjectionV2,
};
use custodian_contracts::types::ExecutionId;
use custodian_ledger::{ApprovedPayload, Keyring, SignDomain, SignRefusal, Signer, Verifier, VerifyError};
use serde_json::json;

fn exe() -> ExecutionId {
    ExecutionId::parse(&cc::id("exe_", 1)).unwrap()
}

/// A release approval that binds the given projection digest.
fn approval_for(digest: &str) -> Approval {
    let mut v = release_approval_json();
    v["scope"]["projection_digest"] = json!(digest);
    cc::parse(&v)
}

fn approved_v2(p: &PublicProjectionV2) -> Result<ApprovedPayload, SignRefusal> {
    let d = p.projection_digest().unwrap();
    ApprovedPayload::projection_v2(
        p,
        &approval_for(d.as_str()),
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    )
}

fn v2_with_destination(dest: &str) -> PublicProjectionV2 {
    let mut v = cc::projection_v2_json();
    v["destination"] = json!(dest);
    cc::parse(&v)
}

#[test]
fn v2_signs_under_the_v2_domain_and_verifies_with_public_keys_only() {
    let s = setup();
    let p = projection_v2();
    let approved = approved_v2(&p).unwrap();
    let sig = s.key.signer.sign(&approved).unwrap();
    let env = PublicProjectionEnvelopeV2 {
        payload: p,
        signature: sig,
    };
    s.verifier.verify_projection_v2(&env).unwrap();
    s.verifier
        .verify_any_projection(&AnyProjectionEnvelope::V2(env.clone()))
        .unwrap();
    assert_eq!(
        SignDomain::PublicProjectionV2.tag(),
        "private-custodian/v2/public-projection"
    );
}

#[test]
fn tampered_destination_fails_the_signature() {
    let s = setup();
    let sig = s.key.signer.sign(&approved_v2(&projection_v2()).unwrap()).unwrap();
    let env = PublicProjectionEnvelopeV2 {
        payload: v2_with_destination("synthetic-other"),
        signature: sig,
    };
    assert_eq!(
        s.verifier.verify_projection_v2(&env),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn approval_must_bind_the_destination_it_signs() {
    // An approval for destination A does not authorize signing destination B.
    let a = projection_v2();
    let b = v2_with_destination("synthetic-other");
    let r = ApprovedPayload::projection_v2(
        &b,
        &approval_for(a.projection_digest().unwrap().as_str()),
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    );
    assert_eq!(r.unwrap_err(), SignRefusal::NotApproved);
    // And an approval of the v1 digest does not authorize the v2 document.
    let r = ApprovedPayload::projection_v2(
        &a,
        &approval_for(projection().projection_digest().unwrap().as_str()),
        &exe(),
        &cc::current(),
        cc::ts(cc::NOW + 5),
        cc::MAX_AGE,
    );
    assert_eq!(r.unwrap_err(), SignRefusal::NotApproved);
}

/// A signature is bound to its major: a v2 signature cannot be passed off on
/// the v1 body (stripped destination, v1 tag) and a v1 signature cannot be
/// passed off on a v2 body.
#[test]
fn signatures_do_not_cross_majors() {
    let s = setup();
    let p2 = projection_v2();
    let sig2 = s.key.signer.sign(&approved_v2(&p2).unwrap()).unwrap();

    // v2 signature on the stripped, v1-labelled body.
    let stripped = PublicProjectionEnvelope {
        payload: projection(),
        signature: sig2.clone(),
    };
    assert_eq!(
        s.verifier.verify_projection(&stripped),
        Err(VerifyError::BadSignature)
    );

    // v1 signature on a v2 body (same fields plus a destination).
    let sig1 = s
        .key
        .signer
        .sign(
            &ApprovedPayload::projection(
                &projection(),
                &cc::parse::<Approval>(&release_approval_json()),
                &exe(),
                &cc::current(),
                cc::ts(cc::NOW + 5),
                cc::MAX_AGE,
            )
            .unwrap(),
        )
        .unwrap();
    let passed_off = PublicProjectionEnvelopeV2 {
        payload: p2.clone(),
        signature: sig1.clone(),
    };
    assert_eq!(
        s.verifier.verify_projection_v2(&passed_off),
        Err(VerifyError::BadSignature)
    );

    // Same bytes, other domain: no cross-verification.
    let canonical = p2.canonical_bytes().unwrap();
    assert_eq!(
        s.verifier.verify_bytes(
            SignDomain::PublicProjection,
            &canonical,
            &sig2,
            cc::ts(cc::NOW + 40)
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn key_scope_is_per_major() {
    // A key authorized only for the v1 projection domain cannot sign v2 ...
    let v1_only = test_key(6, &[SignDomain::PublicProjection], NOW - 100);
    assert_eq!(
        v1_only.signer.sign(&approved_v2(&projection_v2()).unwrap()),
        Err(SignRefusal::WrongDomain)
    );
    // ... and a verifier holding only that key refuses a v2 domain.
    let v2_only = test_key(7, &[SignDomain::PublicProjectionV2], NOW - 100);
    let sig = v2_only
        .signer
        .sign(&approved_v2(&projection_v2()).unwrap())
        .unwrap();
    let env = PublicProjectionEnvelopeV2 {
        payload: projection_v2(),
        signature: sig,
    };
    let narrow_v1 = Verifier::new(Keyring::new().with_root(v1_only.entry.clone()));
    assert!(narrow_v1.verify_projection_v2(&env).is_err());
    Verifier::new(Keyring::new().with_root(v2_only.entry.clone()))
        .verify_projection_v2(&env)
        .unwrap();
}

#[test]
fn from_wire_accepts_v2_only_with_its_own_digest_and_tag() {
    let p = projection_v2();
    let canonical = p.canonical_bytes().unwrap();
    let digest = p.projection_digest().unwrap();
    let tag = SignDomain::PublicProjectionV2.tag();
    assert!(ApprovedPayload::from_wire(tag, &canonical, Some(&digest)).is_ok());
    assert_eq!(
        ApprovedPayload::from_wire(tag, &canonical, None).unwrap_err(),
        SignRefusal::NotApproved
    );
    // The v1 digest of the same fields is not the release digest of v2.
    let v1_digest = projection().projection_digest().unwrap();
    assert_eq!(
        ApprovedPayload::from_wire(tag, &canonical, Some(&v1_digest)).unwrap_err(),
        SignRefusal::NotApproved
    );
    // v2 bytes under the v1 tag, and v1 bytes under the v2 tag, are refused.
    assert!(ApprovedPayload::from_wire(
        SignDomain::PublicProjection.tag(),
        &canonical,
        Some(&digest)
    )
    .is_err());
    let v1_bytes = projection().canonical_bytes().unwrap();
    assert!(ApprovedPayload::from_wire(tag, &v1_bytes, Some(&v1_digest)).is_err());
}
