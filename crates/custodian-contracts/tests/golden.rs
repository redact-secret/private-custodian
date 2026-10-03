//! Golden vectors: canonical bytes and domain-separated digests for every
//! contract. A change to any encoding, tag or digest rule fails here and
//! needs a new schema/domain version, not an edited vector. Regenerate only
//! deliberately: `UPDATE_GOLDEN=1 cargo test -p custodian-contracts --test golden`.

mod common;

use std::fmt::Write as _;
use std::path::PathBuf;

use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::{domain_digest, signing_input, to_canonical_bytes, DomainTag};
use custodian_contracts::execution::{ExecutionRecord, InternalReceipt};
use custodian_contracts::policy::PolicyActivation;
use custodian_contracts::public::PublicProjection;
use custodian_contracts::public_v2::PublicProjectionV2;
use custodian_contracts::request::{EvaluationPlan, EvaluationRequest};
use custodian_contracts::reservation::Reservation;
use custodian_contracts::revocation::RevocationEnvelope;
use custodian_contracts::types::{CandidateDigest, ProjectionDigest};
use custodian_contracts::Contract;

struct Vector {
    name: &'static str,
    domain: DomainTag,
    canonical: Vec<u8>,
    digest: String,
}

fn contract<T: Contract>(name: &'static str, v: &serde_json::Value) -> Vector {
    let doc: T = parse(v);
    Vector {
        name,
        domain: T::DOMAIN,
        canonical: doc.canonical_bytes().unwrap(),
        digest: doc.document_digest().unwrap().as_str().to_owned(),
    }
}

fn vectors() -> Vec<Vector> {
    let req = request();
    let plan_bytes = to_canonical_bytes(&req.plan).unwrap();
    let projection = projection();
    vec![
        contract::<EvaluationRequest>("request", &request_json()),
        Vector {
            name: "plan",
            domain: DomainTag::Plan,
            digest: req.plan.plan_digest().unwrap().as_str().to_owned(),
            canonical: plan_bytes,
        },
        contract::<Approval>("approval-execute", &approval_json()),
        contract::<Approval>("approval-release", &release_approval_json()),
        contract::<Reservation>("reservation", &reservation_json()),
        contract::<ExecutionRecord>("execution", &execution_json()),
        contract::<InternalReceipt>("internal-receipt", &receipt_json()),
        contract::<PolicyActivation>("policy-activation", &activation_json()),
        Vector {
            name: "public-projection",
            domain: DomainTag::PublicProjection,
            digest: projection.projection_digest().unwrap().as_str().to_owned(),
            canonical: projection.canonical_bytes().unwrap(),
        },
        contract::<RevocationEnvelope>("revocation-envelope", &revocation_json()),
        // Added with public projection major 2 (ADR 0119). Appended, so the
        // v1 lines above are byte-for-byte what they were.
        contract::<PublicProjectionV2>("public-projection-v2", &projection_v2_json()),
    ]
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/golden")
}

fn digests_text(vs: &[Vector]) -> String {
    let mut s = String::new();
    for v in vs {
        writeln!(s, "{} {} {}", v.name, v.domain.as_str(), v.digest).unwrap();
    }
    s
}

#[test]
fn golden_vectors_match() {
    let vs = vectors();
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    if update {
        std::fs::create_dir_all(dir()).unwrap();
        for v in &vs {
            std::fs::write(
                dir().join(format!("{}.canonical.json", v.name)),
                &v.canonical,
            )
            .unwrap();
        }
        std::fs::write(dir().join("digests.txt"), digests_text(&vs)).unwrap();
    }
    let expected_digests = std::fs::read_to_string(dir().join("digests.txt")).unwrap();
    assert_eq!(
        digests_text(&vs),
        expected_digests,
        "digest vectors changed"
    );
    for v in &vs {
        let stored = std::fs::read(dir().join(format!("{}.canonical.json", v.name))).unwrap();
        assert_eq!(v.canonical, stored, "canonical bytes changed: {}", v.name);
    }
}

/// Backward compatibility: stored v1 documents still decode strictly and are
/// already canonical.
#[test]
fn stored_v1_documents_still_decode_canonically() {
    let read = |n: &str| std::fs::read(dir().join(format!("{n}.canonical.json"))).unwrap();
    EvaluationRequest::decode_canonical(&read("request")).unwrap();
    Approval::decode_canonical(&read("approval-execute")).unwrap();
    Approval::decode_canonical(&read("approval-release")).unwrap();
    Reservation::decode_canonical(&read("reservation")).unwrap();
    ExecutionRecord::decode_canonical(&read("execution")).unwrap();
    InternalReceipt::decode_canonical(&read("internal-receipt")).unwrap();
    PolicyActivation::decode_canonical(&read("policy-activation")).unwrap();
    PublicProjection::decode_canonical(&read("public-projection")).unwrap();
    RevocationEnvelope::decode_canonical(&read("revocation-envelope")).unwrap();
    PublicProjectionV2::decode_canonical(&read("public-projection-v2")).unwrap();
    let plan: EvaluationPlan = serde_json::from_slice(&read("plan")).unwrap();
    plan.validate().unwrap();
}

/// Independent check of the digest construction against a fixed input, so the
/// rule can be re-implemented elsewhere: sha256("<domain>" 0x00 "<bytes>").
/// Expected values were produced with `shasum -a 256`, not with this crate.
#[test]
fn digest_construction_matches_external_sha256() {
    // printf 'private-custodian/v1/plan\0{}' | shasum -a 256
    let d = domain_digest(DomainTag::Plan, b"{}");
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, "e40cf9eb35e482e790cc78c51035e6ee07cc8667ed46acad19326af063951acc",
        "domain digest construction changed"
    );
    // printf 'synthetic-candidate' | shasum -a 256
    assert_eq!(
        CandidateDigest::of_bytes(b"synthetic-candidate").as_str(),
        "sha256:ba4e586d9645eeb9e880309cb85bbedde21738fc2fc5efb76fc73e3d2dede376"
    );
    let _ = (
        signing_input(DomainTag::Plan, b"{}"),
        ProjectionDigest::from_raw([0; 32]),
    );
}

/// The v1 vectors recorded before major 2 existed are frozen: these lines are
/// what the first release wrote and must never change (no reinterpretation).
#[test]
fn legacy_v1_projection_vector_is_frozen() {
    let digests = std::fs::read_to_string(dir().join("digests.txt")).unwrap();
    assert!(digests.lines().any(|l| l
        == "public-projection private-custodian/v1/public-projection sha256:a5bf82488ffb8a6787aac5fca43f2879fdc58d803bcc7d843992fdeec9f01622"));
    assert!(digests
        .lines()
        .any(|l| l.starts_with("public-projection-v2 private-custodian/v2/public-projection ")));
}

/// The same fields hash differently under v1 and v2: new domain tag, new
/// schema tag, one more field.
#[test]
fn v1_and_v2_digests_never_coincide() {
    assert_ne!(
        projection().projection_digest().unwrap(),
        projection_v2().projection_digest().unwrap()
    );
    let v2_bytes = projection_v2().canonical_bytes().unwrap();
    assert_ne!(
        domain_digest(DomainTag::PublicProjection, &v2_bytes),
        domain_digest(DomainTag::PublicProjectionV2, &v2_bytes)
    );
}
