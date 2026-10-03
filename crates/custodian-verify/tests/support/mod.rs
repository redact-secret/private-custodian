//! The synthetic fixture generator (S1). Deterministic: the throwaway Ed25519
//! seed below is public, belongs to no deployment and protects nothing, and
//! signatures are deterministic, so the output is byte-stable. Every identity
//! and digest is an obviously synthetic placeholder from the contracts test
//! helpers (`cc`). Nothing here reads a ledger, corpus or real key.
//!
//! `UPDATE_FIXTURES=1 cargo test -p custodian-verify --test fixtures`
//! rewrites `fixtures/synthetic/`; without it the test only compares.
#![allow(dead_code)]

#[path = "../../../custodian-contracts/tests/common/mod.rs"]
pub mod cc;

use std::collections::BTreeMap;

use cc::NOW;
use custodian_bridge::wire::{BridgeManifest, BridgeManifestSchema};
use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::public::{PublicProjection, PublicProjectionEnvelope};
use custodian_contracts::revocation::{RevocationEnvelope, SignedRevocationEnvelope};
use custodian_contracts::types::{BoundedVec, DestinationId, DocumentDigest, KeyId, Seq};
use custodian_contracts::Contract;
use custodian_ledger::{ApprovedPayload, SignDomain, Signer, SoftwareSigner};
use serde_json::{json, Value};

pub const DEST: &str = "benchmarks-feed";
/// A public, throwaway test seed. It is not a secret and signs nothing real.
pub const TEST_SEED: [u8; 32] = [0x53; 32];

pub fn feed_id() -> String {
    cc::id("fed_", 1)
}

pub fn signer() -> SoftwareSigner {
    SoftwareSigner::from_seed(
        KeyId::parse(&cc::id("key_", 1)).unwrap(),
        &TEST_SEED,
        [SignDomain::PublicProjection, SignDomain::RevocationEnvelope],
    )
}

pub fn keys_json() -> Value {
    json!({
        "schema": "private-custodian.verify-keys/1",
        "keys": [{
            "key_id": cc::id("key_", 1),
            "public_key": signer().public_key_hex(),
            "purposes": ["projection", "revocation"],
            "valid_from": NOW - 10_000
        }]
    })
}

pub fn expectations_json(domain: &str, candidate_label: &str) -> Value {
    json!({
        "schema": "private-custodian.verify-expectations/1",
        "domain": domain,
        "candidate": cc::dg(candidate_label),
        "config": cc::dg("synthetic-config"),
        "destination": DEST,
        "populations": [{"kind": "opaque", "id": cc::id("ppr_", 1)}],
        "policies": [cc::disclosure_policy()]
    })
}

fn projection_bytes(tamper: bool) -> (Vec<u8>, PublicProjection) {
    let mut v = cc::projection_json();
    if tamper {
        // Same shape, different content: the signature below no longer fits.
        v["cells"][0]["value"]["numerator"] = json!(10);
    }
    let payload: PublicProjection = cc::parse(&v);
    let mut signed_over = cc::projection_json();
    signed_over["cells"][0]["value"]["numerator"] = json!(9);
    let signed_payload: PublicProjection = cc::parse(&signed_over);
    let canonical = signed_payload.canonical_bytes().unwrap();
    let digest = signed_payload.projection_digest().unwrap();
    let approved = ApprovedPayload::from_wire(
        SignDomain::PublicProjection.tag(),
        &canonical,
        Some(&digest),
    )
    .unwrap();
    let signature = signer().sign(&approved).unwrap();
    let bytes = to_canonical_bytes(&PublicProjectionEnvelope {
        payload: payload.clone(),
        signature,
    })
    .unwrap();
    (bytes, payload)
}

fn feed_envelope(
    seq: u64,
    previous: Option<&DocumentDigest>,
    issued: u64,
    entries: Value,
) -> (Vec<u8>, DocumentDigest) {
    let mut v = cc::revocation_json();
    v["sequence"] = json!(seq);
    v["issued_at"] = json!(issued);
    v["fresh_until"] = json!(issued + 3600);
    v["entries"] = entries;
    if let Some(p) = previous {
        v["previous"] = json!(p.as_str());
    }
    let payload: RevocationEnvelope = cc::parse(&v);
    let signature = signer()
        .sign(&ApprovedPayload::revocation(&payload).unwrap())
        .unwrap();
    let digest = payload.document_digest().unwrap();
    (
        to_canonical_bytes(&SignedRevocationEnvelope { payload, signature }).unwrap(),
        digest,
    )
}

/// One case: its files by relative path, and what the verifier must say.
pub struct Case {
    pub name: &'static str,
    pub now: u64,
    pub expected_exit: u8,
    pub expected_reason: &'static str,
    pub files: BTreeMap<String, Vec<u8>>,
}

struct Spec {
    name: &'static str,
    now: u64,
    expected_exit: u8,
    expected_reason: &'static str,
    /// Expectations the caller pins for this case.
    domain: &'static str,
    candidate_label: &'static str,
    tamper: bool,
    /// Feed envelopes to include: (sequence, issued_at, entries).
    feed: Vec<(u64, u64, Value)>,
}

fn revoke_entry() -> Value {
    json!([{
        "target": {"target": "projection", "projection_id": cc::id("prj_", 1)},
        "action": {"action": "revoked"},
        "reason": "error_correction",
        "effective_at": NOW + 90
    }])
}

fn specs() -> Vec<Spec> {
    let base = |name, now, exit, reason| Spec {
        name,
        now,
        expected_exit: exit,
        expected_reason: reason,
        domain: "credential",
        candidate_label: "synthetic-candidate",
        tamper: false,
        feed: vec![(1, NOW + 60, json!([]))],
    };
    vec![
        base("positive", NOW + 120, 0, "ok"),
        // Feed head fresh_until is NOW + 3660: one second later it is stale.
        base("stale-feed", NOW + 3661, 10, "stale"),
        Spec {
            domain: "pii",
            ..base("wrong-domain", NOW + 120, 10, "wrong_domain")
        },
        Spec {
            candidate_label: "synthetic-other-candidate",
            ..base("wrong-candidate", NOW + 120, 10, "wrong_candidate")
        },
        Spec {
            feed: vec![(1, NOW + 60, json!([])), (2, NOW + 90, revoke_entry())],
            ..base("revoked", NOW + 120, 10, "revoked")
        },
        Spec {
            tamper: true,
            ..base("tampered", NOW + 120, 10, "bad_signature")
        },
        // Sequence 2 is absent while 3 is present.
        Spec {
            feed: vec![
                (1, NOW + 60, json!([])),
                (2, NOW + 90, json!([])),
                (3, NOW + 100, json!([])),
            ],
            ..base("feed-gap", NOW + 120, 11, "feed_gap")
        },
    ]
}

fn pretty(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s.into_bytes()
}

pub fn shared_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([("keys.json".to_owned(), pretty(&keys_json()))])
}

pub fn cases() -> Vec<Case> {
    specs()
        .into_iter()
        .map(|s| {
            let (proj_bytes, payload) = projection_bytes(s.tamper);
            let mut files = BTreeMap::new();
            let mut feed_docs = Vec::new();
            let mut prev: Option<DocumentDigest> = None;
            let mut full: Vec<(u64, Vec<u8>)> = Vec::new();
            // A full chain is built so previous links are real; the gap case
            // then drops sequence 2 from the bundle only.
            for (seq, issued, entries) in &s.feed {
                let (b, d) = feed_envelope(*seq, prev.as_ref(), *issued, entries.clone());
                full.push((*seq, b));
                prev = Some(d);
            }
            for (seq, b) in full {
                if s.name == "feed-gap" && seq == 2 {
                    continue;
                }
                feed_docs.push((seq, b));
            }

            let expect = expectations_json(s.domain, s.candidate_label);
            // The manifest answers the request the caller would send, so the
            // case exercises the projection or feed check, not request routing.
            let manifest = BridgeManifest {
                schema: BridgeManifestSchema,
                request_digest: request_digest(&expect),
                feed_id: custodian_contracts::types::FeedId::parse(&feed_id()).unwrap(),
                destination: DestinationId::parse(DEST).unwrap(),
                projections: BoundedVec::new(vec![payload.projection_digest().unwrap()]).unwrap(),
                first_sequence: Seq::new(feed_docs.first().map_or(0, |d| d.0)).unwrap(),
                last_sequence: Seq::new(feed_docs.last().map_or(0, |d| d.0)).unwrap(),
            };
            files.insert(
                "bundle/manifest.json".to_owned(),
                manifest.canonical_bytes().unwrap(),
            );
            files.insert("bundle/projections/0001.json".to_owned(), proj_bytes);
            for (seq, b) in feed_docs {
                files.insert(format!("bundle/revocations/{seq:04}.json"), b);
            }
            files.insert("expectations.json".to_owned(), pretty(&expect));
            files.insert(
                "case.json".to_owned(),
                pretty(&json!({
                    "now": s.now,
                    "expected_exit": s.expected_exit,
                    "expected_reason": s.expected_reason,
                    "feed_id": feed_id()
                })),
            );
            Case {
                name: s.name,
                now: s.now,
                expected_exit: s.expected_exit,
                expected_reason: s.expected_reason,
                files,
            }
        })
        .collect()
}

fn request_digest(expect: &Value) -> DocumentDigest {
    use custodian_bridge::{BridgeConsumer, ConsumerPins};
    use custodian_ledger::{Keyring, Verifier};
    let e = custodian_verify::Expectations::parse(&serde_json::to_vec(expect).unwrap()).unwrap();
    let consumer = BridgeConsumer::new(ConsumerPins {
        domain: e.domain,
        feed_id: custodian_contracts::types::FeedId::parse(&feed_id()).unwrap(),
        destination: e.destination.clone(),
        verifier: Verifier::new(Keyring::new()),
        accepted_populations: e.populations.clone(),
        accepted_policies: e.policies.clone(),
    });
    consumer
        .request(e.candidate, e.config, e.populations)
        .unwrap()
        .digest()
        .unwrap()
}
