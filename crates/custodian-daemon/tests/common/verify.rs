//! Consumer-side verification of a released projection, from public inputs
//! only: the released envelope bytes, the feed documents, one pinned public
//! key and the expectations a caller holds out of band. This is exactly what
//! the `custodian-verify` library does, so a pass here means the output of the
//! pipeline is accepted by the public verifier. Functional verification on
//! public synthetic data; not an independent protected evaluation.
#![allow(dead_code)]

use std::path::Path;

use custodian_bridge::wire::{BridgeManifest, BridgeManifestSchema};
use custodian_bridge::{BridgeConsumer, ConsumerPins};
use custodian_contracts::public_v2::AnyProjectionEnvelope;
use custodian_contracts::types::{BoundedVec, DestinationId, FeedId, Seq};
use custodian_ledger::{Keyring, Verifier};
use custodian_lifecycle::FeedSource;
use custodian_verify::{Bundle, Expectations, Pins, Report};
use serde_json::json;

use super::*;

pub struct Public<'a> {
    pub feed: &'a dyn FeedSource,
    pub feed_id: &'a FeedId,
    /// The pinned public key (64 hex characters) and its identifier.
    pub key_hex: String,
    pub key_id: String,
    /// The keyring the in-test consumer pins (the same key).
    pub roots: &'a Keyring,
}

/// Build the bundle for request `n` in `work` and judge it at `now`. `tamper`
/// flips a byte of the projection; `wrong_key` pins a different public key.
pub fn verify_released(
    env: &Env,
    public: &Public<'_>,
    work: &Path,
    n: u32,
    tamper: bool,
    wrong_key: bool,
    now: u64,
) -> Report {
    let (req, _) = env.request(n);
    let files = env.released_files();
    assert_eq!(files.len(), 1, "exactly one released projection");
    let mut projection = std::fs::read(&files[0]).unwrap();
    let envelope = AnyProjectionEnvelope::decode(&projection).unwrap();
    if tamper {
        let i = projection
            .windows(8)
            .position(|w| w == b"reported")
            .unwrap();
        projection[i] = b'R';
    }
    let dir = work.join(format!("verify-{tamper}-{wrong_key}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bundle/projections")).unwrap();
    std::fs::create_dir_all(dir.join("bundle/revocations")).unwrap();

    let expect_json = json!({
        "schema": "private-custodian.verify-expectations/1",
        "domain": "credential",
        "candidate": req.plan.candidate,
        "config": req.plan.config_digest,
        "destination": DEST,
        "populations": [lc::opaque(1)],
        "policies": [cc::disclosure_policy()]
    });
    let expect = Expectations::parse(&serde_json::to_vec(&expect_json).unwrap()).unwrap();
    // The request the verifier rebuilds from the expectations; the manifest
    // must answer exactly that.
    let consumer = BridgeConsumer::new(ConsumerPins {
        domain: expect.domain,
        feed_id: public.feed_id.clone(),
        destination: expect.destination.clone(),
        verifier: Verifier::new(public.roots.clone()),
        accepted_populations: expect.populations.clone(),
        accepted_policies: expect.policies.clone(),
    });
    let request_digest = consumer
        .request(
            expect.candidate.clone(),
            expect.config.clone(),
            expect.populations.clone(),
        )
        .unwrap()
        .digest()
        .unwrap();
    let mut seqs = Vec::new();
    for e in env
        .store()
        .feed_envelopes(public.feed_id.as_str(), 1)
        .unwrap()
    {
        let bytes = public
            .feed
            .get(public.feed_id, e.sequence)
            .unwrap()
            .expect("delivered");
        std::fs::write(
            dir.join(format!("bundle/revocations/{:04}.json", e.sequence)),
            bytes,
        )
        .unwrap();
        seqs.push(e.sequence);
    }
    let manifest = BridgeManifest {
        schema: BridgeManifestSchema,
        request_digest,
        feed_id: public.feed_id.clone(),
        destination: DestinationId::parse(DEST).unwrap(),
        projections: BoundedVec::new(vec![envelope.projection_digest().unwrap()]).unwrap(),
        first_sequence: Seq::new(*seqs.first().unwrap_or(&0)).unwrap(),
        last_sequence: Seq::new(*seqs.last().unwrap_or(&0)).unwrap(),
    };
    std::fs::write(
        dir.join("bundle/manifest.json"),
        manifest.canonical_bytes().unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("bundle/projections/0001.json"), &projection).unwrap();

    let key_hex = if wrong_key {
        "00".repeat(32)
    } else {
        public.key_hex.clone()
    };
    let keys = json!({
        "schema": "private-custodian.verify-keys/1",
        "keys": [{
            "key_id": public.key_id,
            "public_key": key_hex,
            "purposes": ["projection_v2", "revocation"],
            "valid_from": 1
        }]
    });
    let keys_path = dir.join("keys.json");
    std::fs::write(&keys_path, serde_json::to_vec(&keys).unwrap()).unwrap();
    let pins = Pins::load(&keys_path, public.feed_id.as_str()).unwrap();
    let bundle = Bundle::load(&dir.join("bundle")).unwrap();
    custodian_verify::verify(&pins, &expect, &bundle, now)
}
