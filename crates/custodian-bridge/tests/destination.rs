//! Destination binding through disclosure -> ledger-signed envelope ->
//! bridge service -> public consumer (ADR 0119 to 0121). The consumer holds
//! public keys and pins only. Synthetic data and test-generated keys only.

#[path = "../../custodian-disclosure/tests/common/mod.rs"]
mod common;

use common::*;
use custodian_bridge::testing::MemoryCatalog;
use custodian_bridge::wire::BridgeResponse;
use custodian_bridge::{
    BridgeConsumer, BridgeReason, BridgeRequest, BridgeService, ConsumerPins, Rejection,
    VerificationOutcome,
};
use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{EvaluationDomain, PolicyRef};
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::public_v2::{AnyProjectionEnvelope, DestinationBinding};
use custodian_contracts::revocation::{RevocationEnvelope, SignedRevocationEnvelope, Standing};
use custodian_contracts::types::{DestinationId, DocumentDigest, FeedId, Timestamp};
use custodian_contracts::Contract;
use custodian_disclosure::testing::RecordingSink;
use custodian_ledger::{ApprovedPayload, KeyEntry, Keyring, SignDomain, Signer, Verifier};
use custodian_lifecycle::MemoryFeed;
use serde_json::{json, Value};

const DEST: &str = "benchmarks-feed";
const OTHER: &str = "site-preview";

struct Fx {
    w: World,
    catalog: MemoryCatalog,
    feed: MemoryFeed,
    head: DocumentDigest,
    release_bytes: Vec<u8>,
}

fn feed_id() -> FeedId {
    FeedId::parse(&cc::id("fed_", 1)).unwrap()
}

fn population(n: u32) -> PublicPopulationRef {
    serde_json::from_value(json!({"kind": "opaque", "id": cc::id("ppr_", n)})).unwrap()
}

fn disclosure_policy_ref() -> PolicyRef {
    serde_json::from_value(cc::disclosure_policy()).unwrap()
}

fn t(secs: u64) -> Timestamp {
    now(secs)
}

fn signed_envelope(
    w: &World,
    seq: u64,
    previous: Option<&DocumentDigest>,
    entries: Value,
) -> (Vec<u8>, DocumentDigest) {
    let mut v = cc::revocation_json();
    v["sequence"] = json!(seq);
    v["issued_at"] = json!(NOW + 60);
    v["fresh_until"] = json!(NOW + 60 + 3600);
    v["entries"] = entries;
    if let Some(p) = previous {
        v["previous"] = json!(p.as_str());
    }
    let payload: RevocationEnvelope = cc::parse(&v);
    let signature = w
        .key
        .signer
        .sign(&ApprovedPayload::revocation(&payload).unwrap())
        .unwrap();
    let digest = payload.document_digest().unwrap();
    let signed = SignedRevocationEnvelope { payload, signature };
    (to_canonical_bytes(&signed).unwrap(), digest)
}

impl Fx {
    /// A real release for `DEST`: v2 (bound) when `bound`, legacy v1 otherwise.
    fn new(bound: bool) -> Self {
        let w = World::new(Opts::default());
        let p = with_default_service(&w, |svc| {
            w.provision(svc);
            let key = w.release_key(1);
            if bound {
                svc.prepare_bound(&w.input(&key), &w.destination(DEST), now(PREPARE_AT))
                    .unwrap()
            } else {
                svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap()
            }
        });
        w.export();
        let approval = w.release_approval(&p);
        let dest = w.destination(DEST);
        let obs = disclosure_activation(RELEASE_AT, "active");
        let sink = RecordingSink::new();
        let released = with_default_service(&w, |svc| {
            svc.release(
                &p,
                &w.release_request(&approval, &dest, &obs),
                &sink,
                now(RELEASE_AT),
            )
            .unwrap()
        });
        assert_eq!(released.binding().is_bound(), bound);
        let release_bytes = released.to_bytes().unwrap();
        let catalog = MemoryCatalog::new();
        catalog.add(w.request.plan.config_digest.clone(), released);
        let feed = MemoryFeed::new();
        let (b1, d1) = signed_envelope(&w, 1, None, json!([]));
        feed.force(&feed_id(), 1, b1);
        Self {
            w,
            catalog,
            feed,
            head: d1,
            release_bytes,
        }
    }

    fn service(&self, destination: &str) -> BridgeService<'_> {
        BridgeService {
            catalog: &self.catalog,
            feed: &self.feed,
            feed_id: feed_id(),
            destination: DestinationId::parse(destination).unwrap(),
        }
    }

    fn pins(&self, destination: &str, verifier: Verifier) -> ConsumerPins {
        ConsumerPins {
            domain: EvaluationDomain::Credential,
            feed_id: feed_id(),
            destination: DestinationId::parse(destination).unwrap(),
            verifier,
            accepted_populations: vec![population(1)],
            accepted_policies: vec![disclosure_policy_ref()],
        }
    }

    fn consumer(&self) -> BridgeConsumer {
        BridgeConsumer::new(self.pins(DEST, self.w.verifier.clone()))
    }

    fn request(&self, c: &BridgeConsumer) -> BridgeRequest {
        c.request(
            self.w.request.plan.candidate.clone(),
            self.w.request.plan.config_digest.clone(),
            vec![],
        )
        .unwrap()
    }

    fn ask(&self, req: &BridgeRequest) -> Result<BridgeResponse, BridgeReason> {
        self.service(DEST).answer(&req.canonical_bytes().unwrap())
    }
}

fn with_json(bytes: &[u8], f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(bytes).unwrap();
    f(&mut v);
    to_canonical_bytes(&v).unwrap()
}

#[test]
fn v2_round_trip_is_bound_and_verified_from_the_envelope_alone() {
    let fx = Fx::new(true);
    // Even a consumer that requires binding accepts it.
    let mut c = fx.consumer().require_destination_binding();
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    assert_eq!(
        AnyProjectionEnvelope::decode(&resp.projections[0])
            .unwrap()
            .major(),
        2
    );

    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert!(out.rejected.is_empty(), "{:?}", out.rejected);
    let v = &out.accepted[0];
    assert_eq!(v.major(), 2);
    assert_eq!(v.binding(), DestinationBinding::Bound);
    assert_eq!(v.outcome(), VerificationOutcome::DestinationBound);
    assert_eq!(v.destination().unwrap().as_str(), DEST);
    assert_eq!(c.standing(v, t(NOW + 120)), Standing::Valid);
}

#[test]
fn a_consumer_pinned_to_another_destination_rejects_from_the_signature_covered_field() {
    let fx = Fx::new(true);
    // The consumer pins OTHER; the unsigned manifest label is forged to match.
    let mut c = BridgeConsumer::new(fx.pins(OTHER, fx.w.verifier.clone()));
    let req = fx.request(&c);
    let mut resp = fx.ask(&fx.request(&fx.consumer())).unwrap();
    // The request digest binds the answer to the request.
    resp.manifest.request_digest = req.digest().unwrap();
    resp.manifest.destination = DestinationId::parse(OTHER).unwrap();
    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert!(out.accepted.is_empty());
    assert_eq!(out.rejected, vec![(0, Rejection::DestinationMismatch)]);
    assert_eq!(
        Rejection::DestinationMismatch.code(),
        "destination_mismatch"
    );
}

#[test]
fn tampered_destination_fails_the_signature_and_never_reaches_the_label_check() {
    let fx = Fx::new(true);
    let c = fx.consumer();
    let req = fx.request(&c);
    let tampered = with_json(&fx.release_bytes, |v| {
        v["payload"]["destination"] = json!(OTHER);
    });
    assert_eq!(
        c.verify_projection(&req, &tampered, t(NOW + 120))
            .unwrap_err(),
        Rejection::BadSignature
    );
    // Even when the attacker also swaps the pin to match the tampered label.
    let c2 = BridgeConsumer::new(fx.pins(OTHER, fx.w.verifier.clone()));
    assert_eq!(
        c2.verify_projection(&req, &tampered, t(NOW + 120))
            .unwrap_err(),
        Rejection::BadSignature
    );
}

#[test]
fn downgrade_stripping_and_upgrade_confusion_are_rejected() {
    let fx = Fx::new(true);
    let c = fx.consumer();
    let req = fx.request(&c);
    let relabel_v1 = with_json(&fx.release_bytes, |v| {
        v["payload"]["schema"] = json!("private-custodian.public-projection/1");
    });
    let strip_v2 = with_json(&fx.release_bytes, |v| {
        v["payload"].as_object_mut().unwrap().remove("destination");
    });
    for bytes in [&relabel_v1, &strip_v2] {
        assert_eq!(
            c.verify_projection(&req, bytes, t(NOW + 120)).unwrap_err(),
            Rejection::Malformed
        );
    }
    // Stripped and relabelled v1: well formed, signature made under the v2 domain.
    let downgraded = with_json(&fx.release_bytes, |v| {
        v["payload"].as_object_mut().unwrap().remove("destination");
        v["payload"]["schema"] = json!("private-custodian.public-projection/1");
    });
    assert_eq!(
        c.verify_projection(&req, &downgraded, t(NOW + 120))
            .unwrap_err(),
        Rejection::BadSignature
    );

    // A genuine v1 release passed off as v2, with and without a destination.
    let v1 = Fx::new(false);
    let c1 = v1.consumer();
    let req1 = v1.request(&c1);
    let upgraded = with_json(&v1.release_bytes, |v| {
        v["payload"]["schema"] = json!("private-custodian.public-projection/2");
    });
    assert_eq!(
        c1.verify_projection(&req1, &upgraded, t(NOW + 120))
            .unwrap_err(),
        Rejection::Malformed
    );
    let upgraded_with_dest = with_json(&v1.release_bytes, |v| {
        v["payload"]["schema"] = json!("private-custodian.public-projection/2");
        v["payload"]["destination"] = json!(DEST);
    });
    assert_eq!(
        c1.verify_projection(&req1, &upgraded_with_dest, t(NOW + 120))
            .unwrap_err(),
        Rejection::BadSignature
    );
}

#[test]
fn unknown_fields_oversize_and_non_label_destinations_are_rejected() {
    let fx = Fx::new(true);
    let c = fx.consumer();
    let req = fx.request(&c);
    let extra = with_json(&fx.release_bytes, |v| v["payload"]["note"] = json!("x"));
    let url = with_json(&fx.release_bytes, |v| {
        v["payload"]["destination"] = json!("https://example.invalid/hook");
    });
    for bytes in [
        extra,
        url,
        vec![b' '; custodian_contracts::MAX_DOCUMENT_BYTES + 1],
    ] {
        assert_eq!(
            c.verify_projection(&req, &bytes, t(NOW + 120)).unwrap_err(),
            Rejection::Malformed
        );
    }
    // Non-canonical spacing is malformed too.
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&fx.release_bytes).unwrap())
            .unwrap();
    assert_eq!(
        c.verify_projection(&req, &pretty, t(NOW + 120))
            .unwrap_err(),
        Rejection::Malformed
    );
}

#[test]
fn v1_still_verifies_and_is_labelled_unbound_never_bound() {
    let fx = Fx::new(false);
    let mut c = fx.consumer();
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    assert_eq!(
        AnyProjectionEnvelope::decode(&resp.projections[0])
            .unwrap()
            .major(),
        1
    );

    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert!(out.rejected.is_empty(), "{:?}", out.rejected);
    let v = &out.accepted[0];
    assert_eq!(v.major(), 1);
    assert_eq!(v.binding(), DestinationBinding::Unbound);
    assert_eq!(v.outcome(), VerificationOutcome::DestinationUnbound);
    assert_eq!(v.outcome().code(), "destination_unbound");
    assert!(v.destination().is_none());
    assert_ne!(v.outcome(), VerificationOutcome::DestinationBound);

    // A consumer that requires binding refuses it with its own code.
    let mut strict = fx.consumer().require_destination_binding();
    let out = strict.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert!(out.accepted.is_empty());
    assert_eq!(out.rejected, vec![(0, Rejection::DestinationUnbound)]);
    assert_eq!(Rejection::DestinationUnbound.code(), "destination_unbound");
}

#[test]
fn a_key_authorized_for_v1_only_is_not_accepted_for_v2() {
    let fx = Fx::new(true);
    let kid = fx.w.key.signer.key_id().clone();
    let v1_only = Verifier::new(
        Keyring::new().with_root(
            KeyEntry::root(
                kid,
                &fx.w.key.signer.public_key_hex(),
                [SignDomain::PublicProjection, SignDomain::RevocationEnvelope],
                cc::ts(NOW - 10_000),
            )
            .unwrap(),
        ),
    );
    let c = BridgeConsumer::new(fx.pins(DEST, v1_only));
    let req = fx.request(&c);
    assert_eq!(
        c.verify_projection(&req, &fx.release_bytes, t(NOW + 120))
            .unwrap_err(),
        Rejection::KeyNotAcceptable
    );
}

#[test]
fn revocation_reaches_a_v2_projection_through_the_same_feed() {
    let fx = Fx::new(true);
    let env = AnyProjectionEnvelope::decode(&fx.release_bytes).unwrap();
    let pid = env.common_fields().projection_id;
    let (b2, _d2) = signed_envelope(
        &fx.w,
        2,
        Some(&fx.head),
        json!([{
            "target": {"target": "projection", "projection_id": pid},
            "action": {"action": "revoked"},
            "reason": "error_correction",
            "effective_at": NOW + 60
        }]),
    );
    fx.feed.force(&feed_id(), 2, b2);
    let mut c = fx.consumer();
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert_eq!(out.feed_error, None);
    assert!(out.accepted.is_empty());
    assert_eq!(out.rejected, vec![(0, Rejection::Revoked)]);
}

#[test]
fn the_service_does_not_serve_a_v2_release_for_another_destination() {
    let fx = Fx::new(true);
    // The catalog row is for DEST; a service answering for OTHER skips it.
    let c = BridgeConsumer::new(fx.pins(OTHER, fx.w.verifier.clone()));
    let req = fx.request(&c);
    let resp = fx
        .service(OTHER)
        .answer(&req.canonical_bytes().unwrap())
        .unwrap();
    assert!(resp.projections.is_empty());
}
