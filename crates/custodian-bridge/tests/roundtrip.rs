//! The bridge end to end with synthetic data (C11): the custodian prepares a
//! real approved release (C8) and a signed revocation feed (C9, chained by the
//! test signer), a consumer holding only public keys and pins verifies it, and
//! every way it must refuse is exercised.

#[path = "../../custodian-disclosure/tests/common/mod.rs"]
mod common;

use common::*;
use custodian_bridge::testing::MemoryCatalog;
use custodian_bridge::wire::{BridgeManifest, BridgeResponse};
use custodian_bridge::{
    BridgeConsumer, BridgeReason, BridgeRequest, BridgeService, ConsumerPins, Rejection,
};
use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{EvaluationDomain, PolicyRef};
use custodian_contracts::public::{PublicPopulationRef, PublicProjectionEnvelope};
use custodian_contracts::revocation::{RevocationEnvelope, SignedRevocationEnvelope, Standing};
use custodian_contracts::types::{DestinationId, DocumentDigest, FeedId, Timestamp};
use custodian_contracts::Contract;
use custodian_disclosure::testing::RecordingSink;
use custodian_ledger::{ApprovedPayload, Signer};
use custodian_lifecycle::{FeedSource, MemoryFeed, SyncError};
use serde_json::{json, Value};

const DEST: &str = "benchmarks-feed";

struct Fx {
    w: World,
    catalog: MemoryCatalog,
    feed: MemoryFeed,
    heads: Vec<DocumentDigest>,
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

/// Sign and canonicalize one feed envelope with the test signer.
fn signed_envelope(
    w: &World,
    seq: u64,
    previous: Option<&DocumentDigest>,
    issued: u64,
    fresh_until: u64,
    entries: Value,
) -> (Vec<u8>, DocumentDigest) {
    let mut v = cc::revocation_json();
    v["sequence"] = json!(seq);
    v["issued_at"] = json!(issued);
    v["fresh_until"] = json!(fresh_until);
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
    /// A real release for `DEST` and feed sequence 1 (an empty renewal,
    /// fresh for an hour).
    fn new(opts: Opts) -> Self {
        let w = World::new(opts);
        let w1 = &w;
        let p = with_default_service(w1, |svc| {
            w1.provision(svc);
            svc.prepare(&w1.input(&w1.release_key(1)), now(PREPARE_AT))
                .unwrap()
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
        let release_bytes = released.to_bytes().unwrap();
        let catalog = MemoryCatalog::new();
        catalog.add(w.request.plan.config_digest.clone(), released);
        let feed = MemoryFeed::new();
        let (b1, d1) = signed_envelope(&w, 1, None, NOW + 60, NOW + 60 + 3600, json!([]));
        feed.force(&feed_id(), 1, b1);
        Self {
            w,
            catalog,
            feed,
            heads: vec![d1],
            release_bytes,
        }
    }

    /// Append the next feed envelope.
    fn push(&mut self, issued: u64, fresh_until: u64, entries: Value) {
        let seq = self.heads.len() as u64 + 1;
        let (b, d) = signed_envelope(
            &self.w,
            seq,
            self.heads.last(),
            issued,
            fresh_until,
            entries,
        );
        self.feed.force(&feed_id(), seq, b);
        self.heads.push(d);
    }

    fn service(&self) -> BridgeService<'_> {
        BridgeService {
            catalog: &self.catalog,
            feed: &self.feed,
            feed_id: feed_id(),
            destination: DestinationId::parse(DEST).unwrap(),
        }
    }

    fn pins(&self) -> ConsumerPins {
        ConsumerPins {
            domain: EvaluationDomain::Credential,
            feed_id: feed_id(),
            destination: DestinationId::parse(DEST).unwrap(),
            verifier: self.w.verifier.clone(),
            accepted_populations: vec![population(1)],
            accepted_policies: vec![disclosure_policy_ref()],
        }
    }

    fn request(&self, c: &BridgeConsumer) -> BridgeRequest {
        c.request(
            self.w.request.plan.candidate.clone(),
            self.w.request.plan.config_digest.clone(),
            vec![],
        )
        .unwrap()
    }

    /// The wire round trip a transport would do.
    fn ask(&self, req: &BridgeRequest) -> Result<BridgeResponse, BridgeReason> {
        let r = self.service().answer(&req.canonical_bytes().unwrap())?;
        let wire = BridgeResponse::from_wire(
            &r.manifest.canonical_bytes().unwrap(),
            r.projections.clone(),
            r.revocations.clone(),
        )
        .unwrap();
        assert_eq!(wire, r);
        Ok(wire)
    }
}

fn t(secs: u64) -> Timestamp {
    now(secs)
}

#[test]
fn approved_release_and_feed_verify_with_public_inputs_only() {
    let fx = Fx::new(Opts::default());
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    assert_eq!(req.known_sequence.get(), 0);
    let resp = fx.ask(&req).unwrap();
    assert_eq!(resp.projections.len(), 1);
    assert_eq!(resp.revocations.len(), 1);
    assert_eq!(resp.projections[0], fx.release_bytes);

    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert_eq!(out.feed_error, None);
    assert_eq!(out.feed_applied, 1);
    assert!(out.rejected.is_empty());
    assert_eq!(out.accepted.len(), 1);
    let v = &out.accepted[0];
    assert_eq!(c.standing(v, t(NOW + 120)), Standing::Valid);
    assert_eq!(c.known_sequence(), 1);

    // The attestation arrives exactly as released: nothing claims independence
    // or ground truth.
    let a = serde_json::to_value(v.attestation()).unwrap();
    assert_eq!(a["ground_truth"], "not_established");
    assert_eq!(a["organisational_independence"], "not_claimed");

    // A second ask with the feed state held returns no new feed documents
    // and the same projection; replays are harmless.
    let req2 = fx.request(&c);
    assert_eq!(req2.known_sequence.get(), 1);
    let resp2 = fx.ask(&req2).unwrap();
    assert!(resp2.revocations.is_empty());
    let out2 = c.accept_response(&req2, &resp2, t(NOW + 130)).unwrap();
    assert_eq!(out2.accepted.len(), 1);
    assert_eq!(out2.feed_applied, 0);
}

#[test]
fn a_stale_feed_never_validates_and_an_old_projection_expires() {
    let fx = Fx::new(Opts::default());
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    // Feed head fresh_until is NOW + 3660: one second later it is stale.
    let out = c.accept_response(&req, &resp, t(NOW + 3661)).unwrap();
    assert_eq!(out.accepted.len(), 0);
    assert_eq!(out.rejected, vec![(0, Rejection::Stale)]);

    // Before the feed is read at all, nothing is valid.
    let blank = BridgeConsumer::new(fx.pins());
    assert_eq!(
        blank
            .verify_projection(&req, &fx.release_bytes, t(NOW + 120))
            .unwrap_err(),
        Rejection::Stale
    );

    // A feed renewed past the projection's own freshness: the projection
    // expires on its own (policy freshness is 86400 s from NOW + 50).
    let mut fx = fx;
    fx.push(NOW + 90_000, NOW + 90_000 + 3600, json!([]));
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    let out = c.accept_response(&req, &resp, t(NOW + 90_100)).unwrap();
    assert_eq!(out.rejected, vec![(0, Rejection::Expired)]);
}

#[test]
fn wrong_domain_candidate_and_population_are_rejected_on_both_sides() {
    let fx = Fx::new(Opts::default());
    let c = BridgeConsumer::new(fx.pins());
    let good = fx.request(&c);

    // The consumer verifies against its own request even if a hostile
    // transport hands it a projection that matches another.
    let mut other_candidate = good.clone();
    other_candidate.candidate =
        custodian_contracts::types::CandidateDigest::of_bytes(b"synthetic-other");
    let mut other_domain = good.clone();
    other_domain.domain = EvaluationDomain::Pii;
    let mut other_pop = good.clone();
    other_pop.populations =
        custodian_contracts::types::BoundedVec::new(vec![population(2)]).unwrap();

    // Feed state is irrelevant to these checks: they come first.
    let now = t(NOW + 120);
    let bytes = &fx.release_bytes;
    assert_eq!(
        c.verify_projection(&other_candidate, bytes, now)
            .unwrap_err(),
        Rejection::WrongCandidate
    );
    assert_eq!(
        c.verify_projection(&other_domain, bytes, now).unwrap_err(),
        Rejection::WrongDomain
    );
    assert_eq!(
        c.verify_projection(&other_pop, bytes, now).unwrap_err(),
        Rejection::WrongPopulation
    );

    // A consumer pinned to the other domain rejects it too.
    let mut pii_pins = fx.pins();
    pii_pins.domain = EvaluationDomain::Pii;
    let pii = BridgeConsumer::new(pii_pins);
    let pii_req = pii
        .request(good.candidate.clone(), good.config.clone(), vec![])
        .unwrap();
    assert_eq!(
        pii.verify_projection(&pii_req, bytes, now).unwrap_err(),
        Rejection::WrongDomain
    );

    // A population the product has not pinned, or a policy it does not
    // accept, is not relied on whatever the signature says.
    let mut p = fx.pins();
    p.accepted_populations = vec![population(2)];
    assert_eq!(
        BridgeConsumer::new(p)
            .verify_projection(&good, bytes, now)
            .unwrap_err(),
        Rejection::WrongPopulation
    );
    let mut p = fx.pins();
    p.accepted_populations = vec![];
    assert_eq!(
        BridgeConsumer::new(p)
            .verify_projection(&good, bytes, now)
            .unwrap_err(),
        Rejection::WrongPopulation
    );
    let mut p = fx.pins();
    p.accepted_policies = vec![];
    assert_eq!(
        BridgeConsumer::new(p)
            .verify_projection(&good, bytes, now)
            .unwrap_err(),
        Rejection::PolicyNotAccepted
    );
    let mut p = fx.pins();
    p.feed_id = FeedId::parse(&cc::id("fed_", 2)).unwrap();
    assert_eq!(
        BridgeConsumer::new(p)
            .verify_projection(&good, bytes, now)
            .unwrap_err(),
        Rejection::WrongFeed
    );

    // The service never returns a projection for another candidate, domain
    // or population filter.
    for req in [&other_candidate, &other_domain, &other_pop] {
        let r = fx.ask(req).unwrap();
        assert!(r.projections.is_empty());
        assert!(r.manifest.projections.is_empty());
    }
}

#[test]
fn tampered_unsigned_and_foreign_signatures_are_rejected() {
    let fx = Fx::new(Opts::default());
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    let now = t(NOW + 130);
    let good: Value = serde_json::from_slice(&fx.release_bytes).unwrap();
    let canon = |v: &Value| to_canonical_bytes(v).unwrap();

    // A changed count with a stale signature.
    let mut tampered = good.clone();
    let cell = &mut tampered["payload"]["cells"][3]["value"];
    if cell["state"] == "reported" {
        cell["numerator"] = json!(cell["denominator"].as_u64().unwrap());
    } else {
        tampered["payload"]["fresh_until"] =
            json!(good["payload"]["fresh_until"].as_u64().unwrap() + 1);
    }
    assert_eq!(
        c.verify_projection(&req, &canon(&tampered), now)
            .unwrap_err(),
        Rejection::BadSignature
    );
    // A changed candidate with a stale signature: signature first.
    let mut other = good.clone();
    other["payload"]["candidate"] = json!(cc::dg("synthetic-other"));
    assert_eq!(
        c.verify_projection(&req, &canon(&other), now).unwrap_err(),
        Rejection::BadSignature
    );

    // Unsigned: no signature field at all, an empty-looking signature, or a
    // well-formed signature that does not verify.
    let mut unsigned = good.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    assert_eq!(
        c.verify_projection(&req, &canon(&unsigned), now)
            .unwrap_err(),
        Rejection::Malformed
    );
    let mut dummy = good.clone();
    dummy["signature"]["value"] = json!("A".repeat(86));
    assert_eq!(
        c.verify_projection(&req, &canon(&dummy), now).unwrap_err(),
        Rejection::BadSignature
    );
    // A key the consumer has not pinned.
    let mut foreign = good.clone();
    foreign["signature"]["key_id"] = json!(cc::id("key_", 99));
    assert_eq!(
        c.verify_projection(&req, &canon(&foreign), now)
            .unwrap_err(),
        Rejection::KeyNotAcceptable
    );

    // Not canonical (pretty printed), not JSON, truncated, oversized.
    let pretty = serde_json::to_vec_pretty(&good).unwrap();
    for bad in [
        pretty,
        b"not json".to_vec(),
        fx.release_bytes[..fx.release_bytes.len() / 2].to_vec(),
        vec![b' '; 70_000],
        Vec::new(),
    ] {
        assert_eq!(
            c.verify_projection(&req, &bad, now).unwrap_err(),
            Rejection::Malformed
        );
    }
    // Unknown extra field.
    let mut extra = good.clone();
    extra["payload"]["note"] = json!("x");
    assert_eq!(
        c.verify_projection(&req, &canon(&extra), now).unwrap_err(),
        Rejection::Malformed
    );
    // The untouched bytes still verify: the fixtures are not just failing.
    assert!(c.verify_projection(&req, &fx.release_bytes, now).is_ok());
    // And decode really is the envelope type.
    PublicProjectionEnvelope::decode(&fx.release_bytes).unwrap();
}

#[test]
fn revocation_contamination_and_supersession_reach_the_consumer() {
    let fx = Fx::new(Opts::default());
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    let v = out.accepted[0].clone();
    assert!(c.reevaluate(t(NOW + 125)).is_empty());

    let projection_id = v.projection().projection_id.as_str().to_owned();
    let candidate = v.projection().candidate.as_str().to_owned();
    let population = serde_json::to_value(&v.projection().population).unwrap();
    for (entries, expected) in [
        (
            json!([{"target": {"target":"projection","projection_id": projection_id},
                "action": {"action":"revoked"}, "reason":"error_correction",
                "effective_at": NOW + 200}]),
            Standing::Revoked,
        ),
        (
            json!([{"target": {"target":"candidate","candidate": candidate},
                "action": {"action":"revoked"}, "reason":"error_correction",
                "effective_at": NOW + 200}]),
            Standing::Revoked,
        ),
        (
            json!([{"target": {"target":"population","population": population},
                "action": {"action":"contaminated"}, "reason":"contamination",
                "effective_at": NOW + 200}]),
            Standing::Revoked,
        ),
        (
            json!([{"target": {"target":"projection","projection_id": projection_id},
                "action": {"action":"superseded","superseded_by": cc::id("prj_", 77)},
                "reason":"newer_evidence", "effective_at": NOW + 200}]),
            Standing::Superseded,
        ),
    ] {
        // Each case from the same starting point: sequence 1 valid.
        let mut f = Fx::new(Opts::default());
        f.push(NOW + 300, NOW + 300 + 3600, entries);
        let mut c = BridgeConsumer::new(f.pins());
        let req = f.request(&c);
        let first = f.ask(&req).unwrap();
        // Take sequence 1 only, track the projection, then learn of 2.
        let one = BridgeResponse {
            manifest: first.manifest.clone(),
            projections: first.projections.clone(),
            revocations: vec![first.revocations[0].clone()],
        };
        let out = c.accept_response(&req, &one, t(NOW + 120)).unwrap();
        assert_eq!(out.accepted.len(), 1);
        let req2 = f.request(&c);
        let second = f.ask(&req2).unwrap();
        assert_eq!(second.revocations.len(), 1);
        let out2 = c.accept_response(&req2, &second, t(NOW + 400)).unwrap();
        assert_eq!(out2.feed_applied, 1);
        let changes = c.reevaluate(t(NOW + 401));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].to, expected);
        assert_eq!(c.standing(&out.accepted[0], t(NOW + 401)), expected);
        // The same projection offered again is rejected, not re-accepted.
        assert!(out2.accepted.is_empty());
        let want = if expected == Standing::Revoked {
            Rejection::Revoked
        } else {
            Rejection::Superseded
        };
        assert_eq!(out2.rejected, vec![(0, want)]);
    }
}

#[test]
fn feed_gaps_forks_and_foreign_feeds_are_not_accepted() {
    let mut fx = Fx::new(Opts::default());
    fx.push(NOW + 100, NOW + 100 + 3600, json!([]));
    fx.push(NOW + 110, NOW + 110 + 3600, json!([]));

    // Gap at the source: the service refuses to answer past it.
    fx.feed.remove(&feed_id(), 2);
    let c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    assert_eq!(fx.ask(&req).unwrap_err(), BridgeReason::FeedGap);

    // A hostile transport delivering 1 and 3: the consumer stops at the gap
    // and judges on what it holds; the projection is valid on sequence 1
    // alone but nothing past the gap is applied.
    let mut c = BridgeConsumer::new(fx.pins());
    let one = fx.feed.get(&feed_id(), 1).unwrap().unwrap();
    let three = fx.feed.get(&feed_id(), 3).unwrap().unwrap();
    let resp = BridgeResponse {
        manifest: manifest_for(&fx, &req, 1, 3),
        projections: vec![fx.release_bytes.clone()],
        revocations: vec![one, three],
    };
    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert_eq!(out.feed_applied, 1);
    assert_eq!(out.feed_error, Some(SyncError::Gap));
    assert_eq!(c.known_sequence(), 1);

    // A request ahead of the feed the custodian has.
    let mut ahead = req.clone();
    ahead.known_sequence = custodian_contracts::types::Seq::new(9).unwrap();
    assert_eq!(
        fx.ask(&ahead).unwrap_err(),
        BridgeReason::SequenceAheadOfFeed
    );

    // A fork: a correctly signed different document for an accepted sequence.
    let fx = Fx::new(Opts::default());
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    let (forked, _) = signed_envelope(&fx.w, 1, None, NOW + 61, NOW + 61 + 3600, json!([]));
    fx.feed.force(&feed_id(), 1, forked.clone());
    let resp = BridgeResponse {
        manifest: no_projections(manifest_for(&fx, &req, 1, 1)),
        projections: vec![],
        revocations: vec![forked],
    };
    let out = c.accept_response(&req, &resp, t(NOW + 130)).unwrap();
    assert_eq!(out.feed_error, Some(SyncError::Fork));

    // An unsigned imitation is a bad signature, not a fork alarm.
    let mut imitation: Value =
        serde_json::from_slice(&fx.feed.get(&feed_id(), 1).unwrap().unwrap()).unwrap();
    imitation["payload"]["issued_at"] = json!(NOW + 62);
    let resp = BridgeResponse {
        manifest: no_projections(manifest_for(&fx, &req, 1, 1)),
        projections: vec![],
        revocations: vec![to_canonical_bytes(&imitation).unwrap()],
    };
    let out = c.accept_response(&req, &resp, t(NOW + 130)).unwrap();
    assert_eq!(out.feed_error, Some(SyncError::BadSignature));
}

fn no_projections(mut m: BridgeManifest) -> BridgeManifest {
    m.projections = custodian_contracts::types::BoundedVec::new(vec![]).unwrap();
    m
}

fn manifest_for(fx: &Fx, req: &BridgeRequest, first: u64, last: u64) -> BridgeManifest {
    let mut m = fx.ask_manifest_template(req);
    m.first_sequence = custodian_contracts::types::Seq::new(first).unwrap();
    m.last_sequence = custodian_contracts::types::Seq::new(last).unwrap();
    m
}

impl Fx {
    fn ask_manifest_template(&self, req: &BridgeRequest) -> BridgeManifest {
        let digest = custodian_contracts::types::ProjectionDigest::parse(
            PublicProjectionEnvelope::decode(&self.release_bytes)
                .unwrap()
                .payload
                .projection_digest()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        BridgeManifest {
            schema: Default::default(),
            request_digest: req.digest().unwrap(),
            feed_id: feed_id(),
            destination: DestinationId::parse(DEST).unwrap(),
            projections: custodian_contracts::types::BoundedVec::new(vec![digest]).unwrap(),
            first_sequence: custodian_contracts::types::Seq::new(0).unwrap(),
            last_sequence: custodian_contracts::types::Seq::new(0).unwrap(),
        }
    }
}

#[test]
fn a_response_for_another_request_channel_or_feed_is_rejected() {
    let fx = Fx::new(Opts::default());
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();

    // Another request's answer.
    let mut other = req.clone();
    other.candidate = custodian_contracts::types::CandidateDigest::of_bytes(b"synthetic-other");
    assert_eq!(
        c.accept_response(&other, &resp, t(NOW + 120)).unwrap_err(),
        Rejection::WrongRequest
    );
    // Another channel.
    let mut r = resp.clone();
    r.manifest.destination = DestinationId::parse("site-preview").unwrap();
    assert_eq!(
        c.accept_response(&req, &r, t(NOW + 120)).unwrap_err(),
        Rejection::WrongDestination
    );
    // Another feed.
    let mut r = resp.clone();
    r.manifest.feed_id = FeedId::parse(&cc::id("fed_", 2)).unwrap();
    assert_eq!(
        c.accept_response(&req, &r, t(NOW + 120)).unwrap_err(),
        Rejection::WrongFeed
    );
    // A projection the manifest does not list.
    let mut r = resp.clone();
    r.manifest.projections = custodian_contracts::types::BoundedVec::new(vec![]).unwrap();
    r.projections = vec![fx.release_bytes.clone()];
    // (count mismatch is a bounds failure before anything is parsed)
    assert_eq!(
        c.accept_response(&req, &r, t(NOW + 120)).unwrap_err(),
        Rejection::Malformed
    );
    let mut r = resp.clone();
    let wrong = custodian_contracts::types::ProjectionDigest::from_raw([7u8; 32]);
    r.manifest.projections = custodian_contracts::types::BoundedVec::new(vec![wrong]).unwrap();
    let out = c.accept_response(&req, &r, t(NOW + 120)).unwrap();
    assert_eq!(out.rejected, vec![(0, Rejection::ManifestMismatch)]);
    // A service for another destination returns no release for this one.
    let svc = BridgeService {
        catalog: &fx.catalog,
        feed: &fx.feed,
        feed_id: feed_id(),
        destination: DestinationId::parse("site-preview").unwrap(),
    };
    let r = svc.answer(&req.canonical_bytes().unwrap()).unwrap();
    assert!(r.projections.is_empty());
}

#[test]
fn the_service_refuses_bad_requests_and_unavailable_state_with_fixed_reasons() {
    let fx = Fx::new(Opts::default());
    let c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let good = req.canonical_bytes().unwrap();
    let svc = fx.service();

    let mut non_canonical = serde_json::to_vec_pretty(&req).unwrap();
    non_canonical.push(b'\n');
    let mut unknown: Value = serde_json::from_slice(&good).unwrap();
    unknown["extra"] = json!(1);
    let mut wrong_schema: Value = serde_json::from_slice(&good).unwrap();
    wrong_schema["schema"] = json!("private-custodian.bridge-request/2");
    let mut dup: Value = serde_json::from_slice(&good).unwrap();
    dup["populations"] = json!([
        {"kind":"opaque","id": cc::id("ppr_", 1)},
        {"kind":"opaque","id": cc::id("ppr_", 1)}
    ]);
    let mut many: Value = serde_json::from_slice(&good).unwrap();
    many["populations"] = json!((1..=9u32)
        .map(|n| json!({"kind":"opaque","id": cc::id("ppr_", n)}))
        .collect::<Vec<_>>());
    for bad in [
        non_canonical,
        to_canonical_bytes(&unknown).unwrap(),
        to_canonical_bytes(&wrong_schema).unwrap(),
        to_canonical_bytes(&dup).unwrap(),
        to_canonical_bytes(&many).unwrap(),
        vec![b'x'; 5000],
        Vec::new(),
    ] {
        assert_eq!(svc.answer(&bad).unwrap_err(), BridgeReason::RequestInvalid);
    }

    let mut other_feed = req.clone();
    other_feed.feed_id = FeedId::parse(&cc::id("fed_", 2)).unwrap();
    assert_eq!(
        svc.answer(&other_feed.canonical_bytes().unwrap())
            .unwrap_err(),
        BridgeReason::WrongFeed
    );

    fx.catalog.set_unavailable(true);
    assert_eq!(
        svc.answer(&good).unwrap_err(),
        BridgeReason::CatalogUnavailable
    );
    fx.catalog.set_unavailable(false);
    assert!(svc.answer(&good).is_ok());
}

#[test]
fn nothing_private_appears_in_the_request_the_response_or_the_outcome() {
    let fx = Fx::new(Opts {
        canary: true,
        ..Opts::default()
    });
    let mut c = BridgeConsumer::new(fx.pins());
    let req = fx.request(&c);
    let resp = fx.ask(&req).unwrap();
    let out = c.accept_response(&req, &resp, t(NOW + 120)).unwrap();
    assert_eq!(out.accepted.len(), 1);

    let mut wire = resp.manifest.canonical_bytes().unwrap();
    for d in resp.projections.iter().chain(resp.revocations.iter()) {
        wire.extend_from_slice(d);
    }
    let shown = format!("{out:?} {resp:?}");
    let mut forbidden: Vec<String> = all_canaries().into_iter().map(str::to_owned).collect();
    let plan = &fx.w.request.plan;
    forbidden.push(plan.population.population_digest.as_str().to_owned());
    // The configuration digest is in the request only; the answer carries a
    // digest of the request, not the configuration.
    forbidden.push(plan.config_digest.as_str().to_owned());
    forbidden.push(plan.plan_digest().unwrap().as_str().to_owned());
    for (id, what) in [
        (fx.w.request.request_id.as_str(), "request id"),
        (fx.w.execution.execution_id.as_str(), "execution id"),
        (fx.w.exec_approval.approval_id.as_str(), "approval id"),
        (fx.w.reservation.reservation_id.as_str(), "reservation id"),
        (fx.w.receipt.result.digest.as_str(), "result digest"),
    ] {
        forbidden.push(id.to_owned());
        let _ = what;
    }
    for f in forbidden {
        assert!(
            !String::from_utf8_lossy(&wire).contains(&f),
            "wire leaks {f}"
        );
        assert!(!shown.contains(&f), "debug leaks {f}");
    }
    // The request itself holds public identities only.
    let request_text = String::from_utf8(req.canonical_bytes().unwrap()).unwrap();
    for f in all_canaries() {
        assert!(!request_text.contains(f));
    }
}
