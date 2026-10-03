//! The consumer against the real feed publisher (C9) with a real store:
//! contamination and an operator withdrawal are recorded privately, published
//! as signed envelopes, and reach a consumer that holds public keys only. The
//! projections are signed with the test signer; their release path is covered
//! in `roundtrip.rs`.

#[path = "../../custodian-lifecycle/tests/common/mod.rs"]
mod common;

use common::*;
use custodian_bridge::wire::{BridgeManifest, BridgeManifestSchema, BridgeResponse};
use custodian_bridge::{BridgeConsumer, ConsumerPins, Rejection};
use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{EvaluationDomain, PolicyRef};
use custodian_contracts::public::{PublicProjection, PublicProjectionEnvelope};
use custodian_contracts::revocation::{
    PublicRevocationReason, RevocationAction, RevocationTarget, Standing,
};
use custodian_contracts::types::{
    BoundedVec, CandidateDigest, ConfigDigest, DestinationId, ProjectionDigest, Seq,
};
use custodian_contracts::Contract;
use custodian_ledger::{ApprovedPayload, SignDomain, Signer};
use custodian_lifecycle::{FeedSource, NoFault, RevocationSpec};

const DEST: &str = "benchmarks-feed";

fn sign(w: &FeedWorld, p: &PublicProjection) -> Vec<u8> {
    let canonical = p.canonical_bytes().unwrap();
    let digest = p.projection_digest().unwrap();
    let approved = ApprovedPayload::from_wire(
        SignDomain::PublicProjection.tag(),
        &canonical,
        Some(&digest),
    )
    .unwrap();
    let signature = w.key.signer.sign(&approved).unwrap();
    to_canonical_bytes(&PublicProjectionEnvelope {
        payload: p.clone(),
        signature,
    })
    .unwrap()
}

fn pins(w: &FeedWorld) -> ConsumerPins {
    ConsumerPins {
        domain: EvaluationDomain::Credential,
        feed_id: feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
        verifier: w.verifier.clone(),
        accepted_populations: vec![opaque(1), opaque(2)],
        accepted_policies: vec![
            serde_json::from_value::<PolicyRef>(cc::disclosure_policy()).unwrap()
        ],
    }
}

fn response(
    w: &FeedWorld,
    req: &custodian_bridge::BridgeRequest,
    projections: &[Vec<u8>],
    from: u64,
    to: u64,
) -> BridgeResponse {
    let digests: Vec<ProjectionDigest> = projections
        .iter()
        .map(|b| {
            PublicProjectionEnvelope::decode(b)
                .unwrap()
                .payload
                .projection_digest()
                .unwrap()
        })
        .collect();
    let revocations: Vec<Vec<u8>> = (from..=to)
        .filter_map(|s| w.dest.get(&feed_id(), s).unwrap())
        .collect();
    BridgeResponse {
        manifest: BridgeManifest {
            schema: BridgeManifestSchema,
            request_digest: req.digest().unwrap(),
            feed_id: feed_id(),
            destination: DestinationId::parse(DEST).unwrap(),
            projections: BoundedVec::new(digests).unwrap(),
            first_sequence: Seq::new(if revocations.is_empty() { 0 } else { from }).unwrap(),
            last_sequence: Seq::new(if revocations.is_empty() { 0 } else { to }).unwrap(),
        },
        projections: projections.to_vec(),
        revocations,
    }
}

#[test]
fn contamination_and_withdrawal_published_by_the_custodian_reach_a_public_consumer() {
    let w = FeedWorld::new();
    let publisher = w.publisher(&NoFault);
    let svc = service();
    publisher.publish(&svc, ts(NOW + 100)).unwrap();

    let a = projection(1, "candidate-a"); // population 1: contaminated later
    let b = projection(2, "candidate-a"); // population 2: untouched
    let (ab, bb) = (sign(&w, &a), sign(&w, &b));
    let mut c = BridgeConsumer::new(pins(&w));
    let req = c
        .request(
            CandidateDigest::parse(&cc::dg("candidate-a")).unwrap(),
            ConfigDigest::parse(&cc::dg("synthetic-config")).unwrap(),
            vec![],
        )
        .unwrap();

    let first = response(&w, &req, &[ab.clone(), bb.clone()], 1, 1);
    let out = c.accept_response(&req, &first, ts(NOW + 110)).unwrap();
    assert_eq!(out.accepted.len(), 2);
    assert_eq!(out.feed_applied, 1);
    assert!(c.reevaluate(ts(NOW + 120)).is_empty());

    // A private standing change and an operator withdrawal, then the next
    // publication.
    w.contaminate(EPOCH, "k1");
    publisher
        .record_revocation(
            &human(),
            "withdraw-b",
            &RevocationSpec {
                target: RevocationTarget::Projection {
                    projection_id: b.projection_id.clone(),
                },
                action: RevocationAction::Revoked {},
                reason: PublicRevocationReason::ErrorCorrection,
            },
            ts(NOW + 4200),
        )
        .unwrap();
    let report = publisher.publish(&svc, ts(NOW + 4210)).unwrap();
    assert!(report.entries >= 2);

    let req2 = c
        .request(req.candidate.clone(), req.config.clone(), vec![])
        .unwrap();
    assert_eq!(req2.known_sequence.get(), 1);
    let second = response(&w, &req2, &[ab.clone(), bb.clone()], 2, 2);
    let out2 = c.accept_response(&req2, &second, ts(NOW + 4211)).unwrap();
    assert_eq!(out2.feed_error, None);
    assert_eq!(
        out2.rejected,
        vec![(0, Rejection::Revoked), (1, Rejection::Revoked)]
    );
    let lost = c.reevaluate(ts(NOW + 4212));
    assert_eq!(lost.len(), 2);
    assert!(lost.iter().all(|l| l.to == Standing::Revoked));

    // Later renewals do not restore anything, and a consumer that starts
    // from scratch reaches the same conclusion.
    publisher.publish(&svc, ts(NOW + 7500)).unwrap();
    let mut fresh = BridgeConsumer::new(pins(&w));
    let req3 = fresh
        .request(req.candidate.clone(), req.config.clone(), vec![])
        .unwrap();
    let all = response(&w, &req3, &[ab, bb], 1, 3);
    let out3 = fresh.accept_response(&req3, &all, ts(NOW + 7501)).unwrap();
    assert_eq!(out3.feed_applied, 3);
    assert!(out3.accepted.is_empty());
    assert_eq!(out3.rejected.len(), 2);
    assert!(out3.rejected.iter().all(|(_, r)| *r == Rejection::Revoked));

    // Nothing the consumer shows names a corpus, epoch, actor or budget.
    let shown = format!("{out:?} {out2:?} {out3:?} {lost:?}");
    for private in [
        EPOCH, CORPUS, HUMAN, "epo_", "cor_", "act_", "apr_", "budget",
    ] {
        assert!(!shown.contains(private), "{private}");
    }
}

#[test]
fn a_feed_that_goes_quiet_stops_validating_and_a_gap_stops_the_feed() {
    let w = FeedWorld::new();
    let publisher = w.publisher(&NoFault);
    let svc = service();
    publisher.publish(&svc, ts(NOW + 100)).unwrap();
    publisher.publish(&svc, ts(NOW + 4100)).unwrap();
    publisher.publish(&svc, ts(NOW + 8100)).unwrap();
    let a = projection(1, "candidate-a");
    let ab = sign(&w, &a);
    let mut c = BridgeConsumer::new(pins(&w));
    let req = c
        .request(
            CandidateDigest::parse(&cc::dg("candidate-a")).unwrap(),
            ConfigDigest::parse(&cc::dg("synthetic-config")).unwrap(),
            vec![],
        )
        .unwrap();

    // Sequence 2 is missing at the source.
    w.dest.remove(&feed_id(), 2);
    let r = response(&w, &req, std::slice::from_ref(&ab), 1, 3);
    assert_eq!(r.revocations.len(), 2); // 1 and 3
    let out = c.accept_response(&req, &r, ts(NOW + 110)).unwrap();
    assert_eq!(out.feed_applied, 1);
    assert_eq!(out.feed_error, Some(custodian_lifecycle::SyncError::Gap));
    assert_eq!(out.accepted.len(), 1);

    // With only sequence 1 held, a later time finds the feed stale.
    let late = c.reevaluate(ts(NOW + 4000));
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].to, Standing::Stale);
}
