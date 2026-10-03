//! A synthetic consumer, standing in for benchmarks (C11): it holds only the
//! pinned verification keys and the public feed, and shows freshness,
//! revocation, contamination and the downstream re-evaluation trigger without
//! ever seeing a corpus detail. Product support decisions are the consumer's;
//! the custodian only says what may still be relied on.

mod common;

use common::*;
use custodian_contracts::public::PublicProjection;
use custodian_contracts::revocation::{
    PublicRevocationReason, RevocationAction, RevocationTarget, Standing,
};
use custodian_contracts::types::CandidateDigest;
use custodian_lifecycle::{NoFault, RevocationSpec};
use serde_json::json;

fn proj(n: u32, population: u32, candidate: &str) -> PublicProjection {
    let mut v = cc::projection_json();
    v["projection_id"] = json!(cc::id("prj_", n));
    v["population"] = json!({"kind": "opaque", "id": cc::id("ppr_", population)});
    v["candidate"] = json!(cc::dg(candidate));
    cc::parse(&v)
}

#[test]
fn freshness_revocation_and_contamination_drive_downstream_re_evaluation() {
    let w = FeedWorld::new();
    let p = w.publisher(&NoFault);
    let svc = service();

    // Three released projections the downstream derived support from.
    let a = proj(1, 1, "candidate-a"); // population 1: contaminated later
    let b = proj(2, 2, "candidate-b"); // untouched throughout
    let c = proj(3, 2, "candidate-c"); // its candidate is withdrawn later

    // 1. A fresh feed: everything is usable.
    p.publish(&svc, ts(NOW + 100)).unwrap();
    let mut consumer = w.consumer();
    consumer.sync(&w.dest).unwrap();
    for x in [&a, &b, &c] {
        consumer.track(x.clone(), ts(NOW + 110));
        assert_eq!(consumer.standing(x, ts(NOW + 110)), Standing::Valid);
    }
    assert!(consumer.reevaluate(ts(NOW + 120)).is_empty());

    // 2. The publisher goes quiet. At NOW + 100 + 3600 the feed is stale and a
    // stale feed never validates: the downstream must re-evaluate everything
    // it derived, because it can no longer say nothing was revoked.
    let stale = consumer.reevaluate(ts(NOW + 4000));
    assert_eq!(stale.len(), 3);
    assert!(stale
        .iter()
        .all(|c| c.from == Standing::Valid && c.to == Standing::Stale));

    // 3. Renewal restores freshness. Regaining a standing is not a trigger.
    let renewed = p.publish(&svc, ts(NOW + 4100)).unwrap();
    assert_eq!((renewed.appended, renewed.entries), (Some(2), 0));
    consumer.sync(&w.dest).unwrap();
    assert!(consumer.reevaluate(ts(NOW + 4101)).is_empty());
    assert_eq!(consumer.standing(&b, ts(NOW + 4101)), Standing::Valid);

    // 4. Population 1 is contaminated (private standing change) and one
    // candidate is withdrawn (operator entry). Neither is visible to the
    // consumer until the feed carries it.
    w.contaminate(EPOCH, "k1");
    p.record_revocation(
        &human(),
        "withdraw-c",
        &RevocationSpec {
            target: RevocationTarget::Candidate {
                candidate: CandidateDigest::parse(&cc::dg("candidate-c")).unwrap(),
            },
            action: RevocationAction::Revoked {},
            reason: PublicRevocationReason::ErrorCorrection,
        },
        ts(NOW + 4200),
    )
    .unwrap();
    assert!(consumer.reevaluate(ts(NOW + 4201)).is_empty());
    p.publish(&svc, ts(NOW + 4210)).unwrap();
    consumer.sync(&w.dest).unwrap();
    let changes = consumer.reevaluate(ts(NOW + 4211));
    let mut hit: Vec<_> = changes
        .iter()
        .map(|c| (c.projection.as_str().to_owned(), c.to))
        .collect();
    hit.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(
        hit,
        [
            (cc::id("prj_", 1), Standing::Revoked),
            (cc::id("prj_", 3), Standing::Revoked)
        ]
    );
    assert_eq!(consumer.standing(&b, ts(NOW + 4211)), Standing::Valid);

    // 5. Revocation is not undone by anything later: a projection of the
    // contaminated population released afterwards is revoked too, and the
    // renewals that follow do not clear it.
    let late = proj(9, 1, "candidate-late");
    assert_eq!(consumer.standing(&late, ts(NOW + 4300)), Standing::Revoked);
    p.publish(&svc, ts(NOW + 7500)).unwrap();
    consumer.sync(&w.dest).unwrap();
    assert_eq!(consumer.standing(&a, ts(NOW + 7501)), Standing::Revoked);
    assert_eq!(consumer.standing(&late, ts(NOW + 7501)), Standing::Revoked);

    // 6. Nothing the consumer saw or printed names a corpus, epoch, family,
    // case, budget or actor.
    let shown = format!("{changes:?} {stale:?}");
    for private in [
        EPOCH, CORPUS, HUMAN, "epo_", "cor_", "act_", "apr_", "budget",
    ] {
        assert!(!shown.contains(private), "{private}");
    }
    let mut all = Vec::new();
    for seq in 1..=consumer.sequence() {
        all.push(String::from_utf8(bytes_at(&w, seq)).unwrap());
    }
    for doc in &all {
        for private in [
            EPOCH, CORPUS, HUMAN, "epo_", "cor_", "act_", "apr_", "budget",
        ] {
            assert!(!doc.contains(private), "{private}");
        }
    }
    // A consumer that later joins from scratch reaches the same conclusion.
    let mut fresh = w.consumer();
    fresh.sync(&w.dest).unwrap();
    assert_eq!(fresh.head_digest(), consumer.head_digest());
    assert_eq!(fresh.standing(&a, ts(NOW + 7501)), Standing::Revoked);
    assert_eq!(fresh.standing(&b, ts(NOW + 7501)), Standing::Valid);
}
