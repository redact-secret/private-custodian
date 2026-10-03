//! The public revocation feed end to end: obligations to signed envelopes to
//! a destination to a consumer that has no private access (C9). Real SQLite
//! files, real threads, injected crashes. Synthetic data only.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};

use common::*;
use custodian_contracts::common::ActorKind;
use custodian_contracts::public::PublicProjection;
use custodian_contracts::revocation::{
    PublicRevocationReason, RevocationAction, RevocationTarget, SignedRevocationEnvelope, Standing,
};
use custodian_contracts::types::{CandidateDigest, ProjectionId};
use custodian_core::EpochChange;
use custodian_ledger::{
    ApprovedPayload, ExportStatus, Exporter, MemoryBackend, SignDomain, Signer,
};
use custodian_lifecycle::{
    CrashOnce, DirFeed, FeedConsumer, FeedDestination, FeedSource, LifecyclePoint,
    LifecycleReason as R, NoFault, Observed, PublicPopulations, RevocationSpec, SyncError,
};
use custodian_store::{EpochEventCommand, SqliteStore, StoreConfig};
use serde_json::json;

#[test]
fn a_contamination_reaches_a_consumer_that_has_no_private_access() {
    let w = FeedWorld::new();
    let a = projection(1, "synthetic-candidate");
    let b = projection(2, "synthetic-candidate");
    w.contaminate(EPOCH, "k1");

    let rep = w
        .publisher(&NoFault)
        .publish(&service(), ts(NOW + 100))
        .unwrap();
    assert_eq!(rep.appended, Some(1));
    assert_eq!(rep.entries, 1);
    assert_eq!(rep.delivered, 1);
    assert!(w.store.pending_obligations(10).unwrap().is_empty());

    let mut c = w.consumer();
    // Before it has seen any feed, nothing is usable.
    assert_eq!(c.standing(&a, ts(NOW + 101)), Standing::Stale);
    assert_eq!(c.sync(&w.dest).unwrap().applied, 1);
    assert_eq!(c.standing(&a, ts(NOW + 101)), Standing::Revoked);
    assert_eq!(c.standing(&b, ts(NOW + 101)), Standing::Valid);

    // The document is the public contract and carries no private detail.
    let bytes = bytes_at(&w, 1);
    let env = SignedRevocationEnvelope::decode(&bytes).unwrap();
    assert_eq!(env.payload.sequence.get(), 1);
    assert!(env.payload.previous.is_none());
    let e = &env.payload.entries.as_slice()[0];
    assert!(matches!(e.action, RevocationAction::Contaminated {}));
    assert_eq!(e.reason, PublicRevocationReason::Contamination);
    assert!(matches!(
        &e.target,
        RevocationTarget::Population { population } if *population == opaque(1)
    ));
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in [
        EPOCH, CORPUS, HUMAN, "apr_", "epo_", "cor_", "act_", "req_", "exe_", "budget", "lineage",
        "family", "case", "seed", "path",
    ] {
        assert!(!text.contains(forbidden), "feed leaks {forbidden}");
    }
    // Exactly the contract's keys.
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut top: Vec<_> = v["payload"].as_object().unwrap().keys().cloned().collect();
    top.sort();
    assert_eq!(
        top,
        [
            "entries",
            "feed_id",
            "fresh_until",
            "issued_at",
            "schema",
            "sequence"
        ]
    );
}

#[test]
fn freshness_is_renewed_by_empty_envelopes_and_a_stale_feed_never_validates() {
    let w = FeedWorld::new();
    let a = projection(2, "synthetic-candidate");
    let p = w.publisher(&NoFault);
    // The first call has to start the feed even with nothing to say.
    assert_eq!(
        p.publish(&service(), ts(NOW + 100)).unwrap().appended,
        Some(1)
    );
    // Fresh and nothing pending: no new envelope.
    assert_eq!(p.publish(&service(), ts(NOW + 200)).unwrap().appended, None);
    let mut c = w.consumer();
    c.sync(&w.dest).unwrap();
    assert_eq!(c.standing(&a, ts(NOW + 300)), Standing::Valid);
    // The feed's freshness lapses at NOW + 100 + 3600: stale, never valid.
    assert_eq!(c.standing(&a, ts(NOW + 3701)), Standing::Stale);
    // Renewal before it lapses is an empty envelope that links to the head.
    let rep = p.publish(&service(), ts(NOW + 3200)).unwrap();
    assert_eq!((rep.appended, rep.entries), (Some(2), 0));
    c.sync(&w.dest).unwrap();
    assert_eq!(c.sequence(), 2);
    assert_eq!(c.standing(&a, ts(NOW + 3701)), Standing::Valid);
    // A projection that requires a newer feed than the consumer holds is stale.
    let mut v = cc::projection_json();
    v["population"] = json!({"kind": "opaque", "id": cc::id("ppr_", 2)});
    v["revocation_feed"]["min_sequence"] = json!(3);
    let needs_three: PublicProjection = cc::parse(&v);
    assert_eq!(c.standing(&needs_three, ts(NOW + 3300)), Standing::Stale);
    // A different feed is not evidence about this one.
    let mut other = cc::projection_json();
    other["revocation_feed"]["feed_id"] = json!(cc::id("fed_", 9));
    let other: PublicProjection = cc::parse(&other);
    assert_eq!(c.standing(&other, ts(NOW + 3300)), Standing::Stale);
}

#[test]
fn replayed_forked_gapped_misordered_and_forged_envelopes_are_rejected() {
    let w = FeedWorld::new();
    let p = w.publisher(&NoFault);
    p.publish(&service(), ts(NOW + 100)).unwrap();
    w.contaminate(EPOCH, "k1");
    p.publish(&service(), ts(NOW + 200)).unwrap();
    p.publish(&service(), ts(NOW + 3500)).unwrap();
    let (e1, e2, e3) = (bytes_at(&w, 1), bytes_at(&w, 2), bytes_at(&w, 3));

    let mut c = w.consumer();
    // Out of order: sequence 2 first is a gap, not accepted.
    assert_eq!(c.observe(&e2).unwrap_err(), SyncError::Gap);
    assert_eq!(c.sequence(), 0);
    assert_eq!(c.observe(&e1).unwrap(), Observed::Applied);
    // Replay of an accepted envelope is harmless.
    assert_eq!(c.observe(&e1).unwrap(), Observed::AlreadyApplied);
    assert_eq!(c.observe(&e2).unwrap(), Observed::Applied);
    // A skipped sequence.
    let mut gap = w.consumer();
    gap.observe(&e1).unwrap();
    assert_eq!(gap.observe(&e3).unwrap_err(), SyncError::Gap);

    // A fork: another signed envelope claiming sequence 2.
    let forged_seq2 = {
        let mut v: serde_json::Value = serde_json::from_slice(&e2).unwrap();
        v["payload"]["issued_at"] = json!(NOW + 201);
        v["payload"]["fresh_until"] = json!(NOW + 4000);
        // Re-sign with the real key so only the fork check can catch it.
        resign(&w, &v)
    };
    assert_eq!(c.observe(&forged_seq2).unwrap_err(), SyncError::Fork);
    // An unsigned imitation of an accepted sequence is not an alarm, just a
    // bad signature.
    let mut unsigned: serde_json::Value = serde_json::from_slice(&e2).unwrap();
    unsigned["payload"]["issued_at"] = json!(NOW + 202);
    assert_eq!(
        c.observe(&serde_json::to_vec(&unsigned).unwrap())
            .unwrap_err(),
        SyncError::BadSignature
    );

    // A broken chain: correct sequence, wrong previous digest, valid signature.
    let mut broken = w.consumer();
    broken.observe(&e1).unwrap();
    let bad_link = {
        let mut v: serde_json::Value = serde_json::from_slice(&e2).unwrap();
        v["payload"]["previous"] = json!(cc::dg("not-the-head"));
        resign(&w, &v)
    };
    assert_eq!(
        broken.observe(&bad_link).unwrap_err(),
        SyncError::BrokenChain
    );

    // Bad signature (one flipped payload byte), other feed, non-canonical.
    let mut tampered: serde_json::Value = serde_json::from_slice(&e1).unwrap();
    tampered["payload"]["fresh_until"] = json!(NOW + 999_999);
    let tampered = serde_json::to_vec(&tampered).unwrap();
    assert_eq!(
        w.consumer().observe(&tampered).unwrap_err(),
        SyncError::BadSignature
    );
    let mut other: serde_json::Value = serde_json::from_slice(&e1).unwrap();
    other["payload"]["feed_id"] = json!(cc::id("fed_", 9));
    assert_eq!(
        w.consumer().observe(&resign(&w, &other)).unwrap_err(),
        SyncError::WrongFeed
    );
    let mut spaced = e1.clone();
    spaced.insert(1, b' ');
    assert_eq!(
        w.consumer().observe(&spaced).unwrap_err(),
        SyncError::Malformed
    );
    assert_eq!(
        w.consumer().observe(b"{}").unwrap_err(),
        SyncError::Malformed
    );

    // A key the consumer did not pin.
    let stranger = FeedConsumer::new(feed_id(), verifier_for(&test_key(1, &SignDomain::ALL)));
    let mut stranger = stranger;
    assert_eq!(stranger.observe(&e1).unwrap_err(), SyncError::BadSignature);
    // A pinned key that is not authorized for this document type.
    let narrow = test_key(1, &[SignDomain::PublicProjection]);
    let narrow_verifier = verifier_for(&narrow);
    let mut narrow_c = FeedConsumer::new(feed_id(), narrow_verifier);
    assert_eq!(narrow_c.observe(&e1).unwrap_err(), SyncError::BadSignature);
}

/// Sign an arbitrary (possibly invalid-to-the-chain) payload with the real
/// key, so a test can isolate the consumer check that must catch it.
fn resign(w: &FeedWorld, v: &serde_json::Value) -> Vec<u8> {
    let payload: custodian_contracts::revocation::RevocationEnvelope =
        serde_json::from_value(v["payload"].clone()).unwrap();
    let approved = ApprovedPayload::revocation(&payload).unwrap();
    let signature = w.key.signer.sign(&approved).unwrap();
    custodian_contracts::canonical::to_canonical_bytes(&SignedRevocationEnvelope {
        payload,
        signature,
    })
    .unwrap()
}

#[test]
fn a_gap_in_the_source_is_detected_and_nothing_past_it_is_accepted() {
    let w = FeedWorld::new();
    let p = w.publisher(&NoFault);
    p.publish(&service(), ts(NOW + 100)).unwrap();
    w.contaminate(EPOCH, "k1");
    p.publish(&service(), ts(NOW + 200)).unwrap();
    p.publish(&service(), ts(NOW + 3500)).unwrap();
    w.dest.remove(&feed_id(), 2);
    let mut c = w.consumer();
    assert_eq!(c.sync(&w.dest).unwrap_err(), SyncError::Gap);
    // It holds what it verified before the gap and nothing after.
    assert_eq!(c.sequence(), 1);
    // Restoring the missing envelope from the publisher's durable copy
    // heals it.
    let env = w.store.feed_envelopes(feed_id().as_str(), 2).unwrap();
    w.dest
        .put(&feed_id(), 2, env[0].document.as_bytes())
        .unwrap();
    assert_eq!(c.sync(&w.dest).unwrap().head_sequence, 3);
}

#[test]
fn what_a_crash_leaves_is_finished_by_the_next_publish_exactly_once() {
    for point in [
        LifecyclePoint::BeforeFeedAppend,
        LifecyclePoint::AfterFeedAppend,
        LifecyclePoint::AfterDestinationPut,
    ] {
        let mut w = FeedWorld::new();
        w.contaminate(EPOCH, "k1");
        let crash = CrashOnce::new(point);
        assert_eq!(
            w.publisher(&crash)
                .publish(&service(), ts(NOW + 100))
                .unwrap_err(),
            R::InjectedCrash,
            "{point:?}"
        );
        assert!(crash.fired());
        // Restart: new store connection, same files; the destination object
        // survives (it is not ours).
        w.store = SqliteStore::open(w.db.path()).unwrap();
        let rep = w
            .publisher(&NoFault)
            .publish(&service(), ts(NOW + 110))
            .unwrap();
        assert_eq!(w.dest.sequences(&feed_id()), vec![1], "{point:?}");
        assert_eq!(
            w.store
                .feed_head(feed_id().as_str())
                .unwrap()
                .unwrap()
                .sequence,
            1
        );
        assert!(w.store.pending_obligations(10).unwrap().is_empty());
        let envs = w.store.feed_envelopes(feed_id().as_str(), 1).unwrap();
        assert!(envs.iter().all(|e| e.delivered));
        // The destination holds exactly the durable bytes.
        assert_eq!(bytes_at(&w, 1), envs[0].document.as_bytes());
        // Nothing was lost: the consumer sees the contamination.
        let mut c = w.consumer();
        c.sync(&w.dest).unwrap();
        assert_eq!(
            c.standing(&projection(1, "x"), ts(NOW + 120)),
            Standing::Revoked
        );
        let _ = rep;
        w.store.verify_lifecycle_invariants().unwrap();
    }
}

#[test]
fn a_destination_outage_keeps_the_envelope_durable_and_the_consumer_failing_closed() {
    let w = FeedWorld::new();
    w.contaminate(EPOCH, "k1");
    w.dest.set_unavailable(true);
    assert_eq!(
        w.publisher(&NoFault)
            .publish(&service(), ts(NOW + 100))
            .unwrap_err(),
        R::DestinationUnavailable
    );
    // Durable in the store, not delivered; the consumer has seen nothing, so
    // the contaminated projection is not usable (and neither is any other).
    let envs = w.store.feed_envelopes(feed_id().as_str(), 1).unwrap();
    assert_eq!(envs.len(), 1);
    assert!(!envs[0].delivered);
    let mut c = w.consumer();
    c.sync(&w.dest).unwrap();
    assert!(!c.standing(&projection(1, "x"), ts(NOW + 101)).is_usable());
    assert!(!c.standing(&projection(2, "x"), ts(NOW + 101)).is_usable());
    // Recovery delivers without appending anything new.
    w.dest.set_unavailable(false);
    let rep = w
        .publisher(&NoFault)
        .publish(&service(), ts(NOW + 200))
        .unwrap();
    assert_eq!((rep.appended, rep.delivered), (None, 1));
    c.sync(&w.dest).unwrap();
    assert_eq!(
        c.standing(&projection(1, "x"), ts(NOW + 201)),
        Standing::Revoked
    );
}

#[test]
fn a_destination_holding_different_bytes_is_never_overwritten_or_marked_delivered() {
    let w = FeedWorld::new();
    w.contaminate(EPOCH, "k1");
    w.dest.force(&feed_id(), 1, b"{\"forged\":true}".to_vec());
    assert_eq!(
        w.publisher(&NoFault)
            .publish(&service(), ts(NOW + 100))
            .unwrap_err(),
        R::DestinationConflict
    );
    assert_eq!(bytes_at(&w, 1), b"{\"forged\":true}");
    assert!(!w.store.feed_envelopes(feed_id().as_str(), 1).unwrap()[0].delivered);
    // A consumer refuses the forgery.
    assert_eq!(
        w.consumer().sync(&w.dest).unwrap_err(),
        SyncError::Malformed
    );
}

#[test]
fn concurrent_publishers_produce_one_contiguous_chain_with_each_entry_once() {
    for _ in 0..3 {
        let w = FeedWorld::new();
        const THREADS: usize = 6;
        const ENTRIES: usize = 12;
        let who_ = service();
        for i in 0..ENTRIES {
            let spec = RevocationSpec {
                target: RevocationTarget::Candidate {
                    candidate: CandidateDigest::parse(&cc::dg(&format!("synthetic-{i}"))).unwrap(),
                },
                action: RevocationAction::Revoked {},
                reason: PublicRevocationReason::ErrorCorrection,
            };
            w.publisher(&NoFault)
                .record_revocation(&who_, &format!("rev{i}"), &spec, ts(NOW + 10))
                .unwrap();
        }
        let barrier = std::sync::Barrier::new(THREADS);
        let ok = AtomicU64::new(0);
        std::thread::scope(|s| {
            for t in 0..THREADS {
                let (w, barrier, ok, who_) = (&w, &barrier, &ok, &who_);
                s.spawn(move || {
                    let store = SqliteStore::open_with_config(
                        w.db.path(),
                        StoreConfig::default().with_busy_timeout_ms(60_000),
                    )
                    .unwrap();
                    let p = w.publisher_with(&store, &w.dest, &w.key.signer, &NoFault);
                    barrier.wait();
                    // Distinct issue times so competing envelopes differ.
                    match p.publish(who_, ts(NOW + 100 + t as u64)) {
                        Ok(_) | Err(R::FeedConflict) => {
                            ok.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => panic!("unexpected {e:?}"),
                    }
                });
            }
        });
        assert_eq!(ok.load(Ordering::SeqCst), THREADS as u64);
        // One chain, every obligation in exactly one envelope, all delivered
        // in order, and a consumer accepts the lot.
        assert!(w.store.pending_obligations(100).unwrap().is_empty());
        let envs = w.store.feed_envelopes(feed_id().as_str(), 1).unwrap();
        assert!(!envs.is_empty());
        for (i, e) in envs.iter().enumerate() {
            assert_eq!(e.sequence, (i + 1) as u64);
        }
        let mut entries = 0;
        let mut c = w.consumer();
        w.publisher(&NoFault)
            .deliver_pending(ts(NOW + 200))
            .unwrap();
        c.sync(&w.dest).unwrap();
        for e in &envs {
            let d = SignedRevocationEnvelope::decode(e.document.as_bytes()).unwrap();
            entries += d.payload.entries.len();
        }
        assert_eq!(entries, ENTRIES);
        assert_eq!(c.sequence(), envs.len() as u64);
        for i in 0..ENTRIES {
            let p = projection(2, &format!("synthetic-{i}"));
            assert_eq!(c.standing(&p, ts(NOW + 300)), Standing::Revoked, "{i}");
        }
        assert_eq!(
            c.standing(&projection(2, "unrelated"), ts(NOW + 300)),
            Standing::Valid
        );
        w.store.verify_lifecycle_invariants().unwrap();
        w.store.integrity_check().unwrap();
    }
}

#[test]
fn more_than_one_envelope_of_entries_is_split_in_order() {
    let w = FeedWorld::new();
    let op = service();
    let p = w.publisher(&NoFault);
    for i in 0..130 {
        let spec = RevocationSpec {
            target: RevocationTarget::Candidate {
                candidate: CandidateDigest::parse(&cc::dg(&format!("bulk-{i}"))).unwrap(),
            },
            action: RevocationAction::Revoked {},
            reason: PublicRevocationReason::NewerEvidence,
        };
        p.record_revocation(&op, &format!("bulk{i}"), &spec, ts(NOW + 10))
            .unwrap();
    }
    assert_eq!(p.publish(&op, ts(NOW + 100)).unwrap().entries, 128);
    assert_eq!(p.publish(&op, ts(NOW + 101)).unwrap().entries, 2);
    let mut c = w.consumer();
    assert_eq!(c.sync(&w.dest).unwrap().applied, 2);
    assert_eq!(
        c.standing(&projection(2, "bulk-129"), ts(NOW + 102)),
        Standing::Revoked
    );
}

#[test]
fn operator_entries_are_authorized_validated_idempotent_and_reach_consumers() {
    let w = FeedWorld::new();
    let p = w.publisher(&NoFault);
    let cand = CandidateDigest::parse(&cc::dg("synthetic-candidate")).unwrap();
    let spec = RevocationSpec {
        target: RevocationTarget::Candidate { candidate: cand },
        action: RevocationAction::Revoked {},
        reason: PublicRevocationReason::ErrorCorrection,
    };
    // Agents cannot record or publish.
    assert_eq!(
        p.record_revocation(&agent(), "r1", &spec, ts(NOW))
            .unwrap_err(),
        R::AgentNotPermitted
    );
    assert_eq!(
        p.publish(&agent(), ts(NOW)).unwrap_err(),
        R::AgentNotPermitted
    );
    // A population is revoked by standing changes, not by operator entries.
    let pop_spec = RevocationSpec {
        target: RevocationTarget::Population {
            population: opaque(1),
        },
        action: RevocationAction::Revoked {},
        reason: PublicRevocationReason::ErrorCorrection,
    };
    assert_eq!(
        p.record_revocation(&human(), "r2", &pop_spec, ts(NOW))
            .unwrap_err(),
        R::InvalidInput
    );
    assert!(p.record_revocation(&human(), "r1", &spec, ts(NOW)).unwrap());
    assert!(!p
        .record_revocation(&human(), "r1", &spec, ts(NOW + 1))
        .unwrap());
    let different = RevocationSpec {
        action: RevocationAction::Contaminated {},
        ..spec.clone()
    };
    assert_eq!(
        p.record_revocation(&human(), "r1", &different, ts(NOW + 2))
            .unwrap_err(),
        R::IdempotencyConflict
    );
    // Supersession names the replacing projection.
    let sup = RevocationSpec {
        target: RevocationTarget::Projection {
            projection_id: ProjectionId::parse(&cc::id("prj_", 101)).unwrap(),
        },
        action: RevocationAction::Superseded {
            superseded_by: ProjectionId::parse(&cc::id("prj_", 555)).unwrap(),
        },
        reason: PublicRevocationReason::NewerEvidence,
    };
    p.record_revocation(&human(), "s1", &sup, ts(NOW)).unwrap();
    // A whole disclosure policy version, named by its public reference.
    let policy = RevocationSpec {
        target: RevocationTarget::Policy {
            policy: serde_json::from_value(cc::disclosure_policy()).unwrap(),
        },
        action: RevocationAction::Revoked {},
        reason: PublicRevocationReason::PolicyRevoked,
    };
    p.record_revocation(&human(), "p1", &policy, ts(NOW))
        .unwrap();
    p.publish(&service(), ts(NOW + 100)).unwrap();
    let mut c = w.consumer();
    c.sync(&w.dest).unwrap();
    assert_eq!(
        c.standing(&projection(2, "synthetic-candidate"), ts(NOW + 101)),
        Standing::Revoked
    );
    // Every projection of the revoked policy version is revoked, and a
    // revocation outranks a supersession.
    assert_eq!(
        c.standing(&projection(1, "other"), ts(NOW + 101)),
        Standing::Revoked
    );
    assert_eq!(
        c.standing(&projection(2, "other"), ts(NOW + 101)),
        Standing::Revoked
    );
    let mut other_policy = cc::projection_json();
    other_policy["disclosure_policy"]["version"] = json!(2);
    other_policy["projection_id"] = json!(cc::id("prj_", 101));
    other_policy["candidate"] = json!(cc::dg("other"));
    let other_policy: PublicProjection = cc::parse(&other_policy);
    assert_eq!(
        c.standing(&other_policy, ts(NOW + 101)),
        Standing::Superseded
    );
    other_policy_valid(&c);
}

#[test]
fn a_feed_reference_never_points_at_a_feed_that_misses_a_known_revocation() {
    let w = FeedWorld::new();
    let p = w.publisher(&NoFault);
    assert_eq!(p.feed_ref().unwrap_err(), R::FeedNotInitialized);
    p.publish(&service(), ts(NOW + 100)).unwrap();
    assert_eq!(p.feed_ref().unwrap().min_sequence.get(), 1);
    w.contaminate(EPOCH, "k1");
    assert_eq!(p.feed_ref().unwrap_err(), R::PendingObligations);
    p.publish(&service(), ts(NOW + 110)).unwrap();
    let r = p.feed_ref().unwrap();
    assert_eq!((r.feed_id, r.min_sequence.get()), (feed_id(), 2));
}

#[test]
fn signing_and_time_failures_publish_nothing() {
    let w = FeedWorld::new();
    w.contaminate(EPOCH, "k1");
    // A signer that may not sign revocation envelopes.
    let narrow = test_key(1, &[SignDomain::PublicProjection]);
    let p = w.publisher_with(&w.store, &w.dest, &narrow.signer, &NoFault);
    assert_eq!(
        p.publish(&service(), ts(NOW + 100)).unwrap_err(),
        R::SigningRefused
    );
    // A signer that is down.
    struct Down;
    impl custodian_ledger::SignerTransport for Down {
        fn call(&self, _: &[u8]) -> Result<Vec<u8>, custodian_ledger::SignRefusal> {
            Err(custodian_ledger::SignRefusal::SignerUnavailable)
        }
    }
    let remote = custodian_ledger::RemoteSigner::new(w.key.signer.key_id().clone(), Down);
    let p = w.publisher_with(&w.store, &w.dest, &remote, &NoFault);
    assert_eq!(
        p.publish(&service(), ts(NOW + 100)).unwrap_err(),
        R::SignerUnavailable
    );
    assert!(w.store.feed_head(feed_id().as_str()).unwrap().is_none());
    assert_eq!(w.store.pending_obligations(10).unwrap().len(), 1);
    assert!(w.dest.sequences(&feed_id()).is_empty());
    // The clock may not go backwards relative to the head.
    let p = w.publisher(&NoFault);
    p.publish(&service(), ts(NOW + 5000)).unwrap();
    w.contaminate("epo_synthetic000000000002", "k2");
    assert_eq!(
        p.publish(&service(), ts(NOW + 4000)).unwrap_err(),
        R::ClockSkew
    );
}

#[test]
fn an_obligation_that_cannot_be_made_public_blocks_publication_fail_closed() {
    let w = FeedWorld::new();
    // An epoch the naming object does not know.
    w.contaminate("epo_synthetic000000000099", "k9");
    assert_eq!(
        w.publisher(&NoFault)
            .publish(&service(), ts(NOW + 100))
            .unwrap_err(),
        R::Unpublishable
    );
    assert!(w.dest.sequences(&feed_id()).is_empty());
    assert_eq!(w.store.pending_obligations(10).unwrap().len(), 1);
}

#[test]
fn a_signature_is_bound_to_its_document_type() {
    let w = FeedWorld::new();
    w.contaminate(EPOCH, "k1");
    w.publisher(&NoFault)
        .publish(&service(), ts(NOW + 100))
        .unwrap();
    let env = SignedRevocationEnvelope::decode(&bytes_at(&w, 1)).unwrap();
    assert!(w.verifier.verify_revocation(&env).is_ok());
    let canonical = custodian_contracts::canonical::to_canonical_bytes(&env.payload).unwrap();
    for other in SignDomain::ALL
        .into_iter()
        .filter(|d| *d != SignDomain::RevocationEnvelope)
    {
        assert!(
            w.verifier
                .verify_bytes(other, &canonical, &env.signature, env.payload.issued_at)
                .is_err(),
            "{other:?}"
        );
    }
}

#[test]
fn the_directory_destination_is_create_if_absent_ordered_and_consumable() {
    let w = FeedWorld::new();
    let dir = corpus::Fixture::new();
    let root = dir.tmp.path().join("feed");
    let feed_dir = DirFeed::new(&root);
    w.contaminate(EPOCH, "k1");
    let p = w.publisher_with(&w.store, &feed_dir, &w.key.signer, &NoFault);
    p.publish(&service(), ts(NOW + 100)).unwrap();
    p.publish(&service(), ts(NOW + 3500)).unwrap();
    let names: Vec<_> = std::fs::read_dir(root.join(feed_id().as_str()))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut names = names;
    names.sort();
    assert_eq!(names, ["0000000001.json", "0000000002.json"]);
    // Identical re-put is accepted; different bytes are refused.
    let e1 = feed_dir.get(&feed_id(), 1).unwrap().unwrap();
    assert_eq!(
        feed_dir.put(&feed_id(), 1, &e1).unwrap(),
        custodian_lifecycle::PutOutcome::Identical
    );
    assert_eq!(
        feed_dir.put(&feed_id(), 1, b"{}").unwrap_err(),
        R::DestinationConflict
    );
    assert!(feed_dir.get(&feed_id(), 3).unwrap().is_none());
    let mut c = w.consumer();
    assert_eq!(c.sync(&feed_dir).unwrap().head_sequence, 2);
    assert_eq!(
        c.standing(&projection(1, "x"), ts(NOW + 3600)),
        Standing::Revoked
    );
}

#[test]
fn every_new_audit_event_kind_exports_to_the_private_ledger() {
    let w = FeedWorld::new();
    w.contaminate(EPOCH, "k1");
    w.store
        .apply_epoch_change(&EpochEventCommand {
            epoch_id: EPOCH,
            corpus_id: CORPUS,
            family_id: None,
            idempotency_key: "k2",
            change: EpochChange::Retire,
            reason: "contamination_response",
            actor: HUMAN,
            actor_kind: "human",
            authorization_ref: "apr_synthetic000000000009",
            now: NOW + 51,
        })
        .unwrap();
    w.store
        .record_rotation(&custodian_store::RotationCommand {
            predecessor: EPOCH,
            successor: "epo_synthetic000000000002",
            corpus_id: CORPUS,
            family_id: None,
            actor: HUMAN,
            authorization_ref: "apr_synthetic000000000009",
            now: NOW + 52,
        })
        .unwrap();
    w.publisher(&NoFault)
        .publish(&service(), ts(NOW + 100))
        .unwrap();
    let backend = MemoryBackend::new();
    let exporter = Exporter::new(&backend, &w.key.signer, &w.verifier);
    let report = exporter.export_pending(&w.store, NOW + 200).unwrap();
    assert_eq!(report.status, ExportStatus::Drained);
    let kinds: std::collections::BTreeSet<_> = (1..60)
        .filter_map(|s| w.store.outbox_event(s).unwrap())
        .map(|e| e.kind)
        .collect();
    for k in [
        "epoch.standing",
        "feed.obligation",
        "feed.published",
        "feed.delivered",
        "epoch.rotated",
    ] {
        assert!(kinds.contains(k), "{k}");
    }
    assert!(w.store.outbox_pending(100).unwrap().is_empty());
    // And none of it carried a private value out of its allowlisted keys.
    let _ = ActorKind::Human;
}

#[allow(dead_code)]
fn _assert_traits(p: &dyn PublicPopulations) -> &dyn PublicPopulations {
    p
}

fn other_policy_valid(c: &FeedConsumer) {
    let mut v = cc::projection_json();
    v["disclosure_policy"]["version"] = json!(2);
    v["projection_id"] = json!(cc::id("prj_", 777));
    v["candidate"] = json!(cc::dg("other"));
    let p: PublicProjection = cc::parse(&v);
    assert_eq!(c.standing(&p, ts(NOW + 101)), Standing::Valid);
}
