//! C12 revocation races, including the known gap from C9: a contamination
//! recorded after the last release-time eligibility check does not stop that
//! release. These tests pin exactly what is guaranteed and what is not.
//!
//! Synthetic data, test-generated keys, in-process scripted sandbox. A
//! signature attests origin and binding of project-maintained records, never
//! independent truth, and a feed entry says "do not rely on this", never
//! "this was wrong".

mod c12;

use std::sync::atomic::{AtomicU32, Ordering};

use c12::*;
use custodian_bridge::testing::MemoryCatalog;
use custodian_bridge::{BridgeConsumer, BridgeService, ConsumerPins, Rejection};
use custodian_cli::command::Contaminated;
use custodian_cli::Command;
use custodian_contracts::common::EvaluationDomain;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::revocation::Standing;
use custodian_contracts::types::{DestinationId, Timestamp};
use custodian_disclosure::testing::{RecordingSink, StaticNames};
use custodian_disclosure::{
    DisclosureService, EligibilityRefusal, EligibilitySubject, ReleaseEligibility,
};
use custodian_ledger::{Exporter, Keyring, Signer, Verifier};

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

/// Runs the real eligibility, then fires `hook` right after the `at`-th check
/// has returned, modelling a commit that lands just after that check.
struct Hooked<'a> {
    inner: &'a dyn ReleaseEligibility,
    calls: AtomicU32,
    at: u32,
    hook: Box<dyn Fn() + Send + Sync + 'a>,
}

impl ReleaseEligibility for Hooked<'_> {
    fn check(&self, s: &EligibilitySubject<'_>, now: Timestamp) -> Result<(), EligibilityRefusal> {
        let r = self.inner.check(s, now);
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.at {
            (self.hook)();
        }
        r
    }
}

fn pins(p: &Pipe, keys: &[&lc::TestKey]) -> ConsumerPins {
    let mut ring = Keyring::new();
    for k in keys {
        ring = ring.with_root(k.entry.clone());
    }
    ConsumerPins {
        domain: EvaluationDomain::Credential,
        feed_id: lc::feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
        verifier: Verifier::new(ring),
        accepted_populations: vec![lc::opaque(1)],
        accepted_policies: vec![disclosure_policy_ref()],
    }
    .tap(|_| {
        let _ = p;
    })
}

trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&Self)) -> Self {
        f(&self);
        self
    }
}
impl<T> Tap for T {}

struct Staged {
    req: EvaluationRequest,
    asm: Assembled,
}

/// Request 1 run to completion, feed sequence 1 published, audit exported.
fn stage(p: &Pipe, svc: &custodian_cli::Service<'_, custodian_corpus::FsEpochStore>) -> Staged {
    let (req, _) = p.request(1);
    let (attempt, approval_id) = p.reserve(1);
    let rep = p.dispatch(svc, 1, &attempt).unwrap();
    assert!(rep.result.is_some());
    let asm = p.assemble(1, &attempt, &approval_id, &rep);
    p.w.clock.set(NOW + 40);
    assert_eq!(
        code(&p.w.run(Who::Operator, &Command::FeedPublish)),
        "published"
    );
    assert_eq!(code(&p.export()), "exported");
    Staged { req, asm }
}

fn contaminate(p: &Pipe, key: u32) {
    let o = p.w.run(
        Who::Operator,
        &Command::LifecycleReport {
            epoch: p.w.rw.epoch.clone(),
            kind: Contaminated::Exposed,
            reason: "results_exposed".into(),
            key: lc::idk(key),
        },
    );
    assert!(o.is_ok(), "{}", o.render());
}

#[test]
fn contamination_before_or_between_the_release_checks_stops_the_release() {
    // k = 0: before prepare. k = 1: after prepare's check. k = 2: after the
    // first release check. Each refuses with nothing delivered.
    for k in 0..=2u32 {
        let p = Pipe::with_roster();
        let acts = p.activations();
        let svc = p.start(&acts).unwrap();
        let st = stage(&p, &svc);
        let feed = svc.feed_ref().unwrap();
        p.w.clock.set(PREPARE_AT);
        let verifier = Verifier::new(p.w.roots.clone());
        let exporter = Exporter::new(&p.w.ledger, &p.w.key.signer, &verifier);
        let names = StaticNames(lc::opaque(1));
        let hooked = Hooked {
            inner: svc.eligibility(),
            calls: AtomicU32::new(0),
            at: k,
            hook: Box::new(|| contaminate(&p, 1)),
        };
        let d = DisclosureService {
            store: &p.w.rw.store,
            exporter: &exporter,
            signer: &p.w.key.signer,
            eligibility: &hooked,
            names: &names,
        };
        if k == 0 {
            contaminate(&p, 1);
            assert_eq!(
                prepare_on(&d, feed, &st.req, &st.asm, 1, PREPARE_AT).unwrap_err(),
                "eligibility_denied"
            );
            continue;
        }
        let prepared = prepare_on(&d, feed, &st.req, &st.asm, 1, PREPARE_AT);
        if k == 1 {
            // The commit landed right after prepare's own check: prepare
            // itself succeeded, the first release check refuses.
            let prepared = prepared.unwrap();
            assert_eq!(code(&p.export()), "exported");
            p.w.clock.set(RELEASE_AT);
            let sink = RecordingSink::new();
            assert_eq!(
                release_on(
                    &d,
                    &prepared,
                    &release_approval(&prepared),
                    DEST,
                    &sink,
                    RELEASE_AT
                )
                .unwrap_err(),
                "eligibility_denied",
                "k={k}"
            );
            assert!(sink.delivered().is_empty());
        } else {
            let prepared = prepared.unwrap();
            assert_eq!(code(&p.export()), "exported");
            p.w.clock.set(RELEASE_AT);
            let sink = RecordingSink::new();
            assert_eq!(
                release_on(
                    &d,
                    &prepared,
                    &release_approval(&prepared),
                    DEST,
                    &sink,
                    RELEASE_AT
                )
                .unwrap_err(),
                "eligibility_denied",
                "k={k}"
            );
            assert!(sink.delivered().is_empty(), "k={k}: nothing left custody");
        }
    }
}

#[test]
fn contamination_after_the_last_check_releases_but_is_bounded_by_the_next_feed_entry() {
    // KNOWN GAP (register entry HG-1): a contamination that commits after the
    // last eligibility check cannot stop that release, because bytes cannot
    // be un-sent. What is guaranteed, and asserted here:
    //  * the obligation is durable and counts for eligibility at once;
    //  * no new projection can reference a feed that lacks it;
    //  * the next feed envelope revokes the release;
    //  * a consumer that stops syncing stops trusting the release when its
    //    feed head expires.
    let p = Pipe::with_roster();
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let st = stage(&p, &svc);
    let feed = svc.feed_ref().unwrap();
    p.w.clock.set(PREPARE_AT);
    let verifier = Verifier::new(p.w.roots.clone());
    let exporter = Exporter::new(&p.w.ledger, &p.w.key.signer, &verifier);
    let names = StaticNames(lc::opaque(1));
    // prepare = check 1; release = checks 2 and 3. Fire after check 3.
    let hooked = Hooked {
        inner: svc.eligibility(),
        calls: AtomicU32::new(0),
        at: 3,
        hook: Box::new(|| contaminate(&p, 1)),
    };
    let d = DisclosureService {
        store: &p.w.rw.store,
        exporter: &exporter,
        signer: &p.w.key.signer,
        eligibility: &hooked,
        names: &names,
    };
    let prepared = prepare_on(&d, feed.clone(), &st.req, &st.asm, 1, PREPARE_AT).unwrap();
    assert_eq!(code(&p.export()), "exported");
    p.w.clock.set(RELEASE_AT);
    let sink = RecordingSink::new();
    let released = release_on(
        &d,
        &prepared,
        &release_approval(&prepared),
        DEST,
        &sink,
        RELEASE_AT,
    )
    .expect("publication won the race: this is the documented gap");
    assert_eq!(sink.delivered().len(), 1);

    // The obligation is durable and eligibility refuses from now on.
    assert!(p.w.rw.store.pending_obligation_count().unwrap() > 0);
    assert_eq!(
        svc.feed_ref().unwrap_err().code(),
        "pending_obligations",
        "no projection can point at a feed that lacks the revocation"
    );
    assert_eq!(
        prepare_on(&d, feed, &st.req, &st.asm, 2, RELEASE_AT).unwrap_err(),
        "eligibility_denied"
    );

    // A consumer that synced before the contamination still sees Valid ...
    let catalog = MemoryCatalog::new();
    catalog.add(st.req.plan.config_digest.clone(), released);
    let service = BridgeService {
        catalog: &catalog,
        feed: &p.w.feed,
        feed_id: lc::feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
    };
    let mut consumer = BridgeConsumer::new(pins(&p, &[&p.w.key]));
    let ask = |c: &BridgeConsumer| {
        c.request(
            st.req.plan.candidate.clone(),
            st.req.plan.config_digest.clone(),
            vec![],
        )
        .unwrap()
    };
    let breq = ask(&consumer);
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = consumer
        .accept_response(&breq, &resp, ts(RELEASE_AT + 10))
        .unwrap();
    assert_eq!(out.accepted.len(), 1, "{:?}", out.rejected);
    let v = out.accepted[0].clone();
    assert_eq!(consumer.standing(&v, ts(RELEASE_AT + 10)), Standing::Valid);

    // ... until the next feed entry, which the operator publishes at once.
    p.w.clock.set(RELEASE_AT + 20);
    assert_eq!(
        code(&p.w.run(Who::Operator, &Command::FeedPublish)),
        "published"
    );
    assert!(svc.feed_ref().is_ok());
    let breq = ask(&consumer);
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = consumer
        .accept_response(&breq, &resp, ts(RELEASE_AT + 30))
        .unwrap();
    assert_eq!(out.feed_applied, 1);
    assert_eq!(
        consumer.reevaluate(ts(RELEASE_AT + 31))[0].to,
        Standing::Revoked
    );
    assert_eq!(
        consumer.standing(&v, ts(RELEASE_AT + 31)),
        Standing::Revoked
    );
    // Offered again, it is rejected, not re-accepted.
    let out = consumer
        .accept_response(&breq, &resp, ts(RELEASE_AT + 32))
        .unwrap();
    assert_eq!(out.rejected, vec![(0, Rejection::Revoked)]);

    // A consumer that never syncs again cannot be kept valid past the feed
    // head's freshness: the worst case is the feed ttl (3600 s in this config).
    let mut lazy = BridgeConsumer::new(pins(&p, &[&p.w.key]));
    let breq = ask(&lazy);
    let first = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    // It holds only feed sequence 1 (what existed before the contamination).
    let only_one = custodian_bridge::BridgeResponse {
        manifest: first.manifest.clone(),
        projections: first.projections.clone(),
        revocations: vec![first.revocations[0].clone()],
    };
    let out = lazy
        .accept_response(&breq, &only_one, ts(RELEASE_AT + 10))
        .unwrap();
    let v2 = out.accepted[0].clone();
    assert_eq!(lazy.standing(&v2, ts(RELEASE_AT + 10)), Standing::Valid);
    assert_eq!(lazy.standing(&v2, ts(NOW + 40 + 3_601)), Standing::Stale);
}

#[test]
fn rotation_with_a_key_valid_only_from_now_refuses_the_first_release_of_an_older_policy() {
    // Register entry R-6: the policy record of a release carries the time the
    // activation changed. A key valid only from the rotation instant cannot
    // sign it, the exporter self-check refuses, and the release fails closed.
    rotated(NOW - 5, false);
}

#[test]
fn a_release_signed_by_a_rotated_key_needs_the_new_pin_at_the_consumer() {
    // The new key is declared valid from before the oldest record it must sign.
    rotated(NOW - 2_000, true);
}

fn rotated(effective_at: u64, expect_release: bool) {
    use custodian_ledger::record::{KeyAction, KeyEventBody};
    use custodian_ledger::{LedgerRecord, SignDomain};
    let mut p = Pipe::with_roster();
    let old_key = p.w.key.entry.clone();
    // Rotate: publish key 2 under the pinned root, switch, retire key 1 later.
    let next = lc::test_key(2, &SignDomain::ALL);
    {
        let verifier = Verifier::new(p.w.roots.clone());
        let exporter = Exporter::new(&p.w.ledger, &p.w.key.signer, &verifier);
        let rec = LedgerRecord::key_event(
            KeyEventBody {
                key_id: next.signer.key_id().clone(),
                action: KeyAction::Published,
                public_key: Some(next.signer.public_key_hex()),
                purposes: SignDomain::ALL.to_vec(),
                effective_at: ts(effective_at),
            },
            NOW - 5,
        )
        .unwrap();
        exporter.write_record(&rec).unwrap();
    }
    p.w.key = next;
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let st = stage(&p, &svc);
    p.w.clock.set(PREPARE_AT);
    let prepared = prepare(&p, &svc, &st.req, &st.asm, 1, PREPARE_AT).unwrap();
    assert_eq!(code(&p.export()), "exported");
    p.w.clock.set(RELEASE_AT);
    let sink = RecordingSink::new();
    let released = release(
        &p,
        &svc,
        &prepared,
        &release_approval(&prepared),
        DEST,
        &sink,
        RELEASE_AT,
    );
    if !expect_release {
        assert_eq!(released.unwrap_err(), "signing_refused");
        assert!(sink.delivered().is_empty());
        return;
    }
    let released = released.unwrap();
    let catalog = MemoryCatalog::new();
    catalog.add(st.req.plan.config_digest.clone(), released);
    let service = BridgeService {
        catalog: &catalog,
        feed: &p.w.feed,
        feed_id: lc::feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
    };
    let old_only = ConsumerPins {
        verifier: Verifier::new(Keyring::new().with_root(old_key.clone())),
        ..pins(&p, &[&p.w.key])
    };
    let ask = |c: &BridgeConsumer| {
        c.request(
            st.req.plan.candidate.clone(),
            st.req.plan.config_digest.clone(),
            vec![],
        )
        .unwrap()
    };
    // A consumer still pinned to the old key accepts nothing signed by key 2:
    // trust is never taken from the feed or the ledger.
    let mut stale_pin = BridgeConsumer::new(old_only);
    let breq = ask(&stale_pin);
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = stale_pin.accept_response(&breq, &resp, ts(RELEASE_AT + 10));
    let accepted = out.as_ref().map(|o| o.accepted.len()).unwrap_or(0);
    assert_eq!(accepted, 0);
    // Pinning the new public key out of band is what accepts it.
    let mut fresh = BridgeConsumer::new(pins(&p, &[&p.w.key]));
    let breq = ask(&fresh);
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = fresh
        .accept_response(&breq, &resp, ts(RELEASE_AT + 10))
        .unwrap();
    assert_eq!(out.accepted.len(), 1, "{:?}", out.rejected);
}
