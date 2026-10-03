//! The real eligibility wired into the C8 disclosure service: contamination
//! and revocation versus preparation and publication, historical receipts,
//! and what a consumer then sees (C9). Uses the disclosure crate's synthetic
//! world. Synthetic data only.

#[path = "../../custodian-disclosure/tests/common/mod.rs"]
mod dc;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use custodian_contracts::common::{ActorKind, PolicyRef};
use custodian_contracts::public::{PublicProjection, PublicProjectionEnvelope};
use custodian_contracts::revocation::{
    PublicRevocationReason, RevocationAction, RevocationTarget, Standing,
};
use custodian_contracts::types::{
    ActorRef, ApprovalId, CandidateDigest, DestinationId, ProjectionDigest, Timestamp,
};
use custodian_core::{Contamination, EpochChange};
use custodian_disclosure::ports::EligibilityRefusal;
use custodian_disclosure::testing::RecordingSink;
use custodian_disclosure::{
    verify_release, DisclosureReason as D, EligibilitySubject, ReleaseEligibility, Sink,
};
use custodian_ledger::record::{PublicationBody, PublicationDecision};
use custodian_ledger::{LedgerBackend, LedgerPath, LedgerRecord, SignedLedgerRecord};
use custodian_lifecycle::testing::{FixedActivations, StaticAuthority};
use custodian_lifecycle::{
    FeedConfig, FeedConsumer, FeedPublisher, LifecycleEligibility, MemoryFeed, NoFault,
    PublicPopulations, RevocationSpec,
};
use custodian_store::{EpochEventCommand, SqliteStore, StoreConfig};
use dc::*;
use serde_json::json;

const EPOCH: &str = "epo_synthetic000000000001";
const CORPUS: &str = "cor_synthetic000000000001";

fn ts(secs: u64) -> Timestamp {
    Timestamp::new(secs).unwrap()
}

fn human_ref() -> ActorRef {
    ActorRef::parse("act_synthetichuman000001").unwrap()
}

fn authority() -> StaticAuthority {
    StaticAuthority::new()
        .allow_all("act_synthetichuman000001")
        .allow_all("act_syntheticservice00001")
}

fn operator(kind: ActorKind) -> custodian_lifecycle::OperatorAuthorization {
    custodian_lifecycle::OperatorAuthorization {
        actor: match kind {
            ActorKind::Service => ActorRef::parse("act_syntheticservice00001").unwrap(),
            _ => human_ref(),
        },
        kind,
        authorization: ApprovalId::parse("apr_synthetic000000000009").unwrap(),
    }
}

fn contaminate_on(store: &SqliteStore, key: &str) {
    store
        .apply_epoch_change(&EpochEventCommand {
            epoch_id: EPOCH,
            corpus_id: CORPUS,
            family_id: None,
            idempotency_key: key,
            change: EpochChange::Report(Contamination::Exposed),
            reason: "results_exposed",
            actor: "act_synthetichuman000001",
            actor_kind: "human",
            authorization_ref: "apr_synthetic000000000009",
            now: NOW + 60,
        })
        .unwrap();
}

struct Pops;
impl PublicPopulations for Pops {
    fn public_ref(
        &self,
        epoch: &custodian_contracts::types::EpochId,
    ) -> Option<custodian_contracts::public::PublicPopulationRef> {
        (epoch.as_str() == EPOCH).then(w_population_ref)
    }
}

fn w_population_ref() -> custodian_contracts::public::PublicPopulationRef {
    custodian_contracts::public::PublicPopulationRef::Opaque {
        id: custodian_contracts::types::PublicPopulationId::parse(&cc::id("ppr_", 1)).unwrap(),
    }
}

fn publisher<'a>(
    w: &'a World,
    dest: &'a MemoryFeed,
    authority: &'a StaticAuthority,
) -> FeedPublisher<'a> {
    FeedPublisher {
        store: &w.store,
        populations: &Pops,
        signer: &w.key.signer,
        destination: dest,
        authority,
        config: FeedConfig {
            feed_id: custodian_contracts::types::FeedId::parse(&cc::id("fed_", 1)).unwrap(),
            destination_label: DestinationId::parse("public-feed").unwrap(),
            ttl_secs: 3600,
            renew_margin_secs: 600,
        },
        fault: &NoFault,
    }
}

fn eligibility(w: &World) -> LifecycleEligibility<'_> {
    LifecycleEligibility::new(&w.store).guarding_policy(policy_ref())
}

fn policy_ref() -> PolicyRef {
    serde_json::from_value(disclosure_ref()).unwrap()
}

fn released_projection(bytes: &[u8]) -> PublicProjection {
    PublicProjectionEnvelope::decode(bytes).unwrap().payload
}

fn do_release(
    w: &World,
    elig: &dyn ReleaseEligibility,
    p: &custodian_disclosure::PreparedRelease,
    sink: &dyn Sink,
) -> Result<custodian_disclosure::ReleasedEnvelope, D> {
    let approval = w.release_approval(p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    with_service(w, elig, |svc| {
        svc.release(
            p,
            &w.release_request(&approval, &dest, &obs),
            sink,
            now(RELEASE_AT),
        )
    })
}

fn prepare(
    w: &World,
    elig: &dyn ReleaseEligibility,
    n: u32,
) -> Result<custodian_disclosure::PreparedRelease, D> {
    with_service(w, elig, |svc| {
        w.provision(svc);
        let key = w.release_key(n);
        svc.prepare(&w.input(&key), now(PREPARE_AT))
    })
}

fn has(w: &World, prefix: &str) -> bool {
    w.backend.paths().iter().any(|p| p.starts_with(prefix))
}

#[test]
fn a_clean_epoch_releases_through_the_real_eligibility() {
    let w = World::new(Opts::default());
    let elig = eligibility(&w);
    let p = prepare(&w, &elig, 1).unwrap();
    w.export();
    let sink = RecordingSink::new();
    do_release(&w, &elig, &p, &sink).unwrap();
    assert_eq!(sink.delivered().len(), 1);
}

#[test]
fn a_contaminated_population_is_refused_at_prepare_before_anything_is_charged() {
    let w = World::new(Opts::default());
    let elig = eligibility(&w);
    with_default_service(&w, |svc| w.provision(svc));
    contaminate_on(&w.store, "k1");
    let before = w
        .store
        .release_budget_status(&custodian_store::ReleaseScope::Requester(
            w.request.asserted_actor.as_str(),
        ))
        .unwrap();
    assert_eq!(prepare(&w, &elig, 1).err(), Some(D::EligibilityDenied));
    // Not charged: the requester's budget is untouched.
    assert_eq!(before.as_ref().map(|b| b.consumed), Some(0));
    let after = w
        .store
        .release_budget_status(&custodian_store::ReleaseScope::Requester(
            w.request.asserted_actor.as_str(),
        ))
        .unwrap();
    assert_eq!(before.map(|b| b.consumed), after.map(|b| b.consumed));
    assert!(w.store.disclosure_history("none").unwrap().is_empty());
}

#[test]
fn contamination_between_prepare_and_release_is_refused_before_any_ledger_write() {
    let w = World::new(Opts::default());
    let elig = eligibility(&w);
    let p = prepare(&w, &elig, 1).unwrap();
    w.export();
    contaminate_on(&w.store, "k1");
    let sink = RecordingSink::new();
    assert_eq!(
        do_release(&w, &elig, &p, &sink).err(),
        Some(D::EligibilityDenied)
    );
    assert!(sink.delivered().is_empty());
    assert!(!has(&w, "records/policy/"));
    assert!(!has(&w, "records/publication/"));
}

/// Contaminates the epoch immediately before delegating on the Nth call.
struct Tripwire<'a> {
    inner: &'a dyn ReleaseEligibility,
    store: &'a SqliteStore,
    calls: AtomicU32,
    trip_on: u32,
}

impl ReleaseEligibility for Tripwire<'_> {
    fn check(&self, s: &EligibilitySubject<'_>, now: Timestamp) -> Result<(), EligibilityRefusal> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.trip_on {
            contaminate_on(self.store, "race");
        }
        self.inner.check(s, now)
    }
}

#[test]
fn contamination_just_before_the_last_gate_wins_and_nothing_is_delivered() {
    let w = World::new(Opts::default());
    let real = eligibility(&w);
    let p = prepare(&w, &real, 1).unwrap();
    w.export();
    // The release calls the hook twice: before any ledger write and again
    // immediately before delivery. Contamination lands between the two.
    let trip = Tripwire {
        inner: &real,
        store: &w.store,
        calls: AtomicU32::new(0),
        trip_on: 2,
    };
    let sink = RecordingSink::new();
    assert_eq!(
        do_release(&w, &trip, &p, &sink).err(),
        Some(D::EligibilityDenied)
    );
    assert!(sink.delivered().is_empty());
    // The decision records exist (a decision is not a delivery) but no signed
    // byte left the boundary.
    assert!(has(&w, "records/publication/"));
}

/// Delivers, but commits the contamination first: it lands after the last
/// gate and before the bytes are handed over.
struct ContaminatingSink<'a> {
    store: &'a SqliteStore,
    inner: RecordingSink,
}

impl Sink for ContaminatingSink<'_> {
    fn deliver(&self, r: &custodian_disclosure::ReleasedEnvelope) -> Result<(), D> {
        contaminate_on(self.store, "late");
        self.inner.deliver(r)
    }
}

#[test]
fn contamination_after_the_last_gate_loses_the_race_but_the_feed_still_revokes_what_left() {
    let w = World::new(Opts::default());
    let real = eligibility(&w);
    let p = prepare(&w, &real, 1).unwrap();
    w.export();
    let sink = ContaminatingSink {
        store: &w.store,
        inner: RecordingSink::new(),
    };
    // The release passed its last gate before the contamination committed, so
    // it completes: publication won this race, and the documented consequence
    // follows.
    do_release(&w, &real, &p, &sink).unwrap();
    let bytes = sink.inner.delivered()[0].1.clone();
    let projection = released_projection(&bytes);

    // Until the feed carries it, a consumer holding the pre-contamination
    // feed would still accept the projection. So the first feed envelope is
    // published before the release's feed reference is usable, and the
    // contamination is published as soon as it is recorded.
    let dest = MemoryFeed::new();
    let auth = authority();
    let pubr = publisher(&w, &dest, &auth);
    assert_eq!(
        pubr.publish(&operator(ActorKind::Service), ts(NOW + 120))
            .unwrap()
            .entries,
        1
    );
    let mut consumer = FeedConsumer::new(
        custodian_contracts::types::FeedId::parse(&cc::id("fed_", 1)).unwrap(),
        w.verifier.clone(),
    );
    consumer.sync(&dest).unwrap();
    assert_eq!(
        consumer.standing(&projection, ts(NOW + 121)),
        Standing::Revoked
    );
    // And nothing else of this epoch can leave from now on.
    assert!(eligibility(&w)
        .check(
            &EligibilitySubject {
                candidate: &projection.candidate,
                population: &w.request.plan.population,
                execution: p.execution_id(),
                projection: p.digest(),
            },
            ts(NOW + 121)
        )
        .is_err());
}

#[test]
fn real_threads_racing_release_against_contamination_never_deliver_after_it() {
    let mut delivered_rounds = 0;
    let mut refused_rounds = 0;
    for round in 0..8 {
        let w = World::new(Opts::default());
        let real = eligibility(&w);
        let p = prepare(&w, &real, 1).unwrap();
        w.export();
        let contaminated = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(2));
        let sink = RecordingSink::new();
        let path = w.db.path();
        let result = thread::scope(|s| {
            let (c, b) = (Arc::clone(&contaminated), Arc::clone(&barrier));
            s.spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                b.wait();
                for _ in 0..(round % 4) {
                    thread::yield_now();
                }
                contaminate_on(&store, "race");
                c.store(true, Ordering::SeqCst);
            });
            barrier.wait();
            let after = contaminated.load(Ordering::SeqCst);
            (after, do_release(&w, &real, &p, &sink))
        });
        let (started_after, r) = result;
        match r {
            Ok(_) => {
                assert!(
                    !started_after,
                    "a release that started after the contamination returned was delivered"
                );
                assert_eq!(sink.delivered().len(), 1);
                delivered_rounds += 1;
            }
            Err(D::EligibilityDenied) => {
                assert!(sink.delivered().is_empty());
                refused_rounds += 1;
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
        // Whatever happened, nothing of this epoch can be released now.
        assert_eq!(
            do_release(&w, &real, &p, &RecordingSink::new()).err(),
            Some(D::EligibilityDenied)
        );
    }
    eprintln!("race split: {delivered_rounds} delivered before, {refused_rounds} refused");
}

#[test]
fn historical_receipts_stay_auditable_but_cannot_authorize_revoked_evidence_again() {
    let w = World::new(Opts::default());
    let real = eligibility(&w);
    let p = prepare(&w, &real, 1).unwrap();
    w.export();
    let sink = RecordingSink::new();
    do_release(&w, &real, &p, &sink).unwrap();
    let (dest_label, bytes) = sink.delivered()[0].clone();
    let projection = released_projection(&bytes);

    // The candidate is later revoked by an operator.
    let feed = MemoryFeed::new();
    let auth = authority();
    let pubr = publisher(&w, &feed, &auth);
    pubr.record_revocation(
        &operator(ActorKind::Human),
        "withdrawn",
        &RevocationSpec {
            target: RevocationTarget::Candidate {
                candidate: projection.candidate.clone(),
            },
            action: RevocationAction::Revoked {},
            reason: PublicRevocationReason::ErrorCorrection,
        },
        ts(NOW + 200),
    )
    .unwrap();
    pubr.publish(&operator(ActorKind::Service), ts(NOW + 210))
        .unwrap();

    // Auditable: the signature verifies and the ledgered decision matches the
    // delivered bytes, exactly as before.
    let env = PublicProjectionEnvelope::decode(&bytes).unwrap();
    assert!(w.verifier.verify_projection(&env).is_ok());
    let decision = decision_record(&w, &env, &dest_label);
    let dest = w.destination(&dest_label);
    assert!(verify_release(&bytes, &decision, &dest, &w.verifier).is_ok());

    // A consumer with the feed no longer relies on it.
    let mut consumer = FeedConsumer::new(
        custodian_contracts::types::FeedId::parse(&cc::id("fed_", 1)).unwrap(),
        w.verifier.clone(),
    );
    consumer.sync(&feed).unwrap();
    assert_eq!(
        consumer.standing(&projection, ts(NOW + 211)),
        Standing::Revoked
    );

    // And the custodian cannot re-release it, nor prepare a new release for
    // the revoked candidate: the earlier success is evidence, not permission.
    let again = do_release(&w, &real, &p, &RecordingSink::new());
    assert_eq!(again.err(), Some(D::EligibilityDenied));
    assert_eq!(prepare(&w, &real, 2).err(), Some(D::EligibilityDenied));
    // The ledger still holds the original decision, untouched.
    assert!(has(&w, "records/publication/"));
}

fn decision_record(w: &World, env: &PublicProjectionEnvelope, dest: &str) -> SignedLedgerRecord {
    let p = &env.payload;
    let probe = LedgerRecord::publication(
        PublicationBody {
            projection_id: p.projection_id.clone(),
            receipt_id: p.receipt_id.clone(),
            projection_digest: p.projection_digest().unwrap(),
            signature_key_id: env.signature.key_id.clone(),
            decision: Some(PublicationDecision {
                destination: w.destination(dest),
                disclosure_policy: p.disclosure_policy.clone(),
                execution_id: w.execution.execution_id.clone(),
                approval_id: ApprovalId::parse(&cc::id("apr_", 2)).unwrap(),
                approver: ActorRef::parse(&cc::id("act_", 2)).unwrap(),
                approver_kind: ActorKind::Human,
            }),
        },
        p.issued_at.secs(),
    )
    .unwrap();
    let bytes = w
        .backend
        .get(&LedgerPath::parse(&probe.path()).unwrap())
        .unwrap()
        .expect("decision record is in the ledger");
    SignedLedgerRecord::decode_canonical(&bytes).unwrap()
}

#[test]
fn the_policy_activation_and_unknown_state_gates_fail_closed() {
    let w = World::new(Opts::default());
    let activation_ref = w.policy_binding.clone();
    let subject = |w: &World| {
        let cand: CandidateDigest = w.request.plan.candidate.clone();
        (cand, w.request.plan.population.clone())
    };
    let (cand, pop) = subject(&w);
    let digest = ProjectionDigest::from_raw([0; 32]);
    let exec = w.execution.execution_id.clone();
    let check = |e: &LifecycleEligibility<'_>, at: u64| {
        e.check(
            &EligibilitySubject {
                candidate: &cand,
                population: &pop,
                execution: &exec,
                projection: &digest,
            },
            ts(at),
        )
    };
    // Active and fresh.
    let active = FixedActivations(Some(disclosure_activation(RELEASE_AT, "active")));
    let e = LifecycleEligibility::new(&w.store).requiring_activation(
        activation_ref.clone(),
        &active,
        300,
    );
    assert_eq!(check(&e, RELEASE_AT), Ok(()));
    // Observed too long ago.
    assert_eq!(
        check(&e, RELEASE_AT + 301),
        Err(EligibilityRefusal::Unknown)
    );
    // Revoked or superseded since.
    for status in ["revoked", "superseded"] {
        let src = FixedActivations(Some(disclosure_activation(RELEASE_AT, status)));
        let e = LifecycleEligibility::new(&w.store).requiring_activation(
            activation_ref.clone(),
            &src,
            300,
        );
        assert_eq!(
            check(&e, RELEASE_AT),
            Err(EligibilityRefusal::Revoked),
            "{status}"
        );
    }
    // Unobservable: unknown is not eligible.
    let none = FixedActivations(None);
    let e = LifecycleEligibility::new(&w.store).requiring_activation(activation_ref, &none, 300);
    assert_eq!(check(&e, RELEASE_AT), Err(EligibilityRefusal::Unknown));
}

#[test]
fn a_revoked_policy_or_candidate_or_epoch_each_refuse_and_say_why() {
    let w = World::new(Opts::default());
    let cand = w.request.plan.candidate.clone();
    let pop = w.request.plan.population.clone();
    let digest = ProjectionDigest::from_raw([0; 32]);
    let exec = w.execution.execution_id.clone();
    let ask = |e: &LifecycleEligibility<'_>| {
        e.check(
            &EligibilitySubject {
                candidate: &cand,
                population: &pop,
                execution: &exec,
                projection: &digest,
            },
            ts(RELEASE_AT),
        )
    };
    let e = eligibility(&w);
    assert_eq!(ask(&e), Ok(()));
    let feed = MemoryFeed::new();
    let auth = authority();
    let pubr = publisher(&w, &feed, &auth);
    // A revoked disclosure policy.
    pubr.record_revocation(
        &operator(ActorKind::Human),
        "policy",
        &RevocationSpec {
            target: RevocationTarget::Policy {
                policy: policy_ref(),
            },
            action: RevocationAction::Revoked {},
            reason: PublicRevocationReason::PolicyRevoked,
        },
        ts(NOW + 1),
    )
    .unwrap();
    assert_eq!(ask(&e), Err(EligibilityRefusal::Revoked));
    // A policy this gate does not guard is not affected by it.
    let unguarded = LifecycleEligibility::new(&w.store);
    assert_eq!(ask(&unguarded), Ok(()));
    // A contaminating entry outranks a plain revocation.
    contaminate_on(&w.store, "k1");
    assert_eq!(ask(&e), Err(EligibilityRefusal::Contaminated));
    assert_eq!(ask(&unguarded), Err(EligibilityRefusal::Contaminated));
    // Retired but not contaminated.
    let w2 = World::new(Opts::default());
    w2.store
        .apply_epoch_change(&EpochEventCommand {
            epoch_id: EPOCH,
            corpus_id: CORPUS,
            family_id: None,
            idempotency_key: "r1",
            change: EpochChange::Retire,
            reason: "planned_rotation",
            actor: "act_synthetichuman000001",
            actor_kind: "human",
            authorization_ref: "apr_synthetic000000000009",
            now: NOW + 1,
        })
        .unwrap();
    let e2 = LifecycleEligibility::new(&w2.store);
    assert_eq!(
        e2.check(
            &EligibilitySubject {
                candidate: &cand,
                population: &pop,
                execution: &exec,
                projection: &digest,
            },
            ts(RELEASE_AT)
        ),
        Err(EligibilityRefusal::EpochRetired)
    );
    let _ = json!({});
}
