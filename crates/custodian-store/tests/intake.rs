//! Durable intake stores (C10, migration 0004): delivery replay, installation
//! removal, the request queue, submissions and the activation history.
//!
//! Everything here is synthetic. The App-versus-CLI equivalence test shows the
//! property the issue asks for: the same request charges the budget once
//! whichever path reserves it first.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::common::ActorKind;
use custodian_contracts::policy::PolicyActivation;
use custodian_contracts::types::{ActorRef, Timestamp};
use custodian_contracts::Contract;
use custodian_core::{ActorId, RunState};
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{
    Claim, DeliveryStore, InstallationRegistry, IntakeQueue, QueuedRequest,
};
use custodian_intake::IntakeReason;
use custodian_store::{
    ApproveCommand, FaultInjector, FaultOp, FaultPhase, FaultPoint, ManualClock, SqliteStore,
    StoreConfig, StoreError, SubmissionChannel, SubmissionStatus, SubmitCommand, Submitted,
};
use serde_json::json;

fn uuid(n: u64) -> DeliveryId {
    DeliveryId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap()
}

fn queued(n: u64) -> QueuedRequest {
    QueuedRequest {
        delivery: uuid(n),
        installation: InstallationId::new(900_001).unwrap(),
        repository: RepositoryId::new(800_001).unwrap(),
        pull_request: PullRequestNumber::new(7).unwrap(),
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        actor: ActorRef::parse(&id("act_", 1)).unwrap(),
        github_user: GithubUserId::new(700_001).unwrap(),
        received_at: ts(NOW),
    }
}

fn open_clocked(db: &TempDb) -> (SqliteStore, Arc<ManualClock>) {
    let clock = clock();
    let store = SqliteStore::open_with_config(db.path(), cfg(&clock)).unwrap();
    (store, clock)
}

// ---- delivery store -------------------------------------------------------------

#[test]
fn a_delivery_is_claimed_once_and_survives_restart() {
    let db = TempDb::new("c10-claim");
    {
        let store = open(&db);
        assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::New);
        assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
        store.enqueue(queued(1)).unwrap();
    }
    let store = open(&db);
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
    assert_eq!(store.claim(&uuid(2)).unwrap(), Claim::New);
}

#[test]
fn concurrent_claims_of_one_delivery_yield_exactly_one_new() {
    let db = TempDb::new("c10-claim-race");
    drop(open(&db));
    let path = db.path();
    let news = Arc::new(Mutex::new(0u32));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let path = path.clone();
        let news = news.clone();
        handles.push(std::thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                &path,
                StoreConfig::default().with_busy_timeout_ms(20_000),
            )
            .unwrap();
            for _ in 0..5 {
                if store.claim(&uuid(7)).unwrap() == Claim::New {
                    *news.lock().unwrap() += 1;
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(*news.lock().unwrap(), 1);
}

#[test]
fn a_released_claim_can_be_claimed_again_but_an_enqueued_one_cannot() {
    let db = TempDb::new("c10-release");
    let store = open(&db);
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::New);
    store.release(&uuid(1)).unwrap();
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::New);
    store.enqueue(queued(1)).unwrap();
    // The trigger and the guarded delete: an enqueued claim is permanent.
    store.release(&uuid(1)).unwrap();
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw
        .execute(
            "DELETE FROM intake_deliveries WHERE delivery_id = ?1",
            [uuid(1).as_str()]
        )
        .is_err());
}

#[test]
fn a_claim_that_never_produced_a_queue_row_lapses() {
    // Crash between claim and enqueue: the redelivery must not be lost forever.
    let db = TempDb::new("c10-lapse");
    let (store, clock) = open_clocked(&db);
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::New);
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
    clock.advance(custodian_store::CLAIM_WINDOW_SECS - 1);
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
    clock.advance(1);
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::New);
    // Exactly one claimant gets the lapsed claim.
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
}

// ---- installation registry -------------------------------------------------------

#[test]
fn removal_survives_restart_and_cannot_be_undone() {
    let db = TempDb::new("c10-removal");
    let inst = InstallationId::new(900_001).unwrap();
    let repo = RepositoryId::new(800_001).unwrap();
    let other = RepositoryId::new(800_002).unwrap();
    {
        let store = open(&db);
        assert!(!store.installation_removed(inst).unwrap());
        store.mark_repository_removed(inst, repo).unwrap();
    }
    {
        let store = open(&db);
        assert!(store.repository_removed(inst, repo).unwrap());
        assert!(!store.repository_removed(inst, other).unwrap());
        assert!(!store.installation_removed(inst).unwrap());
        store.mark_installation_removed(inst).unwrap();
        store.mark_installation_removed(inst).unwrap(); // idempotent
    }
    let store = open(&db);
    assert!(store.installation_removed(inst).unwrap());
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw.execute("DELETE FROM intake_removals", []).is_err());
    assert!(raw
        .execute("UPDATE intake_removals SET removed_at = 0", [])
        .is_err());
}

// ---- queue -------------------------------------------------------------------------

#[test]
fn queue_is_fifo_for_one_consumer_and_survives_restart() {
    let db = TempDb::new("c10-queue");
    {
        let store = open(&db);
        for n in 1..=3 {
            store.enqueue(queued(n)).unwrap();
        }
        assert_eq!(store.queue_depth().unwrap(), 3);
    }
    let store = open(&db);
    let mut order = Vec::new();
    while let Some(l) = store.queue_lease("worker-a", NOW, 60).unwrap() {
        order.push(l.request.delivery.clone());
        assert_eq!(l.attempts, 1);
        store.queue_complete(l.seq, l.lease_token, NOW).unwrap();
    }
    assert_eq!(order, vec![uuid(1), uuid(2), uuid(3)]);
    assert_eq!(store.queue_depth().unwrap(), 0);
}

#[test]
fn enqueue_is_idempotent_per_delivery() {
    let db = TempDb::new("c10-enqueue-idem");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    store.enqueue(queued(1)).unwrap();
    assert_eq!(store.queue_depth().unwrap(), 1);
}

#[test]
fn a_lapsed_lease_is_delivered_again_and_the_old_holder_is_fenced() {
    let db = TempDb::new("c10-queue-lease");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let first = store.queue_lease("worker-a", NOW, 60).unwrap().unwrap();
    // Nobody else gets it while the lease is live.
    assert!(store
        .queue_lease("worker-b", NOW + 30, 60)
        .unwrap()
        .is_none());
    // At-least-once: after the lease lapses it is leased again.
    let second = store
        .queue_lease("worker-b", NOW + 60, 60)
        .unwrap()
        .unwrap();
    assert_eq!(second.seq, first.seq);
    assert_eq!(second.attempts, 2);
    assert!(second.lease_token > first.lease_token);
    assert_eq!(
        store.queue_complete(first.seq, first.lease_token, NOW + 61),
        Err(StoreError::LeaseLost)
    );
    store
        .queue_complete(second.seq, second.lease_token, NOW + 61)
        .unwrap();
    // Completion is idempotent, so a retried acknowledgement is harmless.
    store
        .queue_complete(second.seq, second.lease_token, NOW + 62)
        .unwrap();
    store
        .queue_complete(first.seq, first.lease_token, NOW + 63)
        .unwrap();
    assert!(store
        .queue_lease("worker-c", NOW + 500, 60)
        .unwrap()
        .is_none());
}

#[test]
fn a_consumer_that_crashes_before_completing_causes_redelivery_not_loss() {
    let db = TempDb::new("c10-queue-crash");
    {
        let store = open(&db);
        store.enqueue(queued(1)).unwrap();
        let _ = store.queue_lease("worker-a", NOW, 60).unwrap().unwrap();
        // process dies here
    }
    let store = open(&db);
    let again = store
        .queue_lease("worker-b", NOW + 61, 60)
        .unwrap()
        .unwrap();
    assert_eq!(again.request.delivery, uuid(1));
    assert_eq!(again.attempts, 2);
}

#[test]
fn queue_content_is_identifiers_only() {
    let db = TempDb::new("c10-queue-cols");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    let mut stmt = raw.prepare("PRAGMA table_info(intake_queue)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for forbidden in [
        "title", "body", "branch", "label", "comment", "ref", "path", "login",
    ] {
        assert!(cols.iter().all(|c| !c.contains(forbidden)), "{forbidden}");
    }
}

#[derive(Default)]
struct Arm(Mutex<Option<FaultPoint>>);
impl FaultInjector for Arm {
    fn crash_at(&self, point: FaultPoint) -> bool {
        let mut g = self.0.lock().unwrap();
        if *g == Some(point) {
            *g = None;
            true
        } else {
            false
        }
    }
}

#[test]
fn crash_injection_at_every_intake_boundary_loses_and_duplicates_nothing() {
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        for op in [FaultOp::IntakeClaim, FaultOp::IntakeEnqueue] {
            let db = TempDb::new("c10-intake-crash");
            let arm = Arc::new(Arm::default());
            let store = SqliteStore::open_with_config(
                db.path(),
                StoreConfig::default().with_fault(arm.clone()),
            )
            .unwrap();
            *arm.0.lock().unwrap() = Some(FaultPoint { op, phase });
            let claim = store.claim(&uuid(1));
            let enq = if op == FaultOp::IntakeEnqueue {
                store.enqueue(queued(1))
            } else {
                Ok(())
            };
            assert!(claim.is_err() || enq.is_err());
            drop(store);
            // Restart, then the redelivery path: claim (maybe Seen if the
            // claim committed and has not lapsed), enqueue, drain.
            let store = open(&db);
            let _ = store.claim(&uuid(1));
            store.enqueue(queued(1)).unwrap();
            store.enqueue(queued(1)).unwrap();
            assert_eq!(store.queue_depth().unwrap(), 1, "{op:?} {phase:?}");
            assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);
            store.integrity_check().unwrap();
        }
    }
}

#[test]
fn a_full_queue_refuses_and_never_evicts() {
    let db = TempDb::new("c10-queue-full");
    let store = open(&db);
    // Fill through SQL for speed; the bound is the store's constant.
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        let tx = raw.unchecked_transaction().unwrap();
        for n in 0..custodian_store::MAX_PENDING_QUEUE {
            tx.execute(
                "INSERT INTO intake_queue (delivery_id, installation_id, repository_id, \
                 pull_request, head_sha, actor, github_user, received_at, state, updated_at) \
                 VALUES (?1, 1, 1, 1, ?2, ?3, 1, 1, 'queued', 1)",
                (
                    format!("00000000-0000-4000-8000-{n:012x}"),
                    "a".repeat(40),
                    id("act_", 1),
                ),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        store.enqueue(queued(999_999)),
        Err(IntakeReason::QueueUnavailable)
    );
    assert_eq!(
        store.queue_depth().unwrap(),
        u64::try_from(custodian_store::MAX_PENDING_QUEUE).unwrap()
    );
}

#[test]
fn a_store_awaiting_reconcile_refuses_intake_writes_but_not_reads() {
    let db = TempDb::new("c10-reconcile-block");
    let store = open(&db);
    store.claim(&uuid(1)).unwrap();
    store.enqueue(queued(1)).unwrap();
    store
        .verify_external_checkpoint(&custodian_store::Checkpoint {
            seq: 99,
            chain: "x".repeat(64),
        })
        .unwrap_err();
    assert_eq!(store.claim(&uuid(2)), Err(IntakeReason::StoreUnavailable));
    assert!(store.enqueue(queued(2)).is_err());
    assert!(store
        .installation_removed(InstallationId::new(1).unwrap())
        .is_ok());
}

// ---- submissions -----------------------------------------------------------------

fn requester() -> ActorRef {
    ActorRef::parse(&id("act_", 1)).unwrap()
}

fn setup(db: &TempDb, limit: u64) -> (SqliteStore, Fx) {
    let store = open(db);
    let fx = fixture(1);
    provision(&store, &fx, limit);
    store
        .record_activation(&fx.obs.activation, &actor(), NOW)
        .unwrap();
    (store, fx)
}

fn submit(store: &SqliteStore, fx: &Fx) -> Result<Submitted, StoreError> {
    store.submit_request(&SubmitCommand {
        request: &fx.req,
        channel: SubmissionChannel::Cli,
        submitted_by: &requester(),
        now: ts(NOW),
    })
}

fn approve(store: &SqliteStore, fx: &Fx) -> Result<custodian_store::ApproveOutcome, StoreError> {
    approve_with(store, fx, &fx.apr, NOW)
}

fn approve_with(
    store: &SqliteStore,
    fx: &Fx,
    apr: &Approval,
    now: u64,
) -> Result<custodian_store::ApproveOutcome, StoreError> {
    store.approve_submission(&ApproveCommand {
        request_id: fx.req.request_id.as_str(),
        approval: apr,
        now: ts(now),
        max_state_age_secs: MAX_AGE,
        reservation_window_secs: WINDOW,
    })
}

fn approval_variant(fx: &Fx, edit: impl FnOnce(&mut serde_json::Value)) -> Approval {
    let mut v = serde_json::to_value(&fx.apr).unwrap();
    edit(&mut v);
    Approval::decode(&serde_json::to_vec(&v).unwrap()).unwrap()
}

#[test]
fn submit_then_approve_reserves_once_and_audits_the_approval() {
    let db = TempDb::new("c10-approve");
    let (store, fx) = setup(&db, 2);
    assert_eq!(submit(&store, &fx).unwrap(), Submitted::New);
    // A submission holds no budget.
    assert_eq!(status(&store, &fx).held, 0);
    let out = approve(&store, &fx).unwrap();
    assert_eq!(out.reserve.state, RunState::Reserved);
    assert!(!out.reserve.replay);
    assert_eq!(status(&store, &fx).held, 1);
    let rec = store.submission(&fx.request_id()).unwrap().unwrap();
    assert_eq!(rec.status, SubmissionStatus::Approved);
    assert_eq!(rec.decided_by.as_deref(), Some(id("act_", 2).as_str()));
    assert_eq!(
        rec.attempt_id.as_deref(),
        Some(out.reserve.attempt.as_str())
    );
    let kinds: Vec<String> = store
        .outbox_pending(100)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    for k in [
        "request.submitted",
        "approval.granted",
        "reservation.created",
    ] {
        assert!(kinds.iter().any(|x| x == k), "{k} in {kinds:?}");
    }
    store.integrity_check().unwrap();
}

#[test]
fn a_repeat_approval_is_refused_and_charges_nothing() {
    let db = TempDb::new("c10-repeat");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    approve(&store, &fx).unwrap();
    let before = store.outbox_pending(1000).unwrap().len();
    for _ in 0..3 {
        assert_eq!(approve(&store, &fx).err(), Some(StoreError::AlreadyDecided));
    }
    assert_eq!(status(&store, &fx).held, 1);
    assert_eq!(store.outbox_pending(1000).unwrap().len(), before);
}

#[test]
fn self_approval_is_refused_by_the_store_itself() {
    let db = TempDb::new("c10-self");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    let own = approval_variant(&fx, |v| {
        v["approver"] = json!(id("act_", 1));
        v["role_separation"] = json!("single_operator_procedural");
    });
    assert_eq!(
        approve_with(&store, &fx, &own, NOW).err(),
        Some(StoreError::SelfApproval)
    );
    assert_eq!(status(&store, &fx).held, 0);
    assert_eq!(
        store.submission(&fx.request_id()).unwrap().unwrap().status,
        SubmissionStatus::Pending
    );
}

#[test]
fn an_agent_approver_cannot_even_be_constructed_and_the_database_refuses_one() {
    let db = TempDb::new("c10-agent");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    let mut v = serde_json::to_value(&fx.apr).unwrap();
    v["approver_kind"] = json!("agent");
    assert!(Approval::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    // Defence in depth: the table refuses an agent decision whatever the code.
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw
        .execute(
            "UPDATE submissions SET status='approved', decided_by='x', decided_kind='agent', \
             decided_at=1, approval_id='a', attempt_id='b'",
            []
        )
        .is_err());
    assert!(raw
        .execute(
            "UPDATE submissions SET status='approved', decided_by=requester, decided_kind='human', \
             decided_at=1, approval_id='a', attempt_id='b'",
            []
        )
        .is_err());
}

#[test]
fn a_stale_or_revoked_policy_activation_fails_the_approval() {
    let db = TempDb::new("c10-stale");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    // The approval binds sequence 3; a newer sequence supersedes the binding.
    let mut v = serde_json::to_value(&fx.obs.activation).unwrap();
    v["sequence"] = json!(4);
    let newer = PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    store.record_activation(&newer, &actor(), NOW).unwrap();
    assert!(matches!(
        approve(&store, &fx).err(),
        Some(StoreError::Binding(_))
    ));
    assert_eq!(status(&store, &fx).held, 0);
    // Revocation fails closed as well.
    v["sequence"] = json!(5);
    v["status"] = json!("revoked");
    let revoked = PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    store.record_activation(&revoked, &actor(), NOW).unwrap();
    assert!(matches!(
        approve(&store, &fx).err(),
        Some(StoreError::Binding(_))
    ));
}

#[test]
fn a_missing_activation_or_an_expired_approval_fails() {
    let db = TempDb::new("c10-noact");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 5);
    submit(&store, &fx).unwrap();
    // No activation recorded: the policy cannot be observed.
    assert!(matches!(
        approve(&store, &fx).err(),
        Some(StoreError::Binding(_))
    ));
    store
        .record_activation(&fx.obs.activation, &actor(), NOW)
        .unwrap();
    assert!(matches!(
        approve_with(&store, &fx, &fx.apr, NOW + 7200).err(),
        Some(StoreError::Binding(_))
    ));
    assert_eq!(status(&store, &fx).held, 0);
}

#[test]
fn an_exhausted_budget_is_a_recorded_denial_not_a_free_run() {
    let db = TempDb::new("c10-exhausted");
    let store = open(&db);
    let fx1 = fixture(1);
    provision(&store, &fx1, 1);
    store
        .record_activation(&fx1.obs.activation, &actor(), NOW)
        .unwrap();
    submit(&store, &fx1).unwrap();
    assert_eq!(
        approve(&store, &fx1).unwrap().reserve.state,
        RunState::Reserved
    );
    // A second request against the same one-unit budget.
    let fx2 = fixture(2);
    submit(&store, &fx2).unwrap();
    let out = approve(&store, &fx2).unwrap();
    assert_eq!(out.reserve.state, RunState::Denied);
    assert_eq!(status(&store, &fx2).held, 1);
    assert_eq!(status(&store, &fx2).limit, 1);
    store.integrity_check().unwrap();
}

#[test]
fn the_same_request_charges_once_whichever_path_reserves_first() {
    // Contract path (what the GitHub gate hands to the store) first.
    let db = TempDb::new("c10-equiv-app-first");
    let (store, fx) = setup(&db, 5);
    let app = store.reserve_request(&fx.cmd()).unwrap();
    assert!(!app.replay);
    assert_eq!(
        submit(&store, &fx).unwrap(),
        Submitted::ReservedElsewhere {
            attempt: app.attempt.clone(),
            state: RunState::Reserved
        }
    );
    assert_eq!(status(&store, &fx).held, 1);
    assert_eq!(store.submission(&fx.request_id()).unwrap(), None);

    // Operator path first, then the contract path replays.
    let db2 = TempDb::new("c10-equiv-cli-first");
    let (store2, fx2) = setup(&db2, 5);
    submit(&store2, &fx2).unwrap();
    let cli = approve(&store2, &fx2).unwrap();
    let replay = store2.reserve_request(&fx2.cmd()).unwrap();
    assert!(replay.replay);
    assert_eq!(replay.attempt, cli.reserve.attempt);
    assert_eq!(status(&store2, &fx2).held, 1);
}

#[test]
fn a_submission_for_an_already_reserved_key_cannot_be_approved_again() {
    let db = TempDb::new("c10-equiv-race");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    // The App path reserves the same request while the submission waits.
    store.reserve_request(&fx.cmd()).unwrap();
    assert_eq!(approve(&store, &fx).err(), Some(StoreError::AlreadyDecided));
    assert_eq!(status(&store, &fx).held, 1);
}

#[test]
fn the_same_key_with_a_different_request_is_a_conflict() {
    let db = TempDb::new("c10-idem-conflict");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    assert_eq!(
        submit(&store, &fx).unwrap(),
        Submitted::Replay(SubmissionStatus::Pending)
    );
    let other = fixture_with(1, Scope::Population, 1, 0, "synthetic-different-candidate");
    assert_ne!(other.req.plan.candidate, fx.req.plan.candidate);
    assert_eq!(
        submit(&store, &other).err(),
        Some(StoreError::IdempotencyConflict)
    );
}

#[test]
fn concurrent_approvals_of_one_submission_charge_once() {
    let db = TempDb::new("c10-approve-race");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    drop(store);
    let fx = Arc::new(fx);
    let path = db.path();
    let wins = Arc::new(Mutex::new(0u32));
    let mut handles = Vec::new();
    for _ in 0..6 {
        let (fx, path, wins) = (fx.clone(), path.clone(), wins.clone());
        handles.push(std::thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                &path,
                StoreConfig::default().with_busy_timeout_ms(20_000),
            )
            .unwrap();
            if approve(&store, &fx).is_ok() {
                *wins.lock().unwrap() += 1;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(*wins.lock().unwrap(), 1);
    let store = open(&db);
    assert_eq!(status(&store, &fx).held, 1);
    store.integrity_check().unwrap();
}

#[test]
fn crash_during_approval_is_all_or_nothing() {
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        let db = TempDb::new("c10-approve-crash");
        let arm = Arc::new(Arm::default());
        let store = SqliteStore::open_with_config(
            db.path(),
            StoreConfig::default().with_fault(arm.clone()),
        )
        .unwrap();
        let fx = fixture(1);
        provision(&store, &fx, 3);
        store
            .record_activation(&fx.obs.activation, &actor(), NOW)
            .unwrap();
        submit(&store, &fx).unwrap();
        *arm.0.lock().unwrap() = Some(FaultPoint {
            op: FaultOp::ApproveSubmission,
            phase,
        });
        assert!(matches!(
            approve(&store, &fx),
            Err(StoreError::InjectedCrash(_))
        ));
        drop(store);
        let store = open(&db);
        let held = status(&store, &fx).held;
        let sub = store.submission(&fx.request_id()).unwrap().unwrap().status;
        match phase {
            FaultPhase::BeforeCommit => {
                assert_eq!((held, sub), (0, SubmissionStatus::Pending));
                // Retrying after the crash succeeds exactly once.
                approve(&store, &fx).unwrap();
            }
            FaultPhase::AfterCommit => {
                assert_eq!((held, sub), (1, SubmissionStatus::Approved));
                assert_eq!(approve(&store, &fx).err(), Some(StoreError::AlreadyDecided));
            }
        }
        assert_eq!(status(&store, &fx).held, 1);
        store.integrity_check().unwrap();
    }
}

#[test]
fn cancel_before_approval_is_final_and_idempotent() {
    let db = TempDb::new("c10-cancel");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    for _ in 0..2 {
        assert_eq!(
            store
                .cancel_submission(&fx.request_id(), &requester(), ActorKind::Human, ts(NOW))
                .unwrap(),
            SubmissionStatus::Cancelled
        );
    }
    assert_eq!(approve(&store, &fx).err(), Some(StoreError::AlreadyDecided));
    assert_eq!(status(&store, &fx).held, 0);
    store.integrity_check().unwrap();
}

#[test]
fn a_blocked_epoch_takes_no_new_submission() {
    let db = TempDb::new("c10-epoch");
    let (store, fx) = setup(&db, 5);
    store
        .apply_epoch_change(&custodian_store::EpochEventCommand {
            epoch_id: &id("epo_", 1),
            corpus_id: &id("cor_", 1),
            family_id: None,
            idempotency_key: "c10-epoch-block",
            change: custodian_core::EpochChange::Report(custodian_core::Contamination::Exposed),
            reason: "results_exposed",
            actor: "act_syntheticoperator0001",
            actor_kind: "human",
            authorization_ref: "apr_synthetic000000000009",
            now: NOW,
        })
        .unwrap();
    assert_eq!(submit(&store, &fx).err(), Some(StoreError::EpochBlocked));
    assert_eq!(store.submission(&fx.request_id()).unwrap(), None);
}

#[test]
fn submissions_and_approvals_are_refused_while_the_store_awaits_reconcile() {
    let db = TempDb::new("c10-sub-reconcile");
    let (store, fx) = setup(&db, 5);
    submit(&store, &fx).unwrap();
    store
        .verify_external_checkpoint(&custodian_store::Checkpoint {
            seq: 999,
            chain: "x".repeat(64),
        })
        .unwrap_err();
    assert_eq!(approve(&store, &fx).err(), Some(StoreError::NeedsReconcile));
    assert_eq!(status(&store, &fx).held, 0);
    store
        .clear_reconcile(&ActorId::new("act_syntheticoperator0001"), NOW)
        .unwrap();
    approve(&store, &fx).unwrap();
}

// ---- activations --------------------------------------------------------------------

#[test]
fn activation_history_is_append_only_and_monotonic() {
    let db = TempDb::new("c10-activation");
    let store = open(&db);
    let act = observed(NOW, "active").activation;
    assert!(store.record_activation(&act, &actor(), NOW).unwrap());
    // Replay of identical bytes is harmless.
    assert!(!store.record_activation(&act, &actor(), NOW).unwrap());
    // The same sequence with other bytes, or a lower one, is refused.
    let mut v = serde_json::to_value(&act).unwrap();
    v["status"] = json!("revoked");
    let same_seq = PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(
        store.record_activation(&same_seq, &actor(), NOW).err(),
        Some(StoreError::IdentityConflict)
    );
    v["sequence"] = json!(2);
    let lower = PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(
        store.record_activation(&lower, &actor(), NOW).err(),
        Some(StoreError::IdentityConflict)
    );
    v["sequence"] = json!(4);
    let higher = PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(store.record_activation(&higher, &actor(), NOW).unwrap());
    assert_eq!(
        store
            .latest_activation(act.activation_id.as_str())
            .unwrap()
            .unwrap()
            .sequence
            .get(),
        4
    );
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw
        .execute("UPDATE policy_activations SET status = 'active'", [])
        .is_err());
    assert!(raw.execute("DELETE FROM policy_activations", []).is_err());
    let kinds: Vec<String> = store
        .outbox_pending(10)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        kinds.iter().filter(|k| *k == "activation.recorded").count(),
        2
    );
}

#[test]
fn an_observation_is_stamped_with_the_time_of_the_read() {
    let db = TempDb::new("c10-observe");
    let (store, fx) = setup(&db, 1);
    let o = store
        .observe_activation(&fx.apr.activation, Timestamp::new(NOW + 5).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(o.observed_at.secs(), NOW + 5);
    assert!(store
        .observe_activation(
            &custodian_contracts::common::ActivationRef {
                activation_id: custodian_contracts::types::ActivationId::parse(&id("pac_", 9))
                    .unwrap(),
                ..fx.apr.activation.clone()
            },
            ts(NOW)
        )
        .unwrap()
        .is_none());
    let _ = Contract::validate(&fx.obs.activation);
}

#[test]
fn the_number_of_waiting_submissions_is_bounded() {
    let db = TempDb::new("c10-sub-limit");
    let (store, fx) = setup(&db, 5);
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        let tx = raw.unchecked_transaction().unwrap();
        for n in 0..custodian_store::MAX_PENDING_SUBMISSIONS {
            tx.execute(
                "INSERT INTO submissions (request_id, idempotency_key, request_digest, \
                 plan_digest, document, requester, submitted_by, channel, submitted_at, status) \
                 VALUES (?1, ?2, 'd', 'p', '{}', 'r', 'r', 'cli', 1, 'pending')",
                (format!("req_filler{n}"), format!("idk_filler{n}")),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(submit(&store, &fx).err(), Some(StoreError::Constraint));
    assert_eq!(store.submission(&fx.request_id()).unwrap(), None);
    // A cancelled filler frees a slot.
    store
        .cancel_submission("req_filler0", &requester(), ActorKind::Human, ts(NOW))
        .unwrap();
    assert_eq!(submit(&store, &fx).unwrap(), Submitted::New);
}
