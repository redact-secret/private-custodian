//! HG-4: retention of the intake queue, delivery claims and submissions
//! (ADR 0117, migration 0006). Synthetic data only.
//!
//! Properties pinned here: only terminal rows go; nothing goes before its
//! minimum age; a decided submission stays while either of its audit events
//! is unacknowledged; budgets and every history table are untouched; the
//! schema refuses the deletes the code must not make; a crash at either
//! commit boundary of a pass leaves a consistent store and the next pass
//! converges; concurrent traffic is not disturbed.

mod common;

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use common::*;
use custodian_contracts::common::ActorKind;
use custodian_contracts::types::ActorRef;
use custodian_core::ActorId;
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{Claim, DeliveryStore, IntakeQueue, QueuedRequest};
use custodian_store::{
    ApproveCommand, FaultInjector, FaultOp, FaultPhase, FaultPoint, ManualClock, RetentionPolicy,
    SqliteStore, StoreConfig, StoreError, SubmissionChannel, SubmissionStatus, SubmitCommand,
};

const DAY: u64 = 86_400;

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

fn requester() -> ActorRef {
    ActorRef::parse(&id("act_", 1)).unwrap()
}

fn open_clocked(db: &TempDb) -> (SqliteStore, Arc<ManualClock>) {
    let clock = clock();
    let store = SqliteStore::open_with_config(db.path(), cfg(&clock)).unwrap();
    (store, clock)
}

fn policy() -> RetentionPolicy {
    RetentionPolicy {
        queue_done_min_age_secs: 2 * DAY,
        claim_min_age_secs: 10 * DAY,
        decided_submission_min_age_secs: 20 * DAY,
        pending_submission_max_age_secs: 5 * DAY,
        batch_limit: 100,
    }
}

fn count(db: &TempDb, table: &str) -> i64 {
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    raw.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn export_all(store: &SqliteStore, now: u64) {
    for e in store.outbox_pending(1000).unwrap() {
        store
            .outbox_ack(e.seq, &format!("ledger:entry-{}", e.seq), now)
            .unwrap();
    }
}

fn submit(store: &SqliteStore, fx: &Fx, now: u64) {
    store
        .submit_request(&SubmitCommand {
            request: &fx.req,
            channel: SubmissionChannel::Cli,
            submitted_by: &requester(),
            now: ts(now),
        })
        .unwrap();
}

fn approve(store: &SqliteStore, fx: &Fx, now: u64) {
    store
        .approve_submission(&ApproveCommand {
            request_id: fx.req.request_id.as_str(),
            approval: &fx.apr,
            now: ts(now),
            max_state_age_secs: MAX_AGE,
            reservation_window_secs: WINDOW,
        })
        .unwrap();
}

fn cancel(store: &SqliteStore, fx: &Fx, now: u64) {
    store
        .cancel_submission(&fx.request_id(), &requester(), ActorKind::Human, ts(now))
        .unwrap();
}

/// Two finished queue items, one still queued, each with its claim.
fn seed_queue(store: &SqliteStore) {
    for n in 1..=3 {
        assert_eq!(store.claim(&uuid(n)).unwrap(), Claim::New);
        store.enqueue(queued(n)).unwrap();
    }
    for _ in 0..2 {
        let l = store.queue_lease("worker", NOW, 60).unwrap().unwrap();
        store.queue_complete(l.seq, l.lease_token, NOW).unwrap();
    }
}

/// Approved (1), cancelled (2) and pending (3) submissions.
fn seed_submissions(store: &SqliteStore) -> [Fx; 3] {
    let fx = [fixture(1), fixture(2), fixture(3)];
    provision(store, &fx[0], 10);
    store
        .record_activation(&fx[0].obs.activation, &actor(), NOW)
        .unwrap();
    for f in &fx {
        submit(store, f, NOW);
    }
    approve(store, &fx[0], NOW);
    cancel(store, &fx[1], NOW);
    fx
}

#[test]
fn the_policy_has_hard_floors_and_the_placeholder_is_valid() {
    assert!(RetentionPolicy::PLACEHOLDER.validate().is_ok());
    assert!(RetentionPolicy::FLOOR.validate().is_ok());
    let f = RetentionPolicy::FLOOR;
    for bad in [
        RetentionPolicy {
            queue_done_min_age_secs: f.queue_done_min_age_secs - 1,
            ..f
        },
        RetentionPolicy {
            claim_min_age_secs: f.claim_min_age_secs - 1,
            ..f
        },
        RetentionPolicy {
            decided_submission_min_age_secs: 0,
            ..f
        },
        RetentionPolicy {
            pending_submission_max_age_secs: 0,
            ..f
        },
        RetentionPolicy {
            batch_limit: 0,
            ..f
        },
        RetentionPolicy {
            batch_limit: 1001,
            ..f
        },
    ] {
        assert_eq!(bad.validate(), Err(StoreError::InvalidInput));
    }
    // A refused policy touches nothing.
    let db = TempDb::new("ret-floor");
    let store = open(&db);
    let bad = RetentionPolicy {
        claim_min_age_secs: 1,
        ..f
    };
    assert_eq!(
        store.run_retention(&bad, &actor(), NOW + 1000 * DAY).err(),
        Some(StoreError::InvalidInput)
    );
}

#[test]
fn finished_queue_items_go_by_age_and_their_claims_stay_until_their_own_age() {
    let db = TempDb::new("ret-queue");
    let (store, _clock) = open_clocked(&db);
    seed_queue(&store);
    let p = policy();

    // Too young: nothing is removed.
    let r = store.run_retention(&p, &actor(), NOW + DAY).unwrap();
    assert_eq!((r.purged_queue, r.purged_claims), (0, 0));

    // Old enough for the queue, not for the claims.
    let r = store.run_retention(&p, &actor(), NOW + 3 * DAY).unwrap();
    assert_eq!((r.purged_queue, r.purged_claims), (2, 0));
    assert_eq!(count(&db, "intake_queue"), 1, "the waiting item stays");
    assert_eq!(count(&db, "intake_deliveries"), 3);
    // Replay protection still works for a purged item.
    assert_eq!(store.claim(&uuid(1)).unwrap(), Claim::Seen);

    // Claims of purged items go once they are old enough; the claim of the
    // item still queued never goes.
    let r = store.run_retention(&p, &actor(), NOW + 11 * DAY).unwrap();
    assert_eq!((r.purged_queue, r.purged_claims), (0, 2));
    assert_eq!(count(&db, "intake_deliveries"), 1);
    let l = store
        .queue_lease("worker", NOW + 11 * DAY, 60)
        .unwrap()
        .unwrap();
    assert_eq!(l.request.delivery, uuid(3));
    let r = store.run_retention(&p, &actor(), NOW + 100 * DAY).unwrap();
    assert_eq!(
        (r.purged_queue, r.purged_claims),
        (0, 0),
        "leased is not done"
    );
    store
        .queue_complete(l.seq, l.lease_token, NOW + 100 * DAY)
        .unwrap();
    store.integrity_check().unwrap();

    // A pass with nothing to do changes nothing and writes no audit event.
    let n = store.latest_checkpoint().unwrap().unwrap().seq;
    store.run_retention(&p, &actor(), NOW + 100 * DAY).unwrap();
    store.run_retention(&p, &actor(), NOW + 100 * DAY).unwrap();
    assert_eq!(store.latest_checkpoint().unwrap().unwrap().seq, n);
}

#[test]
fn decided_submissions_go_only_after_both_audit_events_are_acknowledged() {
    let db = TempDb::new("ret-submissions");
    let (store, _clock) = open_clocked(&db);
    let fx = seed_submissions(&store);
    let before = status(&store, &fx[0]);
    let p = policy();
    let later = NOW + 30 * DAY;

    // Old enough, but the ledger has acknowledged nothing: all kept.
    let r = store.run_retention(&p, &actor(), later).unwrap();
    assert_eq!(r.purged_submissions, 0);
    assert_eq!(r.kept_unacknowledged, 2);
    assert_eq!(count(&db, "submissions"), 3);

    // Acknowledge only the decisions: still kept (the submission events are
    // not acknowledged for the cancelled one).
    for e in store.outbox_pending(1000).unwrap() {
        if e.kind == "request.cancelled" || e.kind == "approval.granted" {
            store.outbox_ack(e.seq, "ledger:entry", later).unwrap();
        }
    }
    let r = store.run_retention(&p, &actor(), later).unwrap();
    assert_eq!(r.purged_submissions, 0);
    assert_eq!(r.kept_unacknowledged, 2);

    export_all(&store, later);
    let r = store.run_retention(&p, &actor(), later).unwrap();
    assert_eq!(r.purged_submissions, 2);
    assert_eq!(r.kept_unacknowledged, 0);
    assert_eq!(
        count(&db, "submissions"),
        1,
        "the just-expired one is too young"
    );

    // Everything the approved submission produced is still there and the
    // budget is exactly what it was.
    assert_eq!(count(&db, "requests"), 1);
    assert_eq!(count(&db, "approvals"), 1);
    assert_eq!(count(&db, "attempts"), 1);
    assert_eq!(count(&db, "reservations"), 1);
    assert_eq!(status(&store, &fx[0]), before);
    assert!(store.submission(&fx[0].request_id()).unwrap().is_none());
    // The purge itself is audited with counts and nothing else.
    let ev = store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "retention.purged")
        .unwrap();
    assert!(ev.payload.contains("\"purged_submissions\":2"));
    store.integrity_check().unwrap();
}

#[test]
fn a_young_decision_is_kept_even_when_fully_acknowledged() {
    let db = TempDb::new("ret-young");
    let (store, _clock) = open_clocked(&db);
    seed_submissions(&store);
    export_all(&store, NOW);
    let r = store
        .run_retention(&policy(), &actor(), NOW + 19 * DAY)
        .unwrap();
    assert_eq!(r.purged_submissions, 0);
    let r = store
        .run_retention(&policy(), &actor(), NOW + 20 * DAY)
        .unwrap();
    assert_eq!(r.purged_submissions, 2);
}

#[test]
fn a_stale_pending_submission_is_cancelled_with_an_audit_then_ages_out() {
    let db = TempDb::new("ret-pending");
    let (store, _clock) = open_clocked(&db);
    let fx = seed_submissions(&store);
    let p = policy();
    let r = store.run_retention(&p, &actor(), NOW + 4 * DAY).unwrap();
    assert_eq!(r.expired_pending, 0);
    let t = NOW + 6 * DAY;
    let r = store.run_retention(&p, &actor(), t).unwrap();
    assert_eq!(r.expired_pending, 1);
    let rec = store.submission(&fx[2].request_id()).unwrap().unwrap();
    assert_eq!(rec.status, SubmissionStatus::Cancelled);
    // It held no budget and charged none; the cancel is audited with its
    // reason like any other cancellation.
    assert_eq!(status(&store, &fx[0]).held, 1);
    let ev = store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "request.cancelled" && e.payload.contains("retention_expired"))
        .expect("audited");
    assert!(ev.payload.contains(&fx[2].request_id()));
    // The expiry is repeatable: nothing more to expire.
    assert_eq!(
        store
            .run_retention(&p, &actor(), t)
            .unwrap()
            .expired_pending,
        0
    );
    // After the decided age and the export it is removed like any other.
    export_all(&store, t);
    let r = store.run_retention(&p, &actor(), t + 21 * DAY).unwrap();
    assert_eq!(r.purged_submissions, 3);
    assert_eq!(count(&db, "submissions"), 0);
    store.integrity_check().unwrap();
}

#[test]
fn the_batch_limit_bounds_one_pass_and_passes_converge() {
    let db = TempDb::new("ret-batch");
    let (store, _clock) = open_clocked(&db);
    for n in 1..=5 {
        assert_eq!(store.claim(&uuid(n)).unwrap(), Claim::New);
        store.enqueue(queued(n)).unwrap();
        let l = store.queue_lease("worker", NOW, 60).unwrap().unwrap();
        store.queue_complete(l.seq, l.lease_token, NOW).unwrap();
    }
    let p = RetentionPolicy {
        batch_limit: 2,
        ..policy()
    };
    let t = NOW + 30 * DAY;
    let mut total = 0;
    for _ in 0..3 {
        total += store.run_retention(&p, &actor(), t).unwrap().purged_queue;
    }
    assert_eq!(total, 5);
    assert_eq!(count(&db, "intake_queue"), 0);
    assert_eq!(count(&db, "intake_deliveries"), 0);
}

#[test]
fn the_schema_refuses_the_deletes_the_code_must_never_make() {
    let db = TempDb::new("ret-guards");
    let (store, _clock) = open_clocked(&db);
    seed_queue(&store);
    let fx = seed_submissions(&store);
    // Unacknowledged: even a finished submission cannot be deleted by hand.
    drop(store);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    let del = |sql: &str| raw.execute(sql, []);
    assert!(del("DELETE FROM submissions").is_err());
    assert!(del("DELETE FROM submissions WHERE status = 'pending'").is_err());
    assert!(del("DELETE FROM intake_queue WHERE state <> 'done'").is_err());
    // A claim whose queue row exists cannot go.
    assert!(del("DELETE FROM intake_deliveries WHERE enqueued = 1").is_err());
    // Budgets, history and the outbox stay append-only.
    for t in [
        "budgets",
        "requests",
        "approvals",
        "attempts",
        "reservations",
        "transitions",
        "settlements",
        "outbox",
        "budget_imports",
        "policy_activations",
    ] {
        if t == "settlements" || t == "budget_imports" {
            continue; // empty here; their guards are covered elsewhere
        }
        assert!(raw.execute(&format!("DELETE FROM {t}"), []).is_err(), "{t}");
    }
    let _ = fx;
    // Finished queue rows are deletable at the schema level (the purge), and
    // that is the only queue delete.
    assert!(del("DELETE FROM intake_queue WHERE state = 'done'").is_ok());
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
fn a_crash_during_a_pass_leaves_a_consistent_store_and_the_next_pass_converges() {
    for (op, phase) in [
        (FaultOp::RetentionExpire, FaultPhase::BeforeCommit),
        (FaultOp::RetentionExpire, FaultPhase::AfterCommit),
        (FaultOp::RetentionPurge, FaultPhase::BeforeCommit),
        (FaultOp::RetentionPurge, FaultPhase::AfterCommit),
    ] {
        let db = TempDb::new("ret-crash");
        let arm = Arc::new(Arm::default());
        let clock = clock();
        let t = NOW + 40 * DAY;
        {
            let store =
                SqliteStore::open_with_config(db.path(), cfg(&clock).with_fault(arm.clone()))
                    .unwrap();
            seed_queue(&store);
            let fx = seed_submissions(&store);
            export_all(&store, NOW);
            let _ = fx;
            *arm.0.lock().unwrap() = Some(FaultPoint { op, phase });
            assert_eq!(
                store.run_retention(&policy(), &actor(), t).err(),
                Some(StoreError::InjectedCrash(FaultPoint { op, phase }))
            );
        }
        // After the crash: reopen, the store is consistent, nothing was half
        // done, and the audit trail matches what happened.
        let store = SqliteStore::open_with_config(db.path(), cfg(&clock)).unwrap();
        store.integrity_check().unwrap();
        let queue_after_crash = count(&db, "intake_queue");
        let purged_by_crashed_pass = matches!(
            (op, phase),
            (FaultOp::RetentionPurge, FaultPhase::AfterCommit)
        );
        assert_eq!(
            queue_after_crash == 1,
            purged_by_crashed_pass,
            "{op:?} {phase:?}"
        );

        // Whatever was left, one more pass finishes the job, and a further
        // pass has nothing to do.
        export_all(&store, t);
        store.run_retention(&policy(), &actor(), t).unwrap();
        export_all(&store, t);
        let later = t + 21 * DAY;
        store.run_retention(&policy(), &actor(), later).unwrap();
        let r = store.run_retention(&policy(), &actor(), later).unwrap();
        assert_eq!(
            (
                r.expired_pending,
                r.purged_queue,
                r.purged_claims,
                r.purged_submissions
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(count(&db, "intake_queue"), 1);
        assert_eq!(count(&db, "intake_deliveries"), 1);
        assert_eq!(count(&db, "submissions"), 0);
        // Retention never touched the spend.
        assert_eq!(count(&db, "reservations"), 1);
        store.integrity_check().unwrap();
    }
}

#[test]
fn retention_runs_alongside_live_intake_without_losing_or_duplicating_work() {
    let db = TempDb::new("ret-conc");
    {
        let (store, _c) = open_clocked(&db);
        seed_queue(&store);
        export_all(&store, NOW);
    }
    let barrier = Arc::new(Barrier::new(4));
    let path = db.path();
    let mut handles = Vec::new();
    // Two purgers, one intake writer, one consumer.
    for _ in 0..2 {
        let (barrier, path) = (Arc::clone(&barrier), path.clone());
        handles.push(thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                path,
                StoreConfig::default().with_busy_timeout_ms(60_000),
            )
            .unwrap();
            barrier.wait();
            let mut n = 0;
            for _ in 0..10 {
                n += store
                    .run_retention(&policy(), &ActorId::new("act_retention"), NOW + 60 * DAY)
                    .unwrap()
                    .purged_queue;
            }
            n
        }));
    }
    {
        let (barrier, path) = (Arc::clone(&barrier), path.clone());
        handles.push(thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                path,
                StoreConfig::default().with_busy_timeout_ms(60_000),
            )
            .unwrap();
            barrier.wait();
            for n in 10..30 {
                store.claim(&uuid(n)).unwrap();
                store.enqueue(queued(n)).unwrap();
            }
            0
        }));
    }
    {
        let (barrier, path) = (Arc::clone(&barrier), path.clone());
        handles.push(thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                path,
                StoreConfig::default().with_busy_timeout_ms(60_000),
            )
            .unwrap();
            barrier.wait();
            for _ in 0..20 {
                if let Some(l) = store.queue_lease("worker", NOW + 60 * DAY, 60).unwrap() {
                    store
                        .queue_complete(l.seq, l.lease_token, NOW + 60 * DAY)
                        .unwrap();
                }
            }
            0
        }));
    }
    let purged: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    // The two items finished before the pass are purged exactly once between
    // the two purgers, whatever else raced.
    assert!(purged >= 2);
    let store = open(&db);
    store.integrity_check().unwrap();
    // Every delivery that was enqueued is either still queued, done, or
    // gone with its claim kept or lapsed: never a queue row without a claim.
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    let orphans: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM intake_queue q WHERE NOT EXISTS \
             (SELECT 1 FROM intake_deliveries d WHERE d.delivery_id = q.delivery_id)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0);
}

#[test]
fn migration_0006_keeps_every_other_guard() {
    // The three replaced guards are the only change: every other table keeps
    // its absolute delete refusal on a freshly migrated store.
    let db = TempDb::new("ret-triggers");
    drop(open(&db));
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    let mut stmt = raw
        .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE '%delete%' ORDER BY name")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for guarded in [
        "intake_queue_delete_guard",
        "intake_deliveries_delete_guard",
        "submissions_delete_guard",
    ] {
        assert!(names.contains(&guarded.to_owned()), "{guarded}");
    }
    for removed in ["intake_queue_no_delete", "submissions_no_delete"] {
        assert!(!names.contains(&removed.to_owned()), "{removed}");
    }
    for kept in [
        "budgets_no_delete",
        "attempts_no_delete",
        "reservations_no_delete",
        "outbox_no_delete",
        "requests_no_delete",
        "approvals_no_delete",
        "transitions_no_delete",
        "settlements_no_delete",
        "intake_removals_no_delete",
        "policy_activations_no_delete",
    ] {
        assert!(names.contains(&kept.to_owned()), "{kept}");
    }
}
