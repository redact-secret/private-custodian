//! Queue outcomes, request links and pipeline state (S5, migration 0007).
//!
//! Synthetic data only. These tests show that the daemon's bookkeeping is
//! monotone, write-once where it must be, transactional with its audit event,
//! and never touches a budget.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use custodian_contracts::common::{ActorKind, BudgetKind};
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::types::ActorRef;
use custodian_core::{ReasonCode, RunId};
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{IntakeQueue, QueuedRequest};
use custodian_store::migrations::MIGRATIONS;
use custodian_store::{
    ApproveCommand, ApprovedRun, AssembledRecords, FaultInjector, FaultOp, FaultPhase, FaultPoint,
    PipelineStep, PreparedMark, QueueOutcome, QueueSettle, SqliteStore, StartCommand, StoreConfig,
    StoreError, SubmissionChannel, SubmitCommand,
};

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

fn settle<'a>(outcome: QueueOutcome, reason: &'a str, rid: Option<&'a str>) -> QueueSettle<'a> {
    QueueSettle {
        outcome,
        reason,
        request_id: rid,
        link: None,
    }
}

// ---- queue ------------------------------------------------------------------

#[test]
fn settling_a_leased_item_records_its_fate_link_and_one_audit_event_once() {
    let db = TempDb::new("s5-settle");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let l = store.queue_lease("c1", NOW, 60).unwrap().unwrap();
    let q = queued(1);
    store
        .queue_settle(
            l.seq,
            l.lease_token,
            NOW + 1,
            &QueueSettle {
                outcome: QueueOutcome::Submitted,
                reason: "submitted",
                request_id: Some(&id("req_", 1)),
                link: Some(&q),
            },
        )
        .unwrap();
    assert_eq!(store.queue_depth().unwrap(), 0);
    let o = store.queue_outcome(l.seq).unwrap().unwrap();
    assert_eq!(o.outcome, QueueOutcome::Submitted);
    assert_eq!((o.reason.as_str(), o.attempts), ("submitted", 1));
    let link = store.request_link(&id("req_", 1)).unwrap().unwrap();
    assert_eq!(
        (link.installation_id, link.repository_id, link.pull_request),
        (900_001, 800_001, 7)
    );
    assert_eq!(link.head_sha, "a".repeat(40));
    let events: Vec<_> = store
        .outbox_pending(100)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "queue.settled")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].payload.contains("\"outcome\":\"submitted\""));
    // Idempotent: a repeat records nothing new and succeeds.
    store
        .queue_settle(
            l.seq,
            l.lease_token,
            NOW + 2,
            &settle(QueueOutcome::Denied, "other", None),
        )
        .unwrap();
    assert_eq!(
        store.queue_outcome(l.seq).unwrap().unwrap().outcome,
        QueueOutcome::Submitted
    );
    store.integrity_check().unwrap();
    // Nothing in a budget moved.
    assert!(store
        .budget_status(BudgetKind::Run, &fixture(1).scope())
        .unwrap()
        .is_none());
}

#[test]
fn a_stale_holder_cannot_settle_defer_or_release() {
    let db = TempDb::new("s5-stale");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let first = store.queue_lease("c1", NOW, 10).unwrap().unwrap();
    // The lease lapses and another consumer takes the item.
    let second = store.queue_lease("c2", NOW + 11, 10).unwrap().unwrap();
    assert!(second.lease_token > first.lease_token);
    let s = settle(QueueOutcome::Denied, "x", None);
    assert_eq!(
        store.queue_settle(first.seq, first.lease_token, NOW + 12, &s),
        Err(StoreError::LeaseLost)
    );
    assert_eq!(
        store.queue_defer(first.seq, first.lease_token, NOW + 12, 5),
        Err(StoreError::LeaseLost)
    );
    assert_eq!(
        store.queue_release(first.seq, first.lease_token, NOW + 12),
        Err(StoreError::LeaseLost)
    );
    assert!(store.queue_outcome(first.seq).unwrap().is_none());
    store
        .queue_settle(second.seq, second.lease_token, NOW + 13, &s)
        .unwrap();
}

#[test]
fn defer_is_a_bounded_backoff_and_release_gives_the_item_back_at_once() {
    let db = TempDb::new("s5-defer");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let l = store.queue_lease("c1", NOW, 10).unwrap().unwrap();
    store.queue_defer(l.seq, l.lease_token, NOW, 100).unwrap();
    assert!(store.queue_lease("c2", NOW + 50, 10).unwrap().is_none());
    assert!(store.queue_lease("c2", NOW + 99, 10).unwrap().is_none());
    let again = store.queue_lease("c2", NOW + 100, 10).unwrap().unwrap();
    assert_eq!(again.attempts, 2);
    assert!(again.lease_token > l.lease_token);
    // Out-of-range delays are refused.
    for bad in [0, custodian_store::MAX_DEFER_SECS + 1] {
        assert_eq!(
            store.queue_defer(again.seq, again.lease_token, NOW + 100, bad),
            Err(StoreError::InvalidInput)
        );
    }
    store
        .queue_release(again.seq, again.lease_token, NOW + 101)
        .unwrap();
    // Releasing twice is harmless; the next lease is immediate.
    store
        .queue_release(again.seq, again.lease_token, NOW + 101)
        .unwrap();
    let third = store.queue_lease("c3", NOW + 101, 10).unwrap().unwrap();
    assert_eq!(third.attempts, 3);
    assert!(third.lease_token > again.lease_token);
}

#[test]
fn reasons_are_fixed_words_never_free_text() {
    let db = TempDb::new("s5-words");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let l = store.queue_lease("c1", NOW, 10).unwrap().unwrap();
    for bad in ["", "Has Space", "UPPER", "path/like", &"a".repeat(65)] {
        assert_eq!(
            store.queue_settle(
                l.seq,
                l.lease_token,
                NOW,
                &settle(QueueOutcome::Poisoned, bad, None)
            ),
            Err(StoreError::InvalidInput),
            "{bad:?}"
        );
    }
    assert_eq!(store.queue_depth().unwrap(), 1);
}

#[test]
fn queue_outcomes_and_links_are_append_only() {
    let db = TempDb::new("s5-append-only");
    let store = open(&db);
    store.enqueue(queued(1)).unwrap();
    let l = store.queue_lease("c1", NOW, 10).unwrap().unwrap();
    let q = queued(1);
    store
        .queue_settle(
            l.seq,
            l.lease_token,
            NOW,
            &QueueSettle {
                outcome: QueueOutcome::Submitted,
                reason: "submitted",
                request_id: Some(&id("req_", 1)),
                link: Some(&q),
            },
        )
        .unwrap();
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    for sql in [
        "UPDATE queue_outcomes SET reason = 'x'",
        "DELETE FROM queue_outcomes",
        "UPDATE request_links SET head_sha = 'x'",
        "DELETE FROM request_links",
    ] {
        assert!(raw.execute(sql, []).is_err(), "{sql}");
    }
}

// ---- pipeline ----------------------------------------------------------------

struct Approved {
    fx: Fx,
    run: ApprovedRun,
}

fn approved(db: &TempDb, limit: u64) -> (SqliteStore, Approved) {
    let store = open(db);
    let fx = fixture(1);
    provision(&store, &fx, limit);
    store
        .record_activation(&fx.obs.activation, &actor(), NOW)
        .unwrap();
    store
        .submit_request(&SubmitCommand {
            request: &fx.req,
            channel: SubmissionChannel::App,
            submitted_by: &ActorRef::parse(&id("act_", 1)).unwrap(),
            now: ts(NOW),
        })
        .unwrap();
    let out = store
        .approve_submission(&ApproveCommand {
            request_id: fx.req.request_id.as_str(),
            approval: &fx.apr,
            now: ts(NOW),
            max_state_age_secs: MAX_AGE,
            reservation_window_secs: WINDOW,
        })
        .unwrap();
    let run = ApprovedRun {
        request_id: fx.request_id(),
        attempt: out.reserve.attempt,
        approval_id: fx.apr.approval_id.as_str().to_owned(),
    };
    (store, Approved { fx, run })
}

/// Drive the attempt to `completed` through the same store calls the
/// dispatcher makes.
fn complete(store: &SqliteStore, a: &Approved) {
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &a.run.attempt,
            owner: "w",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&a.fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    store.begin_validation(&lease, &actor(), NOW + 3).unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 4,
        )
        .unwrap();
}

#[test]
fn an_approved_attempt_is_discovered_once_and_enrolled_idempotently() {
    let db = TempDb::new("s5-enroll");
    let (store, a) = approved(&db, 3);
    let found = store.approved_unenrolled(10).unwrap();
    assert_eq!(found, vec![a.run.clone()]);
    assert!(store.pipeline_enroll(&a.run, NOW + 1).unwrap());
    assert!(!store.pipeline_enroll(&a.run, NOW + 2).unwrap());
    assert!(store.approved_unenrolled(10).unwrap().is_empty());
    let r = store.pipeline_run(&a.run.attempt).unwrap().unwrap();
    assert_eq!(r.step, PipelineStep::Enrolled);
    assert_eq!(r.enrolled_at, NOW + 1);
    // An attempt that is not an approved submission's cannot be enrolled.
    let forged = ApprovedRun {
        request_id: a.run.request_id.clone(),
        attempt: RunId::new("att_forged".to_owned()),
        approval_id: a.run.approval_id.clone(),
    };
    assert_eq!(
        store.pipeline_enroll(&forged, NOW),
        Err(StoreError::NotFound)
    );
    let wrong_apr = ApprovedRun {
        approval_id: id("apr_", 99),
        ..a.run.clone()
    };
    assert_eq!(
        store.pipeline_enroll(&wrong_apr, NOW),
        Err(StoreError::NotFound)
    );
    store.integrity_check().unwrap();
}

#[test]
fn the_step_only_moves_forward_and_a_final_run_never_changes() {
    let db = TempDb::new("s5-monotone");
    let (store, a) = approved(&db, 3);
    store.pipeline_enroll(&a.run, NOW).unwrap();
    let at = &a.run.attempt;
    assert!(store
        .pipeline_advance(at, PipelineStep::Dispatched, "dispatched", NOW)
        .unwrap());
    // Same step, same reason: nothing. Same step, new reason: updated.
    assert!(!store
        .pipeline_advance(at, PipelineStep::Dispatched, "dispatched", NOW)
        .unwrap());
    assert!(store
        .pipeline_advance(at, PipelineStep::Dispatched, "waiting", NOW + 1)
        .unwrap());
    // Backwards is a no-op, not an error: a resumed pass may repeat an
    // earlier step.
    assert!(!store
        .pipeline_advance(at, PipelineStep::Enrolled, "enrolled", NOW)
        .unwrap());
    assert_eq!(
        store.pipeline_run(at).unwrap().unwrap().step,
        PipelineStep::Dispatched
    );
    assert!(store
        .pipeline_advance(at, PipelineStep::Closed, "attempt_failed", NOW + 2)
        .unwrap());
    assert!(!store
        .pipeline_advance(at, PipelineStep::Released, "released", NOW + 3)
        .unwrap());
    let r = store.pipeline_run(at).unwrap().unwrap();
    assert_eq!(
        (r.step, r.reason.as_str()),
        (PipelineStep::Closed, "attempt_failed")
    );
    assert!(store.pipeline_open(10).unwrap().is_empty());
    // The trigger holds even against direct SQL.
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw
        .execute("UPDATE pipeline_runs SET step = 'enrolled'", [])
        .is_err());
    assert!(raw.execute("DELETE FROM pipeline_runs", []).is_err());
}

#[test]
fn aggregates_are_written_once_and_only_for_an_enrolled_run() {
    let db = TempDb::new("s5-aggregates");
    let (store, a) = approved(&db, 3);
    let at = &a.run.attempt;
    assert_eq!(
        store.pipeline_store_result(at, "{}", Some(b"{}"), NOW),
        Err(StoreError::NotFound),
        "not enrolled yet"
    );
    store.pipeline_enroll(&a.run, NOW).unwrap();
    store
        .pipeline_store_result(at, "{}", Some(b"first"), NOW)
        .unwrap();
    store
        .pipeline_store_result(at, "{}", Some(b"first"), NOW + 1)
        .unwrap();
    assert_eq!(
        store.pipeline_store_result(at, "{}", Some(b"second"), NOW + 2),
        Err(StoreError::IdentityConflict)
    );
    assert_eq!(
        store.pipeline_store_result(at, "{}", Some(b""), NOW),
        Err(StoreError::InvalidInput)
    );
    assert_eq!(
        store.pipeline_artifacts(at).unwrap().unwrap().aggregates,
        Some(b"first".to_vec())
    );
    // Direct SQL cannot rewrite it either.
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw
        .execute("UPDATE pipeline_artifacts SET aggregates = x'00'", [])
        .is_err());
}

#[test]
fn assembly_stores_the_records_with_one_receipt_event_and_advances_the_run() {
    let db = TempDb::new("s5-assemble");
    let (store, a) = approved(&db, 3);
    let at = &a.run.attempt;
    store.pipeline_enroll(&a.run, NOW).unwrap();
    complete(&store, &a);
    store
        .pipeline_advance(at, PipelineStep::Dispatched, "dispatched", NOW)
        .unwrap();
    let digest = dg("receipt");
    let (xid, plan) = (id("exe_", 1), dg("plan"));
    let rec = AssembledRecords {
        execution: "{\"e\":1}",
        execution_id: &xid,
        receipt: Some(("{\"r\":1}", &digest)),
        plan_digest: &plan,
        close_reason: None,
    };
    store.pipeline_assemble(at, &rec, NOW + 5).unwrap();
    store.pipeline_assemble(at, &rec, NOW + 6).unwrap();
    let r = store.pipeline_run(at).unwrap().unwrap();
    assert_eq!(r.step, PipelineStep::Assembled);
    assert_eq!(r.execution_id.as_deref(), Some(id("exe_", 1).as_str()));
    let art = store.pipeline_artifacts(at).unwrap().unwrap();
    assert_eq!(art.receipt_digest.as_deref(), Some(digest.as_str()));
    let n = store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "receipt.issued")
        .count();
    assert_eq!(n, 1, "one audit event however often it is assembled");
    // Different records for the same run are a conflict, not an overwrite.
    let other = AssembledRecords {
        execution: "{\"e\":2}",
        execution_id: &xid,
        receipt: Some(("{\"r\":1}", &digest)),
        plan_digest: &plan,
        close_reason: None,
    };
    assert_eq!(
        store.pipeline_assemble(at, &other, NOW + 7),
        Err(StoreError::IdentityConflict)
    );
    // A run with no close reason must carry a receipt.
    let bad = AssembledRecords {
        execution: "{\"e\":1}",
        execution_id: &xid,
        receipt: None,
        plan_digest: &plan,
        close_reason: None,
    };
    assert_eq!(
        store.pipeline_assemble(at, &bad, NOW),
        Err(StoreError::InvalidInput)
    );
    store.integrity_check().unwrap();
}

#[test]
fn a_prepared_release_is_marked_once_and_only_from_assembled() {
    let db = TempDb::new("s5-prepared");
    let (store, a) = approved(&db, 3);
    let at = &a.run.attempt;
    store.pipeline_enroll(&a.run, NOW).unwrap();
    let mark = PreparedMark {
        prepared_at: NOW + 50,
        release_key: id("idk_", 100),
        projection_digest: dg("projection"),
    };
    assert_eq!(
        store.pipeline_mark_prepared(at, &mark, "prepared", NOW),
        Err(StoreError::InvalidTransition),
        "not assembled"
    );
    complete(&store, &a);
    store
        .pipeline_assemble(
            at,
            &AssembledRecords {
                execution: "{}",
                execution_id: &id("exe_", 1),
                receipt: Some(("{}", &dg("r"))),
                plan_digest: &dg("p"),
                close_reason: None,
            },
            NOW,
        )
        .unwrap();
    store
        .pipeline_mark_prepared(at, &mark, "awaiting_release_approval", NOW + 51)
        .unwrap();
    store
        .pipeline_mark_prepared(at, &mark, "awaiting_release_approval", NOW + 52)
        .unwrap();
    let different = PreparedMark {
        projection_digest: dg("another"),
        ..mark.clone()
    };
    assert_eq!(
        store.pipeline_mark_prepared(at, &different, "x", NOW + 53),
        Err(StoreError::IdentityConflict)
    );
    let r = store.pipeline_run(at).unwrap().unwrap();
    assert_eq!(r.step, PipelineStep::Prepared);
    assert_eq!(r.prepared, Some(mark));
    store.integrity_check().unwrap();
}

#[test]
fn the_approval_document_is_available_for_assembly() {
    let db = TempDb::new("s5-approval-doc");
    let (store, a) = approved(&db, 3);
    let apr = store
        .approval_document(&a.run.request_id, &a.run.approval_id)
        .unwrap()
        .unwrap();
    assert_eq!(apr.approval_id, a.fx.apr.approval_id);
    assert_eq!(apr.approver_kind, ActorKind::Human);
    assert!(store
        .approval_document(&a.run.request_id, &id("apr_", 77))
        .unwrap()
        .is_none());
}

#[test]
fn none_of_this_touches_a_budget() {
    let db = TempDb::new("s5-budget");
    let (store, a) = approved(&db, 3);
    let before = status(&store, &a.fx);
    store.pipeline_enroll(&a.run, NOW).unwrap();
    store
        .pipeline_store_result(&a.run.attempt, "{}", Some(b"x"), NOW)
        .unwrap();
    store
        .pipeline_advance(&a.run.attempt, PipelineStep::Closed, "attempt_failed", NOW)
        .unwrap();
    store.enqueue(queued(1)).unwrap();
    let l = store.queue_lease("c", NOW, 10).unwrap().unwrap();
    store
        .queue_settle(
            l.seq,
            l.lease_token,
            NOW,
            &settle(QueueOutcome::Poisoned, "poison_message", None),
        )
        .unwrap();
    assert_eq!(status(&store, &a.fx), before);
}

// ---- crash injection -------------------------------------------------------------

/// The bookkeeping calls of one daemon pass, in the daemon's order. Every
/// call is idempotent, so running the script again after a crash converges.
fn script(store: &SqliteStore, run: &ApprovedRun, t: u64) -> Result<(), StoreError> {
    store.pipeline_enroll(run, t)?;
    store.pipeline_store_result(&run.attempt, "{}", Some(b"agg"), t)?;
    store.pipeline_advance(&run.attempt, PipelineStep::Dispatched, "dispatched", t)?;
    if let Some(l) = store.queue_lease("c", t, 60)? {
        store.queue_release(l.seq, l.lease_token, t)?;
    }
    if let Some(l) = store.queue_lease("c", t, 60)? {
        store.queue_settle(
            l.seq,
            l.lease_token,
            t,
            &settle(QueueOutcome::Denied, "denied", None),
        )?;
    }
    Ok(())
}

#[test]
fn crash_injection_at_every_pipeline_boundary_loses_and_duplicates_nothing() {
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        for op in [
            FaultOp::QueueSettle,
            FaultOp::QueueRelease,
            FaultOp::PipelineEnroll,
            FaultOp::PipelineStep,
            FaultOp::PipelineArtifacts,
        ] {
            let db = TempDb::new("s5-crash");
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
            store
                .submit_request(&SubmitCommand {
                    request: &fx.req,
                    channel: SubmissionChannel::App,
                    submitted_by: &ActorRef::parse(&id("act_", 1)).unwrap(),
                    now: ts(NOW),
                })
                .unwrap();
            let out = store
                .approve_submission(&ApproveCommand {
                    request_id: fx.req.request_id.as_str(),
                    approval: &fx.apr,
                    now: ts(NOW),
                    max_state_age_secs: MAX_AGE,
                    reservation_window_secs: WINDOW,
                })
                .unwrap();
            let run = ApprovedRun {
                request_id: fx.request_id(),
                attempt: out.reserve.attempt.clone(),
                approval_id: fx.apr.approval_id.as_str().to_owned(),
            };
            store.enqueue(queued(1)).unwrap();
            let before = status(&store, &fx);

            *arm.0.lock().unwrap() = Some(FaultPoint { op, phase });
            let r = script(&store, &run, NOW + 1);
            assert!(
                matches!(r, Err(StoreError::InjectedCrash(_))),
                "{op:?} {phase:?}: the fault was never reached ({r:?})"
            );
            drop(store);

            // Restart (the leases the crash left have lapsed) and run the
            // whole script again.
            let store = open(&db);
            script(&store, &run, NOW + 1_000).unwrap();
            assert_eq!(store.queue_depth().unwrap(), 0, "{op:?} {phase:?}");
            assert_eq!(
                store.queue_outcomes(10).unwrap().len(),
                1,
                "{op:?} {phase:?}: finished exactly once"
            );
            let settled_events = store
                .outbox_pending(1000)
                .unwrap()
                .into_iter()
                .filter(|e| e.kind == "queue.settled")
                .count();
            assert_eq!(settled_events, 1, "{op:?} {phase:?}");
            let r = store.pipeline_run(&run.attempt).unwrap().unwrap();
            assert_eq!(r.step, PipelineStep::Dispatched, "{op:?} {phase:?}");
            assert_eq!(
                store
                    .pipeline_artifacts(&run.attempt)
                    .unwrap()
                    .unwrap()
                    .aggregates,
                Some(b"agg".to_vec())
            );
            assert_eq!(
                status(&store, &fx),
                before,
                "{op:?} {phase:?}: budget moved"
            );
            store.integrity_check().unwrap();
        }
    }
}

// ---- upgrade ------------------------------------------------------------------------

#[test]
fn a_database_at_version_six_upgrades_and_keeps_its_data() {
    let db = TempDb::new("s5-upgrade");
    let fx = fixture(1);
    let six = &MIGRATIONS[..6];
    {
        let store = SqliteStore::open_with(db.path(), StoreConfig::default(), six).unwrap();
        assert_eq!(store.schema_version().unwrap(), 6);
        provision(&store, &fx, 3);
        reserve(&store, &fx).unwrap();
        store.enqueue(queued(1)).unwrap();
    }
    let store = open(&db);
    assert_eq!(store.schema_version().unwrap(), 8);
    assert_eq!(status(&store, &fx).held, 1);
    assert_eq!(store.queue_depth().unwrap(), 1);
    // The new tables work on the upgraded database.
    let l = store.queue_lease("c", NOW, 10).unwrap().unwrap();
    store
        .queue_settle(
            l.seq,
            l.lease_token,
            NOW,
            &settle(QueueOutcome::Denied, "denied", None),
        )
        .unwrap();
    store.integrity_check().unwrap();
}
