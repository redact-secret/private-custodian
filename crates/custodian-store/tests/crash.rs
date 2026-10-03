//! Crash injection at every state boundary.
//!
//! A crash is simulated at the two boundaries of each mutating transaction:
//! just before commit (the operation leaves no trace) and just after commit
//! (durable, but the caller never learns of it). After each crash the store is
//! dropped and the database file reopened, as after a process restart. Each
//! test then asserts: no lost settlement, no double charge, no implicit
//! refund, and that the accounting and audit invariants hold.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_core::{Exposure, ReasonCode, RunId, RunState};
use custodian_store::{
    AckOutcome, FaultInjector, FaultOp, FaultPhase, FaultPoint, Lease, ReserveOutcome,
    RetryCommand, SqliteStore, StartCommand, StoreConfig, StoreError,
};

/// Injector armed on demand for exactly one boundary.
#[derive(Default)]
struct Arm(Mutex<Option<FaultPoint>>);

impl Arm {
    fn arm(&self, op: FaultOp, phase: FaultPhase) {
        *self.0.lock().unwrap() = Some(FaultPoint { op, phase });
    }
    fn fired(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }
}

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

fn open_armed(db: &TempDb, arm: &Arc<Arm>) -> SqliteStore {
    SqliteStore::open_with_config(db.path(), StoreConfig::default().with_fault(arm.clone()))
        .unwrap()
}

const PHASES: [FaultPhase; 2] = [FaultPhase::BeforeCommit, FaultPhase::AfterCommit];

/// The lifecycle script. `c` steps are durable after the crash:
/// 0 reserve, 1 start, 2 exposure, 3 validation, 4 finish, 5 ack.
const STEPS: [FaultOp; 6] = [
    FaultOp::Reserve,
    FaultOp::Start,
    FaultOp::RecordExposure,
    FaultOp::BeginValidation,
    FaultOp::Finish,
    FaultOp::OutboxAck,
];

struct Run {
    outcome: Option<ReserveOutcome>,
    lease: Option<Lease>,
}

fn step(store: &SqliteStore, fx: &Fx, run: &mut Run, i: usize) -> Result<(), StoreError> {
    match i {
        0 => run.outcome = Some(reserve(store, fx)?),
        1 => {
            let o = run.outcome.as_ref().unwrap();
            run.lease = Some(store.start_attempt(&StartCommand {
                attempt: &o.attempt,
                owner: "worker-a",
                actor: &actor(),
                now: NOW + 1,
                lease_secs: LEASE,
                observed: Some(&fx.obs),
                max_state_age_secs: MAX_AGE,
            })?);
        }
        2 => store.record_exposure(run.lease.as_ref().unwrap(), &actor(), NOW + 2)?,
        3 => store.begin_validation(run.lease.as_ref().unwrap(), &actor(), NOW + 3)?,
        4 => {
            store.finish(
                run.lease.as_ref().unwrap(),
                ExecutionOutcome::Success,
                ReasonCode::Completed,
                &actor(),
                NOW + 4,
            )?;
        }
        5 => {
            let ev = terminal_event(store).ok_or(StoreError::NotFound)?;
            store.outbox_ack(ev, "ledger:entry-1", NOW + 5)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Sequence of the first terminal audit event, acknowledged or not.
fn terminal_event(store: &SqliteStore) -> Option<u64> {
    (1..100).find(|seq| {
        store
            .outbox_event(*seq)
            .unwrap()
            .is_some_and(|e| e.kind == "attempt.terminal")
    })
}

fn is_crash(e: &StoreError, op: FaultOp, phase: FaultPhase) -> bool {
    *e == StoreError::InjectedCrash(FaultPoint { op, phase })
}

#[test]
fn crash_at_every_boundary_recovers_without_loss_double_charge_or_refund() {
    for (i, op) in STEPS.iter().copied().enumerate() {
        for phase in PHASES {
            let label = format!("{op:?}/{phase:?}");
            let db = TempDb::new("crash");
            let fx = fixture(1);
            let arm = Arc::new(Arm::default());
            let store = open_armed(&db, &arm);
            provision(&store, &fx, 3);

            let mut run = Run {
                outcome: None,
                lease: None,
            };
            for j in 0..i {
                step(&store, &fx, &mut run, j).unwrap();
            }
            arm.arm(op, phase);
            let err = step(&store, &fx, &mut run, i).unwrap_err();
            assert!(is_crash(&err, op, phase), "{label}: {err:?}");
            assert!(arm.fired());
            drop(store); // process restart

            // Durable steps: those before i, plus step i if it crashed after commit.
            let committed = i + usize::from(phase == FaultPhase::AfterCommit);

            let store = open(&db);
            store
                .integrity_check()
                .unwrap_or_else(|e| panic!("{label}: {e:?}"));

            // A client redelivering the request neither double charges nor re-executes.
            let again = reserve(&store, &fx).unwrap();
            if committed >= 1 {
                assert!(again.replay, "{label}: reserve must replay");
            }
            let st = status(&store, &fx);
            assert!(st.held + st.consumed <= 1, "{label}: double charge {st:?}");

            // Restart recovery long after every lease.
            store.recover(&actor(), NOW + 100_000).unwrap();
            store
                .integrity_check()
                .unwrap_or_else(|e| panic!("{label}: {e:?}"));
            let st = status(&store, &fx);
            assert_eq!(st.held, 0, "{label}: nothing may stay held");
            let attempts = store.request_attempts(&fx.request_id()).unwrap();
            assert_eq!(attempts.len(), 1, "{label}");
            let a = &attempts[0];

            match committed {
                // Reserve itself was lost: the redelivery created the one reservation,
                // which recovery then expired unstarted.
                0 => {
                    assert_eq!(
                        (a.state, st.refunded, st.consumed),
                        (RunState::Expired, 1, 0),
                        "{label}"
                    );
                }
                // Reserved but never started: expired, refunded (nothing acquired).
                1 => {
                    assert_eq!(
                        (a.state, st.refunded, st.consumed),
                        (RunState::Expired, 1, 0),
                        "{label}"
                    );
                    assert_eq!(a.exposure, Exposure::NotExposed);
                }
                // Started, exposure recorded or not, validating or not: the lease
                // lapsed after possible exposure -> failed, consumed, never refunded.
                2..=4 => {
                    assert_eq!(
                        (a.state, st.refunded, st.consumed),
                        (RunState::Failed, 0, 1),
                        "{label}"
                    );
                    assert_eq!(a.exposure, Exposure::Exposed, "{label}");
                }
                // Finished: completed and consumed; recovery changed nothing.
                _ => {
                    assert_eq!(
                        (a.state, st.refunded, st.consumed),
                        (RunState::Completed, 0, 1),
                        "{label}"
                    );
                }
            }
            // Settlement and audit intent are atomic with the terminal state.
            if a.state.is_terminal() {
                assert!(
                    terminal_event(&store).is_some(),
                    "{label}: terminal audit event missing"
                );
            }
        }
    }
}

#[test]
fn holder_resumes_after_restart_with_its_lease() {
    // Crash at each boundary after start; the worker still holds its lease
    // value, the store restarts, the worker repeats the step (every step is
    // idempotent for the holder) and completes. Nothing is charged twice.
    for (i, op) in STEPS.iter().copied().enumerate().skip(2) {
        for phase in PHASES {
            let label = format!("{op:?}/{phase:?}");
            let db = TempDb::new("resume");
            let fx = fixture(1);
            let arm = Arc::new(Arm::default());
            let store = open_armed(&db, &arm);
            provision(&store, &fx, 3);
            let mut run = Run {
                outcome: None,
                lease: None,
            };
            for j in 0..i {
                step(&store, &fx, &mut run, j).unwrap();
            }
            arm.arm(op, phase);
            let err = step(&store, &fx, &mut run, i).unwrap_err();
            assert!(is_crash(&err, op, phase), "{label}");
            drop(store);

            let store = open(&db);
            // Redo the interrupted step and everything after it.
            for j in i..STEPS.len() {
                step(&store, &fx, &mut run, j)
                    .unwrap_or_else(|e| panic!("{label} step {j}: {e:?}"));
            }
            store.integrity_check().unwrap();
            let st = status(&store, &fx);
            assert_eq!((st.held, st.consumed, st.refunded), (0, 1, 0), "{label}");
            let o = run.outcome.unwrap();
            assert_eq!(
                store.attempt(&o.attempt).unwrap().unwrap().state,
                RunState::Completed
            );
            store.check_disclosure_precondition(&o.attempt).unwrap();
        }
    }
}

#[test]
fn crash_during_cancel_never_refunds_a_started_run() {
    for phase in PHASES {
        let db = TempDb::new("cancel");
        let fx = fixture(1);
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        provision(&store, &fx, 2);
        let mut run = Run {
            outcome: None,
            lease: None,
        };
        step(&store, &fx, &mut run, 0).unwrap();
        step(&store, &fx, &mut run, 1).unwrap();
        let o = run.outcome.clone().unwrap();
        arm.arm(FaultOp::Cancel, phase);
        let err = store
            .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 2)
            .unwrap_err();
        assert!(is_crash(&err, FaultOp::Cancel, phase));
        drop(store);

        let store = open(&db);
        // Operator repeats the cancel (idempotent) or recovery runs later.
        if phase == FaultPhase::AfterCommit {
            assert_eq!(
                store
                    .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 3)
                    .unwrap()
                    .state,
                RunState::Cancelled
            );
        } else {
            store.recover(&actor(), NOW + 100_000).unwrap();
        }
        store.integrity_check().unwrap();
        let st = status(&store, &fx);
        assert_eq!((st.held, st.consumed, st.refunded), (0, 1, 0), "{phase:?}");
    }
}

#[test]
fn crash_during_cancel_before_start_refunds_exactly_once() {
    for phase in PHASES {
        let db = TempDb::new("cancel0");
        let fx = fixture(1);
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        provision(&store, &fx, 2);
        let o = reserve(&store, &fx).unwrap();
        arm.arm(FaultOp::Cancel, phase);
        let err = store
            .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 2)
            .unwrap_err();
        assert!(is_crash(&err, FaultOp::Cancel, phase));
        drop(store);
        let store = open(&db);
        store
            .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 3)
            .unwrap();
        store
            .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 4)
            .unwrap();
        store.integrity_check().unwrap();
        let st = status(&store, &fx);
        assert_eq!((st.held, st.consumed, st.refunded), (0, 0, 1), "{phase:?}");
    }
}

#[test]
fn crash_during_recovery_is_resumable_and_settles_each_attempt_once() {
    for phase in PHASES {
        let db = TempDb::new("recover");
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        let fxs: Vec<Fx> = (1..=3).map(fixture).collect();
        provision(&store, &fxs[0], 3);
        let mut outcomes = Vec::new();
        for fx in &fxs {
            outcomes.push(reserve(&store, fx).unwrap());
        }
        // One abandoned mid-run, two never started.
        store
            .start_attempt(&StartCommand {
                attempt: &outcomes[0].attempt,
                owner: "worker-a",
                actor: &actor(),
                now: NOW + 1,
                lease_secs: LEASE,
                observed: Some(&fxs[0].obs),
                max_state_age_secs: MAX_AGE,
            })
            .unwrap();
        arm.arm(FaultOp::Recover, phase);
        let err = store.recover(&actor(), NOW + 100_000).unwrap_err();
        assert!(is_crash(&err, FaultOp::Recover, phase));
        drop(store);

        let store = open(&db);
        store.integrity_check().unwrap();
        store.recover(&actor(), NOW + 100_001).unwrap();
        store.recover(&actor(), NOW + 100_002).unwrap(); // idempotent
        store.integrity_check().unwrap();
        let st = status(&store, &fxs[0]);
        assert_eq!((st.held, st.consumed, st.refunded), (0, 1, 2), "{phase:?}");
    }
}

#[test]
fn crash_during_retry_never_double_charges() {
    for phase in PHASES {
        let db = TempDb::new("retrycrash");
        let fx = fixture_with(1, Scope::Population, 1, 2, "synthetic-candidate-r");
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        provision(&store, &fx, 5);
        let a1 = reserve(&store, &fx).unwrap();
        let lease = store
            .start_attempt(&StartCommand {
                attempt: &a1.attempt,
                owner: "worker-a",
                actor: &actor(),
                now: NOW + 1,
                lease_secs: LEASE,
                observed: Some(&fx.obs),
                max_state_age_secs: MAX_AGE,
            })
            .unwrap();
        store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
        store
            .finish(
                &lease,
                ExecutionOutcome::Failed,
                ReasonCode::ExecutionFailed,
                &actor(),
                NOW + 3,
            )
            .unwrap();

        let obs = observed(NOW + 10, "active");
        let cmd = RetryCommand {
            request: &fx.req,
            approval: &fx.apr,
            observed: &obs,
            from_attempt_no: 1,
            now: ts(NOW + 10),
            max_state_age_secs: MAX_AGE,
            reservation_window_secs: WINDOW,
        };
        arm.arm(FaultOp::Retry, phase);
        let err = store.retry_attempt(&cmd).unwrap_err();
        assert!(is_crash(&err, FaultOp::Retry, phase));
        drop(store);

        let store = open(&db);
        let again = store.retry_attempt(&cmd).unwrap();
        assert_eq!(again.replay, phase == FaultPhase::AfterCommit, "{phase:?}");
        let again2 = store.retry_attempt(&cmd).unwrap();
        assert!(again2.replay);
        assert_eq!(again.attempt, again2.attempt);
        let st = status(&store, &fx);
        assert_eq!((st.held, st.consumed), (1, 1), "{phase:?}");
        assert_eq!(store.request_attempts(&fx.request_id()).unwrap().len(), 2);
        store.integrity_check().unwrap();
    }
}

#[test]
fn crash_around_ack_and_provision_and_exhaustion_denial() {
    // Ack: durable or not, repeating it converges.
    for phase in PHASES {
        let db = TempDb::new("ack");
        let fx = fixture(1);
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        provision(&store, &fx, 1);
        arm.arm(FaultOp::OutboxAck, phase);
        let err = store.outbox_ack(1, "ledger:entry-1", NOW).unwrap_err();
        assert!(is_crash(&err, FaultOp::OutboxAck, phase));
        drop(store);
        let store = open(&db);
        let r = store.outbox_ack(1, "ledger:entry-1", NOW + 1).unwrap();
        assert_eq!(
            r == AckOutcome::AlreadyAcked,
            phase == FaultPhase::AfterCommit
        );
        assert_eq!(
            store.outbox_ack(1, "ledger:entry-1", NOW + 2).unwrap(),
            AckOutcome::AlreadyAcked
        );
        store.integrity_check().unwrap();
    }
    // Provision: re-provisioning converges and never doubles the limit.
    for phase in PHASES {
        let db = TempDb::new("prov");
        let fx = fixture(1);
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        arm.arm(FaultOp::ProvisionBudget, phase);
        let err = store
            .provision_budget(BudgetKind::Run, &fx.scope(), 2, &actor(), NOW)
            .unwrap_err();
        assert!(is_crash(&err, FaultOp::ProvisionBudget, phase));
        drop(store);
        let store = open(&db);
        let st = store
            .provision_budget(BudgetKind::Run, &fx.scope(), 2, &actor(), NOW + 1)
            .unwrap();
        assert_eq!(st.limit, 2);
        store.integrity_check().unwrap();
    }
    // Exhaustion denial is recorded atomically with its outbox event.
    for phase in PHASES {
        let db = TempDb::new("deny");
        let a = fixture(1);
        let b = fixture(2);
        let arm = Arc::new(Arm::default());
        let store = open_armed(&db, &arm);
        provision(&store, &a, 1);
        reserve(&store, &a).unwrap();
        arm.arm(FaultOp::Reserve, phase);
        assert!(reserve(&store, &b).is_err());
        drop(store);
        let store = open(&db);
        let o = reserve(&store, &b).unwrap();
        assert_eq!(o.state, RunState::Denied);
        assert_eq!(o.replay, phase == FaultPhase::AfterCommit);
        assert_eq!(status(&store, &a).held, 1);
        store.integrity_check().unwrap();
    }
}

#[test]
fn restart_with_lapsed_run_cannot_be_started_again() {
    // A worker that crashed after start cannot "resume" by starting again:
    // start is only valid from `reserved`, so nothing executes twice.
    let db = TempDb::new("norestart");
    let fx = fixture(1);
    let store = open(&db);
    provision(&store, &fx, 2);
    let o = reserve(&store, &fx).unwrap();
    let first = store
        .start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner: "worker-a",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    drop(store);
    let store = open(&db);
    let err = store
        .start_attempt(&StartCommand {
            attempt: &RunId::new(o.attempt.as_str()),
            owner: "worker-b",
            actor: &actor(),
            now: NOW + 2,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap_err();
    assert_eq!(err, StoreError::InvalidTransition);
    // The original holder's lease survived the restart.
    store.record_exposure(&first, &actor(), NOW + 3).unwrap();
}
