//! Crash injection between every pipeline step, with restart.
//!
//! A "crash" here is the process dying at a named point: every object is
//! dropped, a new store connection opens the same file, a new startup sequence
//! runs (`recover` included) and the pass is repeated. The properties are the
//! ones the issue names: no lost settlement, no double charge, no double
//! exposure, no double publication, and never a clean receipt for an attempt
//! that did not complete. Synthetic data; the engine runs through the
//! UNSANDBOXED test fake, so nothing here is evidence of isolation.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use custodian_core::{Exposure, RunId, RunState};
use custodian_daemon::pipeline::{PipelineError, PipelinePoint};
use custodian_daemon::Shutdown;
use custodian_store::{FaultInjector, FaultOp, FaultPhase, FaultPoint, PipelineStep, ReleaseScope};

/// Fires once at a chosen store boundary.
#[derive(Default)]
struct Arm(Mutex<Option<FaultPoint>>);

impl Arm {
    fn at(op: FaultOp, phase: FaultPhase) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(FaultPoint { op, phase }))))
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

/// Fires on every call to one operation while armed (a process that cannot
/// complete that write: the closest an in-process test gets to a kill).
struct Jam {
    op: FaultOp,
    armed: Mutex<bool>,
}

impl Jam {
    fn on(op: FaultOp) -> Arc<Self> {
        Arc::new(Self {
            op,
            armed: Mutex::new(true),
        })
    }
    fn release(&self) {
        *self.armed.lock().unwrap() = false;
    }
}

impl FaultInjector for Jam {
    fn crash_at(&self, point: FaultPoint) -> bool {
        *self.armed.lock().unwrap()
            && point.op == self.op
            && point.phase == FaultPhase::BeforeCommit
    }
}

fn now(env: &Env) -> u64 {
    use custodian_store::Clock;
    env.p.w.clock.now()
}

/// One pass; `true` when the process "died" (a pipeline crash point, an
/// injected store fault surfacing, or a refused startup).
fn pass_died(env: &Env, fault: &CrashAt) -> bool {
    match env.try_with_pipeline(fault, |pl, _| pl.pass(&Shutdown::new())) {
        None => true,
        Some(Ok(_)) => false,
        Some(Err(PipelineError::Crash(_))) => true,
        Some(Err(PipelineError::Store(e))) => {
            matches!(e, custodian_store::StoreError::InjectedCrash(_))
        }
    }
}

fn run_of(env: &Env, a: &RunId) -> Option<custodian_store::PipelineRun> {
    env.store().pipeline_run(a).unwrap()
}

fn is_final(env: &Env, a: &RunId) -> bool {
    run_of(env, a).is_some_and(|r| r.step.is_terminal())
}

/// Everything that must hold after any sequence of crashes and restarts.
fn assert_invariants(env: &Env, attempt: &RunId, label: &str) {
    let store = env.store();
    store
        .integrity_check()
        .unwrap_or_else(|e| panic!("{label}: {e}"));
    let exposures = store
        .history(attempt)
        .unwrap()
        .iter()
        .filter(|t| t.is_exposure)
        .count();
    assert!(exposures <= 1, "{label}: {exposures} exposures");
    let b = env.p.w.budget();
    assert_eq!(
        b.held + b.consumed + b.refunded,
        1,
        "{label}: one reservation, accounted exactly once ({b:?})"
    );
    let rec = store.attempt(attempt).unwrap().unwrap();
    // Exposure is never refunded.
    if rec.exposure == Exposure::Exposed {
        assert_eq!(b.refunded, 0, "{label}");
    }
    let run = run_of(env, attempt);
    // A receipt exists only for an attempt that ran to a settled result.
    if let Some(art) = store.pipeline_artifacts(attempt).unwrap() {
        if art.receipt.is_some() && rec.state != RunState::Completed {
            // Only the private partial receipt of a failed attempt is allowed,
            // and it is closed, never prepared.
            assert!(
                run.as_ref().is_some_and(|r| r.step == PipelineStep::Closed),
                "{label}: a receipt for a non-completed attempt must be closed"
            );
        }
    }
    let released = env.released_files();
    assert!(released.len() <= 1, "{label}: {} files", released.len());
    let publications = env
        .p
        .w
        .ledger
        .paths()
        .iter()
        .filter(|p| p.contains("publication"))
        .count();
    assert!(
        publications <= 1,
        "{label}: {publications} publication records"
    );
    assert!(env.ledger_count("receipt.issued") <= 1, "{label}");
    if run
        .as_ref()
        .is_some_and(|r| r.step == PipelineStep::Released)
    {
        assert_eq!(rec.state, RunState::Completed, "{label}");
        assert_eq!(released.len(), 1, "{label}");
        assert_eq!(b.consumed, 1, "{label}");
        // The release was charged once.
        let charged = store
            .release_budget_status(&ReleaseScope::Requester(Who::Requester.actor().as_str()))
            .unwrap()
            .map(|s| s.consumed);
        assert_eq!(charged, Some(1), "{label}: one release charge");
    }
}

/// Drive the run to a final step through restarts. `fault_after` is the store
/// fault to remove at the first restart.
fn drive(env: &mut Env, attempt: &RunId, pfault: &CrashAt, arm: Option<&Arc<Arm>>, label: &str) {
    let mut approved = false;
    let mut restarted = false;
    for _round in 0..16 {
        if is_final(env, attempt) {
            break;
        }
        // The human places the release approval once a projection is prepared.
        if !approved && run_of(env, attempt).is_some_and(|r| r.step == PipelineStep::Prepared) {
            env.write_release_approval(attempt, 1);
            env.at(RELEASE_AT);
            approved = true;
        }
        let died = pass_died(env, pfault);
        let store_fault_fired = arm.is_some_and(|a| a.fired());
        if (died || store_fault_fired) && !restarted {
            // The process is gone: a new one opens the same file, and time
            // passes (lapsed leases are recovered at its start).
            env.restart_store();
            let t = now(env) + 400;
            env.at(t);
            restarted = true;
        } else if died {
            panic!("{label}: died twice");
        }
    }
    assert!(
        is_final(env, attempt),
        "{label}: did not finish: {:?}",
        run_of(env, attempt)
    );
    assert_invariants(env, attempt, label);
    // Settled means settled: more passes change nothing.
    let before = (env.released_files().len(), env.p.w.budget().consumed);
    for _ in 0..2 {
        let _ = pass_died(env, &CrashAt::default());
    }
    assert_eq!(
        before,
        (env.released_files().len(), env.p.w.budget().consumed),
        "{label}"
    );
}

#[test]
fn a_crash_after_every_pipeline_step_converges_to_one_release_and_one_charge() {
    for point in [
        PipelinePoint::AfterEnroll,
        PipelinePoint::AfterDispatch,
        PipelinePoint::AfterAssemble,
        PipelinePoint::AfterPrepare,
        PipelinePoint::AfterMarkPrepared,
        PipelinePoint::AfterRelease,
    ] {
        let label = format!("{point:?}");
        let mut env = Env::new(3);
        let attempt = env.approved(1);
        env.publish_feed();
        let fault = CrashAt::at(point);
        drive(&mut env, &attempt, &fault, None, &label);
        assert!(fault.fired(), "{label}: the crash point was never reached");
        // This script has a human approval, so every crash recovers to a
        // release.
        assert_eq!(
            run_of(&env, &attempt).unwrap().step,
            PipelineStep::Released,
            "{label}"
        );
        assert_eq!(env.p.w.budget().consumed, 1, "{label}");
        assert_eq!(env.released_files().len(), 1, "{label}");
    }
}

#[test]
fn an_injected_store_crash_at_every_boundary_of_the_pipeline_loses_and_duplicates_nothing() {
    let ops = [
        FaultOp::PipelineEnroll,
        FaultOp::PipelineStep,
        FaultOp::PipelineArtifacts,
        FaultOp::Start,
        FaultOp::RecordExposure,
        FaultOp::BeginValidation,
        FaultOp::Finish,
        FaultOp::OutboxAck,
        FaultOp::ProvisionBudget,
        FaultOp::ChargeRelease,
        FaultOp::AppendDisclosureHistory,
    ];
    for op in ops {
        for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
            let label = format!("{op:?}/{phase:?}");
            let mut env = Env::new(3);
            let attempt = env.approved(1);
            env.publish_feed();
            let arm = Arm::at(op, phase);
            env.restart_store_with_fault(arm.clone());
            drive(&mut env, &attempt, &CrashAt::default(), Some(&arm), &label);
            assert!(arm.fired(), "{label}: the boundary was never reached");
        }
    }
}

#[test]
fn a_process_killed_mid_run_leaves_a_consumed_failed_attempt_and_never_a_clean_receipt() {
    let mut env = Env::new(3);
    let attempt = env.approved(1);
    env.publish_feed();
    // The engine runs and its result is kept, but the process can never
    // settle the attempt (every settlement write is lost).
    let jam = Jam::on(FaultOp::Finish);
    env.restart_store_with_fault(jam.clone());
    let died = pass_died(&env, &CrashAt::default());
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert!(
        matches!(rec.state, RunState::Running | RunState::Validating),
        "died={died} state={:?}",
        rec.state
    );
    assert_eq!(rec.exposure, Exposure::Exposed);
    assert!(
        env.store()
            .pipeline_artifacts(&attempt)
            .unwrap()
            .unwrap()
            .result_meta
            .is_some(),
        "the validated result had been kept"
    );
    // The new process starts after the lease lapsed: recovery settles it.
    jam.release();
    env.restart_store();
    let t = now(&env) + 400;
    env.at(t);
    for _ in 0..3 {
        pass_died(&env, &CrashAt::default());
    }
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Failed, Exposure::Exposed)
    );
    let b = env.p.w.budget();
    assert_eq!(
        (b.held, b.consumed, b.refunded),
        (0, 1, 0),
        "consumed, never refunded"
    );
    let run = run_of(&env, &attempt).unwrap();
    assert_eq!(
        (run.step, run.reason.as_str()),
        (PipelineStep::Closed, "execution_failed")
    );
    let art = env.store().pipeline_artifacts(&attempt).unwrap().unwrap();
    assert!(
        art.receipt.is_none(),
        "a kept success result is not a receipt"
    );
    assert!(env.released_files().is_empty());
    assert_eq!(env.ledger_count("receipt.issued"), 0);
    // It ran exactly once.
    let exposures = env
        .store()
        .history(&attempt)
        .unwrap()
        .iter()
        .filter(|t| t.is_exposure)
        .count();
    assert_eq!(exposures, 1);
    env.store().integrity_check().unwrap();
}

#[test]
fn a_crash_after_delivery_delivers_the_same_projection_again_without_a_second_file() {
    let mut env = Env::new(3);
    let attempt = env.approved(1);
    env.publish_feed();
    // Reach Prepared, approve, then die right after delivery.
    pass_died(&env, &CrashAt::default());
    env.write_release_approval(&attempt, 1);
    env.at(RELEASE_AT);
    let fault = CrashAt::at(PipelinePoint::AfterRelease);
    assert!(pass_died(&env, &fault));
    assert_eq!(env.released_files().len(), 1, "delivered before the crash");
    let first = std::fs::read(&env.released_files()[0]).unwrap();
    assert_eq!(
        run_of(&env, &attempt).unwrap().step,
        PipelineStep::Prepared,
        "the release was not recorded"
    );
    env.restart_store();
    pass_died(&env, &CrashAt::default());
    assert_eq!(run_of(&env, &attempt).unwrap().step, PipelineStep::Released);
    assert_eq!(env.released_files().len(), 1, "no second publication");
    assert_eq!(std::fs::read(&env.released_files()[0]).unwrap(), first);
    assert_invariants(&env, &attempt, "after delivery");
}
