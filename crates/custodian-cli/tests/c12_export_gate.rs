//! R-2 end to end (ADR 0116): the export-acknowledged dispatch gate against
//! the real store, ledger, exporter, startup check and dispatcher, with test
//! keys and synthetic data. Project-maintained evidence, not independent
//! validation.
//!
//! The pre-gate drill (`c12_restore_drill.rs`,
//! `spend_after_the_last_export_is_the_documented_unrecoverable_window`)
//! shows an approved request running twice after a restore. These tests show
//! the same restore refused once the store enforces the gate.

mod c12;

use c12::*;
use custodian_cli::{CliReason, Service};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_core::{Exposure, RunState};
use std::sync::{Arc, Mutex};

use custodian_store::{FaultInjector, FaultOp, FaultPhase, FaultPoint, SqliteStore, StoreConfig};
use custodian_worker::WorkerReason;

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

/// The deployment's store configuration: the gate enforced with a bound of zero.
fn enforce(p: &mut Pipe) {
    let path = p.w.rw.db.path();
    p.w.rw.store = SqliteStore::open_with_config(path, StoreConfig::enforced()).unwrap();
}

fn state_of(p: &Pipe, attempt: &custodian_core::RunId) -> (RunState, Exposure) {
    let r = p.w.rw.store.attempt(attempt).unwrap().unwrap();
    (r.state, r.exposure)
}

#[test]
fn dispatch_is_refused_until_the_spend_is_acknowledged_and_nothing_runs_in_the_meantime() {
    let mut p = Pipe::new(5, 10);
    enforce(&mut p);
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let (attempt, _) = p.reserve(1);
    let held = p.w.budget();

    // The reservation is not yet in the ledger: the worker cannot even start.
    let err = p.dispatch(&svc, 1, &attempt).err().unwrap();
    assert_eq!(err, WorkerReason::LedgerUnavailable);
    assert_eq!(p.sandbox.runs(), 0, "no engine ran");
    assert_eq!(
        state_of(&p, &attempt),
        (RunState::Reserved, Exposure::NotExposed)
    );
    let b = p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (held.held, 0, 0));

    // Export, and the start is allowed. Without an export between the start
    // and the exposure record (no barrier) the exposure is refused, the
    // attempt ends unexposed, and still nothing ran.
    assert_eq!(code(&p.export()), "exported");
    let err = p.dispatch(&svc, 1, &attempt).err().unwrap();
    assert_eq!(err, WorkerReason::LedgerUnavailable);
    assert_eq!(
        p.sandbox.runs(),
        0,
        "no engine ran before the start was acknowledged"
    );
    let (state, exposure) = state_of(&p, &attempt);
    assert_eq!(exposure, Exposure::NotExposed);
    assert!(matches!(state, RunState::Failed | RunState::Running));
    p.w.rw.store.verify_invariants().unwrap();
}

#[test]
fn a_gated_dispatch_with_the_export_barrier_runs_once_and_a_restore_cannot_run_it_again() {
    let mut p = Pipe::new(5, 10);
    enforce(&mut p);
    let (req1, _) = p.request(1);
    let acts = p.activations();
    let _svc = p.start(&acts).unwrap();
    let (attempt, _) = p.reserve(1);

    // Backup B: after the approval was exported, before anything ran. The
    // ledger already holds a store checkpoint covering this state.
    assert_eq!(code(&p.export()), "exported");
    let b = p.w.rw.db.dir().join("pre-dispatch.db");
    p.w.rw.store.backup_to(&b).unwrap();

    // The dispatch exports around its own start and its exposure record, and
    // only then opens protected bytes.
    let report = p
        .dispatch_gated(&req1, &attempt, || p.export().is_ok())
        .unwrap();
    assert_eq!(report.outcome, O::Success);
    assert_eq!(p.sandbox.runs(), 1);
    assert_eq!(code(&p.export()), "exported");

    // Loss: the database is replaced by backup B. The ledger knows the start
    // and the exposure, so the startup check refuses; the closed window is
    // exactly the one the pre-gate drill leaves open.
    p.w.rw.store = SqliteStore::open_with_config(&b, StoreConfig::enforced()).unwrap();
    let acts = p.activations();
    let err = Service::start(p.w.parts(), &startup_config(), &acts)
        .err()
        .unwrap();
    assert_eq!(err.reason, CliReason::StoreRolledBack);
    assert_eq!(p.sandbox.runs(), 1, "the request did not run a second time");
}

#[test]
fn a_ledger_outage_fails_closed_and_resets_no_budget() {
    let mut p = Pipe::new(5, 10);
    enforce(&mut p);
    let (req1, _) = p.request(1);
    let acts = p.activations();
    let _svc = p.start(&acts).unwrap();
    let (attempt, _) = p.reserve(1);
    let before = p.w.budget();

    // The ledger is unreachable: the barrier cannot drain, so the start is
    // refused. Repeating changes nothing, however often.
    p.w.ledger.set_available(false);
    for _ in 0..3 {
        let err = p
            .dispatch_gated(&req1, &attempt, || p.export().is_ok())
            .err()
            .unwrap();
        assert_eq!(err, WorkerReason::LedgerUnavailable);
    }
    assert_eq!(p.sandbox.runs(), 0);
    assert_eq!(
        state_of(&p, &attempt),
        (RunState::Reserved, Exposure::NotExposed)
    );
    let after = p.w.budget();
    assert_eq!(
        (before.limit, before.held, before.consumed, before.refunded),
        (after.limit, after.held, after.consumed, after.refunded)
    );
    assert!(p.w.rw.store.unexported_budget_events().unwrap() >= 1);

    // The documented operator path: restore the ledger, export, dispatch.
    p.w.ledger.set_available(true);
    let report = p
        .dispatch_gated(&req1, &attempt, || p.export().is_ok())
        .unwrap();
    assert_eq!(report.outcome, O::Success);
    assert_eq!(p.sandbox.runs(), 1);
    let b = p.w.budget();
    assert_eq!((b.consumed, b.held), (1, 0));
    p.w.rw.store.verify_invariants().unwrap();
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
fn a_crash_between_export_and_acknowledgement_keeps_the_gate_closed_then_open() {
    // The ledger holds the record but the acknowledgement did not become
    // durable (crash before commit) or the caller never learned it did (crash
    // after commit). Before commit the store still counts the event
    // unexported, so a dispatch without an export pass is refused; the next
    // export re-presents the same record (idempotent in the ledger) and
    // acknowledges it, after which the dispatch runs exactly once.
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        let mut p = Pipe::new(5, 10);
        let arm = Arc::new(Arm::default());
        let path = p.w.rw.db.path();
        p.w.rw.store =
            SqliteStore::open_with_config(path, StoreConfig::enforced().with_fault(arm.clone()))
                .unwrap();
        let (req1, _) = p.request(1);
        let (attempt, _) = p.reserve(1);
        *arm.0.lock().unwrap() = Some(FaultPoint {
            op: FaultOp::OutboxAck,
            phase,
        });
        assert_ne!(code(&p.export()), "exported", "{phase:?}");
        match phase {
            FaultPhase::BeforeCommit => {
                let err = p.dispatch_gated(&req1, &attempt, || true).err().unwrap();
                assert_eq!(err, WorkerReason::LedgerUnavailable);
                assert_eq!(p.sandbox.runs(), 0);
            }
            FaultPhase::AfterCommit => {}
        }
        assert_eq!(code(&p.export()), "exported");
        let r = p
            .dispatch_gated(&req1, &attempt, || p.export().is_ok())
            .unwrap();
        assert_eq!(r.outcome, O::Success);
        assert_eq!(p.sandbox.runs(), 1, "{phase:?}: exactly one execution");
        p.w.rw.store.verify_invariants().unwrap();
    }
}
