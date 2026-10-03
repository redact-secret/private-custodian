//! The SQLite store behind the vendor-neutral `StateStore` port, driven by
//! the same `ControlService` and the same scenarios as the in-memory double.
//! Synthetic data only; proves mechanism, not protected-corpus independence.

mod common;

use std::sync::Arc;
use std::thread;

use common::*;
use custodian_core::ports::{Refusal, RunRequest, StateStore};
use custodian_core::testing::{
    ExecMode, InMemoryDisclosure, ScriptedExecutor, StaticAuthorizer, SyntheticCorpus,
};
use custodian_core::{
    ActorId, Exposure, IdempotencyKey, PlanDigest, PopulationId, ReasonCode, RunId, RunState,
};
use custodian_service::ControlService;
use custodian_store::{ManualClock, SqliteStore};

type Svc = ControlService<
    StaticAuthorizer,
    SyntheticCorpus,
    SqliteStore,
    ScriptedExecutor,
    InMemoryDisclosure,
>;

fn plan() -> PlanDigest {
    PlanDigest::new("synthetic-plan-a")
}
fn pop() -> PopulationId {
    PopulationId::new("synthetic-population")
}
fn request(key: &str) -> RunRequest {
    RunRequest {
        actor: ActorId::new("synthetic-requester"),
        plan: plan(),
        population: pop(),
        idempotency_key: IdempotencyKey::new(key),
    }
}

fn service(db: &TempDb, mode: ExecMode, budget: u64, corpus_available: bool) -> Svc {
    let auth = StaticAuthorizer::new(NOW);
    auth.approve(plan(), NOW + 1_000);
    let clock = Arc::new(ManualClock::new(NOW));
    let store =
        SqliteStore::open_with_config(db.path(), cfg(&clock).with_busy_timeout_ms(60_000)).unwrap();
    store
        .provision_port_budget(&pop(), budget, &actor(), NOW)
        .unwrap();
    ControlService::new(
        auth,
        SyntheticCorpus::new(corpus_available),
        store,
        ScriptedExecutor::new(mode),
        InMemoryDisclosure::new(),
    )
}

fn remaining(svc: &Svc) -> u64 {
    svc.store
        .port_budget_status(&pop())
        .unwrap()
        .unwrap()
        .available()
}

fn attempt_of(svc: &Svc, key: &str) -> RunId {
    svc.store.request_attempts(&format!("port:{key}")).unwrap()[0]
        .attempt
        .clone()
}

#[test]
fn happy_path_completes_and_records_history() {
    let db = TempDb::new("port-happy");
    let svc = service(&db, ExecMode::Ok, 1, true);
    let r = svc.run(&request("k1")).unwrap();
    assert_eq!(r.state, RunState::Completed);
    let rec = svc.store.get(&r.run).unwrap();
    assert_eq!(rec.state, RunState::Completed);
    assert_eq!(rec.exposure, Exposure::Exposed);
    assert!(!rec.budget_refunded);
    let states: Vec<_> = rec.history.iter().map(|h| h.0).collect();
    assert_eq!(
        states,
        [
            RunState::Proposed,
            RunState::Authorized,
            RunState::Reserved,
            RunState::Running,
            RunState::Running, // exposure record
            RunState::Validating,
            RunState::Completed
        ]
    );
    assert_eq!(rec.history[4].1, ReasonCode::ProtectedBytesAcquired);
    svc.store.integrity_check().unwrap();
}

#[test]
fn exhausted_budget_refuses_before_protected_access() {
    let db = TempDb::new("port-exhaust");
    let svc = service(&db, ExecMode::Ok, 1, true);
    svc.run(&request("k1")).unwrap();
    assert_eq!(
        svc.run(&request("k2")).unwrap_err(),
        Refusal(ReasonCode::BudgetExhausted)
    );
    assert_eq!(svc.corpus.opens(), 1);
    svc.store.integrity_check().unwrap();
}

#[test]
fn duplicate_dispatch_does_not_recharge_or_reexecute() {
    let db = TempDb::new("port-dup");
    let svc = service(&db, ExecMode::Ok, 2, true);
    let first = svc.run(&request("k1")).unwrap();
    let second = svc.run(&request("k1")).unwrap();
    assert!(second.replay);
    assert_eq!(first.run, second.run);
    assert_eq!(svc.executor.executions(), 1);
    assert_eq!(remaining(&svc), 1);
}

#[test]
fn idempotency_key_reused_with_different_plan_is_rejected() {
    let db = TempDb::new("port-key");
    let svc = service(&db, ExecMode::Ok, 2, true);
    svc.authorizer
        .approve(PlanDigest::new("synthetic-plan-b"), NOW + 1_000);
    svc.run(&request("k1")).unwrap();
    let mut other = request("k1");
    other.plan = PlanDigest::new("synthetic-plan-b");
    assert_eq!(
        svc.run(&other).unwrap_err(),
        Refusal(ReasonCode::PlanMismatch)
    );
}

#[test]
fn failure_before_exposure_refunds_but_after_exposure_does_not() {
    let db = TempDb::new("port-before");
    let before = service(&db, ExecMode::Ok, 1, false);
    assert_eq!(
        before.run(&request("k1")).unwrap_err(),
        Refusal(ReasonCode::CorpusUnavailable)
    );
    assert_eq!(remaining(&before), 1);
    let rec = before.store.get(&attempt_of(&before, "k1")).unwrap();
    assert!(rec.budget_refunded);

    let db2 = TempDb::new("port-after");
    let after = service(&db2, ExecMode::Fail, 1, true);
    assert_eq!(
        after.run(&request("k1")).unwrap_err(),
        Refusal(ReasonCode::ExecutionFailed)
    );
    assert_eq!(remaining(&after), 0);
    // A retry with a new key is a new exposure and is refused, not free.
    assert_eq!(
        after.run(&request("k2")).unwrap_err(),
        Refusal(ReasonCode::BudgetExhausted)
    );
    after.store.integrity_check().unwrap();
}

#[test]
fn malicious_or_mismatched_output_is_rejected_and_budget_stays_spent() {
    for (i, mode) in [ExecMode::WrongPlan, ExecMode::IncompleteRoster]
        .into_iter()
        .enumerate()
    {
        let db = TempDb::new(&format!("port-mal-{i}"));
        let svc = service(&db, mode, 1, true);
        assert_eq!(
            svc.run(&request("k1")).unwrap_err(),
            Refusal(ReasonCode::InvalidArtifact)
        );
        assert_eq!(remaining(&svc), 0);
    }
}

#[test]
fn disclosure_requires_a_completed_run() {
    let db = TempDb::new("port-disc");
    let svc = service(&db, ExecMode::WrongPlan, 1, true);
    let _ = svc.run(&request("k1"));
    let forged = custodian_service::RunReport {
        run: attempt_of(&svc, "k1"),
        state: RunState::Completed,
        replay: false,
        outcome: Some(custodian_core::ports::ExecutionOutcome {
            plan: plan(),
            roster_complete: true,
            passed: 1,
            total: 1,
        }),
    };
    assert_eq!(
        svc.prepare_disclosure(&forged, &ActorId::new("synthetic-requester"))
            .unwrap_err(),
        Refusal(ReasonCode::DisclosureNotPermitted)
    );
}

#[test]
fn expired_authorization_is_refused_before_any_charge() {
    let db = TempDb::new("port-expired");
    let clock = Arc::new(ManualClock::new(NOW + 20));
    let store = SqliteStore::open_with_config(db.path(), cfg(&clock)).unwrap();
    store
        .provision_port_budget(&pop(), 1, &actor(), NOW)
        .unwrap();
    let auth = custodian_core::ports::Authorization {
        id: custodian_core::AuthorizationId::new("synthetic-authorization"),
        actor: ActorId::new("synthetic-requester"),
        plan: plan(),
        population: pop(),
        expires_at: NOW + 10,
    };
    assert_eq!(
        store
            .reserve(&auth, &IdempotencyKey::new("k1"))
            .unwrap_err(),
        Refusal(ReasonCode::AuthorizationExpired)
    );
    assert_eq!(store.port_budget_status(&pop()).unwrap().unwrap().held, 0);
}

#[test]
fn port_transitions_outside_the_table_are_refused() {
    let db = TempDb::new("port-table");
    let svc = service(&db, ExecMode::Ok, 2, true);
    let r = svc.run(&request("k1")).unwrap();
    let run = r.run;
    for to in [
        RunState::Proposed,
        RunState::Authorized,
        RunState::Reserved,
        RunState::Running,
        RunState::Validating,
        RunState::Completed,
        RunState::Failed,
        RunState::Cancelled,
        RunState::Expired,
        RunState::Denied,
    ] {
        assert_eq!(
            svc.store
                .transition(&run, to, ReasonCode::Requested)
                .unwrap_err(),
            Refusal(ReasonCode::InvalidTransition),
            "{to:?}"
        );
    }
    assert_eq!(
        svc.store
            .transition(
                &RunId::new("unknown"),
                RunState::Running,
                ReasonCode::Requested
            )
            .unwrap_err(),
        Refusal(ReasonCode::InvalidTransition)
    );
}

#[test]
fn concurrent_requests_never_exceed_the_budget() {
    let db = TempDb::new("port-conc");
    let svc = Arc::new(service(&db, ExecMode::Ok, 3, true));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let svc = Arc::clone(&svc);
            thread::spawn(move || svc.run(&request(&format!("k{i}"))).is_ok())
        })
        .collect();
    let ok = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|b| *b)
        .count();
    assert_eq!(ok, 3);
    assert_eq!(remaining(&svc), 0);
    assert_eq!(svc.corpus.opens(), 3);
    svc.store.integrity_check().unwrap();
}

#[test]
fn concurrent_duplicate_key_charges_once() {
    let db = TempDb::new("port-conc-dup");
    let svc = Arc::new(service(&db, ExecMode::Ok, 5, true));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let svc = Arc::clone(&svc);
            thread::spawn(move || svc.run(&request("same-key")).unwrap())
        })
        .collect();
    let reports: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(reports.iter().filter(|r| !r.replay).count(), 1);
    assert_eq!(remaining(&svc), 4);
    assert_eq!(svc.executor.executions(), 1);
}
