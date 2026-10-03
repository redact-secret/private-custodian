//! Synthetic service smoke test.
//!
//! Uses only in-memory doubles and invented labels: no protected data, no
//! GitHub App, no signing credentials, no network, no filesystem. It proves
//! lifecycle mechanism, not holdout quality or independence.

use std::sync::Arc;
use std::thread;

use custodian_core::ports::{Refusal, RunRequest, StateStore};
use custodian_core::testing::{
    ExecMode, InMemoryStore, ScriptedExecutor, StaticAuthorizer, SyntheticCorpus,
};
use custodian_core::{
    ActorId, Exposure, IdempotencyKey, PlanDigest, PopulationId, ReasonCode, RunState,
};
use custodian_service::ControlService;

type Svc = ControlService<StaticAuthorizer, SyntheticCorpus, InMemoryStore, ScriptedExecutor>;

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

fn service(mode: ExecMode, budget: u32, corpus_available: bool) -> Svc {
    let auth = StaticAuthorizer::new(10);
    auth.approve(plan(), 100);
    let store = InMemoryStore::new();
    store.set_budget(pop(), budget);
    ControlService::new(
        auth,
        SyntheticCorpus::new(corpus_available),
        store,
        ScriptedExecutor::new(mode),
    )
}

#[test]
fn happy_path_completes() {
    let svc = service(ExecMode::Ok, 1, true);
    let report = svc.run(&request("k1")).unwrap();
    assert_eq!(report.state, RunState::Completed);
    assert_eq!(svc.store.budget_remaining(&pop()), 0);
    let rec = svc.store.get(&report.run).unwrap();
    assert_eq!(rec.exposure, Exposure::Exposed);
    // Reservation precedes exposure in the audit history.
    let states: Vec<_> = rec.history.iter().map(|h| h.0).collect();
    assert_eq!(
        &states[..3],
        &[RunState::Proposed, RunState::Authorized, RunState::Reserved]
    );
}

#[test]
fn unapproved_or_expired_plan_is_denied_before_any_charge() {
    let svc = service(ExecMode::Ok, 1, true);
    let mut r = request("k1");
    r.plan = PlanDigest::new("synthetic-unapproved");
    assert_eq!(
        svc.run(&r).unwrap_err(),
        Refusal(ReasonCode::AuthorizationDenied)
    );

    let auth = StaticAuthorizer::new(10);
    auth.approve(plan(), 10); // expires_at == now: expired
    let store = InMemoryStore::new();
    store.set_budget(pop(), 1);
    let expired = ControlService::new(
        auth,
        SyntheticCorpus::new(true),
        store,
        ScriptedExecutor::new(ExecMode::Ok),
    );
    assert_eq!(
        expired.run(&request("k1")).unwrap_err(),
        Refusal(ReasonCode::AuthorizationExpired)
    );
    assert_eq!(expired.store.budget_remaining(&pop()), 1);
    assert_eq!(expired.corpus.opens(), 0);
}

#[test]
fn authorizer_bound_to_wrong_plan_is_caught() {
    let mut auth = StaticAuthorizer::new(10);
    auth.approve(plan(), 100);
    auth.corrupt_plan_binding = true;
    let store = InMemoryStore::new();
    store.set_budget(pop(), 1);
    let svc = ControlService::new(
        auth,
        SyntheticCorpus::new(true),
        store,
        ScriptedExecutor::new(ExecMode::Ok),
    );
    assert_eq!(
        svc.run(&request("k1")).unwrap_err(),
        Refusal(ReasonCode::PlanMismatch)
    );
    assert_eq!(svc.store.budget_remaining(&pop()), 1);
    assert_eq!(svc.corpus.opens(), 0);
}

#[test]
fn exhausted_budget_refuses_before_protected_access() {
    let svc = service(ExecMode::Ok, 1, true);
    svc.run(&request("k1")).unwrap();
    assert_eq!(
        svc.run(&request("k2")).unwrap_err(),
        Refusal(ReasonCode::BudgetExhausted)
    );
    assert_eq!(svc.corpus.opens(), 1);
}

#[test]
fn duplicate_dispatch_does_not_recharge_or_reexecute() {
    let svc = service(ExecMode::Ok, 2, true);
    let first = svc.run(&request("k1")).unwrap();
    let second = svc.run(&request("k1")).unwrap();
    assert!(second.replay);
    assert_eq!(first.run, second.run);
    assert_eq!(svc.executor.executions(), 1);
    assert_eq!(svc.store.budget_remaining(&pop()), 1);
}

#[test]
fn idempotency_key_reused_with_different_plan_is_rejected() {
    let svc = service(ExecMode::Ok, 2, true);
    svc.authorizer
        .approve(PlanDigest::new("synthetic-plan-b"), 100);
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
    let before = service(ExecMode::Ok, 1, false);
    assert_eq!(
        before.run(&request("k1")).unwrap_err(),
        Refusal(ReasonCode::CorpusUnavailable)
    );
    assert_eq!(before.store.budget_remaining(&pop()), 1);

    let after = service(ExecMode::Fail, 1, true);
    assert_eq!(
        after.run(&request("k1")).unwrap_err(),
        Refusal(ReasonCode::ExecutionFailed)
    );
    assert_eq!(after.store.budget_remaining(&pop()), 0);
    // A retry with a new key is a new exposure and is refused, not free.
    assert_eq!(
        after.run(&request("k2")).unwrap_err(),
        Refusal(ReasonCode::BudgetExhausted)
    );
}

#[test]
fn malicious_or_mismatched_output_is_rejected_and_budget_stays_spent() {
    for mode in [ExecMode::WrongPlan, ExecMode::IncompleteRoster] {
        let svc = service(mode, 1, true);
        assert_eq!(
            svc.run(&request("k1")).unwrap_err(),
            Refusal(ReasonCode::InvalidArtifact)
        );
        assert_eq!(svc.store.budget_remaining(&pop()), 0);
    }
}

#[test]
fn concurrent_requests_never_exceed_the_budget() {
    let svc = Arc::new(service(ExecMode::Ok, 3, true));
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
    assert_eq!(svc.store.budget_remaining(&pop()), 0);
    assert_eq!(svc.corpus.opens(), 3);
}

#[test]
fn concurrent_duplicate_key_charges_once() {
    let svc = Arc::new(service(ExecMode::Ok, 5, true));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let svc = Arc::clone(&svc);
            thread::spawn(move || svc.run(&request("same-key")).unwrap())
        })
        .collect();
    let reports: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(reports.iter().filter(|r| !r.replay).count(), 1);
    assert_eq!(svc.store.budget_remaining(&pop()), 4);
    assert_eq!(svc.executor.executions(), 1);
}
