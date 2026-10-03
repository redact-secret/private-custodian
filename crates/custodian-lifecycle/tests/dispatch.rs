//! Dispatch-time eligibility: the real dispatcher, the real store and the
//! real protected-population adapter, with a synthetic shell-script engine
//! (C9). The sandbox is the unsandboxed test fake, so these tests prove the
//! control-plane ordering and settlement, not isolation. Synthetic data only.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::{CandidateDigest, EpochId};
use custodian_core::ports::Authorization;
use custodian_core::{
    ActorId, AuthorizationId, Contamination, Exposure, PlanDigest, ReasonCode, RunId, RunState,
};
use custodian_corpus::testing::TempRoot;
use custodian_corpus::{population_id_for, FsEpochStore, ProtectedBytes};
use custodian_lifecycle::{EpochReason, GuardedRunLedger, LifecycleEligibility, NoFault};
use custodian_store::{ObligationAction, ObligationCommand, ObligationTarget};
use custodian_worker::artifacts::{hash_file, ArtifactAllowlist};
use custodian_worker::dispatcher::{ArtifactSources, DispatcherConfig};
use custodian_worker::fake::TestOnlyUnsandboxedFake;
use custodian_worker::isolation::IsolationVerification;
use custodian_worker::ports::{CorpusPort, PopulationsCorpus, RunLedger, StoreRunLedger};
use custodian_worker::reason::Result as WResult;
use custodian_worker::sandbox::CancelToken;
use custodian_worker::{DispatchJob, Dispatcher, WorkerReason as W};
use serde_json::json;

fn mkdir(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Artifacts, staging and scratch for the worker, plus the plan pinned to
/// them.
struct Rig {
    _tmp: TempRoot,
    art: PathBuf,
    staging: PathBuf,
    scratch: PathBuf,
    sources: ArtifactSources,
}

const ENGINE: &str = "#!/bin/sh\nprintf '%s\\n' '{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"credential\",\"protocol\":{\"name\":\"synthetic-protocol\",\"version\":\"1\"},\"status\":\"complete\",\"roster\":{\"expected\":2,\"observed\":2,\"failed\":0}}'\n";

fn rig() -> Rig {
    let tmp = TempRoot::new();
    let base = tmp.path().to_path_buf();
    let (art, staging, scratch) = (base.join("art"), base.join("staging"), base.join("scratch"));
    for d in [&art, &staging, &scratch] {
        mkdir(d);
    }
    let put = |name: &str, bytes: &[u8], mode: u32| {
        let p = art.join(name);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    };
    let sources = ArtifactSources {
        engine: put("engine", ENGINE.as_bytes(), 0o755),
        adapter: put("adapter", b"synthetic adapter v1", 0o755),
        scanners: vec![put("scanner", b"synthetic scanner v1", 0o755)],
        candidate: put("candidate", b"synthetic candidate v1", 0o755),
        config: put("config", b"ok", 0o644),
    };
    Rig {
        _tmp: tmp,
        art,
        staging,
        scratch,
        sources,
    }
}

impl Rig {
    fn dispatcher(&self) -> Dispatcher {
        let mut cfg = DispatcherConfig::new(
            self.staging.clone(),
            ArtifactAllowlist::new(std::slice::from_ref(&self.art)).unwrap(),
        );
        cfg.heartbeat_interval = std::time::Duration::from_millis(100);
        Dispatcher::new_for_tests(
            Arc::new(TestOnlyUnsandboxedFake::new_not_isolated(
                self.scratch.clone(),
            )),
            IsolationVerification::test_only_not_isolated(NOW),
            cfg,
        )
        .unwrap()
    }

    fn candidate(&self) -> CandidateDigest {
        CandidateDigest::parse(&hash_file(&self.sources.candidate).unwrap()).unwrap()
    }

    fn request(
        &self,
        w: &RegWorld,
        binding: &custodian_contracts::common::PopulationBinding,
        n: u32,
    ) -> (EvaluationRequest, custodian_contracts::approval::Approval) {
        let a = |p: &Path| json!({"name": "synthetic", "version": "0.0.1", "digest": hash_file(p).unwrap()});
        let _ = w;
        let pop = serde_json::to_value(binding).unwrap();
        let budget = budget_json(binding);
        let mut plan = cc::plan();
        plan["candidate"] = json!(hash_file(&self.sources.candidate).unwrap());
        plan["engine"] = a(&self.sources.engine);
        plan["adapter"] = a(&self.sources.adapter);
        plan["scanners"] = json!([a(&self.sources.scanners[0])]);
        plan["config_digest"] = json!(hash_file(&self.sources.config).unwrap());
        plan["population"] = pop.clone();
        plan["accounting"]["budget"] = budget.clone();
        plan["accounting"]["max_retries"] = json!(1);
        let mut req = cc::request_json();
        req["request_id"] = json!(cc::id("req_", n));
        req["idempotency_key"] = json!(cc::id("idk_", n));
        req["plan"] = plan;
        let request: EvaluationRequest = cc::parse(&req);
        let mut apr = cc::approval_json();
        apr["approval_id"] = json!(cc::id("apr_", n));
        apr["scope"]["request_id"] = json!(cc::id("req_", n));
        apr["scope"]["plan_digest"] = json!(request.plan.plan_digest().unwrap().as_str());
        apr["scope"]["candidate"] = json!(hash_file(&self.sources.candidate).unwrap());
        apr["scope"]["population"] = pop;
        apr["scope"]["budget"] = budget;
        (request, cc::parse(&apr))
    }
}

struct Run {
    req: EvaluationRequest,
    attempt: RunId,
}

fn prepare_run(w: &RegWorld, r: &Rig, n: u32) -> Run {
    if w.store
        .budget_status(BudgetKind::Run, &run_scope(&w.binding))
        .unwrap()
        .is_none()
    {
        w.store
            .provision_budget(BudgetKind::Run, &run_scope(&w.binding), 5, &actor(), NOW)
            .unwrap();
    }
    let (req, apr) = r.request(w, &w.binding, n);
    let out = reserve_req(&w.store, &req, &apr).unwrap();
    Run {
        req,
        attempt: out.attempt,
    }
}

fn store_ledger<'a>(w: &'a RegWorld, attempt: &RunId) -> StoreRunLedger<'a> {
    StoreRunLedger::new(
        &w.store,
        attempt.clone(),
        "worker-synthetic-1",
        ActorId::new("act_synthetic_operator"),
        300,
        300,
        Arc::new(|| NOW + 1),
        Arc::new(|| Some(exec_obs(NOW + 1))),
    )
}

fn corpus<'a>(w: &'a RegWorld) -> PopulationsCorpus<'a, FsEpochStore> {
    PopulationsCorpus::new(
        &w.fx.pop,
        Authorization {
            id: AuthorizationId::new("auth-synthetic"),
            actor: ActorId::new("act_synthetic_operator"),
            plan: PlanDigest::new("plan-synthetic"),
            population: population_id_for(&w.epoch),
            expires_at: 0,
        },
    )
}

/// Counts how often protected bytes were opened.
struct Counting<'a> {
    inner: PopulationsCorpus<'a, FsEpochStore>,
    opens: AtomicU32,
    on_read: Option<Box<dyn Fn() + Send + Sync + 'a>>,
}

impl CorpusPort for Counting<'_> {
    fn open(&self) -> WResult<()> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.inner.open()
    }
    fn binding(&self) -> WResult<custodian_contracts::common::PopulationBinding> {
        self.inner.binding()
    }
    fn entry_names(&self) -> WResult<Vec<String>> {
        self.inner.entry_names()
    }
    fn read_entry(&self, name: &str) -> WResult<ProtectedBytes> {
        if let Some(f) = &self.on_read {
            f();
        }
        self.inner.read_entry(name)
    }
    fn close(&self) {
        self.inner.close()
    }
}

fn counting<'a>(w: &'a RegWorld) -> Counting<'a> {
    Counting {
        inner: corpus(w),
        opens: AtomicU32::new(0),
        on_read: None,
    }
}

/// Runs a hook right after a successful `start`.
struct AfterStart<'a, L: RunLedger> {
    inner: L,
    hook: Box<dyn Fn() + Send + Sync + 'a>,
}

impl<L: RunLedger> RunLedger for AfterStart<'_, L> {
    fn start(&self) -> WResult<()> {
        self.inner.start()?;
        (self.hook)();
        Ok(())
    }
    fn fail_before_start(&self, r: ReasonCode) -> WResult<()> {
        self.inner.fail_before_start(r)
    }
    fn heartbeat(&self) -> WResult<()> {
        self.inner.heartbeat()
    }
    fn record_exposure(&self) -> WResult<()> {
        self.inner.record_exposure()
    }
    fn begin_validation(&self) -> WResult<()> {
        self.inner.begin_validation()
    }
    fn finish(&self, o: O, r: ReasonCode) -> WResult<()> {
        self.inner.finish(o, r)
    }
}

fn budget(w: &RegWorld) -> (u64, u64, u64) {
    let b = w
        .store
        .budget_status(BudgetKind::Run, &run_scope(&w.binding))
        .unwrap()
        .unwrap();
    (b.held, b.consumed, b.refunded)
}

fn state(w: &RegWorld, a: &RunId) -> (RunState, Exposure) {
    let r = w.store.attempt(a).unwrap().unwrap();
    (r.state, r.exposure)
}

fn flag_unreviewed(w: &RegWorld, n: u32) {
    let op = agent();
    let k = idk(n);
    w.manager(&NoFault)
        .report(
            &change(
                &w.epoch,
                &op,
                &k,
                EpochReason::UnreviewedPopulationChange,
                NOW + 2,
            ),
            Contamination::UnreviewedChange,
        )
        .unwrap();
}

fn guarded<'a>(
    w: &'a RegWorld,
    elig: &'a LifecycleEligibility<'a>,
    run: &Run,
    candidate: &CandidateDigest,
) -> GuardedRunLedger<'a, StoreRunLedger<'a>> {
    GuardedRunLedger::new(
        store_ledger(w, &run.attempt),
        elig,
        candidate.clone(),
        w.epoch.clone(),
        Arc::new(|| NOW + 1),
    )
}

fn dispatch(
    r: &Rig,
    run: &Run,
    ledger: &dyn RunLedger,
    corpus: &dyn CorpusPort,
) -> custodian_worker::reason::Result<custodian_worker::DispatchReport> {
    r.dispatcher().run_attempt(
        &DispatchJob {
            plan: &run.req.plan,
            sources: &r.sources,
        },
        ledger,
        corpus,
        &CancelToken::new(),
    )
}

#[test]
fn an_eligible_attempt_runs_through_the_guard_and_consumes_its_unit() {
    let w = RegWorld::new();
    let r = rig();
    let run = prepare_run(&w, &r, 1);
    let elig = LifecycleEligibility::new(&w.store);
    let cand = r.candidate();
    let c = counting(&w);
    let rep = dispatch(&r, &run, &guarded(&w, &elig, &run, &cand), &c).unwrap();
    assert_eq!((rep.outcome, rep.reason), (O::Success, W::Completed));
    assert_eq!(c.opens.load(Ordering::SeqCst), 1);
    assert_eq!(
        state(&w, &run.attempt),
        (RunState::Completed, Exposure::Exposed)
    );
    assert_eq!(budget(&w), (0, 1, 0));
}

#[test]
fn contamination_after_reservation_refuses_before_start_and_refunds() {
    let w = RegWorld::new();
    let r = rig();
    let run = prepare_run(&w, &r, 1);
    flag_unreviewed(&w, 1);
    let elig = LifecycleEligibility::new(&w.store);
    let c = counting(&w);
    let rep = dispatch(&r, &run, &guarded(&w, &elig, &run, &r.candidate()), &c).unwrap();
    assert_eq!(
        (rep.outcome, rep.reason),
        (O::Rejected, W::EligibilityDenied)
    );
    assert_eq!(rep.exposure, Exposure::NotExposed);
    assert!(rep.settled);
    // Nothing opened, nothing consumed: refunded, because no bytes were acquired.
    assert_eq!(c.opens.load(Ordering::SeqCst), 0);
    assert_eq!(
        state(&w, &run.attempt),
        (RunState::Failed, Exposure::NotExposed)
    );
    assert_eq!(budget(&w), (0, 0, 1));
    // The attempt cannot be started again, and a retry is refused too.
    assert!(w
        .store
        .start_attempt(&custodian_store::StartCommand {
            attempt: &run.attempt,
            owner: "late",
            actor: &actor(),
            now: NOW + 3,
            lease_secs: 300,
            observed: Some(&exec_obs(NOW + 3)),
            max_state_age_secs: 300,
        })
        .is_err());
    let (_, apr) = r.request(&w, &w.binding, 1);
    assert_eq!(
        w.store
            .retry_attempt(&custodian_store::RetryCommand {
                request: &run.req,
                approval: &apr,
                observed: &exec_obs(NOW),
                from_attempt_no: 1,
                now: ts(NOW + 4),
                max_state_age_secs: 300,
                reservation_window_secs: 600,
            })
            .unwrap_err(),
        custodian_store::StoreError::EpochBlocked
    );
    w.store.integrity_check().unwrap();
}

#[test]
fn the_store_gate_alone_catches_what_a_non_atomic_check_could_miss() {
    // No guard at all: the contamination commits after reservation and the
    // transaction that takes the lease refuses.
    let w = RegWorld::new();
    let r = rig();
    let run = prepare_run(&w, &r, 1);
    flag_unreviewed(&w, 1);
    let c = counting(&w);
    let rep = dispatch(&r, &run, &store_ledger(&w, &run.attempt), &c).unwrap();
    assert_eq!(
        (rep.outcome, rep.reason),
        (O::Rejected, W::EligibilityDenied)
    );
    assert_eq!(c.opens.load(Ordering::SeqCst), 0);
    assert_eq!(budget(&w), (0, 0, 1));
}

#[test]
fn contamination_between_start_and_exposure_stops_the_attempt_before_protected_bytes() {
    let w = RegWorld::new();
    let r = rig();
    let run = prepare_run(&w, &r, 1);
    let elig = LifecycleEligibility::new(&w.store);
    let cand = r.candidate();
    // The guard passes at start; the contamination commits right after the
    // lease is taken; the guard (and the store) refuse at the exposure gate.
    let ledger = AfterStart {
        inner: guarded(&w, &elig, &run, &cand),
        hook: Box::new(|| flag_unreviewed(&w, 1)),
    };
    let c = counting(&w);
    let rep = dispatch(&r, &run, &ledger, &c).unwrap();
    assert_eq!(
        (rep.outcome, rep.reason),
        (O::Rejected, W::EligibilityDenied)
    );
    assert_eq!(rep.exposure, Exposure::NotExposed);
    assert_eq!(c.opens.load(Ordering::SeqCst), 0);
    assert_eq!(
        state(&w, &run.attempt),
        (RunState::Failed, Exposure::NotExposed)
    );
    assert_eq!(budget(&w), (0, 0, 1));
}

#[test]
fn a_recorded_revocation_of_the_candidate_stops_dispatch_though_the_epoch_is_clean() {
    let w = RegWorld::new();
    let r = rig();
    let run = prepare_run(&w, &r, 1);
    let cand = r.candidate();
    w.store
        .enqueue_obligation(&ObligationCommand {
            obligation_id: "operator:withdrawn",
            target: ObligationTarget::Candidate,
            target_ref: cand.as_str(),
            action: ObligationAction::Revoked,
            superseded_by: None,
            reason: "error_correction",
            effective_at: NOW,
            actor: HUMAN,
            authorization_ref: "apr_synthetic000000000009",
            now: NOW,
        })
        .unwrap();
    // The store's gate knows epochs, not candidates: only the guard refuses.
    assert!(w.store.check_epoch_usable(w.epoch.as_str()).is_ok());
    let elig = LifecycleEligibility::new(&w.store);
    let c = counting(&w);
    let rep = dispatch(&r, &run, &guarded(&w, &elig, &run, &cand), &c).unwrap();
    assert_eq!(
        (rep.outcome, rep.reason),
        (O::Rejected, W::EligibilityDenied)
    );
    assert_eq!(c.opens.load(Ordering::SeqCst), 0);
    assert_eq!(budget(&w), (0, 0, 1));
}

#[test]
fn an_attempt_already_exposed_when_contamination_lands_settles_consumed_and_cannot_be_released() {
    let w = RegWorld::new();
    let r = rig();
    let run = prepare_run(&w, &r, 1);
    let elig = LifecycleEligibility::new(&w.store);
    let cand = r.candidate();
    let mut c = counting(&w);
    let w_ref = &w;
    c.on_read = Some(Box::new(move || {
        // The contamination commits while the attempt is reading protected
        // bytes: the attempt is already exposed.
        let op = human();
        let k = idk(40);
        let _ = w_ref.manager(&NoFault).report(
            &change(&w_ref.epoch, &op, &k, EpochReason::ResultsExposed, NOW + 2),
            Contamination::Exposed,
        );
    }));
    let rep = dispatch(&r, &run, &guarded(&w, &elig, &run, &cand), &c).unwrap();
    // It was past every gate, so it finishes and settles truthfully: exposed
    // and consumed, never refunded.
    assert_eq!(rep.exposure, Exposure::Exposed);
    assert_eq!(budget(&w), (0, 1, 0));
    assert_eq!(state(&w, &run.attempt).1, Exposure::Exposed);
    // Its result cannot authorize anything: eligibility is refused from now on.
    assert_eq!(
        elig.evaluate(&cand, &w.epoch, ts(NOW + 10)),
        Err(custodian_disclosure::EligibilityRefusal::Contaminated)
    );
    w.store.integrity_check().unwrap();
    w.store.verify_lifecycle_invariants().unwrap();
}

#[test]
fn a_retired_epoch_is_refused_at_dispatch_and_its_old_attempt_state_is_untouched() {
    let w = RegWorld::new();
    let r = rig();
    let done = prepare_run(&w, &r, 1);
    let elig = LifecycleEligibility::new(&w.store);
    let cand = r.candidate();
    let rep = dispatch(&r, &done, &guarded(&w, &elig, &done, &cand), &counting(&w)).unwrap();
    assert_eq!(rep.outcome, O::Success);
    let before = (budget(&w), state(&w, &done.attempt));
    let pending = prepare_run(&w, &r, 2);
    let op = human();
    let k = idk(50);
    w.manager(&NoFault)
        .retire(&change(
            &w.epoch,
            &op,
            &k,
            EpochReason::PlannedRotation,
            NOW + 3,
        ))
        .unwrap();
    let rep = dispatch(
        &r,
        &pending,
        &guarded(&w, &elig, &pending, &cand),
        &counting(&w),
    )
    .unwrap();
    assert_eq!(rep.reason, W::EligibilityDenied);
    // History preserved: the earlier completed attempt and its consumption.
    assert_eq!(state(&w, &done.attempt), before.1);
    let (held, consumed, refunded) = budget(&w);
    assert_eq!(consumed, before.0 .1);
    assert_eq!((held, refunded), (0, 1));
    let _: &EpochId = &w.epoch;
}
