//! Dispatcher driving the REAL `custodian-store` (SQLite, tempdir) and the REAL
//! `custodian-corpus` (filesystem adapter, tempdir) with synthetic data. The
//! sandbox here is the unsandboxed test fake, so these tests prove the
//! control-plane integration (ordering, leases, exposure, settlement), not
//! isolation.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::*;
use custodian_contracts::common::{
    Attestation, Authorship, BudgetKind, BudgetScope, EvaluationDomain, GroundTruthClaim,
    IndependenceClaim, OrganisationalIndependence, ReviewStatus, RoleSeparation,
};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_contracts::types::{ActorRef, ConfigDigest, CorpusId, Count, EpochId, Timestamp};
use custodian_core::ports::Authorization;
use custodian_core::{ActorId, AuthorizationId, Exposure, PlanDigest, ReasonCode, RunId, RunState};
use custodian_corpus::seal::{Provenance, ProvenanceOrigin, ReviewRecord};
use custodian_corpus::testing::TempRoot;
use custodian_corpus::{
    population_id_for, EntryName, FsEpochStore, ProtectedBytes, ProtectedPopulations, SealInputs,
};
use custodian_store::{ReserveCommand, SqliteStore};
use custodian_worker::fake::TestOnlyUnsandboxedFake;
use custodian_worker::isolation::IsolationVerification;
use custodian_worker::ports::{CorpusPort, PopulationsCorpus, RunLedger, StoreRunLedger};
use custodian_worker::reason::Result as WResult;
use custodian_worker::sandbox::CancelToken;
use custodian_worker::{DispatchJob, Dispatcher, WorkerReason as R};

fn ts(s: u64) -> Timestamp {
    Timestamp::new(s).unwrap()
}

struct World {
    env: Env,
    tmp: TempRoot,
    pop: ProtectedPopulations<FsEpochStore>,
    store: SqliteStore,
    epoch: EpochId,
    population: serde_json::Value,
    domain: &'static str,
}

fn make_world(label: &str, domain: &'static str, entries: &[(&str, &[u8])]) -> World {
    let env = Env::new(label);
    let tmp = TempRoot::new();
    let root = tmp.path().join("protected");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let pop = ProtectedPopulations::open_fs(&root).unwrap();
    let corpus = CorpusId::parse("cor_aaaaaaaaaaaaaaaa").unwrap();
    let d = if domain == "pii" {
        EvaluationDomain::Pii
    } else {
        EvaluationDomain::Credential
    };
    let w = pop.begin_epoch(corpus.clone(), d, None).unwrap();
    for (n, b) in entries {
        pop.add_entry(&w, &EntryName::parse(n).unwrap(), b).unwrap();
    }
    let epoch = w.epoch_id().clone();
    let inputs = SealInputs {
        custody_version: Count::new(1).unwrap(),
        config_digest: ConfigDigest::from_raw([7u8; 32]),
        budget: BudgetScope::PopulationEpoch {
            corpus_id: corpus,
            epoch_id: epoch.clone(),
            family_id: None,
        },
        provenance: Provenance {
            origin: ProvenanceOrigin::SyntheticGenerated,
            generator: None,
            observed_at: ts(NOW),
        },
        review: ReviewRecord {
            reviewer: ActorRef::parse("act_bbbbbbbbbbbbbbbb").unwrap(),
            reviewed_at: ts(NOW),
            attestation: Attestation {
                independence: IndependenceClaim::CustodianDeclared,
                role_separation: RoleSeparation::SingleOperatorProcedural,
                organisational_independence: OrganisationalIndependence::NotClaimed,
                authorship: Authorship::ProjectAuthored,
                review: ReviewStatus::ProjectReviewed,
                ground_truth: GroundTruthClaim::NotEstablished,
            },
        },
        sealed_by: ActorRef::parse("act_cccccccccccccccc").unwrap(),
        sealed_at: ts(NOW),
    };
    let sealed = pop.seal(w, inputs).unwrap();
    pop.activate(&epoch, ts(NOW)).unwrap();
    let population = serde_json::to_value(&sealed.binding).unwrap();
    let store = SqliteStore::open(env.root.join("store").join("store.db")).unwrap();
    World {
        env,
        tmp,
        pop,
        store,
        epoch,
        population,
        domain,
    }
}

fn actor() -> ActorId {
    ActorId::new("act_synthetic_operator")
}

impl World {
    /// Reserve an attempt for the scenario and return everything needed to run it.
    fn reserve(
        &self,
        p: &Pinned,
        l: &Limits,
        n: u32,
    ) -> (custodian_contracts::request::EvaluationRequest, RunId) {
        let req = request(self.domain, p, l, &self.population, n);
        let apr = approval(&req, n);
        let obs = observed(self.domain);
        if self
            .store
            .budget_status(BudgetKind::Run, &req.plan.accounting.budget)
            .unwrap()
            .is_none()
        {
            self.store
                .provision_budget(
                    BudgetKind::Run,
                    &req.plan.accounting.budget,
                    5,
                    &actor(),
                    NOW,
                )
                .unwrap();
        }
        let out = self
            .store
            .reserve_request(&ReserveCommand {
                request: &req,
                approval: &apr,
                observed: &obs,
                now: ts(NOW),
                max_state_age_secs: 300,
                reservation_window_secs: 600,
            })
            .unwrap();
        (req, out.attempt)
    }

    fn ledger(&self, attempt: &RunId) -> StoreRunLedger<'_> {
        let domain = self.domain;
        StoreRunLedger::new(
            &self.store,
            attempt.clone(),
            "worker-synthetic-1",
            actor(),
            300,
            300,
            Arc::new(|| NOW),
            Arc::new(move || Some(observed(domain))),
        )
    }

    fn corpus(&self) -> PopulationsCorpus<'_, FsEpochStore> {
        PopulationsCorpus::new(
            &self.pop,
            Authorization {
                id: AuthorizationId::new("auth-synthetic"),
                actor: actor(),
                plan: PlanDigest::new("plan-synthetic"),
                population: population_id_for(&self.epoch),
                expires_at: 0,
            },
        )
    }

    fn dispatcher(&self) -> Dispatcher {
        Dispatcher::new_for_tests(
            Arc::new(TestOnlyUnsandboxedFake::new_not_isolated(
                self.env.scratch.clone(),
            )),
            IsolationVerification::test_only_not_isolated(NOW),
            self.env.config(),
        )
        .unwrap()
    }

    fn budget(&self, req: &custodian_contracts::request::EvaluationRequest) -> (u64, u64, u64) {
        let b = self
            .store
            .budget_status(BudgetKind::Run, &req.plan.accounting.budget)
            .unwrap()
            .unwrap();
        (b.held, b.consumed, b.refunded)
    }

    fn state(&self, a: &RunId) -> (RunState, Exposure) {
        let r = self.store.attempt(a).unwrap().unwrap();
        (r.state, r.exposure)
    }
}

const ENTRIES: &[(&str, &[u8])] = &[
    ("one", b"synthetic-one"),
    ("two", b"synthetic-two"),
    ("three", b"synthetic-three"),
];

/// A corpus wrapper proving exposure was already committed in the store at
/// the moment the protected bytes were opened.
struct ExposureChecked<'a> {
    inner: PopulationsCorpus<'a, FsEpochStore>,
    store: &'a SqliteStore,
    attempt: RunId,
    seen_exposed_at_open: std::sync::atomic::AtomicBool,
}

impl CorpusPort for ExposureChecked<'_> {
    fn open(&self) -> WResult<()> {
        let rec = self.store.attempt(&self.attempt).unwrap().unwrap();
        self.seen_exposed_at_open.store(
            rec.exposure == Exposure::Exposed && rec.state == RunState::Running,
            std::sync::atomic::Ordering::SeqCst,
        );
        self.inner.open()
    }
    fn binding(&self) -> WResult<custodian_contracts::common::PopulationBinding> {
        self.inner.binding()
    }
    fn entry_names(&self) -> WResult<Vec<String>> {
        self.inner.entry_names()
    }
    fn read_entry(&self, name: &str) -> WResult<ProtectedBytes> {
        self.inner.read_entry(name)
    }
    fn close(&self) {
        self.inner.close()
    }
}

#[test]
fn success_completes_and_consumes_with_exposure_committed_before_open() {
    for domain in ["credential", "pii"] {
        let w = make_world("ok", domain, ENTRIES);
        let p = pinned(&w.env, "a", "ok");
        let (req, attempt) = w.reserve(&p, &Limits::normal(), 1);
        let ledger = w.ledger(&attempt);
        let corpus = ExposureChecked {
            inner: w.corpus(),
            store: &w.store,
            attempt: attempt.clone(),
            seen_exposed_at_open: Default::default(),
        };
        let rep = w
            .dispatcher()
            .run_attempt(
                &DispatchJob {
                    plan: &req.plan,
                    sources: &p.sources,
                },
                &ledger,
                &corpus,
                &CancelToken::new(),
            )
            .unwrap();
        assert_eq!(
            (rep.outcome, rep.reason),
            (O::Success, R::Completed),
            "{domain}"
        );
        assert!(corpus
            .seen_exposed_at_open
            .load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(w.state(&attempt), (RunState::Completed, Exposure::Exposed));
        assert_eq!(rep.roster().unwrap().expected.get(), 3);
        // Settled once: consumed, not refunded.
        assert_eq!(w.budget(&req), (0, 1, 0));
        w.store.verify_invariants().unwrap();
        // Transition order: exposure before the validating state.
        let h = w.store.history(&attempt).unwrap();
        let exp = h.iter().position(|t| t.is_exposure).unwrap();
        let val = h.iter().position(|t| t.to == RunState::Validating).unwrap();
        assert!(exp < val);
        assert_eq!(w.env.staging_entries(), 0);
        let _ = &w.tmp;
    }
}

#[test]
fn crash_partial_and_rejected_results_fail_the_attempt_and_consume_the_budget() {
    for (mode, outcome) in [
        ("crash", O::Failed),
        ("partial", O::Partial),
        ("garbage", O::Rejected),
    ] {
        let w = make_world("fail", "credential", ENTRIES);
        let p = pinned(&w.env, "a", mode);
        let (req, attempt) = w.reserve(&p, &Limits::normal(), 1);
        let rep = w
            .dispatcher()
            .run_attempt(
                &DispatchJob {
                    plan: &req.plan,
                    sources: &p.sources,
                },
                &w.ledger(&attempt),
                &w.corpus(),
                &CancelToken::new(),
            )
            .unwrap();
        assert_eq!(rep.outcome, outcome, "{mode}");
        assert_eq!(
            w.state(&attempt),
            (RunState::Failed, Exposure::Exposed),
            "{mode}"
        );
        assert_eq!(
            w.budget(&req),
            (0, 1, 0),
            "{mode}: exposed work is never refunded"
        );
        w.store.verify_invariants().unwrap();
    }
}

#[test]
fn identity_mismatch_before_start_is_refunded_and_unexposed() {
    let w = make_world("pre", "credential", ENTRIES);
    let p = pinned(&w.env, "a", "ok");
    let (req, attempt) = w.reserve(&p, &Limits::normal(), 1);
    fs::write(&p.sources.engine, b"a different build").unwrap();
    let rep = w
        .dispatcher()
        .run_attempt(
            &DispatchJob {
                plan: &req.plan,
                sources: &p.sources,
            },
            &w.ledger(&attempt),
            &w.corpus(),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(
        (rep.outcome, rep.reason),
        (O::Rejected, R::IdentityMismatch)
    );
    assert_eq!(w.state(&attempt), (RunState::Failed, Exposure::NotExposed));
    assert_eq!(w.budget(&req), (0, 0, 1));
    w.store.verify_invariants().unwrap();
}

#[test]
fn tampered_protected_entry_fails_closed_after_exposure() {
    let w = make_world("tamper-corpus", "credential", ENTRIES);
    let p = pinned(&w.env, "a", "ok");
    let (req, attempt) = w.reserve(&p, &Limits::normal(), 1);
    // An owner-level attacker edits a sealed entry on disk.
    let entry: PathBuf = tmp_entry(w.tmp.path(), &w.epoch, "two");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&entry, b"tampered").unwrap();
    let rep = w
        .dispatcher()
        .run_attempt(
            &DispatchJob {
                plan: &req.plan,
                sources: &p.sources,
            },
            &w.ledger(&attempt),
            &w.corpus(),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!((rep.outcome, rep.reason), (O::Failed, R::CorpusUnavailable));
    assert_eq!(w.state(&attempt).0, RunState::Failed);
    assert!(
        rep.termination.is_none(),
        "no engine ran on a tampered corpus"
    );
    assert_eq!(w.budget(&req), (0, 1, 0));
}

fn tmp_entry(root: &Path, epoch: &EpochId, name: &str) -> PathBuf {
    root.join("protected")
        .join("sealed")
        .join(epoch.as_str())
        .join("entries")
        .join(name)
}

#[test]
fn cancel_in_the_store_fences_the_holder_and_stops_the_worker() {
    let w = make_world("cancel", "pii", ENTRIES);
    let token = format!("store-cancel-{}", std::process::id());
    let p = pinned(&w.env, "a", &format!("tree {token}"));
    let (req, attempt) = w.reserve(&p, &Limits::normal(), 1);
    let ledger = w.ledger(&attempt);
    let corpus = w.corpus();
    let disp = w.dispatcher();
    let rep = std::thread::scope(|s| {
        s.spawn(|| {
            wait_running(&token);
            w.store
                .cancel(&attempt, &actor(), ReasonCode::Cancelled, NOW)
                .unwrap();
        });
        disp.run_attempt(
            &DispatchJob {
                plan: &req.plan,
                sources: &p.sources,
            },
            &ledger,
            &corpus,
            &CancelToken::new(),
        )
        .unwrap()
    });
    assert_eq!(rep.outcome, O::Cancelled);
    assert_eq!(rep.reason, R::LeaseLost);
    assert!(
        !rep.settled,
        "a fenced holder must not settle; the store already did"
    );
    assert_eq!(w.state(&attempt), (RunState::Cancelled, Exposure::Exposed));
    assert_eq!(
        w.budget(&req),
        (0, 1, 0),
        "running attempt cancelled: presumed exposed, consumed"
    );
    assert!(wait_gone(&token));
    // The old lease token no longer works.
    assert_eq!(
        ledger
            .finish(O::Success, ReasonCode::Completed)
            .unwrap_err(),
        R::LeaseLost
    );
    w.store.verify_invariants().unwrap();
}

#[test]
fn duplicate_dispatch_of_a_started_attempt_is_refused() {
    let w = make_world("dup", "credential", ENTRIES);
    let p = pinned(&w.env, "a", "ok");
    let (req, attempt) = w.reserve(&p, &Limits::normal(), 1);
    let first = w.ledger(&attempt);
    first.start().unwrap();
    // A second dispatcher for the same attempt cannot take the lease.
    let rep = w.dispatcher().run_attempt(
        &DispatchJob {
            plan: &req.plan,
            sources: &p.sources,
        },
        &w.ledger(&attempt),
        &w.corpus(),
        &CancelToken::new(),
    );
    assert!(rep.is_err(), "second start must be refused");
    assert_eq!(w.state(&attempt).0, RunState::Running);
}
