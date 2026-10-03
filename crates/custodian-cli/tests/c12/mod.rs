//! Shared synthetic pipeline for the C12 operational-readiness tests.
//!
//! One `Pipe` wires every layer the earlier issues built, with synthetic data
//! only: the operator CLI (`custodian-cli`), the SQLite runtime store, a real
//! sealed protected-population root, the dispatcher with an in-process
//! scripted sandbox, the ledger exporter over the in-memory backend, the
//! disclosure service, the revocation feed publisher and the benchmarks-side
//! bridge consumer. Keys are generated inside each test and never written
//! down. The scripted sandbox is a test double: it proves control-plane
//! behavior, never isolation (the real bubblewrap tests run in the
//! `worker-isolation` CI job).
//!
//! These tests prove mechanism with project-maintained synthetic fixtures.
//! They are not independent validation and say nothing about corpus quality.
#![allow(dead_code)]
// The shared fixtures of several crates are included by path, and two of them
// include the same contract and store fixtures. Duplicate loading is intended.
#![allow(clippy::duplicate_mod)]

#[path = "../common/mod.rs"]
pub mod base;
#[path = "../../../custodian-disclosure/tests/common/mod.rs"]
pub mod dc;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub mod disclose;
#[allow(unused_imports)]
pub use disclose::*;

pub use base::{approve_cmd, cc, lc, sc, ClockExt, Who, World, NOW};
use custodian_cli::{Command, Service, StartupConfig, StoreActivations};
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::{BudgetKind, PolicyRef};
use custodian_contracts::execution::{ExecutionRecord, InternalReceipt};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::Reservation;
use custodian_core::ports::Authorization;
use custodian_core::{ActorId, AuthorizationId, PlanDigest, RunId};
use custodian_corpus::testing::TempRoot;
use custodian_corpus::{population_id_for, FsEpochStore};
use custodian_ledger::{Keyring, MemoryBackend, SignDomain};
use custodian_lifecycle::{MemoryFeed, NoFault};
use custodian_store::{ManualClock, SqliteStore};
use custodian_worker::artifacts::{hash_file, ArtifactAllowlist};
use custodian_worker::dispatcher::{ArtifactSources, DispatcherConfig};
use custodian_worker::isolation::IsolationVerification;
use custodian_worker::ports::{PopulationsCorpus, StoreRunLedger};
use custodian_worker::reason::Result as WResult;
use custodian_worker::sandbox::{
    CancelToken, RawRun, Sandbox, SandboxKind, SandboxSpec, Termination,
};
use custodian_worker::{DispatchJob, DispatchReport, Dispatcher};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const ROSTER: usize = 75;
pub const PREPARE_AT: u64 = dc::PREPARE_AT;
pub const RELEASE_AT: u64 = dc::RELEASE_AT;
pub const DEST: &str = "benchmarks-feed";

// ---- scripted sandbox -------------------------------------------------------

/// What the scripted sandbox does when the dispatcher runs it.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Print a valid `worker-result/1` for the authorized roster.
    Good,
    /// Print exactly these bytes and exit 0.
    Raw(Vec<u8>),
    /// Exit non-zero with nothing useful.
    Crash,
    /// Report a wall-clock timeout.
    Timeout,
    /// Report an output flood.
    Flood,
}

/// An in-process stand-in for the sandbox. Counts how many times the engine
/// "ran", so a test can prove there was no double execution.
pub struct Scripted {
    pub mode: Mutex<Mode>,
    pub runs: AtomicU32,
    pub roster: u64,
}

impl Scripted {
    pub fn new(roster: u64) -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(Mode::Good),
            runs: AtomicU32::new(0),
            roster,
        })
    }
    pub fn set(&self, m: Mode) {
        *self.mode.lock().unwrap() = m;
    }
    pub fn runs(&self) -> u32 {
        self.runs.load(Ordering::SeqCst)
    }
    pub fn good_stdout(roster: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "private-custodian.worker-result/1",
            "domain": "credential",
            "protocol": {"name": "synthetic-protocol", "version": "1"},
            "status": "complete",
            "roster": {"expected": roster, "observed": roster, "failed": 0}
        }))
        .unwrap()
    }
}

impl Sandbox for Scripted {
    fn kind(&self) -> SandboxKind {
        SandboxKind::TestOnlyUnsandboxedFake
    }

    fn run(
        &self,
        spec: &SandboxSpec,
        _cancel: &CancelToken,
        _keepalive: &mut dyn FnMut() -> bool,
    ) -> WResult<RawRun> {
        spec.validate()?;
        self.runs.fetch_add(1, Ordering::SeqCst);
        let (termination, stdout) = match self.mode.lock().unwrap().clone() {
            Mode::Good => (Termination::Exited(0), Self::good_stdout(self.roster)),
            Mode::Raw(b) => (Termination::Exited(0), b),
            Mode::Crash => (Termination::Exited(139), Vec::new()),
            Mode::Timeout => (Termination::TimedOut, Vec::new()),
            Mode::Flood => (Termination::OutputLimit, Vec::new()),
        };
        Ok(RawRun {
            termination,
            stdout,
            stderr_bytes: 0,
            elapsed: Duration::ZERO,
        })
    }
}

// ---- pinned artifacts -------------------------------------------------------

pub struct Artifacts {
    pub root: TempRoot,
    pub art: PathBuf,
    pub staging: PathBuf,
    pub sources: ArtifactSources,
}

fn mkdir(p: &std::path::Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

impl Artifacts {
    pub fn new() -> Self {
        let root = TempRoot::new();
        let art = root.path().join("art");
        let staging = root.path().join("staging");
        mkdir(&art);
        mkdir(&staging);
        let put = |name: &str, bytes: &[u8], mode: u32| {
            let p = art.join(name);
            fs::write(&p, bytes).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        let sources = ArtifactSources {
            engine: put("engine", b"synthetic engine v1", 0o755),
            adapter: put("adapter", b"synthetic adapter v1", 0o755),
            scanners: vec![put("scanner", b"synthetic scanner v1", 0o755)],
            candidate: put("candidate", b"synthetic candidate v1", 0o755),
            config: put("config", b"synthetic config v1", 0o644),
        };
        Self {
            root,
            art,
            staging,
            sources,
        }
    }

    pub fn dispatcher_config(&self) -> DispatcherConfig {
        let mut c = DispatcherConfig::new(
            self.staging.clone(),
            ArtifactAllowlist::new(std::slice::from_ref(&self.art)).unwrap(),
        );
        c.heartbeat_interval = Duration::from_millis(100);
        c
    }

    pub fn staging_entries(&self) -> usize {
        fs::read_dir(&self.staging).unwrap().count()
    }
}

// ---- the pipeline -----------------------------------------------------------

/// The pieces of one completed, validated execution that the disclosure
/// service needs. Assembled by the test: no production code builds an
/// execution record or internal receipt from a dispatch report yet (recorded
/// in docs/release-readiness.md).
pub struct Assembled {
    pub approval: Approval,
    pub reservation: Reservation,
    pub execution: ExecutionRecord,
    pub receipt: InternalReceipt,
    pub aggregates: Vec<u8>,
    pub attempt: RunId,
}

pub struct Pipe {
    pub w: World,
    pub arts: Artifacts,
    pub sandbox: Arc<Scripted>,
}

pub fn startup_config() -> StartupConfig {
    StartupConfig {
        guarded_policies: vec![
            serde_json::from_value::<PolicyRef>(cc::disclosure_policy()).unwrap()
        ],
        required_activations: vec![cc::request().plan.policy_activation.clone()],
        activation_max_age_secs: 300,
    }
}

impl Pipe {
    /// A world with `limit` run units and a sealed, active population of
    /// `entries` synthetic entries.
    pub fn new(limit: u64, entries: usize) -> Self {
        Self::with_entry_bytes(limit, entries, |i| format!("synthetic-entry-{i}"))
    }

    /// Like `new`, with the bytes of each protected entry chosen by the caller
    /// (the leakage tests plant canaries here).
    pub fn with_entry_bytes(limit: u64, entries: usize, bytes: impl Fn(usize) -> String) -> Self {
        let fx = lc::corpus::Fixture::new();
        let owned: Vec<(String, Vec<u8>)> = (0..entries)
            .map(|i| (format!("entry{i:04}"), bytes(i).into_bytes()))
            .collect();
        let refs: Vec<(&str, &[u8])> = owned
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let epoch = fx.seal_active(&refs);
        let binding = lc::binding_of(&fx, &epoch);
        let db = sc::TempDb::new("c12");
        let store = SqliteStore::open(db.path()).unwrap();
        let rw = lc::RegWorld {
            fx,
            db,
            store,
            epoch,
            binding,
            authority: lc::lenient_authority(),
        };
        rw.store
            .provision_budget(
                BudgetKind::Run,
                &lc::run_scope(&rw.binding),
                limit,
                &sc::actor(),
                NOW,
            )
            .unwrap();
        rw.store
            .record_activation(&cc::activation(), &sc::actor(), NOW)
            .unwrap();
        let key = lc::test_key(1, &SignDomain::ALL);
        let roots = Keyring::new().with_root(key.entry.clone());
        let pubs = lc::StaticPopulations::new().with(rw.epoch.as_str(), lc::opaque(1));
        let w = World {
            rw,
            authority: base::authority(),
            clock: Arc::new(ManualClock::new(NOW)),
            ledger: MemoryBackend::new(),
            key,
            roots,
            feed: MemoryFeed::new(),
            pubs,
            fault: NoFault,
        };
        Self {
            w,
            arts: Artifacts::new(),
            sandbox: Scripted::new(entries as u64),
        }
    }

    pub fn with_roster() -> Self {
        Self::new(3, ROSTER)
    }

    /// The synthetic request number `n`, asserted by the requester identity,
    /// bound to the real sealed population and to the real artifact digests.
    pub fn request(&self, n: u32) -> (EvaluationRequest, Vec<u8>) {
        let s = &self.arts.sources;
        let mut plan = cc::plan();
        plan["purpose"] = json!("protected_evaluation");
        plan["population"] = serde_json::to_value(&self.w.rw.binding).unwrap();
        plan["accounting"]["budget"] = lc::budget_json(&self.w.rw.binding);
        plan["accounting"]["max_retries"] = json!(1);
        let art = |name: &str, p: &std::path::Path| json!({"name": name, "version": "0.0.1", "digest": hash_file(p).unwrap()});
        plan["engine"] = art("synthetic-engine", &s.engine);
        plan["adapter"] = art("synthetic-adapter", &s.adapter);
        plan["scanners"] = json!([art("synthetic-scanner", &s.scanners[0])]);
        plan["candidate"] = json!(hash_file(&s.candidate).unwrap());
        plan["config_digest"] = json!(hash_file(&s.config).unwrap());
        let mut req = cc::request_json();
        req["request_id"] = json!(cc::id("req_", n));
        req["idempotency_key"] = json!(cc::id("idk_", n));
        req["plan"] = plan;
        let request: EvaluationRequest = cc::parse(&req);
        let bytes = request.canonical_bytes().unwrap();
        (request, bytes)
    }

    pub fn submit(&self, n: u32) -> custodian_cli::Output {
        let (_, doc) = self.request(n);
        self.w
            .run(Who::Requester, &Command::RequestSubmit { document: doc })
    }

    pub fn approve(&self, n: u32) -> custodian_cli::Output {
        let (req, _) = self.request(n);
        self.w.run(Who::Approver, &approve_cmd(&req))
    }

    /// Submit and approve request `n`; returns the run id and approval id.
    pub fn reserve(&self, n: u32) -> (RunId, String) {
        let s = self.submit(n);
        assert!(s.is_ok(), "submit: {}", s.code());
        let a = self.approve(n);
        assert!(a.is_ok(), "approve: {}", a.code());
        (
            RunId::new(a.field("attempt_id").unwrap().as_str().unwrap().to_owned()),
            a.field("approval_id").unwrap().as_str().unwrap().to_owned(),
        )
    }

    pub fn export(&self) -> custodian_cli::Output {
        self.w.run(
            Who::Operator,
            &Command::Repair(custodian_cli::command::RepairCommand::Export {
                confirm_store_id: self.w.rw.store.store_id().unwrap(),
            }),
        )
    }

    /// Start the control plane over the current wiring.
    pub fn start<'a>(
        &'a self,
        acts: &'a StoreActivations<'a>,
    ) -> Result<Service<'a, FsEpochStore>, custodian_cli::StartupFailure> {
        Service::start(self.w.parts(), &startup_config(), acts)
    }

    pub fn activations(&self) -> StoreActivations<'_> {
        StoreActivations::new(&self.w.rw.store, self.w.clock.clone())
    }

    pub fn dispatcher(&self) -> Dispatcher {
        Dispatcher::new_for_tests(
            self.sandbox.clone(),
            IsolationVerification::test_only_not_isolated(NOW),
            self.arts.dispatcher_config(),
        )
        .unwrap()
    }

    fn run_ledger<'s>(&self, store: &'s SqliteStore, attempt: &RunId) -> StoreRunLedger<'s> {
        let c1 = self.w.clock.clone();
        let c2 = self.w.clock.clone();
        StoreRunLedger::new(
            store,
            attempt.clone(),
            "worker-c12",
            ActorId::new("act_syntheticworker00001"),
            300,
            300,
            Arc::new(move || c1.as_ref_now()),
            Arc::new(move || Some(cc::observed(cc::activation(), c2.as_ref_now()))),
        )
    }

    fn corpus(&self) -> PopulationsCorpus<'_, FsEpochStore> {
        PopulationsCorpus::new(
            &self.w.rw.fx.pop,
            Authorization {
                id: AuthorizationId::new("auth-synthetic"),
                actor: ActorId::new("act_syntheticworker00001"),
                plan: PlanDigest::new("plan-synthetic"),
                population: population_id_for(&self.w.rw.epoch),
                expires_at: 0,
            },
        )
    }

    /// Dispatch the reserved `attempt` of request `n` through the guarded run
    /// ledger of `svc`, the real store and the real sealed population.
    pub fn dispatch(
        &self,
        svc: &Service<'_, FsEpochStore>,
        n: u32,
        attempt: &RunId,
    ) -> WResult<DispatchReport> {
        let (req, _) = self.request(n);
        self.dispatch_req(svc, &req, attempt)
    }

    /// Like `dispatch`, for a request document built earlier (so a test can
    /// change a pinned artifact afterwards and see the identity check refuse).
    pub fn dispatch_req(
        &self,
        svc: &Service<'_, FsEpochStore>,
        req: &EvaluationRequest,
        attempt: &RunId,
    ) -> WResult<DispatchReport> {
        let guarded = svc.guard_run_ledger(
            self.run_ledger(&self.w.rw.store, attempt),
            req.plan.candidate.clone(),
            self.w.rw.epoch.clone(),
        );
        self.dispatcher().run_attempt(
            &DispatchJob {
                plan: &req.plan,
                sources: &self.arts.sources,
            },
            &guarded,
            &self.corpus(),
            &CancelToken::new(),
        )
    }

    /// Dispatch on a given store connection without the startup wiring. Used
    /// by threads that each hold their own connection; the store's own epoch
    /// gate still applies.
    pub fn dispatch_on(
        &self,
        store: &SqliteStore,
        req: &EvaluationRequest,
        attempt: &RunId,
    ) -> WResult<DispatchReport> {
        self.dispatcher().run_attempt(
            &DispatchJob {
                plan: &req.plan,
                sources: &self.arts.sources,
            },
            &self.run_ledger(store, attempt),
            &self.corpus(),
            &CancelToken::new(),
        )
    }

    /// Dispatch with the R-2 export barrier installed (ADR 0116): `barrier`
    /// is the deployment's export pass, run before `start` and before the
    /// exposure record, and must report whether it drained.
    pub fn dispatch_gated(
        &self,
        req: &EvaluationRequest,
        attempt: &RunId,
        barrier: impl Fn() -> bool + Send + Sync,
    ) -> WResult<DispatchReport> {
        let ledger = self
            .run_ledger(&self.w.rw.store, attempt)
            .with_export_barrier(barrier);
        self.dispatcher().run_attempt(
            &DispatchJob {
                plan: &req.plan,
                sources: &self.arts.sources,
            },
            &ledger,
            &self.corpus(),
            &CancelToken::new(),
        )
    }

    /// Assemble the internal records for a completed attempt (see `Assembled`).
    pub fn assemble(
        &self,
        n: u32,
        attempt: &RunId,
        approval_id: &str,
        report: &DispatchReport,
    ) -> Assembled {
        let (req, _) = self.request(n);
        let plan_digest = req.plan.plan_digest().unwrap();
        let rec = self.w.rw.store.attempt(attempt).unwrap().unwrap();
        let rid = rec.reservation_id.clone().unwrap();
        let reservation = self.w.rw.store.reservation(&rid).unwrap().unwrap();
        let aggregates = serde_json::to_vec(&dc::aggregates_json()).unwrap();
        let roster = report.roster().expect("validated roster");
        let frozen = serde_json::to_value(req.plan.frozen_identities()).unwrap();
        let mut exe = cc::execution_json();
        exe["request_id"] = json!(req.request_id.as_str());
        exe["approval_id"] = json!(approval_id);
        exe["reservation_id"] = json!(rid);
        exe["plan_digest"] = json!(plan_digest.as_str());
        exe["activation"] = serde_json::to_value(&req.plan.policy_activation).unwrap();
        exe["frozen"] = frozen.clone();
        let execution: ExecutionRecord = cc::parse(&exe);
        let mut rcp = cc::receipt_json();
        rcp["plan_digest"] = json!(plan_digest.as_str());
        rcp["activation"] = serde_json::to_value(&req.plan.policy_activation).unwrap();
        rcp["frozen"] = frozen;
        rcp["result"] = json!({
            "digest": dc::sha_digest(&aggregates),
            "size_bytes": aggregates.len(),
            "protocol": serde_json::to_value(&req.plan.protocol).unwrap(),
        });
        rcp["roster"] = serde_json::to_value(roster).unwrap();
        let receipt: InternalReceipt = cc::parse(&rcp);
        let approval = self.execution_approval(&req, approval_id);
        Assembled {
            approval,
            reservation,
            execution,
            receipt,
            aggregates,
            attempt: attempt.clone(),
        }
    }

    /// The approval the CLI composed, rebuilt from the same fields.
    pub fn execution_approval(&self, req: &EvaluationRequest, approval_id: &str) -> Approval {
        let plan = &req.plan;
        let v = json!({
            "schema": "private-custodian.approval/1",
            "approval_id": approval_id,
            "scope": {
                "operation": "execute",
                "request_id": req.request_id,
                "plan_digest": plan.plan_digest().unwrap(),
                "candidate": plan.candidate,
                "population": plan.population,
                "budget": plan.accounting.budget,
            },
            "activation": plan.policy_activation,
            "proposer": req.asserted_actor,
            "approver": Who::Approver.actor(),
            "approver_kind": "human",
            "role_separation": "distinct_principals_procedural",
            "issued_at": NOW,
            "expires_at": NOW + 3600,
        });
        cc::parse(&v)
    }
}

pub fn disclosure_policy_ref() -> PolicyRef {
    serde_json::from_value(cc::disclosure_policy()).unwrap()
}

pub fn sha_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every string the CLI or the library printed, for leakage checks.
pub fn all_text(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| all_text(x, out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            out.push(k.clone());
            all_text(x, out)
        }),
        _ => {}
    }
}

pub fn policy_binding() -> custodian_contracts::common::ActivationRef {
    serde_json::from_value(json!({
        "policy": dc::disclosure_ref(), "activation_id": cc::id("pac_", 2), "sequence": 1
    }))
    .unwrap()
}

/// A release approval (a different approval id and a release scope) bound to
/// one prepared projection.
pub fn release_approval(prepared: &custodian_disclosure::PreparedRelease) -> Approval {
    let mut v = cc::approval_json();
    v["approval_id"] = json!(cc::id("apr_", 2));
    v["scope"] = json!({
        "operation": "release",
        "execution_id": prepared.execution_id().as_str(),
        "projection_digest": prepared.digest().as_str(),
        "disclosure_policy": dc::disclosure_ref()
    });
    v["activation"] = serde_json::to_value(policy_binding()).unwrap();
    v["issued_at"] = json!(NOW + 60);
    v["expires_at"] = json!(NOW + 3600);
    cc::parse(&v)
}
