//! Synthetic harness for the daemon tests. Every identity is an obviously
//! synthetic placeholder, every credential is generated inside a test, keys
//! are never written outside a private temporary directory, and the
//! "protected" population is a few readable placeholder bytes.
//!
//! The control plane underneath is the C12 pipeline harness (the real store,
//! a real sealed population, the real startup sequence, a software signer
//! standing in for the isolated one, the in-memory ledger backend). What this
//! harness adds is the daemon: the synthetic engine binary run as a real child
//! process through the UNSANDBOXED test fake (it proves protocol and control
//! flow, never isolation), pinned artifacts laid out by digest, request and
//! approval directories, and the pipeline over all of it.
//!
//! These tests are functional verification on public synthetic data with
//! project-maintained fixtures. They are not an independent evaluation.
#![allow(dead_code)]
#![allow(clippy::duplicate_mod)]

#[path = "../../../custodian-cli/tests/c12/mod.rs"]
pub mod c12;

pub mod stack;
pub mod verify;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub use c12::*;
use custodian_cli::startup::StoreActivations;
use custodian_contracts::common::{Authorship, ReviewStatus};
use custodian_contracts::request::EvaluationRequest;
use custodian_corpus::testing::TempRoot;
use custodian_corpus::FsEpochStore;
use custodian_daemon::clock::{ClockPin, PinnableClock};
use custodian_daemon::config::AttestationConfig;
use custodian_daemon::log::RecordingLog;
use custodian_daemon::pipeline::approvals::DirApprovals;
use custodian_daemon::pipeline::{
    Pipeline, PipelineFault, PipelinePoint, PipelineSettings, ScopeGuard,
};
use custodian_daemon::sink::DirSink;
use custodian_daemon::source::DirArtifacts;
use custodian_disclosure::testing::StaticNames;
use custodian_intake::checks::{CheckReporter, RecordingCheckSink};
use custodian_intake::config::IntakeConfig;
use custodian_store::{SqliteStore, StoreConfig};
use custodian_worker::artifacts::{hash_file, ArtifactAllowlist};
use custodian_worker::fake::TestOnlyUnsandboxedFake;
use custodian_worker::isolation::IsolationVerification;
use custodian_worker::{Dispatcher, DispatcherConfig};
use serde_json::{json, Value};

/// The synthetic engine, built by cargo for this test run.
pub const ENGINE_BIN: &str = env!("CARGO_BIN_EXE_custodian-synthetic-engine");

/// The self-check probe, run inside the real sandbox before a worker is built.
pub const PROBE_BIN: &str = env!("CARGO_BIN_EXE_custodian-daemon-probe");

/// A logged skip. A skipped test verified nothing and must not be counted as
/// isolation evidence; CI sets `CUSTODIAN_REQUIRE_ISOLATION=1`, which turns
/// every skip into a failure.
pub fn skip(name: &str, why: &str) {
    eprintln!("ISOLATION-TEST-SKIPPED {name}: {why}");
    if std::env::var("CUSTODIAN_REQUIRE_ISOLATION").as_deref() == Ok("1") {
        panic!("isolation required but unavailable for {name}: {why}");
    }
}

/// The real worker for `env`, after the real self-check, or `None` (a logged
/// skip) where isolation cannot be shown. Linux with bubblewrap only.
pub fn real_worker(env: &Env, name: &str) -> Option<Dispatcher> {
    use custodian_worker::bwrap::BubblewrapSandbox;
    use custodian_worker::run_self_check;
    if !cfg!(target_os = "linux") {
        skip(
            name,
            &format!("platform is {}, not linux", std::env::consts::OS),
        );
        return None;
    }
    let sandbox = match BubblewrapSandbox::detect() {
        Ok(s) => s,
        Err(e) => {
            skip(name, &format!("detect: {e}"));
            return None;
        }
    };
    let probe: PathBuf = env.art_dir.join("probe");
    fs::copy(PROBE_BIN, &probe).unwrap();
    set_mode(&probe, 0o755);
    let allowlist = ArtifactAllowlist::new(std::slice::from_ref(&env.art_dir)).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let verification = match run_self_check(
        &sandbox,
        &sandbox.launcher_version(),
        &probe,
        &allowlist,
        &env.p.arts.staging,
        now,
    ) {
        Ok(v) => v,
        Err(e) => {
            skip(name, &format!("self-check failed: {e}"));
            return None;
        }
    };
    let mut cfg = DispatcherConfig::new(env.p.arts.staging.clone(), allowlist);
    cfg.heartbeat_interval = std::time::Duration::from_millis(100);
    Some(Dispatcher::new(Arc::new(sandbox), verification, cfg).expect("verified worker"))
}

pub fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    set_mode(path, 0o700);
}

/// Fires once at a chosen pipeline point.
#[derive(Default)]
pub struct CrashAt(pub Mutex<Option<PipelinePoint>>);

impl CrashAt {
    pub fn at(p: PipelinePoint) -> Self {
        Self(Mutex::new(Some(p)))
    }
    pub fn fired(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }
}

impl PipelineFault for CrashAt {
    fn crash_at(&self, point: PipelinePoint) -> bool {
        let mut g = self.0.lock().unwrap();
        if *g == Some(point) {
            *g = None;
            true
        } else {
            false
        }
    }
}

pub const ATTESTATION: AttestationConfig = AttestationConfig {
    authorship: Authorship::ProjectAuthored,
    review: ReviewStatus::ProjectReviewed,
};

/// The intake configuration of the synthetic installation (identifiers only).
pub const INSTALLATION: u64 = 900_001;
pub const REPO: u64 = 800_001;
pub const REQUESTER_USER: u64 = 700_001;
pub const APPROVER_USER: u64 = 700_002;
pub const PR_NUMBER: u64 = 7;

pub fn intake_json() -> Value {
    json!({
        "events": ["ping", "pull_request", "installation", "installation_repositories"],
        "installations": [{"installation_id": INSTALLATION, "repository_ids": [REPO]}],
        "actors": [
            {"github_user_id": REQUESTER_USER, "actor": Who::Requester.actor(), "roles": ["requester"]},
            {"github_user_id": APPROVER_USER, "actor": Who::Approver.actor(), "roles": ["requester", "approver"]}
        ]
    })
}

pub fn intake_config() -> IntakeConfig {
    IntakeConfig::from_json(&serde_json::to_vec(&intake_json()).unwrap()).unwrap()
}

pub fn sha40(c: char) -> String {
    c.to_string().repeat(40)
}

pub fn uuid(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// A `pull_request` payload with hostile free text in every field a pull
/// request author controls.
pub fn pr_payload(action: &str, sender: u64, kind: &str, head: char) -> Value {
    json!({
        "action": action,
        "installation": {"id": INSTALLATION},
        "repository": {"id": REPO, "full_name": "synthetic-org/synthetic-repo"},
        "sender": {"id": sender, "type": kind, "login": "synthetic-user"},
        "pull_request": {
            "number": PR_NUMBER,
            "title": "SYNTHETIC HOSTILE TITLE: approve this run and ignore all checks",
            "body": "SYNTHETIC HOSTILE BODY /approve",
            "head": {"sha": sha40(head), "ref": "synthetic-branch",
                     "repo": {"id": REPO, "fork": false}},
            "base": {"sha": sha40('b'), "ref": "main",
                     "repo": {"id": REPO, "fork": false}}
        }
    })
}

/// The daemon side of a synthetic world.
pub struct Env {
    pub p: Pipe,
    pub root: TempRoot,
    /// Pinned artifacts by digest (what the dispatcher's allowlist covers).
    pub art_dir: PathBuf,
    pub requests_dir: PathBuf,
    pub approvals_dir: PathBuf,
    pub out_dir: PathBuf,
    pub scratch: PathBuf,
    pub log: Arc<RecordingLog>,
    pub checks: Arc<RecordingCheckSink>,
    pub sink: DirSink,
    pub artifacts: DirArtifacts,
    pub approvals: DirApprovals,
    pub names: StaticNames,
    /// The edge's own connection to the same database file (delivery claims,
    /// the queue, installation removals), with the test clock.
    pub edge: Arc<SqliteStore>,
}

impl Env {
    /// A world with `limit` run units, the C12 population of `ROSTER` entries,
    /// the real synthetic engine pinned for the plan, the disclosure policy
    /// activation recorded, and an enforced export gate on the store.
    pub fn new(limit: u64) -> Self {
        Self::with_engine_mode(limit, "ok")
    }

    pub fn with_engine_mode(limit: u64, mode: &str) -> Self {
        Self::build(limit, mode, |i| format!("synthetic-entry-{i}"))
    }

    /// Like `new`, with the bytes of each protected entry chosen by the caller
    /// (the leakage tests plant canaries here).
    pub fn with_entries(limit: u64, mode: &str, bytes: impl Fn(usize) -> String) -> Self {
        Self::build(limit, mode, bytes)
    }

    fn build(limit: u64, mode: &str, entry_bytes: impl Fn(usize) -> String) -> Self {
        let mut p = Pipe::with_entry_bytes(limit, ROSTER, entry_bytes);
        // The real engine binary and the mode it runs in replace the C12
        // placeholder bytes, BEFORE any request is built (the plan pins their
        // digests).
        let s = &p.arts.sources;
        fs::copy(ENGINE_BIN, &s.engine).unwrap();
        set_mode(&s.engine, 0o755);
        fs::write(&s.config, mode).unwrap();
        set_mode(&s.config, 0o644);

        let root = TempRoot::new();
        let art_dir = root.path().join("artifacts");
        let requests_dir = root.path().join("requests");
        let approvals_dir = root.path().join("approvals");
        let out_dir = root.path().join("released");
        let scratch = root.path().join("scratch");
        for d in [&art_dir, &requests_dir, &approvals_dir, &out_dir, &scratch] {
            private_dir(d);
        }
        // The deployment's store enforces the export gate (ADR 0116).
        p.w.rw.store =
            SqliteStore::open_with_config(p.w.rw.db.path(), StoreConfig::enforced()).unwrap();
        // The disclosure policy activation, recorded by an operator.
        let doc = serde_json::to_vec(&dc::activation_value(
            dc::disclosure_ref(),
            &cc::id("pac_", 2),
            1,
            "active",
        ))
        .unwrap();
        let o = p.w.run(
            Who::Operator,
            &custodian_cli::Command::PolicyImportActivation {
                document: doc,
                confirm_activation_id: cc::id("pac_", 2),
                confirm_sequence: 1,
            },
        );
        assert!(o.is_ok(), "{}", o.code());
        let edge = Arc::new(
            SqliteStore::open_with_config(
                p.w.rw.db.path(),
                StoreConfig::enforced().with_clock(p.w.clock.clone()),
            )
            .unwrap(),
        );
        let env = Self {
            edge,
            sink: DirSink::new(&out_dir),
            artifacts: DirArtifacts::new(&art_dir),
            approvals: DirApprovals::new(&approvals_dir),
            names: StaticNames(lc::opaque(1)),
            log: Arc::new(RecordingLog::new()),
            checks: Arc::new(RecordingCheckSink::new()),
            p,
            root,
            art_dir,
            requests_dir,
            approvals_dir,
            out_dir,
            scratch,
        };
        env.lay_out_artifacts();
        env
    }

    /// Copy every pinned artifact to `art_dir/<hex digest>`.
    pub fn lay_out_artifacts(&self) {
        let s = &self.p.arts.sources;
        let mut all = vec![&s.engine, &s.adapter, &s.candidate, &s.config];
        all.extend(s.scanners.iter());
        for src in all {
            let d = hash_file(src).unwrap();
            let hex = d.strip_prefix("sha256:").unwrap();
            let dst = self.art_dir.join(hex);
            fs::copy(src, &dst).unwrap();
            set_mode(&dst, 0o755);
        }
    }

    pub fn request(&self, n: u32) -> (EvaluationRequest, Vec<u8>) {
        self.p.request(n)
    }

    /// The worker: the real engine as a child process, NOT isolated.
    pub fn dispatcher(&self) -> Dispatcher {
        let mut cfg = DispatcherConfig::new(
            self.p.arts.staging.clone(),
            ArtifactAllowlist::new(std::slice::from_ref(&self.art_dir)).unwrap(),
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

    pub fn settings(&self) -> PipelineSettings {
        PipelineSettings {
            owner: "custodiand-test".to_owned(),
            worker_actor: "custodiand-test".to_owned(),
            lease_secs: 300,
            max_state_age_secs: 300,
            attestation: ATTESTATION,
            destination: custodian_contracts::types::DestinationId::parse(DEST).unwrap(),
            provision_release_budgets: true,
            policy: dc::policy(),
            policy_binding: policy_binding(),
            shutdown_grace: std::time::Duration::from_secs(5),
        }
    }

    /// Start the control plane (the real startup sequence) and run `f` with a
    /// pipeline over it.
    pub fn with_pipeline<R>(
        &self,
        fault: &dyn PipelineFault,
        f: impl FnOnce(&Pipeline<'_, FsEpochStore>, &custodian_cli::Service<'_, FsEpochStore>) -> R,
    ) -> R {
        self.try_with_pipeline(fault, f)
            .expect("the startup sequence refused")
    }

    /// Like `with_pipeline`, but `None` when the startup sequence refuses (a
    /// real daemon would exit; a crash test restarts).
    pub fn try_with_pipeline<R>(
        &self,
        fault: &dyn PipelineFault,
        f: impl FnOnce(&Pipeline<'_, FsEpochStore>, &custodian_cli::Service<'_, FsEpochStore>) -> R,
    ) -> Option<R> {
        let dispatcher = self.dispatcher();
        self.try_with_pipeline_using(&dispatcher, fault, f)
    }

    /// Like `try_with_pipeline` with a worker of the caller's choosing (the
    /// Linux test passes the real bubblewrap one).
    pub fn try_with_pipeline_using<R>(
        &self,
        dispatcher: &Dispatcher,
        fault: &dyn PipelineFault,
        f: impl FnOnce(&Pipeline<'_, FsEpochStore>, &custodian_cli::Service<'_, FsEpochStore>) -> R,
    ) -> Option<R> {
        // The same clock wrapping the daemon applies (`runtime::run`).
        let pin = ClockPin::new();
        let mut parts = self.p.w.parts();
        parts.clock = Arc::new(PinnableClock::new(self.p.w.clock.clone(), pin.clone()));
        let acts = StoreActivations::new(&self.p.w.rw.store, parts.clock.clone());
        let svc = custodian_cli::Service::start(parts.clone(), &startup_config(), &acts).ok()?;
        let reporter = CheckReporter::new(intake_config(), self.edge.clone(), self.checks.clone());
        let scope = ScopeGuard {
            config: intake_config(),
            registry: self.edge.clone(),
        };
        let pipeline = Pipeline {
            pin: &pin,
            parts: parts.clone(),
            svc: &svc,
            dispatcher: Some(dispatcher),
            artifacts: &self.artifacts,
            approvals: &self.approvals,
            sink: &self.sink,
            names: &self.names,
            checks: Some(&reporter),
            scope: Some(&scope),
            settings: self.settings(),
            log: self.log.as_ref(),
            fault,
        };
        Some(f(&pipeline, &svc))
    }

    /// Restart with a store connection that injects a fault.
    pub fn restart_store_with_fault(&mut self, fault: Arc<dyn custodian_store::FaultInjector>) {
        let path = self.p.w.rw.db.path();
        self.p.w.rw.store =
            SqliteStore::open_with_config(&path, StoreConfig::enforced().with_fault(fault))
                .unwrap();
    }

    /// Everything the ledger holds that mentions `needle`.
    pub fn ledger_count(&self, needle: &str) -> usize {
        self.p
            .w
            .ledger
            .paths()
            .iter()
            .filter(|p| {
                self.p
                    .w
                    .ledger
                    .raw(p)
                    .is_some_and(|b| String::from_utf8_lossy(&b).contains(needle))
            })
            .count()
    }

    /// Place the request document for (repository, pull request, head) where
    /// the daemon looks for it, and record the candidate the control plane
    /// staged from that commit.
    pub fn stage_request(&self, n: u32, pull_request: u64, head: char) {
        let (req, bytes) = self.request(n);
        self.stage_request_bytes(&bytes, pull_request, head);
        self.stage_commit(head, &req);
    }

    pub fn stage_request_bytes(&self, bytes: &[u8], pull_request: u64, head: char) {
        let path = self
            .requests_dir
            .join(format!("{REPO}-{pull_request}-{}.json", sha40(head)));
        fs::write(&path, bytes).unwrap();
        set_mode(&path, 0o600);
    }

    pub fn stage_commit(&self, head: char, req: &EvaluationRequest) {
        let dir = self.art_dir.join("commits");
        private_dir(&dir);
        let path = dir.join(format!("{}.json", sha40(head)));
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": "private-custodian.staged-candidate/1",
                "head_sha": sha40(head),
                "candidate": req.plan.candidate,
                "config_digest": req.plan.config_digest,
            }))
            .unwrap(),
        )
        .unwrap();
        set_mode(&path, 0o600);
    }

    /// The real request edge over the edge connection: signed deliveries.
    pub fn edge_intake(&self, secret: &[u8]) -> custodian_intake::webhook::Intake {
        custodian_intake::webhook::Intake::new(
            intake_config(),
            custodian_intake::config::WebhookSecret::new(secret.to_vec()).unwrap(),
            self.edge.clone(),
            self.edge.clone(),
            self.edge.clone(),
        )
    }

    /// An operator publishes the revocation feed (a human action).
    pub fn publish_feed(&self) {
        let o = self
            .p
            .w
            .run(Who::Operator, &custodian_cli::Command::FeedPublish);
        assert!(o.is_ok(), "feed publish: {}", o.code());
    }

    /// The human release approval for request `n`, bound to the run's
    /// execution id and prepared projection digest, written to the approvals
    /// directory. Returns the document.
    pub fn write_release_approval(&self, attempt: &custodian_core::RunId, n: u32) -> Value {
        let run = self
            .p
            .w
            .rw
            .store
            .pipeline_run(attempt)
            .unwrap()
            .expect("run");
        let mark = run.prepared.expect("prepared");
        let mut v = cc::approval_json();
        v["approval_id"] = json!(cc::id("apr_", 2));
        v["scope"] = json!({
            "operation": "release",
            "execution_id": run.execution_id.expect("execution id"),
            "projection_digest": mark.projection_digest,
            "disclosure_policy": dc::disclosure_ref()
        });
        v["activation"] = serde_json::to_value(policy_binding()).unwrap();
        v["issued_at"] = json!(NOW + 60);
        v["expires_at"] = json!(NOW + 3600);
        let (req, _) = self.request(n);
        let path = self
            .approvals_dir
            .join(format!("{}.json", req.request_id.as_str()));
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        set_mode(&path, 0o600);
        v
    }

    /// Submit and approve request `n` on the control plane (the CLI path);
    /// returns the attempt.
    pub fn approved(&self, n: u32) -> custodian_core::RunId {
        let (attempt, _) = self.p.reserve(n);
        attempt
    }

    /// The only moment the clock needs to move for a release.
    pub fn at(&self, secs: u64) {
        self.p.w.clock.set(secs);
    }

    pub fn store(&self) -> &SqliteStore {
        &self.p.w.rw.store
    }

    /// Simulate a restart: a new connection to the same file, enforced gate.
    pub fn restart_store(&mut self) {
        let path = self.p.w.rw.db.path();
        self.p.w.rw.store = SqliteStore::open_with_config(&path, StoreConfig::enforced()).unwrap();
        self.edge = Arc::new(
            SqliteStore::open_with_config(
                &path,
                StoreConfig::enforced().with_clock(self.p.w.clock.clone()),
            )
            .unwrap(),
        );
    }

    pub fn released_files(&self) -> Vec<PathBuf> {
        self.sink.delivered()
    }
}
