//! Synthetic fixtures for the worker tests. Everything is generated in
//! tempdirs; every "credential" is an obviously synthetic canary; no network
//! destination other than documentation/test addresses is used, and none is
//! reachable when isolation holds.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use custodian_contracts::approval::Approval;
use custodian_contracts::common::PopulationBinding;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::policy::{ObservedActivation, PolicyActivation};
use custodian_contracts::request::{EvaluationPlan, EvaluationRequest};
use custodian_contracts::types::{CandidateDigest, Timestamp};
use custodian_contracts::Contract;
use custodian_core::ReasonCode;
use custodian_corpus::ProtectedBytes;
use custodian_worker::artifacts::{hash_file, ArtifactAllowlist};
use custodian_worker::dispatcher::{ArtifactSources, DispatcherConfig};
use custodian_worker::ports::{CorpusPort, RunLedger};
use custodian_worker::reason::{Result as WResult, WorkerReason};
use serde_json::{json, Value};

pub const NOW: u64 = 1_800_000_000;
pub const FIXTURE_BIN: &str = env!("CARGO_BIN_EXE_custodian-worker-fixture");
pub const PROBE_BIN: &str = env!("CARGO_BIN_EXE_custodian-worker-probe");

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A private temp tree: `art/` (allowlisted artifacts), `staging/`, `scratch/`.
pub struct Env {
    pub root: PathBuf,
    pub art: PathBuf,
    pub staging: PathBuf,
    pub scratch: PathBuf,
}

fn mkdir(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

impl Env {
    pub fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = base.join(format!(
            "custodian-worker-test-{}-{label}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        mkdir(&root);
        let e = Self {
            art: root.join("art"),
            staging: root.join("staging"),
            scratch: root.join("scratch"),
            root,
        };
        mkdir(&e.art);
        mkdir(&e.staging);
        mkdir(&e.scratch);
        e
    }

    pub fn allowlist(&self) -> ArtifactAllowlist {
        ArtifactAllowlist::new(std::slice::from_ref(&self.art)).unwrap()
    }

    pub fn config(&self) -> DispatcherConfig {
        let mut c = DispatcherConfig::new(self.staging.clone(), self.allowlist());
        c.heartbeat_interval = std::time::Duration::from_millis(100);
        c
    }

    pub fn put(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let p = self.art.join(name);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    /// Entries left in the staging base (must be empty after every run).
    pub fn staging_entries(&self) -> usize {
        fs::read_dir(&self.staging).unwrap().count()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Pinned artifacts for one scenario. The "engine" is the fixture binary and
/// its behavior is the first line of `config`.
pub struct Pinned {
    pub sources: ArtifactSources,
}

pub fn pinned(env: &Env, tag: &str, mode_line: &str) -> Pinned {
    let engine = env.art.join(format!("engine-{tag}"));
    fs::copy(FIXTURE_BIN, &engine).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
    Pinned {
        sources: ArtifactSources {
            engine,
            adapter: env.put(&format!("adapter-{tag}"), b"synthetic adapter v1", 0o755),
            scanners: vec![env.put(&format!("scanner-{tag}"), b"synthetic scanner v1", 0o755)],
            candidate: env.put(
                &format!("candidate-{tag}"),
                b"synthetic candidate v1",
                0o755,
            ),
            config: env.put(&format!("config-{tag}"), mode_line.as_bytes(), 0o644),
        },
    }
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub cpu: u64,
    pub wall: u64,
    pub mem_mib: u64,
    pub storage_mib: u64,
    pub procs: u64,
    pub out: u64,
}

impl Limits {
    pub fn normal() -> Self {
        Self {
            cpu: 30,
            wall: 20,
            mem_mib: 512,
            storage_mib: 64,
            procs: 32,
            out: 1_048_576,
        }
    }
}

pub fn dg(label: &str) -> String {
    CandidateDigest::of_bytes(label.as_bytes())
        .as_str()
        .to_owned()
}

pub fn id(prefix: &str, n: u32) -> String {
    format!("{prefix}synthetic{n:012}")
}

pub fn synthetic_population(domain: &str) -> Value {
    json!({
        "domain": domain,
        "corpus_id": id("cor_", 1),
        "epoch_id": id("epo_", 1),
        "population_digest": dg("synthetic-population"),
        "custody_version": 1
    })
}

fn artifact(name: &str, path: &Path) -> Value {
    json!({"name": name, "version": "0.0.1", "digest": hash_file(path).unwrap()})
}

fn activation_ref(domain: &str) -> Value {
    json!({
        "policy": {"kind":"approval","domain":domain,"name":"synthetic-approval","version":1},
        "activation_id": id("pac_", 1),
        "sequence": 3
    })
}

pub fn scope_json(population: &Value) -> Value {
    json!({"scope":"population_epoch","corpus_id": population["corpus_id"],
           "epoch_id": population["epoch_id"]})
}

pub fn plan_json(domain: &str, p: &Pinned, l: &Limits, population: &Value) -> Value {
    json!({
        "domain": domain,
        "purpose": "conformance_control",
        "candidate": hash_file(&p.sources.candidate).unwrap(),
        "engine": artifact("synthetic-engine", &p.sources.engine),
        "adapter": artifact("synthetic-adapter", &p.sources.adapter),
        "scanners": [artifact("synthetic-scanner", &p.sources.scanners[0])],
        "protocol": {"domain": domain, "name":"synthetic-protocol", "version":"1"},
        "config_digest": hash_file(&p.sources.config).unwrap(),
        "policy_activation": activation_ref(domain),
        "population": population,
        "accounting": {"kind":"run","budget": scope_json(population),"units":1,"max_retries":1},
        "seed_policy": "custodian_held_fixed",
        "limits": {"cpu_seconds": l.cpu, "wall_seconds": l.wall, "memory_mib": l.mem_mib,
                   "storage_mib": l.storage_mib, "max_processes": l.procs,
                   "max_output_bytes": l.out},
        "disclosure_policy": {"kind":"disclosure","domain":domain,"name":"synthetic-disclosure","version":1}
    })
}

pub fn request(
    domain: &str,
    p: &Pinned,
    l: &Limits,
    population: &Value,
    n: u32,
) -> EvaluationRequest {
    let v = json!({
        "schema": "private-custodian.request/1",
        "request_id": id("req_", n),
        "idempotency_key": id("idk_", n),
        "asserted_actor": id("act_", 1),
        "requested_at": NOW,
        "plan": plan_json(domain, p, l, population)
    });
    EvaluationRequest::decode(&serde_json::to_vec(&v).unwrap()).unwrap()
}

pub fn plan(domain: &str, p: &Pinned, l: &Limits) -> EvaluationPlan {
    request(domain, p, l, &synthetic_population(domain), 1).plan
}

pub fn approval(req: &EvaluationRequest, n: u32) -> Approval {
    let pop = serde_json::to_value(&req.plan.population).unwrap();
    let v = json!({
        "schema": "private-custodian.approval/1",
        "approval_id": id("apr_", n),
        "scope": {
            "operation": "execute",
            "request_id": id("req_", n),
            "plan_digest": req.plan.plan_digest().unwrap().as_str(),
            "candidate": req.plan.candidate.as_str(),
            "population": pop,
            "budget": scope_json(&pop)
        },
        "activation": activation_ref(pop["domain"].as_str().unwrap()),
        "proposer": id("act_", 1),
        "approver": id("act_", 2),
        "approver_kind": "human",
        "role_separation": "distinct_principals_procedural",
        "issued_at": NOW,
        "expires_at": NOW + 3600
    });
    Approval::decode(&serde_json::to_vec(&v).unwrap()).unwrap()
}

pub fn observed(domain: &str) -> ObservedActivation {
    let v = json!({
        "schema": "private-custodian.policy-activation/1",
        "policy": {"kind":"approval","domain":domain,"name":"synthetic-approval","version":1},
        "activation_id": id("pac_", 1),
        "sequence": 3,
        "status": "active",
        "activates_at": NOW - 1000,
        "expires_at": NOW + 100_000,
        "changed_at": NOW - 1000
    });
    ObservedActivation {
        activation: PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap(),
        observed_at: Timestamp::new(NOW).unwrap(),
    }
}

// ---- recording fakes ------------------------------------------------------

pub type Log = Arc<Mutex<Vec<String>>>;

pub fn log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

pub fn events(l: &Log) -> Vec<String> {
    l.lock().unwrap().clone()
}

pub struct RecLedger {
    pub log: Log,
    pub fail_start: Option<WorkerReason>,
    /// Heartbeat reports `LeaseLost` after this many successful beats.
    pub lose_lease_after_beats: Option<usize>,
    beats: Mutex<usize>,
}

impl RecLedger {
    pub fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            fail_start: None,
            lose_lease_after_beats: None,
            beats: Mutex::new(0),
        }
    }
}

impl RunLedger for RecLedger {
    fn start(&self) -> WResult<()> {
        if let Some(r) = self.fail_start {
            return Err(r);
        }
        self.log.lock().unwrap().push("ledger:start".into());
        Ok(())
    }
    fn fail_before_start(&self, reason: ReasonCode) -> WResult<()> {
        self.log
            .lock()
            .unwrap()
            .push(format!("ledger:fail_before_start:{reason:?}"));
        Ok(())
    }
    fn heartbeat(&self) -> WResult<()> {
        let mut b = self.beats.lock().unwrap();
        *b += 1;
        if self.lose_lease_after_beats.is_some_and(|n| *b > n) {
            return Err(WorkerReason::LeaseLost);
        }
        Ok(())
    }
    fn record_exposure(&self) -> WResult<()> {
        self.log.lock().unwrap().push("ledger:exposure".into());
        Ok(())
    }
    fn begin_validation(&self) -> WResult<()> {
        self.log
            .lock()
            .unwrap()
            .push("ledger:begin_validation".into());
        Ok(())
    }
    fn finish(&self, outcome: ExecutionOutcome, reason: ReasonCode) -> WResult<()> {
        self.log
            .lock()
            .unwrap()
            .push(format!("ledger:finish:{outcome:?}:{reason:?}"));
        Ok(())
    }
}

pub struct RecCorpus {
    pub log: Log,
    pub binding: PopulationBinding,
    pub entries: Vec<(String, Vec<u8>)>,
    pub open_fails: bool,
    /// Called on every read (tests use it to tamper mid-flight).
    pub on_read: Option<Box<dyn Fn() + Send + Sync>>,
}

impl RecCorpus {
    pub fn new(log: &Log, plan: &EvaluationPlan, n: usize) -> Self {
        Self {
            log: log.clone(),
            binding: serde_json::from_value(serde_json::to_value(&plan.population).unwrap())
                .unwrap(),
            entries: (0..n)
                .map(|i| {
                    (
                        format!("entry-{i}"),
                        format!("synthetic-input-{i}").into_bytes(),
                    )
                })
                .collect(),
            open_fails: false,
            on_read: None,
        }
    }
}

impl CorpusPort for RecCorpus {
    fn open(&self) -> WResult<()> {
        self.log.lock().unwrap().push("corpus:open".into());
        if self.open_fails {
            return Err(WorkerReason::CorpusUnavailable);
        }
        Ok(())
    }
    fn binding(&self) -> WResult<PopulationBinding> {
        Ok(self.binding.clone())
    }
    fn entry_names(&self) -> WResult<Vec<String>> {
        Ok(self.entries.iter().map(|(n, _)| n.clone()).collect())
    }
    fn read_entry(&self, name: &str) -> WResult<ProtectedBytes> {
        if let Some(f) = &self.on_read {
            f();
        }
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| ProtectedBytes::new(b.clone()))
            .ok_or(WorkerReason::CorpusUnavailable)
    }
    fn close(&self) {
        self.log.lock().unwrap().push("corpus:close".into());
    }
}

/// Is any process on this host running with `token` in its command line?
pub fn process_with_token_exists(token: &str) -> bool {
    let out = std::process::Command::new("ps")
        .args(["-axww", "-o", "command="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.contains(token) && !l.contains("ps -axww"))
}

pub fn wait_gone(token: &str) -> bool {
    for _ in 0..50 {
        if !process_with_token_exists(token) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}
