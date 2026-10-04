//! Minimal synthetic store fixtures for the crash-matrix tests. Trimmed from
//! the pattern already used by `custodian-store`'s and `custodian-worker`'s
//! own integration tests (one population-scoped budget, one request, one
//! approval, one observed activation); every identity and digest here is an
//! obviously synthetic placeholder. No protected data, no secrets, no
//! network.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use custodian_contracts::approval::Approval;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::policy::{ObservedActivation, PolicyActivation};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::CandidateDigest;
use custodian_contracts::Contract;
use custodian_core::ActorId;
use custodian_store::{BudgetStatus, ReserveCommand, ReserveOutcome, SqliteStore, StoreError};
use serde_json::{json, Value};

pub const NOW: u64 = 1_800_000_000;
pub const WINDOW: u64 = 600;
pub const LEASE: u64 = 300;
pub const MAX_AGE: u64 = 300;

pub fn id(prefix: &str, n: u32) -> String {
    format!("{prefix}synthetic{n:012}")
}

pub fn dg(label: &str) -> String {
    CandidateDigest::of_bytes(label.as_bytes())
        .as_str()
        .to_owned()
}

fn artifact(name: &str) -> Value {
    json!({"name": name, "version": "0.0.1", "digest": dg(name)})
}

fn activation_ref() -> Value {
    json!({
        "policy": {"kind":"approval","domain":"credential","name":"synthetic-approval","version":1},
        "activation_id": id("pac_", 1),
        "sequence": 3
    })
}

/// Each fixture gets its own population/epoch, so each gets its own budget
/// scope: tests that create more than one fixture must not see one
/// fixture's settlement bleed into another's budget status.
fn population(n: u32) -> Value {
    json!({
        "domain": "credential",
        "corpus_id": id("cor_", n),
        "epoch_id": id("epo_", n),
        "population_digest": dg("synthetic-population"),
        "custody_version": 1
    })
}

fn scope_json(n: u32) -> Value {
    json!({"scope":"population_epoch","corpus_id": id("cor_", n),"epoch_id": id("epo_", n)})
}

pub struct Fx {
    pub req: EvaluationRequest,
    pub apr: Approval,
    pub obs: ObservedActivation,
}

impl Fx {
    pub fn scope(&self) -> custodian_contracts::common::BudgetScope {
        self.req.plan.accounting.budget.clone()
    }
    pub fn request_id(&self) -> String {
        self.req.request_id.as_str().to_owned()
    }
    pub fn cmd(&self) -> ReserveCommand<'_> {
        ReserveCommand {
            request: &self.req,
            approval: &self.apr,
            observed: &self.obs,
            now: custodian_contracts::types::Timestamp::new(NOW).unwrap(),
            max_state_age_secs: MAX_AGE,
            reservation_window_secs: WINDOW,
        }
    }
}

/// One reservable fixture: candidate `n`, one unit, own request/approval.
pub fn fixture(n: u32) -> Fx {
    let candidate = format!("synthetic-candidate-{n}");
    let plan = json!({
        "domain": "credential",
        "purpose": "conformance_control",
        "candidate": dg(&candidate),
        "engine": artifact("synthetic-engine"),
        "adapter": artifact("synthetic-adapter"),
        "scanners": [artifact("synthetic-scanner")],
        "protocol": {"domain":"credential","name":"synthetic-protocol","version":"1"},
        "config_digest": dg("synthetic-config"),
        "policy_activation": activation_ref(),
        "population": population(n),
        "accounting": {"kind":"run","budget": scope_json(n),"units":1,"max_retries":1},
        "seed_policy": "custodian_held_fixed",
        "limits": {"cpu_seconds":60,"wall_seconds":120,"memory_mib":512,"storage_mib":256,
                   "max_processes":16,"max_output_bytes":1048576},
        "disclosure_policy": {"kind":"disclosure","domain":"credential","name":"synthetic-disclosure","version":1}
    });
    let req_json = json!({
        "schema": "private-custodian.request/1",
        "request_id": id("req_", n),
        "idempotency_key": id("idk_", n),
        "asserted_actor": id("act_", 1),
        "requested_at": NOW,
        "plan": plan
    });
    let req = EvaluationRequest::decode(&serde_json::to_vec(&req_json).unwrap()).unwrap();
    let apr_json = json!({
        "schema": "private-custodian.approval/1",
        "approval_id": id("apr_", n),
        "scope": {
            "operation": "execute",
            "request_id": id("req_", n),
            "plan_digest": req.plan.plan_digest().unwrap().as_str(),
            "candidate": dg(&candidate),
            "population": population(n),
            "budget": scope_json(n)
        },
        "activation": activation_ref(),
        "proposer": id("act_", 1),
        "approver": id("act_", 2),
        "approver_kind": "human",
        "role_separation": "distinct_principals_procedural",
        "issued_at": NOW,
        "expires_at": NOW + 3600
    });
    let apr = Approval::decode(&serde_json::to_vec(&apr_json).unwrap()).unwrap();
    Fx {
        req,
        apr,
        obs: observed(NOW, "active"),
    }
}

pub fn observed(observed_at: u64, status: &str) -> ObservedActivation {
    let v = json!({
        "schema": "private-custodian.policy-activation/1",
        "policy": {"kind":"approval","domain":"credential","name":"synthetic-approval","version":1},
        "activation_id": id("pac_", 1),
        "sequence": 3,
        "status": status,
        "activates_at": NOW - 1000,
        "expires_at": NOW + 100_000,
        "changed_at": NOW - 1000
    });
    ObservedActivation {
        activation: PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap(),
        observed_at: custodian_contracts::types::Timestamp::new(observed_at).unwrap(),
    }
}

pub fn actor() -> ActorId {
    ActorId::new("act_synthetic_operator")
}

/// A temporary directory that removes itself. The store creates the
/// directory itself (0700), so only the path is reserved here.
pub struct TempDb {
    dir: PathBuf,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDb {
    pub fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "custodian-worker-microvm-test-{}-{label}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Self { dir }
    }
    pub fn path(&self) -> PathBuf {
        self.dir.join("store.db")
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn open(db: &TempDb) -> SqliteStore {
    SqliteStore::open(db.path()).unwrap()
}

/// Provision the fixture's budget with `limit` units.
pub fn provision(store: &SqliteStore, fx: &Fx, limit: u64) {
    store
        .provision_budget(BudgetKind::Run, &fx.scope(), limit, &actor(), NOW)
        .unwrap();
}

pub fn reserve(store: &SqliteStore, fx: &Fx) -> Result<ReserveOutcome, StoreError> {
    store.reserve_request(&fx.cmd())
}

fn budget_status(store: &SqliteStore, fx: &Fx) -> BudgetStatus {
    store
        .budget_status(BudgetKind::Run, &fx.scope())
        .unwrap()
        .unwrap()
}

/// `(held, consumed, refunded)` units for the fixture's budget.
pub fn status(store: &SqliteStore, fx: &Fx) -> (u64, u64, u64) {
    let b = budget_status(store, fx);
    (b.held, b.consumed, b.refunded)
}
