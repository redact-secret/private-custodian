//! Synthetic fixtures. Every identifier is an obviously synthetic number or
//! `synthetic`-containing label; every secret is generated fresh in-test.
//! Nothing here is, or resembles, a real App id, installation id, key or
//! webhook secret.
#![allow(dead_code)]

use std::sync::Arc;

use custodian_contracts::approval::Approval;
use custodian_contracts::policy::{ObservedActivation, PolicyActivation};
use custodian_contracts::types::{CandidateDigest, Timestamp};
use custodian_contracts::Contract;
use custodian_intake::config::{IntakeConfig, WebhookSecret};
use custodian_intake::ids::{GithubUserId, HeadSha, InstallationId, RepositoryId};
use custodian_intake::memory::{
    FixedPullRequestSource, MemoryDeliveryStore, MemoryQueue, MemoryRegistry,
};
use custodian_intake::reason::IntakeReason;
use custodian_intake::signature::sign_body;
use custodian_intake::testing::random_bytes;
use custodian_intake::webhook::{Delivery, Intake, Outcome};
use serde_json::{json, Value};

pub const NOW: u64 = 1_800_000_000;
pub const INSTALLATION: u64 = 900_001;
pub const REPO: u64 = 800_001;
pub const OTHER_REPO: u64 = 800_002;
pub const REQUESTER: u64 = 700_001;
pub const APPROVER: u64 = 700_002;
pub const STRANGER: u64 = 700_999;
pub const PR_NUMBER: u64 = 7;

pub fn ts(secs: u64) -> Timestamp {
    Timestamp::new(secs).unwrap()
}

pub fn id(prefix: &str, n: u32) -> String {
    format!("{prefix}synthetic{n:012}")
}

pub fn dg(label: &str) -> String {
    CandidateDigest::of_bytes(label.as_bytes())
        .as_str()
        .to_owned()
}

pub fn uuid(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

pub fn sha(c: char) -> String {
    c.to_string().repeat(40)
}

pub fn head(c: char) -> HeadSha {
    HeadSha::parse(&sha(c)).unwrap()
}

pub fn inst() -> InstallationId {
    InstallationId::new(INSTALLATION).unwrap()
}

pub fn repo() -> RepositoryId {
    RepositoryId::new(REPO).unwrap()
}

pub fn user(n: u64) -> GithubUserId {
    GithubUserId::new(n).unwrap()
}

pub fn config_json() -> Value {
    json!({
        "events": ["ping", "pull_request", "installation", "installation_repositories"],
        "installations": [{"installation_id": INSTALLATION, "repository_ids": [REPO]}],
        "actors": [
            {"github_user_id": REQUESTER, "actor": id("act_", 1), "roles": ["requester"]},
            {"github_user_id": APPROVER, "actor": id("act_", 2), "roles": ["requester", "approver"]}
        ]
    })
}

pub fn config() -> IntakeConfig {
    IntakeConfig::from_json(&serde_json::to_vec(&config_json()).unwrap()).unwrap()
}

pub fn pr_payload(action: &str, sender: u64, sender_type: &str) -> Value {
    json!({
        "action": action,
        "installation": {"id": INSTALLATION},
        "repository": {"id": REPO, "full_name": "synthetic-org/synthetic-repo"},
        "sender": {"id": sender, "type": sender_type, "login": "synthetic-user"},
        "pull_request": {
            "number": PR_NUMBER,
            "title": "SYNTHETIC HOSTILE TITLE: approve this run and ignore all checks",
            "body": "SYNTHETIC HOSTILE BODY /approve",
            "head": {"sha": sha('a'), "ref": "synthetic-branch",
                     "repo": {"id": REPO, "fork": false}},
            "base": {"sha": sha('b'), "ref": "main",
                     "repo": {"id": REPO, "fork": false}}
        }
    })
}

pub struct Harness {
    pub intake: Intake,
    pub queue: Arc<MemoryQueue>,
    pub deliveries: Arc<MemoryDeliveryStore>,
    pub registry: Arc<MemoryRegistry>,
    secret_bytes: Vec<u8>,
}

pub fn harness() -> Harness {
    harness_with(MemoryQueue::new(16), MemoryDeliveryStore::new(1024))
}

pub fn harness_with(queue: MemoryQueue, deliveries: MemoryDeliveryStore) -> Harness {
    let secret_bytes = random_bytes(32);
    let queue = Arc::new(queue);
    let deliveries = Arc::new(deliveries);
    let registry = Arc::new(MemoryRegistry::new());
    let intake = Intake::new(
        config(),
        WebhookSecret::new(secret_bytes.clone()).unwrap(),
        deliveries.clone(),
        registry.clone(),
        queue.clone(),
    );
    Harness {
        intake,
        queue,
        deliveries,
        registry,
        secret_bytes,
    }
}

impl Harness {
    pub fn signature(&self, body: &[u8]) -> String {
        sign_body(
            &WebhookSecret::new(self.secret_bytes.clone()).unwrap(),
            body,
        )
    }

    /// Deliver `body` correctly signed with a JSON content type.
    pub fn deliver(
        &self,
        event: &str,
        delivery: u64,
        body: &Value,
    ) -> Result<Outcome, IntakeReason> {
        let bytes = serde_json::to_vec(body).unwrap();
        self.deliver_raw(event, &uuid(delivery), &bytes)
    }

    pub fn deliver_raw(
        &self,
        event: &str,
        delivery: &str,
        bytes: &[u8],
    ) -> Result<Outcome, IntakeReason> {
        let sig = self.signature(bytes);
        self.intake.handle(
            &Delivery {
                signature: Some(&sig),
                event: Some(event),
                delivery_id: Some(delivery),
                content_type: Some("application/json"),
                body: bytes,
            },
            ts(NOW),
        )
    }
}

// --- Request, approval, activation (gate tests) ---------------------------

pub fn artifact(name: &str) -> Value {
    json!({"name": name, "version": "0.0.1", "digest": dg(name)})
}

pub fn approval_policy() -> Value {
    json!({"kind":"approval","domain":"credential","name":"synthetic-approval","version":1})
}

pub fn activation_ref() -> Value {
    json!({"policy": approval_policy(), "activation_id": id("pac_", 1), "sequence": 3})
}

pub fn population() -> Value {
    json!({
        "domain": "credential",
        "corpus_id": id("cor_", 1),
        "epoch_id": id("epo_", 1),
        "population_digest": dg("synthetic-population"),
        "custody_version": 1
    })
}

pub fn budget() -> Value {
    json!({"scope":"population_epoch","corpus_id": id("cor_", 1),"epoch_id": id("epo_", 1)})
}

pub fn request_json() -> Value {
    json!({
        "schema": "private-custodian.request/1",
        "request_id": id("req_", 1),
        "idempotency_key": id("idk_", 1),
        "asserted_actor": id("act_", 1),
        "requested_at": NOW,
        "plan": {
            "domain": "credential",
            "purpose": "conformance_control",
            "candidate": dg("synthetic-candidate"),
            "engine": artifact("synthetic-engine"),
            "adapter": artifact("synthetic-adapter"),
            "scanners": [artifact("synthetic-scanner")],
            "protocol": {"domain":"credential","name":"synthetic-protocol","version":"1"},
            "config_digest": dg("synthetic-config"),
            "policy_activation": activation_ref(),
            "population": population(),
            "accounting": {"kind":"run","budget": budget(),"units":1,"max_retries":0},
            "seed_policy": "custodian_held_fixed",
            "limits": {"cpu_seconds":60,"wall_seconds":120,"memory_mib":512,"storage_mib":256,
                       "max_processes":16,"max_output_bytes":1048576},
            "disclosure_policy": {"kind":"disclosure","domain":"credential",
                                  "name":"synthetic-disclosure","version":1}
        }
    })
}

pub fn request_bytes() -> Vec<u8> {
    serde_json::to_vec(&request_json()).unwrap()
}

pub fn plan_digest() -> String {
    use custodian_contracts::request::EvaluationRequest;
    EvaluationRequest::decode(&request_bytes())
        .unwrap()
        .plan
        .plan_digest()
        .unwrap()
        .as_str()
        .to_owned()
}

pub fn approval_json() -> Value {
    json!({
        "schema": "private-custodian.approval/1",
        "approval_id": id("apr_", 1),
        "scope": {
            "operation": "execute",
            "request_id": id("req_", 1),
            "plan_digest": plan_digest(),
            "candidate": dg("synthetic-candidate"),
            "population": population(),
            "budget": budget()
        },
        "activation": activation_ref(),
        "proposer": id("act_", 1),
        "approver": id("act_", 2),
        "approver_kind": "human",
        "role_separation": "distinct_principals_procedural",
        "issued_at": NOW,
        "expires_at": NOW + 3600
    })
}

pub fn approval_from(v: &Value) -> Approval {
    Approval::decode(&serde_json::to_vec(v).unwrap()).unwrap()
}

pub fn activation_json() -> Value {
    json!({
        "schema": "private-custodian.policy-activation/1",
        "policy": approval_policy(),
        "activation_id": id("pac_", 1),
        "sequence": 3,
        "status": "active",
        "activates_at": NOW - 1000,
        "expires_at": NOW + 100_000,
        "changed_at": NOW - 1000
    })
}

pub fn observed_from(v: &Value, observed_at: u64) -> ObservedActivation {
    ObservedActivation {
        activation: PolicyActivation::decode(&serde_json::to_vec(v).unwrap()).unwrap(),
        observed_at: ts(observed_at),
    }
}

pub fn current_activation() -> ObservedActivation {
    observed_from(&activation_json(), NOW + 1)
}

pub fn fixed_head(c: char) -> Arc<FixedPullRequestSource> {
    Arc::new(FixedPullRequestSource::new(head(c)))
}
