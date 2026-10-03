//! Synthetic fixtures. Every identity is an obviously synthetic placeholder
//! and every digest is the SHA-256 of a readable synthetic label, so nothing
//! here can be mistaken for real material or traced to a protected asset.
#![allow(dead_code)]

use custodian_contracts::approval::Approval;
use custodian_contracts::execution::{ExecutionRecord, InternalReceipt};
use custodian_contracts::policy::{ObservedActivation, PolicyActivation};
use custodian_contracts::public::{PublicProjection, PublicProjectionEnvelope};
use custodian_contracts::public_v2::PublicProjectionV2;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::Reservation;
use custodian_contracts::revocation::{RevocationEnvelope, SignedRevocationEnvelope};
use custodian_contracts::types::{CandidateDigest, Timestamp};
use custodian_contracts::Contract;
use serde_json::{json, Value};

pub const NOW: u64 = 1_800_000_000;

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

pub fn sig() -> Value {
    json!({
        "key_id": id("key_", 1),
        "algorithm": "ed25519",
        "value": "A".repeat(86),
    })
}

pub fn artifact(name: &str) -> Value {
    json!({"name": name, "version": "0.0.1", "digest": dg(name)})
}

pub fn approval_policy() -> Value {
    json!({"kind":"approval","domain":"credential","name":"synthetic-approval","version":1})
}

pub fn disclosure_policy() -> Value {
    json!({"kind":"disclosure","domain":"credential","name":"synthetic-disclosure","version":1})
}

pub fn activation_ref() -> Value {
    json!({"policy": approval_policy(), "activation_id": id("pac_", 1), "sequence": 3})
}

pub fn protocol() -> Value {
    json!({"domain":"credential","name":"synthetic-protocol","version":"1"})
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

pub fn plan() -> Value {
    json!({
        "domain": "credential",
        "purpose": "conformance_control",
        "candidate": dg("synthetic-candidate"),
        "engine": artifact("synthetic-engine"),
        "adapter": artifact("synthetic-adapter"),
        "scanners": [artifact("synthetic-scanner")],
        "protocol": protocol(),
        "config_digest": dg("synthetic-config"),
        "policy_activation": activation_ref(),
        "population": population(),
        "accounting": {"kind":"run","budget": budget(),"units":1,"max_retries":0},
        "seed_policy": "custodian_held_fixed",
        "limits": {"cpu_seconds":60,"wall_seconds":120,"memory_mib":512,"storage_mib":256,
                   "max_processes":16,"max_output_bytes":1048576},
        "disclosure_policy": disclosure_policy()
    })
}

pub fn request_json() -> Value {
    json!({
        "schema": "private-custodian.request/1",
        "request_id": id("req_", 1),
        "idempotency_key": id("idk_", 1),
        "asserted_actor": id("act_", 1),
        "requested_at": NOW,
        "plan": plan()
    })
}

pub fn request() -> EvaluationRequest {
    parse(&request_json())
}

pub fn plan_digest() -> String {
    request().plan.plan_digest().unwrap().as_str().to_owned()
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

pub fn release_approval_json() -> Value {
    let mut v = approval_json();
    v["scope"] = json!({
        "operation": "release",
        "execution_id": id("exe_", 1),
        "projection_digest": projection().projection_digest().unwrap().as_str(),
        "disclosure_policy": disclosure_policy()
    });
    v
}

pub fn reservation_json() -> Value {
    json!({
        "schema": "private-custodian.reservation/1",
        "reservation_id": id("rsv_", 1),
        "request_id": id("req_", 1),
        "approval_id": id("apr_", 1),
        "plan_digest": plan_digest(),
        "kind": "run",
        "budget": budget(),
        "units": 1,
        "state": "held",
        "exposure": "not_exposed",
        "reserved_at": NOW,
        "lease_expires_at": NOW + 600
    })
}

pub fn frozen() -> Value {
    json!({
        "domain": "credential",
        "candidate": dg("synthetic-candidate"),
        "engine": artifact("synthetic-engine"),
        "adapter": artifact("synthetic-adapter"),
        "scanners": [artifact("synthetic-scanner")],
        "config_digest": dg("synthetic-config"),
        "protocol": protocol(),
        "population_digest": dg("synthetic-population")
    })
}

pub fn execution_json() -> Value {
    json!({
        "schema": "private-custodian.execution/1",
        "execution_id": id("exe_", 1),
        "request_id": id("req_", 1),
        "approval_id": id("apr_", 1),
        "reservation_id": id("rsv_", 1),
        "plan_digest": plan_digest(),
        "activation": activation_ref(),
        "frozen": frozen(),
        "attempt": 1,
        "outcome": "success",
        "exposure": "exposed",
        "reason": "completed",
        "started_at": NOW + 10,
        "finished_at": NOW + 20
    })
}

pub fn attestation() -> Value {
    json!({
        "independence": "custodian-declared",
        "role_separation": "single_operator_procedural",
        "organisational_independence": "not_claimed",
        "authorship": "project_authored",
        "review": "project_reviewed",
        "ground_truth": "not_established"
    })
}

pub fn receipt_json() -> Value {
    json!({
        "schema": "private-custodian.internal-receipt/1",
        "receipt_id": id("rcp_", 1),
        "execution_id": id("exe_", 1),
        "plan_digest": plan_digest(),
        "activation": activation_ref(),
        "frozen": frozen(),
        "outcome": "success",
        "result": {"digest": dg("synthetic-result"), "size_bytes": 2048, "protocol": protocol()},
        "roster": {"expected": 10, "observed": 10, "failed": 0},
        "attestation": attestation(),
        "issued_at": NOW + 30
    })
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

pub fn projection_json() -> Value {
    json!({
        "schema": "private-custodian.public-projection/1",
        "projection_id": id("prj_", 1),
        "receipt_id": id("rcp_", 9),
        "domain": "credential",
        "population": {"kind":"opaque","id": id("ppr_", 1)},
        "candidate": dg("synthetic-candidate"),
        "engine": artifact("synthetic-engine"),
        "protocol": protocol(),
        "scope_kind": "population_epoch",
        "disclosure_policy": disclosure_policy(),
        "attestation": attestation(),
        "cells": [
            {"stratum":"all","metric":"detected","value":{"state":"reported","numerator":9,"denominator":10}},
            {"stratum":"small","metric":"detected","value":{"state":"suppressed"}}
        ],
        "issued_at": NOW + 40,
        "fresh_until": NOW + 40 + 86_400,
        "revocation_feed": {"feed_id": id("fed_", 1), "min_sequence": 1}
    })
}

pub fn projection_envelope_json() -> Value {
    json!({"payload": projection_json(), "signature": sig()})
}

/// The v2 projection: the v1 fixture plus the signed destination, under the
/// v2 schema tag.
pub fn projection_v2_json() -> Value {
    let mut v = projection_json();
    v["schema"] = json!("private-custodian.public-projection/2");
    v["destination"] = json!("synthetic-benchmarks");
    v
}

pub fn projection_v2_envelope_json() -> Value {
    json!({"payload": projection_v2_json(), "signature": sig()})
}

pub fn projection_v2() -> PublicProjectionV2 {
    parse(&projection_v2_json())
}

pub fn revocation_json() -> Value {
    json!({
        "schema": "private-custodian.revocation-envelope/1",
        "feed_id": id("fed_", 1),
        "sequence": 1,
        "issued_at": NOW + 50,
        "fresh_until": NOW + 50 + 3600,
        "entries": [{
            "target": {"target":"candidate","candidate": dg("synthetic-other-candidate")},
            "action": {"action":"contaminated"},
            "reason": "contamination",
            "effective_at": NOW + 50
        }]
    })
}

pub fn revocation_envelope_json() -> Value {
    json!({"payload": revocation_json(), "signature": sig()})
}

pub fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// Parse a fixture through the strict decoder.
pub fn parse<T: Contract>(v: &Value) -> T {
    T::decode(&to_bytes(v)).unwrap()
}

pub fn approval() -> Approval {
    parse(&approval_json())
}
pub fn reservation() -> Reservation {
    parse(&reservation_json())
}
pub fn execution() -> ExecutionRecord {
    parse(&execution_json())
}
pub fn receipt() -> InternalReceipt {
    parse(&receipt_json())
}
pub fn activation() -> PolicyActivation {
    parse(&activation_json())
}
pub fn projection() -> PublicProjection {
    parse(&projection_json())
}
pub fn projection_envelope() -> PublicProjectionEnvelope {
    PublicProjectionEnvelope::decode(&to_bytes(&projection_envelope_json())).unwrap()
}
pub fn revocation() -> RevocationEnvelope {
    parse(&revocation_json())
}
pub fn revocation_envelope() -> SignedRevocationEnvelope {
    SignedRevocationEnvelope::decode(&to_bytes(&revocation_envelope_json())).unwrap()
}

pub fn observed(a: PolicyActivation, observed_at: u64) -> ObservedActivation {
    ObservedActivation {
        activation: a,
        observed_at: ts(observed_at),
    }
}

/// Current activation state exactly as bound, observed just now.
pub fn current() -> ObservedActivation {
    observed(activation(), NOW + 1)
}

pub const MAX_AGE: u64 = 60;
