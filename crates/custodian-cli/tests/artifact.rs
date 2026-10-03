//! Binding checks use only public synthetic documents, with hostile output canaries.
#[path = "../../custodian-contracts/tests/common/mod.rs"]
mod cc;
use custodian_cli::artifact;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn docs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let request = cc::request_json();
    let mut receipt = cc::receipt_json();
    let req: custodian_contracts::request::EvaluationRequest =
        serde_json::from_value(request.clone()).unwrap();
    receipt["plan_digest"] = json!(req.plan.plan_digest().unwrap());
    receipt["activation"] = json!(req.plan.policy_activation);
    receipt["frozen"] = json!(req.plan.frozen_identities());
    let aggregates = json!({"schema":"private-custodian.aggregates/1", "domain":"credential",
        "protocol":{"name":"synthetic-protocol", "version":"1"}, "roster":receipt["roster"],
        "cells":[{"stratum":"overall","metric":"detected","numerator":4,"denominator":10}]});
    let bytes = serde_json::to_vec(&aggregates).unwrap();
    receipt["result"]["digest"] = json!(format!("sha256:{:x}", Sha256::digest(&bytes)));
    receipt["result"]["size_bytes"] = json!(bytes.len());
    let result = json!({"schema":"private-custodian.worker-result/1", "domain":"credential",
        "protocol":{"name":"synthetic-protocol", "version":"1"}, "status":"complete", "roster":receipt["roster"], "aggregates":aggregates});
    (
        serde_json::to_vec(&request).unwrap(),
        serde_json::to_vec(&receipt).unwrap(),
        serde_json::to_vec(&result).unwrap(),
    )
}
#[test]
fn receipt_bound_aggregate_is_checked_and_tampering_is_sanitized() {
    let (request, receipt, result) = docs();
    assert_eq!(
        artifact::validate(&request, &receipt, &result).code(),
        "artifact_bound"
    );
    for mutate in [
        |v: &mut Value| {
            v.as_object_mut().unwrap().remove("aggregates");
        },
        |v: &mut Value| {
            v["aggregates"]["cells"][0]["numerator"] = json!(5);
        },
        |v: &mut Value| {
            v["domain"] = json!("pii");
        },
        |v: &mut Value| {
            v["roster"]["failed"] = json!(1);
        },
        |v: &mut Value| {
            v["aggregates"]["raw-text"] = json!("SYNTHETIC-ARTIFACT-CANARY");
        },
        |v: &mut Value| {
            v["aggregates"] = json!("SYNTHETIC-ARTIFACT-CANARY");
        },
    ] {
        let mut v: Value = serde_json::from_slice(&result).unwrap();
        mutate(&mut v);
        let out = artifact::validate(&request, &receipt, &serde_json::to_vec(&v).unwrap());
        assert!(!out.is_ok());
        assert!(!out.render().contains("SYNTHETIC-ARTIFACT-CANARY"));
    }
    let mut request: Value = serde_json::from_slice(&request).unwrap();
    request["plan"]["candidate"] = json!(cc::dg("other-candidate"));
    assert_eq!(
        artifact::validate(&serde_json::to_vec(&request).unwrap(), &receipt, &result).code(),
        "verification_failed"
    );
}
#[test]
fn offline_grammar_is_closed_and_does_not_read_on_usage_errors() {
    for args in [
        "artifact",
        "artifact validate",
        "artifact validate --request a --request b --result c",
        "artifact validate --request a --receipt b --raw-output c",
    ] {
        let argv = args
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let out = artifact::command(&argv, &|_, _| panic!("usage error must not read"));
        assert_eq!(out.code(), "usage_error");
    }
}
#[test]
fn binary_runs_offline_and_never_echoes_a_path_or_document() {
    let root = std::env::temp_dir().join(format!("custodian-artifact-test-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let (request, receipt, result) = docs();
    for (name, bytes) in [
        ("request", request),
        ("receipt", receipt),
        ("result", result),
    ] {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_custodian"))
            .args(["artifact", "validate", "--result"])
            .arg(root.join("result"))
            .arg("--receipt")
            .arg(root.join("receipt"))
            .arg("--request")
            .arg(root.join("request"))
            .env_remove("CUSTODIAN_CONFIG")
            .output()
            .unwrap()
    };
    let out = run();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 1);
    std::fs::write(root.join("result"), vec![b' '; 65537]).unwrap();
    let out = run();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("document_too_large"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(root.to_str().unwrap()));
    std::fs::remove_dir_all(root).unwrap();
}
