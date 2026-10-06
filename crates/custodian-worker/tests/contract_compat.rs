//! worker-job/1 and worker-result/1 compatibility and hostile-output rules
//! (ADR 0145, #45). Public synthetic data only; no engine is run.

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_worker::result::{job_document, validate_result};
use custodian_worker::WorkerReason as R;
use serde_json::{json, Value};

fn protocol(domain: &str) -> ProtocolRef {
    serde_json::from_value(json!({"domain": domain, "name": "synthetic-protocol", "version": "1"}))
        .unwrap()
}

fn result(domain: &str, extra: Value) -> Vec<u8> {
    let mut v = json!({
        "schema": "private-custodian.worker-result/1",
        "domain": domain,
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "status": "complete",
        "roster": {"expected": 4, "observed": 4, "failed": 0},
    });
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn job_document_is_exactly_the_v1_shape_for_both_domains() {
    for (name, dom) in [
        ("credential", EvaluationDomain::Credential),
        ("pii", EvaluationDomain::Pii),
    ] {
        let entries: Vec<String> = (0..4).map(|i| format!("entry-{i}")).collect();
        let bytes = job_document(dom, &protocol(name), &entries).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["domain", "entries", "protocol", "roster", "schema"]);
        assert_eq!(v["schema"], "private-custodian.worker-job/1");
        assert_eq!(v["domain"], name);
        assert_eq!(v["roster"], 4);
        assert_eq!(v["entries"], json!(entries));
        assert_eq!(
            v["protocol"],
            json!({"name": "synthetic-protocol", "version": "1"})
        );
    }
}

#[test]
fn aggregates_are_additive_and_old_results_stay_valid() {
    let p = protocol("pii");
    let d = EvaluationDomain::Pii;
    let old = validate_result(&result("pii", json!({})), d, &p, 4).unwrap();
    assert_eq!(old.outcome, O::Success);
    assert!(old.aggregates_bytes().is_none());
    let new = validate_result(
        &result("pii", json!({"aggregates": {"schema": "x"}})),
        d,
        &p,
        4,
    )
    .unwrap();
    assert_eq!(new.outcome, O::Success);
    assert!(new.aggregates_bytes().is_some());
    // The worker keeps opaque bytes; the artifact digest covers the whole
    // stdout document, so the aggregates cannot change after validation.
    assert_eq!(
        new.artifact.size_bytes.get() as usize,
        new.private_bytes().len()
    );
}

#[test]
fn hostile_output_cannot_carry_attestation_receipt_or_authority_fields() {
    let p = protocol("pii");
    let d = EvaluationDomain::Pii;
    for (k, val) in [
        ("attestation", json!({"independence": "independent"})),
        ("independence", json!("independent")),
        ("role_separation", json!("separated")),
        ("receipt", json!({"receipt_id": "rcp_synthetic"})),
        ("signature", json!("synthetic")),
        ("authorization", json!("granted")),
        ("outcome", json!("success")),
        ("budget", json!({"refund": 1})),
        ("trusted", json!(true)),
    ] {
        assert_eq!(
            validate_result(&result("pii", json!({ k: val })), d, &p, 4).err(),
            Some(R::ResultMalformed),
            "top-level {k}"
        );
    }
    // Nested inside roster or protocol is refused as well.
    for text in [
        r#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"synthetic-protocol","version":"1"},"status":"complete","roster":{"expected":4,"observed":4,"failed":0,"trusted":true}}"#,
        r#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"synthetic-protocol","version":"1","attested":true},"status":"complete","roster":{"expected":4,"observed":4,"failed":0}}"#,
    ] {
        assert_eq!(
            validate_result(text.as_bytes(), d, &p, 4).err(),
            Some(R::ResultMalformed)
        );
    }
    // Attestation-shaped content inside the opaque aggregates object does not
    // change the outcome or reach the roster; the worker result type has no
    // attestation to mint, and disclosure's closed decoder refuses the object.
    let hostile = validate_result(
        &result(
            "pii",
            json!({"aggregates": {"attestation": {"independence": "independent"}}}),
        ),
        d,
        &p,
        4,
    )
    .unwrap();
    assert_eq!(hostile.outcome, O::Success);
    assert_eq!(hostile.roster.expected.get(), 4);
}

#[test]
fn outcome_comes_only_from_roster_counters_not_from_claims() {
    let p = protocol("pii");
    let d = EvaluationDomain::Pii;
    // A "complete" claim with failures is Partial; a claim of success status
    // is not an accepted value.
    let failed = br#"{"schema":"private-custodian.worker-result/1","domain":"pii","protocol":{"name":"synthetic-protocol","version":"1"},"status":"complete","roster":{"expected":4,"observed":4,"failed":1}}"#;
    assert_eq!(
        validate_result(failed, d, &p, 4).unwrap().outcome,
        O::Partial
    );
    let success = failed.to_vec();
    let success = String::from_utf8(success)
        .unwrap()
        .replace("\"complete\"", "\"success\"");
    assert_eq!(
        validate_result(success.as_bytes(), d, &p, 4).err(),
        Some(R::ResultMalformed)
    );
    // Roster not equal to the authorized one is refused, never adjusted.
    assert_eq!(
        validate_result(&result("pii", json!({})), d, &p, 5).err(),
        Some(R::RosterMismatch)
    );
}
