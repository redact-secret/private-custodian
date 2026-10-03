//! Public synthetic transport controls, not MicroVM isolation evidence.
use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::types::{ProtocolName, VersionLabel};
use custodian_worker::result::{job_document, MAX_RESULT_BYTES};
use custodian_worker_microvm::{
    decode_result, sha256, AttemptBinding, Refusal, ResultEnvelope, MAX_ENVELOPE_BYTES,
    RESULT_ENVELOPE_SCHEMA,
};
use serde_json::{json, Value};

fn protocol() -> ProtocolRef {
    ProtocolRef {
        domain: EvaluationDomain::Credential,
        name: ProtocolName::parse("synthetic-protocol").unwrap(),
        version: VersionLabel::parse("1").unwrap(),
    }
}
fn job() -> Vec<u8> {
    job_document(
        EvaluationDomain::Credential,
        &protocol(),
        &["public-synthetic".into()],
    )
    .unwrap()
}
fn binding() -> AttemptBinding {
    let digest = sha256(b"public-synthetic-artifact");
    serde_json::from_value(json!({
        "request": "req_0000000000000001", "approval": "apr_0000000000000001",
        "reservation": "rsv_0000000000000001", "execution": "exe_0000000000000001",
        "attempt": 1, "fence": 1, "plan_digest": digest,
        "candidate_digest": digest, "image_digest": digest, "image_version": "1.0",
        "engine_digest": digest, "adapter_digest": digest, "config_digest": digest,
        "scanner_digests": [digest], "job_digest": sha256(&job())
    }))
    .unwrap()
}
fn result() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "private-custodian.worker-result/1", "domain": "credential",
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "status": "complete", "roster": {"expected": 1, "observed": 1, "failed": 0},
        "aggregates": {"schema": "private-custodian.aggregates/1", "public_synthetic": true}
    }))
    .unwrap()
}
fn envelope() -> Value {
    serde_json::to_value(ResultEnvelope {
        schema: RESULT_ENVELOPE_SCHEMA.into(),
        binding: binding(),
        stdout: result(),
    })
    .unwrap()
}
fn decode(v: &Value) -> Result<custodian_worker::result::ValidatedResult, Refusal> {
    decode_result(
        &serde_json::to_vec(v).unwrap(),
        &binding(),
        EvaluationDomain::Credential,
        &protocol(),
        1,
    )
}

#[test]
fn synthetic_round_trip_preserves_exact_private_bytes_and_aggregate_channel() {
    binding().check_job(&job()).unwrap();
    let accepted = decode(&envelope()).unwrap();
    assert_eq!(accepted.private_bytes(), result());
    assert!(accepted.aggregates_bytes().is_some());
    // The aggregate content still requires the disclosure validator. Transport
    // acceptance of this intentionally invalid aggregate never grants release.
}

#[test]
fn every_identity_and_fence_is_bound_to_the_control_plane_expectation() {
    for (key, replacement) in [
        ("request", json!("req_0000000000000002")),
        ("approval", json!("apr_0000000000000002")),
        ("reservation", json!("rsv_0000000000000002")),
        ("execution", json!("exe_0000000000000002")),
        ("attempt", json!(2)),
        ("fence", json!(2)),
        ("plan_digest", json!(sha256(b"other"))),
        ("candidate_digest", json!(sha256(b"other"))),
        ("image_digest", json!(sha256(b"other"))),
        ("image_version", json!("2.0")),
        ("engine_digest", json!(sha256(b"other"))),
        ("adapter_digest", json!(sha256(b"other"))),
        ("config_digest", json!(sha256(b"other"))),
        ("scanner_digests", json!([sha256(b"other")])),
        ("job_digest", json!(sha256(b"other"))),
    ] {
        let mut v = envelope();
        v["binding"][key] = replacement;
        assert_eq!(decode(&v).err(), Some(Refusal::BindingMismatch), "{key}");
    }
}

#[test]
fn strict_wire_rejects_unknown_duplicate_and_wrong_version_fields() {
    let mut v = envelope();
    v["raw_log"] = json!("SYNTHETIC-CANARY");
    assert_eq!(decode(&v).err(), Some(Refusal::Malformed));
    let mut v = envelope();
    v["binding"]["authority"] = json!("approved");
    assert_eq!(decode(&v).err(), Some(Refusal::Malformed));
    let mut v = envelope();
    v["schema"] = json!("private-custodian.remote-result/2");
    assert_eq!(decode(&v).err(), Some(Refusal::Malformed));
    let bytes = serde_json::to_vec(&envelope()).unwrap();
    let duplicate = [b"{\"schema\":\"duplicate\",".as_slice(), &bytes[1..]].concat();
    assert_eq!(
        decode_result(
            &duplicate,
            &binding(),
            EvaluationDomain::Credential,
            &protocol(),
            1
        )
        .err(),
        Some(Refusal::Malformed)
    );
}

#[test]
fn exact_job_digest_rejects_changed_bytes_even_if_json_semantics_match() {
    let mut changed = job();
    changed.push(b' ');
    assert_eq!(binding().check_job(&changed), Err(Refusal::BindingMismatch));
}

#[test]
fn bounded_ingress_and_output_refuse_floods_without_returning_canary_text() {
    assert_eq!(
        decode_result(
            &vec![b'x'; MAX_ENVELOPE_BYTES + 1],
            &binding(),
            EvaluationDomain::Credential,
            &protocol(),
            1
        )
        .err(),
        Some(Refusal::Oversized)
    );
    let mut e = ResultEnvelope {
        schema: RESULT_ENVELOPE_SCHEMA.into(),
        binding: binding(),
        stdout: vec![0; MAX_RESULT_BYTES as usize + 1],
    };
    let encoded = serde_json::to_vec(&e).unwrap();
    assert_eq!(
        decode_result(
            &encoded,
            &binding(),
            EvaluationDomain::Credential,
            &protocol(),
            1
        )
        .err(),
        Some(Refusal::Oversized)
    );
    e.stdout = b"SYNTHETIC-CANARY".to_vec();
    let err = decode_result(
        &serde_json::to_vec(&e).unwrap(),
        &binding(),
        EvaluationDomain::Credential,
        &protocol(),
        1,
    )
    .err()
    .unwrap();
    assert_eq!(format!("{err:?}"), "WorkerResultInvalid");
}

#[test]
fn engine_output_cannot_change_domain_protocol_roster_or_mint_attestation() {
    for (key, replacement) in [
        ("domain", json!("pii")),
        ("protocol", json!({"name":"other", "version":"1"})),
        ("roster", json!({"expected":2,"observed":2,"failed":0})),
        ("attestation", json!("trusted")),
    ] {
        let mut output: Value = serde_json::from_slice(&result()).unwrap();
        output[key] = replacement;
        let mut v = envelope();
        v["stdout"] = json!(serde_json::to_vec(&output).unwrap());
        assert_eq!(decode(&v).err(), Some(Refusal::WorkerResultInvalid));
    }
}

#[test]
fn invalid_binding_refuses_zero_fence_empty_pins_and_malformed_identities() {
    for (key, replacement) in [
        ("fence", json!(0)),
        ("attempt", json!(0)),
        ("scanner_digests", json!([])),
    ] {
        let mut v = envelope();
        v["binding"][key] = replacement;
        assert_eq!(decode(&v).err(), Some(Refusal::BindingInvalid));
    }
    for (key, replacement) in [
        ("request", json!("apr_0000000000000001")),
        ("candidate_digest", json!("sha256:short")),
        ("scanner_digests", json!(vec![sha256(b"other"); 9])),
    ] {
        let mut v = envelope();
        v["binding"][key] = replacement;
        assert_eq!(decode(&v).err(), Some(Refusal::Malformed));
    }
}
