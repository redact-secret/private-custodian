//! Negative tests for parsing: unknown fields, oversized payloads, out-of-bound
//! values, wrong schema tags, internal inconsistency, and canonical encoding.

mod common;

use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::{domain_digest, signing_input, to_canonical_bytes, DomainTag};
use custodian_contracts::common::{Attestation, IndependenceClaim};
use custodian_contracts::execution::{ExecutionRecord, InternalReceipt};
use custodian_contracts::policy::PolicyActivation;
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::Reservation;
use custodian_contracts::revocation::{RevocationEnvelope, SignedRevocationEnvelope};
use custodian_contracts::types::*;
use custodian_contracts::{Contract, ContractError, MAX_DOCUMENT_BYTES};
use serde_json::{json, Value};

type Decoder = fn(&[u8]) -> Result<(), ContractError>;

fn docs() -> Vec<(&'static str, Value, Decoder)> {
    vec![
        ("request", request_json(), |b| {
            EvaluationRequest::decode(b).map(|_| ())
        }),
        ("approval", approval_json(), |b| {
            Approval::decode(b).map(|_| ())
        }),
        ("release-approval", release_approval_json(), |b| {
            Approval::decode(b).map(|_| ())
        }),
        ("reservation", reservation_json(), |b| {
            Reservation::decode(b).map(|_| ())
        }),
        ("execution", execution_json(), |b| {
            ExecutionRecord::decode(b).map(|_| ())
        }),
        ("receipt", receipt_json(), |b| {
            InternalReceipt::decode(b).map(|_| ())
        }),
        ("activation", activation_json(), |b| {
            PolicyActivation::decode(b).map(|_| ())
        }),
        ("projection", projection_envelope_json(), |b| {
            PublicProjectionEnvelope::decode(b).map(|_| ())
        }),
        ("revocation", revocation_envelope_json(), |b| {
            SignedRevocationEnvelope::decode(b).map(|_| ())
        }),
    ]
}

fn set(v: &mut Value, ptr: &str, new: Value) {
    *v.pointer_mut(ptr)
        .unwrap_or_else(|| panic!("no pointer {ptr}")) = new;
}

fn decode_with(index: usize, v: &Value) -> Result<(), ContractError> {
    (docs()[index].2)(&to_bytes(v))
}

fn index_of(name: &str) -> usize {
    docs().iter().position(|d| d.0 == name).unwrap()
}

#[test]
fn all_fixtures_decode() {
    for (name, v, dec) in docs() {
        assert_eq!(dec(&to_bytes(&v)), Ok(()), "{name}");
    }
}

#[test]
fn unknown_root_field_rejected() {
    for (name, mut v, dec) in docs() {
        v.as_object_mut().unwrap().insert("extra".into(), json!(1));
        assert_eq!(dec(&to_bytes(&v)), Err(ContractError::Malformed), "{name}");
    }
}

fn inject_nested(v: &mut Value) -> bool {
    // Insert an unknown field into every nested object; returns whether any exist.
    let mut found = false;
    match v {
        Value::Object(m) => {
            for child in m.values_mut() {
                if matches!(child, Value::Object(_) | Value::Array(_)) {
                    found |= inject_nested(child);
                    if let Value::Object(cm) = child {
                        cm.insert("extra".into(), json!(1));
                        found = true;
                    }
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                found |= inject_nested(child);
                if let Value::Object(cm) = child {
                    cm.insert("extra".into(), json!(1));
                    found = true;
                }
            }
        }
        _ => {}
    }
    found
}

#[test]
fn unknown_nested_fields_rejected_everywhere() {
    for (name, v, dec) in docs() {
        let mut m = v.clone();
        assert!(inject_nested(&mut m), "{name} has no nested objects");
        assert_eq!(dec(&to_bytes(&m)), Err(ContractError::Malformed), "{name}");
    }
    // Targeted: one nested object at a time on the deepest request path.
    for ptr in [
        "/plan",
        "/plan/engine",
        "/plan/scanners/0",
        "/plan/population",
        "/plan/accounting",
        "/plan/accounting/budget",
        "/plan/limits",
        "/plan/policy_activation",
        "/plan/policy_activation/policy",
    ] {
        let mut v = request_json();
        v.pointer_mut(ptr)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!("x"));
        assert_eq!(
            EvaluationRequest::decode(&to_bytes(&v)),
            Err(ContractError::Malformed),
            "{ptr}"
        );
    }
}

#[test]
fn oversized_payload_rejected_before_parsing() {
    for (name, v, dec) in docs() {
        let mut bytes = to_bytes(&v);
        bytes.extend(std::iter::repeat_n(b' ', MAX_DOCUMENT_BYTES));
        assert_eq!(dec(&bytes), Err(ContractError::Oversized), "{name}");
    }
    // Garbage larger than the cap is Oversized, not Malformed: no parse attempted.
    let junk = vec![b'{'; MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        EvaluationRequest::decode(&junk),
        Err(ContractError::Oversized)
    );
}

#[test]
fn oversized_fields_and_collections_rejected() {
    let mut v = request_json();
    set(
        &mut v,
        "/request_id",
        json!(format!("req_{}", "a".repeat(65))),
    );
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );

    let mut v = request_json();
    set(&mut v, "/request_id", json!("req_short"));
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );

    let mut v = request_json();
    set(&mut v, "/plan/engine/name", json!("a".repeat(65)));
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );

    let mut v = request_json();
    set(
        &mut v,
        "/plan/scanners",
        json!(vec![artifact("synthetic-scanner"); 9]),
    );
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );

    let cell = json!({"stratum":"s","metric":"m","value":{"state":"suppressed"}});
    let mut v = projection_envelope_json();
    let cells: Vec<Value> = (0..257)
        .map(|i| {
            let mut c = cell.clone();
            c["stratum"] = json!(format!("s{i}"));
            c
        })
        .collect();
    set(&mut v, "/payload/cells", json!(cells));
    assert!(PublicProjectionEnvelope::decode(&to_bytes(&v)).is_err());

    let mut v = revocation_envelope_json();
    let entry = revocation_json()["entries"][0].clone();
    set(&mut v, "/payload/entries", json!(vec![entry; 129]));
    assert!(SignedRevocationEnvelope::decode(&to_bytes(&v)).is_err());
}

#[test]
fn numeric_bounds_and_types_rejected() {
    for (ptr, bad) in [
        ("/plan/accounting/units", json!(17)),
        ("/plan/accounting/units", json!(1.5)),
        ("/plan/accounting/units", json!(-1)),
        ("/plan/accounting/units", json!("1")),
        ("/requested_at", json!(9_007_199_254_740_992u64)),
        ("/requested_at", json!(1.8e9)),
        ("/plan/limits/cpu_seconds", json!(86_401)),
        ("/plan/limits/max_output_bytes", json!(1_073_741_825u64)),
    ] {
        let mut v = request_json();
        set(&mut v, ptr, bad.clone());
        assert_eq!(
            EvaluationRequest::decode(&to_bytes(&v)),
            Err(ContractError::Malformed),
            "{ptr} = {bad}"
        );
    }
}

#[test]
fn null_is_rejected_for_optional_fields() {
    let mut v = request_json();
    v["plan"]["population"]["family_id"] = Value::Null;
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );
    let mut v = revocation_envelope_json();
    v["payload"]["previous"] = Value::Null;
    assert!(SignedRevocationEnvelope::decode(&to_bytes(&v)).is_err());
}

#[test]
fn wrong_schema_tag_or_document_type_rejected() {
    let mut v = request_json();
    set(&mut v, "/schema", json!("private-custodian.request/2"));
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );
    let mut v = request_json();
    v.as_object_mut().unwrap().remove("schema");
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );
    // An approval is not a request, and vice versa.
    assert!(EvaluationRequest::decode(&to_bytes(&approval_json())).is_err());
    assert!(Approval::decode(&to_bytes(&request_json())).is_err());
    assert!(Reservation::decode(&to_bytes(&execution_json())).is_err());
    assert!(ExecutionRecord::decode(&to_bytes(&receipt_json())).is_err());
    assert!(InternalReceipt::decode(&to_bytes(&execution_json())).is_err());
}

#[test]
fn identity_types_are_not_interchangeable() {
    // A reservation id is not an approval id, a plan digest is not a candidate
    // digest of the same text, and so on, by prefix.
    let mut v = approval_json();
    set(&mut v, "/approval_id", json!(id("rsv_", 1)));
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );
    assert!(RequestId::parse(&id("exe_", 1)).is_err());
    assert!(ExecutionId::parse(&id("req_", 1)).is_err());
    assert!(ActorRef::parse(&id("pac_", 1)).is_err());
    assert!(ProjectionDigest::parse("sha256:abc").is_err());
    assert!(CandidateDigest::parse(&dg("x").to_uppercase()).is_err());
    // Public population references are opaque, not internal corpus ids.
    assert!(PublicPopulationId::parse(&id("cor_", 1)).is_err());
}

#[test]
fn duplicate_fields_rejected() {
    let text = r#"{"schema":"private-custodian.policy-activation/1","schema":"private-custodian.policy-activation/1"}"#;
    assert_eq!(
        PolicyActivation::decode(text.as_bytes()),
        Err(ContractError::Malformed)
    );
    let mut s = String::from_utf8(to_bytes(&activation_json())).unwrap();
    s.insert_str(1, r#""sequence":9,"#);
    assert_eq!(
        PolicyActivation::decode(s.as_bytes()),
        Err(ContractError::Malformed)
    );
}

#[test]
fn errors_never_echo_input() {
    let mut v = request_json();
    set(&mut v, "/request_id", json!("req_SECRETMARKERvalue1234567"));
    let e = EvaluationRequest::decode(&to_bytes(&v)).unwrap_err();
    assert!(!format!("{e} {e:?}").contains("SECRETMARKER"));
}

#[test]
fn request_cross_field_inconsistency_rejected() {
    // Domain mismatches: protocol, population, disclosure policy, activation policy.
    for ptr in [
        "/plan/protocol/domain",
        "/plan/population/domain",
        "/plan/disclosure_policy/domain",
        "/plan/policy_activation/policy/domain",
    ] {
        let mut v = request_json();
        set(&mut v, ptr, json!("pii"));
        assert_eq!(
            EvaluationRequest::decode(&to_bytes(&v)),
            Err(ContractError::Inconsistent),
            "{ptr}"
        );
    }
    // Population mismatch: budget scope names another corpus, epoch or family.
    for (ptr, val) in [
        ("/plan/accounting/budget/corpus_id", json!(id("cor_", 2))),
        ("/plan/accounting/budget/epoch_id", json!(id("epo_", 2))),
        ("/plan/accounting/budget/family_id", json!(id("fam_", 1))),
    ] {
        let mut v = request_json();
        set_or_insert(&mut v, ptr, val);
        assert_eq!(
            EvaluationRequest::decode(&to_bytes(&v)),
            Err(ContractError::Inconsistent),
            "{ptr}"
        );
    }
    // Policy kinds: swapped.
    let mut v = request_json();
    set(&mut v, "/plan/disclosure_policy/kind", json!("approval"));
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    let mut v = request_json();
    set(
        &mut v,
        "/plan/policy_activation/policy/kind",
        json!("disclosure"),
    );
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    // Zero units and wrong budget kind.
    let mut v = request_json();
    set(&mut v, "/plan/accounting/units", json!(0));
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    let mut v = request_json();
    set(&mut v, "/plan/accounting/kind", json!("release_query"));
    assert_eq!(
        EvaluationRequest::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
}

fn set_or_insert(v: &mut Value, ptr: &str, val: Value) {
    let (parent, key) = ptr.rsplit_once('/').unwrap();
    v.pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(key.to_owned(), val);
}

#[test]
fn approval_rules_enforced_at_decode() {
    let mut v = approval_json();
    set(&mut v, "/approver_kind", json!("agent"));
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );

    // Same principal must say single-operator; different must say distinct.
    let mut v = approval_json();
    set(&mut v, "/approver", json!(id("act_", 1)));
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    set(
        &mut v,
        "/role_separation",
        json!("single_operator_procedural"),
    );
    assert!(Approval::decode(&to_bytes(&v)).is_ok());
    let mut v = approval_json();
    set(
        &mut v,
        "/role_separation",
        json!("single_operator_procedural"),
    );
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );

    // No organizational separation is representable.
    let mut v = approval_json();
    set(&mut v, "/role_separation", json!("organizational"));
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Malformed)
    );

    let mut v = approval_json();
    set(&mut v, "/expires_at", json!(NOW));
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    set(&mut v, "/expires_at", json!(NOW + 7 * 86_400 + 1));
    assert_eq!(
        Approval::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
}

#[test]
fn execution_and_receipt_consistency_enforced() {
    let mut v = execution_json();
    set(&mut v, "/exposure", json!("not_exposed"));
    assert_eq!(
        ExecutionRecord::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );

    let mut v = execution_json();
    set(&mut v, "/outcome", json!("failed"));
    assert_eq!(
        ExecutionRecord::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    set(&mut v, "/reason", json!("execution_failed"));
    assert!(ExecutionRecord::decode(&to_bytes(&v)).is_ok());

    let mut v = execution_json();
    set(&mut v, "/finished_at", json!(NOW));
    assert_eq!(
        ExecutionRecord::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    let mut v = execution_json();
    set(&mut v, "/attempt", json!(0));
    assert_eq!(
        ExecutionRecord::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );

    // Success needs a full roster; partial needs an incomplete one; failures have no receipt.
    let mut v = receipt_json();
    set(&mut v, "/roster/observed", json!(9));
    assert_eq!(
        InternalReceipt::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    set(&mut v, "/outcome", json!("partial"));
    assert!(InternalReceipt::decode(&to_bytes(&v)).is_ok());
    let mut v = receipt_json();
    set(&mut v, "/outcome", json!("partial"));
    assert_eq!(
        InternalReceipt::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    let mut v = receipt_json();
    set(&mut v, "/outcome", json!("failed"));
    assert_eq!(
        InternalReceipt::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
    let mut v = receipt_json();
    set(&mut v, "/result/protocol/name", json!("other-protocol"));
    assert_eq!(
        InternalReceipt::decode(&to_bytes(&v)),
        Err(ContractError::Inconsistent)
    );
}

#[test]
fn public_projection_leakage_shapes_rejected() {
    let i = index_of("projection");
    // Any extra field is rejected, including every shape that would leak.
    for key in [
        "seed",
        "case_id",
        "path",
        "text",
        "value_hash",
        "range",
        "error",
        "stderr",
        "plan_digest",
        "corpus_id",
        "budget",
        "result",
    ] {
        let mut v = projection_envelope_json();
        v["payload"]
            .as_object_mut()
            .unwrap()
            .insert(key.into(), json!("x"));
        assert_eq!(decode_with(i, &v), Err(ContractError::Malformed), "{key}");
    }
    // A plain content hash is not an accepted population identity.
    let mut v = projection_envelope_json();
    set(
        &mut v,
        "/payload/population",
        json!({"kind":"keyed_commitment","key_id": id("key_", 1),"commitment": dg("pop")}),
    );
    assert_eq!(decode_with(i, &v), Err(ContractError::Malformed));
    // Free text in a label is rejected (allowlisted label alphabet only).
    for bad in ["has space", "Upper", "a/b", "", "caf\u{e9}", "line\nbreak"] {
        let mut v = projection_envelope_json();
        set(&mut v, "/payload/cells/0/stratum", json!(bad));
        assert_eq!(decode_with(i, &v), Err(ContractError::Malformed), "{bad:?}");
    }
    // Internal identities cannot stand in for public ones.
    let mut v = projection_envelope_json();
    set(
        &mut v,
        "/payload/population",
        json!({"kind":"opaque","id": id("cor_", 1)}),
    );
    assert_eq!(decode_with(i, &v), Err(ContractError::Malformed));
    // Suppressed cells carry nothing.
    let mut v = projection_envelope_json();
    set(
        &mut v,
        "/payload/cells/1/value",
        json!({"state":"suppressed","numerator":1}),
    );
    assert_eq!(decode_with(i, &v), Err(ContractError::Malformed));
}

#[test]
fn public_projection_consistency_enforced() {
    let i = index_of("projection");
    let mut v = projection_envelope_json();
    let dup = v["payload"]["cells"][0].clone();
    v["payload"]["cells"].as_array_mut().unwrap().push(dup);
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));

    let mut v = projection_envelope_json();
    set(&mut v, "/payload/cells/0/value/numerator", json!(11));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));

    let mut v = projection_envelope_json();
    set(&mut v, "/payload/fresh_until", json!(NOW + 40));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
    set(
        &mut v,
        "/payload/fresh_until",
        json!(NOW + 40 + 31 * 86_400),
    );
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));

    let mut v = projection_envelope_json();
    set(&mut v, "/payload/disclosure_policy/kind", json!("approval"));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
    let mut v = projection_envelope_json();
    set(&mut v, "/payload/protocol/domain", json!("pii"));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
}

#[test]
fn revocation_chain_shape_enforced() {
    let i = index_of("revocation");
    let mut v = revocation_envelope_json();
    v["payload"]["previous"] = json!(dg("x"));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
    let mut v = revocation_envelope_json();
    set(&mut v, "/payload/sequence", json!(2));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
    let mut v = revocation_envelope_json();
    set(&mut v, "/payload/sequence", json!(0));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
    let mut v = revocation_envelope_json();
    set(&mut v, "/payload/fresh_until", json!(NOW + 50));
    assert_eq!(decode_with(i, &v), Err(ContractError::Inconsistent));
    // Free-form reasons are not representable.
    let mut v = revocation_envelope_json();
    set(
        &mut v,
        "/payload/entries/0/reason",
        json!("operator typed anything here"),
    );
    assert_eq!(decode_with(i, &v), Err(ContractError::Malformed));
    let _ = revocation();
    let _ = RevocationEnvelope::DOMAIN;
}

#[test]
fn independence_vocabulary_is_preserved_and_never_independent() {
    for (wire, claim) in [
        ("public-control", IndependenceClaim::PublicControl),
        ("custodian-declared", IndependenceClaim::CustodianDeclared),
        (
            "procedural-separation",
            IndependenceClaim::ProceduralSeparation,
        ),
    ] {
        let mut a = attestation();
        a["independence"] = json!(wire);
        let parsed: Attestation = serde_json::from_value(a.clone()).unwrap();
        assert_eq!(parsed.independence, claim);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), a);
    }
    for bad in [
        ("independence", json!("independent")),
        ("independence", json!("organisational")),
        ("organisational_independence", json!("claimed")),
        ("organisational_independence", json!(true)),
        ("ground_truth", json!("established")),
        ("ground_truth", json!("independent")),
        ("review", json!("externally_verified")),
        ("authorship", json!("independent_author")),
    ] {
        let mut a = attestation();
        a[bad.0] = bad.1.clone();
        assert!(serde_json::from_value::<Attestation>(a).is_err(), "{bad:?}");
    }
    // The three legacy claims, the two review and two authorship values the
    // custodian can declare, all remain representable.
    for (field, value) in [
        ("review", "not_reviewed"),
        ("review", "project_reviewed"),
        ("review", "external_reviewed_unverified"),
        ("authorship", "project_authored"),
        ("authorship", "external_authored_unverified"),
    ] {
        let mut a = attestation();
        a[field] = json!(value);
        assert!(serde_json::from_value::<Attestation>(a).is_ok());
    }
}

#[test]
fn canonical_form_is_sorted_compact_integer_ascii() {
    let b = to_canonical_bytes(&json!({"b":1,"a":{"d":2,"c":[3,true,"x"]}})).unwrap();
    assert_eq!(b, br#"{"a":{"c":[3,true,"x"],"d":2},"b":1}"#);
    for bad in [
        json!({"a": 1.5}),
        json!({"a": -1}),
        json!({"a": null}),
        json!({"a": 9_007_199_254_740_992u64}),
        json!({"a": "caf\u{e9}"}),
        json!({"a": "quo\"te"}),
        json!({"a": "back\\slash"}),
        json!({"a": "new\nline"}),
        json!({"caf\u{e9}": 1}),
    ] {
        assert_eq!(
            to_canonical_bytes(&bad),
            Err(ContractError::NotCanonicalizable),
            "{bad}"
        );
    }
}

#[test]
fn decode_canonical_rejects_non_canonical_bytes() {
    let canonical = request().canonical_bytes().unwrap();
    assert!(EvaluationRequest::decode_canonical(&canonical).is_ok());
    // Same content, pretty printed or reordered: parses, but is not canonical.
    let pretty = serde_json::to_vec_pretty(&request_json()).unwrap();
    assert!(EvaluationRequest::decode(&pretty).is_ok());
    assert_eq!(
        EvaluationRequest::decode_canonical(&pretty),
        Err(ContractError::NonCanonical)
    );
    let mut spaced = canonical.clone();
    spaced.push(b'\n');
    assert_eq!(
        EvaluationRequest::decode_canonical(&spaced),
        Err(ContractError::NonCanonical)
    );
}

#[test]
fn domain_separation_is_effective() {
    let payload = approval().canonical_bytes().unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for tag in DomainTag::ALL {
        // Every tag is v1 except the projection major 2 tag (ADR 0119).
        let prefix = if tag == DomainTag::PublicProjectionV2 {
            "private-custodian/v2/"
        } else {
            "private-custodian/v1/"
        };
        assert!(tag.as_str().starts_with(prefix));
        assert!(!tag.as_str().as_bytes().contains(&0));
        assert!(seen.insert(tag.as_str()), "duplicate tag");
        let mut expected = tag.as_str().as_bytes().to_vec();
        expected.push(0);
        expected.extend_from_slice(&payload);
        assert_eq!(signing_input(tag, &payload), expected);
    }
    // Byte-identical payloads digest differently under every pair of tags.
    let digests: std::collections::BTreeSet<[u8; 32]> = DomainTag::ALL
        .iter()
        .map(|t| domain_digest(*t, &payload))
        .collect();
    assert_eq!(digests.len(), DomainTag::ALL.len());
    // A document's own digest uses its own tag only.
    let own = approval().document_digest().unwrap();
    let as_request = DocumentDigest::from_raw(domain_digest(DomainTag::Request, &payload));
    assert_ne!(own, as_request);
    // Signing input embeds the domain, so a signature over an approval cannot
    // verify as a signature over any other document type.
    assert_ne!(
        approval().signing_input().unwrap(),
        signing_input(DomainTag::Execution, &payload)
    );
}

#[test]
fn plan_digest_binds_every_material_field() {
    let base = plan_digest();
    for (ptr, val) in [
        ("/plan/candidate", json!(dg("another-candidate"))),
        ("/plan/engine/version", json!("9.9.9")),
        ("/plan/config_digest", json!(dg("another-config"))),
        ("/plan/policy_activation/sequence", json!(4)),
        (
            "/plan/population/population_digest",
            json!(dg("another-population")),
        ),
        ("/plan/population/custody_version", json!(2)),
        ("/plan/accounting/max_retries", json!(1)),
        ("/plan/limits/wall_seconds", json!(121)),
        ("/plan/seed_policy", json!("custodian_held_per_attempt")),
        ("/plan/disclosure_policy/version", json!(2)),
        ("/plan/purpose", json!("protected_evaluation")),
    ] {
        let mut v = request_json();
        set(&mut v, ptr, val);
        let changed: EvaluationRequest = parse(&v);
        assert_ne!(changed.plan.plan_digest().unwrap().as_str(), base, "{ptr}");
    }
    // Request metadata is not part of the plan.
    let mut v = request_json();
    set(&mut v, "/requested_at", json!(NOW + 1));
    let r: EvaluationRequest = parse(&v);
    assert_eq!(r.plan.plan_digest().unwrap().as_str(), base);
}
