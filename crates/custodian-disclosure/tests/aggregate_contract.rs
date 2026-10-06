//! Fail-closed `private-custodian.aggregates/1` contract and the PII profile
//! rules (ADR 0145, #45). Public synthetic data only. This file implements no
//! metric formula: it feeds fixed counts and asserts they are kept exactly or
//! refused, never clamped, rescaled or substituted.

mod common;

use common::*;
use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::{PrivateArtifactRef, RosterCounts};
use custodian_contracts::types::{Count, ResultDigest};
use custodian_disclosure::compose::{decide, Prior};
use custodian_disclosure::policy::DisclosurePolicy;
use custodian_disclosure::{DisclosureReason as R, PrivateAggregates};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The closed PII label profile of ADR 0135 / docs/pii-eval-adoption.md.
const PII_LABELS: [&str; 9] = [
    "type-miss-rate",
    "wrong-family-rate",
    "wrong-jurisdiction-rate",
    "sensitive-miss-rate",
    "non-sensitive-flag-rate",
    "context-discrimination-rate",
    "benign-suppression-rate",
    "jurisdiction-collision-rate",
    "range-collateral-rate",
];

fn counts(e: u64, o: u64, f: u64) -> RosterCounts {
    RosterCounts {
        expected: Count::new(e).unwrap(),
        observed: Count::new(o).unwrap(),
        failed: Count::new(f).unwrap(),
    }
}

fn protocol() -> ProtocolRef {
    serde_json::from_value(json!({"domain":"pii","name":"synthetic-protocol","version":"1"}))
        .unwrap()
}

fn pii_doc(e: u64, o: u64, f: u64, cells: Vec<Value>) -> Value {
    json!({
        "schema": "private-custodian.aggregates/1",
        "domain": "pii",
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "roster": {"expected": e, "observed": o, "failed": f},
        "cells": cells
    })
}

fn cell(metric: &str, n: u64, d: u64) -> Value {
    json!({"stratum":"overall","metric":metric,"numerator":n,"denominator":d})
}

fn full_profile(n: u64, d: u64) -> Vec<Value> {
    PII_LABELS.iter().map(|l| cell(l, n, d)).collect()
}

fn decode_bytes(
    bytes: &[u8],
    reference_bytes: &[u8],
    roster: &RosterCounts,
    domain: EvaluationDomain,
) -> Result<PrivateAggregates, R> {
    let p = protocol();
    let reference = PrivateArtifactRef {
        digest: ResultDigest::from_raw(Sha256::digest(reference_bytes).into()),
        size_bytes: Count::new(reference_bytes.len() as u64).unwrap(),
        protocol: p.clone(),
    };
    PrivateAggregates::decode(bytes, &reference, domain, &p, roster)
}

fn decode(v: &Value, roster: &RosterCounts) -> Result<PrivateAggregates, R> {
    let b = serde_json::to_vec(v).unwrap();
    decode_bytes(&b, &b, roster, EvaluationDomain::Pii)
}

fn pii_policy() -> DisclosurePolicy {
    let mut v = policy_json();
    v["strata"] = json!([{"stratum":"overall","dimension":"total"}]);
    v["total_stratum"] = json!("overall");
    v["relations"] = json!([]);
    v["metrics"] = json!(PII_LABELS);
    v["min_stratum_size"] = json!(1);
    v["min_interval_width"] = json!(1);
    let p: DisclosurePolicy = serde_json::from_value(v).unwrap();
    p.validate().unwrap();
    p
}

#[test]
fn full_nine_label_profile_decodes_with_denominators_not_above_observed() {
    // Complete run: denominators may be anything up to observed, including
    // strictly smaller (an engine-owned sub-population) and zero.
    let r = counts(10, 10, 0);
    for d in [10, 7, 0] {
        assert!(decode(&pii_doc(10, 10, 0, full_profile(0, d)), &r).is_ok());
    }
    // Partial run: the bound is observed, not expected.
    let r = counts(10, 6, 1);
    assert!(decode(&pii_doc(10, 6, 1, full_profile(3, 6)), &r).is_ok());
}

#[test]
fn denominators_and_numerators_are_never_clamped_or_rescaled() {
    let r = counts(10, 10, 0);
    // Denominator above observed (e.g. an axis-assertion count above the case
    // roster, the reason measurable-share stays engine-private): refused.
    assert_eq!(
        decode(&pii_doc(10, 10, 0, vec![cell("type-miss-rate", 3, 11)]), &r).err(),
        Some(R::ArtifactInconsistent)
    );
    // Partial run: a denominator equal to expected but above observed.
    let rp = counts(10, 6, 0);
    assert_eq!(
        decode(&pii_doc(10, 6, 0, vec![cell("type-miss-rate", 3, 10)]), &rp).err(),
        Some(R::ArtifactInconsistent)
    );
    // Numerator above denominator: refused, not capped.
    assert_eq!(
        decode(&pii_doc(10, 10, 0, vec![cell("type-miss-rate", 5, 4)]), &r).err(),
        Some(R::ArtifactInconsistent)
    );
    // Duplicate (stratum, metric): refused, not merged or last-wins.
    assert_eq!(
        decode(
            &pii_doc(
                10,
                10,
                0,
                vec![cell("type-miss-rate", 1, 5), cell("type-miss-rate", 2, 5)]
            ),
            &r
        )
        .err(),
        Some(R::ArtifactInconsistent)
    );
    // Values beyond u64 or negative or fractional do not parse as counts.
    for bad in ["-1", "1.5", "18446744073709551616", "\"3\"", "null"] {
        let text = serde_json::to_string(&pii_doc(10, 10, 0, vec![cell("type-miss-rate", 0, 5)]))
            .unwrap()
            .replace("\"numerator\":0", &format!("\"numerator\":{bad}"));
        assert_eq!(
            decode_bytes(text.as_bytes(), text.as_bytes(), &r, EvaluationDomain::Pii).err(),
            Some(R::ArtifactMalformed),
            "{bad}"
        );
    }
}

#[test]
fn roster_must_equal_the_receipt_exactly() {
    let doc = pii_doc(10, 10, 0, vec![cell("type-miss-rate", 1, 10)]);
    for r in [counts(11, 10, 0), counts(10, 9, 0), counts(10, 10, 1)] {
        assert_eq!(decode(&doc, &r).err(), Some(R::ArtifactMismatch));
    }
    assert!(decode(&doc, &counts(10, 10, 0)).is_ok());
}

#[test]
fn artifact_binding_schema_domain_protocol_and_bounds_fail_closed() {
    let r = counts(10, 10, 0);
    let good = pii_doc(10, 10, 0, vec![cell("type-miss-rate", 1, 10)]);
    let bytes = serde_json::to_vec(&good).unwrap();
    // Digest or size not those the receipt recorded: nothing is parsed.
    let mut other = bytes.clone();
    other.push(b' ');
    assert_eq!(
        decode_bytes(&bytes, &other, &r, EvaluationDomain::Pii).err(),
        Some(R::ArtifactMismatch)
    );
    // Wrong domain, protocol name/version.
    assert_eq!(
        decode_bytes(&bytes, &bytes, &r, EvaluationDomain::Credential).err(),
        Some(R::ArtifactMismatch)
    );
    for (ptr, val) in [("/protocol/name", "other"), ("/protocol/version", "2")] {
        let mut v = good.clone();
        *v.pointer_mut(ptr).unwrap() = json!(val);
        assert_eq!(decode(&v, &r).err(), Some(R::ArtifactMismatch), "{ptr}");
    }
    // Schema revision, empty cells, free-form fields.
    let mut v = good.clone();
    v["schema"] = json!("private-custodian.aggregates/2");
    assert_eq!(decode(&v, &r).err(), Some(R::ArtifactMalformed));
    let mut v = good.clone();
    v["cells"] = json!([]);
    assert_eq!(decode(&v, &r).err(), Some(R::ArtifactMalformed));
    for (k, val) in [
        ("attestation", json!({"independence":"independent"})),
        ("signature", json!("synthetic")),
        ("receipt_id", json!("rcp_synthetic")),
        ("message", json!("free text")),
    ] {
        let mut v = good.clone();
        v[k] = val;
        assert_eq!(decode(&v, &r).err(), Some(R::ArtifactMalformed), "{k}");
    }
    // Cell-count and byte caps.
    let many: Vec<Value> = (0..257)
        .map(|i| json!({"stratum":format!("s{i}"),"metric":"m","numerator":0,"denominator":0}))
        .collect();
    assert_eq!(
        decode(&pii_doc(10, 10, 0, many), &r).err(),
        Some(R::ArtifactMalformed)
    );
    let big = vec![b' '; 64 * 1024 + 1];
    assert_eq!(
        decode_bytes(&big, &big, &r, EvaluationDomain::Pii).err(),
        Some(R::ArtifactMalformed)
    );
    // Not JSON.
    let junk = b"not json";
    assert_eq!(
        decode_bytes(junk, junk, &r, EvaluationDomain::Pii).err(),
        Some(R::ArtifactMalformed)
    );
}

#[test]
fn policy_allows_exactly_the_declared_labels_and_nothing_inferred() {
    let policy = pii_policy();
    let r = counts(10, 10, 0);
    // The nine-label profile passes the policy check.
    let ok = decode(&pii_doc(10, 10, 0, full_profile(2, 10)), &r).unwrap();
    assert!(decide(&policy, &ok, &Prior::default()).is_ok());
    // measurable-share is engine-private: a cell for it is refused even though
    // its counts are consistent.
    let extra = decode(
        &pii_doc(10, 10, 0, vec![cell("measurable-share", 2, 10)]),
        &r,
    )
    .unwrap();
    assert_eq!(
        decide(&policy, &extra, &Prior::default()).err(),
        Some(R::MetricNotAllowed)
    );
    // An unknown stratum is refused, not folded into overall.
    let foreign = decode(
        &pii_doc(
            10,
            10,
            0,
            vec![
                json!({"stratum":"extra","metric":"type-miss-rate","numerator":1,"denominator":10}),
            ],
        ),
        &r,
    )
    .unwrap();
    assert_eq!(
        decide(&policy, &foreign, &Prior::default()).err(),
        Some(R::StratumNotAllowed)
    );
}
