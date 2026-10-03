//! Public projection major 2 (ADR 0119): the destination is inside the signed
//! payload. Compatibility with v1, downgrade and upgrade confusion, bounds,
//! unknown fields, and revocation across both majors. Synthetic data only.

mod common;

use common::*;
use custodian_contracts::canonical::{signing_input, DomainTag};
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::public_v2::{
    AnyProjectionEnvelope, DestinationBinding, PublicProjectionEnvelopeV2, PublicProjectionV2,
};
use custodian_contracts::revocation::{RevocationEnvelope, RevocationLog, Standing};
use custodian_contracts::types::{DestinationId, Timestamp};
use custodian_contracts::{Contract, ContractError, MAX_DOCUMENT_BYTES};
use serde_json::{json, Value};

fn set(v: &mut Value, ptr: &str, new: Value) {
    *v.pointer_mut(ptr).unwrap() = new;
}

#[test]
fn v2_decodes_and_carries_a_bound_destination() {
    let any = AnyProjectionEnvelope::decode(&to_bytes(&projection_v2_envelope_json())).unwrap();
    assert_eq!(any.major(), 2);
    assert_eq!(any.binding(), DestinationBinding::Bound);
    assert_eq!(any.destination().unwrap().as_str(), "synthetic-benchmarks");
}

#[test]
fn v1_still_decodes_and_is_labelled_unbound() {
    let any = AnyProjectionEnvelope::decode(&to_bytes(&projection_envelope_json())).unwrap();
    assert_eq!(any.major(), 1);
    assert_eq!(any.binding(), DestinationBinding::Unbound);
    assert!(!any.binding().is_bound());
    assert!(any.destination().is_none());
    assert_eq!(DestinationBinding::UNBOUND_CODE, "destination_unbound");
}

#[test]
fn v1_and_v2_use_different_domains_and_signing_inputs() {
    assert_eq!(
        DomainTag::PublicProjection.as_str(),
        "private-custodian/v1/public-projection"
    );
    assert_eq!(
        DomainTag::PublicProjectionV2.as_str(),
        "private-custodian/v2/public-projection"
    );
    let v2 = projection_v2();
    assert!(v2
        .signing_input()
        .unwrap()
        .starts_with(b"private-custodian/v2/public-projection\0"));
    // A v2 signing input is never a v1 signing input, even for the same bytes.
    let bytes = v2.canonical_bytes().unwrap();
    assert_ne!(
        signing_input(DomainTag::PublicProjection, &bytes),
        signing_input(DomainTag::PublicProjectionV2, &bytes)
    );
}

#[test]
fn destination_is_part_of_the_digest() {
    let base = projection_v2().projection_digest().unwrap();
    let mut v = projection_v2_json();
    set(&mut v, "/destination", json!("synthetic-other"));
    let other: PublicProjectionV2 = parse(&v);
    assert_ne!(other.projection_digest().unwrap(), base);
}

/// A v2 payload relabelled as v1 (tag changed, destination kept) and a v2
/// payload with the destination stripped but still labelled v2 are both
/// refused by the closed decoders.
#[test]
fn downgrade_and_stripping_are_rejected() {
    let mut v = projection_v2_envelope_json();
    set(
        &mut v,
        "/payload/schema",
        json!("private-custodian.public-projection/1"),
    );
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
    assert!(PublicProjectionEnvelope::decode(&to_bytes(&v)).is_err());

    let mut v = projection_v2_envelope_json();
    v["payload"].as_object_mut().unwrap().remove("destination");
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
    assert!(PublicProjectionEnvelopeV2::decode(&to_bytes(&v)).is_err());
}

/// A v1 payload passed off as v2 (tag changed, no destination) is refused,
/// and so is a v1 document with a destination added under the v1 tag.
#[test]
fn upgrade_confusion_is_rejected() {
    let mut v = projection_envelope_json();
    set(
        &mut v,
        "/payload/schema",
        json!("private-custodian.public-projection/2"),
    );
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
    assert!(PublicProjectionEnvelopeV2::decode(&to_bytes(&v)).is_err());

    let mut v = projection_envelope_json();
    v["payload"]["destination"] = json!("synthetic-benchmarks");
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
}

#[test]
fn unknown_schema_majors_and_missing_tags_are_rejected() {
    for tag in [
        json!("private-custodian.public-projection/0"),
        json!("private-custodian.public-projection/3"),
        json!("private-custodian.public-projection/2 "),
        json!("private-custodian.request/1"),
        json!(2),
    ] {
        let mut v = projection_v2_envelope_json();
        set(&mut v, "/payload/schema", tag);
        assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
    }
    let mut v = projection_v2_envelope_json();
    v["payload"].as_object_mut().unwrap().remove("schema");
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
}

#[test]
fn unknown_fields_are_rejected_in_v2() {
    for ptr in ["", "/payload", "/signature"] {
        let mut v = projection_v2_envelope_json();
        let target = if ptr.is_empty() {
            &mut v
        } else {
            v.pointer_mut(ptr).unwrap()
        };
        target["surprise"] = json!("x");
        assert!(
            AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err(),
            "{ptr}"
        );
    }
    // Duplicate destination member.
    let text = String::from_utf8(to_bytes(&projection_v2_envelope_json())).unwrap();
    let dup = text.replacen(
        "\"destination\":\"synthetic-benchmarks\"",
        "\"destination\":\"synthetic-benchmarks\",\"destination\":\"synthetic-other\"",
        1,
    );
    assert_ne!(dup, text);
    assert!(AnyProjectionEnvelope::decode(dup.as_bytes()).is_err());
}

/// The destination is a bounded label, not a URL, a path or free text.
#[test]
fn destination_is_a_bounded_label() {
    let long = "a".repeat(65);
    for bad in [
        "",
        "https://example.invalid/hook",
        "example.invalid/path",
        "Upper",
        "-leading",
        "has space",
        "user@host",
        "a:b",
        "a/b",
        long.as_str(),
    ] {
        let mut v = projection_v2_envelope_json();
        set(&mut v, "/payload/destination", json!(bad));
        assert!(
            AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err(),
            "accepted {bad:?}"
        );
        assert!(DestinationId::parse(bad).is_err());
    }
    let mut v = projection_v2_envelope_json();
    set(&mut v, "/payload/destination", json!("a".repeat(64)));
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_ok());
    let mut v = projection_v2_envelope_json();
    set(&mut v, "/payload/destination", json!(7));
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
}

#[test]
fn oversize_v2_is_rejected_before_parsing() {
    let big = vec![b' '; MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        AnyProjectionEnvelope::decode(&big),
        Err(ContractError::Oversized)
    );
    assert_eq!(
        PublicProjectionEnvelopeV2::decode(&big),
        Err(ContractError::Oversized)
    );
}

#[test]
fn v2_keeps_the_v1_bounds_and_consistency_rules() {
    let mut v = projection_v2_envelope_json();
    set(&mut v, "/payload/fresh_until", json!(NOW + 40));
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());

    let mut v = projection_v2_envelope_json();
    set(
        &mut v,
        "/payload/cells/0/value",
        json!({"state":"reported","numerator":11,"denominator":10}),
    );
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());

    let cell = json!({"stratum":"s","metric":"m","value":{"state":"suppressed"}});
    let cells: Vec<Value> = (0..257)
        .map(|i| {
            let mut c = cell.clone();
            c["stratum"] = json!(format!("s{i}"));
            c
        })
        .collect();
    let mut v = projection_v2_envelope_json();
    set(&mut v, "/payload/cells", json!(cells));
    assert!(AnyProjectionEnvelope::decode(&to_bytes(&v)).is_err());
}

#[test]
fn v2_adds_only_the_destination_label() {
    let keys = |v: &Value| -> std::collections::BTreeSet<String> {
        v.as_object().unwrap().keys().cloned().collect()
    };
    let added: Vec<String> = keys(&projection_v2_json())
        .difference(&keys(&projection_json()))
        .cloned()
        .collect();
    assert_eq!(added, vec!["destination".to_owned()]);
}

#[test]
fn common_fields_view_matches_for_revocation_and_feed_logic() {
    let v1 = projection();
    let v2 = projection_v2();
    assert_eq!(v1, v2.common_fields());
    let any = AnyProjectionEnvelope::decode(&to_bytes(&projection_v2_envelope_json())).unwrap();
    assert_eq!(any.common_fields(), v1);
    // The view is not the signed document: digests differ.
    assert_ne!(
        v2.common_fields().projection_digest().unwrap(),
        v2.projection_digest().unwrap()
    );
}

/// Revocation entries target fields both majors share, so one feed revokes
/// v1 and v2 projections alike.
#[test]
fn revocation_works_across_both_versions() {
    let v1 = projection();
    let v2 = projection_v2();
    let feed = v1.revocation_feed.feed_id.clone();
    let now = Timestamp::new(NOW + 100).unwrap();
    for (target, label) in [
        (
            json!({"target":"projection","projection_id": v1.projection_id}),
            "projection",
        ),
        (
            json!({"target":"receipt","receipt_id": v1.receipt_id}),
            "receipt",
        ),
        (
            json!({"target":"candidate","candidate": v1.candidate}),
            "candidate",
        ),
    ] {
        let mut r = revocation_json();
        set(&mut r, "/entries/0/target", target);
        set(&mut r, "/entries/0/effective_at", json!(NOW + 60));
        let env: RevocationEnvelope = parse(&r);
        let mut log = RevocationLog::new(feed.clone());
        log.apply(&env).unwrap();
        assert_eq!(log.standing(&v1, now), Standing::Revoked, "v1 {label}");
        assert_eq!(
            log.standing(&v2.common_fields(), now),
            Standing::Revoked,
            "v2 {label}"
        );
    }
}
