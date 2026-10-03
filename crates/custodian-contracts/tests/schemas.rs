//! Checked-in JSON Schemas: drift, boundedness, and public-contract leakage.
//! Regenerate deliberately: `UPDATE_SCHEMAS=1 cargo test -p custodian-contracts --test schemas`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use custodian_contracts::schema::{all_schemas, render, Visibility};
use serde_json::Value;

fn dir(major: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
        .join(major)
}

#[test]
fn checked_in_schemas_equal_generated() {
    let update = std::env::var_os("UPDATE_SCHEMAS").is_some();
    let mut expected_files = BTreeSet::new();
    for entry in all_schemas() {
        let text = render(&entry.schema);
        let path = dir(entry.dir).join(entry.file);
        if update {
            std::fs::create_dir_all(dir(entry.dir)).unwrap();
            std::fs::write(&path, &text).unwrap();
        }
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing schema file {}/{}", entry.dir, entry.file));
        assert_eq!(text, on_disk, "schema drift: {}/{}", entry.dir, entry.file);
        expected_files.insert(format!("{}/{}", entry.dir, entry.file));
    }
    // No stray or orphaned schema files in any major directory.
    let mut on_disk = BTreeSet::new();
    for major in std::fs::read_dir(dir("")).unwrap() {
        let major = major.unwrap();
        for f in std::fs::read_dir(major.path()).unwrap() {
            on_disk.insert(format!(
                "{}/{}",
                major.file_name().to_string_lossy(),
                f.unwrap().file_name().to_string_lossy()
            ));
        }
    }
    assert_eq!(on_disk, expected_files, "unexpected files in schemas/");
}

fn walk(v: &Value, path: &str, f: &mut dyn FnMut(&str, &serde_json::Map<String, Value>)) {
    match v {
        Value::Object(map) => {
            f(path, map);
            for (k, child) in map {
                walk(child, &format!("{path}/{k}"), f);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                walk(child, &format!("{path}/{i}"), f);
            }
        }
        _ => {}
    }
}

/// Every schema, internal and public: closed objects, bounded strings,
/// arrays and integers, and no null.
#[test]
fn every_schema_is_closed_and_bounded() {
    for entry in all_schemas() {
        walk(&entry.schema, entry.file, &mut |path, m| {
            if m.contains_key("properties")
                || m.get("type") == Some(&Value::String("object".into()))
            {
                assert_eq!(
                    m.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "open object at {path}"
                );
            }
            match m.get("type").and_then(Value::as_str) {
                Some("string") => assert!(
                    m.contains_key("maxLength")
                        || m.contains_key("enum")
                        || m.contains_key("const"),
                    "unbounded string at {path}"
                ),
                Some("array") => assert!(m.contains_key("maxItems"), "unbounded array at {path}"),
                Some("integer") => {
                    assert!(m.contains_key("maximum"), "unbounded integer at {path}")
                }
                Some("number") => panic!("float admitted at {path}"),
                Some("null") => panic!("null admitted at {path}"),
                _ => {}
            }
            assert!(
                !matches!(m.get("type"), Some(Value::Array(_))),
                "union type at {path}"
            );
            assert!(!m.contains_key("additionalItems"), "open items at {path}");
        });
    }
}

fn property_names(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk(v, "", &mut |_, m| {
        if let Some(Value::Object(props)) = m.get("properties") {
            out.extend(props.keys().cloned());
        }
    });
    out
}

fn public() -> Vec<custodian_contracts::schema::SchemaEntry> {
    all_schemas()
        .into_iter()
        .filter(|e| e.visibility == Visibility::Public)
        .collect()
}

#[test]
fn public_and_internal_sets_are_separate_and_nonempty() {
    assert_eq!(public().len(), 3);
    let internal = all_schemas()
        .into_iter()
        .filter(|e| e.visibility == Visibility::Internal)
        .count();
    assert_eq!(internal, 6);
}

/// Structural leakage check: names that would carry secrets, case-level
/// detail, internal identities, budgets or actors must not exist anywhere in
/// a public schema.
#[test]
fn public_schemas_have_no_forbidden_properties() {
    const FORBIDDEN: &[&str] = &[
        "seed",
        "secret",
        "token",
        "key_material",
        "case",
        "case_id",
        "cases",
        "path",
        "paths",
        "text",
        "input",
        "inputs",
        "hash",
        "value_hash",
        "range",
        "ranges",
        "offset",
        "error",
        "errors",
        "message",
        "stderr",
        "stdout",
        "log",
        "plan_digest",
        "population_digest",
        "corpus_id",
        "epoch_id",
        "family_id",
        "lineage_id",
        "budget",
        "request_id",
        "execution_id",
        "approval_id",
        "reservation_id",
        "idempotency_key",
        "asserted_actor",
        "actor",
        "proposer",
        "approver",
        "result",
        "roster",
        "limits",
        "config_digest",
        "scanners",
        "adapter",
        "units",
        "exposure",
        "reason_detail",
    ];
    for entry in public() {
        let names = property_names(&entry.schema);
        for bad in FORBIDDEN {
            assert!(
                !names.contains(*bad),
                "forbidden property `{bad}` in public schema {}",
                entry.file
            );
        }
    }
}

/// Public schemas may reference only public types.
#[test]
fn public_schemas_do_not_embed_internal_types() {
    const INTERNAL: &[&str] = &[
        "PopulationBinding",
        "BudgetScope",
        "FrozenIdentities",
        "InternalReceipt",
        "PrivateArtifactRef",
        "RosterCounts",
        "ResourceLimits",
        "AccountingSettings",
        "EvaluationPlan",
        "ActivationRef",
        "ApprovalScope",
        "ExecutionOutcome",
    ];
    for entry in public() {
        let defs: BTreeSet<String> = entry
            .schema
            .get("$defs")
            .and_then(Value::as_object)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();
        for bad in INTERNAL {
            assert!(!defs.contains(*bad), "{bad} reachable from {}", entry.file);
        }
    }
}

/// No hash-shaped field except the named, content-addressed identities: a
/// candidate digest, a component artifact digest and the feed chain link.
/// There is nowhere to put a value-level hash.
#[test]
fn public_digest_fields_are_only_named_identities() {
    const ALLOWED: &[&str] = &["candidate", "digest", "previous", "commitment"];
    for entry in public() {
        walk(&entry.schema, entry.file, &mut |_, m| {
            if let Some(Value::Object(props)) = m.get("properties") {
                for (name, schema) in props {
                    let pattern = schema.get("pattern").and_then(Value::as_str).unwrap_or("");
                    if pattern.contains("sha256:") || pattern.contains("hmac-sha256:") {
                        assert!(
                            ALLOWED.contains(&name.as_str()),
                            "hash-shaped field `{name}` in {}",
                            entry.file
                        );
                    }
                }
            }
        });
    }
}

/// Every internal-only identity pattern must be absent from public schemas.
#[test]
fn public_schemas_exclude_internal_id_patterns() {
    const INTERNAL_PREFIXES: &[&str] = &[
        "^req_", "^idk_", "^apr_", "^rsv_", "^exe_", "^act_", "^cor_", "^epo_", "^fam_", "^lin_",
        "^pac_",
    ];
    for entry in public() {
        let text = serde_json::to_string(&entry.schema).unwrap();
        for p in INTERNAL_PREFIXES {
            assert!(
                !text.contains(p),
                "internal id pattern {p} in {}",
                entry.file
            );
        }
    }
}
