//! Checked-in bridge schemas: drift, boundedness, and no private field names.
//! Regenerate deliberately:
//! `UPDATE_SCHEMAS=1 cargo test -p custodian-bridge --test schemas`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use custodian_bridge::schema::{all_schemas, render};
use serde_json::Value;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/v1")
}

#[test]
fn checked_in_schemas_equal_generated() {
    let update = std::env::var_os("UPDATE_SCHEMAS").is_some();
    let mut expected = BTreeSet::new();
    for entry in all_schemas() {
        let text = render(&entry.schema);
        let path = dir().join(entry.file);
        if update {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, &text).unwrap();
        }
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing schema file {}", entry.file));
        assert_eq!(text, on_disk, "schema drift: {}", entry.file);
        expected.insert(entry.file.to_owned());
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(on_disk, expected, "unexpected files in schemas/v1");
}

fn walk(v: &Value, f: &mut dyn FnMut(&serde_json::Map<String, Value>)) {
    match v {
        Value::Object(map) => {
            f(map);
            map.values().for_each(|c| walk(c, f));
        }
        Value::Array(items) => items.iter().for_each(|c| walk(c, f)),
        _ => {}
    }
}

#[test]
fn schemas_are_closed_bounded_and_carry_no_private_names() {
    for entry in all_schemas() {
        walk(&entry.schema, &mut |m| {
            if m.contains_key("properties") {
                assert_eq!(m.get("additionalProperties"), Some(&Value::Bool(false)));
            }
            match m.get("type").and_then(Value::as_str) {
                Some("string") => assert!(
                    m.contains_key("maxLength")
                        || m.contains_key("enum")
                        || m.contains_key("const"),
                    "unbounded string in {}",
                    entry.file
                ),
                Some("array") => assert!(m.contains_key("maxItems"), "unbounded array"),
                Some("integer") => assert!(m.contains_key("maximum"), "unbounded integer"),
                _ => {}
            }
        });
        let text = serde_json::to_string(&entry.schema).unwrap();
        for private in [
            "corpus",
            "epoch",
            "family",
            "lineage",
            "budget",
            "seed",
            "path",
            "approval",
            "actor",
            "token",
            "credential",
        ] {
            // Property names only: the word may appear in enum descriptions.
            assert!(
                !text.contains(&format!("\"{private}_"))
                    && !text.contains(&format!("\"{private}\":")),
                "{} names {private}",
                entry.file
            );
        }
    }
}
