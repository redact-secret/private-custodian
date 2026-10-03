//! JSON Schemas for the bridge wire documents. The checked-in files under
//! `schemas/v1/` must equal this output byte for byte (`tests/schemas.rs`).
//! The projection and revocation envelopes keep their schemas in
//! `custodian-contracts`; they are not duplicated here.

use schemars::generate::SchemaSettings;
use schemars::JsonSchema;
use serde_json::Value;

use crate::wire::{BridgeManifest, BridgeRequest};

pub struct SchemaEntry {
    pub file: &'static str,
    pub schema: Value,
}

fn gen<T: JsonSchema>(file: &'static str) -> SchemaEntry {
    let schema = SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>();
    let mut value = serde_json::to_value(&schema).unwrap_or(Value::Null);
    strip_null(&mut value);
    SchemaEntry {
        file,
        schema: value,
    }
}

/// Remove `"null"` alternatives that schemars adds for `Option`: the
/// canonical form omits absent fields and never contains null.
fn strip_null(v: &mut Value) {
    match v {
        Value::Object(map) => {
            if let Some(Value::Array(types)) = map.get_mut("type") {
                types.retain(|t| t != "null");
                if types.len() == 1 {
                    let only = types.remove(0);
                    map.insert("type".to_owned(), only);
                }
            }
            for child in map.values_mut() {
                strip_null(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(strip_null),
        _ => {}
    }
}

pub fn all_schemas() -> Vec<SchemaEntry> {
    vec![
        gen::<BridgeRequest>("bridge-request.schema.json"),
        gen::<BridgeManifest>("bridge-response.schema.json"),
    ]
}

/// Pretty JSON with a trailing newline, the checked-in form.
pub fn render(schema: &Value) -> String {
    let mut s = serde_json::to_string_pretty(schema).unwrap_or_default();
    s.push('\n');
    s
}
