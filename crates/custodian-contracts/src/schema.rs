//! JSON Schema generation. The checked-in files under `schemas/v1/` must equal
//! this output byte for byte (drift test in `tests/schemas.rs`).

use schemars::generate::SchemaSettings;
use schemars::JsonSchema;
use serde_json::Value;

use crate::approval::Approval;
use crate::execution::{ExecutionRecord, InternalReceipt};
use crate::policy::PolicyActivation;
use crate::public::PublicProjectionEnvelope;
use crate::request::EvaluationRequest;
use crate::reservation::Reservation;
use crate::revocation::SignedRevocationEnvelope;

/// Which side of the private boundary a contract is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Never leaves the control service, signer or private ledger.
    Internal,
    /// Allowed to cross to benchmarks and the public.
    Public,
}

pub struct SchemaEntry {
    /// File name under `schemas/v1/`.
    pub file: &'static str,
    pub visibility: Visibility,
    pub schema: Value,
}

fn gen<T: JsonSchema>(file: &'static str, visibility: Visibility) -> SchemaEntry {
    let schema = SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>();
    let mut value = serde_json::to_value(&schema).unwrap_or(Value::Null);
    strip_null(&mut value);
    SchemaEntry {
        file,
        visibility,
        schema: value,
    }
}

/// Optional fields are omitted when absent and `null` is rejected, so the
/// published schema must not admit `null`. Rewrites `anyOf: [X, {type: null}]`
/// to `X` and `type: [T, "null"]` to `T`.
fn strip_null(v: &mut Value) {
    match v {
        Value::Object(map) => {
            if let Some(Value::Array(alts)) = map.get("anyOf") {
                let kept: Vec<Value> = alts
                    .iter()
                    .filter(|a| a.get("type") != Some(&Value::String("null".into())))
                    .cloned()
                    .collect();
                if kept.len() == 1 && kept.len() < alts.len() {
                    map.remove("anyOf");
                    if let Some(Value::Object(only)) = kept.into_iter().next() {
                        map.extend(only);
                    }
                }
            }
            if let Some(Value::Array(types)) = map.get("type") {
                let kept: Vec<Value> = types
                    .iter()
                    .filter(|t| t.as_str() != Some("null"))
                    .cloned()
                    .collect();
                if kept.len() == 1 {
                    map.insert("type".into(), kept[0].clone());
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

/// Every contract schema, in a stable order.
pub fn all_schemas() -> Vec<SchemaEntry> {
    use Visibility::*;
    vec![
        gen::<EvaluationRequest>("request.schema.json", Internal),
        gen::<Approval>("approval.schema.json", Internal),
        gen::<Reservation>("reservation.schema.json", Internal),
        gen::<ExecutionRecord>("execution.schema.json", Internal),
        gen::<InternalReceipt>("internal-receipt.schema.json", Internal),
        gen::<PolicyActivation>("policy-activation.schema.json", Internal),
        gen::<PublicProjectionEnvelope>("public-projection.schema.json", Public),
        gen::<SignedRevocationEnvelope>("revocation-envelope.schema.json", Public),
    ]
}

/// Stable text form written to disk.
pub fn render(schema: &Value) -> String {
    let mut s = serde_json::to_string_pretty(schema).unwrap_or_default();
    s.push('\n');
    s
}
