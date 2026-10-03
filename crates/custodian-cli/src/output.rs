//! Structured, sanitized output.
//!
//! One JSON object per invocation on standard output, nothing else. Its
//! fields are an allowlist by construction: a code is a fixed word, a number
//! is a number, and an identifier must match a strict character set or it is
//! replaced by a marker. There is no way to put a free-form string, a path, a
//! worker message or a protected value into the output, because there is no
//! method that accepts one.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::reason::CliReason;

pub const OUTPUT_SCHEMA: &str = "private-custodian.cli-output/1";
/// Marker substituted for an identifier that is not in the safe grammar.
pub const UNSAFE_MARKER: &str = "omitted_unsafe_identifier";

/// An identifier is lowercase ASCII letters, digits and `_ - . :`, at most
/// 128 bytes, and not empty.
pub fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b':')
        })
}

#[derive(Clone, Debug)]
pub struct Output {
    command: &'static str,
    dry_run: bool,
    outcome: Result<&'static str, CliReason>,
    fields: BTreeMap<&'static str, Value>,
}

impl Output {
    /// A success. `code` is a fixed word such as `submitted`.
    pub fn ok(command: &'static str, code: &'static str) -> Self {
        Self {
            command,
            dry_run: false,
            outcome: Ok(code),
            fields: BTreeMap::new(),
        }
    }

    pub fn refused(command: &'static str, reason: CliReason) -> Self {
        Self {
            command,
            dry_run: false,
            outcome: Err(reason),
            fields: BTreeMap::new(),
        }
    }

    /// Keep the fields gathered so far and turn the outcome into a failure.
    /// A verification that found a problem still reports what it looked at.
    pub fn with_failure(mut self, command: &'static str, reason: CliReason) -> Self {
        self.command = command;
        self.outcome = Err(reason);
        self
    }

    pub fn dry(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn id(mut self, key: &'static str, value: &str) -> Self {
        let v = if is_safe_identifier(value) {
            value
        } else {
            UNSAFE_MARKER
        };
        self.fields.insert(key, Value::String(v.to_owned()));
        self
    }

    pub fn opt_id(self, key: &'static str, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.id(key, v),
            None => self,
        }
    }

    pub fn ids(mut self, key: &'static str, values: &[String]) -> Self {
        let list: Vec<Value> = values
            .iter()
            .take(100)
            .map(|v| {
                Value::String(if is_safe_identifier(v) {
                    v.clone()
                } else {
                    UNSAFE_MARKER.to_owned()
                })
            })
            .collect();
        self.fields.insert(key, Value::Array(list));
        self
    }

    pub fn num(mut self, key: &'static str, value: u64) -> Self {
        self.fields.insert(key, json!(value));
        self
    }

    pub fn flag(mut self, key: &'static str, value: bool) -> Self {
        self.fields.insert(key, json!(value));
        self
    }

    /// A fixed vocabulary word chosen by the program, never derived from input.
    pub fn word(mut self, key: &'static str, value: &'static str) -> Self {
        self.fields.insert(key, json!(value));
        self
    }

    pub fn is_ok(&self) -> bool {
        self.outcome.is_ok()
    }

    pub fn code(&self) -> &'static str {
        match self.outcome {
            Ok(c) => c,
            Err(r) => r.code(),
        }
    }

    pub fn reason(&self) -> Option<CliReason> {
        self.outcome.err()
    }

    pub fn exit_code(&self) -> u8 {
        match self.outcome {
            Ok(_) => 0,
            Err(r) => r.exit_code(),
        }
    }

    pub fn field(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    pub fn to_value(&self) -> Value {
        json!({
            "schema": OUTPUT_SCHEMA,
            "command": self.command,
            "ok": self.is_ok(),
            "dry_run": self.dry_run,
            "code": self.code(),
            "exit": self.exit_code(),
            "result": self.fields,
        })
    }

    pub fn render(&self) -> String {
        self.to_value().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_identifiers_are_replaced_not_echoed() {
        let o = Output::ok("x", "done")
            .id("a", "req_abc123")
            .id("b", "/etc/secret path")
            .id("c", "UPPER")
            .id("d", &"x".repeat(200));
        let s = o.render();
        assert!(s.contains("req_abc123"));
        assert!(!s.contains("/etc"));
        assert!(!s.contains("UPPER"));
        assert_eq!(s.matches(UNSAFE_MARKER).count(), 3);
    }

    #[test]
    fn exit_code_follows_the_reason_class() {
        assert_eq!(Output::ok("x", "done").exit_code(), 0);
        assert_eq!(Output::refused("x", CliReason::SelfApproval).exit_code(), 4);
        let v = Output::refused("x", CliReason::StalePolicy).to_value();
        assert_eq!(v["exit"], 5);
        assert_eq!(v["code"], "stale_policy");
        assert_eq!(v["ok"], false);
    }
}
