//! What the ledger knows that a restored, older store has forgotten (R-1,
//! ADR 0130).
//!
//! These are pure functions of the effective audit records of a trustworthy
//! walk. They read no store and write nothing; the operator CLI feeds their
//! output to the store's audited `accept_ledger_loss`. Every rule leans toward
//! more consumption and fewer permissions:
//!
//! * a reservation counts as consumed unless a terminal record says it was
//!   refunded (ambiguity is consumption, as in ADR 0091);
//! * disclosure charges and imported legacy units count as stated;
//! * an epoch keeps the standing its last ledger record states, and an epoch
//!   with any budget-affecting activity in the lost window is flagged so the
//!   caller can retire it.

use std::collections::{BTreeMap, BTreeSet};

use crate::walk::AuditEntry;

/// Audit kinds that spend or hold budget (the store's R-2 list).
fn spends(kind: &str) -> bool {
    custodian_store::BUDGET_AFFECTING_KINDS.contains(&kind)
}

fn str_of<'a>(e: &'a AuditEntry, key: &str) -> Option<&'a str> {
    e.payload.get(key).and_then(|v| v.as_str())
}

fn num_of(e: &AuditEntry, key: &str) -> Option<u64> {
    e.payload.get(key).and_then(serde_json::Value::as_u64)
}

/// Epoch standing as the ledger states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochFloor {
    /// `unaffected`, `unreviewed_change`, `exposed` or `used_for_tuning`.
    pub contamination: String,
    pub retired: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LedgerDerivation {
    /// Units each budget scope has consumed (or must be treated as having
    /// consumed) according to the ledger, over its whole history.
    pub consumed_by_scope: BTreeMap<String, u64>,
}

/// Total consumption per scope over the effective audit records.
pub fn derive_consumption(audit: &[AuditEntry]) -> LedgerDerivation {
    // attempt -> (scope, units, refunded)
    let mut attempts: BTreeMap<&str, (&str, u64, bool)> = BTreeMap::new();
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for e in audit {
        match e.kind.as_str() {
            "reservation.created" => {
                if let (Some(a), Some(s), Some(u)) = (
                    str_of(e, "attempt_id"),
                    str_of(e, "scope_key"),
                    num_of(e, "units"),
                ) {
                    attempts.entry(a).or_insert((s, u, false));
                }
            }
            "attempt.terminal" => {
                if let (Some(a), Some(s), Some(u)) = (
                    str_of(e, "attempt_id"),
                    str_of(e, "scope_key"),
                    num_of(e, "units"),
                ) {
                    let refunded = str_of(e, "settlement") == Some("refunded");
                    let slot = attempts.entry(a).or_insert((s, u, refunded));
                    slot.2 = refunded;
                }
            }
            "disclosure.charged" | "budget.imported" => {
                if let (Some(s), Some(u)) = (str_of(e, "scope_key"), num_of(e, "units")) {
                    let t = out.entry(s.to_owned()).or_insert(0);
                    *t = t.saturating_add(u);
                }
            }
            _ => {}
        }
    }
    for (scope, units, refunded) in attempts.into_values() {
        if !refunded {
            let t = out.entry(scope.to_owned()).or_insert(0);
            *t = t.saturating_add(units);
        }
    }
    LedgerDerivation {
        consumed_by_scope: out,
    }
}

/// The records after position `store_seq`: what the restored store lacks.
pub fn lost_tail(audit: &[AuditEntry], store_seq: u64) -> Vec<&AuditEntry> {
    audit.iter().filter(|e| e.seq > store_seq).collect()
}

/// Budget scopes with any spend-affecting record in `tail`.
pub fn affected_scopes(tail: &[&AuditEntry]) -> BTreeSet<String> {
    tail.iter()
        .filter(|e| spends(&e.kind))
        .filter_map(|e| str_of(e, "scope_key").map(str::to_owned))
        .collect()
}

/// Request and attempt ids that appear only in the lost window. The
/// restored store has no row for them; they are reported, never invented.
pub fn lost_attempts(tail: &[&AuditEntry]) -> BTreeSet<String> {
    tail.iter()
        .filter(|e| spends(&e.kind))
        .filter_map(|e| str_of(e, "attempt_id").map(str::to_owned))
        .collect()
}

/// The standing the lost window's last `epoch.standing` record states, per epoch.
pub fn epoch_floors(tail: &[&AuditEntry]) -> BTreeMap<String, EpochFloor> {
    let mut out: BTreeMap<String, EpochFloor> = BTreeMap::new();
    for e in tail.iter().filter(|e| e.kind == "epoch.standing") {
        if let (Some(id), Some(state)) = (str_of(e, "scope_key"), str_of(e, "state")) {
            let retired = num_of(e, "retired").unwrap_or(0) != 0;
            let prior_retired = out.get(id).is_some_and(|f| f.retired);
            out.insert(
                id.to_owned(),
                EpochFloor {
                    contamination: state.to_owned(),
                    retired: retired || prior_retired,
                },
            );
        }
    }
    out
}

/// Feed obligations and publications recorded in the lost window. Their
/// targets are not in the ledger, so the store cannot recreate them: the
/// operator re-records them (ADR 0130).
pub fn lost_feed_events(tail: &[&AuditEntry]) -> Vec<String> {
    tail.iter()
        .filter(|e| e.kind.starts_with("feed."))
        .map(|e| e.event_id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map, Value};

    fn entry(seq: u64, kind: &str, payload: Value) -> AuditEntry {
        let Value::Object(m) = payload else {
            panic!("object")
        };
        AuditEntry {
            seq,
            record_id: format!("rec-audit-{seq:032x}"),
            event_id: format!("e{seq}"),
            kind: kind.to_owned(),
            chain: "0".repeat(64),
            payload_digest: "0".repeat(64),
            payload_exact: true,
            issued_at: 1,
            payload: Map::from_iter(m),
        }
    }

    #[test]
    fn a_reservation_is_consumed_unless_a_terminal_record_refunds_it() {
        let audit = vec![
            entry(
                1,
                "reservation.created",
                json!({"attempt_id": "a1", "scope_key": "s", "units": 2}),
            ),
            entry(
                2,
                "reservation.created",
                json!({"attempt_id": "a2", "scope_key": "s", "units": 1}),
            ),
            entry(
                3,
                "attempt.terminal",
                json!({"attempt_id": "a2", "scope_key": "s", "units": 1, "settlement": "refunded"}),
            ),
            entry(
                4,
                "disclosure.charged",
                json!({"scope_key": "r", "units": 3}),
            ),
        ];
        let d = derive_consumption(&audit);
        // a1 has no terminal record: ambiguity is consumption.
        assert_eq!(d.consumed_by_scope.get("s"), Some(&2));
        assert_eq!(d.consumed_by_scope.get("r"), Some(&3));
    }

    #[test]
    fn the_tail_scopes_attempts_and_floors_come_from_the_lost_window_only() {
        let audit = vec![
            entry(
                1,
                "reservation.created",
                json!({"attempt_id": "a1", "scope_key": "s1", "units": 1}),
            ),
            entry(
                2,
                "reservation.created",
                json!({"attempt_id": "a2", "scope_key": "s2", "units": 1}),
            ),
            entry(
                3,
                "epoch.standing",
                json!({"scope_key": "epo_x", "state": "exposed", "retired": 0}),
            ),
            entry(
                4,
                "epoch.standing",
                json!({"scope_key": "epo_x", "state": "exposed", "retired": 1}),
            ),
            entry(5, "feed.obligation", json!({"scope_key": "ob1"})),
        ];
        let tail = lost_tail(&audit, 1);
        assert_eq!(tail.len(), 4);
        assert_eq!(affected_scopes(&tail), BTreeSet::from(["s2".to_owned()]));
        assert_eq!(lost_attempts(&tail), BTreeSet::from(["a2".to_owned()]));
        let f = epoch_floors(&tail);
        assert_eq!(
            f.get("epo_x"),
            Some(&EpochFloor {
                contamination: "exposed".into(),
                retired: true
            })
        );
        assert_eq!(lost_feed_events(&tail), vec!["e5".to_owned()]);
    }
}
