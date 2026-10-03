//! Integrity checks and backup.
//!
//! `integrity_check` is what an operator or a recovery test runs: SQLite's
//! own structural check, foreign keys, then the accounting and audit
//! invariants of this store. Failures name the failed check with a fixed
//! string and never include row content.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::StoreError;
use crate::outbox::{chain_of, GENESIS_CHAIN};
use crate::secure_fs;
use crate::store::SqliteStore;

/// (name, SQL returning the number of violating rows; must be zero)
const CHECKS: &[(&str, &str)] = &[
    (
        "budget_counters_match_reservations",
        "SELECT COUNT(*) FROM budgets b WHERE \
         b.held_units <> COALESCE((SELECT SUM(units) FROM reservations r \
             WHERE r.scope_key = b.scope_key AND r.state = 'held'), 0) \
         OR b.consumed_units <> COALESCE((SELECT SUM(units) FROM settlements s \
             WHERE s.scope_key = b.scope_key AND s.result = 'consumed'), 0) \
             + COALESCE((SELECT SUM(units) FROM disclosure_charges c \
             WHERE c.scope_key = b.scope_key), 0) \
             + COALESCE((SELECT SUM(applied_units) FROM budget_imports i \
             WHERE i.scope_key = b.scope_key), 0) \
         OR b.refunded_units <> COALESCE((SELECT SUM(units) FROM settlements s \
             WHERE s.scope_key = b.scope_key AND s.result = 'refunded'), 0)",
    ),
    (
        "budget_import_has_audit_event",
        "SELECT COUNT(*) FROM budget_imports i WHERE NOT EXISTS \
         (SELECT 1 FROM outbox o WHERE o.event_id = 'import:' || i.import_id)",
    ),
    (
        "budget_import_chain_is_monotone",
        "SELECT (SELECT COUNT(*) FROM budget_imports n JOIN budget_imports o \
             ON n.supersedes = o.import_id \
             WHERE n.legacy_units < o.legacy_units OR n.scope_key <> o.scope_key \
                OR n.source_scope_key <> o.source_scope_key) \
         + (SELECT COUNT(*) FROM (SELECT scope_key FROM budget_imports \
             WHERE import_id NOT IN (SELECT supersedes FROM budget_imports \
                                     WHERE supersedes IS NOT NULL) \
             GROUP BY scope_key HAVING COUNT(*) > 1)) \
         + (SELECT COUNT(*) FROM (SELECT source_scope_key FROM budget_imports \
             GROUP BY source_scope_key HAVING COUNT(DISTINCT scope_key) > 1)) \
         + (SELECT COUNT(*) FROM budgets b WHERE EXISTS \
             (SELECT 1 FROM budget_imports i WHERE i.scope_key = b.scope_key) \
             AND b.consumed_units < COALESCE((SELECT MAX(i.legacy_units) \
                 FROM budget_imports i WHERE i.scope_key = b.scope_key), 0))",
    ),
    (
        "budget_never_over_committed",
        "SELECT COUNT(*) FROM budgets WHERE held_units + consumed_units > limit_units",
    ),
    (
        "settled_reservation_has_one_settlement",
        "SELECT COUNT(*) FROM reservations r WHERE (r.state <> 'held') <> \
         EXISTS (SELECT 1 FROM settlements s WHERE s.reservation_id = r.reservation_id)",
    ),
    (
        "terminal_attempt_is_settled",
        "SELECT COUNT(*) FROM attempts a JOIN reservations r ON r.reservation_id = a.reservation_id \
         WHERE a.state IN ('completed', 'failed', 'cancelled', 'expired') AND r.state = 'held'",
    ),
    (
        "live_attempt_holds_its_reservation",
        "SELECT COUNT(*) FROM attempts a JOIN reservations r ON r.reservation_id = a.reservation_id \
         WHERE a.state IN ('reserved', 'running', 'validating') AND r.state <> 'held'",
    ),
    (
        "no_refund_after_exposure",
        "SELECT COUNT(*) FROM settlements s WHERE s.result = 'refunded' AND \
         (s.exposure <> 'not_exposed' OR EXISTS (SELECT 1 FROM transitions t \
             WHERE t.attempt_id = s.attempt_id AND t.kind = 'exposure'))",
    ),
    (
        "transitions_contiguous",
        "SELECT COUNT(*) FROM (SELECT attempt_id FROM transitions \
         GROUP BY attempt_id HAVING COUNT(*) <> MAX(seq))",
    ),
    (
        "attempt_state_matches_last_transition",
        "SELECT COUNT(*) FROM attempts a WHERE a.state IS NOT \
         (SELECT t.to_state FROM transitions t WHERE t.attempt_id = a.attempt_id \
          AND t.kind = 'transition' ORDER BY t.seq DESC LIMIT 1)",
    ),
    (
        "reservation_has_audit_event",
        "SELECT COUNT(*) FROM attempts a WHERE a.reservation_id IS NOT NULL AND NOT EXISTS \
         (SELECT 1 FROM outbox o WHERE o.event_id = 'reserve:' || a.attempt_id)",
    ),
    (
        "terminal_attempt_has_audit_event",
        "SELECT COUNT(*) FROM attempts a WHERE \
         (a.state IN ('completed', 'failed', 'cancelled', 'expired') AND NOT EXISTS \
             (SELECT 1 FROM outbox o WHERE o.event_id = 'terminal:' || a.attempt_id)) \
         OR (a.state = 'denied' AND NOT EXISTS \
             (SELECT 1 FROM outbox o WHERE o.event_id = 'denied:' || a.attempt_id))",
    ),
    (
        "disclosure_charge_has_audit_event",
        "SELECT COUNT(*) FROM disclosure_charges c WHERE NOT EXISTS \
         (SELECT 1 FROM outbox o WHERE o.event_id = \
          'disclosure-charge:' || c.charge_id || ':' || substr(c.scope_key, 1, 16))",
    ),
    (
        "exposed_attempt_has_exposure_record",
        "SELECT COUNT(*) FROM attempts a WHERE a.exposure = 'exposed' AND NOT EXISTS \
         (SELECT 1 FROM transitions t WHERE t.attempt_id = a.attempt_id AND t.kind = 'exposure')",
    ),
    (
        "approved_submission_has_approval_and_attempt",
        "SELECT COUNT(*) FROM submissions s WHERE s.status = 'approved' AND \
         (NOT EXISTS (SELECT 1 FROM approvals a WHERE a.request_id = s.request_id \
              AND a.approval_id = s.approval_id) \
          OR NOT EXISTS (SELECT 1 FROM attempts t WHERE t.attempt_id = s.attempt_id))",
    ),
    (
        "approved_submission_has_audit_event",
        "SELECT COUNT(*) FROM submissions s WHERE s.status = 'approved' AND NOT EXISTS \
         (SELECT 1 FROM outbox o WHERE o.event_id = 'approved:' || s.request_id)",
    ),
    (
        "pipeline_run_follows_an_approved_attempt",
        "SELECT COUNT(*) FROM pipeline_runs p WHERE NOT EXISTS \
         (SELECT 1 FROM submissions s WHERE s.attempt_id = p.attempt_id \
          AND s.request_id = p.request_id AND s.approval_id = p.approval_id \
          AND s.status = 'approved')",
    ),
    (
        "pipeline_prepared_run_has_its_projection",
        "SELECT COUNT(*) FROM pipeline_runs p WHERE \
         (p.step IN ('prepared', 'released') AND p.release_key IS NULL) \
         OR (p.step NOT IN ('prepared', 'released', 'closed') AND p.release_key IS NOT NULL)",
    ),
    (
        "pipeline_assembled_run_has_its_records",
        "SELECT COUNT(*) FROM pipeline_runs p WHERE p.step IN ('assembled', 'prepared', 'released') \
         AND NOT EXISTS (SELECT 1 FROM pipeline_artifacts a WHERE a.attempt_id = p.attempt_id \
              AND a.execution IS NOT NULL AND a.receipt IS NOT NULL)",
    ),
    (
        "pipeline_receipt_has_audit_event",
        "SELECT COUNT(*) FROM pipeline_artifacts a WHERE a.receipt IS NOT NULL AND NOT EXISTS \
         (SELECT 1 FROM outbox o WHERE o.event_id = 'receipt:' || a.attempt_id)",
    ),
    (
        "pipeline_released_attempt_completed",
        "SELECT COUNT(*) FROM pipeline_runs p JOIN attempts a ON a.attempt_id = p.attempt_id \
         WHERE p.step IN ('assembled', 'prepared', 'released') AND a.state <> 'completed'",
    ),
    (
        "queued_request_has_permanent_claim",
        "SELECT COUNT(*) FROM intake_queue q WHERE NOT EXISTS \
         (SELECT 1 FROM intake_deliveries d WHERE d.delivery_id = q.delivery_id AND d.enqueued = 1)",
    ),
];

impl SqliteStore {
    /// Verify accounting and audit invariants (no SQLite structural check).
    pub fn verify_invariants(&self) -> Result<(), StoreError> {
        self.read(|tx| {
            for (name, sql) in CHECKS {
                let bad: i64 = tx.query_row(sql, [], |r| r.get(0))?;
                if bad != 0 {
                    return Err(StoreError::Invariant(name));
                }
            }
            // Outbox: contiguous sequence, payload digests and hash chain.
            let mut stmt =
                tx.prepare("SELECT seq, payload, payload_digest, chain FROM outbox ORDER BY seq")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            let mut prev = GENESIS_CHAIN.to_owned();
            for (expect, row) in (1i64..).zip(rows) {
                let (seq, payload, digest, chain) = row?;
                let actual = crate::migrations::hex(&Sha256::digest(payload.as_bytes()));
                if seq != expect || actual != digest || chain_of(&prev, seq, &digest) != chain {
                    return Err(StoreError::Invariant("outbox_chain"));
                }
                prev = chain;
            }
            Ok(())
        })
    }

    /// SQLite `integrity_check`, `foreign_key_check`, then
    /// [`SqliteStore::verify_invariants`].
    pub fn integrity_check(&self) -> Result<(), StoreError> {
        self.read(|tx| {
            let ok: String = tx.query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))?;
            if ok != "ok" {
                return Err(StoreError::Corrupt);
            }
            let mut stmt = tx.prepare("PRAGMA foreign_key_check")?;
            if stmt.query([])?.next()?.is_some() {
                return Err(StoreError::Invariant("foreign_keys"));
            }
            Ok(())
        })?;
        self.verify_invariants()
    }

    /// Write a consistent snapshot to a new owner-only file (`VACUUM INTO`).
    /// The destination must not exist. A restored snapshot must be compared
    /// to the last exported checkpoint before use
    /// ([`SqliteStore::verify_external_checkpoint`]).
    pub fn backup_to(&self, dest: &Path) -> Result<(), StoreError> {
        if std::fs::symlink_metadata(dest).is_ok() {
            return Err(StoreError::Io);
        }
        secure_fs::prepare(dest)?;
        let dest_str = dest.to_str().ok_or(StoreError::InvalidInput)?;
        let guard = self.lock();
        guard.execute("VACUUM INTO ?1", [dest_str])?;
        Ok(())
    }
}
