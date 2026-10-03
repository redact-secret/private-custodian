//! Retention of the intake queue, delivery claims and submissions (HG-4,
//! ADR 0117).
//!
//! Growth is already bounded at the front (`MAX_PENDING_QUEUE`,
//! `MAX_PENDING_SUBMISSIONS`); this module bounds it at the back by removing
//! rows that are finished and fully accounted for. What is never removed:
//!
//! * budgets, requests, approvals, attempts, reservations, settlements,
//!   transitions, the outbox and every history table: no code here touches
//!   them, and the schema still refuses to delete them;
//! * a pending submission: it is first cancelled by an audited expiry, and
//!   only then becomes a terminal row;
//! * a decided submission while either audit event that describes it (the
//!   submission, the decision) is unacknowledged by the ledger export. The
//!   migration 0006 delete guard enforces this independently of this code;
//! * a delivery claim while a queue row still refers to it, or before its
//!   minimum age: replay protection must outlast what the sender can
//!   redeliver;
//! * anything younger than its configured minimum age, and no minimum may be
//!   configured below the hard floors in [`RetentionPolicy::FLOOR`].
//!
//! Every pass is two transactions (expiry, then purge); a crash leaves each
//! either fully done or not at all, and a repeated pass converges. The purge
//! commits its audit event with the deletes.

use rusqlite::Transaction;
use serde_json::json;

use custodian_core::ActorId;

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::outbox::outbox_append;
use crate::store::{from_sql, sql_time, SqliteStore};

/// Ages and batch size for a retention pass.
///
/// **The values are placeholders that need a human decision** (register HG-4,
/// docs/backup-recovery.md section 5). [`RetentionPolicy::PLACEHOLDER`] exists
/// so tests and the first operator run have something; the repository does
/// not decide what a deployment keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// A finished (`done`) queue item may be removed this long after it
    /// finished.
    pub queue_done_min_age_secs: u64,
    /// A delivery claim may be removed this long after it was made, and only
    /// when no queue row refers to it. This is the replay-protection window.
    pub claim_min_age_secs: u64,
    /// An approved or cancelled submission may be removed this long after its
    /// decision, and only when both its audit events are acknowledged.
    pub decided_submission_min_age_secs: u64,
    /// A submission still pending after this long is cancelled (audited,
    /// holds no budget) and becomes eligible for removal after
    /// `decided_submission_min_age_secs`.
    pub pending_submission_max_age_secs: u64,
    /// Most rows one pass removes per table (1 to 1000).
    pub batch_limit: u32,
}

impl RetentionPolicy {
    /// Hard floors. A policy below any of these is refused, whatever the
    /// caller asks for.
    pub const FLOOR: RetentionPolicy = RetentionPolicy {
        queue_done_min_age_secs: 86_400,
        claim_min_age_secs: 7 * 86_400,
        decided_submission_min_age_secs: 7 * 86_400,
        pending_submission_max_age_secs: 86_400,
        batch_limit: 1,
    };

    /// PLACEHOLDER values, not a decision: seven days for finished queue
    /// items, thirty for claims and pending submissions, ninety for decided
    /// submissions.
    pub const PLACEHOLDER: RetentionPolicy = RetentionPolicy {
        queue_done_min_age_secs: 7 * 86_400,
        claim_min_age_secs: 30 * 86_400,
        decided_submission_min_age_secs: 90 * 86_400,
        pending_submission_max_age_secs: 30 * 86_400,
        batch_limit: 500,
    };

    pub fn validate(&self) -> Result<(), StoreError> {
        let f = &Self::FLOOR;
        let ok = self.queue_done_min_age_secs >= f.queue_done_min_age_secs
            && self.claim_min_age_secs >= f.claim_min_age_secs
            && self.decided_submission_min_age_secs >= f.decided_submission_min_age_secs
            && self.pending_submission_max_age_secs >= f.pending_submission_max_age_secs
            && (1..=1000).contains(&self.batch_limit);
        if ok {
            Ok(())
        } else {
            Err(StoreError::InvalidInput)
        }
    }
}

/// What one retention pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Pending submissions cancelled by the audited expiry.
    pub expired_pending: u64,
    pub purged_queue: u64,
    pub purged_claims: u64,
    pub purged_submissions: u64,
    /// Decided submissions old enough to remove that were kept because an
    /// audit event is still unacknowledged. Export, then run again.
    pub kept_unacknowledged: u64,
}

fn cutoff(now: i64, age: u64) -> Result<i64, StoreError> {
    Ok(now.saturating_sub(sql_time(age)?))
}

const ELIGIBLE_SUBMISSIONS: &str = "\
    SELECT s.request_id FROM submissions s \
    WHERE s.status <> 'pending' AND s.decided_at <= ?1 \
      AND EXISTS (SELECT 1 FROM outbox o WHERE o.event_id = 'submitted:' || s.request_id \
                  AND o.exported_at IS NOT NULL) \
      AND EXISTS (SELECT 1 FROM outbox o WHERE o.event_id = \
                  (CASE s.status WHEN 'approved' THEN 'approved:' ELSE 'cancelled:' END) \
                  || s.request_id AND o.exported_at IS NOT NULL)";

fn expire_pending(
    tx: &Transaction<'_>,
    policy: &RetentionPolicy,
    actor: &ActorId,
    now: i64,
) -> Result<u64, StoreError> {
    let before = cutoff(now, policy.pending_submission_max_age_secs)?;
    let ids: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT request_id FROM submissions WHERE status = 'pending' AND submitted_at <= ?1 \
             ORDER BY submitted_at, request_id LIMIT ?2",
        )?;
        let rows = stmt.query_map((before, i64::from(policy.batch_limit)), |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for id in &ids {
        tx.execute(
            "UPDATE submissions SET status = 'cancelled', decided_by = ?1, \
             decided_kind = 'service', decided_at = ?2 WHERE request_id = ?3 \
             AND status = 'pending'",
            (actor.as_str(), now, id),
        )?;
        outbox_append(
            tx,
            &format!("cancelled:{id}"),
            "request.cancelled",
            Some(id),
            None,
            &json!({
                "event": "request.cancelled", "request_id": id, "reason": "retention_expired",
                "actor": actor.as_str(), "actor_kind": "service", "at": now,
            }),
            now,
        )?;
    }
    Ok(ids.len() as u64)
}

impl SqliteStore {
    /// One retention pass: expire stale pending submissions, then remove
    /// terminal rows that are old enough and fully acknowledged. Idempotent
    /// and safe to repeat or to interrupt at any point (module
    /// documentation). Returns what it did.
    pub fn run_retention(
        &self,
        policy: &RetentionPolicy,
        actor: &ActorId,
        now: u64,
    ) -> Result<RetentionReport, StoreError> {
        policy.validate()?;
        let now_i = sql_time(now)?;
        let expired = self.write(FaultOp::RetentionExpire, |tx| {
            expire_pending(tx, policy, actor, now_i)
        })?;
        let mut report = self.write(FaultOp::RetentionPurge, |tx| {
            let batch = i64::from(policy.batch_limit);
            let mut r = RetentionReport::default();

            // Finished queue items first: they release the claims.
            let q = tx.execute(
                "DELETE FROM intake_queue WHERE seq IN (SELECT seq FROM intake_queue \
                 WHERE state = 'done' AND updated_at <= ?1 ORDER BY seq LIMIT ?2)",
                (cutoff(now_i, policy.queue_done_min_age_secs)?, batch),
            )?;
            r.purged_queue = q as u64;

            let c = tx.execute(
                "DELETE FROM intake_deliveries WHERE delivery_id IN (\
                 SELECT d.delivery_id FROM intake_deliveries d WHERE d.claimed_at <= ?1 \
                 AND NOT EXISTS (SELECT 1 FROM intake_queue q WHERE q.delivery_id = d.delivery_id) \
                 ORDER BY d.claimed_at LIMIT ?2)",
                (cutoff(now_i, policy.claim_min_age_secs)?, batch),
            )?;
            r.purged_claims = c as u64;

            let sub_cut = cutoff(now_i, policy.decided_submission_min_age_secs)?;
            let s = tx.execute(
                &format!(
                    "DELETE FROM submissions WHERE request_id IN ({ELIGIBLE_SUBMISSIONS} \
                     ORDER BY s.decided_at, s.request_id LIMIT ?2)"
                ),
                (sub_cut, batch),
            )?;
            r.purged_submissions = s as u64;

            let kept: i64 = tx.query_row(
                &format!(
                    "SELECT COUNT(*) FROM submissions WHERE status <> 'pending' \
                     AND decided_at <= ?1 AND request_id NOT IN ({ELIGIBLE_SUBMISSIONS})"
                ),
                [sub_cut],
                |row| row.get(0),
            )?;
            r.kept_unacknowledged = from_sql(kept);

            if r.purged_queue + r.purged_claims + r.purged_submissions > 0 {
                let n: i64 =
                    tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM outbox", [], |row| {
                        row.get(0)
                    })?;
                outbox_append(
                    tx,
                    &format!("retention:{n}"),
                    "retention.purged",
                    None,
                    None,
                    &json!({
                        "event": "retention.purged", "actor": actor.as_str(),
                        "purged_queue": r.purged_queue, "purged_claims": r.purged_claims,
                        "purged_submissions": r.purged_submissions, "at": now_i,
                    }),
                    now_i,
                )?;
            }
            Ok(r)
        })?;
        report.expired_pending = expired;
        Ok(report)
    }
}
