//! Queue outcomes, request links and pipeline state for the service daemon
//! (S5, migration 0007, ADR 0125 to 0127).
//!
//! Everything here is bookkeeping around the charging paths, never one of
//! them. No method in this file reserves, starts, exposes, settles, refunds
//! or changes a budget; the daemon reaches those only through the same
//! `approve_submission`, `start_attempt`, `record_exposure`, `finish` and
//! `recover` the CLI and the dispatcher use. What is stored:
//!
//! * the fate of each consumed queue item (a submission, a fixed-code denial,
//!   or a poison message set aside), written in the same transaction that
//!   marks the item done, together with one audit event;
//! * which pull request commit a submitted request came from (for Checks);
//! * the monotonic step of each approved attempt the daemon drives, and its
//!   private records (the aggregate artifact the engine reported, the
//!   execution record and the internal receipt), each written once.
//!
//! Every method is one transaction and idempotent: a repeat with the same
//! values is a no-op, a repeat with different values for a write-once field
//! is `IdentityConflict`.

use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_core::RunId;
use custodian_intake::ports::QueuedRequest;
use rusqlite::OptionalExtension;
use serde_json::json;

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::outbox::outbox_append;
use crate::store::{from_sql, sql_time, SqliteStore};

/// Longest accepted fixed reason or outcome word.
const MAX_WORD: usize = 64;
/// Largest private aggregate artifact the store keeps (the disclosure crate's
/// own cap is the same).
pub const MAX_AGGREGATES_BYTES: usize = 64 * 1024;
/// Largest stored execution record or internal receipt document.
const MAX_DOC_BYTES: usize = 64 * 1024;
/// Longest a queue lease may be deferred by one backoff.
pub const MAX_DEFER_SECS: u64 = 86_400;

fn word_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_WORD
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn secs(v: u64) -> Result<i64, StoreError> {
    sql_time(v)
}

// ---- queue ------------------------------------------------------------------

/// What became of a consumed queue item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueOutcome {
    /// A pending submission was recorded (or already existed).
    Submitted,
    /// Refused with a fixed code; nothing was recorded or charged.
    Denied,
    /// Set aside after bounded retries; nothing was recorded or charged.
    Poisoned,
}

impl QueueOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Denied => "denied",
            Self::Poisoned => "poisoned",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        [Self::Submitted, Self::Denied, Self::Poisoned]
            .into_iter()
            .find(|o| o.as_str() == s)
    }
}

/// The fate to record when a leased queue item is finished.
pub struct QueueSettle<'a> {
    pub outcome: QueueOutcome,
    /// A fixed lowercase word (`[a-z0-9_]{1,64}`); never free text.
    pub reason: &'a str,
    pub request_id: Option<&'a str>,
    /// The queued request, when a submission was recorded: its identifiers
    /// are linked to the request id so a Check can be posted for it.
    pub link: Option<&'a QueuedRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueOutcomeRecord {
    pub seq: u64,
    pub outcome: QueueOutcome,
    pub reason: String,
    pub request_id: Option<String>,
    pub attempts: u32,
    pub settled_at: u64,
}

/// The pull request a submitted request came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLinkRecord {
    pub request_id: String,
    pub delivery_id: String,
    pub installation_id: u64,
    pub repository_id: u64,
    pub pull_request: u64,
    pub head_sha: String,
}

impl SqliteStore {
    /// Push a leased item's lease out by `delay_secs` (bounded backoff): it
    /// is delivered again only after the lease lapses. Only the current
    /// holder may; a stale holder gets `LeaseLost`. The attempts counter is
    /// not touched here (it rose when the item was leased).
    pub fn queue_defer(
        &self,
        seq: u64,
        lease_token: u64,
        now: u64,
        delay_secs: u64,
    ) -> Result<(), StoreError> {
        if delay_secs == 0 || delay_secs > MAX_DEFER_SECS {
            return Err(StoreError::InvalidInput);
        }
        let (seq_i, tok, now_i) = (secs(seq)?, secs(lease_token)?, secs(now)?);
        let until = now_i
            .checked_add(secs(delay_secs)?)
            .ok_or(StoreError::InvalidInput)?;
        self.write(FaultOp::QueueRelease, |tx| {
            let n = tx.execute(
                "UPDATE intake_queue SET lease_expires_at = ?1, updated_at = ?2 \
                 WHERE seq = ?3 AND state = 'leased' AND lease_token = ?4",
                (until, now_i, seq_i, tok),
            )?;
            if n == 1 {
                Ok(())
            } else {
                Err(StoreError::LeaseLost)
            }
        })
    }

    /// Give a leased item back at once (graceful shutdown): it is `queued`
    /// again and the next consumer gets it with a higher fencing token.
    /// Idempotent for the holder; a stale holder gets `LeaseLost`.
    pub fn queue_release(&self, seq: u64, lease_token: u64, now: u64) -> Result<(), StoreError> {
        let (seq_i, tok, now_i) = (secs(seq)?, secs(lease_token)?, secs(now)?);
        self.write(FaultOp::QueueRelease, |tx| {
            let row: Option<(String, i64)> = tx
                .query_row(
                    "SELECT state, lease_token FROM intake_queue WHERE seq = ?1",
                    [seq_i],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None => Err(StoreError::NotFound),
                Some((state, token)) if state == "leased" && token == tok => {
                    tx.execute(
                        "UPDATE intake_queue SET state = 'queued', lease_owner = NULL, \
                         lease_expires_at = NULL, updated_at = ?1 WHERE seq = ?2",
                        (now_i, seq_i),
                    )?;
                    Ok(())
                }
                Some((state, token)) if state == "queued" && token == tok => Ok(()),
                Some(_) => Err(StoreError::LeaseLost),
            }
        })
    }

    /// Finish a leased item and record its fate, its link (when a submission
    /// was made) and one `queue.settled` audit event, in one transaction.
    /// Idempotent: finishing a done item succeeds and records nothing new.
    /// A consumer that no longer holds the lease gets `LeaseLost`.
    pub fn queue_settle(
        &self,
        seq: u64,
        lease_token: u64,
        now: u64,
        settle: &QueueSettle<'_>,
    ) -> Result<(), StoreError> {
        if !word_ok(settle.reason) {
            return Err(StoreError::InvalidInput);
        }
        let (seq_i, tok, now_i) = (secs(seq)?, secs(lease_token)?, secs(now)?);
        self.write(FaultOp::QueueSettle, |tx| {
            let row: Option<(String, i64, i64)> = tx
                .query_row(
                    "SELECT state, lease_token, attempts FROM intake_queue WHERE seq = ?1",
                    [seq_i],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let (state, token, attempts) = row.ok_or(StoreError::NotFound)?;
            if state == "done" {
                return Ok(());
            }
            if state != "leased" || token != tok {
                return Err(StoreError::LeaseLost);
            }
            tx.execute(
                "UPDATE intake_queue SET state = 'done', lease_owner = NULL, \
                 lease_expires_at = NULL, updated_at = ?1 WHERE seq = ?2",
                (now_i, seq_i),
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO queue_outcomes \
                 (seq, outcome, reason, request_id, attempts, settled_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    seq_i,
                    settle.outcome.as_str(),
                    settle.reason,
                    settle.request_id,
                    attempts,
                    now_i,
                ),
            )?;
            if let (Some(rid), Some(q)) = (settle.request_id, settle.link) {
                tx.execute(
                    "INSERT OR IGNORE INTO request_links (request_id, delivery_id, \
                     installation_id, repository_id, pull_request, head_sha, linked_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    (
                        rid,
                        q.delivery.as_str(),
                        secs(q.installation.get())?,
                        secs(q.repository.get())?,
                        secs(q.pull_request.get())?,
                        q.head_sha.as_str(),
                        now_i,
                    ),
                )?;
            }
            let mut payload = json!({
                "event": "queue.settled", "outcome": settle.outcome.as_str(),
                "reason": settle.reason, "attempt_no": attempts, "at": now_i,
            });
            if let (Some(rid), Some(obj)) = (settle.request_id, payload.as_object_mut()) {
                obj.insert("request_id".to_owned(), json!(rid));
            }
            outbox_append(
                tx,
                &format!("queue:{seq}"),
                "queue.settled",
                settle.request_id,
                None,
                &payload,
                now_i,
            )?;
            Ok(())
        })
    }

    /// The recorded fate of a queue item, if it was settled by the daemon.
    pub fn queue_outcome(&self, seq: u64) -> Result<Option<QueueOutcomeRecord>, StoreError> {
        let seq_i = secs(seq)?;
        self.read(|tx| {
            let raw: Option<(String, String, Option<String>, i64, i64)> = tx
                .query_row(
                    "SELECT outcome, reason, request_id, attempts, settled_at \
                     FROM queue_outcomes WHERE seq = ?1",
                    [seq_i],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            raw.map(|(o, reason, request_id, attempts, at)| {
                Ok(QueueOutcomeRecord {
                    seq,
                    outcome: QueueOutcome::parse(&o).ok_or(StoreError::Corrupt)?,
                    reason,
                    request_id,
                    attempts: u32::try_from(attempts).map_err(|_| StoreError::Corrupt)?,
                    settled_at: from_sql(at),
                })
            })
            .transpose()
        })
    }

    /// Every settled queue outcome, oldest first (at most `limit`, 1..=1000).
    pub fn queue_outcomes(&self, limit: u32) -> Result<Vec<QueueOutcomeRecord>, StoreError> {
        let limit = i64::from(limit.clamp(1, 1000));
        let seqs: Vec<i64> = self.read(|tx| {
            let mut stmt = tx.prepare("SELECT seq FROM queue_outcomes ORDER BY seq LIMIT ?1")?;
            let rows = stmt.query_map([limit], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut out = Vec::new();
        for s in seqs {
            if let Some(o) = self.queue_outcome(from_sql(s))? {
                out.push(o);
            }
        }
        Ok(out)
    }

    /// The pull request a submitted request came from, if it came from one.
    pub fn request_link(&self, request_id: &str) -> Result<Option<RequestLinkRecord>, StoreError> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT request_id, delivery_id, installation_id, repository_id, \
                     pull_request, head_sha FROM request_links WHERE request_id = ?1",
                    [request_id],
                    |r| {
                        Ok(RequestLinkRecord {
                            request_id: r.get(0)?,
                            delivery_id: r.get(1)?,
                            installation_id: from_sql(r.get(2)?),
                            repository_id: from_sql(r.get(3)?),
                            pull_request: from_sql(r.get(4)?),
                            head_sha: r.get(5)?,
                        })
                    },
                )
                .optional()?)
        })
    }
}

// ---- pipeline ---------------------------------------------------------------

/// Where an approved attempt is in the daemon's pipeline. Only moves forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PipelineStep {
    /// Discovered; not yet dispatched.
    Enrolled,
    /// The attempt reached a terminal state (and its result, if any, is kept).
    Dispatched,
    /// Execution record (and, when valid, internal receipt) stored.
    Assembled,
    /// A projection was prepared (charged) and awaits or has a release.
    Prepared,
    /// Delivered. Final.
    Released,
    /// Final without a release; `reason` says why.
    Closed,
}

impl PipelineStep {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enrolled => "enrolled",
            Self::Dispatched => "dispatched",
            Self::Assembled => "assembled",
            Self::Prepared => "prepared",
            Self::Released => "released",
            Self::Closed => "closed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Enrolled,
            Self::Dispatched,
            Self::Assembled,
            Self::Prepared,
            Self::Released,
            Self::Closed,
        ]
        .into_iter()
        .find(|x| x.as_str() == s)
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Closed)
    }
    fn rank(self) -> u8 {
        match self {
            Self::Enrolled => 1,
            Self::Dispatched => 2,
            Self::Assembled => 3,
            Self::Prepared => 4,
            Self::Released | Self::Closed => 5,
        }
    }
}

/// An approved submission and the attempt it reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedRun {
    pub request_id: String,
    pub attempt: RunId,
    pub approval_id: String,
}

/// The prepared-release identity, written once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedMark {
    pub prepared_at: u64,
    pub release_key: String,
    pub projection_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineRun {
    pub attempt: RunId,
    pub request_id: String,
    pub approval_id: String,
    pub step: PipelineStep,
    /// Fixed word: why the run is where it is (a waiting reason while open, a
    /// terminal reason once closed or released).
    pub reason: String,
    pub execution_id: Option<String>,
    pub prepared: Option<PreparedMark>,
    pub enrolled_at: u64,
    pub updated_at: u64,
}

/// The private records of a run. Restricted operational data.
#[derive(Clone, PartialEq, Eq)]
pub struct PipelineArtifacts {
    pub result_meta: Option<String>,
    pub aggregates: Option<Vec<u8>>,
    pub execution: Option<String>,
    pub receipt: Option<String>,
    pub receipt_digest: Option<String>,
}

impl core::fmt::Debug for PipelineArtifacts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipelineArtifacts")
            .field("aggregates", &self.aggregates.as_ref().map(Vec::len))
            .field("execution", &self.execution.is_some())
            .field("receipt", &self.receipt.is_some())
            .finish()
    }
}

/// What to store when a run is assembled.
pub struct AssembledRecords<'a> {
    /// Canonical `ExecutionRecord` document.
    pub execution: &'a str,
    pub execution_id: &'a str,
    /// Canonical `InternalReceipt` document and its document digest. Absent
    /// when the attempt did not produce a valid receipt (a failed, rejected
    /// or cancelled run). A partial run (some inputs measured, not all) keeps
    /// its receipt as a private record and is closed.
    pub receipt: Option<(&'a str, &'a str)>,
    pub plan_digest: &'a str,
    /// When set, the run is closed with this fixed reason instead of moving
    /// on to `assembled`.
    pub close_reason: Option<&'a str>,
}

const RUN_COLS: &str = "attempt_id, request_id, approval_id, step, reason, execution_id, \
    prepared_at, release_key, projection_digest, enrolled_at, updated_at";

#[allow(clippy::type_complexity)]
type RawRun = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    i64,
    i64,
);

fn raw_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRun> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
    ))
}

fn parse_run(raw: RawRun) -> Result<PipelineRun, StoreError> {
    let (attempt, request_id, approval_id, step, reason, execution_id, pat, key, digest, en, up) =
        raw;
    let prepared = match (pat, key, digest) {
        (Some(p), Some(k), Some(d)) => Some(PreparedMark {
            prepared_at: from_sql(p),
            release_key: k,
            projection_digest: d,
        }),
        (None, None, None) => None,
        _ => return Err(StoreError::Corrupt),
    };
    Ok(PipelineRun {
        attempt: RunId::new(attempt),
        request_id,
        approval_id,
        step: PipelineStep::parse(&step).ok_or(StoreError::Corrupt)?,
        reason,
        execution_id,
        prepared,
        enrolled_at: from_sql(en),
        updated_at: from_sql(up),
    })
}

fn load_run(tx: &rusqlite::Connection, attempt: &str) -> Result<Option<PipelineRun>, StoreError> {
    tx.query_row(
        &format!("SELECT {RUN_COLS} FROM pipeline_runs WHERE attempt_id = ?1"),
        [attempt],
        raw_run,
    )
    .optional()?
    .map(parse_run)
    .transpose()
}

impl SqliteStore {
    /// Approved submissions whose attempt the pipeline has not enrolled yet,
    /// oldest decision first (at most `limit`, 1..=200).
    pub fn approved_unenrolled(&self, limit: u32) -> Result<Vec<ApprovedRun>, StoreError> {
        let limit = i64::from(limit.clamp(1, 200));
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT s.request_id, s.attempt_id, s.approval_id FROM submissions s \
                 WHERE s.status = 'approved' AND s.attempt_id IS NOT NULL \
                   AND NOT EXISTS (SELECT 1 FROM pipeline_runs p WHERE p.attempt_id = s.attempt_id) \
                 ORDER BY s.decided_at, s.request_id LIMIT ?1",
            )?;
            let rows = stmt.query_map([limit], |r| {
                Ok(ApprovedRun {
                    request_id: r.get(0)?,
                    attempt: RunId::new(r.get::<_, String>(1)?),
                    approval_id: r.get(2)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Start driving an approved attempt. The attempt must belong to an
    /// approved submission of that request and approval. Idempotent: `false`
    /// when already enrolled.
    pub fn pipeline_enroll(&self, run: &ApprovedRun, now: u64) -> Result<bool, StoreError> {
        let now_i = secs(now)?;
        self.write(FaultOp::PipelineEnroll, |tx| {
            let ok: i64 = tx.query_row(
                "SELECT COUNT(*) FROM submissions WHERE request_id = ?1 AND attempt_id = ?2 \
                 AND approval_id = ?3 AND status = 'approved'",
                (&run.request_id, run.attempt.as_str(), &run.approval_id),
                |r| r.get(0),
            )?;
            if ok != 1 {
                return Err(StoreError::NotFound);
            }
            let n = tx.execute(
                "INSERT OR IGNORE INTO pipeline_runs (attempt_id, request_id, approval_id, \
                 step, reason, enrolled_at, updated_at) VALUES (?1, ?2, ?3, 'enrolled', \
                 'enrolled', ?4, ?4)",
                (
                    run.attempt.as_str(),
                    &run.request_id,
                    &run.approval_id,
                    now_i,
                ),
            )?;
            Ok(n == 1)
        })
    }

    pub fn pipeline_run(&self, attempt: &RunId) -> Result<Option<PipelineRun>, StoreError> {
        self.read(|tx| load_run(tx, attempt.as_str()))
    }

    /// Runs that are not final, oldest first (at most `limit`, 1..=200).
    pub fn pipeline_open(&self, limit: u32) -> Result<Vec<PipelineRun>, StoreError> {
        let limit = i64::from(limit.clamp(1, 200));
        self.read(|tx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {RUN_COLS} FROM pipeline_runs WHERE step NOT IN ('released', 'closed') \
                 ORDER BY enrolled_at, attempt_id LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], raw_run)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(parse_run(r?)?);
            }
            Ok(out)
        })
    }

    /// Every run, newest first (at most `limit`, 1..=200). For status output.
    pub fn pipeline_runs(&self, limit: u32) -> Result<Vec<PipelineRun>, StoreError> {
        let limit = i64::from(limit.clamp(1, 200));
        self.read(|tx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {RUN_COLS} FROM pipeline_runs ORDER BY enrolled_at DESC, attempt_id \
                 LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], raw_run)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(parse_run(r?)?);
            }
            Ok(out)
        })
    }

    /// Move a run to `step` (never backwards) and record the fixed `reason`.
    /// Moving to the step it is already at only updates the reason; a run
    /// that is final, or already past `step`, is left alone. Returns whether
    /// anything changed.
    pub fn pipeline_advance(
        &self,
        attempt: &RunId,
        step: PipelineStep,
        reason: &str,
        now: u64,
    ) -> Result<bool, StoreError> {
        if !word_ok(reason) {
            return Err(StoreError::InvalidInput);
        }
        let now_i = secs(now)?;
        self.write(FaultOp::PipelineStep, |tx| {
            let cur = load_run(tx, attempt.as_str())?.ok_or(StoreError::NotFound)?;
            if cur.step.is_terminal() || step.rank() < cur.step.rank() {
                return Ok(false);
            }
            if cur.step == step && cur.reason == reason {
                return Ok(false);
            }
            tx.execute(
                "UPDATE pipeline_runs SET step = ?1, reason = ?2, updated_at = ?3 \
                 WHERE attempt_id = ?4",
                (step.as_str(), reason, now_i, attempt.as_str()),
            )?;
            Ok(true)
        })
    }

    /// Keep the validated result of a run (its outcome and roster counters as
    /// `result_meta`, and the aggregate artifact when the engine reported
    /// one), before the attempt is settled. Write-once: the same values again
    /// are a no-op, different values are `IdentityConflict`.
    pub fn pipeline_store_result(
        &self,
        attempt: &RunId,
        result_meta: &str,
        aggregates: Option<&[u8]>,
        now: u64,
    ) -> Result<(), StoreError> {
        if result_meta.is_empty()
            || result_meta.len() > 1024
            || aggregates.is_some_and(|a| a.is_empty() || a.len() > MAX_AGGREGATES_BYTES)
        {
            return Err(StoreError::InvalidInput);
        }
        let now_i = secs(now)?;
        self.write(FaultOp::PipelineArtifacts, |tx| {
            load_run(tx, attempt.as_str())?.ok_or(StoreError::NotFound)?;
            type Row = (Option<String>, Option<Vec<u8>>);
            let cur: Option<Row> = tx
                .query_row(
                    "SELECT result_meta, aggregates FROM pipeline_artifacts \
                     WHERE attempt_id = ?1",
                    [attempt.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match cur {
                None => {
                    tx.execute(
                        "INSERT INTO pipeline_artifacts (attempt_id, result_meta, aggregates, \
                         stored_at) VALUES (?1, ?2, ?3, ?4)",
                        (attempt.as_str(), result_meta, aggregates, now_i),
                    )?;
                    Ok(())
                }
                Some((None, None)) => {
                    tx.execute(
                        "UPDATE pipeline_artifacts SET result_meta = ?1, aggregates = ?2 \
                         WHERE attempt_id = ?3",
                        (result_meta, aggregates, attempt.as_str()),
                    )?;
                    Ok(())
                }
                Some((meta, agg))
                    if meta.as_deref() == Some(result_meta) && agg.as_deref() == aggregates =>
                {
                    Ok(())
                }
                Some(_) => Err(StoreError::IdentityConflict),
            }
        })
    }

    /// Store the execution record and, when valid, the internal receipt, add
    /// one `receipt.issued` audit event for the receipt (so the signed ledger
    /// attests that exactly this receipt digest was issued) and advance the
    /// run: to `assembled` with a receipt, to `closed` without one. One
    /// transaction; write-once columns make a repeat with identical documents
    /// a no-op and a repeat with different documents `IdentityConflict`.
    pub fn pipeline_assemble(
        &self,
        attempt: &RunId,
        records: &AssembledRecords<'_>,
        now: u64,
    ) -> Result<(), StoreError> {
        let doc_ok = |d: &str| !d.is_empty() && d.len() <= MAX_DOC_BYTES;
        if !doc_ok(records.execution)
            || records.receipt.is_some_and(|(r, _)| !doc_ok(r))
            // A run with no close reason is assembled and must have a receipt.
            || (records.close_reason.is_none() && records.receipt.is_none())
            || records.close_reason.is_some_and(|c| !word_ok(c))
        {
            return Err(StoreError::InvalidInput);
        }
        let now_i = secs(now)?;
        self.write(FaultOp::PipelineArtifacts, |tx| {
            let run = load_run(tx, attempt.as_str())?.ok_or(StoreError::NotFound)?;
            type Row = (Option<String>, Option<String>, Option<String>);
            let cur: Option<Row> = tx
                .query_row(
                    "SELECT execution, receipt, receipt_digest FROM pipeline_artifacts \
                     WHERE attempt_id = ?1",
                    [attempt.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let (rec, dig) = match records.receipt {
                Some((r, d)) => (Some(r), Some(d)),
                None => (None, None),
            };
            match cur {
                None => {
                    tx.execute(
                        "INSERT INTO pipeline_artifacts (attempt_id, execution, receipt, \
                         receipt_digest, stored_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        (attempt.as_str(), records.execution, rec, dig, now_i),
                    )?;
                }
                Some((exe, r, d)) => {
                    let same = exe.as_deref().is_none_or(|e| e == records.execution)
                        && r.as_deref().is_none_or(|e| Some(e) == rec)
                        && d.as_deref().is_none_or(|e| Some(e) == dig);
                    if !same {
                        return Err(StoreError::IdentityConflict);
                    }
                    tx.execute(
                        "UPDATE pipeline_artifacts SET execution = ?1, receipt = ?2, \
                         receipt_digest = ?3 WHERE attempt_id = ?4",
                        (records.execution, rec, dig, attempt.as_str()),
                    )?;
                }
            }
            if let Some(prev) = &run.execution_id {
                if prev != records.execution_id {
                    return Err(StoreError::IdentityConflict);
                }
            }
            let (step, reason) = match records.close_reason {
                None => (PipelineStep::Assembled, "assembled"),
                Some(c) => (PipelineStep::Closed, c),
            };
            if !run.step.is_terminal() && step.rank() >= run.step.rank() {
                tx.execute(
                    "UPDATE pipeline_runs SET step = ?1, reason = ?2, execution_id = ?3, \
                     updated_at = ?4 WHERE attempt_id = ?5",
                    (
                        step.as_str(),
                        reason,
                        records.execution_id,
                        now_i,
                        attempt.as_str(),
                    ),
                )?;
            }
            if let Some((_, digest)) = records.receipt {
                outbox_append(
                    tx,
                    &format!("receipt:{}", attempt.as_str()),
                    "receipt.issued",
                    Some(&run.request_id),
                    Some(attempt.as_str()),
                    &json!({
                        "event": "receipt.issued", "request_id": run.request_id,
                        "attempt_id": attempt.as_str(), "plan_digest": records.plan_digest,
                        "document_digest": digest, "at": now_i,
                        "outcome": if records.close_reason.is_none() { "success" } else { "partial" },
                    }),
                    now_i,
                )?;
            }
            Ok(())
        })
    }

    /// The private records of a run.
    pub fn pipeline_artifacts(
        &self,
        attempt: &RunId,
    ) -> Result<Option<PipelineArtifacts>, StoreError> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT result_meta, aggregates, execution, receipt, receipt_digest \
                     FROM pipeline_artifacts WHERE attempt_id = ?1",
                    [attempt.as_str()],
                    |r| {
                        Ok(PipelineArtifacts {
                            result_meta: r.get(0)?,
                            aggregates: r.get(1)?,
                            execution: r.get(2)?,
                            receipt: r.get(3)?,
                            receipt_digest: r.get(4)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    /// Record the prepared release (once) and move the run to `prepared`. A
    /// repeat with the same values is a no-op; different values are
    /// `IdentityConflict` (a resumed pipeline must continue the projection it
    /// started, not produce another).
    pub fn pipeline_mark_prepared(
        &self,
        attempt: &RunId,
        mark: &PreparedMark,
        reason: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        if !word_ok(reason) {
            return Err(StoreError::InvalidInput);
        }
        let now_i = secs(now)?;
        let at = secs(mark.prepared_at)?;
        self.write(FaultOp::PipelineStep, |tx| {
            let run = load_run(tx, attempt.as_str())?.ok_or(StoreError::NotFound)?;
            if let Some(existing) = &run.prepared {
                return if existing == mark {
                    Ok(())
                } else {
                    Err(StoreError::IdentityConflict)
                };
            }
            // Only an assembled run (it has a receipt) can be prepared.
            if run.step != PipelineStep::Assembled {
                return Err(StoreError::InvalidTransition);
            }
            tx.execute(
                "UPDATE pipeline_runs SET step = 'prepared', reason = ?1, prepared_at = ?2, \
                 release_key = ?3, projection_digest = ?4, updated_at = ?5 \
                 WHERE attempt_id = ?6",
                (
                    reason,
                    at,
                    &mark.release_key,
                    &mark.projection_digest,
                    now_i,
                    attempt.as_str(),
                ),
            )?;
            Ok(())
        })
    }

    /// The approval document recorded for a request, as a contract record.
    pub fn approval_document(
        &self,
        request_id: &str,
        approval_id: &str,
    ) -> Result<Option<Approval>, StoreError> {
        self.read(|tx| {
            let doc: Option<Option<String>> = tx
                .query_row(
                    "SELECT document FROM approvals WHERE request_id = ?1 AND approval_id = ?2",
                    (request_id, approval_id),
                    |r| r.get(0),
                )
                .optional()?;
            doc.flatten()
                .map(|d| Approval::decode(d.as_bytes()).map_err(|_| StoreError::Corrupt))
                .transpose()
        })
    }
}
