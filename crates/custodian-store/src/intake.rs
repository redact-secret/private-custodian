//! Durable request intake (C10, ADR 0080 to 0083).
//!
//! Three groups of operations, all in migration 0004:
//!
//! * the GitHub request-edge ports of `custodian-intake` (`DeliveryStore`,
//!   `InstallationRegistry`, `IntakeQueue`) made durable, plus the queue's
//!   consumer side;
//! * submissions: a validated request that waits for an explicit approval.
//!   Approving one runs the *same* `reserve_tx` the contract path uses, in
//!   the same transaction that marks the submission approved, so the CLI and
//!   the GitHub path share idempotency keys, epoch gates and budget
//!   accounting by construction;
//! * the append-only policy activation history that approvals and the
//!   eligibility gates read.
//!
//! Every method is one transaction. Nothing here can lower or reset a
//! budget; budget changes happen only inside `reserve_tx` and the settlement
//! paths of C4.

use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::{ActivationRef, ActorKind};
use custodian_contracts::policy::{ObservedActivation, PolicyActivation};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::{ActorRef, Timestamp};
use custodian_core::{ActorId, RunId, RunState};
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{
    Claim, DeliveryStore, InstallationRegistry, IntakeQueue, QueuedRequest,
};
use custodian_intake::IntakeReason;
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::lifecycle::{epoch_key, gate_epoch};
use crate::model::ReserveOutcome;
use crate::ops::{intake_from_contracts, reserve_tx};
use crate::outbox::outbox_append;
use crate::store::{from_sql, sql_time, SqliteStore};

/// A claim that never produced a queue row lapses after this many seconds, so
/// a crash between claim and enqueue cannot lose the delivery forever.
pub const CLAIM_WINDOW_SECS: u64 = 300;
/// Most requests that may wait in the queue (state `queued` or `leased`).
/// At capacity the queue refuses; it never evicts.
pub const MAX_PENDING_QUEUE: i64 = 4096;
/// Most submissions that may wait for a decision. A flood of requests from one
/// identity cannot grow the table without bound; at the limit `submit_request`
/// refuses with `StoreError::Constraint` and records nothing.
pub const MAX_PENDING_SUBMISSIONS: i64 = 1024;

fn unavailable<T>(r: Result<T, StoreError>) -> Result<T, IntakeReason> {
    r.map_err(|_| IntakeReason::StoreUnavailable)
}

fn secs(v: u64) -> Result<i64, StoreError> {
    sql_time(v)
}

// ---- GitHub edge ports ------------------------------------------------------

impl DeliveryStore for SqliteStore {
    /// One atomic check-and-insert (one `BEGIN IMMEDIATE` transaction): of
    /// any number of concurrent claims for one id, exactly one gets `New`.
    /// A claim that already produced a queue row is permanent. A claim that
    /// did not lapses after [`CLAIM_WINDOW_SECS`] and is handed out again to
    /// exactly one claimant.
    fn claim(&self, id: &DeliveryId) -> Result<Claim, IntakeReason> {
        let now = self.cfg.clock.now();
        unavailable(self.write(FaultOp::IntakeClaim, |tx| {
            let now_i = secs(now)?;
            let row: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT claimed_at, enqueued FROM intake_deliveries WHERE delivery_id = ?1",
                    [id.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None => {
                    tx.execute(
                        "INSERT INTO intake_deliveries (delivery_id, claimed_at, enqueued) \
                         VALUES (?1, ?2, 0)",
                        (id.as_str(), now_i),
                    )?;
                    Ok(Claim::New)
                }
                Some((claimed_at, 0))
                    if now_i.saturating_sub(claimed_at) >= secs(CLAIM_WINDOW_SECS)? =>
                {
                    tx.execute(
                        "UPDATE intake_deliveries SET claimed_at = ?1 WHERE delivery_id = ?2",
                        (now_i, id.as_str()),
                    )?;
                    Ok(Claim::New)
                }
                Some(_) => Ok(Claim::Seen),
            }
        }))
    }

    fn release(&self, id: &DeliveryId) -> Result<(), IntakeReason> {
        unavailable(self.write(FaultOp::IntakeClaim, |tx| {
            // The trigger refuses to forget a claim that produced a queue row.
            tx.execute(
                "DELETE FROM intake_deliveries WHERE delivery_id = ?1 AND enqueued = 0",
                [id.as_str()],
            )?;
            Ok(())
        }))
    }
}

impl InstallationRegistry for SqliteStore {
    fn installation_removed(&self, installation: InstallationId) -> Result<bool, IntakeReason> {
        unavailable(self.read(|tx| removed(tx, installation.get(), 0)))
    }

    fn repository_removed(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<bool, IntakeReason> {
        unavailable(self.read(|tx| removed(tx, installation.get(), repository.get())))
    }

    fn mark_installation_removed(&self, installation: InstallationId) -> Result<(), IntakeReason> {
        self.mark_removed(installation.get(), 0)
    }

    fn mark_repository_removed(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<(), IntakeReason> {
        self.mark_removed(installation.get(), repository.get())
    }
}

fn removed(tx: &Connection, installation: u64, repository: u64) -> Result<bool, StoreError> {
    let n: i64 = tx.query_row(
        "SELECT COUNT(*) FROM intake_removals WHERE installation_id = ?1 AND repository_id = ?2",
        (secs(installation)?, secs(repository)?),
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

impl SqliteStore {
    fn mark_removed(&self, installation: u64, repository: u64) -> Result<(), IntakeReason> {
        let now = self.cfg.clock.now();
        unavailable(self.write(FaultOp::IntakeRemoval, |tx| {
            tx.execute(
                "INSERT OR IGNORE INTO intake_removals (installation_id, repository_id, removed_at) \
                 VALUES (?1, ?2, ?3)",
                (secs(installation)?, secs(repository)?, secs(now)?),
            )?;
            Ok(())
        }))
    }
}

impl IntakeQueue for SqliteStore {
    /// Record the request for later processing. Idempotent per delivery id (a
    /// repeat is a no-op). Marks the delivery claim permanent in the same
    /// transaction. Refuses at capacity.
    fn enqueue(&self, request: QueuedRequest) -> Result<(), IntakeReason> {
        let r = self.write(FaultOp::IntakeEnqueue, |tx| {
            let now = secs(self.cfg.clock.now())?;
            let depth: i64 = tx.query_row(
                "SELECT COUNT(*) FROM intake_queue WHERE state <> 'done'",
                [],
                |r| r.get(0),
            )?;
            let exists: i64 = tx.query_row(
                "SELECT COUNT(*) FROM intake_queue WHERE delivery_id = ?1",
                [request.delivery.as_str()],
                |r| r.get(0),
            )?;
            if exists == 0 {
                if depth >= MAX_PENDING_QUEUE {
                    return Err(StoreError::Constraint);
                }
                tx.execute(
                    "INSERT INTO intake_queue (delivery_id, installation_id, repository_id, \
                     pull_request, head_sha, actor, github_user, received_at, state, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9)",
                    (
                        request.delivery.as_str(),
                        secs(request.installation.get())?,
                        secs(request.repository.get())?,
                        secs(request.pull_request.get())?,
                        request.head_sha.as_str(),
                        request.actor.as_str(),
                        secs(request.github_user.get())?,
                        secs(request.received_at.secs())?,
                        now,
                    ),
                )?;
            }
            tx.execute(
                "INSERT INTO intake_deliveries (delivery_id, claimed_at, enqueued) \
                 VALUES (?1, ?2, 1) \
                 ON CONFLICT (delivery_id) DO UPDATE SET enqueued = 1",
                (request.delivery.as_str(), now),
            )?;
            Ok(())
        });
        r.map_err(|e| match e {
            StoreError::Constraint => IntakeReason::QueueUnavailable,
            _ => IntakeReason::StoreUnavailable,
        })
    }
}

/// A queue item leased to a consumer. Delivery is at-least-once: if the
/// lease lapses before [`SqliteStore::queue_complete`], the item is leased
/// again, so the consumer must be idempotent. The reservation idempotency key
/// is what makes it so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedRequest {
    pub seq: u64,
    pub request: QueuedRequest,
    /// How many times this item has been leased, including this lease.
    pub attempts: u32,
    pub lease_token: u64,
    pub lease_expires_at: u64,
}

fn queued_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawQueued> {
    Ok(RawQueued {
        seq: r.get(0)?,
        delivery: r.get(1)?,
        installation: r.get(2)?,
        repository: r.get(3)?,
        pull_request: r.get(4)?,
        head_sha: r.get(5)?,
        actor: r.get(6)?,
        github_user: r.get(7)?,
        received_at: r.get(8)?,
        attempts: r.get(9)?,
    })
}

struct RawQueued {
    seq: i64,
    delivery: String,
    installation: i64,
    repository: i64,
    pull_request: i64,
    head_sha: String,
    actor: String,
    github_user: i64,
    received_at: i64,
    attempts: i64,
}

impl RawQueued {
    fn parse(self) -> Result<(u64, u32, QueuedRequest), StoreError> {
        let bad = |_| StoreError::Corrupt;
        Ok((
            from_sql(self.seq),
            u32::try_from(self.attempts).map_err(|_| StoreError::Corrupt)?,
            QueuedRequest {
                delivery: DeliveryId::parse(&self.delivery).map_err(bad)?,
                installation: InstallationId::new(from_sql(self.installation))
                    .ok_or(StoreError::Corrupt)?,
                repository: RepositoryId::new(from_sql(self.repository))
                    .ok_or(StoreError::Corrupt)?,
                pull_request: PullRequestNumber::new(from_sql(self.pull_request))
                    .ok_or(StoreError::Corrupt)?,
                head_sha: HeadSha::parse(&self.head_sha).map_err(bad)?,
                actor: ActorRef::parse(&self.actor).map_err(|_| StoreError::Corrupt)?,
                github_user: GithubUserId::new(from_sql(self.github_user))
                    .ok_or(StoreError::Corrupt)?,
                received_at: Timestamp::new(from_sql(self.received_at))
                    .map_err(|_| StoreError::Corrupt)?,
            },
        ))
    }
}

impl SqliteStore {
    /// Lease the oldest request that is queued, or whose previous lease
    /// lapsed. One consumer gets it; the fencing token rises on every lease.
    pub fn queue_lease(
        &self,
        owner: &str,
        now: u64,
        lease_secs: u64,
    ) -> Result<Option<LeasedRequest>, StoreError> {
        if owner.is_empty() || owner.len() > 128 || lease_secs == 0 {
            return Err(StoreError::InvalidInput);
        }
        let now_i = secs(now)?;
        let expires = now_i
            .checked_add(secs(lease_secs)?)
            .ok_or(StoreError::InvalidInput)?;
        self.write(FaultOp::IntakeLease, |tx| {
            let raw = tx
                .query_row(
                    "SELECT seq, delivery_id, installation_id, repository_id, pull_request, \
                     head_sha, actor, github_user, received_at, attempts FROM intake_queue \
                     WHERE state = 'queued' OR (state = 'leased' AND lease_expires_at <= ?1) \
                     ORDER BY seq LIMIT 1",
                    [now_i],
                    queued_from_row,
                )
                .optional()?;
            let Some(raw) = raw else { return Ok(None) };
            let seq = raw.seq;
            let (seq_u, attempts, request) = raw.parse()?;
            let token: i64 = tx.query_row(
                "SELECT lease_token FROM intake_queue WHERE seq = ?1",
                [seq],
                |r| r.get(0),
            )?;
            let token = token + 1;
            tx.execute(
                "UPDATE intake_queue SET state = 'leased', lease_owner = ?1, lease_token = ?2, \
                 lease_expires_at = ?3, attempts = attempts + 1, updated_at = ?4 WHERE seq = ?5",
                (owner, token, expires, now_i, seq),
            )?;
            Ok(Some(LeasedRequest {
                seq: seq_u,
                request,
                attempts: attempts + 1,
                lease_token: from_sql(token),
                lease_expires_at: from_sql(expires),
            }))
        })
    }

    /// Mark a leased item done. Idempotent: completing a done item succeeds.
    /// A consumer that no longer holds the lease gets `LeaseLost`.
    pub fn queue_complete(&self, seq: u64, lease_token: u64, now: u64) -> Result<(), StoreError> {
        let now_i = secs(now)?;
        let seq_i = secs(seq)?;
        let token_i = secs(lease_token)?;
        self.write(FaultOp::IntakeComplete, |tx| {
            let row: Option<(String, i64)> = tx
                .query_row(
                    "SELECT state, lease_token FROM intake_queue WHERE seq = ?1",
                    [seq_i],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None => Err(StoreError::NotFound),
                Some((state, _)) if state == "done" => Ok(()),
                Some((state, token)) if state == "leased" && token == token_i => {
                    tx.execute(
                        "UPDATE intake_queue SET state = 'done', lease_owner = NULL, \
                         lease_expires_at = NULL, updated_at = ?1 WHERE seq = ?2",
                        (now_i, seq_i),
                    )?;
                    Ok(())
                }
                Some(_) => Err(StoreError::LeaseLost),
            }
        })
    }

    /// Requests waiting (queued or leased, not done).
    pub fn queue_depth(&self) -> Result<u64, StoreError> {
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM intake_queue WHERE state <> 'done'",
                [],
                |r| r.get(0),
            )?;
            Ok(from_sql(n))
        })
    }
}

// ---- Submissions ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionChannel {
    Cli,
    App,
}

impl SubmissionChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::App => "app",
        }
    }
    fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "cli" => Ok(Self::Cli),
            "app" => Ok(Self::App),
            _ => Err(StoreError::Corrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionStatus {
    Pending,
    Approved,
    Cancelled,
}

impl SubmissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Cancelled => "cancelled",
        }
    }
    fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(StoreError::Corrupt),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionRecord {
    pub request_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub plan_digest: String,
    pub requester: String,
    pub submitted_by: String,
    pub channel: SubmissionChannel,
    pub submitted_at: u64,
    pub status: SubmissionStatus,
    pub decided_by: Option<String>,
    pub decided_at: Option<u64>,
    pub approval_id: Option<String>,
    pub attempt_id: Option<String>,
}

pub struct SubmitCommand<'a> {
    pub request: &'a EvaluationRequest,
    pub channel: SubmissionChannel,
    /// The authenticated principal that submitted it. Recorded, never
    /// trusted as the requester: the requester is the request's
    /// `asserted_actor`, which the caller has already checked against the
    /// authenticated identity.
    pub submitted_by: &'a ActorRef,
    pub now: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submitted {
    /// Recorded now, waiting for approval.
    New,
    /// The same request was submitted before; its current status.
    Replay(SubmissionStatus),
    /// The idempotency key is already reserved (for example by the GitHub
    /// path). Nothing was recorded and nothing will be charged again.
    ReservedElsewhere { attempt: RunId, state: RunState },
}

pub struct ApproveCommand<'a> {
    pub request_id: &'a str,
    /// The approval record the CLI composed. The store re-checks every
    /// binding: request, plan, candidate, population, budget, activation,
    /// time, agent and self-approval.
    pub approval: &'a Approval,
    pub now: Timestamp,
    pub max_state_age_secs: u64,
    pub reservation_window_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApproveOutcome {
    pub reserve: ReserveOutcome,
}

const SUBMISSION_COLS: &str = "request_id, idempotency_key, request_digest, plan_digest, \
    requester, submitted_by, channel, submitted_at, status, decided_by, decided_at, \
    approval_id, attempt_id";

fn submission_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawSubmission> {
    Ok(RawSubmission {
        request_id: r.get(0)?,
        idempotency_key: r.get(1)?,
        request_digest: r.get(2)?,
        plan_digest: r.get(3)?,
        requester: r.get(4)?,
        submitted_by: r.get(5)?,
        channel: r.get(6)?,
        submitted_at: r.get(7)?,
        status: r.get(8)?,
        decided_by: r.get(9)?,
        decided_at: r.get(10)?,
        approval_id: r.get(11)?,
        attempt_id: r.get(12)?,
    })
}

struct RawSubmission {
    request_id: String,
    idempotency_key: String,
    request_digest: String,
    plan_digest: String,
    requester: String,
    submitted_by: String,
    channel: String,
    submitted_at: i64,
    status: String,
    decided_by: Option<String>,
    decided_at: Option<i64>,
    approval_id: Option<String>,
    attempt_id: Option<String>,
}

impl RawSubmission {
    fn parse(self) -> Result<SubmissionRecord, StoreError> {
        Ok(SubmissionRecord {
            request_id: self.request_id,
            idempotency_key: self.idempotency_key,
            request_digest: self.request_digest,
            plan_digest: self.plan_digest,
            requester: self.requester,
            submitted_by: self.submitted_by,
            channel: SubmissionChannel::parse(&self.channel)?,
            submitted_at: from_sql(self.submitted_at),
            status: SubmissionStatus::parse(&self.status)?,
            decided_by: self.decided_by,
            decided_at: self.decided_at.map(from_sql),
            approval_id: self.approval_id,
            attempt_id: self.attempt_id,
        })
    }
}

fn load_submission(tx: &Connection, request_id: &str) -> Result<Option<RawSubmission>, StoreError> {
    Ok(tx
        .query_row(
            &format!("SELECT {SUBMISSION_COLS} FROM submissions WHERE request_id = ?1"),
            [request_id],
            submission_from_row,
        )
        .optional()?)
}

fn check_window(secs_: u64) -> Result<i64, StoreError> {
    if secs_ == 0 {
        return Err(StoreError::InvalidInput);
    }
    sql_time(secs_)
}

impl SqliteStore {
    /// Record a validated request that waits for an approval. Idempotent per
    /// request: the same document again reports its status; the same key or
    /// id with a different document is a conflict. If the idempotency key is
    /// already reserved (by any channel) nothing is recorded.
    pub fn submit_request(&self, cmd: &SubmitCommand<'_>) -> Result<Submitted, StoreError> {
        cmd.request.validate()?;
        let digest = cmd.request.document_digest()?.as_str().to_owned();
        let plan_digest = cmd.request.plan.plan_digest()?.as_str().to_owned();
        let document = String::from_utf8(cmd.request.canonical_bytes()?)
            .map_err(|_| StoreError::InvalidInput)?;
        let now = secs(cmd.now.secs())?;
        let request_id = cmd.request.request_id.as_str();
        let key = cmd.request.idempotency_key.as_str();
        self.write(FaultOp::SubmitRequest, |tx| {
            // Already reserved through any path: report, record nothing.
            let reserved: Option<(String, String)> = tx
                .query_row(
                    "SELECT request_id, request_digest FROM requests WHERE idempotency_key = ?1",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((rid, rdigest)) = reserved {
                if rid != request_id || rdigest != digest {
                    return Err(StoreError::IdempotencyConflict);
                }
                let row =
                    crate::store::load_latest_attempt(tx, &rid)?.ok_or(StoreError::Corrupt)?;
                return Ok(Submitted::ReservedElsewhere {
                    attempt: RunId::new(row.attempt_id),
                    state: row.state,
                });
            }
            let by_key: Option<(String, String)> = tx
                .query_row(
                    "SELECT request_id, request_digest FROM submissions \
                     WHERE idempotency_key = ?1 OR request_id = ?2",
                    (key, request_id),
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((rid, rdigest)) = by_key {
                if rid != request_id || rdigest != digest {
                    return Err(StoreError::IdempotencyConflict);
                }
                let raw = load_submission(tx, &rid)?.ok_or(StoreError::Corrupt)?;
                return Ok(Submitted::Replay(raw.parse()?.status));
            }
            let waiting: i64 = tx.query_row(
                "SELECT COUNT(*) FROM submissions WHERE status = 'pending'",
                [],
                |r| r.get(0),
            )?;
            if waiting >= MAX_PENDING_SUBMISSIONS {
                return Err(StoreError::Constraint);
            }
            // A blocked epoch takes no new request. The reservation checks
            // again; failing here just spares the approver the wait.
            gate_epoch(tx, &epoch_key("contract", None, Some(&document))?)?;
            tx.execute(
                "INSERT INTO submissions (request_id, idempotency_key, request_digest, \
                 plan_digest, document, requester, submitted_by, channel, submitted_at, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending')",
                (
                    request_id,
                    key,
                    &digest,
                    &plan_digest,
                    &document,
                    cmd.request.asserted_actor.as_str(),
                    cmd.submitted_by.as_str(),
                    cmd.channel.as_str(),
                    now,
                ),
            )?;
            outbox_append(
                tx,
                &format!("submitted:{request_id}"),
                "request.submitted",
                Some(request_id),
                None,
                &json!({
                    "event": "request.submitted", "request_id": request_id,
                    "plan_digest": plan_digest, "requester": cmd.request.asserted_actor.as_str(),
                    "actor": cmd.submitted_by.as_str(),
                    "channel": cmd.channel.as_str(), "at": now,
                }),
                now,
            )?;
            Ok(Submitted::New)
        })
    }

    /// The pending request's canonical document, for composing an approval.
    pub fn submission_request(
        &self,
        request_id: &str,
    ) -> Result<Option<(EvaluationRequest, SubmissionRecord)>, StoreError> {
        self.read(|tx| {
            let doc: Option<String> = tx
                .query_row(
                    "SELECT document FROM submissions WHERE request_id = ?1",
                    [request_id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(doc) = doc else { return Ok(None) };
            let request =
                EvaluationRequest::decode(doc.as_bytes()).map_err(|_| StoreError::Corrupt)?;
            let raw = load_submission(tx, request_id)?.ok_or(StoreError::Corrupt)?;
            Ok(Some((request, raw.parse()?)))
        })
    }

    pub fn submission(&self, request_id: &str) -> Result<Option<SubmissionRecord>, StoreError> {
        self.read(|tx| {
            load_submission(tx, request_id)?
                .map(RawSubmission::parse)
                .transpose()
        })
    }

    /// Submissions, newest first, at most `limit` (1..=200).
    pub fn submissions(&self, limit: u32) -> Result<Vec<SubmissionRecord>, StoreError> {
        let limit = i64::from(limit.clamp(1, 200));
        self.read(|tx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {SUBMISSION_COLS} FROM submissions ORDER BY submitted_at DESC, request_id \
                 LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], submission_from_row)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?.parse()?);
            }
            Ok(out)
        })
    }

    /// Approve a pending submission: re-check everything, reserve through the
    /// same `reserve_tx` the contract path uses, and mark the submission
    /// approved, in one transaction.
    ///
    /// Refusals (each writes nothing): unknown request, already decided
    /// (repeat approval, cancelled, or reserved through another path), the
    /// approver is the requester, an agent approver, any binding failure
    /// (plan, candidate, population, budget scope, activation, expiry), a
    /// stale or missing activation observation, a blocked epoch. An exhausted
    /// budget is not a refusal: the denial is recorded exactly as on the
    /// contract path (`ReserveOutcome::state == Denied`).
    pub fn approve_submission(
        &self,
        cmd: &ApproveCommand<'_>,
    ) -> Result<ApproveOutcome, StoreError> {
        let window = check_window(cmd.reservation_window_secs)?;
        let now = secs(cmd.now.secs())?;
        let approval_id = cmd.approval.approval_id.as_str();
        self.write(FaultOp::ApproveSubmission, |tx| {
            let raw = load_submission(tx, cmd.request_id)?.ok_or(StoreError::NotFound)?;
            let rec = raw.parse()?;
            if rec.status != SubmissionStatus::Pending {
                return Err(StoreError::AlreadyDecided);
            }
            // Structural separation of duties, independent of any caller.
            if cmd.approval.approver_kind == ActorKind::Agent {
                return Err(StoreError::Binding(
                    custodian_contracts::BindingError::ApproverNotPermitted,
                ));
            }
            if cmd.approval.approver.as_str() == rec.requester
                || cmd.approval.approver == cmd.approval.proposer
            {
                return Err(StoreError::SelfApproval);
            }
            let doc: String = tx.query_row(
                "SELECT document FROM submissions WHERE request_id = ?1",
                [cmd.request_id],
                |r| r.get(0),
            )?;
            let request =
                EvaluationRequest::decode(doc.as_bytes()).map_err(|_| StoreError::Corrupt)?;
            // Read the activation state inside this transaction: the policy
            // that is checked is the policy that is current at the reservation.
            let observed = observe_tx(tx, &cmd.approval.activation, cmd.now)?.ok_or(
                StoreError::Binding(custodian_contracts::BindingError::StateStale),
            )?;
            let intake = intake_from_contracts(
                &request,
                cmd.approval,
                &observed,
                cmd.now,
                cmd.max_state_age_secs,
            )?;
            let reserve = reserve_tx(tx, &intake, now, window)?;
            if reserve.replay {
                // Reserved through another path with another approval: this
                // approval was not used and is not recorded.
                return Err(StoreError::AlreadyDecided);
            }
            tx.execute(
                "UPDATE submissions SET status = 'approved', decided_by = ?1, decided_kind = ?2, \
                 decided_at = ?3, approval_id = ?4, attempt_id = ?5 WHERE request_id = ?6",
                (
                    cmd.approval.approver.as_str(),
                    kind_str(cmd.approval.approver_kind),
                    now,
                    approval_id,
                    reserve.attempt.as_str(),
                    cmd.request_id,
                ),
            )?;
            outbox_append(
                tx,
                &format!("approved:{}", cmd.request_id),
                "approval.granted",
                Some(cmd.request_id),
                Some(reserve.attempt.as_str()),
                &json!({
                    "event": "approval.granted", "request_id": cmd.request_id,
                    "approval_id": approval_id,
                    "actor": cmd.approval.approver.as_str(),
                    "actor_kind": kind_str(cmd.approval.approver_kind),
                    "requester": rec.requester, "plan_digest": rec.plan_digest,
                    "activation_id": cmd.approval.activation.activation_id.as_str(),
                    "activation_sequence": cmd.approval.activation.sequence.get(),
                    "attempt_id": reserve.attempt.as_str(),
                    "state": crate::model::state_str(reserve.state),
                    "reason": crate::model::reason_str(reserve.reason),
                    "at": now,
                }),
                now,
            )?;
            Ok(ApproveOutcome { reserve })
        })
    }

    /// Cancel a submission that has not been approved. Idempotent. An
    /// approved one is cancelled through its attempt (`cancel`), which keeps
    /// the C4 settlement rules.
    pub fn cancel_submission(
        &self,
        request_id: &str,
        actor: &ActorRef,
        kind: ActorKind,
        now: Timestamp,
    ) -> Result<SubmissionStatus, StoreError> {
        let now = secs(now.secs())?;
        self.write(FaultOp::CancelSubmission, |tx| {
            let rec = load_submission(tx, request_id)?
                .ok_or(StoreError::NotFound)?
                .parse()?;
            match rec.status {
                SubmissionStatus::Cancelled => Ok(SubmissionStatus::Cancelled),
                SubmissionStatus::Approved => Err(StoreError::AlreadyDecided),
                SubmissionStatus::Pending => {
                    tx.execute(
                        "UPDATE submissions SET status = 'cancelled', decided_by = ?1, \
                         decided_kind = ?2, decided_at = ?3 WHERE request_id = ?4",
                        (actor.as_str(), kind_str(kind), now, request_id),
                    )?;
                    outbox_append(
                        tx,
                        &format!("cancelled:{request_id}"),
                        "request.cancelled",
                        Some(request_id),
                        None,
                        &json!({
                            "event": "request.cancelled", "request_id": request_id,
                            "actor": actor.as_str(), "actor_kind": kind_str(kind), "at": now,
                        }),
                        now,
                    )?;
                    Ok(SubmissionStatus::Cancelled)
                }
            }
        })
    }

    /// The latest attempt of a request, if it was reserved.
    pub fn latest_attempt_of(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::model::AttemptRecord>, StoreError> {
        self.read(|tx| {
            Ok(crate::store::load_latest_attempt(tx, request_id)?.map(|r| r.into_record()))
        })
    }

    /// Request document of a reserved request (contract origin only).
    pub fn reserved_request(
        &self,
        request_id: &str,
    ) -> Result<Option<EvaluationRequest>, StoreError> {
        self.read(|tx| {
            let doc: Option<Option<String>> = tx
                .query_row(
                    "SELECT document FROM requests WHERE request_id = ?1",
                    [request_id],
                    |r| r.get(0),
                )
                .optional()?;
            doc.flatten()
                .map(|d| EvaluationRequest::decode(d.as_bytes()).map_err(|_| StoreError::Corrupt))
                .transpose()
        })
    }
}

fn kind_str(k: ActorKind) -> &'static str {
    match k {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
    }
}

// ---- Policy activations --------------------------------------------------------

fn latest_activation_tx(
    tx: &Connection,
    activation_id: &str,
) -> Result<Option<PolicyActivation>, StoreError> {
    let doc: Option<String> = tx
        .query_row(
            "SELECT document FROM policy_activations WHERE activation_id = ?1 \
             ORDER BY sequence DESC LIMIT 1",
            [activation_id],
            |r| r.get(0),
        )
        .optional()?;
    doc.map(|d| PolicyActivation::decode(d.as_bytes()).map_err(|_| StoreError::Corrupt))
        .transpose()
}

fn observe_tx(
    tx: &Connection,
    binding: &ActivationRef,
    now: Timestamp,
) -> Result<Option<ObservedActivation>, StoreError> {
    Ok(
        latest_activation_tx(tx, binding.activation_id.as_str())?.map(|activation| {
            ObservedActivation {
                activation,
                // Read inside the caller's transaction, just now.
                observed_at: now,
            }
        }),
    )
}

impl SqliteStore {
    /// Append an activation state. A higher sequence is a new state; the
    /// same sequence with identical bytes is a replay (`false`); the same or
    /// a lower sequence with different bytes is refused. The caller (the
    /// CLI) restricts this to a human operator who names the exact id and
    /// sequence; the store only guarantees append-only monotonicity.
    pub fn record_activation(
        &self,
        activation: &PolicyActivation,
        actor: &ActorId,
        now: u64,
    ) -> Result<bool, StoreError> {
        activation.validate()?;
        let document = String::from_utf8(activation.canonical_bytes()?)
            .map_err(|_| StoreError::InvalidInput)?;
        let digest = activation.document_digest()?.as_str().to_owned();
        let id = activation.activation_id.as_str();
        let seq = secs(activation.sequence.get())?;
        let now_i = secs(now)?;
        let status = match activation.status {
            custodian_contracts::policy::ActivationStatus::Active => "active",
            custodian_contracts::policy::ActivationStatus::Revoked => "revoked",
            custodian_contracts::policy::ActivationStatus::Superseded => "superseded",
        };
        let kind = serde_json::to_value(activation.policy.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(StoreError::InvalidInput)?;
        self.write(FaultOp::RecordActivation, |tx| {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT document_digest FROM policy_activations \
                     WHERE activation_id = ?1 AND sequence = ?2",
                    (id, seq),
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(d) = existing {
                return if d == digest {
                    Ok(false)
                } else {
                    Err(StoreError::IdentityConflict)
                };
            }
            // The trigger refuses a non-increasing sequence; checking first
            // gives the caller a fixed error instead of a constraint.
            let max: i64 = tx.query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM policy_activations WHERE activation_id = ?1",
                [id],
                |r| r.get(0),
            )?;
            if seq <= max {
                return Err(StoreError::IdentityConflict);
            }
            tx.execute(
                "INSERT INTO policy_activations (activation_id, sequence, policy_kind, status, \
                 document, document_digest, recorded_by, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (id, seq, kind, status, &document, &digest, actor.as_str(), now_i),
            )?;
            outbox_append(
                tx,
                &format!("activation:{id}:{seq}"),
                "activation.recorded",
                None,
                None,
                &json!({
                    "event": "activation.recorded", "activation_id": id,
                    "activation_sequence": seq, "state": status, "document_digest": digest,
                    "actor": actor.as_str(), "at": now_i,
                }),
                now_i,
            )?;
            Ok(true)
        })
    }

    /// The newest recorded state of an activation.
    pub fn latest_activation(
        &self,
        activation_id: &str,
    ) -> Result<Option<PolicyActivation>, StoreError> {
        self.read(|tx| latest_activation_tx(tx, activation_id))
    }

    /// The newest state for the activation `binding` names, stamped with the
    /// time of this read. `None` when no state is recorded.
    pub fn observe_activation(
        &self,
        binding: &ActivationRef,
        now: Timestamp,
    ) -> Result<Option<ObservedActivation>, StoreError> {
        self.read(|tx| observe_tx(tx, binding, now))
    }
}
