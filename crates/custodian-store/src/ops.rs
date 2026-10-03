//! Lifecycle operations. Each public method is exactly one transaction
//! (`SqliteStore::write`): dedupe, budget check, charge and state change
//! commit together or not at all.

use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{BudgetKind, BudgetScope};
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::policy::ObservedActivation;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::{Reservation, ReservationState};
use custodian_contracts::types::Timestamp;
use custodian_contracts::Contract;
use custodian_core::{ActorId, Exposure, ReasonCode, RunId, RunState};
use rusqlite::{OptionalExtension, Transaction};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::migrations::hex;
use crate::model::*;
use crate::outbox::outbox_append;
use crate::store::*;

pub(crate) fn kind_str(k: BudgetKind) -> &'static str {
    match k {
        BudgetKind::Run => "run",
        BudgetKind::ReleaseQuery => "release_query",
    }
}

/// Budget identity: a digest of the kind and the canonical scope. A blind
/// scope carries its lineage, so a new candidate digest alone maps to the
/// same key and gets no fresh budget.
pub fn budget_scope_key(kind: BudgetKind, scope: &BudgetScope) -> Result<String, StoreError> {
    let bytes = to_canonical_bytes(scope)?;
    Ok(scope_key_of(kind_str(kind), &bytes))
}

pub(crate) fn scope_key_of(kind: &str, canonical: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/store/budget-scope/v1\0");
    h.update(kind.as_bytes());
    h.update([0]);
    h.update(canonical);
    hex(&h.finalize())
}

pub(crate) fn digest_of(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/store/identity/v1");
    for p in parts {
        h.update([0]);
        h.update(p.as_bytes());
    }
    hex(&h.finalize())
}

/// Everything the store persists for a request and its approval, already
/// validated (contract path) or synthesized (port path).
pub(crate) struct Intake {
    pub request_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub plan_digest: String,
    pub scope_key: String,
    pub kind: &'static str,
    pub units: i64,
    pub max_retries: i64,
    pub actor: String,
    pub requested_at: i64,
    pub origin: &'static str,
    pub subject: Option<String>,
    pub document: Option<String>,
    pub approval_id: String,
    pub approval_digest: String,
    pub approver: String,
    pub activation_id: String,
    pub activation_seq: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub approval_doc: Option<String>,
}

fn utf8(bytes: Vec<u8>) -> Result<String, StoreError> {
    String::from_utf8(bytes).map_err(|_| StoreError::InvalidInput)
}

fn intake_from_contracts(
    req: &EvaluationRequest,
    approval: &Approval,
    observed: &ObservedActivation,
    now: Timestamp,
    max_age: u64,
) -> Result<Intake, StoreError> {
    req.validate()?;
    approval.validate()?;
    // Reject before any write: plan, candidate, population, budget scope,
    // activation binding, approval window and current activation state.
    approval.check_for_execution(req, observed, now, max_age)?;
    let acc = &req.plan.accounting;
    let scope_bytes = to_canonical_bytes(&acc.budget)?;
    let kind = kind_str(acc.kind);
    Ok(Intake {
        request_id: req.request_id.as_str().to_owned(),
        idempotency_key: req.idempotency_key.as_str().to_owned(),
        request_digest: req.document_digest()?.as_str().to_owned(),
        plan_digest: req.plan.plan_digest()?.as_str().to_owned(),
        scope_key: scope_key_of(kind, &scope_bytes),
        kind,
        units: i64::try_from(acc.units.get()).map_err(|_| StoreError::InvalidInput)?,
        max_retries: i64::try_from(acc.max_retries.get()).map_err(|_| StoreError::InvalidInput)?,
        actor: req.asserted_actor.as_str().to_owned(),
        requested_at: sql_time(req.requested_at.secs())?,
        origin: "contract",
        subject: None,
        document: Some(utf8(req.canonical_bytes()?)?),
        approval_id: approval.approval_id.as_str().to_owned(),
        approval_digest: approval.document_digest()?.as_str().to_owned(),
        approver: approval.approver.as_str().to_owned(),
        activation_id: approval.activation.activation_id.as_str().to_owned(),
        activation_seq: i64::try_from(approval.activation.sequence.get())
            .map_err(|_| StoreError::InvalidInput)?,
        issued_at: sql_time(approval.issued_at.secs())?,
        expires_at: sql_time(approval.expires_at.secs())?,
        approval_doc: Some(utf8(approval.canonical_bytes()?)?),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push_transition(
    tx: &Transaction<'_>,
    attempt_id: &str,
    request_id: &str,
    is_exposure: bool,
    from: Option<RunState>,
    to: RunState,
    actor: &str,
    reason: ReasonCode,
    auth_ref: &str,
    at: i64,
) -> Result<(), StoreError> {
    let seq: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM transitions WHERE attempt_id = ?1",
        [attempt_id],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO transitions (attempt_id, seq, request_id, kind, from_state, to_state, \
         actor, reason, authorization_ref, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        (
            attempt_id,
            seq,
            request_id,
            if is_exposure {
                "exposure"
            } else {
                "transition"
            },
            from.map(state_str),
            state_str(to),
            actor,
            reason_str(reason),
            auth_ref,
            at,
        ),
    )?;
    Ok(())
}

fn replay_outcome(tx: &Transaction<'_>, row: &AttemptRow) -> Result<ReserveOutcome, StoreError> {
    Ok(ReserveOutcome {
        attempt: RunId::new(row.attempt_id.clone()),
        request_id: row.request_id.clone(),
        reservation_id: row.reservation_id.clone(),
        attempt_no: u32::try_from(row.attempt_no).map_err(|_| StoreError::Corrupt)?,
        state: row.state,
        reason: last_reason(tx, &row.attempt_id)?,
        replay: true,
    })
}

fn insert_approval(tx: &Transaction<'_>, i: &Intake) -> Result<(), StoreError> {
    let existing: Option<String> = tx
        .query_row(
            "SELECT approval_digest FROM approvals WHERE request_id = ?1 AND approval_id = ?2",
            (&i.request_id, &i.approval_id),
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        Some(d) if d == i.approval_digest => Ok(()),
        Some(_) => Err(StoreError::IdentityConflict),
        None => {
            tx.execute(
                "INSERT INTO approvals (request_id, approval_id, approval_digest, approver, \
                 activation_id, activation_seq, issued_at, expires_at, document) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                (
                    &i.request_id,
                    &i.approval_id,
                    &i.approval_digest,
                    &i.approver,
                    &i.activation_id,
                    i.activation_seq,
                    i.issued_at,
                    i.expires_at,
                    &i.approval_doc,
                ),
            )?;
            Ok(())
        }
    }
}

/// Create attempt `attempt_no`: hold budget and move
/// `proposed -> authorized -> reserved`, or record a denial when the budget
/// cannot cover the units. Called inside the caller's transaction.
fn create_attempt(
    tx: &Transaction<'_>,
    i: &Intake,
    attempt_no: i64,
    prior_attempt: Option<&str>,
    now: i64,
    window: i64,
) -> Result<ReserveOutcome, StoreError> {
    let budget: Option<(i64, i64, i64)> = tx
        .query_row(
            "SELECT limit_units, held_units, consumed_units FROM budgets WHERE scope_key = ?1",
            [&i.scope_key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let affordable = budget.is_some_and(|(l, h, c)| l - h - c >= i.units);
    let actor = i.actor.as_str();
    let auth = i.approval_id.as_str();
    let attempt_id = format!("exe_{}", SqliteStore::new_suffix(tx)?);

    if !affordable {
        if let Some(prior) = prior_attempt {
            // A refused retry creates no attempt; the refusal is audited.
            outbox_append(
                tx,
                &format!("retry-denied:{}:{attempt_no}", i.request_id),
                "retry.denied",
                Some(&i.request_id),
                Some(prior),
                &json!({
                    "event": "retry.denied", "request_id": i.request_id,
                    "attempt_no": attempt_no, "reason": "budget_exhausted",
                    "scope_key": i.scope_key, "units": i.units, "at": now,
                }),
                now,
            )?;
            return Ok(ReserveOutcome {
                attempt: RunId::new(prior.to_owned()),
                request_id: i.request_id.clone(),
                reservation_id: None,
                attempt_no: u32::try_from(attempt_no).map_err(|_| StoreError::InvalidInput)?,
                state: RunState::Denied,
                reason: ReasonCode::BudgetExhausted,
                replay: false,
            });
        }
        tx.execute(
            "INSERT INTO attempts (attempt_id, request_id, attempt_no, state, exposure, \
             authorization_ref, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'denied', 'not_exposed', ?4, ?5, ?5)",
            (&attempt_id, &i.request_id, attempt_no, auth, now),
        )?;
        push_transition(
            tx,
            &attempt_id,
            &i.request_id,
            false,
            None,
            RunState::Proposed,
            actor,
            ReasonCode::Requested,
            auth,
            now,
        )?;
        push_transition(
            tx,
            &attempt_id,
            &i.request_id,
            false,
            Some(RunState::Proposed),
            RunState::Denied,
            actor,
            ReasonCode::BudgetExhausted,
            auth,
            now,
        )?;
        outbox_append(
            tx,
            &format!("denied:{attempt_id}"),
            "request.denied",
            Some(&i.request_id),
            Some(&attempt_id),
            &json!({
                "event": "request.denied", "request_id": i.request_id,
                "attempt_id": attempt_id, "plan_digest": i.plan_digest,
                "scope_key": i.scope_key, "units": i.units,
                "state": "denied", "reason": "budget_exhausted", "at": now,
            }),
            now,
        )?;
        return Ok(ReserveOutcome {
            attempt: RunId::new(attempt_id),
            request_id: i.request_id.clone(),
            reservation_id: None,
            attempt_no: u32::try_from(attempt_no).map_err(|_| StoreError::InvalidInput)?,
            state: RunState::Denied,
            reason: ReasonCode::BudgetExhausted,
            replay: false,
        });
    }

    let reservation_id = format!("rsv_{}", SqliteStore::new_suffix(tx)?);
    let lease_expires_at = now.checked_add(window).ok_or(StoreError::InvalidInput)?;
    tx.execute(
        "INSERT INTO attempts (attempt_id, request_id, attempt_no, state, exposure, \
         authorization_ref, reservation_id, lease_expires_at, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'reserved', 'not_exposed', ?4, ?5, ?6, ?7, ?7)",
        (
            &attempt_id,
            &i.request_id,
            attempt_no,
            auth,
            &reservation_id,
            lease_expires_at,
            now,
        ),
    )?;
    tx.execute(
        "INSERT INTO reservations (reservation_id, attempt_id, request_id, approval_id, \
         plan_digest, scope_key, kind, units, state, exposure, reserved_at, lease_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'held', 'not_exposed', ?9, ?10)",
        (
            &reservation_id,
            &attempt_id,
            &i.request_id,
            auth,
            &i.plan_digest,
            &i.scope_key,
            i.kind,
            i.units,
            now,
            lease_expires_at,
        ),
    )?;
    // Charge at reservation. The CHECK on budgets makes over-commit
    // unrepresentable even if the affordability test above were wrong.
    tx.execute(
        "UPDATE budgets SET held_units = held_units + ?1 WHERE scope_key = ?2",
        (i.units, &i.scope_key),
    )?;
    push_transition(
        tx,
        &attempt_id,
        &i.request_id,
        false,
        None,
        RunState::Proposed,
        actor,
        ReasonCode::Requested,
        auth,
        now,
    )?;
    push_transition(
        tx,
        &attempt_id,
        &i.request_id,
        false,
        Some(RunState::Proposed),
        RunState::Authorized,
        actor,
        ReasonCode::Authorized,
        auth,
        now,
    )?;
    push_transition(
        tx,
        &attempt_id,
        &i.request_id,
        false,
        Some(RunState::Authorized),
        RunState::Reserved,
        actor,
        ReasonCode::BudgetReserved,
        auth,
        now,
    )?;
    outbox_append(
        tx,
        &format!("reserve:{attempt_id}"),
        "reservation.created",
        Some(&i.request_id),
        Some(&attempt_id),
        &json!({
            "event": "reservation.created", "request_id": i.request_id,
            "attempt_id": attempt_id, "attempt_no": attempt_no,
            "reservation_id": reservation_id, "approval_id": i.approval_id,
            "plan_digest": i.plan_digest, "scope_key": i.scope_key,
            "units": i.units, "state": "reserved", "reason": "budget_reserved", "at": now,
        }),
        now,
    )?;
    Ok(ReserveOutcome {
        attempt: RunId::new(attempt_id),
        request_id: i.request_id.clone(),
        reservation_id: Some(reservation_id),
        attempt_no: u32::try_from(attempt_no).map_err(|_| StoreError::InvalidInput)?,
        state: RunState::Reserved,
        reason: ReasonCode::BudgetReserved,
        replay: false,
    })
}

pub(crate) fn reserve_tx(
    tx: &Transaction<'_>,
    i: &Intake,
    now: i64,
    window: i64,
) -> Result<ReserveOutcome, StoreError> {
    let by_key: Option<(String, String)> = tx
        .query_row(
            "SELECT request_id, request_digest FROM requests WHERE idempotency_key = ?1",
            [&i.idempotency_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((request_id, digest)) = by_key {
        // Same key, different request: refuse. Same request: replay.
        if request_id != i.request_id || digest != i.request_digest {
            return Err(StoreError::IdempotencyConflict);
        }
        let latest = load_latest_attempt(tx, &request_id)?.ok_or(StoreError::Corrupt)?;
        return replay_outcome(tx, &latest);
    }
    let same_id: Option<String> = tx
        .query_row(
            "SELECT request_id FROM requests WHERE request_id = ?1",
            [&i.request_id],
            |r| r.get(0),
        )
        .optional()?;
    if same_id.is_some() {
        return Err(StoreError::IdentityConflict);
    }
    tx.execute(
        "INSERT INTO requests (request_id, idempotency_key, request_digest, plan_digest, \
         scope_key, kind, units, max_retries, actor, requested_at, origin, subject, document) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        (
            &i.request_id,
            &i.idempotency_key,
            &i.request_digest,
            &i.plan_digest,
            &i.scope_key,
            i.kind,
            i.units,
            i.max_retries,
            &i.actor,
            i.requested_at,
            i.origin,
            &i.subject,
            &i.document,
        ),
    )?;
    insert_approval(tx, i)?;
    create_attempt(tx, i, 1, None, now, window)
}

fn check_window(secs: u64) -> Result<i64, StoreError> {
    if secs == 0 {
        return Err(StoreError::InvalidInput);
    }
    sql_time(secs)
}

impl SqliteStore {
    /// Provision or raise a budget limit. A limit can only rise, never fall,
    /// and consumption is never reset: restoring budget is a reviewed policy
    /// revision, not a store operation. Raising is recorded in the outbox.
    pub fn provision_budget(
        &self,
        kind: BudgetKind,
        scope: &BudgetScope,
        limit: u64,
        actor: &ActorId,
        now: u64,
    ) -> Result<BudgetStatus, StoreError> {
        let bytes = to_canonical_bytes(scope)?;
        let key = scope_key_of(kind_str(kind), &bytes);
        self.provision_raw(kind_str(kind), &key, &utf8(bytes)?, limit, actor, now)
    }

    pub(crate) fn provision_raw(
        &self,
        kind: &str,
        key: &str,
        scope_json: &str,
        limit: u64,
        actor: &ActorId,
        now: u64,
    ) -> Result<BudgetStatus, StoreError> {
        let limit_i = sql_time(limit)?;
        let now_i = sql_time(now)?;
        self.write(FaultOp::ProvisionBudget, |tx| {
            let cur: Option<i64> = tx
                .query_row(
                    "SELECT limit_units FROM budgets WHERE scope_key = ?1",
                    [key],
                    |r| r.get(0),
                )
                .optional()?;
            match cur {
                Some(c) if limit_i < c => return Err(StoreError::InvalidInput),
                Some(c) if limit_i == c => {}
                other => {
                    if other.is_none() {
                        tx.execute(
                            "INSERT INTO budgets (scope_key, kind, scope_json, limit_units) \
                             VALUES (?1, ?2, ?3, ?4)",
                            (key, kind, scope_json, limit_i),
                        )?;
                    } else {
                        tx.execute(
                            "UPDATE budgets SET limit_units = ?1 WHERE scope_key = ?2",
                            (limit_i, key),
                        )?;
                    }
                    outbox_append(
                        tx,
                        &format!("provision:{key}:{limit_i}"),
                        "budget.provisioned",
                        None,
                        None,
                        &json!({
                            "event": "budget.provisioned", "scope_key": key, "kind": kind,
                            "previous_limit": other, "limit": limit_i,
                            "actor": actor.as_str(), "at": now_i,
                        }),
                        now_i,
                    )?;
                }
            }
            budget_status_tx(tx, key)?.ok_or(StoreError::Corrupt)
        })
    }

    /// Dedupe by idempotency key, check approval and activation, check and
    /// charge the budget, and move `proposed -> authorized -> reserved`, all
    /// in one transaction. A replay returns the existing attempt and never
    /// charges. Insufficient budget records a denial (`state == Denied`).
    pub fn reserve_request(&self, cmd: &ReserveCommand<'_>) -> Result<ReserveOutcome, StoreError> {
        let window = check_window(cmd.reservation_window_secs)?;
        let intake = intake_from_contracts(
            cmd.request,
            cmd.approval,
            cmd.observed,
            cmd.now,
            cmd.max_state_age_secs,
        )?;
        let now = sql_time(cmd.now.secs())?;
        self.write(FaultOp::Reserve, |tx| reserve_tx(tx, &intake, now, window))
    }

    /// Create the next attempt of a request after `from_attempt_no` failed or
    /// expired. Every check of a first reservation runs again and the budget
    /// is charged again: no retry is free, and exposure is never forgiven.
    pub fn retry_attempt(&self, cmd: &RetryCommand<'_>) -> Result<ReserveOutcome, StoreError> {
        let window = check_window(cmd.reservation_window_secs)?;
        let intake = intake_from_contracts(
            cmd.request,
            cmd.approval,
            cmd.observed,
            cmd.now,
            cmd.max_state_age_secs,
        )?;
        let now = sql_time(cmd.now.secs())?;
        let from_no = i64::from(cmd.from_attempt_no);
        self.write(FaultOp::Retry, |tx| {
            let stored: Option<(String, i64)> = tx
                .query_row(
                    "SELECT request_digest, max_retries FROM requests WHERE request_id = ?1",
                    [&intake.request_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (digest, max_retries) = stored.ok_or(StoreError::NotFound)?;
            if digest != intake.request_digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let from =
                load_attempt_by_no(tx, &intake.request_id, from_no)?.ok_or(StoreError::NotFound)?;
            if let Some(next) = load_attempt_by_no(tx, &intake.request_id, from_no + 1)? {
                return replay_outcome(tx, &next);
            }
            if !matches!(from.state, RunState::Failed | RunState::Expired) || from_no > max_retries
            {
                return Err(StoreError::RetryRefused);
            }
            insert_approval(tx, &intake)?;
            create_attempt(
                tx,
                &intake,
                from_no + 1,
                Some(&from.attempt_id),
                now,
                window,
            )
        })
    }

    /// Take the lease and move `reserved -> running`. Exactly one caller
    /// wins; a duplicate start finds the attempt already running and is
    /// refused, so nothing executes twice. For attempts reserved through the
    /// contract API the approval and reservation are re-checked against
    /// freshly observed activation state.
    pub fn start_attempt(&self, cmd: &StartCommand<'_>) -> Result<Lease, StoreError> {
        let now = sql_time(cmd.now)?;
        let ttl = check_window(cmd.lease_secs)?;
        let expires = now.checked_add(ttl).ok_or(StoreError::InvalidInput)?;
        if cmd.owner.is_empty() || cmd.owner.len() > 128 {
            return Err(StoreError::InvalidInput);
        }
        self.write(FaultOp::Start, |tx| {
            let row = load_attempt(tx, cmd.attempt.as_str())?.ok_or(StoreError::NotFound)?;
            if row.state != RunState::Reserved {
                return Err(StoreError::InvalidTransition);
            }
            if row.lease_expires_at.is_none_or(|e| e <= now) {
                return Err(StoreError::LeaseLost);
            }
            let origin: String = tx.query_row(
                "SELECT origin FROM requests WHERE request_id = ?1",
                [&row.request_id],
                |r| r.get(0),
            )?;
            if origin == "contract" {
                let observed = cmd.observed.ok_or(StoreError::Binding(
                    custodian_contracts::BindingError::StateStale,
                ))?;
                check_documents(
                    tx,
                    &row,
                    observed,
                    Timestamp::new(cmd.now)?,
                    cmd.max_state_age_secs,
                )?;
            }
            let token = row.lease_token + 1;
            let n = tx.execute(
                "UPDATE attempts SET state = 'running', lease_owner = ?1, lease_token = ?2, \
                 lease_expires_at = ?3, version = version + 1, updated_at = ?4 \
                 WHERE attempt_id = ?5 AND version = ?6 AND state = 'reserved'",
                (cmd.owner, token, expires, now, &row.attempt_id, row.version),
            )?;
            if n != 1 {
                return Err(StoreError::InvalidTransition);
            }
            push_transition(
                tx,
                &row.attempt_id,
                &row.request_id,
                false,
                Some(RunState::Reserved),
                RunState::Running,
                cmd.actor.as_str(),
                ReasonCode::BudgetReserved,
                &row.authorization_ref,
                now,
            )?;
            outbox_append(
                tx,
                &format!("started:{}", row.attempt_id),
                "attempt.started",
                Some(&row.request_id),
                Some(&row.attempt_id),
                &json!({
                    "event": "attempt.started", "request_id": row.request_id,
                    "attempt_id": row.attempt_id, "state": "running",
                    "lease_token": token, "at": now,
                }),
                now,
            )?;
            Ok(Lease {
                attempt: cmd.attempt.clone(),
                owner: cmd.owner.to_owned(),
                token: from_sql(token),
                expires_at: from_sql(expires),
            })
        })
    }

    /// Extend a live lease. Refused once the lease expired or was fenced.
    pub fn renew_lease(
        &self,
        lease: &Lease,
        now: u64,
        lease_secs: u64,
    ) -> Result<Lease, StoreError> {
        let now_i = sql_time(now)?;
        let expires = now_i
            .checked_add(check_window(lease_secs)?)
            .ok_or(StoreError::InvalidInput)?;
        self.write(FaultOp::RenewLease, |tx| {
            let row = require_lease(tx, lease, now_i)?;
            let new_exp = expires.max(row.lease_expires_at.unwrap_or(0));
            let n = tx.execute(
                "UPDATE attempts SET lease_expires_at = ?1, version = version + 1, updated_at = ?2 \
                 WHERE attempt_id = ?3 AND version = ?4",
                (new_exp, now_i, &row.attempt_id, row.version),
            )?;
            if n != 1 {
                return Err(StoreError::LeaseLost);
            }
            Ok(Lease {
                expires_at: from_sql(new_exp),
                ..lease.clone()
            })
        })
    }

    /// Record, before protected bytes are opened (write-ahead), that the
    /// attempt may acquire them. After this commits, no outcome refunds the
    /// reservation. Idempotent.
    pub fn record_exposure(
        &self,
        lease: &Lease,
        actor: &ActorId,
        now: u64,
    ) -> Result<(), StoreError> {
        let now_i = sql_time(now)?;
        self.write(FaultOp::RecordExposure, |tx| {
            let row = require_lease(tx, lease, now_i)?;
            if row.state != RunState::Running {
                return Err(StoreError::InvalidTransition);
            }
            if row.exposure == Exposure::Exposed {
                return Ok(());
            }
            mark_exposed(tx, &row, actor.as_str(), now_i)?;
            outbox_append(
                tx,
                &format!("exposure:{}", row.attempt_id),
                "exposure.recorded",
                Some(&row.request_id),
                Some(&row.attempt_id),
                &json!({
                    "event": "exposure.recorded", "request_id": row.request_id,
                    "attempt_id": row.attempt_id, "state": "running",
                    "exposure": "exposed", "reason": "protected_bytes_acquired", "at": now_i,
                }),
                now_i,
            )?;
            Ok(())
        })
    }

    /// `running -> validating`. Requires recorded exposure: a run that
    /// produced a result necessarily acquired protected bytes.
    pub fn begin_validation(
        &self,
        lease: &Lease,
        actor: &ActorId,
        now: u64,
    ) -> Result<(), StoreError> {
        let now_i = sql_time(now)?;
        self.write(FaultOp::BeginValidation, |tx| {
            let row = require_lease(tx, lease, now_i)?;
            if row.state == RunState::Validating {
                // Duplicate delivery of a committed step: nothing to do.
                return Ok(());
            }
            if !row.state.can_transition(RunState::Validating) || row.exposure != Exposure::Exposed
            {
                return Err(StoreError::InvalidTransition);
            }
            let n = tx.execute(
                "UPDATE attempts SET state = 'validating', version = version + 1, updated_at = ?1 \
                 WHERE attempt_id = ?2 AND version = ?3 AND state = 'running'",
                (now_i, &row.attempt_id, row.version),
            )?;
            if n != 1 {
                return Err(StoreError::InvalidTransition);
            }
            push_transition(
                tx,
                &row.attempt_id,
                &row.request_id,
                false,
                Some(RunState::Running),
                RunState::Validating,
                actor.as_str(),
                ReasonCode::Completed,
                &row.authorization_ref,
                now_i,
            )
        })
    }

    /// Terminal state, settlement and audit-export intent in ONE transaction.
    /// Held by the lease holder. `Success` requires `validating`; any other
    /// outcome is the holder reporting how the attempt ended. Settlement is
    /// `Reservation::settled_state` over the recorded exposure.
    /// Idempotent for the holder: repeating the same finish returns the
    /// stored settlement.
    pub fn finish(
        &self,
        lease: &Lease,
        outcome: ExecutionOutcome,
        reason: ReasonCode,
        actor: &ActorId,
        now: u64,
    ) -> Result<Settlement, StoreError> {
        let now_i = sql_time(now)?;
        self.write(FaultOp::Finish, |tx| {
            let row = load_attempt(tx, lease.attempt.as_str())?.ok_or(StoreError::NotFound)?;
            if row.lease_token != i64::try_from(lease.token).map_err(|_| StoreError::LeaseLost)?
                || row.lease_owner.as_deref() != Some(lease.owner.as_str())
            {
                return Err(StoreError::LeaseLost);
            }
            let target = outcome.terminal_run_state();
            if row.state.is_terminal() {
                if row.state == target {
                    return existing_settlement(tx, &row);
                }
                return Err(StoreError::InvalidTransition);
            }
            if row.lease_expires_at.is_none_or(|e| e <= now_i) {
                return Err(StoreError::LeaseLost);
            }
            if outcome == ExecutionOutcome::Success && row.exposure != Exposure::Exposed {
                return Err(StoreError::InvalidTransition);
            }
            terminate(
                tx,
                &row,
                outcome,
                reason,
                actor.as_str(),
                now_i,
                row.exposure,
                false,
            )
        })
    }

    /// Cancel an attempt. Before start: cancelled and refunded. While
    /// running: the holder may have acquired bytes, so exposure is presumed,
    /// the reservation is consumed and the lease is fenced. Not allowed from
    /// `validating` (not in the transition table). Idempotent.
    pub fn cancel(
        &self,
        attempt: &RunId,
        actor: &ActorId,
        reason: ReasonCode,
        now: u64,
    ) -> Result<Settlement, StoreError> {
        let now_i = sql_time(now)?;
        self.write(FaultOp::Cancel, |tx| {
            let row = load_attempt(tx, attempt.as_str())?.ok_or(StoreError::NotFound)?;
            match row.state {
                RunState::Cancelled => existing_settlement(tx, &row),
                RunState::Reserved => terminate(
                    tx,
                    &row,
                    ExecutionOutcome::Cancelled,
                    reason,
                    actor.as_str(),
                    now_i,
                    row.exposure,
                    true,
                ),
                RunState::Running => terminate(
                    tx,
                    &row,
                    ExecutionOutcome::Cancelled,
                    reason,
                    actor.as_str(),
                    now_i,
                    Exposure::Exposed,
                    true,
                ),
                _ => Err(StoreError::InvalidTransition),
            }
        })
    }

    /// `reserved -> failed` for a failure before start (nothing acquired,
    /// refunded). Idempotent.
    pub fn fail_before_start(
        &self,
        attempt: &RunId,
        actor: &ActorId,
        reason: ReasonCode,
        now: u64,
    ) -> Result<Settlement, StoreError> {
        let now_i = sql_time(now)?;
        self.write(FaultOp::FailBeforeStart, |tx| {
            let row = load_attempt(tx, attempt.as_str())?.ok_or(StoreError::NotFound)?;
            match row.state {
                RunState::Failed if row.attempt_no >= 1 && row.exposure == Exposure::NotExposed => {
                    existing_settlement(tx, &row)
                }
                RunState::Reserved => terminate(
                    tx,
                    &row,
                    ExecutionOutcome::Failed,
                    reason,
                    actor.as_str(),
                    now_i,
                    row.exposure,
                    true,
                ),
                _ => Err(StoreError::InvalidTransition),
            }
        })
    }

    /// Sweep attempts whose lease or reservation window lapsed by `now`.
    ///
    /// - `reserved`: never started, so no bytes can have been acquired:
    ///   `expired`, refunded.
    /// - `running` or `validating`: the holder may have acquired bytes and
    ///   the store cannot know: exposure is presumed, the attempt is
    ///   `failed`, the reservation is consumed, the lease is fenced. Never
    ///   refunded, never retried automatically.
    ///
    /// Each attempt is recovered in its own transaction, so a crash during
    /// recovery loses nothing and the sweep can simply be run again.
    pub fn recover(&self, actor: &ActorId, now: u64) -> Result<RecoveryReport, StoreError> {
        let now_i = sql_time(now)?;
        let ids: Vec<String> = self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT attempt_id FROM attempts \
                 WHERE state IN ('reserved', 'running', 'validating') \
                   AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?1 \
                 ORDER BY created_at, attempt_id",
            )?;
            let rows = stmt.query_map([now_i], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut report = RecoveryReport::default();
        for id in ids {
            let done = self.write(FaultOp::Recover, |tx| {
                let Some(row) = load_attempt(tx, &id)? else {
                    return Ok(None);
                };
                if row.lease_expires_at.is_none_or(|e| e > now_i) {
                    return Ok(None);
                }
                match row.state {
                    RunState::Reserved => {
                        terminate(
                            tx,
                            &row,
                            ExecutionOutcome::Expired,
                            ReasonCode::AuthorizationExpired,
                            actor.as_str(),
                            now_i,
                            row.exposure,
                            true,
                        )?;
                        Ok(Some(true))
                    }
                    RunState::Running | RunState::Validating => {
                        terminate(
                            tx,
                            &row,
                            ExecutionOutcome::Failed,
                            ReasonCode::ExecutionFailed,
                            actor.as_str(),
                            now_i,
                            Exposure::Exposed,
                            true,
                        )?;
                        Ok(Some(false))
                    }
                    _ => Ok(None),
                }
            })?;
            match done {
                Some(true) => report.expired_unstarted.push(RunId::new(id)),
                Some(false) => report.failed_consumed.push(RunId::new(id)),
                None => {}
            }
        }
        Ok(report)
    }

    // ---- reads ---------------------------------------------------------

    pub fn request_attempts(&self, request_id: &str) -> Result<Vec<AttemptRecord>, StoreError> {
        self.read(|tx| {
            let ids: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT attempt_id FROM attempts WHERE request_id = ?1 ORDER BY attempt_no",
                )?;
                let rows = stmt.query_map([request_id], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            let mut out = Vec::new();
            for id in ids {
                if let Some(r) = load_attempt(tx, &id)? {
                    out.push(r.into_record());
                }
            }
            Ok(out)
        })
    }

    pub fn history(&self, attempt: &RunId) -> Result<Vec<TransitionRecord>, StoreError> {
        self.read(|tx| history_tx(tx, attempt.as_str()))
    }

    pub fn budget_status_by_key(
        &self,
        scope_key: &str,
    ) -> Result<Option<BudgetStatus>, StoreError> {
        self.read(|tx| budget_status_tx(tx, scope_key))
    }

    pub fn budget_status(
        &self,
        kind: BudgetKind,
        scope: &BudgetScope,
    ) -> Result<Option<BudgetStatus>, StoreError> {
        self.budget_status_by_key(&budget_scope_key(kind, scope)?)
    }

    /// The reservation as the C2 contract, for `Reservation` checks by
    /// callers. Only reservations created through the contract API have one.
    pub fn reservation(&self, reservation_id: &str) -> Result<Option<Reservation>, StoreError> {
        self.read(|tx| reservation_contract(tx, reservation_id))
    }
}

pub(crate) fn budget_status_tx(
    tx: &rusqlite::Connection,
    key: &str,
) -> Result<Option<BudgetStatus>, StoreError> {
    Ok(tx
        .query_row(
            "SELECT limit_units, held_units, consumed_units, refunded_units FROM budgets \
             WHERE scope_key = ?1",
            [key],
            |r| {
                Ok(BudgetStatus {
                    scope_key: key.to_owned(),
                    limit: from_sql(r.get(0)?),
                    held: from_sql(r.get(1)?),
                    consumed: from_sql(r.get(2)?),
                    refunded: from_sql(r.get(3)?),
                })
            },
        )
        .optional()?)
}

pub(crate) fn history_tx(
    tx: &rusqlite::Connection,
    attempt: &str,
) -> Result<Vec<TransitionRecord>, StoreError> {
    let mut stmt = tx.prepare(
        "SELECT seq, kind, from_state, to_state, actor, reason, authorization_ref, at \
         FROM transitions WHERE attempt_id = ?1 ORDER BY seq",
    )?;
    let rows = stmt.query_map([attempt], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, i64>(7)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, kind, from, to, actor, reason, auth, at) = row?;
        out.push(TransitionRecord {
            seq: from_sql(seq),
            from: from
                .map(|s| parse_state(&s).ok_or(StoreError::Corrupt))
                .transpose()?,
            to: parse_state(&to).ok_or(StoreError::Corrupt)?,
            is_exposure: kind == "exposure",
            actor,
            reason: parse_reason(&reason).ok_or(StoreError::Corrupt)?,
            authorization_ref: auth,
            at: from_sql(at),
        });
    }
    Ok(out)
}

/// The holder's current lease, still live and unfenced.
pub(crate) fn require_lease(
    tx: &Transaction<'_>,
    lease: &Lease,
    now: i64,
) -> Result<AttemptRow, StoreError> {
    let row = load_attempt(tx, lease.attempt.as_str())?.ok_or(StoreError::NotFound)?;
    let token = i64::try_from(lease.token).map_err(|_| StoreError::LeaseLost)?;
    if row.lease_token != token
        || row.lease_owner.as_deref() != Some(lease.owner.as_str())
        || !matches!(row.state, RunState::Running | RunState::Validating)
        || row.lease_expires_at.is_none_or(|e| e <= now)
    {
        return Err(StoreError::LeaseLost);
    }
    Ok(row)
}

fn mark_exposed(
    tx: &Transaction<'_>,
    row: &AttemptRow,
    actor: &str,
    now: i64,
) -> Result<(), StoreError> {
    let n = tx.execute(
        "UPDATE attempts SET exposure = 'exposed', version = version + 1, updated_at = ?1 \
         WHERE attempt_id = ?2 AND version = ?3",
        (now, &row.attempt_id, row.version),
    )?;
    if n != 1 {
        return Err(StoreError::InvalidTransition);
    }
    if let Some(rsv) = &row.reservation_id {
        tx.execute(
            "UPDATE reservations SET exposure = 'exposed' \
             WHERE reservation_id = ?1 AND state = 'held'",
            [rsv],
        )?;
    }
    push_transition(
        tx,
        &row.attempt_id,
        &row.request_id,
        true,
        Some(row.state),
        row.state,
        actor,
        ReasonCode::ProtectedBytesAcquired,
        &row.authorization_ref,
        now,
    )
}

fn existing_settlement(tx: &Transaction<'_>, row: &AttemptRow) -> Result<Settlement, StoreError> {
    let (rsv, units, result, exposure): (String, i64, String, String) = tx
        .query_row(
            "SELECT reservation_id, units, result, exposure FROM settlements WHERE attempt_id = ?1",
            [&row.attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
        .ok_or(StoreError::InvalidTransition)?;
    let seq: i64 = tx.query_row(
        "SELECT seq FROM outbox WHERE event_id = ?1",
        [format!("terminal:{}", row.attempt_id)],
        |r| r.get(0),
    )?;
    Ok(Settlement {
        attempt: RunId::new(row.attempt_id.clone()),
        reservation_id: rsv,
        units: from_sql(units),
        result: if result == "refunded" {
            ReservationState::Refunded
        } else {
            ReservationState::Consumed
        },
        exposure: parse_exposure(&exposure).ok_or(StoreError::Corrupt)?,
        state: row.state,
        outbox_seq: from_sql(seq),
    })
}

/// The one place an attempt reaches a terminal state with a reservation:
/// state change, transition row, settlement (via
/// `Reservation::settled_state`, the only refund implementation), budget
/// counters and the outbox event, in the caller's single transaction.
#[allow(clippy::too_many_arguments)]
fn terminate(
    tx: &Transaction<'_>,
    row: &AttemptRow,
    outcome: ExecutionOutcome,
    reason: ReasonCode,
    actor: &str,
    now: i64,
    exposure: Exposure,
    fence: bool,
) -> Result<Settlement, StoreError> {
    let target = outcome.terminal_run_state();
    if !row.state.can_transition(target) {
        return Err(StoreError::InvalidTransition);
    }
    let rsv_id = row.reservation_id.clone().ok_or(StoreError::Corrupt)?;
    if exposure == Exposure::Exposed && row.exposure == Exposure::NotExposed {
        // Presumed exposure (cancel while running, lapsed lease): record it
        // as a distinct, auditable row before the terminal transition.
        mark_exposed(tx, row, actor, now)?;
    }
    let version = if exposure == Exposure::Exposed && row.exposure == Exposure::NotExposed {
        row.version + 1
    } else {
        row.version
    };
    let n = tx.execute(
        "UPDATE attempts SET state = ?1, exposure = ?2, \
         lease_token = lease_token + ?3, version = version + 1, updated_at = ?4 \
         WHERE attempt_id = ?5 AND version = ?6 AND state = ?7",
        (
            state_str(target),
            exposure_str(exposure),
            i64::from(fence),
            now,
            &row.attempt_id,
            version,
            state_str(row.state),
        ),
    )?;
    if n != 1 {
        return Err(StoreError::InvalidTransition);
    }
    push_transition(
        tx,
        &row.attempt_id,
        &row.request_id,
        false,
        Some(row.state),
        target,
        actor,
        reason,
        &row.authorization_ref,
        now,
    )?;

    let (scope_key, units): (String, i64) = tx.query_row(
        "SELECT scope_key, units FROM reservations WHERE reservation_id = ?1",
        [&rsv_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let settled = Reservation::settled_state(exposure.into(), outcome);
    let (consumed, refunded) = match settled {
        ReservationState::Consumed => (units, 0),
        ReservationState::Refunded => (0, units),
        ReservationState::Held => return Err(StoreError::Corrupt),
    };
    let result = if refunded > 0 { "refunded" } else { "consumed" };
    let n = tx.execute(
        "UPDATE reservations SET state = ?1, exposure = ?2, settled_at = ?3 \
         WHERE reservation_id = ?4 AND state = 'held'",
        (result, exposure_str(exposure), now, &rsv_id),
    )?;
    if n != 1 {
        return Err(StoreError::Corrupt);
    }
    tx.execute(
        "UPDATE budgets SET held_units = held_units - ?1, consumed_units = consumed_units + ?2, \
         refunded_units = refunded_units + ?3 WHERE scope_key = ?4",
        (units, consumed, refunded, &scope_key),
    )?;
    tx.execute(
        "INSERT INTO settlements (reservation_id, attempt_id, scope_key, units, result, \
         exposure, outcome, reason, settled_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        (
            &rsv_id,
            &row.attempt_id,
            &scope_key,
            units,
            result,
            exposure_str(exposure),
            outcome_str(outcome),
            reason_str(reason),
            now,
        ),
    )?;
    let seq = outbox_append(
        tx,
        &format!("terminal:{}", row.attempt_id),
        "attempt.terminal",
        Some(&row.request_id),
        Some(&row.attempt_id),
        &json!({
            "event": "attempt.terminal", "request_id": row.request_id,
            "attempt_id": row.attempt_id, "attempt_no": row.attempt_no,
            "reservation_id": rsv_id, "scope_key": scope_key, "units": units,
            "prior_state": state_str(row.state), "state": state_str(target),
            "outcome": outcome_str(outcome), "reason": reason_str(reason),
            "exposure": exposure_str(exposure), "settlement": result,
            "actor": actor, "authorization_ref": row.authorization_ref, "at": now,
        }),
        now,
    )?;
    Ok(Settlement {
        attempt: RunId::new(row.attempt_id.clone()),
        reservation_id: rsv_id,
        units: from_sql(units),
        result: settled,
        exposure,
        state: target,
        outbox_seq: from_sql(seq),
    })
}

fn outcome_str(o: ExecutionOutcome) -> &'static str {
    match o {
        ExecutionOutcome::Success => "success",
        ExecutionOutcome::Partial => "partial",
        ExecutionOutcome::Failed => "failed",
        ExecutionOutcome::Cancelled => "cancelled",
        ExecutionOutcome::Expired => "expired",
        ExecutionOutcome::Rejected => "rejected",
    }
}

fn reservation_contract(
    tx: &rusqlite::Connection,
    reservation_id: &str,
) -> Result<Option<Reservation>, StoreError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        i64,
        i64,
        String,
    )> = tx
        .query_row(
            "SELECT r.request_id, r.approval_id, r.plan_digest, r.kind, b.scope_json, \
             r.state, r.units, r.exposure, r.state, r.reserved_at, r.lease_expires_at, r.attempt_id \
             FROM reservations r JOIN budgets b ON b.scope_key = r.scope_key \
             WHERE r.reservation_id = ?1",
            [reservation_id],
            |r| {
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
                    r.get(11)?,
                ))
            },
        )
        .optional()?;
    let Some((req, apr, plan, kind, scope, state, units, exposure, _, at, lease, _)) = row else {
        return Ok(None);
    };
    let scope: Value = serde_json::from_str(&scope).map_err(|_| StoreError::Corrupt)?;
    let doc = json!({
        "schema": "private-custodian.reservation/1",
        "reservation_id": reservation_id, "request_id": req, "approval_id": apr,
        "plan_digest": plan, "kind": kind, "budget": scope, "units": units,
        "state": state, "exposure": exposure, "reserved_at": at, "lease_expires_at": lease,
    });
    // Port-origin reservations carry non-contract identities and do not
    // parse; that is not corruption.
    Ok(serde_json::from_value::<Reservation>(doc).ok())
}

/// Re-run the approval and reservation binding checks for an attempt
/// created through the contract API, against freshly observed activation.
fn check_documents(
    tx: &Transaction<'_>,
    row: &AttemptRow,
    observed: &ObservedActivation,
    now: Timestamp,
    max_age: u64,
) -> Result<(), StoreError> {
    let req_doc: String = tx.query_row(
        "SELECT document FROM requests WHERE request_id = ?1",
        [&row.request_id],
        |r| r.get(0),
    )?;
    let apr_doc: String = tx.query_row(
        "SELECT document FROM approvals WHERE request_id = ?1 AND approval_id = ?2",
        (&row.request_id, &row.authorization_ref),
        |r| r.get(0),
    )?;
    let request = EvaluationRequest::decode(req_doc.as_bytes()).map_err(|_| StoreError::Corrupt)?;
    let approval = Approval::decode(apr_doc.as_bytes()).map_err(|_| StoreError::Corrupt)?;
    approval.check_for_execution(&request, observed, now, max_age)?;
    let rsv_id = row.reservation_id.as_deref().ok_or(StoreError::Corrupt)?;
    let reservation = reservation_contract(tx, rsv_id)?.ok_or(StoreError::Corrupt)?;
    reservation.check_for_execution(&request, &approval.approval_id, now)?;
    Ok(())
}
