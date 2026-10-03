//! Public data types of the store API. None carries an input value; every
//! text field is an identity, a digest or a fixed vocabulary string.

use custodian_contracts::approval::Approval;
use custodian_contracts::policy::ObservedActivation;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::ReservationState;
use custodian_contracts::types::Timestamp;
use custodian_core::{Exposure, ReasonCode, RunId, RunState};

pub(crate) fn state_str(s: RunState) -> &'static str {
    match s {
        RunState::Proposed => "proposed",
        RunState::Authorized => "authorized",
        RunState::Reserved => "reserved",
        RunState::Running => "running",
        RunState::Validating => "validating",
        RunState::Completed => "completed",
        RunState::Denied => "denied",
        RunState::Failed => "failed",
        RunState::Cancelled => "cancelled",
        RunState::Expired => "expired",
    }
}

pub(crate) fn parse_state(s: &str) -> Option<RunState> {
    Some(match s {
        "proposed" => RunState::Proposed,
        "authorized" => RunState::Authorized,
        "reserved" => RunState::Reserved,
        "running" => RunState::Running,
        "validating" => RunState::Validating,
        "completed" => RunState::Completed,
        "denied" => RunState::Denied,
        "failed" => RunState::Failed,
        "cancelled" => RunState::Cancelled,
        "expired" => RunState::Expired,
        _ => return None,
    })
}

pub(crate) fn exposure_str(e: Exposure) -> &'static str {
    match e {
        Exposure::NotExposed => "not_exposed",
        Exposure::Exposed => "exposed",
    }
}

pub(crate) fn parse_exposure(s: &str) -> Option<Exposure> {
    match s {
        "not_exposed" => Some(Exposure::NotExposed),
        "exposed" => Some(Exposure::Exposed),
        _ => None,
    }
}

pub(crate) fn reason_str(r: ReasonCode) -> &'static str {
    match r {
        ReasonCode::Requested => "requested",
        ReasonCode::Authorized => "authorized",
        ReasonCode::AuthorizationDenied => "authorization_denied",
        ReasonCode::PlanMismatch => "plan_mismatch",
        ReasonCode::AuthorizationExpired => "authorization_expired",
        ReasonCode::BudgetReserved => "budget_reserved",
        ReasonCode::BudgetExhausted => "budget_exhausted",
        ReasonCode::DuplicateRequest => "duplicate_request",
        ReasonCode::CorpusUnavailable => "corpus_unavailable",
        ReasonCode::ExecutionFailed => "execution_failed",
        ReasonCode::InvalidArtifact => "invalid_artifact",
        ReasonCode::Cancelled => "cancelled",
        ReasonCode::Completed => "completed",
        ReasonCode::ProtectedBytesAcquired => "protected_bytes_acquired",
        ReasonCode::InvalidTransition => "invalid_transition",
        ReasonCode::StoreUnavailable => "store_unavailable",
        ReasonCode::DisclosureNotPermitted => "disclosure_not_permitted",
    }
}

pub(crate) fn parse_reason(s: &str) -> Option<ReasonCode> {
    use ReasonCode::*;
    [
        Requested,
        Authorized,
        AuthorizationDenied,
        PlanMismatch,
        AuthorizationExpired,
        BudgetReserved,
        BudgetExhausted,
        DuplicateRequest,
        CorpusUnavailable,
        ExecutionFailed,
        InvalidArtifact,
        Cancelled,
        Completed,
        ProtectedBytesAcquired,
        InvalidTransition,
        StoreUnavailable,
        DisclosureNotPermitted,
    ]
    .into_iter()
    .find(|r| reason_str(*r) == s)
}

/// Compare-and-swap lease on one attempt. `token` is a fencing token: it
/// increases whenever the lease is taken, and every state-changing call by the
/// holder must present the current token. A cancelled, recovered or expired
/// attempt rejects the old token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub attempt: RunId,
    pub owner: String,
    pub token: u64,
    pub expires_at: u64,
}

/// Everything needed to reserve budget for a request. The store itself runs
/// `EvaluationRequest` validation and `Approval::check_for_execution` (with
/// the freshly observed activation) before it writes anything.
pub struct ReserveCommand<'a> {
    pub request: &'a EvaluationRequest,
    pub approval: &'a Approval,
    pub observed: &'a ObservedActivation,
    pub now: Timestamp,
    pub max_state_age_secs: u64,
    /// How long the reservation may wait to be started before it lapses and
    /// is expired (and refunded: no protected bytes can have been acquired).
    pub reservation_window_secs: u64,
}

/// A retry is a new attempt. It re-runs every check a first reservation
/// runs and charges the budget again.
pub struct RetryCommand<'a> {
    pub request: &'a EvaluationRequest,
    pub approval: &'a Approval,
    pub observed: &'a ObservedActivation,
    /// The attempt being retried. Naming it makes a duplicate delivery of the
    /// same retry find the attempt it already created instead of charging.
    pub from_attempt_no: u32,
    pub now: Timestamp,
    pub max_state_age_secs: u64,
    pub reservation_window_secs: u64,
}

/// Start an attempt: lease plus `reserved -> running` in one transaction.
pub struct StartCommand<'a> {
    pub attempt: &'a RunId,
    pub owner: &'a str,
    pub actor: &'a custodian_core::ActorId,
    pub now: u64,
    pub lease_secs: u64,
    /// Fresh activation observation. Required when the attempt was reserved
    /// through the contract API (documents stored); the approval and
    /// reservation are re-checked against current activation state.
    pub observed: Option<&'a ObservedActivation>,
    pub max_state_age_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveOutcome {
    pub attempt: RunId,
    pub request_id: String,
    pub reservation_id: Option<String>,
    pub attempt_no: u32,
    /// `Reserved` when budget is held; `Denied` when it was refused (for
    /// example `BudgetExhausted`) and the denial recorded.
    pub state: RunState,
    pub reason: ReasonCode,
    /// True when the idempotency key (or retry) had already been processed.
    /// A replay never charges and never executes anything.
    pub replay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub attempt: RunId,
    pub reservation_id: String,
    pub units: u64,
    /// Always `Consumed` or `Refunded`, decided by `Reservation::settled_state`.
    pub result: ReservationState,
    pub exposure: Exposure,
    pub state: RunState,
    pub outbox_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRecord {
    pub attempt: RunId,
    pub request_id: String,
    pub attempt_no: u32,
    pub state: RunState,
    pub exposure: Exposure,
    pub authorization_ref: String,
    pub reservation_id: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_token: u64,
    pub lease_expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionRecord {
    pub seq: u64,
    /// `from == None` only for the initial `proposed` row. An exposure record
    /// has `from == Some(to)` and reason `ProtectedBytesAcquired`.
    pub from: Option<RunState>,
    pub to: RunState,
    pub is_exposure: bool,
    pub actor: String,
    pub reason: ReasonCode,
    pub authorization_ref: String,
    pub at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetStatus {
    pub scope_key: String,
    pub limit: u64,
    pub held: u64,
    pub consumed: u64,
    pub refunded: u64,
}

impl BudgetStatus {
    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.held + self.consumed)
    }
}

/// One audit-export intent. `payload` is canonical JSON with identities,
/// digests and fixed vocabulary only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxEvent {
    pub seq: u64,
    pub event_id: String,
    pub kind: String,
    pub request_id: Option<String>,
    pub attempt_id: Option<String>,
    pub payload: String,
    pub payload_digest: String,
    pub chain: String,
    pub created_at: u64,
    pub exported_at: Option<u64>,
    pub export_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    Acked,
    /// Already acknowledged with the same reference: a no-op.
    AlreadyAcked,
}

/// Position in the hash-chained outbox, for an external (private-ledger)
/// checkpoint. A database whose chain does not contain this checkpoint is an
/// older or divergent copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub seq: u64,
    pub chain: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Reserved attempts whose window lapsed: expired and refunded.
    pub expired_unstarted: Vec<RunId>,
    /// Running or validating attempts whose lease lapsed: failed and the
    /// reservation conservatively consumed.
    pub failed_consumed: Vec<RunId>,
}
