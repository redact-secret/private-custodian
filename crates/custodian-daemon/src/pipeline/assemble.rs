//! Receipt assembly (R-3): the `ExecutionRecord` and `InternalReceipt` of an
//! attempt, built from what the store and the validated result recorded.
//!
//! Nothing here reads a live object. Every input is a durable record, so the
//! same attempt assembled twice, or before and after a crash, yields the same
//! bytes (identities are derived from the attempt id, times come from the
//! attempt's own transition history, never from a clock).
//!
//! # Rules (C2 and C6, restated as code)
//!
//! * **The attempt's settled state decides the outcome, the stored result
//!   never does.** A `completed` attempt is `success`; a `failed` one is
//!   `failed`, `rejected` or `partial`; `cancelled` and `expired` are
//!   themselves; a `denied` one never ran and gets no record. A validated
//!   result found next to a `failed` attempt (a crash after the result was
//!   kept and before it was settled, or a failed settlement) therefore cannot
//!   become a clean receipt: **a crash never produces a clean receipt.**
//! * **`partial` is accepted only when observed < expected.** A run whose
//!   counters say otherwise (everything observed, some item failed) has no
//!   valid receipt shape and is refused, not coerced.
//! * **A success needs its aggregate artifact**, bound by digest and size to
//!   the receipt, naming the frozen domain and protocol and carrying the
//!   receipt's own roster counters (`PrivateAggregates::decode`).
//! * **No drift.** The records must bind to the stored request, approval and
//!   reservation (`ExecutionRecord::check_binding`), the receipt's frozen
//!   identities must equal the plan's, and the roster the engine reported must
//!   equal the entry count of the sealed epoch recorded in the registry; the
//!   epoch's population binding must still be the plan's.
//! * **Attestation is declared, not derived from the engine.** Independence
//!   follows the plan's purpose (a conformance control is `public-control`,
//!   anything else `custodian-declared`), role separation follows the
//!   approval, organizational independence is `not_claimed`, authorship and
//!   review are the operator's configured declaration, and ground truth is
//!   `not_established`. A signature over a projection attests origin and
//!   binding, never truth.

use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::{to_canonical_bytes, Contract};
use custodian_contracts::common::{Attestation, IndependenceClaim, Purpose};
use custodian_contracts::execution::{ExecutionOutcome, ExecutionRecord, InternalReceipt};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::Reservation;
use custodian_core::{ReasonCode, RunState};
use custodian_corpus::registry::{EpochState, RegistryView};
use custodian_disclosure::PrivateAggregates;
use custodian_store::{AttemptRecord, TransitionRecord};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::AttestationConfig;

/// The validated outcome and roster counters of a result, kept by the sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultMeta {
    /// `success` or `partial`.
    pub outcome: String,
    pub expected: u64,
    pub observed: u64,
    pub failed: u64,
}

impl ResultMeta {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
    pub fn parse(s: &str) -> Option<Self> {
        let m: Self = serde_json::from_str(s).ok()?;
        matches!(m.outcome.as_str(), "success" | "partial").then_some(m)
    }
}

/// What the assembler may produce for an attempt.
#[derive(Debug)]
pub enum Assembled {
    /// A valid, releasable-shape pair. The run moves on.
    Releasable {
        execution: ExecutionRecord,
        receipt: InternalReceipt,
    },
    /// The execution is recorded and the run closes with this fixed reason.
    /// A partial run also keeps its (valid, never releasable) receipt.
    Closed {
        execution: ExecutionRecord,
        receipt: Option<InternalReceipt>,
        reason: &'static str,
    },
    /// Nothing to record (the attempt never ran).
    Nothing { reason: &'static str },
}

pub struct Inputs<'a> {
    pub request: &'a EvaluationRequest,
    pub approval: &'a Approval,
    pub reservation: Option<&'a Reservation>,
    pub attempt: &'a AttemptRecord,
    pub history: &'a [TransitionRecord],
    pub meta: Option<&'a ResultMeta>,
    pub aggregates: Option<&'a [u8]>,
    pub attestation: AttestationConfig,
    /// The registry view, for the roster and population drift checks.
    pub registry: &'a RegistryView,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `<prefix>` + 32 hex characters derived from a domain and the attempt id.
pub fn derived_id(prefix: &str, domain: &str, attempt: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/v1/daemon/");
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(attempt.as_bytes());
    format!("{prefix}{}", &hex(&h.finalize())[..32])
}

fn reason_word(r: ReasonCode) -> &'static str {
    match r {
        ReasonCode::Completed => "completed",
        ReasonCode::ExecutionFailed => "execution_failed",
        ReasonCode::InvalidArtifact => "invalid_artifact",
        ReasonCode::PlanMismatch => "plan_mismatch",
        ReasonCode::AuthorizationDenied => "authorization_denied",
        ReasonCode::AuthorizationExpired => "authorization_expired",
        ReasonCode::CorpusUnavailable => "corpus_unavailable",
        ReasonCode::StoreUnavailable => "store_unavailable",
        ReasonCode::Cancelled => "cancelled",
        ReasonCode::BudgetExhausted => "budget_exhausted",
        ReasonCode::BudgetReserved => "budget_reserved",
        ReasonCode::Requested => "requested",
        ReasonCode::Authorized => "authorized",
        ReasonCode::DuplicateRequest => "duplicate_request",
        ReasonCode::ProtectedBytesAcquired => "protected_bytes_acquired",
        ReasonCode::InvalidTransition => "invalid_transition",
        ReasonCode::DisclosureNotPermitted => "disclosure_not_permitted",
    }
}

/// `started_at` and `finished_at` from the attempt's own history.
fn times(history: &[TransitionRecord]) -> Option<(u64, u64)> {
    let first = history.first()?.at;
    let started = history
        .iter()
        .find(|t| t.to == RunState::Running && !t.is_exposure)
        .map_or(first, |t| t.at);
    let finished = history.last()?.at.max(started);
    Some((started, finished))
}

fn outcome_of(
    a: &AttemptRecord,
    last: ReasonCode,
    meta: Option<&ResultMeta>,
) -> Option<ExecutionOutcome> {
    Some(match a.state {
        RunState::Completed => ExecutionOutcome::Success,
        RunState::Cancelled => ExecutionOutcome::Cancelled,
        RunState::Expired => ExecutionOutcome::Expired,
        RunState::Failed => match last {
            ReasonCode::InvalidArtifact
            | ReasonCode::PlanMismatch
            | ReasonCode::AuthorizationDenied => ExecutionOutcome::Rejected,
            _ if meta.is_some_and(|m| m.outcome == "partial") => ExecutionOutcome::Partial,
            _ => ExecutionOutcome::Failed,
        },
        // Never ran, or not settled: no execution to record.
        _ => return None,
    })
}

fn outcome_word(o: ExecutionOutcome) -> &'static str {
    match o {
        ExecutionOutcome::Success => "success",
        ExecutionOutcome::Partial => "partial",
        ExecutionOutcome::Failed => "failed",
        ExecutionOutcome::Cancelled => "cancelled",
        ExecutionOutcome::Expired => "expired",
        ExecutionOutcome::Rejected => "rejected",
    }
}

/// Build the records for a settled attempt, or say why none can be.
pub fn assemble(i: &Inputs<'_>) -> Result<Assembled, &'static str> {
    let plan = &i.request.plan;
    let attempt_id = i.attempt.attempt.as_str();
    if i.attempt.state == RunState::Denied {
        return Ok(Assembled::Nothing {
            reason: "reservation_denied",
        });
    }
    let last = i.history.last().ok_or("history_missing")?;
    let Some(outcome) = outcome_of(i.attempt, last.reason, i.meta) else {
        return Err("attempt_not_settled");
    };
    let reservation = i.reservation.ok_or("reservation_missing")?;
    let (started, finished) = times(i.history).ok_or("history_missing")?;
    let plan_digest = plan.plan_digest().map_err(|_| "plan_invalid")?;
    let exposure = i.attempt.exposure;
    let reason = if outcome == ExecutionOutcome::Success {
        "completed"
    } else {
        // Anything but success carries the settlement's own fixed reason; a
        // failed settlement can never be labelled "completed".
        match reason_word(last.reason) {
            "completed" => "execution_failed",
            w => w,
        }
    };

    let exe_json = json!({
        "schema": "private-custodian.execution/1",
        "execution_id": derived_id("exe_", "execution-id", attempt_id),
        "request_id": i.request.request_id,
        "approval_id": i.approval.approval_id,
        "reservation_id": reservation.reservation_id,
        "plan_digest": plan_digest,
        "activation": plan.policy_activation,
        "frozen": plan.frozen_identities(),
        "attempt": i.attempt.attempt_no,
        "outcome": outcome_word(outcome),
        "exposure": custodian_contracts::common::ExposureState::from(exposure),
        "reason": reason,
        "started_at": started,
        "finished_at": finished,
    });
    let execution: ExecutionRecord =
        serde_json::from_value(exe_json).map_err(|_| "execution_invalid")?;
    execution.validate().map_err(|_| "execution_invalid")?;
    execution
        .check_binding(i.request, reservation)
        .map_err(|_| "binding_drift")?;
    if i.approval.approval_id != execution.approval_id {
        return Err("binding_drift");
    }

    let closed = |reason: &'static str| {
        Ok(Assembled::Closed {
            execution: execution.clone(),
            receipt: None,
            reason,
        })
    };
    match outcome {
        ExecutionOutcome::Success | ExecutionOutcome::Partial => {}
        ExecutionOutcome::Failed => return closed("execution_failed"),
        ExecutionOutcome::Rejected => return closed("execution_rejected"),
        ExecutionOutcome::Cancelled => return closed("execution_cancelled"),
        ExecutionOutcome::Expired => return closed("execution_expired"),
    }

    // From here the attempt measured something: it needs a result.
    let meta = i.meta.ok_or("result_missing")?;
    if outcome == ExecutionOutcome::Success
        && !(meta.outcome == "success" && meta.observed == meta.expected && meta.failed == 0)
    {
        return Err("result_inconsistent");
    }
    // The engine's roster must be the sealed epoch's roster, and the epoch
    // must still be the population the plan froze.
    let (row, state) = i
        .registry
        .get(&plan.population.epoch_id)
        .ok_or("population_drift")?;
    if row.corpus_id != plan.population.corpus_id
        || row.family_id != plan.population.family_id
        || row.domain != plan.population.domain
        || row.custody_version != plan.population.custody_version
        || row.population_digest != plan.population.population_digest
        || state == EpochState::Sealed
        || row.entry_count != meta.expected
    {
        return Err("population_drift");
    }

    let Some(aggregates) = i.aggregates else {
        return closed("aggregates_missing");
    };
    let attestation = Attestation {
        independence: if plan.purpose == Purpose::ConformanceControl {
            IndependenceClaim::PublicControl
        } else {
            IndependenceClaim::CustodianDeclared
        },
        role_separation: i.approval.role_separation,
        organisational_independence:
            custodian_contracts::common::OrganisationalIndependence::NotClaimed,
        authorship: i.attestation.authorship,
        review: i.attestation.review,
        ground_truth: custodian_contracts::common::GroundTruthClaim::NotEstablished,
    };
    let rcp_json = json!({
        "schema": "private-custodian.internal-receipt/1",
        "receipt_id": derived_id("rcp_", "receipt-id", attempt_id),
        "execution_id": execution.execution_id,
        "plan_digest": plan_digest,
        "activation": plan.policy_activation,
        "frozen": plan.frozen_identities(),
        "outcome": outcome_word(outcome),
        "result": {
            "digest": custodian_contracts::types::ResultDigest::from_raw(
                Sha256::digest(aggregates).into()),
            "size_bytes": aggregates.len(),
            "protocol": plan.protocol,
        },
        "roster": {"expected": meta.expected, "observed": meta.observed, "failed": meta.failed},
        "attestation": attestation,
        "issued_at": finished,
    });
    let receipt: InternalReceipt =
        serde_json::from_value(rcp_json).map_err(|_| "receipt_invalid")?;
    // Partial is accepted only when observed < expected; this is the check.
    if receipt.validate().is_err() {
        return if outcome == ExecutionOutcome::Partial {
            closed("partial_not_releasable")
        } else {
            Err("receipt_invalid")
        };
    }
    if receipt.frozen != plan.frozen_identities() || receipt.plan_digest != plan_digest {
        return Err("binding_drift");
    }
    // The artifact is exactly the one the receipt names, for this domain,
    // protocol and roster.
    PrivateAggregates::decode(
        aggregates,
        &receipt.result,
        plan.domain,
        &receipt.frozen.protocol,
        &receipt.roster,
    )
    .map_err(|_| "aggregates_invalid")?;

    if outcome == ExecutionOutcome::Partial {
        return Ok(Assembled::Closed {
            execution,
            receipt: Some(receipt),
            reason: "partial_not_releasable",
        });
    }
    Ok(Assembled::Releasable { execution, receipt })
}

/// Canonical bytes of a record, as the store keeps them.
pub fn canonical<T: Contract>(v: &T) -> Result<String, &'static str> {
    let bytes = to_canonical_bytes(v).map_err(|_| "record_invalid")?;
    String::from_utf8(bytes).map_err(|_| "record_invalid")
}
