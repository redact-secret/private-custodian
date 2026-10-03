//! The queue consumer: from an accepted delivery to a pending submission.
//!
//! The webhook edge validated and enqueued identifiers. The consumer leases
//! one item at a time (a fencing token rises with every lease), looks up what
//! the item refers to, runs the same checks the execution gate runs before an
//! approval can matter, and records a **pending submission** through the same
//! `submit_request` the CLI uses (channel `app`). It never approves, reserves
//! or charges anything: a human approves on the control plane, and only that
//! transaction reserves budget.
//!
//! # Outcomes (each recorded in one transaction with one audit event)
//!
//! * `submitted`: a pending submission exists (new, replayed, or already
//!   reserved through the CLI);
//! * `denied`: a terminal refusal with a fixed reason (scope removed, actor
//!   not allowed, stale commit, candidate or configuration mismatch, a stale
//!   policy activation, a blocked epoch, a request document the control
//!   plane rejects);
//! * `poisoned`: the item could not be processed within `max_attempts`
//!   leases. It is set aside with the fixed reason `poison_message` and never
//!   retried; nothing was reserved or charged for it.
//!
//! # Retries
//!
//! A transient failure (source unavailable, store busy, token endpoint down,
//! document not provided yet) pushes the item's lease out by a deterministic
//! exponential backoff (`QueueConfig::backoff_secs`) and moves on; the item is
//! delivered again when the lease lapses. The number of leases is bounded, so
//! no item loops forever. A crash between the lease and the outcome is the
//! same thing: the lease lapses, the item is leased again with a higher
//! fencing token, and every step is idempotent (the submission is keyed by
//! the request's idempotency key), so nothing is lost or done twice.
//!
//! # Shutdown
//!
//! When shutdown is requested the consumer stops claiming; an item it already
//! leased and has not yet acted on is released at once (`queue_release`), one
//! it is acting on is finished.

use std::sync::Arc;

use custodian_contracts::policy::{check_current, MAX_STATE_AGE_SECS};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::Timestamp;
use custodian_contracts::Contract;
use custodian_core::ReasonCode;
use custodian_intake::checks::{CheckReason, CheckReporter, CheckState, CheckUpdate};
use custodian_intake::gate::ExecutionGate;
use custodian_intake::ports::QueuedRequest;
use custodian_intake::IntakeReason;
use custodian_store::{
    Clock, LeasedRequest, QueueOutcome, QueueSettle, SqliteStore, StoreError, SubmissionChannel,
    SubmitCommand,
};

use crate::config::QueueConfig;
use crate::log::EventLog;
use crate::schedule::Degraded;
use crate::shutdown::Shutdown;
use crate::source::{CandidateStager, RequestSource, SourceError};

/// The fixed reason an item is set aside under.
pub const POISON_REASON: &str = "poison_message";

/// What one call to [`QueueConsumer::step`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing was waiting (or shutdown was requested before claiming).
    Idle,
    /// An item was finished with this outcome and reason.
    Settled(QueueOutcome, &'static str),
    /// A transient failure; the lease was pushed out for a backoff.
    Deferred(&'static str),
    /// Shutdown was requested after the lease: the item was given back.
    Released,
}

enum Verdict {
    Submit(String),
    Deny(&'static str, CheckReason),
    Retry(&'static str),
    GiveBack,
}

pub struct QueueConsumer {
    pub store: Arc<SqliteStore>,
    pub gate: ExecutionGate,
    pub requests: Arc<dyn RequestSource>,
    pub stager: Arc<dyn CandidateStager>,
    pub checks: Option<Arc<CheckReporter>>,
    pub clock: Arc<dyn Clock>,
    pub log: Arc<dyn EventLog>,
    pub cfg: QueueConfig,
    /// Set by a failing scheduled `startup_check`: nothing is claimed while it
    /// is set.
    pub degraded: Degraded,
}

fn store_word(e: &StoreError) -> &'static str {
    match e {
        StoreError::InjectedCrash(_) => "injected_crash",
        _ => "store_unavailable",
    }
}

impl QueueConsumer {
    fn now(&self) -> Result<Timestamp, StoreError> {
        Timestamp::new(self.clock.now()).map_err(|_| StoreError::InvalidInput)
    }

    /// Lease at most one item and carry it to an outcome. `Err` is a store
    /// failure that left the item leased (it lapses and is delivered again).
    pub fn step(&self, shutdown: &Shutdown) -> Result<Step, StoreError> {
        if shutdown.is_requested() || self.degraded.is_set() {
            return Ok(Step::Idle);
        }
        let now = self.now()?;
        let Some(leased) =
            self.store
                .queue_lease(&self.cfg.owner, now.secs(), self.cfg.lease_secs)?
        else {
            return Ok(Step::Idle);
        };
        if shutdown.is_requested() {
            self.store
                .queue_release(leased.seq, leased.lease_token, now.secs())?;
            self.log.event("consumer", "released");
            return Ok(Step::Released);
        }
        let q = &leased.request;

        // A crash loop or a long retry history: the item has used its leases.
        if leased.attempts > self.cfg.max_attempts {
            return self.poison(&leased, now);
        }
        match self.process(&leased, shutdown, now) {
            Verdict::Submit(request_id) => {
                self.store.queue_settle(
                    leased.seq,
                    leased.lease_token,
                    now.secs(),
                    &QueueSettle {
                        outcome: QueueOutcome::Submitted,
                        reason: "submitted",
                        request_id: Some(&request_id),
                        link: Some(q),
                    },
                )?;
                self.log.event("consumer", "submitted");
                self.check(
                    q,
                    CheckState::Queued,
                    Some(CheckReason::Core(ReasonCode::Requested)),
                );
                Ok(Step::Settled(QueueOutcome::Submitted, "submitted"))
            }
            Verdict::Deny(word, reason) => {
                self.store.queue_settle(
                    leased.seq,
                    leased.lease_token,
                    now.secs(),
                    &QueueSettle {
                        outcome: QueueOutcome::Denied,
                        reason: word,
                        request_id: None,
                        link: None,
                    },
                )?;
                self.log.event("consumer", word);
                self.check(q, CheckState::Denied, Some(reason));
                Ok(Step::Settled(QueueOutcome::Denied, word))
            }
            Verdict::GiveBack => {
                self.store
                    .queue_release(leased.seq, leased.lease_token, now.secs())?;
                self.log.event("consumer", "released");
                Ok(Step::Released)
            }
            Verdict::Retry(word) => {
                if leased.attempts >= self.cfg.max_attempts {
                    return self.poison(&leased, now);
                }
                self.store.queue_defer(
                    leased.seq,
                    leased.lease_token,
                    now.secs(),
                    self.cfg.backoff_secs(leased.attempts),
                )?;
                self.log.event("consumer", word);
                Ok(Step::Deferred(word))
            }
        }
    }

    fn poison(&self, leased: &LeasedRequest, now: Timestamp) -> Result<Step, StoreError> {
        self.store.queue_settle(
            leased.seq,
            leased.lease_token,
            now.secs(),
            &QueueSettle {
                outcome: QueueOutcome::Poisoned,
                reason: POISON_REASON,
                request_id: None,
                link: None,
            },
        )?;
        self.log.event("consumer", POISON_REASON);
        self.check(
            &leased.request,
            CheckState::Failed,
            Some(CheckReason::Intake(IntakeReason::QueueUnavailable)),
        );
        Ok(Step::Settled(QueueOutcome::Poisoned, POISON_REASON))
    }

    /// Best effort: a Check that cannot be posted never changes the outcome.
    fn check(&self, q: &QueuedRequest, state: CheckState, reason: Option<CheckReason>) {
        let Some(reporter) = &self.checks else { return };
        let update = CheckUpdate {
            installation: q.installation,
            repository: q.repository,
            head_sha: q.head_sha.clone(),
            state,
            reason,
        };
        if reporter.report(&update).is_err() {
            self.log.event("consumer", "check_failed");
        }
    }

    fn process(&self, leased: &LeasedRequest, shutdown: &Shutdown, now: Timestamp) -> Verdict {
        let q = &leased.request;
        let denied =
            |word: &'static str, r: IntakeReason| Verdict::Deny(word, CheckReason::Intake(r));

        let bytes = match self.requests.request_for(q) {
            Ok(Some(b)) => b,
            Ok(None) => return Verdict::Retry("request_not_provided"),
            Err(SourceError::Rejected) => {
                return denied("request_rejected", IntakeReason::RequestInvalid)
            }
            Err(SourceError::Unavailable) => return Verdict::Retry("request_source_unavailable"),
        };
        let staged = match self.stager.staged(q) {
            Ok(Some(s)) => s,
            Ok(None) => return Verdict::Retry("candidate_not_staged"),
            Err(SourceError::Rejected) => {
                return denied("candidate_rejected", IntakeReason::CandidateMismatch)
            }
            Err(SourceError::Unavailable) => return Verdict::Retry("candidate_source_unavailable"),
        };
        let Ok(request) = EvaluationRequest::decode(&bytes) else {
            return denied("request_invalid", IntakeReason::RequestInvalid);
        };

        // The policy activation the plan binds must be current, exactly as
        // `request submit` requires.
        let observed = match self
            .store
            .observe_activation(&request.plan.policy_activation, now)
        {
            Ok(Some(o)) => o,
            Ok(None) => {
                return denied("activation_not_current", IntakeReason::ActivationNotCurrent)
            }
            Err(e) => return Verdict::Retry(store_word(&e)),
        };
        if check_current(
            &request.plan.policy_activation,
            &observed,
            now,
            MAX_STATE_AGE_SECS,
        )
        .is_err()
        {
            return denied("activation_not_current", IntakeReason::ActivationNotCurrent);
        }

        // Scope, actor assertion, stale commit, candidate and configuration
        // digests: the gate runs them all before it looks for an approval.
        // `ApprovalRequired` therefore means every other check passed; an
        // approval is not something this stage may have.
        match self
            .gate
            .authorize(q, &bytes, &staged, None, &observed, now)
        {
            Err(IntakeReason::ApprovalRequired) => {}
            Ok(_) => return Verdict::Retry("gate_inconsistent"),
            Err(
                r @ (IntakeReason::StoreUnavailable
                | IntakeReason::QueueUnavailable
                | IntakeReason::TokenUnavailable
                | IntakeReason::AppAuthFailed
                | IntakeReason::CheckUpdateFailed),
            ) => return Verdict::Retry(r.as_str()),
            Err(r) => return Verdict::Deny(r.as_str(), CheckReason::Intake(r)),
        }

        if shutdown.is_requested() {
            return Verdict::GiveBack;
        }
        match self.store.submit_request(&SubmitCommand {
            request: &request,
            channel: SubmissionChannel::App,
            submitted_by: &q.actor,
            now,
        }) {
            Ok(_) => Verdict::Submit(request.request_id.as_str().to_owned()),
            Err(StoreError::EpochBlocked) => Verdict::Deny(
                "epoch_blocked",
                CheckReason::Core(ReasonCode::AuthorizationDenied),
            ),
            Err(StoreError::IdempotencyConflict) => Verdict::Deny(
                "idempotency_conflict",
                CheckReason::Core(ReasonCode::DuplicateRequest),
            ),
            Err(StoreError::Constraint) => Verdict::Retry("submission_limit"),
            Err(e) => Verdict::Retry(store_word(&e)),
        }
    }

    /// Run until shutdown is requested. A store failure is logged and the
    /// loop continues after the poll interval; it never panics or exits.
    pub fn run(&self, shutdown: &Shutdown) {
        while !shutdown.is_requested() {
            match self.step(shutdown) {
                Ok(Step::Idle) => {
                    shutdown.sleep(self.cfg.poll);
                }
                Ok(_) => {}
                Err(e) => {
                    self.log.event("consumer", store_word(&e));
                    shutdown.sleep(self.cfg.poll);
                }
            }
        }
    }
}
