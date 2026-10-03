//! The request-to-projection pipeline (R-3, ADR 0126).
//!
//! ```text
//!  approved submission (a human approved it on the control plane; the
//!  reservation and the budget hold were made in that same transaction)
//!        |
//!        v   enroll                         pipeline_runs.step = enrolled
//!   [ dispatch ]  scope re-check, pinned artifacts, start (export gate),
//!        |        write-ahead exposure (export-acknowledged), open corpus,
//!        |        run in the sandbox, validate, keep the result, settle
//!        v                                  step = dispatched
//!   [ assemble ]  ExecutionRecord + InternalReceipt from durable records
//!        |        (rules in `assemble`), one `receipt.issued` audit event
//!        v                                  step = assembled   (or closed)
//!   [ prepare ]   terminal audit exported, feed reference, release budgets,
//!        |        `prepare_bound` (charges the release, builds the v2
//!        |        projection for one destination)
//!        v                                  step = prepared
//!   [ release ]   a distinct HUMAN release approval, charge audit exported,
//!        |        `release`: sign through the isolated signer, ledger the
//!        |        policy and the decision, deliver
//!        v                                  step = released    (final)
//! ```
//!
//! # Idempotent and resumable
//!
//! Every function here can run again after a crash at any point and converges
//! to the same state without a second charge, a second exposure, a second
//! receipt or a second publication:
//!
//! * the **reservation** was made at approval and is keyed by the request's
//!   idempotency key; nothing here reserves or refunds, and the dispatcher's
//!   `start`, `record_exposure` and `finish` are the store's own fenced,
//!   idempotent transitions;
//! * a crash **during** a run leaves the attempt `running`. Its lease lapses
//!   and `recover` settles it `failed` with the unit consumed (exposure is
//!   presumed). The run is never started again and never refunded, and any
//!   result that had been kept cannot become a clean receipt (the settled
//!   state decides, see `assemble`);
//! * **assembly** is a pure function of durable records (ids derived from the
//!   attempt id, times from its history) written write-once;
//! * **prepare** is replayed with the persisted `prepared_at` and the same
//!   release key, so the charge replays instead of repeating and the digest a
//!   release approval bound is the digest produced again; if the recomputed
//!   digest differs (a policy changed underneath) the run is closed with
//!   `projection_changed` instead of continuing under a different projection;
//! * **release** repeats `release` itself: the ledger records are
//!   `Identical`, the signature is deterministic and the sink writes a
//!   projection once (`DirSink`).
//!
//! Resuming proves exact identity: the stored request, plan digest, approval,
//! candidate and population binding are re-derived and compared before each
//! stage, never assumed from the previous run.
//!
//! # What the daemon never does
//!
//! It never approves, grants or fabricates an approval of either scope, never
//! publishes the revocation feed (an operator action), never raises a run
//! budget, never signs (the isolated signer does) and never reads a release
//! approval from anywhere but a file a human placed.

pub mod approvals;
pub mod assemble;

use std::sync::Arc;
use std::time::Duration;

use custodian_cli::reason::CliReason;
use custodian_cli::startup::{export_all, StoreActivations};
use custodian_cli::{Parts, Service};
use custodian_contracts::common::ActivationRef;
use custodian_contracts::execution::{ExecutionRecord, InternalReceipt};
use custodian_contracts::types::{IdempotencyKey, Timestamp};
use custodian_contracts::Contract;
use custodian_core::ports::Authorization;
use custodian_core::{ActorId, AuthorizationId, PlanDigest, ReasonCode, RunId, RunState};
use custodian_corpus::{population_id_for, EpochBlobStore};
use custodian_disclosure::ports::Sink;
use custodian_disclosure::{
    DisclosurePolicy, DisclosureReason, PrepareInput, PreparedRelease, PublicPopulationNames,
    ReleaseRequest,
};
use custodian_intake::checks::{CheckReason, CheckReporter, CheckState, CheckUpdate};
use custodian_intake::config::IntakeConfig;
use custodian_intake::ids::{HeadSha, InstallationId, RepositoryId};
use custodian_intake::ports::InstallationRegistry;
use custodian_ledger::{walk_ledger, ExportStatus, Exporter, Verifier};
use custodian_store::{
    AssembledRecords, Clock, PipelineRun, PipelineStep, PreparedMark, SqliteStore, StoreError,
};
use custodian_worker::ports::{PopulationsCorpus, StoreRunLedger};
use custodian_worker::reason::WorkerReason;
use custodian_worker::result::ValidatedResult;
use custodian_worker::sandbox::CancelToken;
use custodian_worker::{DispatchJob, Dispatcher, ResultSink};

use crate::clock::ClockPin;
use crate::config::AttestationConfig;
use crate::log::EventLog;
use crate::shutdown::Shutdown;
use crate::source::{DirArtifacts, SourceError};

use approvals::{ApprovalFile, ReleaseApprovals};
use assemble::{assemble, canonical, derived_id, Assembled, Inputs, ResultMeta};

/// Points where a test can simulate the process dying, after the named step's
/// durable effect and before the next one. Production never fires any.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PipelinePoint {
    AfterEnroll,
    /// The run reached a terminal state and the result was kept; the step has
    /// not been recorded yet.
    AfterDispatch,
    AfterAssemble,
    /// The release was prepared (charged); the mark has not been stored.
    AfterPrepare,
    AfterMarkPrepared,
    /// The projection was delivered; the step has not been recorded.
    AfterRelease,
}

pub trait PipelineFault: Send + Sync {
    fn crash_at(&self, point: PipelinePoint) -> bool;
}

#[derive(Debug, Default)]
pub struct NoPipelineFault;

impl PipelineFault for NoPipelineFault {
    fn crash_at(&self, _point: PipelinePoint) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum PipelineError {
    Store(StoreError),
    /// A simulated crash (tests only).
    Crash(PipelinePoint),
}

impl From<StoreError> for PipelineError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

type Res<T> = Result<T, PipelineError>;

/// What a pass found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    pub enrolled: usize,
    pub advanced: usize,
    /// (request id, fixed waiting reason) of runs that could not move.
    pub waiting: Vec<(String, &'static str)>,
}

enum Progress {
    Advanced,
    Waiting(&'static str),
    Done,
}

/// Everything fixed at start that the pipeline needs besides its wiring.
pub struct PipelineSettings {
    pub owner: String,
    pub worker_actor: String,
    pub lease_secs: u64,
    pub max_state_age_secs: u64,
    pub attestation: AttestationConfig,
    pub destination: custodian_contracts::types::DestinationId,
    pub provision_release_budgets: bool,
    pub policy: DisclosurePolicy,
    pub policy_binding: ActivationRef,
    pub shutdown_grace: Duration,
}

/// Re-checks that the installation and repository a request came from are
/// still allowed and not removed, immediately before protected execution.
pub struct ScopeGuard {
    pub config: IntakeConfig,
    pub registry: Arc<dyn InstallationRegistry>,
}

impl ScopeGuard {
    fn check(&self, installation: u64, repository: u64) -> Result<(), &'static str> {
        let (Some(i), Some(r)) = (
            InstallationId::new(installation),
            RepositoryId::new(repository),
        ) else {
            return Err("scope_removed");
        };
        if !self.config.installation_allowed(i)
            || !self.config.repository_allowed(i, r)
            || self.registry.installation_removed(i).unwrap_or(true)
            || self.registry.repository_removed(i, r).unwrap_or(true)
        {
            return Err("scope_removed");
        }
        Ok(())
    }
}

pub struct Pipeline<'a, S: EpochBlobStore> {
    pub parts: Parts<'a, S>,
    pub svc: &'a Service<'a, S>,
    /// `None` when no verified worker exists on this host: runs wait with
    /// `worker_unavailable` and nothing executes.
    pub dispatcher: Option<&'a Dispatcher>,
    pub artifacts: &'a DirArtifacts,
    pub approvals: &'a dyn ReleaseApprovals,
    pub sink: &'a dyn Sink,
    pub names: &'a dyn PublicPopulationNames,
    pub checks: Option<&'a CheckReporter>,
    pub scope: Option<&'a ScopeGuard>,
    pub settings: PipelineSettings,
    pub log: &'a dyn EventLog,
    pub fault: &'a dyn PipelineFault,
    /// The handle that pins `parts.clock` (a `PinnableClock`) during a
    /// prepare replay.
    pub pin: &'a ClockPin,
}

// ---- the result sink ------------------------------------------------------------

struct StoreResultSink<'s> {
    store: &'s SqliteStore,
    attempt: RunId,
    clock: Arc<dyn Clock>,
}

impl ResultSink for StoreResultSink<'_> {
    fn persist(&self, r: &ValidatedResult) -> Result<(), WorkerReason> {
        let meta = ResultMeta {
            outcome: match r.outcome {
                custodian_contracts::execution::ExecutionOutcome::Success => "success",
                _ => "partial",
            }
            .to_owned(),
            expected: r.roster.expected.get(),
            observed: r.roster.observed.get(),
            failed: r.roster.failed.get(),
        };
        self.store
            .pipeline_store_result(
                &self.attempt,
                &meta.to_json(),
                r.aggregates_bytes(),
                self.clock.now(),
            )
            .map_err(|_| WorkerReason::LedgerUnavailable)
    }
}

fn wait_word(r: CliReason) -> &'static str {
    match r {
        CliReason::SignerUnavailable => "signer_unavailable",
        CliReason::LedgerUnavailable => "ledger_unavailable",
        CliReason::StoreUnavailable => "store_unavailable",
        CliReason::LedgerUntrusted
        | CliReason::StoreRolledBack
        | CliReason::RegistryRolledBack
        | CliReason::StoreNeedsReconcile => "store_needs_reconcile",
        _ => "export_pending",
    }
}

/// How a disclosure refusal is handled: wait for the world to change, or
/// close the run with the refusal's own fixed word.
enum Disposition {
    Wait(&'static str),
    Close(&'static str),
}

fn dispose(e: DisclosureReason) -> Disposition {
    use DisclosureReason as D;
    match e {
        D::StoreUnavailable
        | D::LedgerUnavailable
        | D::SignerUnavailable
        | D::PreconditionNotMet
        | D::AuditNotAcknowledged
        | D::DeliveryFailed
        | D::ActivationStale
        | D::ActivationNotCurrent
        | D::HistoryConflict => Disposition::Wait(e.as_str()),
        // A human can replace the release approval file; keep waiting.
        D::ApprovalWrongScope
        | D::ApprovalNotBound
        | D::ApprovalExpired
        | D::ApproverNotPermitted => Disposition::Wait(e.as_str()),
        other => Disposition::Close(other.as_str()),
    }
}

impl<S: EpochBlobStore> Pipeline<'_, S> {
    fn store(&self) -> &SqliteStore {
        self.parts.store
    }

    fn now(&self) -> Res<Timestamp> {
        Timestamp::new(self.parts.clock.now())
            .map_err(|_| PipelineError::Store(StoreError::InvalidInput))
    }

    fn crash(&self, p: PipelinePoint) -> Res<()> {
        if self.fault.crash_at(p) {
            Err(PipelineError::Crash(p))
        } else {
            Ok(())
        }
    }

    /// Export every pending audit event and record the checkpoints. `Ok`
    /// only when the export drained.
    fn drain(&self) -> Result<(), &'static str> {
        let now = Timestamp::new(self.parts.clock.now()).map_err(|_| "store_unavailable")?;
        match export_all(&self.parts, now) {
            Ok((report, _)) if matches!(report.status, ExportStatus::Drained) => Ok(()),
            Ok(_) => Err("export_pending"),
            Err(r) => Err(wait_word(r)),
        }
    }

    /// One pass: enroll what a human approved, then drive every open run as
    /// far as it can go. Returns when nothing can move.
    pub fn pass(&self, shutdown: &Shutdown) -> Res<PassReport> {
        let mut report = PassReport::default();
        let now = self.now()?;
        for run in self.store().approved_unenrolled(50)? {
            if self.store().pipeline_enroll(&run, now.secs())? {
                report.enrolled += 1;
                self.crash(PipelinePoint::AfterEnroll)?;
            }
        }
        for run in self.store().pipeline_open(50)? {
            if shutdown.is_requested() {
                break;
            }
            self.drive(run, shutdown, &mut report)?;
        }
        Ok(report)
    }

    fn drive(&self, first: PipelineRun, shutdown: &Shutdown, report: &mut PassReport) -> Res<()> {
        let attempt = first.attempt.clone();
        // A run advances at most a handful of steps per pass.
        for _ in 0..8 {
            let Some(run) = self.store().pipeline_run(&attempt)? else {
                return Ok(());
            };
            let progress = match run.step {
                PipelineStep::Enrolled => self.step_dispatch(&run, shutdown)?,
                PipelineStep::Dispatched => self.step_assemble(&run)?,
                PipelineStep::Assembled | PipelineStep::Prepared => self.step_release(&run)?,
                PipelineStep::Released | PipelineStep::Closed => Progress::Done,
            };
            match progress {
                Progress::Advanced => report.advanced += 1,
                Progress::Done => return Ok(()),
                Progress::Waiting(why) => {
                    let now = self.now()?;
                    self.store()
                        .pipeline_advance(&attempt, run.step, why, now.secs())?;
                    report.waiting.push((run.request_id.clone(), why));
                    return Ok(());
                }
            }
            if shutdown.is_requested() {
                return Ok(());
            }
        }
        Ok(())
    }

    // ---- checks -------------------------------------------------------------------

    /// Best effort and fixed text only.
    fn check(&self, request_id: &str, state: CheckState, reason: CheckReason) {
        let (Some(reporter), Ok(Some(link))) = (self.checks, self.store().request_link(request_id))
        else {
            return;
        };
        let (Some(installation), Some(repository), Ok(head)) = (
            InstallationId::new(link.installation_id),
            RepositoryId::new(link.repository_id),
            HeadSha::parse(&link.head_sha),
        ) else {
            return;
        };
        let update = CheckUpdate {
            installation,
            repository,
            head_sha: head,
            state,
            reason: Some(reason),
        };
        if reporter.report(&update).is_err() {
            self.log.event("pipeline", "check_failed");
        }
    }

    fn close(
        &self,
        run: &PipelineRun,
        reason: &'static str,
        check: Option<(CheckState, CheckReason)>,
    ) -> Res<Progress> {
        let now = self.now()?;
        self.store()
            .pipeline_advance(&run.attempt, PipelineStep::Closed, reason, now.secs())?;
        self.log.event("pipeline", reason);
        if let Some((s, r)) = check {
            self.check(&run.request_id, s, r);
        }
        Ok(Progress::Done)
    }

    // ---- dispatch -------------------------------------------------------------------

    fn step_dispatch(&self, run: &PipelineRun, shutdown: &Shutdown) -> Res<Progress> {
        let store = self.store();
        let Some(attempt) = store.attempt(&run.attempt)? else {
            return self.close(run, "attempt_missing", None);
        };
        let settled = |word: &'static str| -> Res<Progress> {
            let now = self.now()?;
            store.pipeline_advance(&run.attempt, PipelineStep::Dispatched, word, now.secs())?;
            Ok(Progress::Advanced)
        };
        match attempt.state {
            RunState::Reserved => {}
            RunState::Proposed | RunState::Authorized => {
                return Ok(Progress::Waiting("attempt_not_reserved"))
            }
            RunState::Running | RunState::Validating => {
                return Ok(Progress::Waiting("attempt_in_flight"))
            }
            RunState::Completed => return settled("attempt_completed"),
            RunState::Failed => return settled("attempt_failed"),
            RunState::Cancelled => return settled("attempt_cancelled"),
            RunState::Expired => return settled("attempt_expired"),
            RunState::Denied => return settled("attempt_denied"),
        }
        if shutdown.is_requested() {
            return Ok(Progress::Waiting("shutting_down"));
        }
        let Some(request) = store.reserved_request(&run.request_id)? else {
            return self.close(run, "request_missing", None);
        };

        // The installation and repository must still be allowed. A request
        // approved before they were removed is cancelled (nothing was
        // exposed, so the unit is refunded) rather than run.
        if let (Some(scope), Some(link)) = (self.scope, store.request_link(&run.request_id)?) {
            if let Err(word) = scope.check(link.installation_id, link.repository_id) {
                let now = self.now()?;
                store.cancel(
                    &run.attempt,
                    &ActorId::new(self.settings.worker_actor.clone()),
                    ReasonCode::Cancelled,
                    now.secs(),
                )?;
                return self.close(
                    run,
                    word,
                    Some((
                        CheckState::Denied,
                        CheckReason::Core(ReasonCode::AuthorizationDenied),
                    )),
                );
            }
        }
        let Some(dispatcher) = self.dispatcher else {
            return Ok(Progress::Waiting("worker_unavailable"));
        };
        let sources = match self.artifacts.sources_for(&request.plan) {
            Ok(s) => s,
            Err(SourceError::Unavailable) => return Ok(Progress::Waiting("artifact_unavailable")),
            Err(SourceError::Rejected) => {
                let now = self.now()?;
                store.cancel(
                    &run.attempt,
                    &ActorId::new(self.settings.worker_actor.clone()),
                    ReasonCode::Cancelled,
                    now.secs(),
                )?;
                return self.close(run, "artifact_rejected", None);
            }
        };

        // The rollback and ledger check, with no bypass, immediately before
        // protected bytes could be opened (as `Service::start` runs it before
        // anything writes). A refusal here holds the run.
        if custodian_cli::startup::check(&self.parts).is_err() {
            return Ok(Progress::Waiting("startup_check_refused"));
        }
        let now = self.now()?;
        let Some(observed) = store.observe_activation(&request.plan.policy_activation, now)? else {
            return Ok(Progress::Waiting("policy_activation_missing"));
        };
        let clock = self.parts.clock.clone();
        let clock2 = self.parts.clock.clone();
        let observed2 = observed.clone();
        let inner = StoreRunLedger::new(
            store,
            run.attempt.clone(),
            self.settings.owner.clone(),
            ActorId::new(self.settings.worker_actor.clone()),
            self.settings.lease_secs,
            self.settings.max_state_age_secs,
            Arc::new(move || clock.now()),
            Arc::new(move || Some(observed2.clone())),
        )
        // R-2 (ADR 0116): dispatch is closed unless the audit export drains.
        .with_export_barrier(|| self.drain().is_ok());
        let _ = clock2;
        let guarded = self.svc.guard_run_ledger(
            inner,
            request.plan.candidate.clone(),
            request.plan.population.epoch_id.clone(),
        );
        let corpus = PopulationsCorpus::new(
            self.parts.populations,
            Authorization {
                id: AuthorizationId::new(run.approval_id.clone()),
                actor: ActorId::new(self.settings.worker_actor.clone()),
                plan: PlanDigest::new(
                    request
                        .plan
                        .plan_digest()
                        .map(|d| d.as_str().to_owned())
                        .unwrap_or_default(),
                ),
                population: population_id_for(&request.plan.population.epoch_id),
                expires_at: 0,
            },
        );
        let sink = StoreResultSink {
            store,
            attempt: run.attempt.clone(),
            clock: self.parts.clock.clone(),
        };
        self.check(
            &run.request_id,
            CheckState::InProgress,
            CheckReason::Core(ReasonCode::BudgetReserved),
        );
        let cancel = CancelToken::new();
        let outcome = std::thread::scope(|scope| {
            // On shutdown the run gets a grace period to finish; after it the
            // worker is cancelled (and, having been exposed, is consumed, never
            // refunded).
            let done = Shutdown::new();
            let (watch_done, watch_cancel, grace) =
                (done.clone(), cancel.clone(), self.settings.shutdown_grace);
            scope.spawn(move || {
                while !watch_done.is_requested() {
                    if shutdown.is_requested() {
                        if watch_done.sleep(grace) {
                            return;
                        }
                        watch_cancel.cancel();
                        return;
                    }
                    watch_done.sleep(Duration::from_millis(20));
                }
            });
            let r = dispatcher.run_attempt_with(
                &DispatchJob {
                    plan: &request.plan,
                    sources: &sources,
                },
                &guarded,
                &corpus,
                &cancel,
                &sink,
            );
            done.request();
            r
        });
        match outcome {
            Ok(report) => {
                self.crash(PipelinePoint::AfterDispatch)?;
                let word = match report.outcome {
                    custodian_contracts::execution::ExecutionOutcome::Success => {
                        "dispatched_success"
                    }
                    custodian_contracts::execution::ExecutionOutcome::Partial => {
                        "dispatched_partial"
                    }
                    custodian_contracts::execution::ExecutionOutcome::Failed => "dispatched_failed",
                    custodian_contracts::execution::ExecutionOutcome::Cancelled => {
                        "dispatched_cancelled"
                    }
                    custodian_contracts::execution::ExecutionOutcome::Expired => {
                        "dispatched_expired"
                    }
                    custodian_contracts::execution::ExecutionOutcome::Rejected => {
                        "dispatched_rejected"
                    }
                };
                let now = self.now()?;
                store.pipeline_advance(&run.attempt, PipelineStep::Dispatched, word, now.secs())?;
                self.log.event("pipeline", word);
                Ok(Progress::Advanced)
            }
            // Nothing could be settled (the ledger or the store was
            // unreachable, the export gate held). The attempt is exactly as
            // it was or lapses into recovery; try again on a later pass.
            Err(WorkerReason::LedgerUnavailable) => Ok(Progress::Waiting("ledger_unavailable")),
            Err(r) => Ok(Progress::Waiting(r.code())),
        }
    }

    // ---- assemble -------------------------------------------------------------------

    fn step_assemble(&self, run: &PipelineRun) -> Res<Progress> {
        let store = self.store();
        let Some(attempt) = store.attempt(&run.attempt)? else {
            return self.close(run, "attempt_missing", None);
        };
        if !matches!(
            attempt.state,
            RunState::Completed
                | RunState::Failed
                | RunState::Cancelled
                | RunState::Expired
                | RunState::Denied
        ) {
            return Ok(Progress::Waiting("attempt_in_flight"));
        }
        let (Some(request), Some(approval)) = (
            store.reserved_request(&run.request_id)?,
            store.approval_document(&run.request_id, &run.approval_id)?,
        ) else {
            return self.close(run, "records_missing", None);
        };
        let reservation = match &attempt.reservation_id {
            Some(id) => store.reservation(id)?,
            None => None,
        };
        let history = store.history(&run.attempt)?;
        let art = store.pipeline_artifacts(&run.attempt)?;
        let meta = art
            .as_ref()
            .and_then(|a| a.result_meta.as_deref())
            .and_then(ResultMeta::parse);
        let view = match self.parts.populations.registry().view() {
            Ok(v) => v,
            Err(_) => return Ok(Progress::Waiting("store_unavailable")),
        };
        let outcome = assemble(&Inputs {
            request: &request,
            approval: &approval,
            reservation: reservation.as_ref(),
            attempt: &attempt,
            history: &history,
            meta: meta.as_ref(),
            aggregates: art.as_ref().and_then(|a| a.aggregates.as_deref()),
            attestation: self.settings.attestation,
            registry: &view,
        });
        let now = self.now()?;
        let plan_digest = request
            .plan
            .plan_digest()
            .map(|d| d.as_str().to_owned())
            .unwrap_or_default();
        let fail_check = |word: &'static str| {
            (
                CheckState::Failed,
                CheckReason::Core(match word {
                    "execution_rejected" | "aggregates_invalid" => ReasonCode::InvalidArtifact,
                    _ => ReasonCode::ExecutionFailed,
                }),
            )
        };
        match outcome {
            Ok(Assembled::Nothing { reason }) => self.close(
                run,
                reason,
                Some((
                    CheckState::Denied,
                    CheckReason::Core(ReasonCode::BudgetExhausted),
                )),
            ),
            Ok(Assembled::Closed {
                execution,
                receipt,
                reason,
            }) => {
                let exe = canonical(&execution)
                    .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
                let rcp = match &receipt {
                    Some(r) => {
                        let doc = canonical(r)
                            .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
                        let digest = r
                            .document_digest()
                            .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
                        Some((doc, digest.as_str().to_owned()))
                    }
                    None => None,
                };
                store.pipeline_assemble(
                    &run.attempt,
                    &AssembledRecords {
                        execution: &exe,
                        execution_id: execution.execution_id.as_str(),
                        receipt: rcp.as_ref().map(|(d, g)| (d.as_str(), g.as_str())),
                        plan_digest: &plan_digest,
                        close_reason: Some(reason),
                    },
                    now.secs(),
                )?;
                self.crash(PipelinePoint::AfterAssemble)?;
                self.log.event("pipeline", reason);
                let (s, r) = fail_check(reason);
                self.check(&run.request_id, s, r);
                Ok(Progress::Done)
            }
            Ok(Assembled::Releasable { execution, receipt }) => {
                let exe = canonical(&execution)
                    .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
                let doc = canonical(&receipt)
                    .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
                let digest = receipt
                    .document_digest()
                    .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
                store.pipeline_assemble(
                    &run.attempt,
                    &AssembledRecords {
                        execution: &exe,
                        execution_id: execution.execution_id.as_str(),
                        receipt: Some((&doc, digest.as_str())),
                        plan_digest: &plan_digest,
                        close_reason: None,
                    },
                    now.secs(),
                )?;
                self.crash(PipelinePoint::AfterAssemble)?;
                self.log.event("pipeline", "assembled");
                Ok(Progress::Advanced)
            }
            // The records disagree with each other or with the sealed epoch:
            // refuse, record nothing, close with the fixed word.
            Err(word) => self.close(run, word, Some(fail_check(word))),
        }
    }

    // ---- prepare and release -----------------------------------------------------------

    fn step_release(&self, run: &PipelineRun) -> Res<Progress> {
        let store = self.store();
        let (Some(request), Some(approval), Some(art)) = (
            store.reserved_request(&run.request_id)?,
            store.approval_document(&run.request_id, &run.approval_id)?,
            store.pipeline_artifacts(&run.attempt)?,
        ) else {
            return self.close(run, "records_missing", None);
        };
        let (Some(exe_doc), Some(rcp_doc), Some(aggregates)) = (
            art.execution.as_deref(),
            art.receipt.as_deref(),
            art.aggregates.as_deref(),
        ) else {
            return self.close(run, "records_missing", None);
        };
        let (Ok(execution), Ok(receipt)) = (
            ExecutionRecord::decode(exe_doc.as_bytes()),
            InternalReceipt::decode(rcp_doc.as_bytes()),
        ) else {
            return self.close(run, "records_invalid", None);
        };
        let Some(attempt) = store.attempt(&run.attempt)? else {
            return self.close(run, "attempt_missing", None);
        };
        let reservation = match &attempt.reservation_id {
            Some(id) => store.reservation(id)?,
            None => None,
        };
        let Some(reservation) = reservation else {
            return self.close(run, "records_missing", None);
        };

        // The terminal audit event must be acknowledged before anything is
        // prepared (the disclosure precondition); the same pass also records
        // the checkpoints.
        if let Err(word) = self.drain() {
            return Ok(Progress::Waiting(word));
        }
        let feed = match self.svc.feed_ref() {
            Ok(f) => f,
            Err(CliReason::PendingObligations | CliReason::NotConfigured) => {
                return Ok(Progress::Waiting("feed_unpublished"))
            }
            Err(r) => return Ok(Progress::Waiting(wait_word(r))),
        };
        let walk = match walk_ledger(self.parts.ledger, self.parts.roots) {
            Ok(w) => w,
            Err(_) => return Ok(Progress::Waiting("ledger_unavailable")),
        };
        let verifier = Verifier::new(walk.keyring);
        let exporter = Exporter::new(self.parts.ledger, self.parts.signer, &verifier);
        let disclosure = self.svc.disclosure_service(store, &exporter, self.names);

        // Prepare is replayed with the persisted instant, so the projection
        // (and its digest) is the one a release approval bound.
        let prepared_at = match &run.prepared {
            Some(m) => m.prepared_at,
            None => self.parts.clock.now(),
        };
        let at = Timestamp::new(prepared_at)
            .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
        // Hold the control plane's clock at that instant for the prepare
        // only (see `clock`): the shared eligibility reads time from it.
        let pin_guard = self.pin.pin(prepared_at);
        let release_key =
            IdempotencyKey::parse(&derived_id("idk_", "release-key", run.attempt.as_str()))
                .map_err(|_| PipelineError::Store(StoreError::InvalidInput))?;
        let Some(exec_obs) = store.observe_activation(&request.plan.policy_activation, at)? else {
            return Ok(Progress::Waiting("policy_activation_missing"));
        };
        let Some(policy_obs) = store.observe_activation(&self.settings.policy_binding, at)? else {
            return Ok(Progress::Waiting("policy_activation_missing"));
        };
        if self.settings.provision_release_budgets {
            if let Err(e) = disclosure.provision_budgets(
                &self.settings.policy,
                &request.plan,
                &request.asserted_actor,
                &ActorId::new(self.settings.worker_actor.clone()),
                at.secs(),
            ) {
                return Ok(match dispose(e) {
                    Disposition::Wait(w) => Progress::Waiting(w),
                    Disposition::Close(w) => return self.close_disclosure(run, w, e),
                });
            }
        }
        let prepared: PreparedRelease = match disclosure.prepare_bound(
            &PrepareInput {
                policy: &self.settings.policy,
                request: &request,
                execution_approval: &approval,
                reservation: &reservation,
                execution: &execution,
                receipt: &receipt,
                aggregates,
                attempt: &run.attempt,
                execution_activation: &exec_obs,
                policy_binding: &self.settings.policy_binding,
                policy_activation: &policy_obs,
                release_key: &release_key,
                feed,
            },
            &self.settings.destination,
            at,
        ) {
            Ok(p) => p,
            Err(e) => {
                return match dispose(e) {
                    Disposition::Wait(w) => Ok(Progress::Waiting(w)),
                    Disposition::Close(w) => self.close_disclosure(run, w, e),
                }
            }
        };
        drop(pin_guard);
        self.crash(PipelinePoint::AfterPrepare)?;
        let digest = prepared.digest().as_str().to_owned();
        if let Some(m) = &run.prepared {
            if m.projection_digest != digest {
                return self.close(run, "projection_changed", None);
            }
        } else {
            let now = self.now()?;
            match store.pipeline_mark_prepared(
                &run.attempt,
                &PreparedMark {
                    prepared_at,
                    release_key: release_key.as_str().to_owned(),
                    projection_digest: digest.clone(),
                },
                "awaiting_release_approval",
                now.secs(),
            ) {
                Ok(()) => {}
                Err(StoreError::IdentityConflict) => {
                    return self.close(run, "projection_changed", None)
                }
                Err(e) => return Err(e.into()),
            }
            self.crash(PipelinePoint::AfterMarkPrepared)?;
            self.log.event("pipeline", "prepared");
        }

        // A human's release approval, from a file; the daemon has no other
        // source and grants nothing.
        let release_approval = match self.approvals.approval_for(&run.request_id) {
            Ok(Some(a)) => a,
            Ok(None) => return Ok(Progress::Waiting("awaiting_release_approval")),
            Err(ApprovalFile::Rejected) => {
                return Ok(Progress::Waiting("release_approval_rejected"))
            }
        };
        // The charge audit must be acknowledged before release.
        if let Err(word) = self.drain() {
            return Ok(Progress::Waiting(word));
        }
        let now = self.now()?;
        let Some(policy_now) = store.observe_activation(&self.settings.policy_binding, now)? else {
            return Ok(Progress::Waiting("policy_activation_missing"));
        };
        match disclosure.release(
            &prepared,
            &ReleaseRequest {
                approval: &release_approval,
                destination: &self.settings.destination,
                policy: &self.settings.policy,
                policy_activation: &policy_now,
            },
            self.sink,
            now,
        ) {
            Ok(_) => {}
            Err(e) => {
                return match dispose(e) {
                    Disposition::Wait(w) => Ok(Progress::Waiting(w)),
                    Disposition::Close(w) => self.close_disclosure(run, w, e),
                }
            }
        }
        self.crash(PipelinePoint::AfterRelease)?;
        let done = self.now()?;
        store.pipeline_advance(
            &run.attempt,
            PipelineStep::Released,
            "released",
            done.secs(),
        )?;
        self.log.event("pipeline", "released");
        self.check(
            &run.request_id,
            CheckState::Completed,
            CheckReason::Core(ReasonCode::Completed),
        );
        // Record the release's audit events; the scheduler would too.
        let _ = self.drain();
        Ok(Progress::Done)
    }

    fn close_disclosure(
        &self,
        run: &PipelineRun,
        word: &'static str,
        e: DisclosureReason,
    ) -> Res<Progress> {
        self.close(run, word, Some((e.check_state(), e.check_reason())))
    }
}

/// `StoreActivations` is re-exported so embedders wire the one activation
/// source `Service::start` needs.
pub type Activations<'a> = StoreActivations<'a>;
