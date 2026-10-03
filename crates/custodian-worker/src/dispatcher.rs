//! The dispatcher: runs one reserved attempt of an approved, frozen plan in
//! the sandbox and settles it in the run ledger.
//!
//! Order (each step fails closed; ADR 0042):
//!
//! 1. check the isolation verification matches this sandbox and is fresh;
//! 2. resolve every pinned artifact through the allowlist and verify its
//!    digest against the plan's frozen identities (before any protected input);
//!    a failure here is `fail_before_start` (refunded: nothing was exposed);
//! 3. `ledger.start()` takes the lease;
//! 4. stage the artifacts immutably, hashing the bytes copied, then re-hash
//!    the staged copies;
//! 5. `ledger.record_exposure()` is committed BEFORE the corpus is opened;
//! 6. open the corpus (verifies the whole epoch), compare its binding with the
//!    plan, materialize inputs read-only, write the job document;
//! 7. run in the sandbox with a heartbeat that renews the lease;
//! 8. re-verify staged and source artifacts and the input shape;
//! 9. `ledger.begin_validation()`, validate the bounded result, map it to an
//!    `ExecutionOutcome`, `ledger.finish(..)`.
//!
//! A crash, signal, timeout, output flood, non-zero exit or lost lease is
//! never a clean scan: it maps to `Failed` or `Cancelled` and the worker's
//! stdout is not even parsed.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use custodian_contracts::common::PopulationBinding;
use custodian_contracts::execution::{ExecutionOutcome, PrivateArtifactRef, RosterCounts};
use custodian_contracts::request::EvaluationPlan;
use custodian_core::Exposure;

use crate::artifacts::{hash_file, ArtifactAllowlist, Staging};
use crate::isolation::{Grade, IsolationVerification};
use crate::ports::{CorpusPort, RunLedger};
use crate::reason::{Result, WorkerReason as R};
use crate::result::{
    job_document, validate_result, ValidatedResult, MAX_RESULT_BYTES, MAX_STDERR_BYTES,
};
use crate::sandbox::{CancelToken, Quotas, RoMount, Sandbox, SandboxSpec, Termination};

const MIB: u64 = 1024 * 1024;

/// Operator ceilings. The effective quota is the smaller of the plan's
/// `ResourceLimits` and these caps; a plan can ask for less, never more.
#[derive(Clone, Copy, Debug)]
pub struct OperatorCaps {
    pub max_cpu_seconds: u64,
    pub max_wall: Duration,
    pub max_memory_mib: u64,
    pub max_storage_mib: u64,
    pub max_processes: u64,
}

impl Default for OperatorCaps {
    fn default() -> Self {
        Self {
            max_cpu_seconds: 3600,
            max_wall: Duration::from_secs(3600),
            max_memory_mib: 8192,
            max_storage_mib: 4096,
            max_processes: 256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DispatcherConfig {
    /// Private (0700) directory under which per-run staging is created.
    pub staging_base: PathBuf,
    pub allowlist: ArtifactAllowlist,
    pub caps: OperatorCaps,
    /// How often the lease is renewed while a worker runs.
    pub heartbeat_interval: Duration,
    /// A verification older than this is refused.
    pub verification_max_age_secs: u64,
    /// Upper bound on protected bytes materialized for one run.
    pub max_input_total_bytes: u64,
}

impl DispatcherConfig {
    pub fn new(staging_base: PathBuf, allowlist: ArtifactAllowlist) -> Self {
        Self {
            staging_base,
            allowlist,
            caps: OperatorCaps::default(),
            heartbeat_interval: Duration::from_secs(10),
            verification_max_age_secs: 3600,
            max_input_total_bytes: 1 << 30,
        }
    }
}

/// Where the control plane found each pinned artifact. Every path must be
/// under an allowlisted root, and its bytes must hash to the plan's frozen
/// identity, or the job is refused.
#[derive(Clone, Debug)]
pub struct ArtifactSources {
    pub engine: PathBuf,
    pub adapter: PathBuf,
    /// Same order and length as `plan.scanners`.
    pub scanners: Vec<PathBuf>,
    pub candidate: PathBuf,
    pub config: PathBuf,
}

pub struct DispatchJob<'a> {
    pub plan: &'a EvaluationPlan,
    pub sources: &'a ArtifactSources,
}

/// Result of one dispatched attempt. Carries no worker text.
pub struct DispatchReport {
    pub outcome: ExecutionOutcome,
    pub reason: R,
    pub exposure: Exposure,
    /// How the worker ended, when it ran.
    pub termination: Option<Termination>,
    /// Present only for a validated result (success or partial).
    pub result: Option<ValidatedResult>,
    /// False when the lease was lost: the store already settled the attempt.
    pub settled: bool,
    pub elapsed: Duration,
    /// The verification this dispatch ran under.
    pub isolation: IsolationVerification,
}

impl DispatchReport {
    pub fn artifact(&self) -> Option<&PrivateArtifactRef> {
        self.result.as_ref().map(|r| &r.artifact)
    }
    pub fn roster(&self) -> Option<&RosterCounts> {
        self.result.as_ref().map(|r| &r.roster)
    }
}

impl core::fmt::Debug for DispatchReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DispatchReport")
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("exposure", &self.exposure)
            .field("termination", &self.termination)
            .field("settled", &self.settled)
            .finish()
    }
}

struct Pin {
    name: String,
    source: PathBuf,
    expected: String,
    executable: bool,
}

struct Verdict {
    outcome: ExecutionOutcome,
    reason: R,
    termination: Option<Termination>,
    result: Option<ValidatedResult>,
    exposure: Exposure,
}

enum Halt {
    Fenced(Exposure),
    Ledger,
}

fn led<T>(r: Result<T>, e: Exposure) -> core::result::Result<T, Halt> {
    r.map_err(|x| {
        if x == R::LeaseLost {
            Halt::Fenced(e)
        } else {
            Halt::Ledger
        }
    })
}

struct CloseOnDrop<'a>(&'a dyn CorpusPort);
impl Drop for CloseOnDrop<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}

pub struct Dispatcher {
    sandbox: std::sync::Arc<dyn Sandbox>,
    verification: IsolationVerification,
    cfg: DispatcherConfig,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Dispatcher {
    /// Build a dispatcher. Requires a `Verified` self-check record produced
    /// for this very sandbox kind with every check passed.
    pub fn new(
        sandbox: std::sync::Arc<dyn Sandbox>,
        verification: IsolationVerification,
        cfg: DispatcherConfig,
    ) -> Result<Self> {
        if verification.grade != Grade::Verified
            || !verification.all_passed()
            || verification.sandbox != sandbox.kind()
        {
            return Err(R::IsolationNotVerified);
        }
        Ok(Self {
            sandbox,
            verification,
            cfg,
        })
    }

    /// TEST ONLY: accepts the unsandboxed fake with its test-only record.
    #[cfg(feature = "test-fakes")]
    pub fn new_for_tests(
        sandbox: std::sync::Arc<dyn Sandbox>,
        verification: IsolationVerification,
        cfg: DispatcherConfig,
    ) -> Result<Self> {
        if verification.grade != Grade::TestOnlyNotIsolated
            || verification.sandbox != sandbox.kind()
        {
            return Err(R::IsolationNotVerified);
        }
        Ok(Self {
            sandbox,
            verification,
            cfg,
        })
    }

    pub fn verification(&self) -> &IsolationVerification {
        &self.verification
    }

    fn check_verification_fresh(&self) -> Result<()> {
        if self.verification.grade == Grade::Verified
            && now_secs().saturating_sub(self.verification.verified_at)
                > self.cfg.verification_max_age_secs
        {
            return Err(R::VerificationStale);
        }
        Ok(())
    }

    fn quotas(&self, plan: &EvaluationPlan) -> Result<Quotas> {
        let l = &plan.limits;
        let c = &self.cfg.caps;
        let out = l.max_output_bytes.get();
        let q = Quotas {
            cpu_seconds: l.cpu_seconds.get().min(c.max_cpu_seconds),
            wall: Duration::from_secs(l.wall_seconds.get()).min(c.max_wall),
            memory_bytes: l.memory_mib.get().min(c.max_memory_mib) * MIB,
            storage_bytes: l.storage_mib.get().min(c.max_storage_mib) * MIB,
            max_processes: u64::from(l.max_processes.get() as u32).min(c.max_processes),
            stdout_bytes: out.min(MAX_RESULT_BYTES),
            stderr_bytes: out.min(MAX_STDERR_BYTES),
        };
        if q.cpu_seconds == 0
            || q.wall.is_zero()
            || q.memory_bytes == 0
            || q.storage_bytes == 0
            || q.max_processes == 0
            || q.stdout_bytes == 0
            || q.stderr_bytes == 0
        {
            return Err(R::PlanInconsistent);
        }
        Ok(q)
    }

    /// Resolve every artifact through the allowlist and verify its digest
    /// against the plan, before any protected input is touched.
    fn pins(&self, job: &DispatchJob<'_>) -> Result<Vec<Pin>> {
        let plan = job.plan;
        plan.validate().map_err(|_| R::PlanInconsistent)?;
        if job.sources.scanners.len() != plan.scanners.len() {
            return Err(R::PlanInconsistent);
        }
        let mut pins = vec![
            Pin {
                name: "engine".into(),
                source: job.sources.engine.clone(),
                expected: plan.engine.digest.as_str().to_owned(),
                executable: true,
            },
            Pin {
                name: "adapter".into(),
                source: job.sources.adapter.clone(),
                expected: plan.adapter.digest.as_str().to_owned(),
                executable: true,
            },
            Pin {
                name: "candidate".into(),
                source: job.sources.candidate.clone(),
                expected: plan.candidate.as_str().to_owned(),
                executable: true,
            },
            Pin {
                name: "config".into(),
                source: job.sources.config.clone(),
                expected: plan.config_digest.as_str().to_owned(),
                executable: false,
            },
        ];
        for (i, s) in plan.scanners.as_slice().iter().enumerate() {
            pins.push(Pin {
                name: format!("scanner-{i}"),
                source: job.sources.scanners[i].clone(),
                expected: s.digest.as_str().to_owned(),
                executable: true,
            });
        }
        for p in &mut pins {
            p.source = self.cfg.allowlist.resolve(&p.source)?;
            if hash_file(&p.source)? != p.expected {
                return Err(R::IdentityMismatch);
            }
        }
        Ok(pins)
    }

    /// Run one reserved attempt. `Err` means nothing could be settled
    /// (ledger unreachable); every other path returns a report.
    pub fn run_attempt(
        &self,
        job: &DispatchJob<'_>,
        ledger: &dyn RunLedger,
        corpus: &dyn CorpusPort,
        cancel: &CancelToken,
    ) -> Result<DispatchReport> {
        let t0 = Instant::now();
        let report = |outcome, reason, exposure, settled, term, result| DispatchReport {
            outcome,
            reason,
            exposure,
            termination: term,
            result,
            settled,
            elapsed: t0.elapsed(),
            isolation: self.verification.clone(),
        };

        // Steps 1-2: nothing exposed yet, so a refusal is refunded.
        let pre: Result<(Vec<Pin>, Quotas)> = (|| {
            self.check_verification_fresh()?;
            let q = self.quotas(job.plan)?;
            let p = self.pins(job)?;
            if cancel.is_cancelled() {
                return Err(R::Cancelled);
            }
            Ok((p, q))
        })();
        let (pins, quotas) = match pre {
            Ok(x) => x,
            Err(reason) => {
                let outcome = match reason {
                    R::Cancelled => ExecutionOutcome::Cancelled,
                    R::IsolationNotVerified | R::VerificationStale | R::UnsupportedPlatform => {
                        ExecutionOutcome::Failed
                    }
                    _ => ExecutionOutcome::Rejected,
                };
                ledger.fail_before_start(reason.core_reason())?;
                return Ok(report(
                    outcome,
                    reason,
                    Exposure::NotExposed,
                    true,
                    None,
                    None,
                ));
            }
        };

        // Step 3. A refusal here (the epoch was contaminated, changed or
        // retired since reservation, C9) happens before anything was exposed:
        // settle it as a refunded pre-start failure.
        match ledger.start() {
            Ok(()) => {}
            Err(R::EligibilityDenied) => {
                ledger.fail_before_start(R::EligibilityDenied.core_reason())?;
                return Ok(report(
                    ExecutionOutcome::Rejected,
                    R::EligibilityDenied,
                    Exposure::NotExposed,
                    true,
                    None,
                    None,
                ));
            }
            Err(e) => return Err(e),
        }

        match self.drive(job, ledger, corpus, cancel, &pins, quotas) {
            Ok(v) => {
                let settled = match ledger.finish(v.outcome, v.reason.core_reason()) {
                    Ok(()) => true,
                    Err(R::LeaseLost) => false,
                    Err(e) => return Err(e),
                };
                Ok(report(
                    v.outcome,
                    v.reason,
                    v.exposure,
                    settled,
                    v.termination,
                    v.result,
                ))
            }
            Err(Halt::Fenced(e)) => Ok(report(
                ExecutionOutcome::Cancelled,
                R::LeaseLost,
                e,
                false,
                None,
                None,
            )),
            Err(Halt::Ledger) => {
                // Best effort; if the ledger is down the lease lapses and
                // recovery settles the attempt as exposed-and-consumed.
                let _ = ledger.finish(ExecutionOutcome::Failed, R::LedgerUnavailable.core_reason());
                Err(R::LedgerUnavailable)
            }
        }
    }

    fn drive(
        &self,
        job: &DispatchJob<'_>,
        ledger: &dyn RunLedger,
        corpus: &dyn CorpusPort,
        cancel: &CancelToken,
        pins: &[Pin],
        quotas: Quotas,
    ) -> core::result::Result<Verdict, Halt> {
        let verdict = |outcome, reason, exposure| {
            Ok(Verdict {
                outcome,
                reason,
                termination: None,
                result: None,
                exposure,
            })
        };
        let rejects = |r: R| matches!(r, R::IdentityMismatch | R::ArtifactInvalid);

        // Step 4: stage immutably, then re-hash the staged copies.
        let mut staging = match Staging::create(&self.cfg.staging_base) {
            Ok(s) => s,
            Err(r) => return verdict(ExecutionOutcome::Failed, r, Exposure::NotExposed),
        };
        for p in pins {
            if let Err(r) = staging.stage_pinned(&p.name, &p.source, &p.expected, p.executable) {
                let o = if rejects(r) {
                    ExecutionOutcome::Rejected
                } else {
                    ExecutionOutcome::Failed
                };
                return verdict(o, r, Exposure::NotExposed);
            }
        }
        if let Err(r) = staging.verify(R::IdentityChangedAfterStaging) {
            return verdict(ExecutionOutcome::Rejected, r, Exposure::NotExposed);
        }
        if cancel.is_cancelled() {
            return verdict(
                ExecutionOutcome::Cancelled,
                R::Cancelled,
                Exposure::NotExposed,
            );
        }

        // Step 5: write-ahead exposure record, then and only then the corpus.
        match ledger.record_exposure() {
            Ok(()) => {}
            // The last gate before protected bytes: nothing was opened.
            Err(R::EligibilityDenied) => {
                return verdict(
                    ExecutionOutcome::Rejected,
                    R::EligibilityDenied,
                    Exposure::NotExposed,
                )
            }
            other => led(other, Exposure::NotExposed)?,
        }
        let exposed = Exposure::Exposed;
        // R-2 (ADR 0116): the exposure record must be acknowledged by the
        // ledger export before protected bytes are opened. If it is not, the
        // attempt stays exposed (the unit is consumed, never refunded) and
        // the corpus is never opened.
        led(ledger.confirm_exposure_exported(), exposed)?;
        let _close = CloseOnDrop(corpus);

        // Step 6.
        if corpus.open().is_err() {
            return verdict(ExecutionOutcome::Failed, R::CorpusUnavailable, exposed);
        }
        let plan = job.plan;
        match corpus.binding() {
            Ok(b) if binding_matches(&b, plan) => {}
            Ok(_) => return verdict(ExecutionOutcome::Rejected, R::PopulationMismatch, exposed),
            Err(r) => return verdict(ExecutionOutcome::Failed, r, exposed),
        }
        let names = match corpus.entry_names() {
            Ok(n) if !n.is_empty() => n,
            Ok(_) => return verdict(ExecutionOutcome::Rejected, R::RosterMismatch, exposed),
            Err(r) => return verdict(ExecutionOutcome::Failed, r, exposed),
        };
        let mut total = 0u64;
        for n in &names {
            let bytes = match corpus.read_entry(n) {
                Ok(b) => b,
                Err(r) => return verdict(ExecutionOutcome::Failed, r, exposed),
            };
            total += bytes.len() as u64;
            if total > self.cfg.max_input_total_bytes {
                return verdict(ExecutionOutcome::Failed, R::StagingFailed, exposed);
            }
            if let Err(r) = staging.materialize_input(n, bytes.expose()) {
                return verdict(ExecutionOutcome::Failed, r, exposed);
            }
        }
        drop(_close); // protected bytes are staged; release the handle now
        if let Err(r) = staging.verify_input_shape(names.len()) {
            return verdict(ExecutionOutcome::Failed, r, exposed);
        }
        let doc = match job_document(plan.domain, &plan.protocol, &names) {
            Ok(d) => d,
            Err(r) => return verdict(ExecutionOutcome::Failed, r, exposed),
        };
        if let Err(r) = staging.write_job(&doc) {
            return verdict(ExecutionOutcome::Failed, r, exposed);
        }
        if cancel.is_cancelled() {
            return verdict(ExecutionOutcome::Cancelled, R::Cancelled, exposed);
        }
        // Last look at the staged copies before anything runs.
        if let Err(r) = staging.verify(R::IdentityChangedAfterStaging) {
            return verdict(ExecutionOutcome::Rejected, r, exposed);
        }

        // Step 7.
        let spec = SandboxSpec {
            program: "/stage/engine".into(),
            args: vec!["--job".into(), "/job/job.json".into()],
            ro_mounts: vec![
                RoMount {
                    host: staging.stage_dir(),
                    inner: "/stage".into(),
                },
                RoMount {
                    host: staging.input_dir(),
                    inner: "/input".into(),
                },
                RoMount {
                    host: staging.job_dir(),
                    inner: "/job".into(),
                },
            ],
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), "/scratch".into()),
                ("TMPDIR".into(), "/scratch".into()),
                ("LANG".into(), "C".into()),
            ],
            launcher_env_canaries: Vec::new(),
            quotas,
        };
        let mut last_beat = Instant::now();
        let interval = self.cfg.heartbeat_interval;
        let mut keepalive = || {
            if last_beat.elapsed() < interval {
                return true;
            }
            last_beat = Instant::now();
            // A transient store error keeps the run alive; the store itself
            // fences the lease if it lapses.
            !matches!(ledger.heartbeat(), Err(R::LeaseLost))
        };
        let run = match self.sandbox.run(&spec, cancel, &mut keepalive) {
            Ok(r) => r,
            Err(r) => return verdict(ExecutionOutcome::Failed, r, exposed),
        };

        // Step 8: nothing may have changed, whatever the worker reported.
        let mut drift = staging.verify(R::IdentityChangedAfterExecution).is_err();
        drift |= staging.verify_input_shape(names.len()).is_err();
        for p in pins {
            drift |= !matches!(hash_file(&p.source), Ok(d) if d == p.expected);
        }
        if drift {
            return verdict(
                ExecutionOutcome::Rejected,
                R::IdentityChangedAfterExecution,
                exposed,
            );
        }

        // Step 9.
        let term = Some(run.termination);
        let fail = |o, r| {
            Ok(Verdict {
                outcome: o,
                reason: r,
                termination: term,
                result: None,
                exposure: exposed,
            })
        };
        match run.termination {
            Termination::Fenced => Err(Halt::Fenced(exposed)),
            Termination::Cancelled => fail(ExecutionOutcome::Cancelled, R::Cancelled),
            Termination::TimedOut => fail(ExecutionOutcome::Failed, R::Timeout),
            Termination::OutputLimit => fail(ExecutionOutcome::Failed, R::OutputLimit),
            Termination::Signaled(_) => fail(ExecutionOutcome::Failed, R::Signaled),
            Termination::Exited(c) if c != 0 => fail(ExecutionOutcome::Failed, R::NonZeroExit),
            Termination::Exited(_) => {
                led(ledger.begin_validation(), exposed)?;
                match validate_result(&run.stdout, plan.domain, &plan.protocol, names.len() as u64)
                {
                    Ok(v) => Ok(Verdict {
                        outcome: v.outcome,
                        reason: v.reason,
                        termination: term,
                        exposure: exposed,
                        result: Some(v),
                    }),
                    Err(r) => fail(ExecutionOutcome::Rejected, r),
                }
            }
        }
    }
}

fn binding_matches(b: &PopulationBinding, plan: &EvaluationPlan) -> bool {
    let p = &plan.population;
    b.domain == p.domain
        && b.corpus_id == p.corpus_id
        && b.epoch_id == p.epoch_id
        && b.population_digest == p.population_digest
        && b.domain == plan.domain
}
