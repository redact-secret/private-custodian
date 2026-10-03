//! Wiring and process model (ADR 0128).
//!
//! One process, a small fixed set of threads:
//!
//! ```text
//!   main thread (control loop)        listener threads             consumer threads
//!   ---------------------------       -------------------          ------------------
//!   Service::start (startup check,    accept loop + one            lease, check, submit
//!     recover, reconcile, deliver,    short-lived thread per       (own store connection)
//!     export, one eligibility)        connection, capped;
//!   scheduler tick                    Intake::handle (own
//!   pipeline pass (dispatch,          store connection)
//!     assemble, prepare, release)
//! ```
//!
//! The control loop owns everything that borrows the deployment (the
//! `Service`, the signer, the ledger, the dispatcher); the other threads own
//! only `Arc`s and their own store connections. Nothing the listener or a
//! consumer does can reserve, start, expose, settle, sign or release: those
//! paths are reachable only from the control loop, behind the startup
//! sequence's `Service`.
//!
//! The startup sequence is `custodian_cli::Service::start`: the
//! `startup_check` with no bypass, `recover`, `reconcile_registry`,
//! `deliver_pending`, the ledger export and the single `LifecycleEligibility`.
//! If it refuses, `run` returns `startup_refused` and no listener is bound.
//!
//! Shutdown (the flag in [`Shutdown`], set by `SIGTERM`/`SIGINT` in the
//! binary): the listener stops accepting and in-flight requests finish within
//! their deadlines; consumers stop claiming and give back an item they have
//! leased but not acted on; the control loop starts no new run, and a run in
//! flight gets `shutdown_grace_secs` before its worker is cancelled (a
//! cancelled run that was exposed is consumed, as always).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use custodian_cli::startup::StoreActivations;
use custodian_cli::{Parts, Service, StartupConfig};
use custodian_contracts::common::ActivationRef;
use custodian_corpus::EpochBlobStore;
use custodian_disclosure::ports::Sink;
use custodian_disclosure::{DisclosurePolicy, PublicPopulationNames};
use custodian_intake::checks::{CheckReporter, CheckSink};
use custodian_intake::config::{IntakeConfig, WebhookSecret};
use custodian_intake::gate::ExecutionGate;
use custodian_intake::ports::{
    DeliveryStore, InstallationRegistry, IntakeQueue, PullRequestSource,
};
use custodian_intake::webhook::Intake;
use custodian_store::{SqliteStore, StoreConfig};
use custodian_worker::artifacts::ArtifactAllowlist;
use custodian_worker::bwrap::BubblewrapSandbox;
use custodian_worker::{run_self_check, Dispatcher, DispatcherConfig};

use crate::config::{DaemonConfig, Sandbox, WorkerConfig};
use crate::consumer::QueueConsumer;
use crate::http::{HttpServer, IntakeHandler};
use crate::log::EventLog;
use crate::pipeline::approvals::ReleaseApprovals;
use crate::pipeline::{Pipeline, PipelineError, PipelineFault, PipelineSettings, ScopeGuard};
use crate::reason::DaemonReason;
use crate::schedule::{Degraded, Scheduler};
use crate::shutdown::Shutdown;
use crate::source::{CandidateStager, DirArtifacts, RequestSource};

/// Everything `run` needs that is not the configuration file. The binary
/// builds it from the file; tests build it with doubles.
pub struct RunInputs<'a, S: EpochBlobStore> {
    pub config: DaemonConfig,
    pub parts: Parts<'a, S>,
    /// Location and configuration for the extra store connections the
    /// listener and the consumers use (same file, same clock, same gate).
    pub store_path: PathBuf,
    pub store_config: StoreConfig,
    pub intake: IntakeConfig,
    pub webhook_secret: WebhookSecret,
    pub policy: DisclosurePolicy,
    pub dispatcher: Option<Dispatcher>,
    pub names: &'a dyn PublicPopulationNames,
    pub pulls: Arc<dyn PullRequestSource>,
    pub checks: Option<Arc<dyn CheckSink>>,
    /// False when GitHub access is disabled: deliveries still queue, durably,
    /// but nothing is consumed.
    pub consume_queue: bool,
    pub requests: Arc<dyn RequestSource>,
    pub stager: Arc<dyn CandidateStager>,
    pub approvals: Arc<dyn ReleaseApprovals>,
    pub sink: Arc<dyn Sink>,
    pub log: Arc<dyn EventLog>,
    pub fault: Arc<dyn PipelineFault>,
}

/// What `run` reports on a clean stop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitReport {
    pub control_passes: u64,
}

/// The activation reference a disclosure policy's configured activation
/// names.
pub fn policy_binding(
    policy: &DisclosurePolicy,
    cfg: &DaemonConfig,
) -> Result<ActivationRef, DaemonReason> {
    serde_json::from_value(serde_json::json!({
        "policy": policy.policy,
        "activation_id": cfg.release.activation_id,
        "sequence": cfg.release.activation_sequence,
    }))
    .map_err(|_| DaemonReason::ConfigInvalid)
}

/// Build the worker. `None` (with a fixed word) unless the host passes the
/// startup self-check: no verified isolation, no dispatcher, no execution.
pub fn build_worker(
    cfg: &WorkerConfig,
    artifacts_dir: &std::path::Path,
) -> (Option<Dispatcher>, &'static str) {
    if cfg.sandbox == Sandbox::None {
        return (None, "worker_disabled");
    }
    let Ok(sandbox) = BubblewrapSandbox::detect() else {
        return (None, "isolation_unavailable");
    };
    let Some(probe) = &cfg.probe_path else {
        return (None, "isolation_check_failed");
    };
    let Ok(allowlist) = ArtifactAllowlist::new(std::slice::from_ref(&artifacts_dir.to_path_buf()))
    else {
        return (None, "isolation_check_failed");
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let Ok(verification) = run_self_check(
        &sandbox,
        &sandbox.launcher_version(),
        probe,
        &allowlist,
        &cfg.staging_dir,
        now,
    ) else {
        return (None, "isolation_check_failed");
    };
    let mut dcfg = DispatcherConfig::new(cfg.staging_dir.clone(), allowlist);
    dcfg.verification_max_age_secs = cfg.verification_max_age_secs;
    match Dispatcher::new(Arc::new(sandbox), verification, dcfg) {
        Ok(d) => (Some(d), "worker_verified"),
        Err(_) => (None, "isolation_check_failed"),
    }
}

/// Run the daemon until `shutdown` is requested. `ready` is called once, with
/// the address the listener bound, after the startup sequence passed.
pub fn run<S: EpochBlobStore>(
    inp: RunInputs<'_, S>,
    shutdown: &Shutdown,
    ready: &dyn Fn(SocketAddr),
) -> Result<ExitReport, DaemonReason> {
    let RunInputs {
        config,
        parts,
        store_path,
        store_config,
        intake,
        webhook_secret,
        policy,
        dispatcher,
        names,
        pulls,
        checks,
        consume_queue,
        requests,
        stager,
        approvals,
        sink,
        log,
        fault,
    } = inp;
    let binding = policy_binding(&policy, &config)?;

    // 1. The startup sequence, exactly as the operator tooling runs it.
    let limits = parts.authority.policy().limits();
    let startup = StartupConfig {
        guarded_policies: vec![policy.policy.clone()],
        required_activations: config.required_activations.clone(),
        activation_max_age_secs: limits.max_state_age_secs,
    };
    let acts = StoreActivations::new(parts.store, parts.clock.clone());
    let svc = match Service::start(parts.clone(), &startup, &acts) {
        Ok(s) => s,
        Err(f) => {
            // The step is a fixed word; the reason is a fixed code.
            log.event("startup", f.step);
            log.event("startup", f.reason.code());
            return Err(DaemonReason::StartupRefused);
        }
    };
    log.event("runtime", "started");

    // 2. The edge: its own store connection, the real Intake, the listener.
    let open = || {
        SqliteStore::open_with_config(&store_path, store_config.clone())
            .map(Arc::new)
            .map_err(|_| DaemonReason::NotConfigured)
    };
    let edge_store = open()?;
    let handler = IntakeHandler::new(
        Intake::new(
            intake.clone(),
            webhook_secret,
            edge_store.clone() as Arc<dyn DeliveryStore>,
            edge_store.clone() as Arc<dyn InstallationRegistry>,
            edge_store.clone() as Arc<dyn IntakeQueue>,
        ),
        parts.clock.clone(),
    );
    let mut lcfg = config.listener.clone();
    lcfg.max_body_bytes = intake.max_body_bytes();
    let server = HttpServer::start(lcfg, Arc::new(handler), log.clone())?;
    ready(server.local_addr());

    // 3. Consumers, each with its own connection.
    let degraded = Degraded::new();
    let mut consumers = Vec::new();
    if consume_queue {
        for _ in 0..config.queue.workers {
            let store = open()?;
            let reporter = checks.as_ref().map(|sink| {
                Arc::new(CheckReporter::new(
                    intake.clone(),
                    store.clone() as Arc<dyn InstallationRegistry>,
                    sink.clone(),
                ))
            });
            consumers.push(QueueConsumer {
                gate: ExecutionGate::new(
                    intake.clone(),
                    store.clone() as Arc<dyn InstallationRegistry>,
                    pulls.clone(),
                ),
                store,
                requests: requests.clone(),
                stager: stager.clone(),
                checks: reporter,
                clock: parts.clock.clone(),
                log: log.clone(),
                cfg: config.queue.clone(),
                degraded: degraded.clone(),
            });
        }
    } else {
        log.event("runtime", "queue_not_consumed");
    }

    // 4. The control loop.
    let pipeline_store = open()?;
    let scope = ScopeGuard {
        config: intake.clone(),
        registry: pipeline_store.clone() as Arc<dyn InstallationRegistry>,
    };
    let reporter = checks.as_ref().map(|sink| {
        CheckReporter::new(
            intake.clone(),
            pipeline_store.clone() as Arc<dyn InstallationRegistry>,
            sink.clone(),
        )
    });
    let artifacts = DirArtifacts::new(config.artifacts_dir.clone());
    let pipeline = Pipeline {
        parts: parts.clone(),
        svc: &svc,
        dispatcher: dispatcher.as_ref(),
        artifacts: &artifacts,
        approvals: approvals.as_ref(),
        sink: sink.as_ref(),
        names,
        checks: reporter.as_ref(),
        scope: Some(&scope),
        settings: PipelineSettings {
            owner: config.pipeline.owner.clone(),
            worker_actor: config.pipeline.worker_actor.clone(),
            lease_secs: config.pipeline.lease_secs,
            max_state_age_secs: limits.max_state_age_secs,
            attestation: config.attestation,
            destination: config.release.destination.clone(),
            provision_release_budgets: config.release.provision_budgets_from_policy,
            policy: policy.clone(),
            policy_binding: binding,
            shutdown_grace: config.pipeline.shutdown_grace,
        },
        log: log.as_ref(),
        fault: fault.as_ref(),
    };
    let mut scheduler = Scheduler::new(
        parts.clone(),
        config.schedule,
        log.clone(),
        degraded.clone(),
    );

    let mut report = ExitReport::default();
    let outcome = std::thread::scope(|scope| {
        for c in &consumers {
            scope.spawn(move || c.run(shutdown));
        }
        let mut result = Ok(());
        while !shutdown.is_requested() {
            scheduler.tick(parts.clock.now());
            if !scheduler.degraded() {
                match pipeline.pass(shutdown) {
                    Ok(_) => {}
                    Err(PipelineError::Store(_)) => log.event("pipeline", "store_unavailable"),
                    Err(PipelineError::Crash(_)) => {
                        // A simulated crash (tests): stop everything at once.
                        shutdown.request();
                        result = Err(DaemonReason::Stopped);
                        break;
                    }
                }
            }
            report.control_passes += 1;
            shutdown.sleep(config.pipeline.poll);
        }
        result
    });
    server.stop();
    log.event("runtime", "stopped");
    outcome.map(|()| report)
}
