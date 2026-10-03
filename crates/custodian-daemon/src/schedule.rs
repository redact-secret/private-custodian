//! Scheduled maintenance: the passes the startup sequence runs once, run
//! again on intervals (ADR 0125).
//!
//! | Task | What it runs | Why it repeats |
//! | --- | --- | --- |
//! | `recover` | `SqliteStore::recover` | a lapsed lease settles (an exposed attempt is consumed, never refunded) |
//! | `reconcile_registry` | `EpochManager::reconcile_registry` | the registry mirrors the store's epoch standing |
//! | `deliver_pending` | `FeedPublisher::deliver_pending` | committed feed envelopes reach the destination |
//! | `export` | `Exporter::export_pending` | audit events reach the private ledger |
//! | `checkpoint` | `export_all` (export, then the store and registry checkpoints) | external anchors for the rollback check |
//! | `startup_check` | `custodian_cli::startup::check`, the same call, no bypass | a restore or an untrusted ledger is noticed while running |
//! | `signer_liveness` | `Signer::liveness` | a dead signer is visible before a release needs it |
//!
//! Every task is one of the existing idempotent operations; none charges,
//! refunds, approves, publishes a feed envelope or edits a budget. A failing
//! task is recorded under a fixed word and retried on its next interval; it
//! never stops the others, except `startup_check`: a refusal marks the daemon
//! degraded and the consumers and the pipeline stop starting work until a
//! later check passes (the check itself persists the store's write block when
//! the store became untrustworthy, which only the audited operator repair
//! lifts).
//!
//! The feed envelope that carries a new revocation is published by an
//! operator (`feed publish`, a human action); the scheduler only delivers
//! what an operator already committed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use custodian_cli::reason::CliReason;
use custodian_cli::startup::{check, export_all};
use custodian_cli::Parts;
use custodian_contracts::types::Timestamp;
use custodian_core::ActorId;
use custodian_corpus::EpochBlobStore;
use custodian_ledger::{walk_ledger, ExportStatus, Exporter, Verifier};
use custodian_lifecycle::{EpochManager, FeedPublisher};

use crate::config::ScheduleConfig;
use crate::log::EventLog;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Task {
    Recover,
    ReconcileRegistry,
    DeliverPending,
    Export,
    Checkpoint,
    StartupCheck,
    SignerLiveness,
}

impl Task {
    pub const ALL: [Task; 7] = [
        Self::Recover,
        Self::ReconcileRegistry,
        Self::DeliverPending,
        Self::Export,
        Self::Checkpoint,
        Self::StartupCheck,
        Self::SignerLiveness,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Recover => "recover",
            Self::ReconcileRegistry => "reconcile_registry",
            Self::DeliverPending => "deliver_pending",
            Self::Export => "export",
            Self::Checkpoint => "checkpoint",
            Self::StartupCheck => "startup_check",
            Self::SignerLiveness => "signer_liveness",
        }
    }

    fn interval(self, c: &ScheduleConfig) -> u64 {
        match self {
            Self::Recover => c.recover_secs,
            Self::ReconcileRegistry => c.reconcile_registry_secs,
            Self::DeliverPending => c.deliver_pending_secs,
            Self::Export => c.export_secs,
            Self::Checkpoint => c.checkpoint_secs,
            Self::StartupCheck => c.startup_check_secs,
            Self::SignerLiveness => c.signer_liveness_secs,
        }
    }
}

/// The fixed word a task ended with: `ok` or a refusal code.
pub type TaskResult = Result<(), &'static str>;

/// Shared "do not start new work" flag, set by a failing `startup_check`.
#[derive(Clone, Debug, Default)]
pub struct Degraded(Arc<AtomicBool>);

impl Degraded {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    fn set(&self, v: bool) {
        self.0.store(v, Ordering::SeqCst);
    }
}

pub struct Scheduler<'a, S: EpochBlobStore> {
    parts: Parts<'a, S>,
    cfg: ScheduleConfig,
    log: Arc<dyn EventLog>,
    last: BTreeMap<Task, u64>,
    degraded: Degraded,
    /// The last result of every task that has run, for status and tests.
    pub results: BTreeMap<Task, TaskResult>,
}

fn cli_word(r: CliReason) -> &'static str {
    r.code()
}

impl<'a, S: EpochBlobStore> Scheduler<'a, S> {
    pub fn new(
        parts: Parts<'a, S>,
        cfg: ScheduleConfig,
        log: Arc<dyn EventLog>,
        degraded: Degraded,
    ) -> Self {
        Self {
            parts,
            cfg,
            log,
            last: BTreeMap::new(),
            degraded,
            results: BTreeMap::new(),
        }
    }

    pub fn degraded(&self) -> bool {
        self.degraded.is_set()
    }

    /// Run every task whose interval has elapsed (all of them on the first
    /// call). Returns what ran.
    pub fn tick(&mut self, now: u64) -> Vec<(Task, TaskResult)> {
        let mut ran = Vec::new();
        for t in Task::ALL {
            let due = self
                .last
                .get(&t)
                .is_none_or(|l| now.saturating_sub(*l) >= t.interval(&self.cfg));
            if !due {
                continue;
            }
            self.last.insert(t, now);
            let r = self.run(t, now);
            self.log.event(
                "scheduler",
                match (&r, t) {
                    (Ok(()), _) => "task_ok",
                    (Err(_), _) => "task_failed",
                },
            );
            if let Err(word) = &r {
                self.log.event("scheduler", word);
            }
            self.results.insert(t, r);
            ran.push((t, r));
        }
        ran
    }

    /// Run one task now, regardless of its interval.
    pub fn run(&self, task: Task, now: u64) -> TaskResult {
        let p = &self.parts;
        let ts = Timestamp::new(now).map_err(|_| "store_unavailable")?;
        match task {
            Task::Recover => p
                .store
                .recover(&ActorId::new("custodiand-scheduler"), now)
                .map(|_| ())
                .map_err(|e| cli_word(e.into())),
            Task::ReconcileRegistry => EpochManager {
                store: p.store,
                populations: p.populations,
                authority: p.authority,
                fault: p.fault,
            }
            .reconcile_registry(ts)
            .map(|_| ())
            .map_err(|e| cli_word(e.into())),
            Task::DeliverPending => FeedPublisher {
                store: p.store,
                populations: p.feed_populations,
                signer: p.signer,
                destination: p.feed_destination,
                authority: p.authority,
                config: p.feed_config.clone(),
                fault: p.fault,
            }
            .deliver_pending(ts)
            .map(|_| ())
            .map_err(|e| cli_word(e.into())),
            Task::Export => {
                let walk = walk_ledger(p.ledger, p.roots).map_err(|_| "ledger_unavailable")?;
                let verifier = Verifier::new(walk.keyring);
                let exporter = Exporter::new(p.ledger, p.signer, &verifier);
                match exporter.export_pending(p.store, now) {
                    Ok(r) if matches!(r.status, ExportStatus::Drained) => Ok(()),
                    Ok(_) => Err("export_pending"),
                    Err(e) => Err(cli_word(custodian_cli::control::export_reason(e))),
                }
            }
            Task::Checkpoint => export_all(p, ts)
                .map(|(r, _)| r)
                .map_err(cli_word)
                .and_then(|r| {
                    if matches!(r.status, ExportStatus::Drained) {
                        Ok(())
                    } else {
                        Err("export_pending")
                    }
                }),
            Task::StartupCheck => match check(p) {
                Ok(_) => {
                    self.degraded.set(false);
                    Ok(())
                }
                Err((reason, _)) => {
                    self.degraded.set(true);
                    Err(cli_word(reason))
                }
            },
            Task::SignerLiveness => p.signer.liveness().map_err(|_| "signer_unavailable"),
        }
    }
}
