//! The scheduled maintenance passes: intervals, the failure of each task, the
//! degraded state a failing startup check causes, and the signer-liveness
//! probe. Synthetic only.

mod common;

use std::collections::BTreeSet;

use common::*;
use custodian_cli::Parts;
use custodian_contracts::common::Signature;
use custodian_core::{ActorId, Exposure, RunState};
use custodian_corpus::FsEpochStore;
use custodian_daemon::config::ScheduleConfig;
use custodian_daemon::schedule::{Degraded, Scheduler, Task, DEGRADED_RETRY_SECS};
use custodian_ledger::{ApprovedPayload, SignRefusal, Signer};
use custodian_store::{SqliteStore, StartCommand};

fn sched<'a>(env: &'a Env, degraded: Degraded) -> Scheduler<'a, FsEpochStore> {
    Scheduler::new(
        env.p.w.parts(),
        ScheduleConfig::default(),
        env.log.clone(),
        degraded,
    )
}

fn ran(r: &[(Task, Result<(), &'static str>)]) -> BTreeSet<Task> {
    r.iter().map(|(t, _)| *t).collect()
}

#[test]
fn the_first_tick_runs_every_task_and_later_ticks_only_what_is_due() {
    let env = Env::new(3);
    let mut s = sched(&env, Degraded::new());
    let r = s.tick(0, NOW);
    assert_eq!(ran(&r), Task::ALL.into_iter().collect());
    assert!(r.iter().all(|(_, res)| res.is_ok()), "{r:?}");
    // The checkpoints reached the ledger.
    assert!(env
        .p
        .w
        .ledger
        .paths()
        .iter()
        .any(|p| p.contains("checkpoint")));
    // Defaults: recover 60, reconcile 300, deliver 60, export 30,
    // checkpoint 300, startup 300, signer 60.
    assert!(s.tick(1, NOW).is_empty());
    assert_eq!(ran(&s.tick(31, NOW)), BTreeSet::from([Task::Export]));
    assert_eq!(
        ran(&s.tick(61, NOW)),
        BTreeSet::from([
            Task::Recover,
            Task::DeliverPending,
            Task::Export,
            Task::SignerLiveness
        ])
    );
    assert_eq!(
        ran(&s.tick(301, NOW)),
        Task::ALL.into_iter().collect::<BTreeSet<_>>()
    );
    // Intervals are measured on the schedule's own seconds, so a jump in the
    // control plane's time repeats nothing.
    assert!(s.tick(302, NOW + 1_000_000).is_empty());
}

#[test]
fn recover_settles_a_lapsed_lease_as_consumed_never_refunded() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    let s = sched(&env, Degraded::new());
    // The spend must be acknowledged before the store allows a start (R-2).
    s.run(Task::Export, NOW).unwrap();
    let obs = cc::observed(cc::activation(), NOW);
    env.store()
        .start_attempt(&StartCommand {
            attempt: &attempt,
            owner: "crashed-worker",
            actor: &ActorId::new("worker"),
            now: NOW,
            lease_secs: 10,
            observed: Some(&obs),
            max_state_age_secs: 300,
        })
        .unwrap();
    // Not lapsed yet: nothing happens.
    s.run(Task::Recover, NOW + 5).unwrap();
    assert_eq!(
        env.store().attempt(&attempt).unwrap().unwrap().state,
        RunState::Running
    );
    // Lapsed: failed, exposure presumed, the unit consumed.
    s.run(Task::Recover, NOW + 11).unwrap();
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Failed, Exposure::Exposed)
    );
    let b = env.p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
    s.run(Task::Recover, NOW + 12).unwrap();
    assert_eq!(
        env.p.w.budget().consumed,
        1,
        "a second sweep changes nothing"
    );
}

#[test]
fn a_ledger_outage_fails_export_and_checkpoint_and_marks_the_daemon_degraded_until_it_clears() {
    let env = Env::new(3);
    env.approved(1);
    let degraded = Degraded::new();
    let mut s = sched(&env, degraded.clone());
    assert!(s.tick(0, NOW).iter().all(|(_, r)| r.is_ok()));
    assert!(!degraded.is_set());
    env.approved(2);
    env.p.w.ledger.set_available(false);
    assert!(s.run(Task::Export, NOW).is_err());
    assert!(s.run(Task::Checkpoint, NOW).is_err());
    assert_eq!(s.run(Task::StartupCheck, NOW), Err("ledger_unavailable"));
    assert!(degraded.is_set(), "no work starts while the check refuses");
    assert!(
        env.store().outbox_pending_count().unwrap() > 0,
        "nothing was lost"
    );
    // The retry is soon, whatever the 300 s interval says.
    env.p.w.ledger.set_available(true);
    assert!(s.tick(1, NOW).is_empty() || degraded.is_set());
    let r = s.tick(DEGRADED_RETRY_SECS + 1, NOW);
    assert!(ran(&r).contains(&Task::StartupCheck), "{r:?}");
    assert!(!degraded.is_set());
    s.run(Task::Export, NOW).unwrap();
    assert_eq!(env.store().outbox_pending_count().unwrap(), 0);
}

#[test]
fn a_restored_older_store_is_detected_blocked_and_keeps_the_daemon_degraded() {
    let env = Env::new(3);
    let degraded = Degraded::new();
    let s = sched(&env, degraded.clone());
    let snapshot = env.root.path().join("snapshot").join("store.db");
    env.approved(1);
    s.run(Task::Checkpoint, NOW).unwrap();
    env.store().backup_to(&snapshot).unwrap();
    // More spend, exported and checkpointed, then the operator restores the
    // older copy.
    env.approved(2);
    s.run(Task::Checkpoint, NOW).unwrap();
    let older = SqliteStore::open(&snapshot).unwrap();
    let parts = Parts {
        store: &older,
        ..env.p.w.parts()
    };
    let s2 = Scheduler::new(
        parts,
        ScheduleConfig::default(),
        env.log.clone(),
        degraded.clone(),
    );
    let r = s2.run(Task::StartupCheck, NOW);
    assert_eq!(r, Err("store_rolled_back"));
    assert!(degraded.is_set());
    assert!(
        older.needs_reconcile().unwrap(),
        "the write block is persisted"
    );
}

/// A signer that cannot be reached.
struct DeadSigner(custodian_contracts::types::KeyId);

impl Signer for DeadSigner {
    fn key_id(&self) -> &custodian_contracts::types::KeyId {
        &self.0
    }
    fn sign(&self, _: &ApprovedPayload) -> Result<Signature, SignRefusal> {
        Err(SignRefusal::SignerUnavailable)
    }
    fn liveness(&self) -> Result<(), SignRefusal> {
        Err(SignRefusal::SignerUnavailable)
    }
}

#[test]
fn signer_liveness_reports_a_dead_signer_with_a_fixed_word() {
    let env = Env::new(3);
    let s = sched(&env, Degraded::new());
    assert_eq!(s.run(Task::SignerLiveness, NOW), Ok(()));
    let dead = DeadSigner(env.p.w.key.signer.key_id().clone());
    let parts = Parts {
        signer: &dead,
        ..env.p.w.parts()
    };
    let s2 = Scheduler::new(
        parts,
        ScheduleConfig::default(),
        env.log.clone(),
        Degraded::new(),
    );
    assert_eq!(s2.run(Task::SignerLiveness, NOW), Err("signer_unavailable"));
    // With the signer dead the export cannot run either, and says so.
    env.approved(1);
    assert_eq!(s2.run(Task::Export, NOW), Err("signer_unavailable"));
    assert!(env.store().outbox_pending_count().unwrap() > 0);
}
