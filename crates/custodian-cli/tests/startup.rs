//! Startup wiring and the restore/outage behavior of the control plane (C10).
//! Synthetic only.

mod common;

use std::sync::Arc;

use common::*;
use custodian_cli::command::{
    ReconcileTarget, RepairCommand, RevocationKind, RevocationVerb, VerifyTarget,
};
use custodian_cli::{CliReason, Command, Service, StartupConfig, StoreActivations};
use custodian_contracts::common::PolicyRef;
use custodian_contracts::types::{CandidateDigest, EpochId, Timestamp};
use custodian_core::{ActorId, RunId};
use custodian_ledger::Exporter;
use custodian_store::{SqliteStore, StoreError};
use custodian_worker::ports::{RunLedger, StoreRunLedger};
use custodian_worker::reason::WorkerReason;

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn config() -> StartupConfig {
    StartupConfig {
        guarded_policies: vec![
            serde_json::from_value::<PolicyRef>(cc::disclosure_policy()).unwrap()
        ],
        required_activations: vec![cc::request().plan.policy_activation.clone()],
        activation_max_age_secs: 300,
    }
}

fn export_cmd(w: &World) -> Command {
    Command::Repair(RepairCommand::Export {
        confirm_store_id: w.rw.store.store_id().unwrap(),
    })
}

// ---- outage and restore ------------------------------------------------------------

#[test]
fn a_ledger_outage_refuses_every_mutation_and_changes_nothing() {
    let w = World::new(2);
    w.ledger.set_available(false);
    let o = w.submit(Who::Requester, 1);
    assert_eq!(code(&o), "ledger_unavailable");
    assert_eq!(o.exit_code(), 7);
    assert_eq!(w.rw.store.submission(&cc::id("req_", 1)).unwrap(), None);
    // Reads of the ledger are unavailable too; the store itself is not blocked.
    assert_eq!(
        code(&w.run(Who::Auditor, &Command::Verify(VerifyTarget::Ledger))),
        "ledger_unavailable"
    );
    assert!(!w.rw.store.needs_reconcile().unwrap());
    w.ledger.set_available(true);
    assert_eq!(code(&w.submit(Who::Requester, 1)), "submitted");
}

#[test]
fn a_restored_older_store_blocks_writes_and_no_flag_can_clear_it() {
    let mut w = World::new(5);
    w.submit(Who::Requester, 1);
    assert!(w.approve(Who::Approver, 1).is_ok());
    assert_eq!(code(&w.run(Who::Operator, &export_cmd(&w))), "exported");
    // A backup taken now, then more spending, then a later export.
    let backup = w.rw.db.dir().join("backup.db");
    w.rw.store.backup_to(&backup).unwrap();
    w.submit(Who::Requester, 2);
    assert!(w.approve(Who::Approver, 2).is_ok());
    assert_eq!(code(&w.run(Who::Operator, &export_cmd(&w))), "exported");
    assert_eq!(w.budget().held, 2);

    // Restore the older copy: it lacks the second reservation.
    let newer_path = w.rw.db.path();
    w.rw.store = SqliteStore::open(&backup).unwrap();
    assert_eq!(
        w.budget().held,
        1,
        "the restored store understates spending"
    );

    let o = w.submit(Who::Requester, 3);
    assert_eq!(code(&o), "store_rolled_back");
    assert_eq!(o.exit_code(), 8);
    // The block is persisted: every later write is refused, whoever asks.
    assert!(w.rw.store.needs_reconcile().unwrap());
    assert_eq!(code(&w.approve(Who::Approver, 2)), "store_needs_reconcile");
    use custodian_intake::ports::DeliveryStore;
    assert_eq!(
        w.rw.store.claim(
            &custodian_intake::ids::DeliveryId::parse("00000000-0000-4000-8000-000000000001")
                .unwrap()
        ),
        Err(custodian_intake::IntakeReason::StoreUnavailable)
    );
    assert_eq!(w.budget().held, 1, "nothing was written");
    // verify reports it with fixed codes.
    let v = w.run(Who::Auditor, &Command::Verify(VerifyTarget::Checkpoint));
    assert_eq!(code(&v), "store_rolled_back");
    assert_eq!(v.field("store_checkpoint").unwrap(), "behind_ledger");

    // The audited clear is refused: the store is behind the ledger. No
    // confirmation makes it succeed, and no command raises a count.
    let local = w.rw.store.latest_checkpoint().unwrap().unwrap().seq;
    let clear = Command::Repair(RepairCommand::ClearReconcile {
        confirm_store_id: w.rw.store.store_id().unwrap(),
        confirm_checkpoint_seq: local,
    });
    let o = w.run(Who::Operator, &clear);
    assert_eq!(code(&o), "store_behind_ledger");
    assert_eq!(o.exit_code(), 5);
    assert!(w.rw.store.needs_reconcile().unwrap());

    // The way out is a newer copy, not a flag: reopen the up-to-date store.
    drop(std::mem::replace(
        &mut w.rw.store,
        SqliteStore::open(&newer_path).unwrap(),
    ));
    assert!(!w.rw.store.needs_reconcile().unwrap());
    assert_eq!(w.budget().held, 2);
    assert_eq!(code(&w.submit(Who::Requester, 3)), "submitted");
}

#[test]
fn an_untrusted_ledger_persists_the_block_and_clearing_needs_exact_confirmations() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    assert_eq!(code(&w.run(Who::Operator, &export_cmd(&w))), "exported");

    w.ledger.inject("records/audit/zz-forged.json", b"{}");
    let o = w.submit(Who::Requester, 2);
    assert_eq!(code(&o), "ledger_untrusted");
    assert_eq!(o.exit_code(), 8);
    assert!(w.rw.store.needs_reconcile().unwrap());

    let local = w.rw.store.latest_checkpoint().unwrap().unwrap().seq;
    let sid = w.rw.store.store_id().unwrap();
    let clear = |sid: &str, seq: u64| {
        Command::Repair(RepairCommand::ClearReconcile {
            confirm_store_id: sid.to_owned(),
            confirm_checkpoint_seq: seq,
        })
    };
    // Still untrusted: refused.
    assert_eq!(
        code(&w.run(Who::Operator, &clear(&sid, local))),
        "ledger_untrusted"
    );
    // The ledger is repaired out of band (here: the forged file is removed).
    w.ledger.remove("records/audit/zz-forged.json");
    // Writes stay blocked until a human clears.
    assert_eq!(code(&w.submit(Who::Requester, 2)), "store_needs_reconcile");

    for (who, cmd, expect) in [
        (Who::Approver, clear(&sid, local), "forbidden"),
        (Who::Service, clear(&sid, local), "automation_not_permitted"),
        (Who::Agent, clear(&sid, local), "agent_not_permitted"),
        (
            Who::Operator,
            clear("0123456789abcdef", local),
            "confirmation_mismatch",
        ),
        (
            Who::Operator,
            clear(&sid, local + 1),
            "confirmation_mismatch",
        ),
    ] {
        assert_eq!(code(&w.run(who, &cmd)), expect, "{who:?}");
        assert!(w.rw.store.needs_reconcile().unwrap());
    }
    assert_eq!(
        code(&w.dry(Who::Operator, &clear(&sid, local))),
        "would_clear"
    );
    assert!(w.rw.store.needs_reconcile().unwrap());
    let o = w.run(Who::Operator, &clear(&sid, local));
    assert_eq!(code(&o), "cleared");
    assert_eq!(o.field("was_blocked").unwrap(), true);
    assert!(!w.rw.store.needs_reconcile().unwrap());
    // The clearing is itself audited, with the operator as actor.
    let ev =
        w.rw.store
            .outbox_pending(1000)
            .unwrap()
            .into_iter()
            .find(|e| e.kind == "store.reconciled")
            .expect("audited");
    assert!(ev.payload.contains(&Who::Operator.actor()));
    // History and budgets are exactly what they were; writes resume.
    assert_eq!(w.budget().held, 0);
    assert_eq!(code(&w.submit(Who::Requester, 2)), "submitted");
}

// ---- Service::start ------------------------------------------------------------------

#[test]
fn startup_runs_the_checks_then_recover_sweep_delivery_and_export_in_order() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    assert!(w.approve(Who::Approver, 1).is_ok());
    // A reservation that lapsed while the service was down.
    w.clock.set(NOW + 5_000);
    // A permanent contamination recorded in the store but not yet mirrored
    // into the registry (a crash between the two).
    w.rw.store
        .apply_epoch_change(&custodian_store::EpochEventCommand {
            epoch_id: w.rw.epoch.as_str(),
            corpus_id: lc::CORPUS,
            family_id: None,
            idempotency_key: "c10-startup-exposed",
            change: custodian_core::EpochChange::Report(custodian_core::Contamination::Exposed),
            reason: "results_exposed",
            actor: lc::HUMAN,
            actor_kind: "human",
            authorization_ref: "apr_synthetic000000000009",
            now: NOW + 10,
        })
        .unwrap();
    // A revocation obligation published but not delivered (destination down).
    let record = Command::FeedRecordRevocation {
        id: "synthetic-startup-1".into(),
        what: RevocationKind::Candidate(CandidateDigest::parse(&cc::dg("synthetic-bad")).unwrap()),
        verb: RevocationVerb::Revoked,
        reason: "error_correction".into(),
    };
    // (the epoch is retired in the store only, so the registry is still active)
    assert_eq!(code(&w.run(Who::Operator, &record)), "recorded");
    w.feed.set_unavailable(true);
    let p = w.run(Who::Operator, &Command::FeedPublish);
    assert_eq!(code(&p), "destination_unavailable");
    assert_eq!(p.exit_code(), 7);
    w.feed.set_unavailable(false);
    assert!(w.feed.sequences(&lc::feed_id()).is_empty());

    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let svc = Service::start(w.parts(), &config(), &acts).unwrap();
    assert_eq!(
        svc.recovery.expired_unstarted.len(),
        1,
        "lapsed reservation"
    );
    assert_eq!(svc.registry_retired, 1, "registry mirrors the store");
    assert_eq!(svc.feed_delivered, 1, "committed envelope delivered");
    assert_eq!(w.feed.sequences(&lc::feed_id()), vec![1]);
    assert_eq!(
        svc.export_status,
        custodian_ledger::ExportStatus::Drained,
        "outbox exported"
    );
    // Unstarted reservation: refunded, never consumed.
    let b = w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 1));
    // The ledger now holds the audit trail and both checkpoints.
    assert!(w.ledger.file_count() > 3);
    assert_eq!(
        code(&w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified"
    );
    assert_eq!(
        w.rw.fx.pop.state(&w.rw.epoch).unwrap(),
        custodian_corpus::EpochState::Retired
    );
}

#[test]
fn startup_refuses_before_writing_when_the_store_is_older_than_the_ledger() {
    let mut w = World::new(5);
    w.submit(Who::Requester, 1);
    w.approve(Who::Approver, 1);
    w.run(Who::Operator, &export_cmd(&w));
    let backup = w.rw.db.dir().join("older.db");
    w.rw.store.backup_to(&backup).unwrap();
    w.submit(Who::Requester, 2);
    w.approve(Who::Approver, 2);
    w.run(Who::Operator, &export_cmd(&w));
    w.rw.store = SqliteStore::open(&backup).unwrap();
    // A reservation in the older copy that `recover` would settle.
    w.clock.set(NOW + 9_000);
    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let err = Service::start(w.parts(), &config(), &acts).err().unwrap();
    assert_eq!(err.step, "startup_check");
    assert_eq!(err.reason, CliReason::StoreRolledBack);
    // Nothing was recovered: the check came before the first write.
    let att =
        w.rw.store
            .latest_attempt_of(&cc::id("req_", 1))
            .unwrap()
            .unwrap();
    assert_eq!(att.state, custodian_core::RunState::Reserved);
    assert!(w.rw.store.needs_reconcile().unwrap());
    // A second start is refused too (the block is persisted).
    let err = Service::start(w.parts(), &config(), &acts).err().unwrap();
    assert_eq!(err.reason, CliReason::StoreNeedsReconcile);
}

#[test]
fn there_is_no_way_to_start_without_the_startup_check() {
    // The only constructor of a Service is `Service::start`, which runs the
    // check; a Service has private fields, so it cannot be built any other
    // way. This test pins the observable half: a ledger that cannot be read
    // refuses startup.
    let w = World::new(1);
    w.ledger.set_available(false);
    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let err = Service::start(w.parts(), &config(), &acts).err().unwrap();
    assert_eq!(
        (err.step, err.reason),
        ("startup_check", CliReason::LedgerUnavailable)
    );
}

#[test]
fn every_run_ledger_is_guarded_by_the_one_shared_eligibility() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    let o = w.approve(Who::Approver, 1);
    let attempt = RunId::new(o.field("attempt_id").unwrap().as_str().unwrap().to_owned());
    let (req, _) = w.request(1);

    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let svc = Service::start(w.parts(), &config(), &acts).unwrap();
    let inner = || {
        StoreRunLedger::new(
            &w.rw.store,
            attempt.clone(),
            "worker-synthetic-1",
            ActorId::new("act_syntheticworker00001"),
            300,
            300,
            Arc::new(|| NOW + 1),
            Arc::new(|| Some(cc::observed(cc::activation(), NOW + 1))),
        )
    };

    // A recorded revocation of this candidate stops dispatch even though the
    // store's own epoch gate knows nothing about it.
    let record = Command::FeedRecordRevocation {
        id: "synthetic-guard-1".into(),
        what: RevocationKind::Candidate(req.plan.candidate.clone()),
        verb: RevocationVerb::Revoked,
        reason: "error_correction".into(),
    };
    assert_eq!(code(&w.run(Who::Operator, &record)), "recorded");
    let guarded = svc.guard_run_ledger(
        inner(),
        req.plan.candidate.clone(),
        req.plan.population.epoch_id.clone(),
    );
    assert_eq!(guarded.start(), Err(WorkerReason::EligibilityDenied));
    assert_eq!(
        guarded.record_exposure(),
        Err(WorkerReason::EligibilityDenied)
    );
    // The attempt is still reserved: the guard refused before the store call.
    assert_eq!(
        w.rw.store.attempt(&attempt).unwrap().unwrap().state,
        custodian_core::RunState::Reserved
    );
    // Without the guard the store would have started it. That is the gap the
    // guard closes, and why no RunLedger is handed out unwrapped.
    assert!(inner().start().is_ok());
}

#[test]
fn a_contaminated_epoch_is_refused_by_the_guard_and_by_the_shared_eligibility() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    let o = w.approve(Who::Approver, 1);
    let attempt = RunId::new(o.field("attempt_id").unwrap().as_str().unwrap().to_owned());
    let (req, _) = w.request(1);
    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let svc = Service::start(w.parts(), &config(), &acts).unwrap();
    let now = Timestamp::new(NOW + 1).unwrap();
    assert!(svc
        .eligibility()
        .evaluate(&req.plan.candidate, &req.plan.population.epoch_id, now)
        .is_ok());
    let r = w.run(
        Who::Operator,
        &Command::LifecycleReport {
            epoch: req.plan.population.epoch_id.clone(),
            kind: custodian_cli::command::Contaminated::Exposed,
            reason: "results_exposed".into(),
            key: idk(1),
        },
    );
    assert_eq!(code(&r), "reported");
    let guarded = svc.guard_run_ledger(
        StoreRunLedger::new(
            &w.rw.store,
            attempt,
            "worker-synthetic-1",
            ActorId::new("act_syntheticworker00001"),
            300,
            300,
            Arc::new(|| NOW + 1),
            Arc::new(|| Some(cc::observed(cc::activation(), NOW + 1))),
        ),
        req.plan.candidate.clone(),
        req.plan.population.epoch_id.clone(),
    );
    assert_eq!(guarded.start(), Err(WorkerReason::EligibilityDenied));
    assert_eq!(
        svc.eligibility()
            .evaluate(&req.plan.candidate, &req.plan.population.epoch_id, now)
            .err(),
        Some(custodian_disclosure::EligibilityRefusal::Contaminated)
    );
}

#[test]
fn a_revoked_or_superseded_activation_fails_the_shared_gate_through_the_real_store() {
    let w = World::new(1);
    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let svc = Service::start(w.parts(), &config(), &acts).unwrap();
    let (req, _) = w.request(1);
    let epoch: EpochId = req.plan.population.epoch_id.clone();
    let now = Timestamp::new(NOW).unwrap();
    assert!(svc
        .eligibility()
        .evaluate(&req.plan.candidate, &epoch, now)
        .is_ok());
    let mut v = serde_json::to_value(cc::activation()).unwrap();
    v["sequence"] = serde_json::json!(4);
    v["status"] = serde_json::json!("revoked");
    use custodian_contracts::Contract;
    let revoked =
        custodian_contracts::policy::PolicyActivation::decode(&serde_json::to_vec(&v).unwrap())
            .unwrap();
    w.rw.store
        .record_activation(&revoked, &sc::actor(), NOW)
        .unwrap();
    assert_eq!(
        svc.eligibility()
            .evaluate(&req.plan.candidate, &epoch, now)
            .err(),
        Some(custodian_disclosure::EligibilityRefusal::Revoked)
    );
    // An activation the store has never seen cannot be observed: unknown.
    let unknown = cc::request().plan.policy_activation.clone();
    let mut other = unknown;
    other.activation_id =
        custodian_contracts::types::ActivationId::parse(&cc::id("pac_", 42)).unwrap();
    use custodian_lifecycle::ActivationSource;
    assert!(acts.observe(&other).is_none());
}

#[test]
fn the_feed_reference_follows_publication_and_the_disclosure_service_shares_the_gate() {
    let w = World::new(1);
    let acts = StoreActivations::new(&w.rw.store, w.clock.clone());
    let svc = Service::start(w.parts(), &config(), &acts).unwrap();
    // No envelope yet.
    assert_eq!(svc.feed_ref().err(), Some(CliReason::NotConfigured));
    let record = Command::FeedRecordRevocation {
        id: "synthetic-feed-1".into(),
        what: RevocationKind::Candidate(CandidateDigest::parse(&cc::dg("synthetic-bad")).unwrap()),
        verb: RevocationVerb::Contaminated,
        reason: "contamination".into(),
    };
    assert_eq!(code(&w.run(Who::Operator, &record)), "recorded");
    // A projection must not point at a feed that is missing a known revocation.
    assert_eq!(svc.feed_ref().err(), Some(CliReason::PendingObligations));
    assert_eq!(
        code(&w.run(Who::Operator, &Command::FeedPublish)),
        "published"
    );
    let fr = svc.feed_ref().unwrap();
    assert_eq!(fr.min_sequence.get(), 1);
    assert_eq!(fr.feed_id, lc::feed_id());

    // The disclosure service is built over the same eligibility object.
    let walk = custodian_ledger::walk_ledger(&w.ledger, &w.roots).unwrap();
    let verifier = custodian_ledger::Verifier::new(walk.keyring);
    let exporter = Exporter::new(&w.ledger, &w.key.signer, &verifier);
    let names = w.rw.names();
    let ds = svc.disclosure_service(&w.rw.store, &exporter, &names);
    let a = ds.eligibility as *const dyn custodian_disclosure::ReleaseEligibility as *const u8;
    let b = svc.eligibility() as *const _ as *const u8;
    assert_eq!(a, b);
}

#[test]
fn reconcile_diagnoses_without_writing_and_names_the_store_for_repair() {
    let w = World::new(1);
    let r = w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Store));
    assert_eq!(code(&r), "consistent");
    assert_eq!(r.field("needs_reconcile").unwrap(), false);
    assert_eq!(
        r.field("store_checkpoint_seq").unwrap(),
        &serde_json::json!(w.rw.store.latest_checkpoint().unwrap().unwrap().seq)
    );
    let before = w.rw.store.latest_checkpoint().unwrap();
    for t in [
        ReconcileTarget::Store,
        ReconcileTarget::Ledger,
        ReconcileTarget::Feed,
    ] {
        w.run(Who::Auditor, &Command::Reconcile(t));
    }
    assert_eq!(w.rw.store.latest_checkpoint().unwrap(), before);
    assert_eq!(w.ledger.file_count(), 0);
    let _ = StoreError::Busy;
}
