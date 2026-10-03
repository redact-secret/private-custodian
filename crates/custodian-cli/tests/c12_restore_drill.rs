//! C12 backup/restore drill, automated against synthetic data.
//!
//! The drill restores an older database than the private ledger knows and
//! proves: no double execution, no double charge, no republishing of revoked
//! evidence, `startup_check` refusal, the `clear-reconcile` path, and the one
//! residual window (spend after the last export and backup is not detectable).
//! Backups are taken with the store's own `backup_to`, never by copying a live
//! file. Synthetic data and test-generated keys only; project-maintained
//! evidence, not independent validation.

mod c12;

use c12::*;
use custodian_cli::command::{Contaminated, RepairCommand, VerifyTarget};
use custodian_cli::{CliReason, Command, Service};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_disclosure::{EligibilitySubject, ReleaseEligibility};
use custodian_lifecycle::LifecycleEligibility;
use custodian_store::SqliteStore;

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn clear_cmd(p: &Pipe) -> Command {
    let seq = p.w.rw.store.latest_checkpoint().unwrap().unwrap().seq;
    Command::Repair(RepairCommand::ClearReconcile {
        confirm_store_id: p.w.rw.store.store_id().unwrap(),
        confirm_checkpoint_seq: seq,
    })
}

/// Run request `n` to completion and export, so the ledger holds its terminal
/// event and a store checkpoint.
fn spend(p: &Pipe, n: u32) {
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let (attempt, _) = p.reserve(n);
    let rep = p.dispatch(&svc, n, &attempt).unwrap();
    assert_eq!(rep.outcome, O::Success);
    assert_eq!(code(&p.export()), "exported");
}

#[test]
fn restoring_a_database_older_than_the_ledger_cannot_double_spend_or_republish() {
    let mut p = Pipe::new(5, 10);
    spend(&p, 1);
    // Backup B0: taken after request 1 is exported and checkpointed.
    let b0 = p.w.rw.db.dir().join("b0.db");
    p.w.rw.store.backup_to(&b0).unwrap();

    // Later: request 2 runs and is exported; the epoch is then declared
    // exposed and the feed publishes the revocation. The ledger is ahead of B0.
    spend(&p, 2);
    let newer_path = p.w.rw.db.path();
    p.w.clock.set(NOW + 500);
    let rep = p.w.run(
        Who::Operator,
        &Command::LifecycleReport {
            epoch: p.w.rw.epoch.clone(),
            kind: Contaminated::Exposed,
            reason: "results_exposed".into(),
            key: lc::idk(7),
        },
    );
    assert!(rep.is_ok(), "{}", rep.code());
    assert_eq!(
        code(&p.w.run(Who::Operator, &Command::FeedPublish)),
        "published"
    );
    assert_eq!(code(&p.export()), "exported");
    let spent_before = p.w.budget();
    assert_eq!((spent_before.consumed, spent_before.held), (2, 0));
    let runs_before = p.sandbox.runs();
    assert_eq!(runs_before, 2);

    // Disaster: only the older copy survives.
    p.w.rw.store = SqliteStore::open(&b0).unwrap();
    assert_eq!(
        p.w.budget().consumed,
        1,
        "the restored store understates spending"
    );

    // 1. startup_check refuses before anything writes, and persists the block.
    {
        let acts = p.activations();
        let err = Service::start(p.w.parts(), &startup_config(), &acts)
            .err()
            .unwrap();
        assert_eq!(
            (err.step, err.reason),
            ("startup_check", CliReason::StoreRolledBack)
        );
    }
    assert!(p.w.rw.store.needs_reconcile().unwrap());

    // 2. No double charge, no double execution: a redelivery of request 2 and
    //    a brand-new request are both refused; nothing runs; nothing is spent.
    assert_eq!(code(&p.submit(2)), "store_needs_reconcile");
    assert_eq!(code(&p.submit(3)), "store_needs_reconcile");
    assert_eq!(code(&p.approve(2)), "store_needs_reconcile");
    assert_eq!(p.sandbox.runs(), runs_before);
    assert_eq!(
        p.w.budget().consumed,
        1,
        "nothing was written to the restored store"
    );

    // 3. No republishing of revoked evidence: the restored store does not even
    //    know about the exposure, yet eligibility is closed while it awaits
    //    reconciliation, so a release of request 1's evidence cannot go out.
    let (req1, _) = p.request(1);
    let elig = LifecycleEligibility::new(&p.w.rw.store);
    let refusal = elig
        .check(
            &EligibilitySubject {
                candidate: &req1.plan.candidate,
                population: &req1.plan.population,
                execution: &custodian_contracts::types::ExecutionId::parse(&cc::id("exe_", 1))
                    .unwrap(),
                projection: &custodian_contracts::types::ProjectionDigest::from_raw([0u8; 32]),
            },
            ts(RELEASE_AT),
        )
        .unwrap_err();
    assert_eq!(format!("{refusal:?}"), "Unknown");

    // 4. The audited clear is refused: the store is behind the ledger, and no
    //    confirmation changes that.
    let o = p.w.run(Who::Operator, &clear_cmd(&p));
    assert_eq!((code(&o), o.exit_code()), ("store_behind_ledger", 5));
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    let v = p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::Checkpoint));
    assert_eq!(code(&v), "store_rolled_back");

    // 5. The write block also stops the epoch-level repair that
    //    docs/operator-runbook.md section 6.3 used to name for the
    //    no-newer-copy case: it is refused, not executable. This is recorded
    //    as register entry G-R1 in docs/release-readiness.md.
    let retire = Command::LifecycleRetire {
        epoch: p.w.rw.epoch.clone(),
        confirm_epoch: p.w.rw.epoch.clone(),
        reason: "operator_decision".into(),
        key: lc::idk(8),
    };
    let r = p.w.run(Who::Operator, &retire);
    assert_eq!((code(&r), r.exit_code()), ("store_needs_reconcile", 8));

    // 6. The way out is a newer copy: reopen the surviving up-to-date file.
    drop(std::mem::replace(
        &mut p.w.rw.store,
        SqliteStore::open(&newer_path).unwrap(),
    ));
    // The newer copy was never blocked (only the restored one was).
    assert!(!p.w.rw.store.needs_reconcile().unwrap());
    let b = p.w.budget();
    assert_eq!(
        (b.consumed, b.held, b.refunded),
        (2, 0, 0),
        "no spend lost or double counted"
    );
    // Replaying request 2 charges nothing and runs nothing.
    let again = p.submit(2);
    assert!(!again.is_ok());
    assert_eq!(p.sandbox.runs(), runs_before);
    assert_eq!(p.w.budget().consumed, 2);
    // The contamination is in force: new use is refused.
    assert_eq!(code(&p.submit(3)), "epoch_blocked");
    let acts = p.activations();
    p.start(&acts).expect("the newer copy starts cleanly");
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified"
    );
}

#[test]
fn a_contained_restore_is_cleared_only_by_the_audited_exact_confirmation() {
    let mut p = Pipe::new(5, 10);
    spend(&p, 1);
    let b1 = p.w.rw.db.dir().join("b1.db");
    p.w.rw.store.backup_to(&b1).unwrap();
    // The backup is as sensitive as the database: owner-only.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&b1).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "backup file is owner-only");
    }
    // Restore it. It holds the ledger's newest checkpoint: contained.
    p.w.rw.store = SqliteStore::open(&b1).unwrap();
    p.w.rw.store.integrity_check().unwrap();
    {
        let acts = p.activations();
        p.start(&acts)
            .expect("a contained restore passes startup_check");
    }
    // A write block left over from an earlier refusal (here set by hand, as
    // `startup_check` does on an untrusted ledger).
    p.w.rw.store.block_for_reconcile().unwrap();
    assert_eq!(code(&p.submit(2)), "store_needs_reconcile");
    {
        let acts = p.activations();
        let err = Service::start(p.w.parts(), &startup_config(), &acts)
            .err()
            .unwrap();
        assert_eq!(err.reason, CliReason::StoreNeedsReconcile);
    }
    // Exact confirmations, human operator only; a dry run writes nothing.
    let good = clear_cmd(&p);
    assert_eq!(code(&p.w.run(Who::Approver, &good)), "forbidden");
    assert_eq!(code(&p.w.run(Who::Agent, &good)), "agent_not_permitted");
    let sid = p.w.rw.store.store_id().unwrap();
    let wrong = Command::Repair(RepairCommand::ClearReconcile {
        confirm_store_id: sid,
        confirm_checkpoint_seq: 999,
    });
    assert_eq!(
        code(&p.w.run(Who::Operator, &wrong)),
        "confirmation_mismatch"
    );
    assert_eq!(code(&p.w.dry(Who::Operator, &good)), "would_clear");
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    let before = p.w.budget();
    assert_eq!(code(&p.w.run(Who::Operator, &good)), "cleared");
    assert!(!p.w.rw.store.needs_reconcile().unwrap());
    // Clearing is itself an audited event naming the operator; budgets are
    // exactly what they were.
    let ev = p
        .w
        .rw
        .store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "store.reconciled")
        .expect("audited");
    assert!(ev.payload.contains(&Who::Operator.actor()));
    let after = p.w.budget();
    assert_eq!(
        (before.limit, before.held, before.consumed, before.refunded),
        (after.limit, after.held, after.consumed, after.refunded)
    );
    assert_eq!(code(&p.export()), "exported");
    assert!(p.submit(2).is_ok(), "writes resume");
    p.w.rw.store.verify_invariants().unwrap();
}

#[test]
fn spend_after_the_last_export_is_the_documented_unrecoverable_window() {
    // Residual risk, stated plainly: the ledger can only detect a rollback of
    // what it was told. Spend recorded in the database but not yet exported
    // is invisible to every check, so restoring a backup that predates it is
    // not refused, and the lost spend can be spent again. The mitigation is
    // operational (export after each approval, back up at least as often as
    // exporting); this test pins both halves. Register entry G-R2.
    let mut p = Pipe::new(5, 10);
    spend(&p, 1);
    let b = p.w.rw.db.dir().join("window.db");
    p.w.rw.store.backup_to(&b).unwrap();

    // Request 2 is approved and run, but never exported before the loss.
    {
        let acts = p.activations();
        let svc = p.start(&acts).unwrap();
        let (attempt, _) = p.reserve(2);
        assert_eq!(p.dispatch(&svc, 2, &attempt).unwrap().outcome, O::Success);
    }
    assert!(
        p.w.rw.store.outbox_pending_count().unwrap() > 0,
        "spend is still unexported"
    );
    assert_eq!(p.sandbox.runs(), 2);

    // Loss: the restore is not refused (the ledger knows nothing newer) ...
    p.w.rw.store = SqliteStore::open(&b).unwrap();
    {
        let acts = p.activations();
        p.start(&acts)
            .expect("undetectable: the ledger never saw request 2");
    }
    assert_eq!(p.w.budget().consumed, 1, "request 2's spend is gone");
    // ... and the same request can run again: a second execution and a
    // second charge for what was one approved request.
    let (attempt, _) = p.reserve(2);
    {
        let acts = p.activations();
        let svc = p.start(&acts).unwrap();
        assert_eq!(p.dispatch(&svc, 2, &attempt).unwrap().outcome, O::Success);
    }
    assert_eq!(p.sandbox.runs(), 3, "RPO window: executed twice");

    // Mitigation: when the approval was exported before the loss, the same
    // restore is refused instead.
    let mut q = Pipe::new(5, 10);
    spend(&q, 1);
    let b = q.w.rw.db.dir().join("window.db");
    q.w.rw.store.backup_to(&b).unwrap();
    let (_attempt, _) = q.reserve(2);
    assert_eq!(code(&q.export()), "exported", "export right after approval");
    q.w.rw.store = SqliteStore::open(&b).unwrap();
    let acts = q.activations();
    let err = Service::start(q.w.parts(), &startup_config(), &acts)
        .err()
        .unwrap();
    assert_eq!(err.reason, CliReason::StoreRolledBack);
    assert_eq!(q.sandbox.runs(), 1);
}
