//! S6 (ADR 0130): the executable restore procedure for the case the C12
//! drill could not resolve (R-1): a store restored from a backup older than
//! the private ledger's checkpoint, with no newer copy anywhere.
//!
//! Every test uses synthetic data and test-generated keys. A passing run is
//! functional verification on public synthetic data, not an independent
//! protected evaluation.

mod c12;

use c12::*;
use custodian_cli::command::{Contaminated, RepairCommand, VerifyTarget, LOSS_ACKNOWLEDGEMENT};
use custodian_cli::{CliReason, Command, Service};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_store::SqliteStore;
use serde_json::Value;

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn text(o: &custodian_cli::Output, key: &str) -> String {
    o.field(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn num(o: &custodian_cli::Output, key: &str) -> u64 {
    o.field(key).and_then(Value::as_u64).unwrap_or(u64::MAX)
}

fn spend(p: &Pipe, n: u32) {
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let (attempt, _) = p.reserve(n);
    assert_eq!(p.dispatch(&svc, n, &attempt).unwrap().outcome, O::Success);
    assert_eq!(code(&p.export()), "exported");
}

fn plan_cmd(p: &Pipe) -> Command {
    Command::Repair(RepairCommand::LossPlan {
        confirm_store_id: p.w.rw.store.store_id().unwrap(),
    })
}

struct Accept {
    store_seq: u64,
    ledger_seq: u64,
    chain: String,
    digest: String,
    ack: String,
}

fn accept_cmd(p: &Pipe, a: &Accept) -> Command {
    Command::Repair(RepairCommand::AcceptLoss {
        confirm_store_id: p.w.rw.store.store_id().unwrap(),
        confirm_store_seq: a.store_seq,
        confirm_ledger_seq: a.ledger_seq,
        confirm_ledger_chain: a.chain.clone(),
        confirm_plan_digest: a.digest.clone(),
        acknowledge: a.ack.clone(),
    })
}

/// The disaster of `restoring_a_database_older_than_the_ledger...`: request 1
/// is backed up, request 2 runs and is exported, the epoch is exposed and the
/// feed publishes, then only the old backup survives. Returns the pipe with
/// the restored (blocked) store in place and the request-2 spend count.
fn disaster() -> (Pipe, u32) {
    let mut p = Pipe::new(5, 10);
    spend(&p, 1);
    let b0 = p.w.rw.db.dir().join("b0.db");
    p.w.rw.store.backup_to(&b0).unwrap();
    spend(&p, 2);
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
    let runs = p.sandbox.runs();
    p.w.rw.store = SqliteStore::open(&b0).unwrap();
    let acts = p.activations();
    let err = Service::start(p.w.parts(), &startup_config(), &acts)
        .err()
        .unwrap();
    assert_eq!(err.reason, CliReason::StoreRolledBack);
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    (p, runs)
}

#[test]
fn the_previously_blocking_restore_is_recovered_by_an_explicit_audited_acceptance() {
    let (p, runs) = disaster();
    assert_eq!(
        p.w.budget().consumed,
        1,
        "the restored store understates spending"
    );

    // The old dead ends are still dead ends: nothing but the new path helps.
    let clear = Command::Repair(RepairCommand::ClearReconcile {
        confirm_store_id: p.w.rw.store.store_id().unwrap(),
        confirm_checkpoint_seq: p.w.rw.store.latest_checkpoint().unwrap().unwrap().seq,
    });
    assert_eq!(code(&p.w.run(Who::Operator, &clear)), "store_behind_ledger");
    assert_eq!(code(&p.submit(3)), "store_needs_reconcile");

    // The plan is read-only, but it is part of the repair group: operators
    // only. Auditors, requesters and agents cannot run it.
    assert_eq!(code(&p.w.run(Who::Auditor, &plan_cmd(&p))), "forbidden");
    let plan = p.w.run(Who::Operator, &plan_cmd(&p));
    assert_eq!(code(&plan), "planned", "{}", plan.render());
    assert_eq!(code(&p.w.run(Who::Requester, &plan_cmd(&p))), "forbidden");
    assert_eq!(
        code(&p.w.run(Who::Agent, &plan_cmd(&p))),
        "agent_not_permitted"
    );
    assert!(num(&plan, "events_to_adopt") > 0);
    assert_eq!(num(&plan, "units_to_recover"), 1);
    assert_eq!(num(&plan, "epochs_affected"), 1);
    assert_eq!(num(&plan, "epochs_to_retire"), 1);
    assert!(
        p.w.rw.store.needs_reconcile().unwrap(),
        "plan wrote nothing"
    );
    assert_eq!(p.w.budget().consumed, 1);

    let good = Accept {
        store_seq: p.w.rw.store.latest_checkpoint().unwrap().unwrap().seq,
        ledger_seq: num(&plan, "ledger_seq"),
        chain: text(&plan, "ledger_chain"),
        digest: text(&plan, "plan_digest"),
        ack: LOSS_ACKNOWLEDGEMENT.to_owned(),
    };

    // Exact confirmations, human operator only, and the loss is acknowledged
    // in words. Every refusal changes nothing.
    let refuse = |a: &Accept, who: Who| code(&p.w.run(who, &accept_cmd(&p, a)));
    assert_eq!(refuse(&good, Who::Approver), "forbidden");
    assert_eq!(refuse(&good, Who::Agent), "agent_not_permitted");
    assert_eq!(refuse(&good, Who::Requester), "forbidden");
    let mut bad = Accept {
        ack: "yes".into(),
        ..clone_accept(&good)
    };
    assert_eq!(refuse(&bad, Who::Operator), "confirmation_mismatch");
    bad = Accept {
        store_seq: good.store_seq + 1,
        ..clone_accept(&good)
    };
    assert_eq!(refuse(&bad, Who::Operator), "confirmation_mismatch");
    bad = Accept {
        ledger_seq: good.ledger_seq + 1,
        ..clone_accept(&good)
    };
    assert_eq!(refuse(&bad, Who::Operator), "confirmation_mismatch");
    bad = Accept {
        chain: "0".repeat(64),
        ..clone_accept(&good)
    };
    assert_eq!(refuse(&bad, Who::Operator), "confirmation_mismatch");
    bad = Accept {
        digest: format!("sha256:{}", "0".repeat(64)),
        ..clone_accept(&good)
    };
    assert_eq!(refuse(&bad, Who::Operator), "confirmation_mismatch");
    let wrong_store = Command::Repair(RepairCommand::AcceptLoss {
        confirm_store_id: "0".repeat(32),
        confirm_store_seq: good.store_seq,
        confirm_ledger_seq: good.ledger_seq,
        confirm_ledger_chain: good.chain.clone(),
        confirm_plan_digest: good.digest.clone(),
        acknowledge: good.ack.clone(),
    });
    assert_eq!(
        code(&p.w.run(Who::Operator, &wrong_store)),
        "confirmation_mismatch"
    );
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    assert_eq!(p.w.budget().consumed, 1);

    // A dry run validates everything and writes nothing.
    let dry = p.w.dry(Who::Operator, &accept_cmd(&p, &good));
    assert_eq!(code(&dry), "would_accept");
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    assert_eq!(p.w.budget().consumed, 1);

    // The acceptance.
    let done = p.w.run(Who::Operator, &accept_cmd(&p, &good));
    assert_eq!(code(&done), "accepted", "{}", done.render());
    assert_eq!(num(&done, "recovered_units"), 1);
    assert_eq!(num(&done, "epochs_retired"), 1);
    assert!(!p.w.rw.store.needs_reconcile().unwrap());

    // Budgets only rose, to exactly what the lost newer copy showed.
    let b = p.w.budget();
    assert_eq!((b.consumed, b.held, b.refunded), (2, 0, 0));
    p.w.rw.store.integrity_check().unwrap();

    // The epoch is contaminated (as the ledger states) and retired: nothing
    // new can run on it, and the request that had run is not run again.
    let st =
        p.w.rw
            .store
            .epoch_standing(p.w.rw.epoch.as_str())
            .unwrap()
            .unwrap();
    assert!(st.standing.retired);
    assert_eq!(st.standing.contamination.as_str(), "exposed");
    assert_eq!(code(&p.submit(3)), "epoch_blocked");
    let again = p.submit(2);
    assert!(!again.is_ok());
    assert_eq!(p.sandbox.runs(), runs, "nothing ran again");

    // A repeat of the same acceptance is a no-op.
    let rep = p.w.run(Who::Operator, &accept_cmd(&p, &good));
    assert_eq!(code(&rep), "accepted");
    assert_eq!(rep.field("replay"), Some(&Value::Bool(true)));
    assert_eq!(p.w.budget().consumed, 2);

    // The acceptance is itself an audited event, exported like any other,
    // and the control plane starts again over a clean verification.
    let ev =
        p.w.rw
            .store
            .outbox_pending(1000)
            .unwrap()
            .into_iter()
            .find(|e| e.kind == "store.loss_accepted")
            .expect("audited");
    assert!(ev.payload.contains(&Who::Operator.actor()));
    assert_eq!(code(&p.export()), "exported");
    {
        let acts = p.activations();
        p.start(&acts)
            .expect("the recovered store passes startup_check");
    }
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified"
    );
    // Nothing is left to accept.
    assert_eq!(
        code(&p.w.run(Who::Operator, &plan_cmd(&p))),
        "store_not_behind_ledger"
    );
}

fn clone_accept(a: &Accept) -> Accept {
    Accept {
        store_seq: a.store_seq,
        ledger_seq: a.ledger_seq,
        chain: a.chain.clone(),
        digest: a.digest.clone(),
        ack: a.ack.clone(),
    }
}

#[test]
fn a_store_that_is_not_a_prefix_of_the_ledger_is_an_incident_not_a_repair() {
    // The restored copy comes from a different history (another store with
    // the same shape). It is not behind the ledger, it is elsewhere.
    let p = Pipe::new(5, 10);
    spend(&p, 1);
    spend(&p, 2);
    let q = Pipe::new(5, 10);
    spend(&q, 1);
    let alien = p.w.rw.db.dir().join("alien.db");
    q.w.rw.store.backup_to(&alien).unwrap();
    let mut p = p;
    p.w.rw.store = SqliteStore::open(&alien).unwrap();
    {
        let acts = p.activations();
        assert!(Service::start(p.w.parts(), &startup_config(), &acts).is_err());
    }
    let o = p.w.run(Who::Operator, &plan_cmd(&p));
    assert_eq!(
        (code(&o), o.exit_code()),
        ("lineage_diverged", 8),
        "{}",
        o.render()
    );
    assert!(p.w.rw.store.needs_reconcile().unwrap());
}

#[test]
fn a_healthy_store_has_nothing_to_accept() {
    let p = Pipe::new(5, 10);
    spend(&p, 1);
    let o = p.w.run(Who::Operator, &plan_cmd(&p));
    assert_eq!(code(&o), "store_not_behind_ledger");
    // And accepting is refused before it can touch anything.
    let a = Accept {
        store_seq: 1,
        ledger_seq: 1,
        chain: "0".repeat(64),
        digest: format!("sha256:{}", "0".repeat(64)),
        ack: LOSS_ACKNOWLEDGEMENT.to_owned(),
    };
    assert_eq!(
        code(&p.w.run(Who::Operator, &accept_cmd(&p, &a))),
        "store_not_behind_ledger"
    );
    p.w.rw.store.verify_invariants().unwrap();
}

#[test]
fn a_tampered_ledger_tail_is_never_adopted() {
    // Remove one audit record from the ledger: the walk reports a gap, the ledger is untrusted, and no plan or acceptance is
    // possible while it is.
    let (p, _) = disaster();
    let victim =
        p.w.ledger
            .paths()
            .into_iter()
            .find(|f| f.starts_with("records/audit/"))
            .unwrap();
    p.w.ledger.remove(&victim);
    let o = p.w.run(Who::Operator, &plan_cmd(&p));
    assert_eq!(code(&o), "ledger_untrusted");
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    assert_eq!(p.w.budget().consumed, 1);
}
