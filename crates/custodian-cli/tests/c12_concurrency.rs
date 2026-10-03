//! C12 concurrency tests across the whole control plane: many operators and
//! workers on separate database connections racing for the same budget, the
//! same request, the same attempt and the same ledger. Real threads, file
//! database, synthetic data. Deterministic assertions only: the outcomes are
//! counted, never ordered.
//!
//! These prove mechanism with project-maintained synthetic fixtures; they
//! are not independent validation.

mod c12;

use std::thread;

use c12::*;
use custodian_cli::command::{Contaminated, VerifyTarget};
use custodian_cli::{Command, Control};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_core::{Exposure, RunState};
use custodian_store::SqliteStore;

/// Run `cmd` as `who` on a fresh connection to the same database file.
fn on_own_connection(p: &Pipe, who: Who, cmd: &Command) -> custodian_cli::Output {
    let store = SqliteStore::open(p.w.rw.db.path()).unwrap();
    let mut parts = p.w.parts();
    parts.store = &store;
    Control::new(parts).execute(&p.w.principal(who), cmd, false)
}

fn count(outs: &[&'static str], word: &str) -> usize {
    outs.iter().filter(|c| **c == word).count()
}

#[test]
fn concurrent_approvals_for_the_last_units_reserve_exactly_the_limit() {
    let p = Pipe::new(3, 4);
    for n in 1..=8 {
        assert!(p.submit(n).is_ok());
    }
    let p = &p;
    let codes: Vec<&'static str> = thread::scope(|s| {
        let hs: Vec<_> = (1..=8u32)
            .map(|n| {
                s.spawn(move || {
                    let (req, _) = p.request(n);
                    on_own_connection(p, Who::Approver, &approve_cmd(&req)).code()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(count(&codes, "approved"), 3, "{codes:?}");
    assert_eq!(count(&codes, "budget_exhausted"), 5, "{codes:?}");
    let b = p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (3, 0, 0));
    // The five losers are recorded denials: no free run, and audited.
    let kinds = p.w.kinds();
    assert_eq!(kinds.iter().filter(|k| *k == "reservation.created").count(), 3);
    assert_eq!(kinds.iter().filter(|k| *k == "request.denied").count(), 5);
    p.w.rw.store.verify_invariants().unwrap();
    assert_eq!(p.sandbox.runs(), 0);
}

#[test]
fn the_same_request_approved_by_many_at_once_is_reserved_once() {
    let p = Pipe::new(3, 4);
    assert!(p.submit(1).is_ok());
    let p = &p;
    let codes: Vec<&'static str> = thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(move || {
                    let (req, _) = p.request(1);
                    on_own_connection(p, Who::Approver, &approve_cmd(&req)).code()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(count(&codes, "approved"), 1, "{codes:?}");
    assert_eq!(count(&codes, "already_decided"), 7, "{codes:?}");
    assert_eq!(p.w.budget().held, 1, "one charge");
    p.w.rw.store.verify_invariants().unwrap();
}

#[test]
fn duplicate_dispatch_of_one_attempt_runs_the_engine_once_and_charges_once() {
    let p = Pipe::new(3, 6);
    let (attempt, _) = p.reserve(1);
    let (req, _) = p.request(1);
    let p = &p;
    let outcomes: Vec<Option<O>> = thread::scope(|s| {
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let (req, attempt) = (req.clone(), attempt.clone());
                s.spawn(move || {
                    let store = SqliteStore::open(p.w.rw.db.path()).unwrap();
                    p.dispatch_on(&store, &req, &attempt).ok().map(|r| r.outcome)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(p.sandbox.runs(), 1, "one execution: {outcomes:?}");
    assert_eq!(
        outcomes.iter().filter(|o| **o == Some(O::Success)).count(),
        1,
        "{outcomes:?}"
    );
    let rec = p.w.rw.store.attempt(&attempt).unwrap().unwrap();
    assert_eq!((rec.state, rec.exposure), (RunState::Completed, Exposure::Exposed));
    let b = p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
    p.w.rw.store.verify_invariants().unwrap();
    assert_eq!(p.arts.staging_entries(), 0);
}

#[test]
fn contamination_racing_with_approvals_never_lets_a_reservation_in_after_it() {
    let p = Pipe::new(8, 4);
    for n in 1..=6 {
        assert!(p.submit(n).is_ok());
    }
    let p = &p;
    let codes: Vec<&'static str> = thread::scope(|s| {
        let mut hs = Vec::new();
        for n in 1..=6u32 {
            hs.push(s.spawn(move || {
                let (req, _) = p.request(n);
                on_own_connection(p, Who::Approver, &approve_cmd(&req)).code()
            }));
        }
        hs.push(s.spawn(move || {
            on_own_connection(
                p,
                Who::Operator,
                &Command::LifecycleReport {
                    epoch: p.w.rw.epoch.clone(),
                    kind: Contaminated::Exposed,
                    reason: "results_exposed".into(),
                    key: lc::idk(1),
                },
            )
            .code()
        }));
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    // Whichever committed first won: each approval is either in or refused.
    let approved = count(&codes[..6], "approved");
    let blocked = count(&codes[..6], "epoch_blocked");
    assert_eq!(approved + blocked, 6, "{codes:?}");
    assert!(codes[6] == "reported" || codes[6] == "retired", "{codes:?}");
    assert_eq!(p.w.budget().held, approved as u64);
    // After the contamination returned, nothing new gets in.
    assert_eq!(p.submit(7).code(), "epoch_blocked");
    assert_eq!(p.w.budget().held, approved as u64);
    p.w.rw.store.verify_invariants().unwrap();
    p.w.rw.store.verify_lifecycle_invariants().unwrap();
    // Already-reserved attempts cannot start on a contaminated epoch.
    assert_eq!(p.sandbox.runs(), 0);
}

#[test]
fn concurrent_exports_write_each_audit_event_once_and_the_ledger_stays_trustworthy() {
    let p = Pipe::new(6, 4);
    for n in 1..=4 {
        p.reserve(n);
    }
    let p = &p;
    let codes: Vec<&'static str> = thread::scope(|s| {
        let hs: Vec<_> = (0..3)
            .map(|_| {
                s.spawn(move || {
                    let store = SqliteStore::open(p.w.rw.db.path()).unwrap();
                    let cmd = Command::Repair(custodian_cli::command::RepairCommand::Export {
                        confirm_store_id: store.store_id().unwrap(),
                    });
                    on_own_connection(p, Who::Operator, &cmd).code()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    // A racing exporter may find work already done; none may corrupt the ledger.
    assert!(
        codes.iter().all(|c| *c == "exported" || *c == "export_conflict" || *c == "ledger_unavailable"),
        "{codes:?}"
    );
    assert_eq!(p.export().code(), "exported", "a final pass drains the outbox");
    assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), 0);
    assert_eq!(
        p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All)).code(),
        "verified"
    );
}
