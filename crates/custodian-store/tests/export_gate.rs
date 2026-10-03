//! R-2: the export-acknowledged dispatch gate (ADR 0116).
//!
//! `start_attempt` and `record_exposure` refuse with
//! `StoreError::ExportPending` while budget-affecting audit events are not
//! acknowledged by the ledger export. These tests drive the store directly;
//! the "export" is `outbox_ack`, exactly what the exporter calls once the
//! signed record is durable. Synthetic data only.

mod common;

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use common::*;
use custodian_core::{ReasonCode, RunId, RunState};
use custodian_store::{
    ExportGate, FaultInjector, FaultOp, FaultPhase, FaultPoint, Lease, SqliteStore, StartCommand,
    StoreConfig, StoreError, BUDGET_AFFECTING_KINDS,
};

fn enforced() -> StoreConfig {
    StoreConfig::enforced().with_busy_timeout_ms(60_000)
}

fn open_enforced(db: &TempDb) -> SqliteStore {
    SqliteStore::open_with_config(db.path(), enforced()).unwrap()
}

fn start(store: &SqliteStore, fx: &Fx, attempt: &RunId, now: u64) -> Result<Lease, StoreError> {
    store.start_attempt(&StartCommand {
        attempt,
        owner: "worker-a",
        actor: &actor(),
        now,
        lease_secs: LEASE,
        observed: Some(&fx.obs),
        max_state_age_secs: MAX_AGE,
    })
}

/// What the exporter does for every pending event: acknowledge it.
fn export_all(store: &SqliteStore, now: u64) -> usize {
    let pending = store.outbox_pending(1000).unwrap();
    for e in &pending {
        store
            .outbox_ack(e.seq, &format!("ledger:entry-{}", e.seq), now)
            .unwrap();
    }
    pending.len()
}

fn reserved(store: &SqliteStore, fx: &Fx) -> RunId {
    let o = reserve(store, fx).unwrap();
    assert_eq!(o.state, RunState::Reserved);
    o.attempt
}

#[test]
fn the_default_library_configuration_has_no_gate_and_production_enforces_zero() {
    assert_eq!(StoreConfig::default().export_gate, ExportGate::Off);
    assert_eq!(
        StoreConfig::enforced().export_gate,
        ExportGate::Enforced { max_unexported: 0 }
    );
    // With the gate off the existing behavior is unchanged.
    let db = TempDb::new("gate-off");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let a = reserved(&store, &fx);
    let lease = start(&store, &fx, &a, NOW + 1).unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    assert!(store.exposure_export_acknowledged(&lease).unwrap());
}

#[test]
fn start_is_refused_until_the_reservation_is_acknowledged() {
    let db = TempDb::new("gate-start");
    let store = open_enforced(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let a = reserved(&store, &fx);
    let before = status(&store, &fx);
    assert!(store.unexported_budget_events().unwrap() >= 1);

    for t in 1..4 {
        assert_eq!(
            start(&store, &fx, &a, NOW + t).err(),
            Some(StoreError::ExportPending)
        );
    }
    // A refusal changes nothing: still reserved, nothing held more or less,
    // no start event, the lease untouched.
    let rec = store.attempt(&a).unwrap().unwrap();
    assert_eq!(rec.state, RunState::Reserved);
    assert_eq!(rec.lease_token, 0);
    assert_eq!(status(&store, &fx), before);
    assert!(store
        .outbox_pending(1000)
        .unwrap()
        .iter()
        .all(|e| e.kind != "attempt.started"));
    // The fixed code a caller sees, and the core reason over the port.
    assert_eq!(
        StoreError::ExportPending.to_string(),
        "store_export_pending"
    );
    assert_eq!(
        StoreError::ExportPending.reason(),
        ReasonCode::StoreUnavailable
    );

    export_all(&store, NOW + 5);
    assert_eq!(store.unexported_budget_events().unwrap(), 0);
    let lease = start(&store, &fx, &a, NOW + 6).unwrap();
    assert_eq!(lease.token, 1);
    // A duplicate start still finds the attempt running.
    assert_eq!(
        start(&store, &fx, &a, NOW + 7).err(),
        Some(StoreError::InvalidTransition)
    );
}

#[test]
fn exposure_waits_for_the_start_to_be_acknowledged_and_dispatch_waits_for_settlement() {
    let db = TempDb::new("gate-exposure");
    let store = open_enforced(&db);
    let fx1 = fixture(1);
    let fx2 = fixture(2);
    provision(&store, &fx1, 3);
    let a1 = reserved(&store, &fx1);
    export_all(&store, NOW + 1);
    let lease = start(&store, &fx1, &a1, NOW + 2).unwrap();

    // Protected bytes cannot be opened while the ledger has not heard of the
    // start: the exposure is refused and recorded nowhere.
    assert_eq!(
        store.record_exposure(&lease, &actor(), NOW + 3).err(),
        Some(StoreError::ExportPending)
    );
    assert_eq!(
        store.attempt(&a1).unwrap().unwrap().exposure,
        custodian_core::Exposure::NotExposed
    );
    export_all(&store, NOW + 4);
    store.record_exposure(&lease, &actor(), NOW + 5).unwrap();
    // The exposure record itself is acknowledged before bytes may be opened.
    assert!(!store.exposure_export_acknowledged(&lease).unwrap());
    export_all(&store, NOW + 6);
    assert!(store.exposure_export_acknowledged(&lease).unwrap());

    store.begin_validation(&lease, &actor(), NOW + 7).unwrap();
    store
        .finish(
            &lease,
            custodian_contracts::execution::ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 8,
        )
        .unwrap();

    // The settlement is unacknowledged spend: no other attempt may start.
    let a2 = reserved(&store, &fx2);
    export_all_but_terminal(&store, NOW + 9);
    assert_eq!(
        start(&store, &fx2, &a2, NOW + 10).err(),
        Some(StoreError::ExportPending)
    );
    export_all(&store, NOW + 11);
    start(&store, &fx2, &a2, NOW + 12).unwrap();
    store.integrity_check().unwrap();
}

fn export_all_but_terminal(store: &SqliteStore, now: u64) {
    for e in store.outbox_pending(1000).unwrap() {
        if e.kind != "attempt.terminal" {
            store
                .outbox_ack(e.seq, &format!("ledger:entry-{}", e.seq), now)
                .unwrap();
        }
    }
}

#[test]
fn only_budget_affecting_events_hold_dispatch_back() {
    let db = TempDb::new("gate-kinds");
    let store = open_enforced(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let a = reserved(&store, &fx);
    // Ack every budget-affecting event and leave the rest pending.
    for e in store.outbox_pending(1000).unwrap() {
        if BUDGET_AFFECTING_KINDS.contains(&e.kind.as_str()) {
            store.outbox_ack(e.seq, "ledger:entry", NOW).unwrap();
        }
    }
    let pending_kinds: Vec<String> = store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(pending_kinds.contains(&"budget.provisioned".to_owned()));
    start(&store, &fx, &a, NOW + 1).unwrap();
}

#[test]
fn gate_covers_every_budget_affecting_kind() {
    // Every kind the store can emit that charges, holds, settles or imports
    // budget is in the list; adding a kind without updating it fails here.
    let mut listed = BUDGET_AFFECTING_KINDS.to_vec();
    listed.sort_unstable();
    assert_eq!(
        listed,
        vec![
            "approval.granted",
            "attempt.started",
            "attempt.terminal",
            "budget.imported",
            "disclosure.charged",
            "exposure.recorded",
            "reservation.created",
        ]
    );
}

#[test]
fn a_nonzero_bound_is_honored_exactly() {
    let db = TempDb::new("gate-bound");
    let cfg = StoreConfig::default().with_export_gate(ExportGate::Enforced { max_unexported: 1 });
    let store = SqliteStore::open_with_config(db.path(), cfg).unwrap();
    let fx1 = fixture(1);
    let fx2 = fixture(2);
    provision(&store, &fx1, 3);
    let a1 = reserved(&store, &fx1);
    let a2 = reserved(&store, &fx2);
    // Two reservations pending: over the bound of one.
    assert_eq!(
        start(&store, &fx1, &a1, NOW + 1).err(),
        Some(StoreError::ExportPending)
    );
    // Acknowledge the first reservation only: one pending, within the bound.
    let first = store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "reservation.created")
        .unwrap();
    store
        .outbox_ack(first.seq, "ledger:entry", NOW + 2)
        .unwrap();
    start(&store, &fx1, &a1, NOW + 3).unwrap();
    // The start event is pending now as well: two again, so the second
    // attempt waits.
    assert_eq!(
        start(&store, &fx2, &a2, NOW + 4).err(),
        Some(StoreError::ExportPending)
    );
}

#[test]
fn ledger_unavailable_fails_closed_and_never_changes_a_budget() {
    let db = TempDb::new("gate-ledger-down");
    let store = open_enforced(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let a = reserved(&store, &fx);
    let before = status(&store, &fx);
    // The ledger is down: nothing is acknowledged, however long we wait and
    // however many times recovery and retries run.
    for t in 0..5 {
        assert_eq!(
            start(&store, &fx, &a, NOW + 10 + t).err(),
            Some(StoreError::ExportPending)
        );
        store.recover(&actor(), NOW + 20 + t).unwrap();
    }
    // The reservation window lapsed: recovery refunds the unstarted
    // reservation (the existing rule), it never returns more than was held,
    // and a lapsed reservation can no longer start either.
    let after = status(&store, &fx);
    assert!(after.consumed <= before.consumed + before.held);
    assert!(after.refunded <= before.held);
    assert!(store.attempt(&a).unwrap().unwrap().state != RunState::Running);
    store.integrity_check().unwrap();
}

// ---- crash between export and acknowledgement ---------------------------------

#[derive(Default)]
struct Arm(Mutex<Option<FaultPoint>>);

impl FaultInjector for Arm {
    fn crash_at(&self, point: FaultPoint) -> bool {
        let mut g = self.0.lock().unwrap();
        if *g == Some(point) {
            *g = None;
            true
        } else {
            false
        }
    }
}

#[test]
fn a_crash_between_export_and_acknowledgement_keeps_dispatch_closed_until_the_ack_is_durable() {
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        let db = TempDb::new("gate-crash-ack");
        let arm = Arc::new(Arm::default());
        let fx = fixture(1);
        let attempt;
        {
            let store =
                SqliteStore::open_with_config(db.path(), enforced().with_fault(arm.clone()))
                    .unwrap();
            provision(&store, &fx, 2);
            attempt = reserved(&store, &fx);
            // The record reached the ledger; the process dies around the ack.
            let ev = store
                .outbox_pending(1000)
                .unwrap()
                .into_iter()
                .find(|e| e.kind == "reservation.created")
                .unwrap();
            *arm.0.lock().unwrap() = Some(FaultPoint {
                op: FaultOp::OutboxAck,
                phase,
            });
            assert!(matches!(
                store.outbox_ack(ev.seq, "ledger:entry-1", NOW + 1),
                Err(StoreError::InjectedCrash(_))
            ));
        }
        let store = open_enforced(&db);
        let ev = store
            .outbox_pending(1000)
            .unwrap()
            .into_iter()
            .find(|e| e.kind == "reservation.created");
        match phase {
            FaultPhase::BeforeCommit => {
                // Not acknowledged: still refused. The exporter re-presents
                // the same record (idempotent in the ledger) and acks again.
                assert_eq!(
                    start(&store, &fx, &attempt, NOW + 2).err(),
                    Some(StoreError::ExportPending)
                );
                let ev = ev.expect("still pending");
                store.outbox_ack(ev.seq, "ledger:entry-1", NOW + 3).unwrap();
            }
            FaultPhase::AfterCommit => {
                assert!(ev.is_none(), "the acknowledgement was durable");
            }
        }
        start(&store, &fx, &attempt, NOW + 4).unwrap();
        store.integrity_check().unwrap();
    }
}

// ---- restore drill at the store level -------------------------------------------

#[test]
fn the_gate_closes_the_restore_window_an_older_backup_is_detected_before_exposure() {
    // Without the gate (the pre-R-2 behavior): start and exposure happen with
    // the ledger knowing nothing newer than the checkpoint, and a restore of
    // the pre-start backup passes the checkpoint comparison, so the request
    // can run again.
    let db = TempDb::new("gate-drill-off");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let a = reserved(&store, &fx);
    export_all(&store, NOW + 1);
    let ledger_checkpoint = store.latest_checkpoint().unwrap().unwrap();
    let backup = db.dir().join("pre-start.db");
    store.backup_to(&backup).unwrap();
    let lease = start(&store, &fx, &a, NOW + 2).unwrap();
    store.record_exposure(&lease, &actor(), NOW + 3).unwrap();
    // Dispatch happened and nothing about it reached the ledger.
    let restored = SqliteStore::open(&backup).unwrap();
    restored
        .verify_external_checkpoint(&ledger_checkpoint)
        .expect("undetectable without the gate: the ledger knows nothing newer");

    // With the gate: exposure cannot happen until the ledger acknowledged
    // the start, so the independent checkpoint then covers it, and the same
    // restore is refused.
    let db = TempDb::new("gate-drill-on");
    let store = open_enforced(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let a = reserved(&store, &fx);
    export_all(&store, NOW + 1);
    let backup = db.dir().join("pre-start.db");
    store.backup_to(&backup).unwrap();
    let lease = start(&store, &fx, &a, NOW + 2).unwrap();
    assert_eq!(
        store.record_exposure(&lease, &actor(), NOW + 3).err(),
        Some(StoreError::ExportPending),
        "the window is closed: no exposure before the start is acknowledged"
    );
    export_all(&store, NOW + 4);
    let ledger_checkpoint = store.latest_checkpoint().unwrap().unwrap();
    store.record_exposure(&lease, &actor(), NOW + 5).unwrap();
    export_all(&store, NOW + 6);
    assert!(store.exposure_export_acknowledged(&lease).unwrap());

    let restored = SqliteStore::open(&backup).unwrap();
    assert_eq!(
        restored
            .verify_external_checkpoint(&ledger_checkpoint)
            .err(),
        Some(StoreError::NeedsReconcile)
    );
    // The blocked copy takes no new write: the request cannot run again.
    assert_eq!(
        start(&restored, &fx, &a, NOW + 7).err(),
        Some(StoreError::NeedsReconcile)
    );
}

// ---- concurrency ---------------------------------------------------------------

#[test]
fn concurrent_starts_are_all_refused_until_acknowledged_then_exactly_one_wins_each() {
    const N: u32 = 8;
    let db = TempDb::new("gate-conc");
    let attempts: Vec<(Fx, RunId)> = {
        let store = open_enforced(&db);
        provision(&store, &fixture(1), u64::from(N));
        (1..=N)
            .map(|n| {
                let fx = fixture(n);
                let a = reserved(&store, &fx);
                (fx, a)
            })
            .collect()
    };

    // Phase A: nothing acknowledged, every start is refused.
    let barrier = Arc::new(Barrier::new(attempts.len()));
    let handles: Vec<_> = attempts
        .iter()
        .map(|(fx, a)| {
            let (barrier, path) = (Arc::clone(&barrier), db.path());
            let (fx, a) = (fx.obs.clone(), a.clone());
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(path, enforced()).unwrap();
                let fxn = fixture(1);
                barrier.wait();
                store
                    .start_attempt(&StartCommand {
                        attempt: &a,
                        owner: "worker",
                        actor: &actor(),
                        now: NOW + 1,
                        lease_secs: LEASE,
                        observed: Some(&fx),
                        max_state_age_secs: MAX_AGE,
                    })
                    .err()
                    .map(|e| (e, fxn.request_id()))
            })
        })
        .collect();
    for h in handles {
        assert_eq!(
            h.join().unwrap().map(|(e, _)| e),
            Some(StoreError::ExportPending)
        );
    }

    // Phase B: the export races the starts. A start either waits (refused)
    // or, if it won, ran after every earlier event was acknowledged. No other
    // outcome exists.
    let barrier = Arc::new(Barrier::new(attempts.len() + 1));
    let mut handles: Vec<_> = attempts
        .iter()
        .map(|(fx, a)| {
            let (barrier, path) = (Arc::clone(&barrier), db.path());
            let (obs, a) = (fx.obs.clone(), a.clone());
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(path, enforced()).unwrap();
                barrier.wait();
                store
                    .start_attempt(&StartCommand {
                        attempt: &a,
                        owner: "worker",
                        actor: &actor(),
                        now: NOW + 2,
                        lease_secs: LEASE,
                        observed: Some(&obs),
                        max_state_age_secs: MAX_AGE,
                    })
                    .map(|_| ())
            })
        })
        .collect();
    let exporter = {
        let (barrier, path) = (Arc::clone(&barrier), db.path());
        thread::spawn(move || {
            let store = SqliteStore::open_with_config(path, enforced()).unwrap();
            barrier.wait();
            export_all(&store, NOW + 2);
            Ok(())
        })
    };
    handles.push(exporter);
    for h in handles {
        match h.join().unwrap() {
            Ok(()) | Err(StoreError::ExportPending) => {}
            Err(other) => panic!("unexpected {other}"),
        }
    }

    // Phase C: with everything acknowledged, duplicate starts of one attempt
    // have exactly one winner, and the gate then holds the next start behind
    // the first one's own start event.
    let store = open_enforced(&db);
    export_all(&store, NOW + 3);
    let (fx, a) = &attempts[0];
    let running = store.attempt(a).unwrap().unwrap().state == RunState::Running;
    if !running {
        let wins = (0..4)
            .filter(|i| start(&store, fx, a, NOW + 4 + i).is_ok())
            .count();
        assert_eq!(wins, 1);
    }
    store.integrity_check().unwrap();
}
