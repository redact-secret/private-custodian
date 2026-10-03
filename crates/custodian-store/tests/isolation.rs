//! Transaction isolation: writers are serialized by `BEGIN IMMEDIATE`, readers
//! see a consistent WAL snapshot and never a half-applied reservation, and a
//! writer that cannot get the lock fails closed without changing anything.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use common::*;
use custodian_core::ports::{Refusal, StateStore};
use custodian_core::ReasonCode;
use custodian_store::{SqliteStore, StoreConfig, StoreError};

#[test]
fn reader_sees_only_committed_state_and_writer_fails_closed_when_busy() {
    let db = TempDb::new("iso-busy");
    let store =
        SqliteStore::open_with_config(db.path(), StoreConfig::default().with_busy_timeout_ms(100))
            .unwrap();
    let fx = fixture(1);
    provision(&store, &fx, 2);

    // Another connection takes the write lock and changes the budget
    // without committing.
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE; UPDATE budgets SET limit_units = limit_units + 5;")
        .unwrap();

    // Readers are not blocked and see the last committed snapshot.
    assert_eq!(status(&store, &fx).limit, 2);

    // A second writer cannot interleave: it waits out the busy timeout and
    // fails closed with Busy. Nothing was written.
    assert_eq!(reserve(&store, &fx).unwrap_err(), StoreError::Busy);
    assert_eq!(
        Refusal::from(StoreError::Busy),
        Refusal(ReasonCode::StoreUnavailable)
    );

    raw.execute_batch("COMMIT").unwrap();
    assert_eq!(status(&store, &fx).limit, 7);
    // The refused request left no trace and can simply be retried.
    assert!(store.request_attempts(&fx.request_id()).unwrap().is_empty());
    assert!(!reserve(&store, &fx).unwrap().replay);
    store.integrity_check().unwrap();
}

#[test]
fn rolled_back_writer_leaves_no_partial_state() {
    let db = TempDb::new("iso-rollback");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let before = store.latest_checkpoint().unwrap();

    let raw = rusqlite::Connection::open(db.path()).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE; UPDATE budgets SET held_units = 1;")
        .unwrap();
    assert_eq!(status(&store, &fx).held, 0);
    raw.execute_batch("ROLLBACK").unwrap();
    assert_eq!(status(&store, &fx).held, 0);
    assert_eq!(store.latest_checkpoint().unwrap(), before);
}

#[test]
fn readers_never_observe_a_half_applied_reservation() {
    // One thread reserves repeatedly while another repeatedly runs the
    // cross-table invariant check in a single read snapshot. If budget,
    // reservation, transition and outbox writes were not one atomic commit,
    // the snapshot would eventually catch them out of step.
    let db = TempDb::new("iso-snapshot");
    {
        let store = open(&db);
        provision(&store, &fixture(1), 60);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (path, stop) = (db.path(), Arc::clone(&stop));
        thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                path,
                StoreConfig::default().with_busy_timeout_ms(60_000),
            )
            .unwrap();
            let mut checks = 0u32;
            while !stop.load(Ordering::SeqCst) {
                store.verify_invariants().unwrap();
                checks += 1;
            }
            checks
        })
    };
    let writer = {
        let path = db.path();
        thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                path,
                StoreConfig::default().with_busy_timeout_ms(60_000),
            )
            .unwrap();
            for n in 1..=60u32 {
                assert!(!reserve(&store, &fixture(n)).unwrap().replay);
            }
        })
    };
    writer.join().unwrap();
    stop.store(true, Ordering::SeqCst);
    assert!(reader.join().unwrap() > 0);
    let store = open(&db);
    assert_eq!(status(&store, &fixture(1)).held, 60);
}

#[test]
fn database_constraints_hold_even_if_the_code_were_wrong() {
    // Defence in depth: bypass the API and try to break the invariants
    // directly. The schema itself must refuse.
    let db = TempDb::new("iso-constraints");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    let o = reserve(&store, &fx).unwrap();
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

    let must_fail = |sql: &str| {
        assert!(raw.execute_batch(sql).is_err(), "schema accepted: {sql}");
    };
    // Over-commit the budget.
    must_fail("UPDATE budgets SET held_units = held_units + 1;");
    // Lower the limit / erase consumption.
    must_fail("UPDATE budgets SET limit_units = 0;");
    must_fail("DELETE FROM budgets;");
    // Rewrite or delete history.
    must_fail("UPDATE transitions SET reason = 'completed';");
    must_fail("DELETE FROM transitions;");
    must_fail("DELETE FROM outbox;");
    must_fail("UPDATE outbox SET payload = '{}';");
    must_fail("DELETE FROM requests;");
    // A refund of an exposed reservation is unrepresentable.
    must_fail(&format!(
        "UPDATE reservations SET state = 'refunded', exposure = 'exposed', settled_at = 1 \
         WHERE attempt_id = '{}';",
        o.attempt.as_str()
    ));
    // Two live attempts for one request.
    must_fail(&format!(
        "INSERT INTO attempts (attempt_id, request_id, attempt_no, state, exposure, \
         authorization_ref, created_at, updated_at) \
         VALUES ('exe_dup', '{}', 2, 'reserved', 'not_exposed', 'x', 1, 1);",
        fx.request_id()
    ));
    store.integrity_check().unwrap();
}

#[test]
fn port_reserve_is_one_atomic_check_and_charge() {
    // The same guarantee through the vendor-neutral port.
    use custodian_core::ports::Authorization;
    use custodian_core::{ActorId, AuthorizationId, IdempotencyKey, PlanDigest, PopulationId};
    let db = TempDb::new("iso-port");
    let clock = clock();
    let store = SqliteStore::open_with_config(db.path(), cfg(&clock)).unwrap();
    let pop = PopulationId::new("synthetic-population");
    store.provision_port_budget(&pop, 1, &actor(), NOW).unwrap();
    let auth = Authorization {
        id: AuthorizationId::new("synthetic-authorization"),
        actor: ActorId::new("synthetic-requester"),
        plan: PlanDigest::new("synthetic-plan-a"),
        population: pop,
        expires_at: NOW + 1000,
    };
    let a = store.reserve(&auth, &IdempotencyKey::new("k1")).unwrap();
    assert!(!a.replay);
    assert_eq!(
        store
            .reserve(&auth, &IdempotencyKey::new("k2"))
            .unwrap_err(),
        Refusal(ReasonCode::BudgetExhausted)
    );
    assert!(
        store
            .reserve(&auth, &IdempotencyKey::new("k1"))
            .unwrap()
            .replay
    );
}
