//! Real threads against a real file database. Each thread opens its own
//! connection, so SQLite's write lock (`BEGIN IMMEDIATE`) is what serializes
//! them, exactly as for several worker processes. Synthetic data only.

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use common::*;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_core::{ReasonCode, RunState};
use custodian_store::{SqliteStore, StartCommand, StoreConfig, StoreError};

fn open_patient(db: &TempDb) -> SqliteStore {
    SqliteStore::open_with_config(
        db.path(),
        StoreConfig::default().with_busy_timeout_ms(60_000),
    )
    .unwrap()
}

#[test]
fn concurrent_requests_cannot_exceed_the_budget() {
    const LIMIT: u64 = 3;
    const THREADS: u32 = 24;
    let db = TempDb::new("conc-budget");
    {
        let store = open_patient(&db);
        provision(&store, &fixture(1), LIMIT);
    }
    let barrier = Arc::new(Barrier::new(THREADS as usize));
    let handles: Vec<_> = (1..=THREADS)
        .map(|n| {
            let barrier = Arc::clone(&barrier);
            let path = db.path();
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                let fx = fixture(n);
                barrier.wait();
                reserve(&store, &fx).unwrap().state
            })
        })
        .collect();
    let states: Vec<RunState> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let reserved = states.iter().filter(|s| **s == RunState::Reserved).count();
    let denied = states.iter().filter(|s| **s == RunState::Denied).count();
    assert_eq!(reserved as u64, LIMIT);
    assert_eq!(denied as u64, u64::from(THREADS) - LIMIT);

    let store = open_patient(&db);
    let st = status(&store, &fixture(1));
    assert_eq!((st.held, st.consumed, st.limit), (LIMIT, 0, LIMIT));
    store.integrity_check().unwrap();
}

#[test]
fn exactly_one_wins_the_last_unit() {
    for round in 0..5 {
        let db = TempDb::new("conc-last");
        {
            let store = open_patient(&db);
            provision(&store, &fixture(1), 1);
        }
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (1..=8u32)
            .map(|n| {
                let barrier = Arc::clone(&barrier);
                let path = db.path();
                thread::spawn(move || {
                    let store = SqliteStore::open_with_config(
                        path,
                        StoreConfig::default().with_busy_timeout_ms(60_000),
                    )
                    .unwrap();
                    let fx = fixture(n);
                    barrier.wait();
                    reserve(&store, &fx).unwrap().state
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|s| *s == RunState::Reserved)
            .count();
        assert_eq!(wins, 1, "round {round}");
    }
}

#[test]
fn concurrent_duplicate_delivery_charges_once() {
    let db = TempDb::new("conc-dup");
    {
        let store = open_patient(&db);
        provision(&store, &fixture(1), 5);
    }
    let barrier = Arc::new(Barrier::new(10));
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = db.path();
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                let fx = fixture(1);
                barrier.wait();
                reserve(&store, &fx).unwrap()
            })
        })
        .collect();
    let outs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outs.iter().filter(|o| !o.replay).count(), 1);
    assert!(outs.iter().all(|o| o.attempt == outs[0].attempt));
    let store = open_patient(&db);
    assert_eq!(status(&store, &fixture(1)).held, 1);
    assert_eq!(
        store
            .request_attempts(&fixture(1).request_id())
            .unwrap()
            .len(),
        1
    );
    store.integrity_check().unwrap();
}

#[test]
fn concurrent_start_lets_exactly_one_worker_execute() {
    let db = TempDb::new("conc-start");
    let fx = fixture(1);
    let o = {
        let store = open_patient(&db);
        provision(&store, &fx, 1);
        reserve(&store, &fx).unwrap()
    };
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|w| {
            let barrier = Arc::clone(&barrier);
            let path = db.path();
            let attempt = o.attempt.clone();
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                let fx = fixture(1);
                barrier.wait();
                store.start_attempt(&StartCommand {
                    attempt: &attempt,
                    owner: &format!("worker-{w}"),
                    actor: &actor(),
                    now: NOW + 1,
                    lease_secs: LEASE,
                    observed: Some(&fx.obs),
                    max_state_age_secs: MAX_AGE,
                })
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| *e == StoreError::InvalidTransition));
}

#[test]
fn cancel_racing_the_holder_settles_exactly_once() {
    for round in 0..10 {
        let db = TempDb::new("conc-cancel");
        let fx = fixture(1);
        let (o, lease) = {
            let store = open_patient(&db);
            provision(&store, &fx, 1);
            let o = reserve(&store, &fx).unwrap();
            let lease = store
                .start_attempt(&StartCommand {
                    attempt: &o.attempt,
                    owner: "worker-a",
                    actor: &actor(),
                    now: NOW + 1,
                    lease_secs: LEASE,
                    observed: Some(&fx.obs),
                    max_state_age_secs: MAX_AGE,
                })
                .unwrap();
            store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
            (o, lease)
        };
        let barrier = Arc::new(Barrier::new(2));
        let holder = {
            let (barrier, path, lease) = (Arc::clone(&barrier), db.path(), lease.clone());
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                barrier.wait();
                store.finish(
                    &lease,
                    ExecutionOutcome::Failed,
                    ReasonCode::ExecutionFailed,
                    &actor(),
                    NOW + 3,
                )
            })
        };
        let canceller = {
            let (barrier, path, attempt) = (Arc::clone(&barrier), db.path(), o.attempt.clone());
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                barrier.wait();
                store.cancel(&attempt, &actor(), ReasonCode::Cancelled, NOW + 3)
            })
        };
        let (h, c) = (holder.join().unwrap(), canceller.join().unwrap());
        // Whichever commits first wins; the other is refused or idempotent.
        assert!(h.is_ok() || c.is_ok(), "round {round}");
        let store = open_patient(&db);
        let st = status(&store, &fx);
        assert_eq!(
            (st.held, st.consumed, st.refunded),
            (0, 1, 0),
            "round {round}"
        );
        let a = store.attempt(&o.attempt).unwrap().unwrap();
        assert!(matches!(a.state, RunState::Failed | RunState::Cancelled));
        store.integrity_check().unwrap();
    }
}

#[test]
fn shared_store_handle_is_safe_across_threads() {
    let db = TempDb::new("conc-shared");
    let store = Arc::new(open_patient(&db));
    provision(&store, &fixture(1), 4);
    let handles: Vec<_> = (1..=16u32)
        .map(|n| {
            let store = Arc::clone(&store);
            thread::spawn(move || reserve(&store, &fixture(n)).unwrap().state)
        })
        .collect();
    let reserved = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|s| *s == RunState::Reserved)
        .count();
    assert_eq!(reserved, 4);
    store.integrity_check().unwrap();
}
