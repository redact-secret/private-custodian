//! Checkpoints, startup check and rollback detection against the real store
//! and the real corpus registry. In-memory ledger, test-generated keys.

mod common;

use common::*;
use custodian_ledger::{
    startup_check, walk_ledger, Exporter, FindingCode, MemoryBackend, StartupRefusal, WriteOutcome,
};
use custodian_store::{SqliteStore, StoreError};

fn export_all(store: &SqliteStore, s: &Setup, backend: &MemoryBackend, now: u64) {
    let ex = Exporter::new(backend, &s.key.signer, &s.verifier);
    ex.export_pending(store, now).unwrap();
    ex.record_store_checkpoint(store, now).unwrap();
}

#[test]
fn startup_passes_on_a_consistent_store_and_ledger() {
    let db = TempDb::new("cp-ok");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&store, &s, &backend, NOW + 10);
    let r = startup_check(&backend, &s.keyring, &store, None).unwrap();
    assert_eq!(r.store_checkpoint, store.latest_checkpoint().unwrap());
    assert!(r.quarantined.is_empty());
}

#[test]
fn first_run_with_an_empty_ledger_is_allowed_and_reports_no_checkpoint() {
    let db = TempDb::new("cp-first");
    let store = open(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    let r = startup_check(&backend, &s.keyring, &store, None).unwrap();
    assert_eq!(r.store_checkpoint, None);
    assert_eq!(r.ledger_records, 0);
}

#[test]
fn a_ledger_that_is_behind_the_store_is_normal() {
    // Events not yet exported: the store is ahead, which is not a rollback.
    let db = TempDb::new("cp-behind");
    let (store, fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&store, &s, &backend, NOW + 10);
    let fx2 = fixture(2);
    provision(&store, &fx2, 3);
    complete(&store, &fx2);
    let _ = fx;
    assert!(startup_check(&backend, &s.keyring, &store, None).is_ok());
}

#[test]
fn restored_older_database_is_refused_and_stays_blocked() {
    let dir = TempDir::new("cp-restore");
    let db = TempDb::new("cp-restore-live");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let first = complete(&store, &fx);
    // Operator takes a backup now.
    let backup_path = dir.path().join("backup").join("store.db");
    store.backup_to(&backup_path).unwrap();

    // Life goes on: more spending and more exported events.
    let fx2 = fixture(2);
    provision(&store, &fx2, 3);
    complete(&store, &fx2);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&store, &s, &backend, NOW + 10);
    let spent = status(&store, &fx2);
    assert!(startup_check(&backend, &s.keyring, &store, None).is_ok());

    // Disaster: the stale backup is restored.
    let restored = SqliteStore::open(&backup_path).unwrap();
    assert!(restored.outbox_event(first.outbox_seq).unwrap().is_some());
    assert!(!restored.needs_reconcile().unwrap());
    let err = startup_check(&backend, &s.keyring, &restored, None).unwrap_err();
    assert_eq!(err, StartupRefusal::StoreRolledBack);
    // The store persisted the block: writes are refused...
    assert!(restored.needs_reconcile().unwrap());
    assert_eq!(
        reserve(&restored, &fx2).unwrap_err(),
        StoreError::NeedsReconcile
    );
    // ...across a restart, and the next startup check refuses too.
    drop(restored);
    let reopened = SqliteStore::open(&backup_path).unwrap();
    assert_eq!(
        startup_check(&backend, &s.keyring, &reopened, None).unwrap_err(),
        StartupRefusal::StoreBlocked
    );
    // The ledger still holds the figures the operator must reconcile to.
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert_eq!(w.store_checkpoint, store.latest_checkpoint().unwrap());
    assert!(spent.consumed > 0);
}

#[test]
fn diverged_database_with_the_same_length_is_refused() {
    // A different history reaching the same sequence number has a different
    // chain value.
    let db_a = TempDb::new("cp-div-a");
    let db_b = TempDb::new("cp-div-b");
    let (a, _fa, _) = populated_store(&db_a);
    let b = open(&db_b);
    let fx = fixture(7);
    provision(&b, &fx, 3);
    complete(&b, &fx);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&a, &s, &backend, NOW + 10);
    assert_eq!(
        startup_check(&backend, &s.keyring, &b, None).unwrap_err(),
        StartupRefusal::StoreRolledBack
    );
}

#[test]
fn unavailable_ledger_refuses_to_serve() {
    let db = TempDb::new("cp-unavail");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&store, &s, &backend, NOW + 10);
    backend.set_available(false);
    assert_eq!(
        startup_check(&backend, &s.keyring, &store, None).unwrap_err(),
        StartupRefusal::LedgerUnavailable
    );
}

#[test]
fn forged_checkpoint_cannot_lower_or_raise_trust() {
    let db = TempDb::new("cp-forged");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&store, &s, &backend, NOW + 10);

    // An attacker with ledger write access adds a checkpoint signed by their
    // own key, claiming a far-future position.
    let rogue = test_key(9, &all_domains(), NOW - 10_000);
    let rogue_ring = custodian_ledger::Keyring::new().with_root(rogue.entry.clone());
    let rogue_verifier = custodian_ledger::Verifier::new(rogue_ring);
    let rogue_backend = MemoryBackend::new();
    let rogue_ex = Exporter::new(&rogue_backend, &rogue.signer, &rogue_verifier);
    let fake = custodian_ledger::LedgerRecord::store_checkpoint(
        &custodian_store::Checkpoint {
            seq: 9_999,
            chain: "e".repeat(64),
        },
        NOW + 99,
    )
    .unwrap();
    assert_eq!(rogue_ex.write_record(&fake).unwrap(), WriteOutcome::Created);
    backend.inject(&fake.path(), &rogue_backend.raw(&fake.path()).unwrap());

    match startup_check(&backend, &s.keyring, &store, None).unwrap_err() {
        StartupRefusal::LedgerUntrusted(f) => assert!(f.iter().any(|f| matches!(
            f.code,
            FindingCode::BadSignature(custodian_ledger::VerifyError::UnknownKey)
        ))),
        other => panic!("{other:?}"),
    }
    // Refusal did not poison the store: the block is only set by a real mismatch.
    assert!(!store.needs_reconcile().unwrap());
}

#[test]
fn quarantined_conflicts_are_reported_but_do_not_block_startup() {
    let db = TempDb::new("cp-quarantine");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    export_all(&store, &s, &backend, NOW + 10);
    backend.inject(
        "quarantine/rec-audit-00000000000000000000000000000000/ab.json",
        b"x",
    );
    let r = startup_check(&backend, &s.keyring, &store, None).unwrap();
    assert_eq!(r.quarantined.len(), 1);
}

#[test]
fn checkpoint_records_are_deterministic_per_observation() {
    let db = TempDb::new("cp-det");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    assert_eq!(
        ex.record_store_checkpoint(&store, NOW + 10).unwrap(),
        Some(WriteOutcome::Created)
    );
    assert_eq!(
        ex.record_store_checkpoint(&store, NOW + 10).unwrap(),
        Some(WriteOutcome::Identical)
    );
    // A later observation is a new record, not a conflict.
    assert_eq!(
        ex.record_store_checkpoint(&store, NOW + 20).unwrap(),
        Some(WriteOutcome::Created)
    );
    assert!(walk_ledger(&backend, &s.keyring).unwrap().is_trustworthy());
    // An empty store has nothing to checkpoint.
    let db2 = TempDb::new("cp-det-empty");
    let empty = open(&db2);
    assert_eq!(ex.record_store_checkpoint(&empty, NOW).unwrap(), None);
}

#[test]
fn registry_rollback_and_divergence_are_detected() {
    let s = setup();
    let backend = MemoryBackend::new();
    let db = TempDb::new("cp-registry");
    let store = open(&db);
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);

    // A registry with two events (sealed, activated), checkpointed.
    let reg = corpus::Fixture::new();
    reg.seal_active(&[("a.bin", b"synthetic-a")]);
    let view = reg.pop.registry().view().unwrap();
    assert_eq!(view.event_count(), 2);
    assert_eq!(
        ex.record_registry_checkpoint(&view, NOW + 10).unwrap(),
        Some(WriteOutcome::Created)
    );
    let r = startup_check(&backend, &s.keyring, &store, Some(&view)).unwrap();
    assert_eq!(r.registry_checked, Some((view.head().clone(), 2)));

    // The registry grows: still contains the checkpointed head.
    reg.seal(&[("b.bin", b"synthetic-b")]);
    let grown = reg.pop.registry().view().unwrap();
    assert!(grown.event_count() > 2);
    assert_eq!(grown.head_after(2).as_ref(), Some(view.head()));
    startup_check(&backend, &s.keyring, &store, Some(&grown)).unwrap();

    // A registry restored to fewer events is a rollback.
    let short = corpus::Fixture::new();
    short.seal(&[("a.bin", b"synthetic-a")]);
    let short_view = short.pop.registry().view().unwrap();
    assert_eq!(short_view.event_count(), 1);
    assert_eq!(
        startup_check(&backend, &s.keyring, &store, Some(&short_view)).unwrap_err(),
        StartupRefusal::RegistryRolledBack
    );

    // A different history with at least as many events has another head.
    let other = corpus::Fixture::new();
    other.seal_active(&[("a.bin", b"synthetic-a")]);
    other.seal(&[("b.bin", b"synthetic-b")]);
    let other_view = other.pop.registry().view().unwrap();
    assert!(other_view.event_count() >= 2);
    assert_eq!(
        startup_check(&backend, &s.keyring, &store, Some(&other_view)).unwrap_err(),
        StartupRefusal::RegistryRolledBack
    );
}

#[test]
fn empty_registry_has_nothing_to_checkpoint() {
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let reg = corpus::Fixture::new();
    let view = reg.pop.registry().view().unwrap();
    assert_eq!(ex.record_registry_checkpoint(&view, NOW).unwrap(), None);
}
