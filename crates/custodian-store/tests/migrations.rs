//! Migration rules: forward-only, checksum-verified, atomic, and a newer or
//! tampered schema is refused rather than reinterpreted. Also file
//! permissions and the open-time checks.

#![cfg(unix)]

mod common;

use common::*;
use custodian_store::migrations::{self, Migration, APPLICATION_ID, MIGRATIONS};
use custodian_store::secure_fs::mode_of;
use custodian_store::{SqliteStore, StoreConfig, StoreError};

/// A synthetic migration after the last real one (the real list has six).
const V2: Migration = Migration {
    version: 7,
    name: "synthetic-add-note",
    sql: "CREATE TABLE synthetic_note (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT;",
};

fn v1_and_v2() -> Vec<Migration> {
    let mut v = MIGRATIONS.to_vec();
    v.push(V2);
    v
}

#[test]
fn fresh_database_is_created_at_the_latest_version_with_identity() {
    let db = TempDb::new("mig-fresh");
    let store = open(&db);
    assert_eq!(
        store.schema_version().unwrap(),
        migrations::latest_version()
    );
    drop(store);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    let app: i64 = raw
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .unwrap();
    assert_eq!(app, APPLICATION_ID);
    let mode: String = raw
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let (v, sum): (i64, String) = raw
        .query_row("SELECT version, checksum FROM schema_migrations", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(v, 1);
    assert_eq!(sum, MIGRATIONS[0].checksum());
    assert_eq!(sum.len(), 64);
}

#[test]
fn reopening_is_a_no_op_and_keeps_state() {
    let db = TempDb::new("mig-reopen");
    let fx = fixture(1);
    {
        let store = open(&db);
        provision(&store, &fx, 2);
        reserve(&store, &fx).unwrap();
    }
    let store = open(&db);
    assert_eq!(status(&store, &fx).held, 1);
    let n: i64 = rusqlite::Connection::open(db.path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(usize::try_from(n).unwrap(), MIGRATIONS.len());
}

#[test]
fn forward_upgrade_applies_only_pending_migrations_and_keeps_data() {
    let db = TempDb::new("mig-upgrade");
    let fx = fixture(1);
    {
        let store = open(&db);
        provision(&store, &fx, 2);
        reserve(&store, &fx).unwrap();
    }
    let store = SqliteStore::open_with(db.path(), StoreConfig::default(), &v1_and_v2()).unwrap();
    assert_eq!(store.schema_version().unwrap(), 7);
    assert_eq!(status(&store, &fx).held, 1);
    store.integrity_check().unwrap();
}

#[test]
fn a_newer_schema_is_refused_not_reinterpreted() {
    let db = TempDb::new("mig-newer");
    {
        SqliteStore::open_with(db.path(), StoreConfig::default(), &v1_and_v2()).unwrap();
    }
    // The v1-only binary must refuse the v2 database.
    let err = SqliteStore::open(db.path()).err().unwrap();
    assert_eq!(err, StoreError::SchemaTooNew);
}

#[test]
fn a_tampered_or_divergent_migration_is_refused() {
    let db = TempDb::new("mig-tamper");
    drop(open(&db));
    // A different build whose migration 1 has different bytes.
    let edited = [Migration {
        version: 1,
        name: "initial",
        sql: "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;",
    }];
    let err = SqliteStore::open_with(db.path(), StoreConfig::default(), &edited)
        .err()
        .unwrap();
    assert_eq!(err, StoreError::MigrationChecksum);

    // Direct tampering with the recorded checksum is equally refused.
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute("UPDATE schema_migrations SET checksum = 'x'", [])
            .unwrap();
    }
    assert_eq!(
        SqliteStore::open(db.path()).err().unwrap(),
        StoreError::MigrationChecksum
    );
}

#[test]
fn a_gap_in_applied_versions_is_refused() {
    let db = TempDb::new("mig-gap");
    {
        SqliteStore::open_with(db.path(), StoreConfig::default(), &v1_and_v2()).unwrap();
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute("DELETE FROM schema_migrations WHERE version = 1", [])
            .unwrap();
    }
    assert_eq!(
        SqliteStore::open_with(db.path(), StoreConfig::default(), &v1_and_v2())
            .err()
            .unwrap(),
        StoreError::MigrationChecksum
    );
}

#[test]
fn a_failing_migration_rolls_back_completely() {
    let db = TempDb::new("mig-fail");
    let fx = fixture(1);
    {
        let store = open(&db);
        provision(&store, &fx, 1);
    }
    let bad = Migration {
        version: 7,
        name: "synthetic-bad",
        sql: "CREATE TABLE synthetic_half (id INTEGER); SELECT * FROM table_that_does_not_exist;",
    };
    let mut list = MIGRATIONS.to_vec();
    list.push(bad);
    assert_eq!(
        SqliteStore::open_with(db.path(), StoreConfig::default(), &list)
            .err()
            .unwrap(),
        StoreError::MigrationFailed
    );
    // Still at the last real version, nothing half-applied, data intact.
    let store = open(&db);
    assert_eq!(
        store.schema_version().unwrap(),
        migrations::latest_version()
    );
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    let n: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'synthetic_half'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(status(&store, &fx).limit, 1);
}

#[test]
fn a_malformed_migration_list_is_refused() {
    let db = TempDb::new("mig-list");
    let skipped = [MIGRATIONS[0], Migration { version: 4, ..V2 }];
    assert_eq!(
        SqliteStore::open_with(db.path(), StoreConfig::default(), &skipped)
            .err()
            .unwrap(),
        StoreError::MigrationFailed
    );
}

#[test]
fn a_foreign_sqlite_file_is_not_adopted() {
    let db = TempDb::new("mig-foreign");
    std::fs::create_dir(db.dir()).unwrap();
    set_mode(db.dir(), 0o700);
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute_batch("CREATE TABLE unrelated (x INTEGER);")
            .unwrap();
    }
    set_mode(&db.path(), 0o600);
    assert_eq!(
        SqliteStore::open(db.path()).err().unwrap(),
        StoreError::NotAStore
    );
}

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn files_and_directory_are_owner_only_and_wider_modes_are_refused() {
    let db = TempDb::new("perm");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    reserve(&store, &fx).unwrap(); // makes -wal and -shm exist
    assert_eq!(mode_of(db.dir()).unwrap(), 0o700);
    assert_eq!(mode_of(&db.path()).unwrap(), 0o600);
    for suffix in ["-wal", "-shm"] {
        let side = std::path::PathBuf::from(format!("{}{suffix}", db.path().display()));
        if side.exists() {
            assert_eq!(mode_of(&side).unwrap() & 0o077, 0, "{suffix}");
        }
    }
    drop(store);

    // A group/world-readable database file is refused, not silently chmodded.
    set_mode(&db.path(), 0o640);
    assert_eq!(
        SqliteStore::open(db.path()).err().unwrap(),
        StoreError::Permissions
    );
    assert_eq!(mode_of(&db.path()).unwrap(), 0o640);
    set_mode(&db.path(), 0o600);

    // A group/world-accessible directory is refused.
    set_mode(db.dir(), 0o750);
    assert_eq!(
        SqliteStore::open(db.path()).err().unwrap(),
        StoreError::Permissions
    );
    set_mode(db.dir(), 0o700);

    // A symlink in place of the database is refused.
    let link = db.dir().join("link.db");
    std::os::unix::fs::symlink(db.path(), &link).unwrap();
    assert_eq!(
        SqliteStore::open(&link).err().unwrap(),
        StoreError::Permissions
    );
    open(&db).integrity_check().unwrap();
}

#[test]
fn backup_is_owner_only_consistent_and_a_stale_restore_is_blocked() {
    let db = TempDb::new("backup");
    let restored = TempDb::new("restored");
    let fx = fixture(1);
    let store = open(&db);
    provision(&store, &fx, 3);
    reserve(&store, &fx).unwrap();

    let snapshot_dir = TempDb::new("snapshot");
    let snapshot = snapshot_dir.path();
    store.backup_to(&snapshot).unwrap();
    assert_eq!(mode_of(&snapshot).unwrap(), 0o600);
    // Refuses to overwrite.
    assert_eq!(store.backup_to(&snapshot).unwrap_err(), StoreError::Io);

    // Work continues after the backup: a second reservation is exported and
    // the checkpoint recorded outside the database (the private ledger).
    let fx2 = fixture(2);
    reserve(&store, &fx2).unwrap();
    let external = store.latest_checkpoint().unwrap().unwrap();
    assert_eq!(status(&store, &fx).held, 2);

    // "Restore" the old snapshot as the live database.
    std::fs::create_dir(restored.dir()).unwrap();
    set_mode(restored.dir(), 0o700);
    std::fs::copy(&snapshot, restored.path()).unwrap();
    set_mode(&restored.path(), 0o600);
    let old = SqliteStore::open(restored.path()).unwrap();
    old.integrity_check().unwrap();
    // The restored copy understates consumption (held 1 instead of 2).
    assert_eq!(status(&old, &fx).held, 1);

    // The checkpoint comparison catches it and the store refuses to run.
    assert_eq!(
        old.verify_external_checkpoint(&external).unwrap_err(),
        StoreError::NeedsReconcile
    );
    assert!(old.needs_reconcile().unwrap());
    assert_eq!(
        reserve(&old, &fixture(3)).unwrap_err(),
        StoreError::NeedsReconcile
    );
    assert_eq!(
        old.recover(&actor(), NOW + 10_000).unwrap_err(),
        StoreError::NeedsReconcile
    );
    // The block is persistent across restarts.
    drop(old);
    let old = SqliteStore::open(restored.path()).unwrap();
    assert!(old.needs_reconcile().unwrap());

    // The live database matches its own checkpoint.
    store.verify_external_checkpoint(&external).unwrap();
    assert!(!store.needs_reconcile().unwrap());

    // Only an explicit, audited operator action lifts the block.
    old.clear_reconcile(&actor(), NOW + 20_000).unwrap();
    assert!(!old.needs_reconcile().unwrap());
    assert!(old
        .outbox_pending(100)
        .unwrap()
        .iter()
        .any(|e| e.kind == "store.reconciled"));
}
