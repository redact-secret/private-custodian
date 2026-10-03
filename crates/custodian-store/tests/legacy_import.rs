//! HG-3: legacy consumption import into the runtime budget store
//! (ADR 0102, ADR 0115). Synthetic identities and counts only.
//!
//! Properties pinned here: an import can only add; it is idempotent by
//! (record id, digest); a conflicting re-import is refused and recorded;
//! ambiguity leaves no headroom; a batch is all-or-none; the invariant check
//! sees a hand-edited import; a crash at either commit boundary leaves
//! nothing or everything; concurrent applies and reservations never exceed the
//! limit.

mod common;

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_core::RunState;
use custodian_store::migrations::MIGRATIONS;
use custodian_store::{
    FaultInjector, FaultOp, FaultPhase, FaultPoint, ImportOutcome, ImportRefusal,
    LegacyImportCommand, LegacyImportItem, SqliteStore, StoreConfig, StoreError,
};

const HANDOFF: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REPORT: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SOURCE: &str = "holdout|credential|pop=synthetic-pop/epoch=synthetic-epoch/family=-";

fn import_id(n: u32) -> String {
    format!("lgi_{n:032x}")
}

fn digest(n: u32) -> String {
    format!("sha256:{n:064x}")
}

fn item(fx: &Fx, n: u32, consumed: u64, limit: Option<u64>, exhausted: bool) -> LegacyImportItem {
    LegacyImportItem {
        import_id: import_id(n),
        record_digest: digest(n),
        source_scope_key: SOURCE.to_owned(),
        scope: fx.scope(),
        consumed,
        declared_limit: limit,
        exhausted,
    }
}

fn apply(
    store: &SqliteStore,
    items: &[LegacyImportItem],
    now: u64,
) -> Result<ImportOutcome, StoreError> {
    store.apply_legacy_imports(&LegacyImportCommand {
        items,
        handoff_digest: HANDOFF,
        report_digest: REPORT,
        actor: &actor(),
        now,
    })
}

fn applied(o: ImportOutcome) -> custodian_store::ImportReport {
    match o {
        ImportOutcome::Applied(r) => r,
        other => panic!("expected applied, got {other:?}"),
    }
}

fn refused(o: ImportOutcome) -> ImportRefusal {
    match o {
        ImportOutcome::Refused { reason, .. } => reason,
        other => panic!("expected refused, got {other:?}"),
    }
}

fn kinds(store: &SqliteStore) -> Vec<String> {
    store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

#[test]
fn a_first_import_creates_the_budget_at_the_declared_limit_with_the_consumed_units() {
    let db = TempDb::new("imp-create");
    let store = open(&db);
    let fx = fixture(1);
    let r = applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
    assert_eq!((r.created, r.superseded, r.already_applied), (1, 0, 0));
    assert_eq!(r.applied_units, 2);
    let st = status(&store, &fx);
    assert_eq!((st.limit, st.consumed, st.held, st.refunded), (5, 2, 0, 0));
    assert_eq!(st.available(), 3);
    assert_eq!(store.imported_units(&fx.scope()).unwrap(), (2, 1));
    // Audited: the budget creation and the import, both pending export.
    let k = kinds(&store);
    assert!(k.contains(&"budget.provisioned".to_owned()));
    assert!(k.contains(&"budget.imported".to_owned()));
    // The remaining units are really usable and the next one is really not.
    assert_eq!(reserve(&store, &fx).unwrap().state, RunState::Reserved);
    store.integrity_check().unwrap();
}

#[test]
fn replay_is_idempotent_and_writes_nothing() {
    let db = TempDb::new("imp-replay");
    let store = open(&db);
    let fx = fixture(1);
    let items = [item(&fx, 1, 2, Some(5), false)];
    applied(apply(&store, &items, NOW).unwrap());
    let before = (status(&store, &fx), store.latest_checkpoint().unwrap());
    for t in 1..4 {
        let r = applied(apply(&store, &items, NOW + t).unwrap());
        assert_eq!((r.created, r.superseded, r.already_applied), (0, 0, 1));
        assert_eq!(r.applied_units, 0);
    }
    assert_eq!(
        before,
        (status(&store, &fx), store.latest_checkpoint().unwrap())
    );
    assert_eq!(store.imported_units(&fx.scope()).unwrap(), (2, 1));
    store.integrity_check().unwrap();
}

#[test]
fn an_import_never_lowers_resets_or_refunds_anything() {
    let db = TempDb::new("imp-monotone");
    let store = open(&db);
    let fx = fixture(1);
    applied(apply(&store, &[item(&fx, 1, 3, Some(5), false)], NOW).unwrap());
    let base = status(&store, &fx);

    // A newer record that states fewer consumed units.
    let lower = item(&fx, 2, 1, Some(5), false);
    assert_eq!(
        refused(apply(&store, &[lower], NOW + 1).unwrap()),
        ImportRefusal::WouldReduceConsumption
    );
    // A newer record that changes the stated limit.
    let relimit = item(&fx, 3, 3, Some(9), false);
    assert_eq!(
        refused(apply(&store, &[relimit], NOW + 2).unwrap()),
        ImportRefusal::WouldChangeLimit
    );
    // A record that "un-exhausts" an exhausted scope.
    let exhausted = item(&fx, 4, 5, Some(5), true);
    applied(apply(&store, &[exhausted], NOW + 3).unwrap());
    let reopened = item(&fx, 5, 5, Some(5), false);
    assert_eq!(
        refused(apply(&store, &[reopened], NOW + 4).unwrap()),
        ImportRefusal::WouldReduceConsumption
    );

    let st = status(&store, &fx);
    assert_eq!(st.consumed, 5);
    assert!(st.consumed >= base.consumed && st.limit >= base.limit && st.refunded == 0);
    // Every refusal was recorded and exportable.
    let refusals = kinds(&store)
        .iter()
        .filter(|k| *k == "budget.import_refused")
        .count();
    assert_eq!(refusals, 3);
    store.integrity_check().unwrap();
}

#[test]
fn consumed_units_never_decrease_over_any_sequence_of_records() {
    let db = TempDb::new("imp-seq");
    let store = open(&db);
    let fx = fixture(1);
    let mut last = 0;
    // A deterministic zig-zag of totals; lower ones must be refused.
    for (i, total) in [1u64, 3, 2, 3, 0, 4, 4, 2, 5, 1].iter().enumerate() {
        let n = u32::try_from(i).unwrap() + 1;
        let out = apply(
            &store,
            &[item(&fx, n, *total, Some(6), false)],
            NOW + u64::from(n),
        )
        .unwrap();
        match out {
            ImportOutcome::Applied(_) => assert!(*total >= last),
            ImportOutcome::Refused { .. } => assert!(*total < last),
        }
        let now = status(&store, &fx).consumed;
        assert!(now >= last, "consumed went from {last} to {now}");
        last = now;
    }
    assert_eq!(last, 5);
    store.integrity_check().unwrap();
}

#[test]
fn a_newer_record_adds_only_the_difference() {
    let db = TempDb::new("imp-diff");
    let store = open(&db);
    let fx = fixture(1);
    applied(apply(&store, &[item(&fx, 1, 2, Some(6), false)], NOW).unwrap());
    let r = applied(apply(&store, &[item(&fx, 2, 4, Some(6), false)], NOW + 1).unwrap());
    assert_eq!((r.created, r.superseded, r.applied_units), (0, 1, 2));
    assert_eq!(status(&store, &fx).consumed, 4);
    // The older record is still a no-op, never a re-add.
    applied(apply(&store, &[item(&fx, 1, 2, Some(6), false)], NOW + 2).unwrap());
    assert_eq!(status(&store, &fx).consumed, 4);
    assert_eq!(store.imported_units(&fx.scope()).unwrap(), (4, 2));
    store.integrity_check().unwrap();
}

#[test]
fn ambiguous_or_unknown_limit_leaves_no_headroom() {
    // New budget, limit unknown: exhausted at the imported figure.
    let db = TempDb::new("imp-ambiguous-new");
    let store = open(&db);
    let fx = fixture(1);
    applied(apply(&store, &[item(&fx, 1, 0, None, true)], NOW).unwrap());
    let st = status(&store, &fx);
    assert_eq!((st.limit, st.consumed, st.available()), (0, 0, 0));
    let denied = reserve(&store, &fx).unwrap();
    assert_eq!(denied.state, RunState::Denied);

    // An existing, larger runtime budget is exhausted too: the remaining
    // headroom becomes consumed, so nothing about the ambiguity is "free".
    let db = TempDb::new("imp-ambiguous-existing");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 7);
    applied(apply(&store, &[item(&fx, 1, 0, None, true)], NOW).unwrap());
    let st = status(&store, &fx);
    assert_eq!((st.limit, st.consumed, st.available()), (7, 7, 0));
    assert_eq!(store.imported_units(&fx.scope()).unwrap(), (7, 1));
    assert_eq!(reserve(&store, &fx).unwrap().state, RunState::Denied);
    store.integrity_check().unwrap();
}

#[test]
fn an_import_cannot_exceed_the_runtime_limit_and_does_not_raise_it_silently() {
    let db = TempDb::new("imp-exceeds");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let out = apply(&store, &[item(&fx, 1, 3, None, false)], NOW).unwrap();
    assert_eq!(refused(out), ImportRefusal::ExceedsLimit);
    let st = status(&store, &fx);
    assert_eq!((st.limit, st.consumed), (2, 0));
    // The declared limit may raise the runtime limit, never lower it.
    applied(apply(&store, &[item(&fx, 2, 3, Some(4), false)], NOW + 1).unwrap());
    let st = status(&store, &fx);
    assert_eq!((st.limit, st.consumed), (4, 3));
    store.integrity_check().unwrap();
}

#[test]
fn a_conflicting_reimport_with_different_bytes_is_refused_and_recorded() {
    let db = TempDb::new("imp-conflict");
    let store = open(&db);
    let fx = fixture(1);
    applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
    let mut forged = item(&fx, 1, 2, Some(5), false);
    forged.record_digest = digest(99);
    let out = apply(&store, &[forged], NOW + 1).unwrap();
    assert_eq!(refused(out), ImportRefusal::DigestConflict);
    assert_eq!(status(&store, &fx).consumed, 2);
    let ev = store
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "budget.import_refused")
        .expect("recorded");
    assert!(ev.payload.contains("digest_conflict"));
    assert!(ev.payload.contains(&import_id(1)));
    // Re-presenting the same conflicting bytes records nothing new.
    let mut again = item(&fx, 1, 2, Some(5), false);
    again.record_digest = digest(99);
    refused(apply(&store, &[again], NOW + 2).unwrap());
    assert_eq!(
        kinds(&store)
            .iter()
            .filter(|k| *k == "budget.import_refused")
            .count(),
        1
    );
    store.integrity_check().unwrap();
}

#[test]
fn a_batch_is_all_or_none() {
    let db = TempDb::new("imp-batch");
    let store = open(&db);
    let fx1 = fixture(1);
    let fx2 = fixture_with(2, Scope::Lineage(1), 1, 0, "synthetic-candidate-2");
    // The second item is invalid (consumed is not a possible total here).
    let mut bad = item(&fx2, 2, 1, Some(2), false);
    bad.source_scope_key = "blind|credential|cand=synthetic/epoch=synthetic-epoch".to_owned();
    bad.import_id = "lgi_not-a-valid-id".to_owned();
    let good = item(&fx1, 1, 2, Some(5), false);
    assert_eq!(
        refused(apply(&store, &[good.clone(), bad.clone()], NOW).unwrap()),
        ImportRefusal::InvalidItem
    );
    assert!(store
        .budget_status(BudgetKind::Run, &fx1.scope())
        .unwrap()
        .is_none());
    assert_eq!(store.imported_units(&fx1.scope()).unwrap(), (0, 0));
    // Fixed, the same batch applies completely.
    bad.import_id = import_id(2);
    let r = applied(apply(&store, &[good, bad], NOW + 1).unwrap());
    assert_eq!(r.created, 2);
    assert_eq!(status(&store, &fx1).consumed, 2);
    assert_eq!(status(&store, &fx2).consumed, 1);
    store.integrity_check().unwrap();
}

#[test]
fn the_legacy_scope_and_the_custodian_budget_stay_bound_one_to_one() {
    let db = TempDb::new("imp-binding");
    let store = open(&db);
    let fx1 = fixture(1);
    let fx2 = fixture_with(2, Scope::Lineage(1), 1, 0, "synthetic-candidate-2");
    applied(apply(&store, &[item(&fx1, 1, 1, Some(3), false)], NOW).unwrap());
    // The same legacy scope aimed at another custodian budget.
    let moved = item(&fx2, 2, 1, Some(3), false);
    assert_eq!(
        refused(apply(&store, &[moved], NOW + 1).unwrap()),
        ImportRefusal::ScopeBindingConflict
    );
    // Another legacy scope aimed at the same custodian budget.
    let mut other = item(&fx1, 3, 2, Some(3), false);
    other.source_scope_key = "holdout|credential|pop=other/epoch=other/family=-".to_owned();
    assert_eq!(
        refused(apply(&store, &[other], NOW + 2).unwrap()),
        ImportRefusal::ScopeBindingConflict
    );
    // Two different items for one budget in one call.
    let mut a = item(&fx2, 4, 1, Some(3), false);
    a.source_scope_key = "blind|credential|cand=synthetic/epoch=synthetic-epoch".to_owned();
    let mut b = item(&fx2, 5, 2, Some(3), false);
    b.source_scope_key = a.source_scope_key.clone();
    assert_eq!(
        refused(apply(&store, &[a, b], NOW + 3).unwrap()),
        ImportRefusal::DuplicateInBatch
    );
    store.integrity_check().unwrap();
}

#[test]
fn imported_consumption_is_visible_to_the_invariant_check_and_a_hand_edit_is_caught() {
    let db = TempDb::new("imp-invariant");
    {
        let store = open(&db);
        let fx = fixture(1);
        applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
        store.integrity_check().unwrap();
    }
    // Edit the import row after removing its guard (an attacker with file
    // access): the counter and the ledger of imports now disagree.
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute_batch("DROP TRIGGER budget_imports_immutable;")
            .unwrap();
        raw.execute("UPDATE budget_imports SET applied_units = 1", [])
            .unwrap();
    }
    let store = open(&db);
    assert_eq!(
        store.verify_invariants().err(),
        Some(StoreError::Invariant("budget_counters_match_reservations"))
    );

    // Editing the counter up (allowed by the budget trigger) is caught as well.
    let db = TempDb::new("imp-invariant-2");
    {
        let store = open(&db);
        let fx = fixture(1);
        applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
    }
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute("UPDATE budgets SET consumed_units = consumed_units + 1", [])
            .unwrap();
    }
    assert!(open(&db).verify_invariants().is_err());

    // An import row without its audit event is caught.
    let db = TempDb::new("imp-invariant-3");
    {
        let store = open(&db);
        let fx = fixture(1);
        applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
    }
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute_batch("DROP TRIGGER outbox_ack_only;").unwrap();
        raw.execute(
            "UPDATE outbox SET event_id = 'x:' || seq WHERE kind = 'budget.imported'",
            [],
        )
        .unwrap();
    }
    assert!(open(&db).verify_invariants().is_err());
}

#[test]
fn imports_and_their_rows_cannot_be_updated_or_deleted() {
    let db = TempDb::new("imp-append-only");
    let store = open(&db);
    let fx = fixture(1);
    applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
    drop(store);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw
        .execute("UPDATE budget_imports SET legacy_units = 0", [])
        .is_err());
    assert!(raw.execute("DELETE FROM budget_imports", []).is_err());
    assert!(raw
        .execute("UPDATE budgets SET consumed_units = 0", [])
        .is_err());
}

// ---- crash injection ---------------------------------------------------------

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
fn a_crash_at_either_commit_boundary_leaves_nothing_or_everything() {
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        let db = TempDb::new("imp-crash");
        let fx = fixture(1);
        let arm = Arc::new(Arm::default());
        let items = [item(&fx, 1, 2, Some(5), false)];
        {
            let store = SqliteStore::open_with_config(
                db.path(),
                StoreConfig::default().with_fault(arm.clone()),
            )
            .unwrap();
            *arm.0.lock().unwrap() = Some(FaultPoint {
                op: FaultOp::ApplyLegacyImport,
                phase,
            });
            let err = apply(&store, &items, NOW).err().unwrap();
            assert_eq!(
                err,
                StoreError::InjectedCrash(FaultPoint {
                    op: FaultOp::ApplyLegacyImport,
                    phase
                })
            );
        }
        let store = open(&db);
        match phase {
            FaultPhase::BeforeCommit => {
                assert!(store
                    .budget_status(BudgetKind::Run, &fx.scope())
                    .unwrap()
                    .is_none());
                assert_eq!(store.imported_units(&fx.scope()).unwrap(), (0, 0));
                assert!(store.outbox_pending(10).unwrap().is_empty());
            }
            FaultPhase::AfterCommit => {
                assert_eq!(status(&store, &fx).consumed, 2);
                assert_eq!(store.imported_units(&fx.scope()).unwrap(), (2, 1));
            }
        }
        // Either way a replay converges to exactly one application.
        applied(apply(&store, &items, NOW + 1).unwrap());
        assert_eq!(status(&store, &fx).consumed, 2);
        assert_eq!(store.imported_units(&fx.scope()).unwrap(), (2, 1));
        store.integrity_check().unwrap();
    }
}

// ---- concurrency -------------------------------------------------------------

#[test]
fn concurrent_applies_and_reservations_never_exceed_the_limit_or_double_apply() {
    const THREADS: u32 = 12;
    let db = TempDb::new("imp-conc");
    {
        let store = open(&db);
        provision(&store, &fixture(1), 5);
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
                if n % 2 == 0 {
                    // Half the threads apply the same record (3 of 5 units).
                    let out = apply(&store, &[item(&fx, 1, 3, Some(5), false)], NOW + 1).unwrap();
                    matches!(out, ImportOutcome::Applied(_))
                } else {
                    // The others race to reserve.
                    reserve(&store, &fx).unwrap();
                    true
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let store = open(&db);
    let fx = fixture(1);
    let st = status(&store, &fx);
    // Whatever the interleaving, the import was applied at most once and the
    // limit held. Applications that found no room were refused, not forced.
    let (units, rows) = store.imported_units(&fx.scope()).unwrap();
    assert!(rows <= 1 && units == 3 * rows, "units {units} rows {rows}");
    assert!(st.held + st.consumed <= st.limit);
    assert_eq!(st.consumed, units);
    store.integrity_check().unwrap();
}

// ---- migration and restore ---------------------------------------------------

#[test]
fn a_database_at_version_four_upgrades_and_keeps_its_data() {
    let db = TempDb::new("imp-upgrade");
    let fx = fixture(1);
    let four = &MIGRATIONS[..4];
    {
        let store = SqliteStore::open_with(db.path(), StoreConfig::default(), four).unwrap();
        assert_eq!(store.schema_version().unwrap(), 4);
        provision(&store, &fx, 3);
        reserve(&store, &fx).unwrap();
    }
    let store = open(&db);
    assert_eq!(
        store.schema_version().unwrap(),
        u32::try_from(MIGRATIONS.len()).unwrap()
    );
    assert_eq!(status(&store, &fx).held, 1);
    // The new table works on the upgraded database.
    applied(apply(&store, &[item(&fx, 1, 1, Some(3), false)], NOW).unwrap());
    assert_eq!(status(&store, &fx).consumed, 1);
    store.integrity_check().unwrap();
}

#[test]
fn restoring_a_backup_older_than_an_import_is_detected_against_the_checkpoint() {
    let db = TempDb::new("imp-restore");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 5);
    let older = db.dir().join("older.db");
    store.backup_to(&older).unwrap();
    applied(apply(&store, &[item(&fx, 1, 2, Some(5), false)], NOW).unwrap());
    let cp = store.latest_checkpoint().unwrap().unwrap();
    // The import is an outbox event like any other state change: a copy that
    // predates it does not contain the checkpoint and is write-blocked.
    let restored = SqliteStore::open(&older).unwrap();
    assert_eq!(
        restored.verify_external_checkpoint(&cp).err(),
        Some(StoreError::NeedsReconcile)
    );
    assert!(restored.needs_reconcile().unwrap());
    assert_eq!(
        reserve(&restored, &fx).err(),
        Some(StoreError::NeedsReconcile)
    );
}
