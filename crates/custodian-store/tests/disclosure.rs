//! Release and query budgets and disclosure history (C8).

mod common;

use common::*;
use custodian_store::{ChargeOutcome, ReleaseCharge, ReleaseScope, StoreError};

fn charge<'a>(
    id: &'a str,
    scopes: &'a [ReleaseScope<'a>],
    units: u64,
    actor: &'a custodian_core::ActorId,
) -> ReleaseCharge<'a> {
    ReleaseCharge {
        charge_id: id,
        scopes,
        units,
        actor,
        now: NOW,
    }
}

#[test]
fn charge_is_all_or_nothing_across_scopes_and_never_refunded() {
    let db = TempDb::new("disc-charge");
    let store = open(&db);
    let fx = fixture(1);
    let scope = fx.scope();
    let pop = ReleaseScope::Budget(&scope);
    let req = ReleaseScope::Requester("act_synthetic_operator");
    let a = actor();
    store.provision_release_budget(&pop, 5, &a, NOW).unwrap();
    // The requester scope is not provisioned yet: nothing may be drawn.
    let scopes = [pop.clone(), req.clone()];
    assert_eq!(
        store
            .charge_release_query(&charge("idk_a", &scopes, 1, &a))
            .unwrap(),
        ChargeOutcome::NotProvisioned
    );
    assert_eq!(
        store.release_budget_status(&pop).unwrap().unwrap().consumed,
        0
    );

    store.provision_release_budget(&req, 1, &a, NOW).unwrap();
    assert_eq!(
        store
            .charge_release_query(&charge("idk_a", &scopes, 1, &a))
            .unwrap(),
        ChargeOutcome::Charged
    );
    // Same charge id: a replay, not a second charge.
    assert_eq!(
        store
            .charge_release_query(&charge("idk_a", &scopes, 1, &a))
            .unwrap(),
        ChargeOutcome::Replayed
    );
    assert_eq!(
        store.release_budget_status(&pop).unwrap().unwrap().consumed,
        1
    );
    // The requester scope is now empty, so the population scope must not be
    // charged by the refused attempt either.
    assert_eq!(
        store
            .charge_release_query(&charge("idk_b", &scopes, 1, &a))
            .unwrap(),
        ChargeOutcome::Exhausted
    );
    let st = store.release_budget_status(&pop).unwrap().unwrap();
    assert_eq!((st.consumed, st.refunded), (1, 0));
    // Same id, different shape: refused.
    assert_eq!(
        store
            .charge_release_query(&charge("idk_a", &scopes, 2, &a))
            .err()
            .unwrap(),
        StoreError::IdentityConflict
    );
    // The limit can rise, never fall.
    assert!(store.provision_release_budget(&pop, 1, &a, NOW).is_err());
    store.integrity_check().unwrap();
}

#[test]
fn run_and_release_budgets_are_separate_kinds() {
    let db = TempDb::new("disc-kind");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let scope = fx.scope();
    let pop = ReleaseScope::Budget(&scope);
    let a = actor();
    // A run budget exists for this scope but no release budget: not drawn.
    assert_eq!(
        store
            .charge_release_query(&charge("idk_a", std::slice::from_ref(&pop), 1, &a))
            .unwrap(),
        ChargeOutcome::NotProvisioned
    );
    assert_eq!(status(&store, &fx).consumed, 0);
    assert_ne!(pop.key().unwrap(), status(&store, &fx).scope_key);
}

#[test]
fn charge_audit_is_exported_only_after_ack() {
    let db = TempDb::new("disc-audit");
    let store = open(&db);
    let fx = fixture(1);
    let scope = fx.scope();
    let pop = ReleaseScope::Budget(&scope);
    let a = actor();
    store.provision_release_budget(&pop, 2, &a, NOW).unwrap();
    assert!(!store.charge_audit_exported("idk_a").unwrap());
    store
        .charge_release_query(&charge("idk_a", std::slice::from_ref(&pop), 1, &a))
        .unwrap();
    assert!(!store.charge_audit_exported("idk_a").unwrap());
    for ev in store.outbox_pending(100).unwrap() {
        store.outbox_ack(ev.seq, "ledger/test", NOW).unwrap();
    }
    assert!(store.charge_audit_exported("idk_a").unwrap());
}

#[test]
fn history_appends_are_conditional_idempotent_and_ordered() {
    let db = TempDb::new("disc-history");
    let store = open(&db);
    assert_eq!(
        store
            .append_disclosure_history("series-1", 0, "prj_a", "{}", NOW)
            .unwrap(),
        1
    );
    // Identical repeat: the existing sequence.
    assert_eq!(
        store
            .append_disclosure_history("series-1", 0, "prj_a", "{}", NOW)
            .unwrap(),
        1
    );
    // Same release id, different payload: refused.
    assert_eq!(
        store
            .append_disclosure_history("series-1", 1, "prj_a", "{\"x\":1}", NOW)
            .err()
            .unwrap(),
        StoreError::IdentityConflict
    );
    // A writer that read an older head loses.
    assert_eq!(
        store
            .append_disclosure_history("series-1", 0, "prj_b", "{}", NOW)
            .err()
            .unwrap(),
        StoreError::Conflict
    );
    assert_eq!(
        store
            .append_disclosure_history("series-1", 1, "prj_b", "{}", NOW)
            .unwrap(),
        2
    );
    let h = store.disclosure_history("series-1").unwrap();
    assert_eq!(h.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert!(store.disclosure_history("series-2").unwrap().is_empty());
    store.integrity_check().unwrap();
}

#[test]
fn concurrent_charges_and_history_appends_cannot_overdraw_or_fork() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const LIMIT: u64 = 5;
    const THREADS: u32 = 16;
    let db = TempDb::new("disc-conc");
    let fx = fixture(1);
    let scope = fx.scope();
    {
        let store = open(&db);
        store
            .provision_release_budget(&ReleaseScope::Budget(&scope), LIMIT, &actor(), NOW)
            .unwrap();
    }
    let barrier = Arc::new(Barrier::new(THREADS as usize));
    let handles: Vec<_> = (0..THREADS)
        .map(|n| {
            let barrier = Arc::clone(&barrier);
            let path = db.path();
            let scope = scope.clone();
            thread::spawn(move || {
                let store = custodian_store::SqliteStore::open_with_config(
                    path,
                    custodian_store::StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                let a = actor();
                let id = format!("idk_c{n}");
                let scopes = [ReleaseScope::Budget(&scope)];
                barrier.wait();
                let charged = store
                    .charge_release_query(&charge(&id, &scopes, 1, &a))
                    .unwrap();
                // Everyone also races to append after the same head.
                let appended = store.append_disclosure_history(
                    "series-race",
                    0,
                    &format!("prj_r{n}"),
                    "{}",
                    NOW,
                );
                (charged, appended.is_ok())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let charged = results
        .iter()
        .filter(|(c, _)| *c == ChargeOutcome::Charged)
        .count();
    let appended = results.iter().filter(|(_, a)| *a).count();
    assert_eq!(charged as u64, LIMIT);
    assert_eq!(appended, 1, "exactly one writer wins the append at head 0");
    let store = open(&db);
    let st = store
        .release_budget_status(&ReleaseScope::Budget(&scope))
        .unwrap()
        .unwrap();
    assert_eq!((st.consumed, st.limit), (LIMIT, LIMIT));
    store.integrity_check().unwrap();
}
