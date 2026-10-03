//! R-1 (ADR 0130): accepting a restore loss in the store. The tail a ledger
//! would supply is produced here by a donor store that kept running; a copy
//! taken earlier plays the restored store. Synthetic data only; functional
//! verification, not an independent protected evaluation.

mod common;

use std::collections::BTreeMap;

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_core::{ActorId, Contamination, ReasonCode};
use custodian_store::{
    budget_scope_key, LossAcceptCommand, LossEpoch, LossEvent, LossOutcome, LossRefusal,
    SqliteStore, StartCommand, StoreError,
};

fn run_to_completion(store: &SqliteStore, fx: &Fx, at: u64) {
    let o = reserve(store, fx).unwrap();
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner: "worker-a",
            actor: &actor(),
            now: at + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    store.record_exposure(&lease, &actor(), at + 2).unwrap();
    store.begin_validation(&lease, &actor(), at + 3).unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            at + 4,
        )
        .unwrap();
}

/// The donor's events after `from` as a ledger would hand them over.
fn tail_of(donor: &SqliteStore, from: u64) -> Vec<LossEvent> {
    let last = donor.latest_checkpoint().unwrap().unwrap().seq;
    ((from + 1)..=last)
        .map(|seq| {
            let e = donor.outbox_event(seq).unwrap().unwrap();
            LossEvent {
                seq: e.seq,
                event_id: e.event_id,
                kind: e.kind,
                request_id: e.request_id,
                attempt_id: e.attempt_id,
                payload: e.payload,
                payload_digest: e.payload_digest,
                chain: e.chain,
                created_at: e.created_at,
                export_ref: format!("ledger/rec-audit-{seq:032x}"),
            }
        })
        .collect()
}

fn digest(label: &str) -> String {
    format!("sha256:{}", dg(label).trim_start_matches("sha256:"))
}

/// The temporary directories are held only to keep the databases alive.
#[allow(dead_code)]
struct Scene {
    donor_db: TempDb,
    restored_db: TempDb,
    donor: SqliteStore,
    restored: SqliteStore,
    fx: Fx,
    before: u64,
}

/// A donor that ran request 1 to completion after the copy was taken.
fn scene() -> Scene {
    let donor_db = TempDb::new("loss-donor");
    let donor = open(&donor_db);
    let fx = fixture(1);
    provision(&donor, &fx, 5);
    let restored_db = TempDb::new("loss-restored");
    // The copy is taken after provisioning and before any spend.
    donor.backup_to(&restored_db.path()).unwrap();
    let before = donor.latest_checkpoint().unwrap().unwrap().seq;
    run_to_completion(&donor, &fx, NOW);
    let restored = SqliteStore::open(restored_db.path()).unwrap();
    restored.block_for_reconcile().unwrap();
    Scene {
        donor_db,
        restored_db,
        donor,
        restored,
        fx,
        before,
    }
}

fn consumed_map(fx: &Fx, units: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([(
        budget_scope_key(BudgetKind::Run, &fx.scope()).unwrap(),
        units,
    )])
}

fn accept<'a>(
    s: &'a Scene,
    events: &'a [LossEvent],
    consumed: &'a BTreeMap<String, u64>,
    epochs: &'a [LossEpoch],
    plan: &'a str,
    actor: &'a ActorId,
) -> LossAcceptCommand<'a> {
    let _ = s;
    LossAcceptCommand {
        plan_digest: plan,
        events,
        ledger_consumed: consumed,
        epochs,
        actor,
        now: NOW + 100,
    }
}

#[test]
fn the_ledger_tail_is_adopted_byte_for_byte_and_budgets_only_rise() {
    let s = scene();
    assert_eq!(status(&s.restored, &s.fx).consumed, 0);
    let events = tail_of(&s.donor, s.before);
    assert!(events.len() >= 4);
    let consumed = consumed_map(&s.fx, 1);
    let epochs = [LossEpoch {
        epoch_id: id("epo_", 1),
        corpus_id: id("cor_", 1),
        family_id: None,
        floor: Some(Contamination::Exposed),
        retire: true,
    }];
    let who = actor();
    let plan = digest("plan-1");
    let out = s
        .restored
        .accept_ledger_loss(&accept(&s, &events, &consumed, &epochs, &plan, &who))
        .unwrap();
    let LossOutcome::Accepted(rep) = out else {
        panic!("{out:?}")
    };
    assert!(!rep.replay);
    assert_eq!(rep.adopted_events, events.len() as u64);
    assert_eq!((rep.recovered_scopes, rep.recovered_units), (1, 1));
    assert_eq!((rep.epochs_flagged, rep.epochs_retired), (1, 1));

    // The block is cleared in the same transaction; the chain is the donor's.
    assert!(!s.restored.needs_reconcile().unwrap());
    for e in &events {
        let mine = s.restored.outbox_event(e.seq).unwrap().unwrap();
        assert_eq!(
            (mine.chain.as_str(), mine.payload_digest.as_str()),
            (e.chain.as_str(), e.payload_digest.as_str())
        );
        assert_eq!(mine.export_ref.as_deref(), Some(e.export_ref.as_str()));
        assert!(mine.exported_at.is_some());
    }
    // Budgets only rose, and the invariants (including the new unit sums and
    // the audit event of the acceptance) hold.
    assert_eq!(status(&s.restored, &s.fx).consumed, 1);
    s.restored.integrity_check().unwrap();
    // The standing is what the ledger stated, plus the retirement.
    let st = s
        .restored
        .epoch_standing(&id("epo_", 1))
        .unwrap()
        .unwrap()
        .standing;
    assert!(st.retired);
    assert_eq!(st.contamination, Contamination::Exposed);
    assert_eq!(
        s.restored.check_epoch_usable(&id("epo_", 1)),
        Err(StoreError::EpochBlocked)
    );
    // The acceptance and the recovery are audited and pending export.
    let kinds: Vec<String> = s
        .restored
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(kinds.contains(&"store.loss_accepted".to_owned()));
    assert!(kinds.contains(&"budget.recovered".to_owned()));
    // The donor's own checkpoint is now contained.
    let tip = s.donor.latest_checkpoint().unwrap().unwrap();
    assert!(s.restored.contains_checkpoint(&tip).unwrap());
}

#[test]
fn the_same_plan_again_changes_nothing() {
    let s = scene();
    let events = tail_of(&s.donor, s.before);
    let consumed = consumed_map(&s.fx, 1);
    let who = actor();
    let plan = digest("plan-2");
    let cmd = accept(&s, &events, &consumed, &[], &plan, &who);
    assert!(matches!(
        s.restored.accept_ledger_loss(&cmd).unwrap(),
        LossOutcome::Accepted(r) if !r.replay
    ));
    let latest = s.restored.latest_checkpoint().unwrap().unwrap();
    let again = s.restored.accept_ledger_loss(&cmd).unwrap();
    assert!(matches!(again, LossOutcome::Accepted(r) if r.replay));
    assert_eq!(s.restored.latest_checkpoint().unwrap().unwrap(), latest);
    assert_eq!(status(&s.restored, &s.fx).consumed, 1);
    assert!(s.restored.loss_accepted(&plan).unwrap());
    s.restored.integrity_check().unwrap();
}

#[test]
fn a_tail_that_does_not_extend_the_stores_own_chain_is_refused_and_nothing_is_written() {
    let s = scene();
    let consumed = consumed_map(&s.fx, 1);
    let who = actor();
    let plan = digest("plan-3");
    let good = tail_of(&s.donor, s.before);
    let blocked_checkpoint = s.restored.latest_checkpoint().unwrap().unwrap();

    let refuse = |events: &[LossEvent]| {
        let out = s
            .restored
            .accept_ledger_loss(&accept(&s, events, &consumed, &[], &plan, &who))
            .unwrap();
        let LossOutcome::Refused(why) = out else {
            panic!("accepted")
        };
        why
    };

    // Empty, or a skipped event.
    assert_eq!(refuse(&[]), LossRefusal::InvalidPlan);
    assert_eq!(refuse(&good[1..]), LossRefusal::NotContiguous);
    let mut gap = good.clone();
    gap.remove(1);
    assert_eq!(refuse(&gap), LossRefusal::NotContiguous);
    // A payload that does not hash to its digest.
    let mut forged = good.clone();
    forged[0].payload = forged[0].payload.replace("\"at\"", "\"zz\"");
    assert_eq!(refuse(&forged), LossRefusal::ChainMismatch);
    // A chain value that is not the one the store's chain produces.
    let mut chain = good.clone();
    chain[1].chain = "0".repeat(64);
    assert_eq!(refuse(&chain), LossRefusal::ChainMismatch);
    // A tail from another store's history: a different prefix, other chain.
    let other_db = TempDb::new("loss-other");
    let other = open(&other_db);
    let ofx = fixture(1);
    provision(&other, &ofx, 6);
    run_to_completion(&other, &ofx, NOW);
    let foreign: Vec<LossEvent> = tail_of(&other, s.before);
    assert_eq!(refuse(&foreign), LossRefusal::ChainMismatch);

    // Nothing changed: still blocked, same checkpoint, budget untouched.
    assert!(s.restored.needs_reconcile().unwrap());
    assert_eq!(
        s.restored.latest_checkpoint().unwrap().unwrap(),
        blocked_checkpoint
    );
    assert_eq!(status(&s.restored, &s.fx).consumed, 0);
    assert!(!s.restored.loss_accepted(&plan).unwrap());
}

#[test]
fn consumption_beyond_the_limit_saturates_the_budget_instead_of_exceeding_it() {
    let s = scene();
    let events = tail_of(&s.donor, s.before);
    // The ledger shows far more consumed than the restored limit allows
    // (the limit was raised in the lost window, for instance).
    let consumed = consumed_map(&s.fx, 50);
    let who = actor();
    let plan = digest("plan-4");
    let out = s
        .restored
        .accept_ledger_loss(&accept(&s, &events, &consumed, &[], &plan, &who))
        .unwrap();
    let LossOutcome::Accepted(rep) = out else {
        panic!("{out:?}")
    };
    assert_eq!((rep.recovered_units, rep.saturated_scopes), (5, 1));
    let st = status(&s.restored, &s.fx);
    assert_eq!((st.consumed, st.held, st.available()), (5, 0, 0));
    s.restored.integrity_check().unwrap();
}

#[test]
fn a_scope_the_store_never_heard_of_starts_consumed_when_it_is_provisioned() {
    let s = scene();
    let events = tail_of(&s.donor, s.before);
    // A second scope that exists only in the lost window.
    let other = fixture_with(2, Scope::Lineage(9), 1, 0, "synthetic-candidate-2");
    let key = budget_scope_key(BudgetKind::Run, &other.scope()).unwrap();
    let mut consumed = consumed_map(&s.fx, 1);
    consumed.insert(key, 3);
    let who = actor();
    let plan = digest("plan-5");
    assert!(matches!(
        s.restored
            .accept_ledger_loss(&accept(&s, &events, &consumed, &[], &plan, &who))
            .unwrap(),
        LossOutcome::Accepted(r) if r.recovered_scopes == 2
    ));
    s.restored.integrity_check().unwrap();
    // Provisioning it later cannot hand back the units: it starts with 3 consumed.
    s.restored
        .provision_budget(BudgetKind::Run, &other.scope(), 4, &actor(), NOW + 200)
        .unwrap();
    let st = status(&s.restored, &other);
    assert_eq!((st.limit, st.consumed, st.available()), (4, 3, 1));
    s.restored.integrity_check().unwrap();
    // A limit below the recovered consumption cannot be provisioned at all.
    let low = fixture_with(4, Scope::Lineage(7), 1, 0, "synthetic-candidate-4");
    let mut more = consumed_map(&s.fx, 1);
    more.insert(budget_scope_key(BudgetKind::Run, &low.scope()).unwrap(), 6);
    // (Recorded through a store that has not yet adopted a tail: reuse the
    // donor's copy so the same refusal path is exercised.)
    let db2 = TempDb::new("loss-restored-2");
    let donor2 = open(&TempDb::new("loss-donor-2"));
    let fx2 = fixture(1);
    provision(&donor2, &fx2, 5);
    donor2.backup_to(&db2.path()).unwrap();
    let before2 = donor2.latest_checkpoint().unwrap().unwrap().seq;
    run_to_completion(&donor2, &fx2, NOW);
    let restored2 = SqliteStore::open(db2.path()).unwrap();
    restored2.block_for_reconcile().unwrap();
    let ev2 = tail_of(&donor2, before2);
    let plan2 = digest("plan-6");
    assert!(matches!(
        restored2
            .accept_ledger_loss(&accept(&s, &ev2, &more, &[], &plan2, &who))
            .unwrap(),
        LossOutcome::Accepted(_)
    ));
    assert!(restored2
        .provision_budget(BudgetKind::Run, &low.scope(), 2, &actor(), NOW + 200)
        .is_err());
    restored2
        .provision_budget(BudgetKind::Run, &low.scope(), 6, &actor(), NOW + 200)
        .unwrap();
    assert_eq!(status(&restored2, &low).available(), 0);
    restored2.integrity_check().unwrap();
}
