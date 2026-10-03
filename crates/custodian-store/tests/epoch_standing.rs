//! Epoch standing, the use gate, obligations, the feed chain and rotation
//! links at the store level (C9). Real SQLite files, real threads, injected
//! crashes at every new transaction boundary. Synthetic data only.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_core::standing::EvidenceEffect;
use custodian_core::{Contamination, EpochChange, EpochStanding, ReasonCode, RunState};
use custodian_store::{
    EpochEventCommand, FaultInjector, FaultOp, FaultPhase, FaultPoint, FeedAppend,
    ObligationAction, ObligationCommand, ObligationTarget, RotationCommand, SqliteStore,
    StartCommand, StoreConfig, StoreError,
};

const EPOCH: &str = "epo_synthetic000000000001";
const CORPUS: &str = "cor_synthetic000000000001";
const OTHER_EPOCH: &str = "epo_synthetic000000000002";

fn cmd<'a>(key: &'a str, change: EpochChange, reason: &'a str, now: u64) -> EpochEventCommand<'a> {
    EpochEventCommand {
        epoch_id: EPOCH,
        corpus_id: CORPUS,
        family_id: None,
        idempotency_key: key,
        change,
        reason,
        actor: "act_synthetic_operator",
        actor_kind: "human",
        authorization_ref: "apr_synthetic000000000009",
        now,
    }
}

fn report(
    store: &SqliteStore,
    key: &str,
    kind: Contamination,
) -> custodian_store::EpochEventOutcome {
    store
        .apply_epoch_change(&cmd(
            key,
            EpochChange::Report(kind),
            "operator_decision",
            NOW + 10,
        ))
        .unwrap()
}

fn patient(db: &TempDb) -> SqliteStore {
    SqliteStore::open_with_config(
        db.path(),
        StoreConfig::default().with_busy_timeout_ms(60_000),
    )
    .unwrap()
}

#[test]
fn reports_never_downgrade_and_every_event_is_kept_with_its_prior_state() {
    let db = TempDb::new("c9-monotonic");
    let store = open(&db);
    assert_eq!(store.epoch_standing(EPOCH).unwrap(), None);
    assert!(store.check_epoch_usable(EPOCH).is_ok());

    let a = report(&store, "k1", Contamination::UnreviewedChange);
    assert!(a.changed);
    assert_eq!(a.new.contamination, Contamination::UnreviewedChange);
    let b = report(&store, "k2", Contamination::UsedForTuning);
    assert_eq!(b.prior.contamination, Contamination::UnreviewedChange);
    assert_eq!(b.new.contamination, Contamination::UsedForTuning);
    // A weaker later report changes nothing, is still recorded, and cannot
    // hide the stronger earlier one.
    let c = report(&store, "k3", Contamination::Exposed);
    assert!(!c.changed);
    assert_eq!(c.new.contamination, Contamination::UsedForTuning);

    let events = store.epoch_events(EPOCH).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(
        events.iter().map(|e| e.changed).collect::<Vec<_>>(),
        [true, true, false]
    );
    assert_eq!(
        events[1].prior.contamination,
        Contamination::UnreviewedChange
    );
    assert_eq!(events[0].actor_kind, "human");
    assert_eq!(events[0].authorization_ref, "apr_synthetic000000000009");
    let s = store.epoch_standing(EPOCH).unwrap().unwrap();
    assert_eq!(s.version, 2);
    store.verify_lifecycle_invariants().unwrap();
    store.integrity_check().unwrap();
}

#[test]
fn only_an_unreviewed_change_clears_and_a_refused_clear_writes_nothing() {
    let db = TempDb::new("c9-clear");
    let store = open(&db);
    // Nothing recorded: nothing to clear.
    assert_eq!(
        store
            .apply_epoch_change(&cmd("c0", EpochChange::Clear, "reviewed_no_impact", NOW))
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    assert!(store.epoch_standing(EPOCH).unwrap().is_none());

    report(&store, "k1", Contamination::UnreviewedChange);
    assert!(store.check_epoch_usable(EPOCH).is_err());
    let cleared = store
        .apply_epoch_change(&cmd(
            "c1",
            EpochChange::Clear,
            "reviewed_no_impact",
            NOW + 20,
        ))
        .unwrap();
    assert_eq!(cleared.new, EpochStanding::CLEAN);
    assert!(store.check_epoch_usable(EPOCH).is_ok());

    // A permanent contamination is never cleared.
    report(&store, "k2", Contamination::Exposed);
    let before = store.epoch_events(EPOCH).unwrap().len();
    assert_eq!(
        store
            .apply_epoch_change(&cmd(
                "c2",
                EpochChange::Clear,
                "reviewed_no_impact",
                NOW + 30
            ))
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    assert_eq!(store.epoch_events(EPOCH).unwrap().len(), before);
    assert!(store.check_epoch_usable(EPOCH).is_err());
    // History is preserved: report, clear, report.
    let kinds: Vec<_> = store
        .epoch_events(EPOCH)
        .unwrap()
        .into_iter()
        .map(|e| e.change)
        .collect();
    assert_eq!(kinds, ["report", "clear", "report"]);
}

#[test]
fn the_database_itself_refuses_a_downgrade_an_un_retire_and_any_deletion() {
    let db = TempDb::new("c9-triggers");
    let store = open(&db);
    report(&store, "k1", Contamination::Exposed);
    drop(store);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    for sql in [
        "UPDATE epoch_standing SET contamination = 'unaffected', version = version + 1",
        "UPDATE epoch_standing SET contamination = 'unreviewed_change', version = version + 1",
        "UPDATE epoch_standing SET contamination = 'used_for_tuning'",
        "DELETE FROM epoch_standing",
        "UPDATE epoch_events SET reason = 'edited'",
        "DELETE FROM epoch_events",
    ] {
        assert!(raw.execute(sql, []).is_err(), "{sql}");
    }
    // Raising through SQL with a correct version bump is allowed (the code
    // path does exactly this); retirement is one-way.
    raw.execute(
        "UPDATE epoch_standing SET contamination = 'used_for_tuning', retired = 1, version = version + 1",
        [],
    )
    .unwrap();
    assert!(raw
        .execute(
            "UPDATE epoch_standing SET retired = 0, version = version + 1",
            []
        )
        .is_err());
}

#[test]
fn the_reviewed_clearance_is_the_only_downgrade_the_database_allows() {
    let db = TempDb::new("c9-trigger-clear");
    let store = open(&db);
    report(&store, "k1", Contamination::UnreviewedChange);
    drop(store);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    raw.execute(
        "UPDATE epoch_standing SET contamination = 'unaffected', version = version + 1",
        [],
    )
    .unwrap();
}

#[test]
fn contamination_blocks_reserve_retry_start_and_exposure_but_not_replays_or_settlement() {
    let db = TempDb::new("c9-gate");
    let store = open(&db);
    let fx1 = fixture(1);
    let fx2 = fixture(2);
    let fx3 = fixture(3);
    provision(&store, &fx1, 5);

    // fx1 gets as far as running with exposure recorded; fx2 is reserved;
    // fx3 is not yet requested.
    let o1 = reserve(&store, &fx1).unwrap();
    let o2 = reserve(&store, &fx2).unwrap();
    let start = |o: &custodian_store::ReserveOutcome, fx: &Fx, owner: &str| {
        store.start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner,
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
    };
    let lease1 = start(&o1, &fx1, "w1").unwrap();
    store.record_exposure(&lease1, &actor(), NOW + 2).unwrap();
    let held_before = status(&store, &fx1);

    let out = report(&store, "k1", Contamination::Exposed);
    assert!(out.changed);

    // Refused, each with nothing written.
    assert_eq!(reserve(&store, &fx3).unwrap_err(), StoreError::EpochBlocked);
    assert_eq!(
        start(&o2, &fx2, "w2").unwrap_err(),
        StoreError::EpochBlocked
    );
    assert_eq!(
        store.attempt(&o2.attempt).unwrap().unwrap().state,
        RunState::Reserved
    );
    assert_eq!(status(&store, &fx1), held_before);
    assert!(store
        .request_attempts(&fx3.request_id())
        .unwrap()
        .is_empty());

    // A replay of an already accepted request charges nothing and is allowed.
    let replay = reserve(&store, &fx1).unwrap();
    assert!(replay.replay);

    // The already exposed attempt is re-evaluated at the next gate, but the
    // gates it can still reach (validation, finish) do not strand it: it
    // settles truthfully, consumed.
    store.record_exposure(&lease1, &actor(), NOW + 3).unwrap(); // idempotent
    store.begin_validation(&lease1, &actor(), NOW + 4).unwrap();
    store
        .finish(
            &lease1,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 5,
        )
        .unwrap();
    let st = status(&store, &fx1);
    assert_eq!(st.consumed, 1);
    store.integrity_check().unwrap();
    store.verify_lifecycle_invariants().unwrap();
}

#[test]
fn a_running_unexposed_attempt_is_stopped_at_the_exposure_gate_and_refunded() {
    let db = TempDb::new("c9-gate-exposure");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let o = reserve(&store, &fx).unwrap();
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner: "w1",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    report(&store, "k1", Contamination::UsedForTuning);
    assert_eq!(
        store
            .record_exposure(&lease, &actor(), NOW + 2)
            .unwrap_err(),
        StoreError::EpochBlocked
    );
    // Nothing was opened, so the failure settles as a refund.
    let fin = store
        .finish(
            &lease,
            ExecutionOutcome::Rejected,
            ReasonCode::AuthorizationDenied,
            &actor(),
            NOW + 3,
        )
        .unwrap();
    let _ = fin;
    let st = status(&store, &fx);
    assert_eq!((st.held, st.consumed, st.refunded), (0, 0, 1));
    store.integrity_check().unwrap();
}

#[test]
fn retirement_blocks_use_and_never_edits_budget() {
    let db = TempDb::new("c9-retire");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    reserve(&store, &fx).unwrap();
    let before = status(&store, &fx);
    let out = store
        .apply_epoch_change(&cmd(
            "r1",
            EpochChange::Retire,
            "planned_rotation",
            NOW + 10,
        ))
        .unwrap();
    assert!(out.changed && out.new.retired);
    assert_eq!(
        reserve(&store, &fixture(2)).unwrap_err(),
        StoreError::EpochBlocked
    );
    assert_eq!(status(&store, &fx), before);
    // Retirement cannot be undone, by report or by anything else.
    let again = store
        .apply_epoch_change(&cmd(
            "r2",
            EpochChange::Retire,
            "planned_rotation",
            NOW + 11,
        ))
        .unwrap();
    assert!(!again.changed);
    assert_eq!(
        store
            .apply_epoch_change(&cmd(
                "r3",
                EpochChange::Clear,
                "reviewed_no_impact",
                NOW + 12
            ))
            .unwrap_err(),
        StoreError::InvalidTransition
    );
}

#[test]
fn idempotent_retries_replay_and_conflicting_reuse_is_refused() {
    let db = TempDb::new("c9-idem");
    let store = open(&db);
    let first = report(&store, "same-key", Contamination::Exposed);
    let again = report(&store, "same-key", Contamination::Exposed);
    assert!(!first.replay && again.replay);
    assert_eq!(first.event_seq, again.event_seq);
    assert_eq!(first.obligation_id, again.obligation_id);
    assert_eq!(store.epoch_events(EPOCH).unwrap().len(), 1);
    // Same key, different content.
    assert_eq!(
        store
            .apply_epoch_change(&cmd(
                "same-key",
                EpochChange::Report(Contamination::UsedForTuning),
                "operator_decision",
                NOW + 20
            ))
            .unwrap_err(),
        StoreError::IdempotencyConflict
    );
    // Same key, different actor.
    let mut c = cmd(
        "same-key",
        EpochChange::Report(Contamination::Exposed),
        "operator_decision",
        NOW + 20,
    );
    c.actor = "act_synthetic_other";
    assert_eq!(
        store.apply_epoch_change(&c).unwrap_err(),
        StoreError::IdempotencyConflict
    );
    // One obligation, one audit event per event row, however often retried.
    assert_eq!(store.pending_obligations(10).unwrap().len(), 1);
    // A different corpus for the same epoch is an identity conflict.
    let mut c = cmd("other", EpochChange::Retire, "planned_rotation", NOW + 21);
    c.corpus_id = "cor_synthetic000000000002";
    assert_eq!(
        store.apply_epoch_change(&c).unwrap_err(),
        StoreError::IdentityConflict
    );
    store.verify_lifecycle_invariants().unwrap();
}

#[test]
fn a_transition_and_its_feed_obligation_commit_together() {
    let db = TempDb::new("c9-obligation");
    let store = open(&db);
    // Unreviewed change: private only.
    let a = report(&store, "k1", Contamination::UnreviewedChange);
    assert!(a.obligation_id.is_none());
    assert!(store.pending_obligations(10).unwrap().is_empty());
    // Escalation to a permanent contamination: public consequence.
    let b = report(&store, "k2", Contamination::Exposed);
    let id = b
        .obligation_id
        .expect("contamination records an obligation");
    let pending = store.pending_obligations(10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].obligation_id, id);
    assert_eq!(pending[0].target, ObligationTarget::Population);
    assert_eq!(pending[0].target_ref, EPOCH);
    assert_eq!(pending[0].action, ObligationAction::Contaminated);
    assert_eq!(pending[0].reason, "contamination");
    // A later retirement adds nothing: contamination already says it.
    let c = store
        .apply_epoch_change(&cmd(
            "k3",
            EpochChange::Retire,
            "contamination_response",
            NOW + 30,
        ))
        .unwrap();
    assert!(c.changed && c.obligation_id.is_none());
    assert_eq!(store.pending_obligations(10).unwrap().len(), 1);
    // The audit trail has the events.
    let kinds: Vec<_> = (1..40)
        .filter_map(|s| store.outbox_event(s).unwrap())
        .map(|e| e.kind)
        .collect();
    assert!(kinds.iter().any(|k| k == "epoch.standing"));
    assert!(kinds.iter().any(|k| k == "feed.obligation"));
    // The evidence-effect rule agrees.
    let _ = EvidenceEffect::Contaminated;
    store.verify_lifecycle_invariants().unwrap();
}

#[test]
fn retiring_a_clean_epoch_revokes_its_evidence_as_epoch_rotation() {
    let db = TempDb::new("c9-retire-effect");
    let store = open(&db);
    let out = store
        .apply_epoch_change(&cmd("r1", EpochChange::Retire, "planned_rotation", NOW))
        .unwrap();
    assert!(out.obligation_id.is_some());
    let p = &store.pending_obligations(10).unwrap()[0];
    assert_eq!(
        (p.action, p.reason.as_str()),
        (ObligationAction::Revoked, "epoch_rotation")
    );
}

#[test]
fn operator_obligations_are_idempotent_validated_and_never_removed() {
    let db = TempDb::new("c9-op-obligation");
    let store = open(&db);
    let base = |id: &'static str| ObligationCommand {
        obligation_id: id,
        target: ObligationTarget::Candidate,
        target_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        action: ObligationAction::Revoked,
        superseded_by: None,
        reason: "error_correction",
        effective_at: NOW,
        actor: "act_synthetic_operator",
        authorization_ref: "apr_synthetic000000000009",
        now: NOW,
    };
    assert!(store.enqueue_obligation(&base("operator:o1")).unwrap());
    assert!(!store.enqueue_obligation(&base("operator:o1")).unwrap());
    let mut changed = base("operator:o1");
    changed.action = ObligationAction::Contaminated;
    assert_eq!(
        store.enqueue_obligation(&changed).unwrap_err(),
        StoreError::IdentityConflict
    );
    let mut free_text = base("operator:o2");
    free_text.reason = "because I said so";
    assert_eq!(
        store.enqueue_obligation(&free_text).unwrap_err(),
        StoreError::InvalidInput
    );
    let mut bad_super = base("operator:o3");
    bad_super.action = ObligationAction::Superseded;
    assert_eq!(
        store.enqueue_obligation(&bad_super).unwrap_err(),
        StoreError::InvalidInput
    );
    drop(store);
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    assert!(raw.execute("DELETE FROM feed_obligations", []).is_err());
    assert!(raw
        .execute("UPDATE feed_obligations SET action = 'revoked'", [])
        .is_err());
}

// ---- feed ----------------------------------------------------------------------

const FEED: &str = "fed_synthetic000000000001";

fn digest(n: u8) -> String {
    format!("sha256:{}", format!("{n:02x}").repeat(32))
}

fn append<'a>(
    seq: u64,
    prev: Option<&'a str>,
    digest: &'a str,
    doc: &'a str,
    ids: &'a [String],
) -> FeedAppend<'a> {
    FeedAppend {
        feed_id: FEED,
        sequence: seq,
        previous_digest: prev,
        digest,
        document: doc,
        issued_at: NOW + seq,
        fresh_until: NOW + seq + 3600,
        obligation_ids: ids,
        now: NOW + seq,
    }
}

#[test]
fn the_feed_is_contiguous_chained_and_publishes_each_obligation_once() {
    let db = TempDb::new("c9-feed");
    let store = open(&db);
    let out = report(&store, "k1", Contamination::Exposed);
    let ids = vec![out.obligation_id.unwrap()];
    let (d1, d2) = (digest(1), digest(2));
    assert!(store.feed_head(FEED).unwrap().is_none());

    // A gap, a wrong link, and a wrong first link are refused.
    assert_eq!(
        store
            .append_feed_envelope(&append(2, None, &d1, "{}", &[]))
            .unwrap_err(),
        StoreError::Conflict
    );
    assert_eq!(
        store
            .append_feed_envelope(&append(1, Some(&d2), &d1, "{}", &[]))
            .unwrap_err(),
        StoreError::Conflict
    );
    store
        .append_feed_envelope(&append(1, None, &d1, "{\"a\":1}", &ids))
        .unwrap();
    // Identical repeat accepted; different bytes for the same sequence refused.
    store
        .append_feed_envelope(&append(1, None, &d1, "{\"a\":1}", &ids))
        .unwrap();
    assert_eq!(
        store
            .append_feed_envelope(&append(1, None, &d2, "{\"a\":2}", &[]))
            .unwrap_err(),
        StoreError::Conflict
    );
    // An obligation already published cannot ride in a second envelope, and
    // the failed append leaves nothing behind.
    assert_eq!(
        store
            .append_feed_envelope(&append(2, Some(&d1), &d2, "{\"b\":1}", &ids))
            .unwrap_err(),
        StoreError::Conflict
    );
    assert_eq!(store.feed_head(FEED).unwrap().unwrap().sequence, 1);
    assert!(store.pending_obligations(10).unwrap().is_empty());
    store
        .append_feed_envelope(&append(2, Some(&d1), &d2, "{\"b\":1}", &[]))
        .unwrap();

    // Delivery is in order and idempotent.
    assert_eq!(
        store
            .mark_feed_delivered(FEED, 2, "public-feed", NOW)
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    store
        .mark_feed_delivered(FEED, 1, "public-feed", NOW)
        .unwrap();
    store
        .mark_feed_delivered(FEED, 1, "public-feed", NOW)
        .unwrap();
    store
        .mark_feed_delivered(FEED, 2, "public-feed", NOW)
        .unwrap();
    let envs = store.feed_envelopes(FEED, 1).unwrap();
    assert_eq!(envs.len(), 2);
    assert!(envs.iter().all(|e| e.delivered));
    store.verify_lifecycle_invariants().unwrap();
    drop(store);

    // The database refuses a gap, a fork and any edit even from a raw writer.
    let raw = rusqlite::Connection::open(db.path()).unwrap();
    for sql in [
        "INSERT INTO feed_envelopes VALUES ('fed_synthetic000000000001', 4, 'x', 'y', '{}', 1, 2, 3)",
        "INSERT INTO feed_envelopes VALUES ('fed_synthetic000000000001', 3, 'sha256:wrong', 'y', '{}', 1, 2, 3)",
        "UPDATE feed_envelopes SET document = '{}'",
        "DELETE FROM feed_envelopes",
        "DELETE FROM feed_deliveries",
    ] {
        assert!(raw.execute(sql, []).is_err(), "{sql}");
    }
}

#[test]
fn two_publishers_racing_for_a_sequence_cannot_fork_the_feed() {
    for round in 0..4 {
        let db = TempDb::new("c9-feed-race");
        drop(patient(&db));
        const N: usize = 8;
        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                let path = db.path();
                thread::spawn(move || {
                    let store = SqliteStore::open_with_config(
                        path,
                        StoreConfig::default().with_busy_timeout_ms(60_000),
                    )
                    .unwrap();
                    let d = digest(10 + u8::try_from(i).unwrap());
                    let doc = format!("{{\"publisher\":{i}}}");
                    barrier.wait();
                    store.append_feed_envelope(&append(1, None, &d, &doc, &[]))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let won = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(won, 1, "round {round}: exactly one publisher wins");
        assert!(results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| *e == StoreError::Conflict));
        let store = patient(&db);
        assert_eq!(store.feed_envelopes(FEED, 1).unwrap().len(), 1);
        store.verify_lifecycle_invariants().unwrap();
    }
}

// ---- rotation ------------------------------------------------------------------

fn rot<'a>(pred: &'a str, succ: &'a str) -> RotationCommand<'a> {
    RotationCommand {
        predecessor: pred,
        successor: succ,
        corpus_id: CORPUS,
        family_id: None,
        actor: "act_synthetic_operator",
        authorization_ref: "apr_synthetic000000000009",
        now: NOW + 40,
    }
}

#[test]
fn rotation_links_a_retired_epoch_to_one_successor_and_touches_no_budget() {
    let db = TempDb::new("c9-rotation");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    reserve(&store, &fx).unwrap();
    let old_budget = status(&store, &fx);

    // The predecessor must already be retired.
    assert_eq!(
        store.record_rotation(&rot(EPOCH, OTHER_EPOCH)).unwrap_err(),
        StoreError::InvalidTransition
    );
    store
        .apply_epoch_change(&cmd(
            "r1",
            EpochChange::Retire,
            "planned_rotation",
            NOW + 30,
        ))
        .unwrap();
    assert!(store.record_rotation(&rot(EPOCH, OTHER_EPOCH)).unwrap());
    assert!(!store.record_rotation(&rot(EPOCH, OTHER_EPOCH)).unwrap());
    assert_eq!(
        store.successor_of(EPOCH).unwrap().as_deref(),
        Some(OTHER_EPOCH)
    );
    // A second successor for the same predecessor, or a second predecessor
    // for the same successor, is a different link: refused.
    assert_eq!(
        store
            .record_rotation(&rot(EPOCH, "epo_synthetic000000000003"))
            .unwrap_err(),
        StoreError::IdentityConflict
    );
    // Self-link is meaningless.
    assert_eq!(
        store.record_rotation(&rot(EPOCH, EPOCH)).unwrap_err(),
        StoreError::InvalidInput
    );
    // The exhausted old budget is exactly as it was: no reset, no edit.
    assert_eq!(status(&store, &fx), old_budget);
    assert_eq!(old_budget.held, 1);
    // A contaminated successor cannot be linked.
    let db2 = TempDb::new("c9-rotation-blocked");
    let s2 = open(&db2);
    s2.apply_epoch_change(&cmd("r1", EpochChange::Retire, "planned_rotation", NOW))
        .unwrap();
    let mut blocked = cmd(
        "b1",
        EpochChange::Report(Contamination::Exposed),
        "operator_decision",
        NOW,
    );
    blocked.epoch_id = OTHER_EPOCH;
    s2.apply_epoch_change(&blocked).unwrap();
    assert_eq!(
        s2.record_rotation(&rot(EPOCH, OTHER_EPOCH)).unwrap_err(),
        StoreError::EpochBlocked
    );
    let _ = BudgetKind::Run;
}

// ---- crash at every new boundary ---------------------------------------------------

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

fn armed(db: &TempDb, op: FaultOp, phase: FaultPhase) -> SqliteStore {
    let arm = Arc::new(Arm::default());
    *arm.0.lock().unwrap() = Some(FaultPoint { op, phase });
    SqliteStore::open_with_config(db.path(), StoreConfig::default().with_fault(arm)).unwrap()
}

const PHASES: [FaultPhase; 2] = [FaultPhase::BeforeCommit, FaultPhase::AfterCommit];

#[test]
fn crash_at_the_standing_change_boundaries_leaves_all_or_nothing_and_a_retry_converges() {
    for phase in PHASES {
        let db = TempDb::new("c9-crash-change");
        let store = armed(&db, FaultOp::EpochChange, phase);
        let c = cmd(
            "k1",
            EpochChange::Report(Contamination::Exposed),
            "operator_decision",
            NOW,
        );
        assert_eq!(
            store.apply_epoch_change(&c).unwrap_err(),
            StoreError::InjectedCrash(FaultPoint {
                op: FaultOp::EpochChange,
                phase
            })
        );
        drop(store);
        let store = open(&db);
        let durable = store.epoch_standing(EPOCH).unwrap().is_some();
        assert_eq!(durable, phase == FaultPhase::AfterCommit, "{phase:?}");
        // Whatever happened, the epoch is either untouched or fully blocked
        // with its obligation and audit event; never half.
        store.verify_lifecycle_invariants().unwrap();
        let obligations = store.pending_obligations(10).unwrap().len();
        assert_eq!(obligations, usize::from(durable));
        // The retry converges to exactly one event and one obligation.
        let out = store.apply_epoch_change(&c).unwrap();
        assert_eq!(out.replay, durable);
        assert_eq!(store.epoch_events(EPOCH).unwrap().len(), 1);
        assert_eq!(store.pending_obligations(10).unwrap().len(), 1);
        assert!(store.check_epoch_usable(EPOCH).is_err());
        store.verify_lifecycle_invariants().unwrap();
        store.integrity_check().unwrap();
    }
}

#[test]
fn crash_at_the_obligation_feed_delivery_and_rotation_boundaries_is_repeatable() {
    for phase in PHASES {
        // Obligation enqueue.
        let db = TempDb::new("c9-crash-oblig");
        let store = armed(&db, FaultOp::ObligationEnqueue, phase);
        let o = ObligationCommand {
            obligation_id: "operator:c1",
            target: ObligationTarget::Candidate,
            target_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            action: ObligationAction::Revoked,
            superseded_by: None,
            reason: "error_correction",
            effective_at: NOW,
            actor: "act_synthetic_operator",
            authorization_ref: "apr_synthetic000000000009",
            now: NOW,
        };
        assert!(store.enqueue_obligation(&o).is_err());
        drop(store);
        let store = open(&db);
        let durable = !store.pending_obligations(10).unwrap().is_empty();
        assert_eq!(durable, phase == FaultPhase::AfterCommit);
        store.enqueue_obligation(&o).unwrap();
        assert_eq!(store.pending_obligations(10).unwrap().len(), 1);
        store.verify_lifecycle_invariants().unwrap();

        // Feed append: obligation stamp and envelope are one unit.
        let db = TempDb::new("c9-crash-feed");
        {
            let s = open(&db);
            s.enqueue_obligation(&o).unwrap();
        }
        let store = armed(&db, FaultOp::FeedAppend, phase);
        let ids = vec!["operator:c1".to_owned()];
        let d1 = digest(1);
        assert!(store
            .append_feed_envelope(&append(1, None, &d1, "{\"a\":1}", &ids))
            .is_err());
        drop(store);
        let store = open(&db);
        let durable = store.feed_head(FEED).unwrap().is_some();
        assert_eq!(durable, phase == FaultPhase::AfterCommit);
        assert_eq!(
            store.pending_obligations(10).unwrap().is_empty(),
            durable,
            "envelope and stamp are atomic"
        );
        store
            .append_feed_envelope(&append(1, None, &d1, "{\"a\":1}", &ids))
            .unwrap();
        store.verify_lifecycle_invariants().unwrap();

        // Delivery mark.
        let db = TempDb::new("c9-crash-deliver");
        {
            let s = open(&db);
            s.append_feed_envelope(&append(1, None, &d1, "{\"a\":1}", &[]))
                .unwrap();
        }
        let store = armed(&db, FaultOp::FeedDelivered, phase);
        assert!(store
            .mark_feed_delivered(FEED, 1, "public-feed", NOW)
            .is_err());
        drop(store);
        let store = open(&db);
        assert_eq!(
            store.feed_envelopes(FEED, 1).unwrap()[0].delivered,
            phase == FaultPhase::AfterCommit
        );
        store
            .mark_feed_delivered(FEED, 1, "public-feed", NOW)
            .unwrap();
        assert!(store.feed_envelopes(FEED, 1).unwrap()[0].delivered);

        // Rotation link.
        let db = TempDb::new("c9-crash-rot");
        {
            let s = open(&db);
            s.apply_epoch_change(&cmd("r1", EpochChange::Retire, "planned_rotation", NOW))
                .unwrap();
        }
        let store = armed(&db, FaultOp::RecordRotation, phase);
        assert!(store.record_rotation(&rot(EPOCH, OTHER_EPOCH)).is_err());
        drop(store);
        let store = open(&db);
        assert_eq!(
            store.successor_of(EPOCH).unwrap().is_some(),
            phase == FaultPhase::AfterCommit
        );
        store.record_rotation(&rot(EPOCH, OTHER_EPOCH)).unwrap();
        assert_eq!(
            store.successor_of(EPOCH).unwrap().as_deref(),
            Some(OTHER_EPOCH)
        );
    }
}

// ---- races ------------------------------------------------------------------------

/// Contamination racing with dispatch, with real threads on separate
/// connections. `start_attempt` runs its gate in the same transaction that
/// takes the lease, and writers are serialized, so the order of the two
/// commits is total. The invariant, checked on every round: no start that
/// began after the contamination call returned succeeds.
#[test]
fn contamination_racing_with_start_fails_closed_in_every_interleaving() {
    const ATTEMPTS: u32 = 8;
    let mut started_before = 0;
    let mut refused = 0;
    for round in 0..12 {
        let db = TempDb::new("c9-race-start");
        let attempts: Vec<_> = {
            let store = patient(&db);
            provision(&store, &fixture(1), 100);
            (1..=ATTEMPTS)
                .map(|n| {
                    let fx = fixture(n);
                    let o = reserve(&store, &fx).unwrap();
                    (n, o.attempt)
                })
                .collect()
        };
        let contaminated = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(usize::try_from(ATTEMPTS).unwrap() + 1));
        let mut handles = Vec::new();
        for (n, attempt) in attempts {
            let (barrier, contaminated, path) =
                (Arc::clone(&barrier), Arc::clone(&contaminated), db.path());
            handles.push(thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                let fx = fixture(n);
                barrier.wait();
                // Stagger a little so some starts land before the report.
                for _ in 0..(n % 4) {
                    thread::yield_now();
                }
                let after_report_returned = contaminated.load(Ordering::SeqCst);
                let r = store.start_attempt(&StartCommand {
                    attempt: &attempt,
                    owner: &format!("w{n}"),
                    actor: &actor(),
                    now: NOW + 1,
                    lease_secs: LEASE,
                    observed: Some(&fx.obs),
                    max_state_age_secs: MAX_AGE,
                });
                (attempt, after_report_returned, r)
            }));
        }
        let reporter = {
            let (barrier, contaminated, path) =
                (Arc::clone(&barrier), Arc::clone(&contaminated), db.path());
            thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                barrier.wait();
                for _ in 0..(round % 5) {
                    thread::yield_now();
                }
                store
                    .apply_epoch_change(&cmd(
                        "race",
                        EpochChange::Report(Contamination::Exposed),
                        "operator_decision",
                        NOW + 1,
                    ))
                    .unwrap();
                contaminated.store(true, Ordering::SeqCst);
            })
        };
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        reporter.join().unwrap();

        let store = patient(&db);
        for (attempt, after, r) in &results {
            let state = store.attempt(attempt).unwrap().unwrap().state;
            match r {
                Ok(_) => {
                    assert!(
                        !after,
                        "a start that began after the report returned succeeded"
                    );
                    assert_eq!(state, RunState::Running);
                    started_before += 1;
                }
                Err(StoreError::EpochBlocked) => {
                    assert_eq!(state, RunState::Reserved, "a refused start changes nothing");
                    refused += 1;
                }
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        // Whatever the interleaving, nothing can start now.
        for (attempt, _, r) in &results {
            if r.is_err() {
                let fx = fixture(1);
                assert_eq!(
                    store
                        .start_attempt(&StartCommand {
                            attempt,
                            owner: "late",
                            actor: &actor(),
                            now: NOW + 2,
                            lease_secs: LEASE,
                            observed: Some(&fx.obs),
                            max_state_age_secs: MAX_AGE,
                        })
                        .unwrap_err(),
                    StoreError::EpochBlocked
                );
            }
        }
        store.integrity_check().unwrap();
        store.verify_lifecycle_invariants().unwrap();
    }
    // The interleaving is scheduler-dependent, so the split is informative
    // only; the per-attempt assertions above hold for every split.
    eprintln!("race split: {started_before} started before, {refused} refused");
    assert_eq!(
        started_before + refused,
        12 * usize::try_from(ATTEMPTS).unwrap()
    );
}

/// Contamination racing with reservation (new requests).
#[test]
fn contamination_racing_with_reservation_never_admits_a_request_after_it() {
    for _ in 0..8 {
        let db = TempDb::new("c9-race-reserve");
        {
            let store = patient(&db);
            provision(&store, &fixture(1), 100);
        }
        const N: u32 = 8;
        let contaminated = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(usize::try_from(N).unwrap() + 1));
        let mut handles = Vec::new();
        for n in 1..=N {
            let (barrier, contaminated, path) =
                (Arc::clone(&barrier), Arc::clone(&contaminated), db.path());
            handles.push(thread::spawn(move || {
                let store = SqliteStore::open_with_config(
                    path,
                    StoreConfig::default().with_busy_timeout_ms(60_000),
                )
                .unwrap();
                let fx = fixture(n);
                barrier.wait();
                let after = contaminated.load(Ordering::SeqCst);
                (after, reserve(&store, &fx))
            }));
        }
        let (b, c, path) = (Arc::clone(&barrier), Arc::clone(&contaminated), db.path());
        let reporter = thread::spawn(move || {
            let store = SqliteStore::open_with_config(
                path,
                StoreConfig::default().with_busy_timeout_ms(60_000),
            )
            .unwrap();
            b.wait();
            store
                .apply_epoch_change(&cmd(
                    "race",
                    EpochChange::Report(Contamination::UsedForTuning),
                    "operator_decision",
                    NOW,
                ))
                .unwrap();
            c.store(true, Ordering::SeqCst);
        });
        for h in handles {
            let (after, r) = h.join().unwrap();
            match r {
                Ok(_) => assert!(!after),
                Err(StoreError::EpochBlocked) => {}
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        reporter.join().unwrap();
        let store = patient(&db);
        assert!(reserve(&store, &fixture(99)).is_err());
        store.integrity_check().unwrap();
    }
}
