//! Audit outbox: terminal state, settlement and export intent commit together;
//! acknowledgement is idempotent; a failed export keeps disclosure closed.

mod common;

use common::*;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_core::ports::Refusal;
use custodian_core::{ReasonCode, RunState};
use custodian_store::{AckOutcome, StartCommand, StoreError};
use serde_json::Value;

fn complete(store: &custodian_store::SqliteStore, fx: &Fx) -> custodian_store::Settlement {
    let o = reserve(store, fx).unwrap();
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
    store.begin_validation(&lease, &actor(), NOW + 3).unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 4,
        )
        .unwrap()
}

#[test]
fn terminal_state_settlement_and_export_intent_share_one_commit() {
    let db = TempDb::new("ob-atomic");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    let s = complete(&store, &fx);

    let ev = store.outbox_event(s.outbox_seq).unwrap().unwrap();
    assert_eq!(ev.kind, "attempt.terminal");
    assert_eq!(ev.event_id, format!("terminal:{}", s.attempt.as_str()));
    let p: Value = serde_json::from_str(&ev.payload).unwrap();
    assert_eq!(p["prior_state"], "validating");
    assert_eq!(p["state"], "completed");
    assert_eq!(p["settlement"], "consumed");
    assert_eq!(p["exposure"], "exposed");
    assert_eq!(p["authorization_ref"], fx.apr.approval_id.as_str());
    // Bounded vocabulary: no free text, and no candidate or population detail.
    let text = ev.payload.to_lowercase();
    assert!(!text.contains("synthetic-candidate"));
    assert!(!text.contains("cor_synthetic"));
    assert!(ev.exported_at.is_none());

    // Every state-changing step produced an event, in order, chained.
    let kinds: Vec<_> = store
        .outbox_pending(100)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            "budget.provisioned",
            "reservation.created",
            "attempt.started",
            "exposure.recorded",
            "attempt.terminal"
        ]
    );
    store.verify_invariants().unwrap();
}

#[test]
fn ack_is_idempotent_and_never_rewrites() {
    let db = TempDb::new("ob-ack");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    complete(&store, &fx);
    let first = store.outbox_pending(1).unwrap();
    assert_eq!(first.len(), 1);
    let seq = first[0].seq;

    assert_eq!(
        store.outbox_ack(seq, "ledger:e1", NOW + 10).unwrap(),
        AckOutcome::Acked
    );
    assert_eq!(
        store.outbox_ack(seq, "ledger:e1", NOW + 11).unwrap(),
        AckOutcome::AlreadyAcked
    );
    // A different reference is refused, not overwritten.
    assert_eq!(
        store.outbox_ack(seq, "ledger:other", NOW + 12).unwrap_err(),
        StoreError::IdentityConflict
    );
    let ev = store.outbox_event(seq).unwrap().unwrap();
    assert_eq!(ev.export_ref.as_deref(), Some("ledger:e1"));
    assert_eq!(ev.exported_at, Some(NOW + 10));
    assert_eq!(
        store.outbox_ack(9999, "ledger:x", NOW).unwrap_err(),
        StoreError::NotFound
    );
    let long = "x".repeat(129);
    for bad in ["", "has space", "semi;colon", long.as_str()] {
        assert_eq!(
            store.outbox_ack(seq, bad, NOW).unwrap_err(),
            StoreError::InvalidInput
        );
    }
    // Acked events leave the pending list; the rest stay in sequence order.
    let rest = store.outbox_pending(100).unwrap();
    assert!(rest.iter().all(|e| e.seq != seq));
    assert!(rest.windows(2).all(|w| w[0].seq < w[1].seq));
    store.verify_invariants().unwrap();
}

#[test]
fn export_failure_keeps_disclosure_closed() {
    let db = TempDb::new("ob-disclose");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let s = complete(&store, &fx);

    // Completed and settled, but the audit export has not happened.
    assert_eq!(
        store.check_disclosure_precondition(&s.attempt).unwrap_err(),
        Refusal(ReasonCode::DisclosureNotPermitted)
    );
    // Acknowledging an unrelated event does not open it.
    let first = store.outbox_pending(1).unwrap()[0].seq;
    store.outbox_ack(first, "ledger:e0", NOW + 10).unwrap();
    assert!(store.check_disclosure_precondition(&s.attempt).is_err());
    // Only the durable export of the terminal event does.
    store
        .outbox_ack(s.outbox_seq, "ledger:e1", NOW + 11)
        .unwrap();
    store.check_disclosure_precondition(&s.attempt).unwrap();

    // A cancelled run is never disclosable, exported or not.
    let fx2 = fixture(2);
    let o = reserve(&store, &fx2).unwrap();
    let cancelled = store
        .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 20)
        .unwrap();
    store
        .outbox_ack(cancelled.outbox_seq, "ledger:e2", NOW + 21)
        .unwrap();
    assert_eq!(
        store.attempt(&o.attempt).unwrap().unwrap().state,
        RunState::Cancelled
    );
    assert!(store.check_disclosure_precondition(&o.attempt).is_err());
    // Unknown attempts are refused.
    assert!(store
        .check_disclosure_precondition(&custodian_core::RunId::new("nope"))
        .is_err());
}

#[test]
fn outbox_chain_detects_edits() {
    let db = TempDb::new("ob-chain");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    complete(&store, &fx);
    let cp = store.latest_checkpoint().unwrap().unwrap();
    assert_eq!(cp.seq, 5);
    store.verify_invariants().unwrap();
    drop(store);

    // Bypass the append-only triggers (as an attacker with file access could)
    // and edit a payload: the chain check names it.
    {
        let raw = rusqlite::Connection::open(db.path()).unwrap();
        raw.execute_batch("DROP TRIGGER outbox_ack_only;").unwrap();
        raw.execute("UPDATE outbox SET payload = '{}' WHERE seq = 2", [])
            .unwrap();
    }
    let store = open(&db);
    assert_eq!(
        store.verify_invariants().unwrap_err(),
        StoreError::Invariant("outbox_chain")
    );
}

#[test]
fn deterministic_event_ids_make_redelivery_harmless() {
    let db = TempDb::new("ob-dedupe");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    let s = complete(&store, &fx);
    let before = store.latest_checkpoint().unwrap().unwrap();
    // Repeating terminal operations adds no events.
    reserve(&store, &fx).unwrap();
    store
        .cancel(&s.attempt, &actor(), ReasonCode::Cancelled, NOW + 9)
        .unwrap_err();
    assert_eq!(store.latest_checkpoint().unwrap().unwrap(), before);
}
