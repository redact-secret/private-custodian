//! State machine, idempotency, settlement policy, leases and retries.
//! Synthetic data only; proves mechanism, not protected-corpus quality.

mod common;

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::reservation::ReservationState;
use custodian_contracts::BindingError;
use custodian_contracts::Contract;
use custodian_core::{Exposure, ReasonCode, RunState};
use custodian_store::{Lease, ReserveOutcome, RetryCommand, SqliteStore, StartCommand, StoreError};

fn start(store: &SqliteStore, fx: &Fx, o: &ReserveOutcome, now: u64) -> Result<Lease, StoreError> {
    store.start_attempt(&StartCommand {
        attempt: &o.attempt,
        owner: "worker-a",
        actor: &actor(),
        now,
        lease_secs: LEASE,
        observed: Some(&fx.obs),
        max_state_age_secs: MAX_AGE,
    })
}

fn to_validating(store: &SqliteStore, fx: &Fx, o: &ReserveOutcome) -> Lease {
    let lease = start(store, fx, o, NOW + 1).unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    store.begin_validation(&lease, &actor(), NOW + 3).unwrap();
    lease
}

#[test]
fn happy_path_persists_actor_reason_prior_state_and_authorization() {
    let db = TempDb::new("happy");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    let o = reserve(&store, &fx).unwrap();
    assert_eq!(o.state, RunState::Reserved);
    assert!(!o.replay);
    assert_eq!(status(&store, &fx).held, 1);

    let lease = to_validating(&store, &fx, &o);
    let s = store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 4,
        )
        .unwrap();
    assert_eq!(s.state, RunState::Completed);
    assert_eq!(s.result, ReservationState::Consumed);
    assert_eq!(s.exposure, Exposure::Exposed);

    let st = status(&store, &fx);
    assert_eq!((st.held, st.consumed, st.refunded), (0, 1, 0));

    let h = store.history(&o.attempt).unwrap();
    let path: Vec<_> = h.iter().map(|t| (t.from, t.to, t.is_exposure)).collect();
    use RunState::*;
    assert_eq!(
        path,
        vec![
            (None, Proposed, false),
            (Some(Proposed), Authorized, false),
            (Some(Authorized), Reserved, false),
            (Some(Reserved), Running, false),
            (Some(Running), Running, true),
            (Some(Running), Validating, false),
            (Some(Validating), Completed, false),
        ]
    );
    for (i, t) in h.iter().enumerate() {
        assert_eq!(t.seq, i as u64 + 1);
        assert_eq!(t.authorization_ref, fx.apr.approval_id.as_str());
        assert!(!t.actor.is_empty());
    }
    assert_eq!(h[4].reason, ReasonCode::ProtectedBytesAcquired);
    assert_eq!(h[6].reason, ReasonCode::Completed);

    // The reservation is visible as the C2 contract and is settled.
    let rsv = store.reservation(&s.reservation_id).unwrap().unwrap();
    assert_eq!(rsv.state, ReservationState::Consumed);
    store.integrity_check().unwrap();
}

#[test]
fn unexpected_transitions_are_rejected() {
    let db = TempDb::new("table");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let o = reserve(&store, &fx).unwrap();

    // Cannot run a reservation that was never started; a stale/forged lease is refused.
    let forged = Lease {
        attempt: o.attempt.clone(),
        owner: "worker-a".into(),
        token: 1,
        expires_at: NOW + 999,
    };
    assert_eq!(
        store
            .begin_validation(&forged, &actor(), NOW + 1)
            .unwrap_err(),
        StoreError::LeaseLost
    );

    let lease = start(&store, &fx, &o, NOW + 1).unwrap();
    // Running -> Completed is not in the table (validation is mandatory).
    assert_eq!(
        store
            .finish(
                &lease,
                ExecutionOutcome::Success,
                ReasonCode::Completed,
                &actor(),
                NOW + 2
            )
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    // Running -> Validating requires recorded exposure.
    assert_eq!(
        store
            .begin_validation(&lease, &actor(), NOW + 2)
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    // Running -> Expired is not in the table.
    assert_eq!(
        store
            .finish(
                &lease,
                ExecutionOutcome::Expired,
                ReasonCode::AuthorizationExpired,
                &actor(),
                NOW + 2
            )
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    store.begin_validation(&lease, &actor(), NOW + 3).unwrap();
    // Validating -> Cancelled is not in the table.
    assert_eq!(
        store
            .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 4)
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    // A second start of a running attempt is refused: nothing executes twice.
    assert_eq!(
        start(&store, &fx, &o, NOW + 4).unwrap_err(),
        StoreError::InvalidTransition
    );
    store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::InvalidArtifact,
            &actor(),
            NOW + 5,
        )
        .unwrap();
    // Terminal states have no outgoing transitions.
    assert_eq!(
        store
            .cancel(&o.attempt, &actor(), ReasonCode::Cancelled, NOW + 6)
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    assert_eq!(
        store
            .fail_before_start(&o.attempt, &actor(), ReasonCode::ExecutionFailed, NOW + 6)
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    // Repeating the holder's finish is idempotent and returns the stored settlement.
    let again = store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::InvalidArtifact,
            &actor(),
            NOW + 7,
        )
        .unwrap();
    assert_eq!(again.result, ReservationState::Consumed);
    // Finishing with a different outcome after the fact is refused.
    assert_eq!(
        store
            .finish(
                &lease,
                ExecutionOutcome::Success,
                ReasonCode::Completed,
                &actor(),
                NOW + 7
            )
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    store.integrity_check().unwrap();
}

#[test]
fn duplicate_delivery_neither_charges_nor_executes_twice() {
    let db = TempDb::new("dup");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let first = reserve(&store, &fx).unwrap();
    let second = reserve(&store, &fx).unwrap();
    assert!(second.replay && !first.replay);
    assert_eq!(first.attempt, second.attempt);
    assert_eq!(first.reservation_id, second.reservation_id);
    assert_eq!(status(&store, &fx).held, 1);

    // A replay after the attempt progressed reports the current state.
    let lease = to_validating(&store, &fx, &first);
    store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 4,
        )
        .unwrap();
    let third = reserve(&store, &fx).unwrap();
    assert!(third.replay);
    assert_eq!(third.state, RunState::Completed);
    let st = status(&store, &fx);
    assert_eq!((st.held, st.consumed), (0, 1));
    assert_eq!(store.request_attempts(&fx.request_id()).unwrap().len(), 1);
}

#[test]
fn idempotency_and_identity_conflicts_are_refused() {
    let db = TempDb::new("conflict");
    let store = open(&db);
    let a = fixture(1);
    provision(&store, &a, 5);
    reserve(&store, &a).unwrap();

    // Same idempotency key, different request content (different candidate).
    let mut other = fixture_with(1, Scope::Population, 1, 0, "synthetic-candidate-other");
    assert_eq!(
        reserve(&store, &other).unwrap_err(),
        StoreError::IdempotencyConflict
    );
    // Different key, same request id is also refused.
    other = fixture_with(1, Scope::Population, 1, 0, "synthetic-candidate-1");
    let same_request_other_key = {
        let mut v = serde_json::to_value(&other.req).unwrap();
        v["idempotency_key"] = serde_json::Value::String(id("idk_", 77));
        custodian_contracts::request::EvaluationRequest::decode(&serde_json::to_vec(&v).unwrap())
            .unwrap()
    };
    let cmd = custodian_store::ReserveCommand {
        request: &same_request_other_key,
        ..other.cmd()
    };
    // The approval binds the original plan digest which is unchanged, so only
    // the identity rule can reject it.
    assert_eq!(
        store.reserve_request(&cmd).unwrap_err(),
        StoreError::IdentityConflict
    );
    assert_eq!(status(&store, &a).held, 1);
}

#[test]
fn invalid_bindings_are_rejected_before_any_reservation() {
    let db = TempDb::new("bind");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 5);

    // Revoked activation.
    let revoked = observed(NOW, "revoked");
    let cmd = custodian_store::ReserveCommand {
        observed: &revoked,
        ..fx.cmd()
    };
    assert_eq!(
        store.reserve_request(&cmd).unwrap_err(),
        StoreError::Binding(BindingError::ActivationRevoked)
    );
    // Stale observation.
    let stale = observed(NOW - 10_000, "active");
    let cmd = custodian_store::ReserveCommand {
        observed: &stale,
        ..fx.cmd()
    };
    assert_eq!(
        store.reserve_request(&cmd).unwrap_err(),
        StoreError::Binding(BindingError::StateStale)
    );
    // Expired approval.
    let cmd = fx.cmd_at(NOW + 3601);
    let fresh = observed(NOW + 3601, "active");
    let cmd = custodian_store::ReserveCommand {
        observed: &fresh,
        ..cmd
    };
    assert_eq!(
        store.reserve_request(&cmd).unwrap_err(),
        StoreError::Binding(BindingError::ApprovalExpired)
    );
    // Approval for a different request/plan.
    let other = fixture_with(2, Scope::Population, 1, 0, "synthetic-candidate-2");
    let cmd = custodian_store::ReserveCommand {
        approval: &other.apr,
        ..fx.cmd()
    };
    assert_eq!(
        store.reserve_request(&cmd).unwrap_err(),
        StoreError::Binding(BindingError::RequestMismatch)
    );

    let st = status(&store, &fx);
    assert_eq!((st.held, st.consumed), (0, 0));
    assert!(store.request_attempts(&fx.request_id()).unwrap().is_empty());
    assert!(store
        .outbox_pending(100)
        .unwrap()
        .iter()
        .all(|e| e.kind == "budget.provisioned"));
}

#[test]
fn exhaustion_is_denied_and_recorded_not_silently_dropped() {
    let db = TempDb::new("exhaust");
    let store = open(&db);
    let a = fixture(1);
    let b = fixture(2);
    provision(&store, &a, 1);
    assert_eq!(reserve(&store, &a).unwrap().state, RunState::Reserved);
    let denied = reserve(&store, &b).unwrap();
    assert_eq!(denied.state, RunState::Denied);
    assert_eq!(denied.reason, ReasonCode::BudgetExhausted);
    assert!(denied.reservation_id.is_none());
    // Replay of the denied key is the same denial, not a fresh evaluation.
    let again = reserve(&store, &b).unwrap();
    assert!(again.replay);
    assert_eq!(again.state, RunState::Denied);
    assert_eq!(status(&store, &a).held, 1);
    let h = store.history(&denied.attempt).unwrap();
    assert_eq!(h.last().unwrap().to, RunState::Denied);
    assert_eq!(h.last().unwrap().reason, ReasonCode::BudgetExhausted);
    assert!(store
        .outbox_pending(100)
        .unwrap()
        .iter()
        .any(|e| e.kind == "request.denied"));
    store.integrity_check().unwrap();
}

#[test]
fn unprovisioned_budget_denies() {
    let db = TempDb::new("unprov");
    let store = open(&db);
    let fx = fixture(1);
    let o = reserve(&store, &fx).unwrap();
    assert_eq!(o.state, RunState::Denied);
    assert!(store
        .budget_status(BudgetKind::Run, &fx.scope())
        .unwrap()
        .is_none());
    store.integrity_check().unwrap();
}

#[test]
fn blind_budget_is_per_lineage_not_per_candidate_digest() {
    let db = TempDb::new("lineage");
    let store = open(&db);
    let a = fixture_with(1, Scope::Lineage(1), 1, 0, "synthetic-candidate-tuned-1");
    let b = fixture_with(2, Scope::Lineage(1), 1, 0, "synthetic-candidate-tuned-2");
    let c = fixture_with(3, Scope::Lineage(2), 1, 0, "synthetic-candidate-tuned-3");
    provision(&store, &a, 1);
    provision(&store, &c, 1);
    assert_ne!(
        custodian_store::budget_scope_key(BudgetKind::Run, &a.scope()).unwrap(),
        custodian_store::budget_scope_key(BudgetKind::Run, &c.scope()).unwrap()
    );
    assert_eq!(
        custodian_store::budget_scope_key(BudgetKind::Run, &a.scope()).unwrap(),
        custodian_store::budget_scope_key(BudgetKind::Run, &b.scope()).unwrap()
    );
    assert_eq!(reserve(&store, &a).unwrap().state, RunState::Reserved);
    // A new candidate digest in the same lineage gets no fresh budget.
    assert_eq!(reserve(&store, &b).unwrap().state, RunState::Denied);
    // A different lineage has its own budget.
    assert_eq!(reserve(&store, &c).unwrap().state, RunState::Reserved);
}

#[test]
fn budget_provisioning_never_shrinks_or_resets() {
    let db = TempDb::new("prov");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 2);
    let o = reserve(&store, &fx).unwrap();
    let lease = to_validating(&store, &fx, &o);
    store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 4,
        )
        .unwrap();
    // Lowering the limit is refused; re-provisioning the same limit keeps consumption.
    assert_eq!(
        store
            .provision_budget(BudgetKind::Run, &fx.scope(), 1, &actor(), NOW + 5)
            .unwrap_err(),
        StoreError::InvalidInput
    );
    let same = store
        .provision_budget(BudgetKind::Run, &fx.scope(), 2, &actor(), NOW + 5)
        .unwrap();
    assert_eq!((same.limit, same.consumed), (2, 1));
    let raised = store
        .provision_budget(BudgetKind::Run, &fx.scope(), 3, &actor(), NOW + 6)
        .unwrap();
    assert_eq!(
        (raised.limit, raised.consumed, raised.available()),
        (3, 1, 2)
    );
}

#[test]
fn refund_follows_settled_state_only() {
    let db = TempDb::new("refund");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 5);

    // 1. cancelled before start: nothing acquired -> refunded.
    let a = reserve(&store, &fx).unwrap();
    let s = store
        .cancel(&a.attempt, &actor(), ReasonCode::Cancelled, NOW + 1)
        .unwrap();
    assert_eq!(
        (s.result, s.exposure),
        (ReservationState::Refunded, Exposure::NotExposed)
    );
    assert_eq!(status(&store, &fx).consumed, 0);
    // Cancel is idempotent.
    assert_eq!(
        store
            .cancel(&a.attempt, &actor(), ReasonCode::Cancelled, NOW + 2)
            .unwrap(),
        s
    );

    // 2. failure reported by the holder before any exposure -> refunded.
    let f2 = fixture(2);
    let b = reserve(&store, &f2).unwrap();
    let lease = start(&store, &f2, &b, NOW + 1).unwrap();
    let s = store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::CorpusUnavailable,
            &actor(),
            NOW + 2,
        )
        .unwrap();
    assert_eq!(s.result, ReservationState::Refunded);

    // 3. failure after recorded exposure -> consumed.
    let f3 = fixture(3);
    let c = reserve(&store, &f3).unwrap();
    let lease = start(&store, &f3, &c, NOW + 1).unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    let s = store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::ExecutionFailed,
            &actor(),
            NOW + 3,
        )
        .unwrap();
    assert_eq!(s.result, ReservationState::Consumed);

    // 4. cancellation while running: exposure presumed -> consumed, lease fenced.
    let f4 = fixture(4);
    let d = reserve(&store, &f4).unwrap();
    let lease = start(&store, &f4, &d, NOW + 1).unwrap();
    let s = store
        .cancel(&d.attempt, &actor(), ReasonCode::Cancelled, NOW + 2)
        .unwrap();
    assert_eq!(
        (s.result, s.exposure),
        (ReservationState::Consumed, Exposure::Exposed)
    );
    assert_eq!(
        store
            .record_exposure(&lease, &actor(), NOW + 3)
            .unwrap_err(),
        StoreError::LeaseLost
    );
    assert_eq!(
        store
            .finish(
                &lease,
                ExecutionOutcome::Success,
                ReasonCode::Completed,
                &actor(),
                NOW + 3
            )
            .unwrap_err(),
        StoreError::LeaseLost
    );
    let h = store.history(&d.attempt).unwrap();
    assert!(
        h.iter().any(|t| t.is_exposure),
        "presumed exposure is recorded"
    );

    // 5. fail before start -> refunded.
    let f5 = fixture(5);
    let e = reserve(&store, &f5).unwrap();
    let s = store
        .fail_before_start(&e.attempt, &actor(), ReasonCode::ExecutionFailed, NOW + 1)
        .unwrap();
    assert_eq!(s.result, ReservationState::Refunded);

    let st = status(&store, &fx);
    assert_eq!((st.held, st.consumed, st.refunded), (0, 2, 3));
    assert_eq!(st.available(), 3);
    store.integrity_check().unwrap();
}

#[test]
fn lease_expiry_renewal_and_loss() {
    let db = TempDb::new("lease");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    let o = reserve(&store, &fx).unwrap();
    let lease = start(&store, &fx, &o, NOW + 1).unwrap();
    assert_eq!(lease.expires_at, NOW + 1 + LEASE);
    assert_eq!(lease.token, 1);

    // Renewal extends; it cannot shorten.
    let renewed = store.renew_lease(&lease, NOW + 100, LEASE).unwrap();
    assert_eq!(renewed.expires_at, NOW + 100 + LEASE);
    assert_eq!(renewed.token, lease.token);
    let short = store.renew_lease(&renewed, NOW + 101, 1).unwrap();
    assert_eq!(short.expires_at, renewed.expires_at);

    // A different owner presenting the same token is refused.
    let imposter = Lease {
        owner: "worker-b".into(),
        ..renewed.clone()
    };
    assert_eq!(
        store
            .record_exposure(&imposter, &actor(), NOW + 102)
            .unwrap_err(),
        StoreError::LeaseLost
    );

    // After expiry the holder can do nothing; recovery settles the attempt.
    let late = NOW + 100 + LEASE + 1;
    assert_eq!(
        store.record_exposure(&renewed, &actor(), late).unwrap_err(),
        StoreError::LeaseLost
    );
    assert_eq!(
        store.renew_lease(&renewed, late, LEASE).unwrap_err(),
        StoreError::LeaseLost
    );
    assert_eq!(
        store
            .finish(
                &renewed,
                ExecutionOutcome::Failed,
                ReasonCode::ExecutionFailed,
                &actor(),
                late
            )
            .unwrap_err(),
        StoreError::LeaseLost
    );
    let report = store.recover(&actor(), late).unwrap();
    assert_eq!(report.failed_consumed, vec![o.attempt.clone()]);
    assert_eq!(status(&store, &fx).consumed, 1);
    // After recovery the old holder is fenced even with a "valid" clock.
    assert_eq!(
        store
            .finish(
                &renewed,
                ExecutionOutcome::Failed,
                ReasonCode::ExecutionFailed,
                &actor(),
                NOW + 2
            )
            .unwrap_err(),
        StoreError::LeaseLost
    );
}

#[test]
fn recovery_policy_expired_reservation_refunds_and_lapsed_run_consumes() {
    let db = TempDb::new("recover");
    let store = open(&db);
    let a = fixture(1);
    let b = fixture(2);
    let c = fixture(3);
    provision(&store, &a, 3);
    let ra = reserve(&store, &a).unwrap(); // never started
    let rb = reserve(&store, &b).unwrap(); // started, then abandoned
    let rc = reserve(&store, &c).unwrap(); // validating, then abandoned
    start(&store, &b, &rb, NOW + 1).unwrap();
    to_validating(&store, &c, &rc);

    // Nothing has lapsed yet.
    assert_eq!(
        store.recover(&actor(), NOW + 10).unwrap(),
        Default::default()
    );
    // A start after the window is refused.
    assert_eq!(
        start(&store, &a, &ra, NOW + WINDOW).unwrap_err(),
        StoreError::LeaseLost
    );

    let report = store.recover(&actor(), NOW + WINDOW + 10_000).unwrap();
    assert_eq!(report.expired_unstarted, vec![ra.attempt.clone()]);
    let mut consumed = report.failed_consumed.clone();
    consumed.sort();
    let mut want = vec![rb.attempt.clone(), rc.attempt.clone()];
    want.sort();
    assert_eq!(consumed, want);

    let st = status(&store, &a);
    assert_eq!((st.held, st.consumed, st.refunded), (0, 2, 1));
    let rec = store.attempt(&ra.attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Expired, Exposure::NotExposed)
    );
    let rec = store.attempt(&rb.attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Failed, Exposure::Exposed)
    );
    // Idempotent: a second sweep changes nothing.
    assert_eq!(
        store.recover(&actor(), NOW + 20_000).unwrap(),
        Default::default()
    );
    store.integrity_check().unwrap();
}

#[test]
fn start_rechecks_activation_and_requires_an_observation() {
    let db = TempDb::new("startcheck");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 1);
    let o = reserve(&store, &fx).unwrap();
    let revoked = observed(NOW + 1, "revoked");
    let err = store
        .start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner: "worker-a",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&revoked),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap_err();
    assert_eq!(err, StoreError::Binding(BindingError::ActivationRevoked));
    let err = store
        .start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner: "worker-a",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: None,
            max_state_age_secs: MAX_AGE,
        })
        .unwrap_err();
    assert_eq!(err, StoreError::Binding(BindingError::StateStale));
    // The attempt is still reserved; cancelling refunds it.
    assert_eq!(
        store.attempt(&o.attempt).unwrap().unwrap().state,
        RunState::Reserved
    );
    assert_eq!(
        store
            .cancel(
                &o.attempt,
                &actor(),
                ReasonCode::AuthorizationDenied,
                NOW + 2
            )
            .unwrap()
            .result,
        ReservationState::Refunded
    );
}

#[test]
fn retries_are_new_attempts_that_charge_again() {
    let db = TempDb::new("retry");
    let store = open(&db);
    let fx = fixture_with(1, Scope::Population, 1, 1, "synthetic-candidate-retry");
    provision(&store, &fx, 2);
    let a1 = reserve(&store, &fx).unwrap();
    // A retry of a live attempt is refused.
    let retry = |from: u32, now: u64| {
        let obs = observed(now, "active");
        store.retry_attempt(&RetryCommand {
            request: &fx.req,
            approval: &fx.apr,
            observed: &obs,
            from_attempt_no: from,
            now: ts(now),
            max_state_age_secs: MAX_AGE,
            reservation_window_secs: WINDOW,
        })
    };
    assert_eq!(retry(1, NOW + 5).unwrap_err(), StoreError::RetryRefused);

    // Attempt 1 fails after exposure: consumed.
    let lease = start(&store, &fx, &a1, NOW + 1).unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::ExecutionFailed,
            &actor(),
            NOW + 3,
        )
        .unwrap();
    assert_eq!(status(&store, &fx).consumed, 1);

    // The retry is a new attempt, charged again; nothing was restored.
    let a2 = retry(1, NOW + 10).unwrap();
    assert_eq!(a2.state, RunState::Reserved);
    assert_eq!(a2.attempt_no, 2);
    assert_ne!(a2.attempt, a1.attempt);
    let st = status(&store, &fx);
    assert_eq!((st.held, st.consumed), (1, 1));
    // Duplicate delivery of the same retry finds the attempt; no second charge.
    let dup = retry(1, NOW + 11).unwrap();
    assert!(dup.replay);
    assert_eq!(dup.attempt, a2.attempt);
    assert_eq!(status(&store, &fx).held, 1);

    // Attempt 2 fails too. max_retries = 1 -> no third attempt.
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &a2.attempt,
            owner: "worker-a",
            actor: &actor(),
            now: NOW + 12,
            lease_secs: LEASE,
            observed: Some(&observed(NOW + 12, "active")),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::ExecutionFailed,
            &actor(),
            NOW + 13,
        )
        .unwrap(); // not exposed: refunded
    assert_eq!(retry(2, NOW + 20).unwrap_err(), StoreError::RetryRefused);
    assert_eq!(retry(7, NOW + 20).unwrap_err(), StoreError::NotFound);
    assert_eq!(store.request_attempts(&fx.request_id()).unwrap().len(), 2);
    store.integrity_check().unwrap();
}

#[test]
fn retry_passes_the_same_budget_and_approval_checks() {
    let db = TempDb::new("retrychk");
    let store = open(&db);
    let fx = fixture_with(1, Scope::Population, 1, 3, "synthetic-candidate-retry2");
    provision(&store, &fx, 1);
    let a1 = reserve(&store, &fx).unwrap();
    let lease = start(&store, &fx, &a1, NOW + 1).unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Failed,
            ReasonCode::ExecutionFailed,
            &actor(),
            NOW + 3,
        )
        .unwrap();

    let obs = observed(NOW + 10, "active");
    fn mk<'a>(
        fx: &'a Fx,
        obs: &'a custodian_contracts::policy::ObservedActivation,
        now: u64,
    ) -> RetryCommand<'a> {
        RetryCommand {
            request: &fx.req,
            approval: &fx.apr,
            observed: obs,
            from_attempt_no: 1,
            now: ts(now),
            max_state_age_secs: MAX_AGE,
            reservation_window_secs: WINDOW,
        }
    }
    // Exhausted: exposure consumed the only unit; the retry is denied, not free.
    let denied = store.retry_attempt(&mk(&fx, &obs, NOW + 10)).unwrap();
    assert_eq!(denied.state, RunState::Denied);
    assert_eq!(denied.reason, ReasonCode::BudgetExhausted);
    assert_eq!(store.request_attempts(&fx.request_id()).unwrap().len(), 1);
    assert!(store
        .outbox_pending(100)
        .unwrap()
        .iter()
        .any(|e| e.kind == "retry.denied"));

    // Revoked activation: rejected by the approval check.
    let revoked = observed(NOW + 10, "revoked");
    assert_eq!(
        store
            .retry_attempt(&mk(&fx, &revoked, NOW + 10))
            .unwrap_err(),
        StoreError::Binding(BindingError::ActivationRevoked)
    );
    // Expired approval.
    let later = observed(NOW + 4000, "active");
    assert_eq!(
        store
            .retry_attempt(&mk(&fx, &later, NOW + 4000))
            .unwrap_err(),
        StoreError::Binding(BindingError::ApprovalExpired)
    );
    // Raising the limit is the only way to fund another attempt.
    store
        .provision_budget(BudgetKind::Run, &fx.scope(), 2, &actor(), NOW + 11)
        .unwrap();
    assert_eq!(
        store.retry_attempt(&mk(&fx, &obs, NOW + 12)).unwrap().state,
        RunState::Reserved
    );
    store.integrity_check().unwrap();
}
