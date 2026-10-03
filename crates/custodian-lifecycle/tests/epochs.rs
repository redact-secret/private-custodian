//! Contamination reports, clearance, retirement and rotation through the
//! real protected-population registry and the real store (C9). Synthetic
//! data only.

mod common;

use common::*;
use custodian_contracts::common::{ActorKind, BudgetKind, EvaluationDomain};
use custodian_core::{Contamination, EpochStanding};
use custodian_corpus::registry::EpochState;
use custodian_lifecycle::testing::StaticAuthority;
use custodian_lifecycle::{
    CrashOnce, EpochManager, EpochReason, LifecycleFault, LifecyclePoint, LifecycleReason as R,
    NoFault, RotationBudget, RotationRequest,
};
use custodian_store::{ObligationAction, ObligationTarget, StoreError};

fn reg_state(w: &RegWorld, e: &custodian_contracts::types::EpochId) -> EpochState {
    w.fx.pop.state(e).unwrap()
}

#[test]
fn an_agent_can_only_report_and_every_other_action_is_operator_only() {
    let w = RegWorld::new();
    let m = w.manager(&NoFault);
    let a = agent();

    // Reporting is conservative and allowed.
    let r = m
        .report(
            &change(
                &w.epoch,
                &a,
                &idk(1),
                EpochReason::UnreviewedPopulationChange,
                NOW + 1,
            ),
            Contamination::UnreviewedChange,
        )
        .unwrap();
    assert!(r.changed);

    // But not a permanent contamination: that retires the epoch and is
    // published, so it needs an accountable human or service.
    assert_eq!(
        m.report(
            &change(&w.epoch, &a, &idk(9), EpochReason::ResultsExposed, NOW + 1),
            Contamination::Exposed
        )
        .unwrap_err(),
        R::AgentNotPermitted
    );
    assert_eq!(
        m.standing(&w.epoch).unwrap().contamination,
        Contamination::UnreviewedChange
    );
    assert!(w.store.pending_obligations(10).unwrap().is_empty());

    // Everything else is refused, whatever the (lenient) authority says.
    let clear = m
        .clear(&change(
            &w.epoch,
            &a,
            &idk(2),
            EpochReason::ReviewedNoImpact,
            NOW + 2,
        ))
        .unwrap_err();
    assert_eq!(clear, R::AgentNotPermitted);
    let retire = m
        .retire(&change(
            &w.epoch,
            &a,
            &idk(3),
            EpochReason::PlannedRotation,
            NOW + 3,
        ))
        .unwrap_err();
    assert_eq!(retire, R::AgentNotPermitted);
    let next = w.seal_next("agent");
    let rot = m
        .rotate(&RotationRequest {
            predecessor: &w.epoch,
            successor: &next,
            who: &a,
            key: &idk(4),
            reason: EpochReason::PlannedRotation,
            budgets: &[],
            now: ts(NOW + 4),
        })
        .unwrap_err();
    assert_eq!(rot, R::AgentNotPermitted);
    assert_eq!(
        m.standing(&w.epoch).unwrap().contamination,
        Contamination::UnreviewedChange
    );
    assert_eq!(reg_state(&w, &w.epoch), EpochState::Active);
}

#[test]
fn clearing_needs_a_human_with_permission_and_the_one_fitting_reason() {
    let w = RegWorld::new();
    let m = w.manager(&NoFault);
    m.report(
        &change(
            &w.epoch,
            &human(),
            &idk(1),
            EpochReason::IntegrityAlarm,
            NOW + 1,
        ),
        Contamination::UnreviewedChange,
    )
    .unwrap();

    // A service identity cannot clear even when the authority allows it.
    assert_eq!(
        m.clear(&change(
            &w.epoch,
            &service(),
            &idk(2),
            EpochReason::ReviewedNoImpact,
            NOW + 2
        ))
        .unwrap_err(),
        R::Unauthorized
    );
    // A human the authority does not permit cannot either.
    let strict = StaticAuthority::new().allow(
        HUMAN,
        custodian_lifecycle::OperatorAction::ReportContamination,
    );
    let m_strict = EpochManager {
        store: &w.store,
        populations: &w.fx.pop,
        authority: &strict,
        fault: &NoFault,
    };
    assert_eq!(
        m_strict
            .clear(&change(
                &w.epoch,
                &human(),
                &idk(3),
                EpochReason::ReviewedNoImpact,
                NOW + 3
            ))
            .unwrap_err(),
        R::Unauthorized
    );
    // The reason must be the review outcome.
    assert_eq!(
        m.clear(&change(
            &w.epoch,
            &human(),
            &idk(4),
            EpochReason::OperatorDecision,
            NOW + 4
        ))
        .unwrap_err(),
        R::InvalidChange
    );
    assert!(!m.standing(&w.epoch).unwrap().usable());

    // The reviewed clearance works, is audited with actor and authorization,
    // and the history of the flag stays.
    let out = m
        .clear(&change(
            &w.epoch,
            &human(),
            &idk(5),
            EpochReason::ReviewedNoImpact,
            NOW + 5,
        ))
        .unwrap();
    assert_eq!(out.transition.new, EpochStanding::CLEAN);
    assert!(m.standing(&w.epoch).unwrap().usable());
    let events = w.store.epoch_events(w.epoch.as_str()).unwrap();
    assert_eq!(
        events.iter().map(|e| e.change.as_str()).collect::<Vec<_>>(),
        ["report", "clear"]
    );
    assert_eq!(events[1].actor, HUMAN);
    assert_eq!(events[1].actor_kind, "human");
    assert_eq!(events[1].authorization_ref, "apr_synthetic000000000009");
    assert_eq!(
        events[1].prior.contamination,
        Contamination::UnreviewedChange
    );
    assert_eq!(events[1].reason, "reviewed_no_impact");
    // An unreviewed change is not retired and not published.
    assert_eq!(reg_state(&w, &w.epoch), EpochState::Active);
    assert!(w.store.pending_obligations(10).unwrap().is_empty());
    // The epoch takes new requests again.
    let (req, apr) = request_for(&w.binding, 1);
    w.store
        .provision_budget(BudgetKind::Run, &run_scope(&w.binding), 2, &actor(), NOW)
        .unwrap();
    assert!(reserve_req(&w.store, &req, &apr).is_ok());
    w.store.verify_lifecycle_invariants().unwrap();
}

#[test]
fn a_permanent_contamination_is_never_cleared_and_retires_the_epoch_everywhere() {
    let w = RegWorld::new();
    let m = w.manager(&NoFault);
    for (i, (kind, reason)) in [
        (Contamination::Exposed, EpochReason::ResultsExposed),
        (Contamination::UsedForTuning, EpochReason::TunedOnResults),
    ]
    .into_iter()
    .enumerate()
    {
        let w = RegWorld::new();
        let m = w.manager(&NoFault);
        let out = m
            .report(&change(&w.epoch, &human(), &idk(10), reason, NOW + 1), kind)
            .unwrap();
        assert_eq!(out.transition.new.contamination, kind, "{i}");
        let retirement = out.retirement.expect("automatic retirement");
        assert!(retirement.transition.new.retired);
        // The registry follows: no read can open the protected bytes either.
        assert_eq!(reg_state(&w, &w.epoch), EpochState::Retired);
        assert!(w
            .fx
            .pop
            .open_verified(&corpus::authorization(&w.epoch))
            .is_err());
        // The public consequence is recorded with the transition.
        let pending = w.store.pending_obligations(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].action, ObligationAction::Contaminated);
        assert_eq!(pending[0].target, ObligationTarget::Population);
        // Not clearable, by a human, with any reason.
        assert_eq!(
            m.clear(&change(
                &w.epoch,
                &human(),
                &idk(11),
                EpochReason::ReviewedNoImpact,
                NOW + 2
            ))
            .unwrap_err(),
            R::NotClearable
        );
        assert!(!m.standing(&w.epoch).unwrap().usable());
        w.store.verify_lifecycle_invariants().unwrap();
    }
    // A weaker report after a stronger one cannot soften it.
    m.report(
        &change(
            &w.epoch,
            &human(),
            &idk(20),
            EpochReason::TunedOnResults,
            NOW + 1,
        ),
        Contamination::UsedForTuning,
    )
    .unwrap();
    let weak = m
        .report(
            &change(
                &w.epoch,
                &agent(),
                &idk(21),
                EpochReason::UnreviewedPopulationChange,
                NOW + 2,
            ),
            Contamination::UnreviewedChange,
        )
        .unwrap();
    assert!(!weak.changed);
    assert_eq!(
        m.standing(&w.epoch).unwrap().contamination,
        Contamination::UsedForTuning
    );
}

#[test]
fn reports_are_validated_and_idempotent() {
    let op = human();
    let w = RegWorld::new();
    let m = w.manager(&NoFault);
    // Reason must fit the kind; an unknown epoch is refused.
    assert_eq!(
        m.report(
            &change(&w.epoch, &op, &idk(1), EpochReason::TunedOnResults, NOW),
            Contamination::Exposed
        )
        .unwrap_err(),
        R::InvalidChange
    );
    assert_eq!(
        m.report(
            &change(&w.epoch, &op, &idk(1), EpochReason::ResultsExposed, NOW),
            Contamination::Unaffected
        )
        .unwrap_err(),
        R::InvalidChange
    );
    let ghost = custodian_contracts::types::EpochId::parse("epo_zzzzzzzzzzzzzzzzzzzz").unwrap();
    assert_eq!(
        m.report(
            &change(&ghost, &op, &idk(1), EpochReason::ResultsExposed, NOW),
            Contamination::Exposed
        )
        .unwrap_err(),
        R::UnknownEpoch
    );
    // Nothing above reached the store.
    assert!(w.store.epoch_events(w.epoch.as_str()).unwrap().is_empty());

    let k2 = idk(2);
    let req = change(&w.epoch, &op, &k2, EpochReason::ResultsExposed, NOW + 1);
    let first = m.report(&req, Contamination::Exposed).unwrap();
    let again = m.report(&req, Contamination::Exposed).unwrap();
    assert!(!first.replay && again.replay);
    // Report plus its automatic retirement: two events, never four.
    assert_eq!(w.store.epoch_events(w.epoch.as_str()).unwrap().len(), 2);
    assert_eq!(w.store.pending_obligations(10).unwrap().len(), 1);
    // The same key for a different change is refused.
    let conflicting = change(&w.epoch, &op, &k2, EpochReason::TunedOnResults, NOW + 2);
    assert_eq!(
        m.report(&conflicting, Contamination::UsedForTuning)
            .unwrap_err(),
        R::IdempotencyConflict
    );
}

#[test]
fn rotation_gives_a_new_epoch_new_budgets_and_leaves_the_old_state_alone() {
    let w = RegWorld::new();
    let op = human();
    let m = w.manager(&NoFault);
    let next = w.seal_next("b");
    let next_binding = binding_of(&w.fx, &next);

    // The old epoch's budget is exhausted: one unit held of one.
    w.store
        .provision_budget(BudgetKind::Run, &run_scope(&w.binding), 1, &actor(), NOW)
        .unwrap();
    let (req, apr) = request_for(&w.binding, 1);
    reserve_req(&w.store, &req, &apr).unwrap();
    let old_before = w
        .store
        .budget_status(BudgetKind::Run, &run_scope(&w.binding))
        .unwrap()
        .unwrap();
    assert_eq!((old_before.limit, old_before.held), (1, 1));

    let rotation = RotationRequest {
        predecessor: &w.epoch,
        successor: &next,
        who: &op,
        key: &idk(1),
        reason: EpochReason::PlannedRotation,
        budgets: &[RotationBudget {
            kind: BudgetKind::Run,
            scope: run_scope(&next_binding),
            limit: 2,
        }],
        now: ts(NOW + 5),
    };
    let out = m.rotate(&rotation).unwrap();
    assert!(out.linked && out.activated);
    assert_eq!(out.budgets_provisioned, 1);

    // Registry: old retired, new active. Store: linked, old unusable.
    assert_eq!(reg_state(&w, &w.epoch), EpochState::Retired);
    assert_eq!(reg_state(&w, &next), EpochState::Active);
    assert_eq!(
        w.store.successor_of(w.epoch.as_str()).unwrap().as_deref(),
        Some(next.as_str())
    );
    assert!(w.store.check_epoch_usable(w.epoch.as_str()).is_err());
    assert!(w.store.check_epoch_usable(next.as_str()).is_ok());

    // The old budget is exactly what it was: nothing reset, nothing edited.
    let old_after = w
        .store
        .budget_status(BudgetKind::Run, &run_scope(&w.binding))
        .unwrap()
        .unwrap();
    assert_eq!(old_after, old_before);
    // The new epoch has its own scope key and its own limit.
    assert_ne!(
        custodian_store::budget_scope_key(BudgetKind::Run, &run_scope(&w.binding)).unwrap(),
        custodian_store::budget_scope_key(BudgetKind::Run, &run_scope(&next_binding)).unwrap()
    );
    let new_budget = w
        .store
        .budget_status(BudgetKind::Run, &run_scope(&next_binding))
        .unwrap()
        .unwrap();
    assert_eq!(
        (new_budget.limit, new_budget.held, new_budget.consumed),
        (2, 0, 0)
    );
    // Old epoch takes no new request even though raising its limit is
    // possible: the gate, not the budget, closes it.
    let (req2, apr2) = request_for(&w.binding, 2);
    assert_eq!(
        reserve_req(&w.store, &req2, &apr2).unwrap_err(),
        StoreError::EpochBlocked
    );
    let (req3, apr3) = request_for(&next_binding, 3);
    assert!(reserve_req(&w.store, &req3, &apr3).is_ok());
    // Evidence from the retired epoch is revoked, as a rotation.
    let pending = w.store.pending_obligations(10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].action, pending[0].reason.as_str()),
        (ObligationAction::Revoked, "epoch_rotation")
    );

    // Repeating the rotation changes nothing.
    let again = m.rotate(&rotation).unwrap();
    assert!(!again.linked && !again.activated);
    assert_eq!(w.store.pending_obligations(10).unwrap().len(), 1);
    w.store.verify_lifecycle_invariants().unwrap();
    w.store.integrity_check().unwrap();
}

#[test]
fn a_rotation_needs_a_genuinely_new_reviewed_population_and_only_its_own_budgets() {
    let w = RegWorld::new();
    let m = w.manager(&NoFault);
    let go = |next: &custodian_contracts::types::EpochId,
              budgets: &[RotationBudget],
              who: &custodian_lifecycle::OperatorAuthorization| {
        m.rotate(&RotationRequest {
            predecessor: &w.epoch,
            successor: next,
            who,
            key: &idk(9),
            reason: EpochReason::PlannedRotation,
            budgets,
            now: ts(NOW + 1),
        })
    };
    // Same content under a new epoch id is not a new population.
    let same =
        w.fx.seal(&[("one", b"synthetic-one"), ("two", b"synthetic-two")]);
    assert_eq!(go(&same, &[], &human()).unwrap_err(), R::RotationInvalid);
    // A different domain is not a successor of this corpus epoch.
    let pii = {
        let wr =
            w.fx.pop
                .begin_epoch(corpus::corpus_id(), EvaluationDomain::Pii, None)
                .unwrap();
        w.fx.pop
            .add_entry(&wr, &corpus::name("one"), b"synthetic-pii-one")
            .unwrap();
        let e = wr.epoch_id().clone();
        let inputs = corpus::inputs_for(
            &e,
            custodian_contracts::common::ReviewStatus::ProjectReviewed,
        );
        w.fx.pop.seal(wr, inputs).unwrap();
        e
    };
    assert_eq!(go(&pii, &[], &human()).unwrap_err(), R::EpochMismatch);
    // A budget for another epoch (here the old one) is refused before anything
    // is retired.
    let next = w.seal_next("c");
    let sneaky = RotationBudget {
        kind: BudgetKind::Run,
        scope: run_scope(&w.binding),
        limit: 99,
    };
    assert_eq!(
        go(&next, &[sneaky], &human()).unwrap_err(),
        R::RotationInvalid
    );
    assert!(m.standing(&w.epoch).unwrap().usable());
    assert_eq!(reg_state(&w, &w.epoch), EpochState::Active);
    // Unknown successor.
    let ghost = custodian_contracts::types::EpochId::parse("epo_zzzzzzzzzzzzzzzzzzzz").unwrap();
    assert_eq!(go(&ghost, &[], &human()).unwrap_err(), R::UnknownEpoch);
    // A contaminated successor cannot be activated by rotation.
    m.report(
        &change(
            &next,
            &human(),
            &idk(30),
            EpochReason::ResultsExposed,
            NOW + 1,
        ),
        Contamination::Exposed,
    )
    .unwrap();
    assert_eq!(go(&next, &[], &human()).unwrap_err(), R::RotationInvalid);
    assert!(m.standing(&w.epoch).unwrap().usable());
}

#[test]
fn crash_at_every_rotation_boundary_fails_closed_and_a_rerun_converges() {
    for point in [
        LifecyclePoint::AfterStoreRetire,
        LifecyclePoint::AfterRegistryRetire,
        LifecyclePoint::AfterRotationLink,
        LifecyclePoint::AfterRotationBudgets,
    ] {
        let mut w = RegWorld::new();
        let op = human();
        let epoch = w.epoch.clone();
        let next = w.seal_next("d");
        let next_binding = binding_of(&w.fx, &next);
        let budgets = [RotationBudget {
            kind: BudgetKind::Run,
            scope: run_scope(&next_binding),
            limit: 3,
        }];
        let rotation = RotationRequest {
            predecessor: &epoch,
            successor: &next,
            who: &op,
            key: &idk(1),
            reason: EpochReason::PlannedRotation,
            budgets: &budgets,
            now: ts(NOW + 5),
        };
        let crash = CrashOnce::new(point);
        assert_eq!(
            w.manager(&crash).rotate(&rotation).unwrap_err(),
            R::InjectedCrash,
            "{point:?}"
        );
        assert!(crash.fired());

        // Fail closed at the crash: the old epoch cannot be used, and the new
        // one cannot be used yet (activation is the last step).
        assert!(
            w.store.check_epoch_usable(w.epoch.as_str()).is_err(),
            "{point:?}"
        );
        assert_eq!(reg_state(&w, &next), EpochState::Sealed, "{point:?}");
        let (req, apr) = request_for(&w.binding, 1);
        assert_eq!(
            reserve_req(&w.store, &req, &apr).unwrap_err(),
            StoreError::EpochBlocked
        );
        assert!(w
            .fx
            .pop
            .open_verified(&corpus::authorization(&next))
            .is_err());

        // A restart and a re-run complete it, exactly once.
        w.restart_store();
        let out = w.manager(&NoFault).rotate(&rotation).unwrap();
        assert!(out.activated, "{point:?}");
        assert_eq!(reg_state(&w, &w.epoch), EpochState::Retired);
        assert_eq!(reg_state(&w, &next), EpochState::Active);
        assert_eq!(
            w.store.successor_of(w.epoch.as_str()).unwrap().as_deref(),
            Some(next.as_str())
        );
        let b = w
            .store
            .budget_status(BudgetKind::Run, &run_scope(&next_binding))
            .unwrap()
            .unwrap();
        assert_eq!(b.limit, 3);
        let retire_events = w
            .store
            .epoch_events(w.epoch.as_str())
            .unwrap()
            .into_iter()
            .filter(|e| e.changed)
            .count();
        assert_eq!(retire_events, 1, "{point:?}");
        assert_eq!(
            w.store.pending_obligations(10).unwrap().len(),
            1,
            "{point:?}"
        );
        w.store.verify_lifecycle_invariants().unwrap();
        w.store.integrity_check().unwrap();
    }
}

#[test]
fn crash_between_a_report_and_its_retirement_converges_on_retry_and_on_sweep() {
    let op = human();
    // Retry with the same key.
    let w = RegWorld::new();
    let crash = CrashOnce::new(LifecyclePoint::AfterReport);
    let k1 = idk(1);
    let req = change(&w.epoch, &op, &k1, EpochReason::ResultsExposed, NOW + 1);
    assert_eq!(
        w.manager(&crash)
            .report(&req, Contamination::Exposed)
            .unwrap_err(),
        R::InjectedCrash
    );
    // Contaminated and blocked in the store; the registry has not followed.
    assert!(w.store.check_epoch_usable(w.epoch.as_str()).is_err());
    assert_eq!(reg_state(&w, &w.epoch), EpochState::Active);
    let out = w
        .manager(&NoFault)
        .report(&req, Contamination::Exposed)
        .unwrap();
    assert!(out.replay);
    assert_eq!(reg_state(&w, &w.epoch), EpochState::Retired);

    // No retry at all: the startup sweep makes the registry say what the
    // store says.
    let w = RegWorld::new();
    for point in [
        LifecyclePoint::AfterReport,
        LifecyclePoint::AfterStoreRetire,
    ] {
        let w = RegWorld::new();
        let crash = CrashOnce::new(point);
        let k1 = idk(1);
        let req = change(&w.epoch, &op, &k1, EpochReason::ResultsExposed, NOW + 1);
        assert!(w
            .manager(&crash)
            .report(&req, Contamination::Exposed)
            .is_err());
        assert_eq!(reg_state(&w, &w.epoch), EpochState::Active, "{point:?}");
        let m = w.manager(&NoFault);
        // Contaminated is permanent, so the sweep retires it even if the
        // retirement event itself never ran.
        assert_eq!(m.reconcile_registry(ts(NOW + 9)).unwrap(), 1, "{point:?}");
        assert_eq!(reg_state(&w, &w.epoch), EpochState::Retired);
        assert_eq!(m.reconcile_registry(ts(NOW + 10)).unwrap(), 0);
    }
    let _ = w;
}

#[test]
fn lifecycle_fault_points_are_all_reachable() {
    // Guards the crash tests above against silently skipping a point.
    let all: Vec<_> = LifecyclePoint::ALL.to_vec();
    assert_eq!(all.len(), 8);
    let f: &dyn LifecycleFault = &NoFault;
    assert!(all.iter().all(|p| !f.crash_at(*p)));
    let _ = ActorKind::Human;
}
