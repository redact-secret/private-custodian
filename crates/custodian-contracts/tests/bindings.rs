//! Binding, freshness, revocation and settlement semantics.

mod common;

use common::*;
use custodian_contracts::common::{ActorKind, BudgetScope, ExposureState};
use custodian_contracts::execution::{ExecutionOutcome, ExecutionRecord, InternalReceipt};
use custodian_contracts::policy::{check_current, PolicyActivation, MAX_STATE_AGE_SECS};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::{Reservation, ReservationState};
use custodian_contracts::revocation::{RevocationEnvelope, RevocationLog, Standing};
use custodian_contracts::types::*;
use custodian_contracts::{BindingError as B, Contract};
use serde_json::{json, Value};

fn set(v: &mut Value, ptr: &str, new: Value) {
    *v.pointer_mut(ptr)
        .unwrap_or_else(|| panic!("no pointer {ptr}")) = new;
}

fn check_exec(
    a: &custodian_contracts::approval::Approval,
    r: &EvaluationRequest,
) -> Result<PlanDigest, B> {
    a.check_for_execution(r, &current(), ts(NOW + 5), MAX_AGE)
}

// --- Approval: execution ---------------------------------------------------

#[test]
fn matching_approval_passes_and_returns_plan_digest() {
    let d = check_exec(&approval(), &request()).unwrap();
    assert_eq!(d.as_str(), plan_digest());
}

#[test]
fn approval_wrong_request_actor_plan_candidate_domain_population_budget_activation() {
    let r = request();
    // Different request.
    let mut v = approval_json();
    set(&mut v, "/scope/request_id", json!(id("req_", 2)));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::RequestMismatch));
    // Different proposer than the authenticated requester.
    let mut v = approval_json();
    set(&mut v, "/proposer", json!(id("act_", 7)));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::RequestMismatch));
    // Plan changed after approval (any field): digest no longer matches.
    let mut rv = request_json();
    set(&mut rv, "/plan/limits/cpu_seconds", json!(61));
    let changed: EvaluationRequest = parse(&rv);
    assert_eq!(check_exec(&approval(), &changed), Err(B::PlanMismatch));
    // Approval digest forged to another plan.
    let mut v = approval_json();
    set(&mut v, "/scope/plan_digest", json!(dg("another-plan")));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::PlanMismatch));
    // Candidate mismatch with a matching plan digest.
    let mut v = approval_json();
    set(&mut v, "/scope/candidate", json!(dg("another-candidate")));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::CandidateMismatch));
    // Domain mismatch.
    let mut v = approval_json();
    set(&mut v, "/scope/population/domain", json!("pii"));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::DomainMismatch));
    // Population mismatch (digest, epoch, custody version, family).
    for (ptr, val) in [
        (
            "/scope/population/population_digest",
            json!(dg("another-population")),
        ),
        ("/scope/population/epoch_id", json!(id("epo_", 2))),
        ("/scope/population/custody_version", json!(2)),
    ] {
        let mut v = approval_json();
        set(&mut v, ptr, val);
        assert_eq!(
            check_exec(&parse(&v), &r),
            Err(B::PopulationMismatch),
            "{ptr}"
        );
    }
    let mut v = approval_json();
    v["scope"]["population"]["family_id"] = json!(id("fam_", 1));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::PopulationMismatch));
    // Budget scope mismatch (a different scope kind is a different budget).
    let mut v = approval_json();
    set(
        &mut v,
        "/scope/budget",
        json!({"scope":"candidate_lineage_epoch","corpus_id": id("cor_", 1),
               "epoch_id": id("epo_", 1), "lineage_id": id("lin_", 1)}),
    );
    assert_eq!(check_exec(&parse(&v), &r), Err(B::BudgetScopeMismatch));
    // Activation mismatch: approval bound to another activation than the plan.
    let mut v = approval_json();
    set(&mut v, "/activation/activation_id", json!(id("pac_", 2)));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::ActivationMismatch));
    let mut v = approval_json();
    set(&mut v, "/activation/sequence", json!(2));
    assert_eq!(check_exec(&parse(&v), &r), Err(B::ActivationMismatch));
}

#[test]
fn approval_operation_and_actor_kind() {
    let r = request();
    assert_eq!(
        check_exec(&parse(&release_approval_json()), &r),
        Err(B::OperationMismatch)
    );
    // Decode refuses an agent approver; a hand-built one is also refused at check time.
    let mut a = approval();
    a.approver_kind = ActorKind::Agent;
    assert_eq!(check_exec(&a, &r), Err(B::ApproverNotPermitted));
}

#[test]
fn stale_or_expired_approval_rejected() {
    let a = approval();
    let r = request();
    let cur = current();
    let at = |now| a.check_for_execution(&r, &cur, ts(now), 1_000_000);
    assert_eq!(at(NOW - 1), Err(B::ApprovalNotYetValid));
    assert_eq!(at(NOW + 3600), Err(B::ApprovalExpired));
    assert_eq!(at(NOW + 99_999), Err(B::ApprovalExpired));
}

#[test]
fn activation_state_must_be_current_and_active() {
    let a = approval();
    let r = request();
    let now = ts(NOW + 100);
    let run = |obs| a.check_for_execution(&r, &obs, now, MAX_AGE);

    // Observed too long ago, in the future, or with an absurd allowance.
    assert_eq!(run(observed(activation(), NOW + 1)), Err(B::StateStale));
    assert_eq!(run(observed(activation(), NOW + 101)), Err(B::StateStale));
    assert_eq!(
        a.check_for_execution(&r, &observed(activation(), NOW - 1000), now, u64::MAX),
        Err(B::StateStale),
        "caller allowance is clamped to the ceiling"
    );
    assert_eq!(MAX_STATE_AGE_SECS, 300);
    assert!(run(observed(activation(), NOW + 99)).is_ok());

    let fresh = NOW + 100;
    // Revoked (a revocation record has a higher sequence).
    let mut v = activation_json();
    set(&mut v, "/status", json!("revoked"));
    set(&mut v, "/sequence", json!(4));
    assert_eq!(run(observed(parse(&v), fresh)), Err(B::ActivationRevoked));
    // Revoked, even if the stored sequence was not advanced.
    let mut v = activation_json();
    set(&mut v, "/status", json!("revoked"));
    assert_eq!(run(observed(parse(&v), fresh)), Err(B::ActivationRevoked));
    // Superseded.
    let mut v = activation_json();
    set(&mut v, "/status", json!("superseded"));
    assert_eq!(
        run(observed(parse(&v), fresh)),
        Err(B::ActivationSuperseded)
    );
    // Still active but state moved on since the approval was bound: stale approval.
    let mut v = activation_json();
    set(&mut v, "/sequence", json!(4));
    assert_eq!(
        run(observed(parse(&v), fresh)),
        Err(B::ActivationSuperseded)
    );
    // Observed state older than the binding is not usable either.
    let mut v = activation_json();
    set(&mut v, "/sequence", json!(2));
    assert_eq!(run(observed(parse(&v), fresh)), Err(B::ActivationMismatch));
    // Another activation or policy version.
    let mut v = activation_json();
    set(&mut v, "/activation_id", json!(id("pac_", 2)));
    assert_eq!(run(observed(parse(&v), fresh)), Err(B::ActivationMismatch));
    let mut v = activation_json();
    set(&mut v, "/policy/version", json!(2));
    assert_eq!(run(observed(parse(&v), fresh)), Err(B::ActivationMismatch));
    // Window.
    let mut v = activation_json();
    set(&mut v, "/activates_at", json!(NOW + 500));
    set(&mut v, "/changed_at", json!(NOW));
    assert_eq!(
        run(observed(parse(&v), fresh)),
        Err(B::ActivationNotYetActive)
    );
    let mut v = activation_json();
    set(&mut v, "/expires_at", json!(NOW + 100));
    assert_eq!(run(observed(parse(&v), fresh)), Err(B::ActivationExpired));
    let mut v = activation_json();
    set(&mut v, "/expires_at", json!(NOW - 1000));
    let r: Result<PolicyActivation, _> = PolicyActivation::decode(&to_bytes(&v));
    assert!(r.is_err(), "expiry must follow activation");
}

#[test]
fn revocation_wins_over_time_window() {
    let mut v = activation_json();
    set(&mut v, "/status", json!("revoked"));
    let a: PolicyActivation = parse(&v);
    // Well inside the activation window, still revoked.
    assert_eq!(
        check_current(
            &approval().activation,
            &observed(a, NOW + 5),
            ts(NOW + 5),
            MAX_AGE
        ),
        Err(B::ActivationRevoked)
    );
}

// --- Release approval ---------------------------------------------------------

#[test]
fn release_requires_its_own_approval_bound_to_projection() {
    let a: custodian_contracts::approval::Approval = parse(&release_approval_json());
    let digest = projection().projection_digest().unwrap();
    let pol = projection().disclosure_policy;
    let exe = ExecutionId::parse(&id("exe_", 1)).unwrap();
    let now = ts(NOW + 5);
    assert_eq!(
        a.check_for_release(&exe, &digest, &pol, &current(), now, MAX_AGE),
        Ok(())
    );
    assert_eq!(
        a.check_for_release(
            &ExecutionId::parse(&id("exe_", 2)).unwrap(),
            &digest,
            &pol,
            &current(),
            now,
            MAX_AGE
        ),
        Err(B::ExecutionMismatch)
    );
    let other = ProjectionDigest::from_raw([7; 32]);
    assert_eq!(
        a.check_for_release(&exe, &other, &pol, &current(), now, MAX_AGE),
        Err(B::ProjectionMismatch)
    );
    let mut other_pol = pol.clone();
    other_pol.version = Version::new(2).unwrap();
    assert_eq!(
        a.check_for_release(&exe, &digest, &other_pol, &current(), now, MAX_AGE),
        Err(B::PolicyMismatch)
    );
    // An execution approval never authorizes release: completion is not release.
    assert_eq!(
        approval().check_for_release(&exe, &digest, &pol, &current(), now, MAX_AGE),
        Err(B::OperationMismatch)
    );
    // And release honours revocation and staleness like execution does.
    let mut v = activation_json();
    set(&mut v, "/status", json!("revoked"));
    assert_eq!(
        a.check_for_release(
            &exe,
            &digest,
            &pol,
            &observed(parse(&v), NOW + 5),
            now,
            MAX_AGE
        ),
        Err(B::ActivationRevoked)
    );
}

// --- Reservation and refund rule -------------------------------------------------

#[test]
fn reservation_bindings() {
    let r = request();
    let apr = ApprovalId::parse(&id("apr_", 1)).unwrap();
    let res = reservation();
    assert_eq!(res.check_for_execution(&r, &apr, ts(NOW + 1)), Ok(()));
    assert_eq!(
        res.check_for_execution(&r, &ApprovalId::parse(&id("apr_", 2)).unwrap(), ts(NOW + 1)),
        Err(B::ReservationMismatch)
    );
    assert_eq!(
        res.check_for_execution(&r, &apr, ts(NOW + 600)),
        Err(B::ReservationMismatch)
    );
    let mut v = reservation_json();
    set(&mut v, "/plan_digest", json!(dg("another-plan")));
    assert_eq!(
        parse::<Reservation>(&v).check_for_execution(&r, &apr, ts(NOW)),
        Err(B::PlanMismatch)
    );
    let mut v = reservation_json();
    set(&mut v, "/budget/epoch_id", json!(id("epo_", 2)));
    assert_eq!(
        parse::<Reservation>(&v).check_for_execution(&r, &apr, ts(NOW)),
        Err(B::BudgetScopeMismatch)
    );
    let mut v = reservation_json();
    set(&mut v, "/state", json!("consumed"));
    assert_eq!(
        parse::<Reservation>(&v).check_for_execution(&r, &apr, ts(NOW)),
        Err(B::ReservationMismatch)
    );
    let mut v = reservation_json();
    set(&mut v, "/request_id", json!(id("req_", 2)));
    assert_eq!(
        parse::<Reservation>(&v).check_for_execution(&r, &apr, ts(NOW)),
        Err(B::ReservationMismatch)
    );
}

#[test]
fn refund_only_when_no_protected_bytes_acquired() {
    use ExecutionOutcome::*;
    for outcome in [Success, Partial, Failed, Cancelled, Expired, Rejected] {
        // Exposed: never refunded, whatever happened afterwards.
        assert_eq!(
            Reservation::settled_state(ExposureState::Exposed, outcome),
            ReservationState::Consumed,
            "{outcome:?}"
        );
    }
    for outcome in [Failed, Cancelled, Expired] {
        assert_eq!(
            Reservation::settled_state(ExposureState::NotExposed, outcome),
            ReservationState::Refunded,
            "{outcome:?}"
        );
    }
    // Never a refund for a completed or rejected-after-run attempt.
    assert_eq!(
        Reservation::settled_state(ExposureState::NotExposed, Success),
        ReservationState::Consumed
    );
    // A refunded reservation cannot record exposure.
    let mut v = reservation_json();
    set(&mut v, "/state", json!("refunded"));
    set(&mut v, "/exposure", json!("exposed"));
    assert!(Reservation::decode(&to_bytes(&v)).is_err());
    set(&mut v, "/exposure", json!("not_exposed"));
    assert!(Reservation::decode(&to_bytes(&v)).is_ok());

    let mut v = execution_json();
    set(&mut v, "/outcome", json!("failed"));
    set(&mut v, "/reason", json!("execution_failed"));
    assert!(!parse::<ExecutionRecord>(&v).refund_allowed());
    set(&mut v, "/exposure", json!("not_exposed"));
    assert!(parse::<ExecutionRecord>(&v).refund_allowed());
    assert!(!execution().refund_allowed());
}

#[test]
fn legacy_budget_scopes_are_distinct_and_expressible() {
    let pop: BudgetScope = serde_json::from_value(budget()).unwrap();
    let blind: BudgetScope = serde_json::from_value(
        json!({"scope":"candidate_lineage_epoch","corpus_id": id("cor_", 1),
               "epoch_id": id("epo_", 1), "lineage_id": id("lin_", 1)}),
    )
    .unwrap();
    let blind2: BudgetScope = serde_json::from_value(
        json!({"scope":"candidate_lineage_epoch","corpus_id": id("cor_", 1),
               "epoch_id": id("epo_", 1), "lineage_id": id("lin_", 2)}),
    )
    .unwrap();
    let fam: BudgetScope = serde_json::from_value(
        json!({"scope":"population_epoch","corpus_id": id("cor_", 1),
               "epoch_id": id("epo_", 1), "family_id": id("fam_", 1)}),
    )
    .unwrap();
    // One counter per scope: none of these may collapse into another.
    let all = [&pop, &blind, &blind2, &fam];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            assert_eq!(i == j, a == b, "{i} vs {j}");
        }
    }
    let set: std::collections::HashSet<_> = all.iter().map(|s| (*s).clone()).collect();
    assert_eq!(set.len(), 4);
    // A new candidate digest does not create a new lineage budget key.
    let mut a = request_json();
    set_scope(&mut a, &blind);
    let mut b = a.clone();
    set_candidate(&mut b, "yet-another-candidate");
    let (ra, rb): (EvaluationRequest, EvaluationRequest) = (parse(&a), parse(&b));
    assert_ne!(ra.plan.candidate, rb.plan.candidate);
    assert_eq!(ra.plan.accounting.budget, rb.plan.accounting.budget);
}

fn set_scope(v: &mut Value, s: &BudgetScope) {
    v["plan"]["accounting"]["budget"] = serde_json::to_value(s).unwrap();
}

fn set_candidate(v: &mut Value, label: &str) {
    v["plan"]["candidate"] = json!(dg(label));
}

// --- Execution and receipt --------------------------------------------------

#[test]
fn execution_frozen_identities_must_match_plan() {
    let r = request();
    let res = reservation();
    assert_eq!(execution().check_binding(&r, &res), Ok(()));

    for (ptr, val, want) in [
        (
            "/frozen/candidate",
            json!(dg("another-candidate")),
            B::CandidateMismatch,
        ),
        ("/frozen/domain", json!("pii"), B::DomainMismatch),
        (
            "/frozen/population_digest",
            json!(dg("another-population")),
            B::PopulationMismatch,
        ),
        (
            "/frozen/config_digest",
            json!(dg("another-config")),
            B::PlanMismatch,
        ),
        (
            "/frozen/engine/digest",
            json!(dg("another-engine")),
            B::PlanMismatch,
        ),
        ("/frozen/protocol/version", json!("2"), B::PlanMismatch),
        ("/plan_digest", json!(dg("another-plan")), B::PlanMismatch),
        ("/request_id", json!(id("req_", 2)), B::RequestMismatch),
        (
            "/reservation_id",
            json!(id("rsv_", 2)),
            B::ReservationMismatch,
        ),
        ("/approval_id", json!(id("apr_", 2)), B::ReservationMismatch),
        (
            "/activation/activation_id",
            json!(id("pac_", 2)),
            B::ActivationMismatch,
        ),
    ] {
        let mut v = execution_json();
        set(&mut v, ptr, val);
        // Domain mismatch inside `frozen` is caught by the frozen comparison.
        assert_eq!(
            parse::<ExecutionRecord>(&v).check_binding(&r, &res),
            Err(want),
            "{ptr}"
        );
    }
}

#[test]
fn only_full_success_is_releasable() {
    assert!(execution().is_releasable());
    for (outcome, reason, exposure) in [
        ("partial", "execution_failed", "exposed"),
        ("failed", "execution_failed", "exposed"),
        ("cancelled", "cancelled", "exposed"),
        ("expired", "authorization_expired", "not_exposed"),
        ("rejected", "invalid_artifact", "exposed"),
    ] {
        let mut v = execution_json();
        set(&mut v, "/outcome", json!(outcome));
        set(&mut v, "/reason", json!(reason));
        set(&mut v, "/exposure", json!(exposure));
        assert!(!parse::<ExecutionRecord>(&v).is_releasable(), "{outcome}");
    }
}

#[test]
fn prior_successful_receipt_does_not_bypass_revocation() {
    let rc = receipt();
    let now = ts(NOW + 100);
    let ok = observed(activation(), NOW + 99);
    assert_eq!(rc.check_still_valid(&ok, now, MAX_AGE), Ok(()));

    // Same receipt, same success, but the policy activation was revoked since.
    let mut v = activation_json();
    set(&mut v, "/status", json!("revoked"));
    set(&mut v, "/sequence", json!(4));
    assert_eq!(
        rc.check_still_valid(&observed(parse(&v), NOW + 99), now, MAX_AGE),
        Err(B::ActivationRevoked)
    );
    // No current state, or old state: cannot be used.
    assert_eq!(
        rc.check_still_valid(&observed(activation(), NOW - 1), now, MAX_AGE),
        Err(B::StateStale)
    );
    // A partial receipt is never reusable.
    let mut v = receipt_json();
    set(&mut v, "/outcome", json!("partial"));
    set(&mut v, "/roster/observed", json!(5));
    assert_eq!(
        parse::<InternalReceipt>(&v).check_still_valid(&ok, now, MAX_AGE),
        Err(B::NotReleasable)
    );
}

// --- Public projection standing and the revocation feed ---------------------------

fn feed_id() -> FeedId {
    FeedId::parse(&id("fed_", 1)).unwrap()
}

fn env(
    seq: u64,
    previous: Option<&RevocationEnvelope>,
    entries: Vec<Value>,
    fresh_until: u64,
) -> RevocationEnvelope {
    let mut v = revocation_json();
    set(&mut v, "/sequence", json!(seq));
    set(&mut v, "/fresh_until", json!(fresh_until));
    set(&mut v, "/entries", json!(entries));
    if let Some(p) = previous {
        v["previous"] = json!(p.document_digest().unwrap().as_str());
    }
    parse(&v)
}

fn unrelated() -> Value {
    revocation_json()["entries"][0].clone()
}

fn entry(target: Value, action: Value, effective_at: u64) -> Value {
    json!({"target": target, "action": action, "reason": "contamination", "effective_at": effective_at})
}

fn live_log() -> (RevocationLog, RevocationEnvelope) {
    let e1 = env(1, None, vec![unrelated()], NOW + 10_000);
    let mut log = RevocationLog::new(feed_id());
    log.apply(&e1).unwrap();
    (log, e1)
}

#[test]
fn projection_valid_only_with_fresh_feed() {
    let p = projection();
    let now = ts(NOW + 100);
    let (log, _) = live_log();
    assert_eq!(log.standing(&p, now), Standing::Valid);
    assert!(Standing::Valid.is_usable());

    // No feed state at all: unknown is not valid.
    assert_eq!(
        RevocationLog::new(feed_id()).standing(&p, now),
        Standing::Stale
    );
    // Feed not fresh any more.
    assert_eq!(log.standing(&p, ts(NOW + 10_001)), Standing::Stale);
    // Projection past its own freshness.
    let (log2, _) = {
        let e = env(1, None, vec![], NOW + 1_000_000);
        let mut l = RevocationLog::new(feed_id());
        l.apply(&e).unwrap();
        (l, e)
    };
    assert_eq!(log2.standing(&p, ts(NOW + 40 + 86_400)), Standing::Expired);
    // Not yet issued.
    assert_eq!(log.standing(&p, ts(NOW)), Standing::Stale);
    // Projection requires a newer feed than the consumer holds.
    let mut v = projection_json();
    set(&mut v, "/revocation_feed/min_sequence", json!(2));
    assert_eq!(log.standing(&parse(&v), now), Standing::Stale);
    // Different feed.
    let mut v = projection_json();
    set(&mut v, "/revocation_feed/feed_id", json!(id("fed_", 2)));
    assert_eq!(log.standing(&parse(&v), now), Standing::Stale);
    assert!(!Standing::Stale.is_usable() && !Standing::Expired.is_usable());
}

#[test]
fn revocation_targets_all_apply() {
    let p = projection();
    let now = ts(NOW + 100);
    let targets = [
        json!({"target":"projection","projection_id": id("prj_", 1)}),
        json!({"target":"receipt","receipt_id": id("rcp_", 9)}),
        json!({"target":"candidate","candidate": dg("synthetic-candidate")}),
        json!({"target":"population","population":{"kind":"opaque","id": id("ppr_", 1)}}),
        json!({"target":"policy","policy": disclosure_policy()}),
    ];
    for t in targets {
        for action in [
            json!({"action":"revoked"}),
            json!({"action":"contaminated"}),
        ] {
            let (mut log, e1) = live_log();
            let e2 = env(
                2,
                Some(&e1),
                vec![entry(t.clone(), action, NOW + 60)],
                NOW + 10_000,
            );
            log.apply(&e2).unwrap();
            assert_eq!(log.standing(&p, now), Standing::Revoked, "{t}");
        }
    }
    // Non-matching targets do not revoke.
    let (mut log, e1) = live_log();
    let other = vec![
        entry(
            json!({"target":"projection","projection_id": id("prj_", 2)}),
            json!({"action":"revoked"}),
            NOW,
        ),
        entry(
            json!({"target":"candidate","candidate": dg("not-it")}),
            json!({"action":"revoked"}),
            NOW,
        ),
        entry(
            json!({"target":"population","population":{"kind":"opaque","id": id("ppr_", 2)}}),
            json!({"action":"revoked"}),
            NOW,
        ),
    ];
    log.apply(&env(2, Some(&e1), other, NOW + 10_000)).unwrap();
    assert_eq!(log.standing(&p, now), Standing::Valid);
}

#[test]
fn revocation_overrides_earlier_success_and_staleness_cannot_hide_it() {
    let p = projection();
    let (mut log, e1) = live_log();
    assert_eq!(log.standing(&p, ts(NOW + 100)), Standing::Valid);
    let e2 = env(
        2,
        Some(&e1),
        vec![entry(
            json!({"target":"projection","projection_id": id("prj_", 1)}),
            json!({"action":"revoked"}),
            NOW + 200,
        )],
        NOW + 10_000,
    );
    log.apply(&e2).unwrap();
    // Effective time not reached: still valid; reached: revoked, forever after.
    assert_eq!(log.standing(&p, ts(NOW + 199)), Standing::Valid);
    assert_eq!(log.standing(&p, ts(NOW + 200)), Standing::Revoked);
    // Revoked even when the feed itself has gone stale or the projection expired.
    assert_eq!(log.standing(&p, ts(NOW + 50_000)), Standing::Revoked);
    assert_eq!(
        log.standing(&p, ts(NOW + 40 + 86_400 + 5)),
        Standing::Revoked
    );
    // A later empty envelope cannot clear it.
    let e3 = env(3, Some(&e2), vec![], NOW + 20_000);
    log.apply(&e3).unwrap();
    assert_eq!(log.standing(&p, ts(NOW + 300)), Standing::Revoked);
}

#[test]
fn supersession_is_not_validity() {
    let p = projection();
    let (mut log, e1) = live_log();
    let e2 = env(
        2,
        Some(&e1),
        vec![entry(
            json!({"target":"projection","projection_id": id("prj_", 1)}),
            json!({"action":"superseded","superseded_by": id("prj_", 2)}),
            NOW + 60,
        )],
        NOW + 10_000,
    );
    log.apply(&e2).unwrap();
    assert_eq!(log.standing(&p, ts(NOW + 100)), Standing::Superseded);
    assert!(!Standing::Superseded.is_usable());
    // Revocation outranks supersession.
    let e3 = env(
        3,
        Some(&e2),
        vec![entry(
            json!({"target":"projection","projection_id": id("prj_", 1)}),
            json!({"action":"revoked"}),
            NOW + 70,
        )],
        NOW + 10_000,
    );
    log.apply(&e3).unwrap();
    assert_eq!(log.standing(&p, ts(NOW + 100)), Standing::Revoked);
}

#[test]
fn feed_chain_integrity() {
    let (mut log, e1) = live_log();
    // Replay of the same sequence.
    assert!(log.apply(&e1).is_err());
    // Gap.
    let gap = env(3, Some(&e1), vec![], NOW + 10_000);
    assert!(log.apply(&gap).is_err());
    // Wrong previous link.
    let mut bad = env(2, Some(&e1), vec![], NOW + 10_000);
    bad.previous = Some(DocumentDigest::from_raw([1; 32]));
    assert!(log.apply(&bad).is_err());
    // Other feed.
    let mut v = revocation_json();
    set(&mut v, "/feed_id", json!(id("fed_", 2)));
    v["sequence"] = json!(2);
    v["previous"] = json!(e1.document_digest().unwrap().as_str());
    assert!(log.apply(&parse::<RevocationEnvelope>(&v)).is_err());
    assert_eq!(log.sequence(), 1);
    // Correct next link applies.
    let ok = env(2, Some(&e1), vec![], NOW + 10_000);
    assert!(log.apply(&ok).is_ok());
    assert_eq!(log.sequence(), 2);
    // An envelope that fails its own shape rules is rejected.
    let mut broken = env(3, Some(&ok), vec![], NOW + 10_000);
    broken.previous = None;
    assert!(log.apply(&broken).is_err());
}

#[test]
fn effective_at_in_the_future_does_not_revoke_yet() {
    let p = projection();
    let (mut log, e1) = live_log();
    let e2 = env(
        2,
        Some(&e1),
        vec![entry(
            json!({"target":"candidate","candidate": dg("synthetic-candidate")}),
            json!({"action":"contaminated"}),
            NOW + 5_000,
        )],
        NOW + 10_000,
    );
    log.apply(&e2).unwrap();
    assert_eq!(log.standing(&p, ts(NOW + 100)), Standing::Valid);
    assert_eq!(log.standing(&p, ts(NOW + 5_000)), Standing::Revoked);
}
