//! The operator CLI through the same authorization and budget control plane
//! (C10). Synthetic only: no real credential, key, population or deployment.

mod common;

use common::*;
use custodian_cli::command::{
    Contaminated, ReconcileTarget, RepairCommand, RevocationKind, RevocationVerb, VerifyTarget,
};
use custodian_cli::{CliReason, Command, OperatorPolicy};
use custodian_contracts::policy::PolicyActivation;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::{ActorRef, EpochId};
use custodian_contracts::Contract;
use custodian_core::{Contamination, RunState};
use serde_json::json;

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn request_as(w: &World, n: u32, who: Who) -> (EvaluationRequest, Vec<u8>) {
    let (req, _) = w.request(n);
    let mut v = serde_json::to_value(&req).unwrap();
    v["asserted_actor"] = json!(who.actor());
    let bytes = serde_json::to_vec(&v).unwrap();
    let req = EvaluationRequest::decode(&bytes).unwrap();
    let canonical = req.canonical_bytes().unwrap();
    (req, canonical)
}

fn submit_doc(w: &World, who: Who, doc: Vec<u8>) -> custodian_cli::Output {
    w.run(who, &Command::RequestSubmit { document: doc })
}

// ---- authentication and the operator policy ---------------------------------------

#[test]
fn a_wrong_unknown_short_or_expired_credential_authenticates_nobody() {
    let w = World::new(1);
    let now = custodian_contracts::types::Timestamp::new(NOW).unwrap();
    let a = &w.authority;
    let ok = a.authenticate(&Who::Requester.actor(), &Who::Requester.token(), now);
    assert!(ok.is_ok());
    // wrong credential for a real identity, unknown identity, short credential:
    // one code for all three, so the answer is no oracle for who exists.
    let wrong = a
        .authenticate(&Who::Requester.actor(), &Who::Approver.token(), now)
        .unwrap_err();
    let unknown = a
        .authenticate(&cc::id("act_", 99), &Who::Requester.token(), now)
        .unwrap_err();
    let short = a
        .authenticate(&Who::Requester.actor(), b"short", now)
        .unwrap_err();
    let malformed = a
        .authenticate("not an actor", &Who::Requester.token(), now)
        .unwrap_err();
    assert_eq!(wrong, CliReason::Unauthenticated);
    assert_eq!(wrong, unknown);
    assert_eq!(wrong, short);
    assert_eq!(wrong, malformed);
    assert_eq!(wrong.exit_code(), 3);
    // A policy outside its validity window authenticates nobody.
    let late = custodian_contracts::types::Timestamp::new(NOW + 2_000_000).unwrap();
    assert_eq!(
        a.authenticate(&Who::Requester.actor(), &Who::Requester.token(), late)
            .unwrap_err(),
        CliReason::OperatorPolicyExpired
    );
    let early = custodian_contracts::types::Timestamp::new(NOW - 5000).unwrap();
    assert_eq!(
        a.authenticate(&Who::Requester.actor(), &Who::Requester.token(), early)
            .unwrap_err(),
        CliReason::OperatorPolicyExpired
    );
}

#[test]
fn the_policy_file_cannot_grant_an_agent_or_automation_identity_authority() {
    let base = |kind: &str, roles: &[&str]| {
        let mut p = policy_json(NOW - 10, NOW + 10_000);
        p["identities"] = json!([{
            "actor": Who::Agent.actor(), "kind": kind, "roles": roles,
            "credential_sha256": credential_hex(),
        }]);
        serde_json::to_vec(&p).unwrap()
    };
    // Control: a human may hold anything.
    assert!(OperatorPolicy::from_json(&base("human", &["approver", "operator"])).is_ok());
    for roles in [
        &["approver"][..],
        &["operator"],
        &["auditor"],
        &["requester", "approver"],
    ] {
        assert_eq!(
            OperatorPolicy::from_json(&base("agent", roles)).unwrap_err(),
            CliReason::OperatorPolicyInvalid,
            "agent {roles:?}"
        );
    }
    for roles in [&["approver"][..], &["operator"], &["requester", "operator"]] {
        assert_eq!(
            OperatorPolicy::from_json(&base("service", roles)).unwrap_err(),
            CliReason::OperatorPolicyInvalid,
            "service {roles:?}"
        );
    }
    assert!(OperatorPolicy::from_json(&base("service", &["requester", "auditor"])).is_ok());
}

fn credential_hex() -> String {
    custodian_cli::credential_digest(b"synthetic-credential-for-shape-tests-0000")
}

#[test]
fn a_malformed_policy_file_is_refused() {
    let good = policy_json(NOW - 10, NOW + 10_000);
    let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
    let mut p = good.clone();
    p["schema"] = json!("other/1");
    cases.push(("schema", p));
    let mut p = good.clone();
    p["unexpected"] = json!(1);
    cases.push(("unknown field", p));
    let mut p = good.clone();
    p["expires_at"] = json!(NOW - 10);
    cases.push(("empty window", p));
    let mut p = good.clone();
    p["identities"] = json!([]);
    cases.push(("no identities", p));
    let mut p = good.clone();
    p["identities"][0]["credential_sha256"] = json!("ABC");
    cases.push(("bad digest", p));
    let mut p = good.clone();
    let dup = p["identities"][0].clone();
    p["identities"].as_array_mut().unwrap().push(dup);
    cases.push(("duplicate identity", p));
    let mut p = good.clone();
    p["identities"][1]["credential_sha256"] = p["identities"][0]["credential_sha256"].clone();
    cases.push(("shared credential", p));
    let mut p = good.clone();
    p["identities"][0]["roles"] = json!([]);
    cases.push(("no roles", p));
    let mut p = good.clone();
    p["limits"] = json!({"approval_ttl_secs": 999_999_999u64});
    cases.push(("ttl above the contract cap", p));
    for (why, p) in cases {
        assert_eq!(
            OperatorPolicy::from_json(&serde_json::to_vec(&p).unwrap()).unwrap_err(),
            CliReason::OperatorPolicyInvalid,
            "{why}"
        );
    }
}

// ---- unauthorized actions -----------------------------------------------------------

#[test]
fn every_role_is_limited_to_its_own_commands() {
    let w = World::new(3);
    let (req, doc) = w.request(1);
    // An approver does not hold the requester role.
    assert_eq!(
        code(&submit_doc(&w, Who::Approver, doc.clone())),
        "forbidden"
    );
    assert_eq!(
        code(&submit_doc(&w, Who::Auditor, doc.clone())),
        "forbidden"
    );
    assert_eq!(
        code(&submit_doc(&w, Who::Operator, doc.clone())),
        "forbidden"
    );
    assert!(submit_doc(&w, Who::Requester, doc).is_ok());
    // A requester cannot approve, repair, publish, report or verify.
    assert_eq!(
        code(&w.run(Who::Requester, &approve_cmd(&req))),
        "forbidden"
    );
    assert_eq!(code(&w.run(Who::Auditor, &approve_cmd(&req))), "forbidden");
    assert_eq!(code(&w.run(Who::Operator, &approve_cmd(&req))), "forbidden");
    assert_eq!(
        code(&w.run(Who::Requester, &Command::Verify(VerifyTarget::All))),
        "forbidden"
    );
    assert_eq!(
        code(&w.run(Who::Approver, &Command::Verify(VerifyTarget::All))),
        "forbidden"
    );
    assert_eq!(
        code(&w.run(Who::Requester, &Command::FeedPublish)),
        "forbidden"
    );
    assert_eq!(
        code(&w.run(Who::Approver, &Command::FeedPublish)),
        "forbidden"
    );
    assert_eq!(
        code(&w.run(Who::Auditor, &Command::FeedPublish)),
        "forbidden"
    );
    let id = w.rw.store.store_id().unwrap();
    for who in [Who::Requester, Who::Approver, Who::Auditor] {
        let o = w.run(
            who,
            &Command::Repair(RepairCommand::Recover {
                confirm_store_id: id.clone(),
            }),
        );
        assert_eq!(code(&o), "forbidden", "{who:?}");
        assert_eq!(o.exit_code(), 4);
    }
    // A requester sees only its own request; an auditor sees all.
    assert!(w.run(Who::Auditor, &status_cmd(&req)).is_ok());
    assert!(w.run(Who::Requester, &status_cmd(&req)).is_ok());
    // Nothing was charged by any of the refusals.
    assert_eq!(w.budget().held, 0);
}

#[test]
fn an_agent_identity_can_request_but_never_approve_cancel_others_or_repair() {
    let w = World::new(3);
    let (req, doc) = request_as(&w, 1, Who::Agent);
    assert!(submit_doc(&w, Who::Agent, doc).is_ok());
    let approve = approve_cmd(&req);
    let o = w.run(Who::Agent, &approve);
    assert_eq!(code(&o), "agent_not_permitted");
    assert_eq!(o.exit_code(), 4);
    assert_eq!(
        code(&w.run(Who::Agent, &Command::FeedPublish)),
        "agent_not_permitted"
    );
    assert_eq!(
        code(&w.run(Who::Agent, &Command::Verify(VerifyTarget::All))),
        "agent_not_permitted"
    );
    let (epoch, key) = (w.rw.epoch.clone(), idk(1));
    for cmd in [
        Command::LifecycleRetire {
            epoch: epoch.clone(),
            confirm_epoch: epoch.clone(),
            reason: "operator_decision".into(),
            key: key.clone(),
        },
        Command::LifecycleClear {
            epoch: epoch.clone(),
            confirm_epoch: epoch.clone(),
            key: key.clone(),
        },
        Command::LifecycleReport {
            epoch: epoch.clone(),
            kind: Contaminated::UnreviewedChange,
            reason: "integrity_alarm".into(),
            key: key.clone(),
        },
    ] {
        assert_eq!(code(&w.run(Who::Agent, &cmd)), "agent_not_permitted");
    }
    // The pending request was not approved by any of that.
    let st = w.run(Who::Auditor, &status_cmd(&req));
    assert_eq!(st.field("submission").unwrap(), "pending");
    assert_eq!(w.budget().held, 0);
}

#[test]
fn an_automation_identity_can_never_approve_clear_retire_rotate_or_publish() {
    let w = World::new(3);
    let (req, doc) = request_as(&w, 1, Who::Service);
    assert!(submit_doc(&w, Who::Service, doc).is_ok());
    let epoch = w.rw.epoch.clone();
    let next = w.rw.seal_next("svc");
    let cmds = vec![
        approve_cmd(&req),
        Command::FeedPublish,
        Command::LifecycleClear {
            epoch: epoch.clone(),
            confirm_epoch: epoch.clone(),
            key: idk(1),
        },
        Command::LifecycleRetire {
            epoch: epoch.clone(),
            confirm_epoch: epoch.clone(),
            reason: "operator_decision".into(),
            key: idk(2),
        },
        Command::LifecycleRotate {
            predecessor: epoch.clone(),
            successor: next.clone(),
            confirm_predecessor: epoch.clone(),
            confirm_successor: next,
            run_budget_limit: 1,
            reason: "planned_rotation".into(),
            key: idk(3),
        },
        Command::LifecycleReport {
            epoch: epoch.clone(),
            kind: Contaminated::Exposed,
            reason: "results_exposed".into(),
            key: idk(4),
        },
        Command::Repair(RepairCommand::Recover {
            confirm_store_id: w.rw.store.store_id().unwrap(),
        }),
    ];
    for c in cmds {
        let o = w.run(Who::Service, &c);
        assert_eq!(code(&o), "automation_not_permitted", "{}", c.name());
        assert_eq!(o.exit_code(), 4);
    }
    // It may verify (auditor role) and see status.
    assert!(w
        .run(Who::Service, &Command::Verify(VerifyTarget::Ledger))
        .is_ok());
    assert_eq!(w.budget().held, 0);
    assert_eq!(
        w.rw.store.epoch_standing(epoch.as_str()).unwrap(),
        None,
        "no standing was recorded"
    );
}

// ---- the request path -----------------------------------------------------------------

#[test]
fn submit_then_explicit_approval_reserves_the_budget_once_and_is_audited() {
    let w = World::new(2);
    let (req, _) = w.request(1);
    let o = w.submit(Who::Requester, 1);
    assert_eq!(code(&o), "submitted");
    assert_eq!(o.field("status").unwrap(), "pending");
    // Submitting holds nothing.
    assert_eq!(w.budget().held, 0);
    // The requester's status shows pending.
    let st = w.run(Who::Requester, &status_cmd(&req));
    assert_eq!(st.field("submission").unwrap(), "pending");
    assert_eq!(st.field("budget_available").unwrap(), 2);

    let o = w.approve(Who::Approver, 1);
    assert_eq!(code(&o), "approved", "{}", o.render());
    assert_eq!(o.exit_code(), 0);
    assert_eq!(o.field("run_state").unwrap(), "reserved");
    assert_eq!(w.budget().held, 1);
    for k in [
        "request.submitted",
        "approval.granted",
        "reservation.created",
    ] {
        assert!(w.kinds().iter().any(|x| x == k), "{k}");
    }
    let st = w.run(Who::Auditor, &status_cmd(&req));
    assert_eq!(st.field("submission").unwrap(), "approved");
    assert_eq!(st.field("run_state").unwrap(), "reserved");
    assert_eq!(
        st.field("decided_by").unwrap(),
        &json!(Who::Approver.actor())
    );
    // The submission is idempotent and does not double count.
    let again = w.submit(Who::Requester, 1);
    assert_eq!(again.field("status").unwrap(), "reserved_elsewhere");
    assert_eq!(w.budget().held, 1);
    w.rw.store.integrity_check().unwrap();
}

#[test]
fn a_repeat_approval_is_refused_and_changes_nothing() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    assert!(w.approve(Who::Approver, 1).is_ok());
    let before = w.kinds().len();
    for who in [Who::Approver, Who::Dual] {
        let o = w.approve(who, 1);
        assert_eq!(code(&o), "already_decided");
        assert_eq!(o.exit_code(), 5);
    }
    assert_eq!(w.budget().held, 1);
    assert_eq!(w.kinds().len(), before);
}

#[test]
fn the_requester_cannot_approve_their_own_request() {
    let w = World::new(3);
    // The dual-role human requests and tries to approve it.
    let (req, doc) = request_as(&w, 1, Who::Dual);
    assert!(submit_doc(&w, Who::Dual, doc).is_ok());
    let o = w.run(Who::Dual, &approve_cmd(&req));
    assert_eq!(code(&o), "self_approval");
    assert_eq!(o.exit_code(), 4);
    assert_eq!(w.budget().held, 0);
    assert_eq!(
        w.run(Who::Auditor, &status_cmd(&req))
            .field("submission")
            .unwrap(),
        "pending"
    );
    // The same human can approve somebody else's request.
    w.submit(Who::Requester, 2);
    assert!(w.approve(Who::Dual, 2).is_ok());
    // And a different approver can approve theirs.
    assert!(w.run(Who::Approver, &approve_cmd(&req)).is_ok());
    assert_eq!(w.budget().held, 2);
}

#[test]
fn a_request_document_cannot_claim_another_requester() {
    let w = World::new(3);
    let (_, doc) = request_as(&w, 1, Who::Approver);
    // The requester presents a document that names the approver.
    let o = submit_doc(&w, Who::Requester, doc);
    assert_eq!(code(&o), "actor_mismatch");
    assert_eq!(w.rw.store.submission(&cc::id("req_", 1)).unwrap(), None);
}

#[test]
fn approval_needs_the_exact_plan_digest() {
    let w = World::new(3);
    let (req, _) = w.request(1);
    w.submit(Who::Requester, 1);
    let wrong = Command::RequestApprove {
        request_id: req.request_id.clone(),
        confirm_plan_digest: custodian_contracts::types::PlanDigest::parse(&cc::dg("other"))
            .unwrap(),
        ttl_secs: None,
    };
    let o = w.run(Who::Approver, &wrong);
    assert_eq!(code(&o), "confirmation_mismatch");
    assert_eq!(o.exit_code(), 5);
    assert_eq!(w.budget().held, 0);
}

#[test]
fn an_exhausted_budget_is_a_recorded_denial_and_never_a_free_run() {
    let w = World::new(1);
    w.submit(Who::Requester, 1);
    assert!(w.approve(Who::Approver, 1).is_ok());
    w.submit(Who::Requester, 2);
    let o = w.approve(Who::Approver, 2);
    assert_eq!(code(&o), "budget_exhausted");
    assert_eq!(o.exit_code(), 5);
    assert_eq!(o.field("recorded").unwrap(), true);
    assert_eq!(o.field("run_state").unwrap(), "denied");
    let b = w.budget();
    assert_eq!((b.limit, b.held, b.consumed), (1, 1, 0));
    // A denied request cannot be approved again.
    assert_eq!(code(&w.approve(Who::Approver, 2)), "already_decided");
    // The dry run says so before anything is recorded.
    w.submit(Who::Requester, 3);
    let d = w.dry(Who::Approver, &approve_cmd(&w.request(3).0));
    assert_eq!(code(&d), "budget_exhausted");
    assert_eq!(d.field("recorded"), None);
    assert_eq!(
        w.rw.store
            .submission(&cc::id("req_", 3))
            .unwrap()
            .unwrap()
            .status,
        custodian_store::SubmissionStatus::Pending
    );
    w.rw.store.integrity_check().unwrap();
}

fn newer_activation(w: &World, seq: u64, status: &str) {
    let mut v = serde_json::to_value(cc::activation()).unwrap();
    v["sequence"] = json!(seq);
    v["status"] = json!(status);
    let act = PolicyActivation::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    w.rw.store
        .record_activation(&act, &sc::actor(), NOW)
        .unwrap();
}

#[test]
fn a_stale_superseded_revoked_or_expired_policy_fails_submit_and_approve() {
    // Superseded by a newer sequence.
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    newer_activation(&w, 4, "active");
    let o = w.approve(Who::Approver, 1);
    assert_eq!(code(&o), "policy_not_current");
    assert_eq!(o.exit_code(), 5);
    assert_eq!(code(&w.submit(Who::Requester, 2)), "policy_not_current");
    assert_eq!(w.budget().held, 0);
    // Revoked.
    newer_activation(&w, 5, "revoked");
    assert_eq!(code(&w.approve(Who::Approver, 1)), "policy_not_current");
    // The read-only validator agrees.
    let (_, doc) = w.request(9);
    assert_eq!(
        code(&w.run(Who::Requester, &Command::PolicyValidate { document: doc })),
        "policy_not_current"
    );

    // Expired by the clock.
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    w.clock.set(NOW + 200_000);
    assert_eq!(code(&w.approve(Who::Approver, 1)), "policy_not_current");

    // Never observed: the plan names an activation the store has never seen.
    let w = World::new(3);
    let mut v = serde_json::to_value(&w.request(1).0).unwrap();
    v["plan"]["policy_activation"]["activation_id"] = json!(cc::id("pac_", 77));
    let r = EvaluationRequest::decode(&serde_json::to_vec(&v).unwrap()).unwrap();
    let o = submit_doc(&w, Who::Requester, r.canonical_bytes().unwrap());
    assert_eq!(code(&o), "stale_policy");
    assert_eq!(o.exit_code(), 5);
}

#[test]
fn an_expired_approval_ttl_is_capped_by_the_reviewed_policy() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    let (req, _) = w.request(1);
    // Asking for a longer lifetime than the policy allows is capped, not obeyed.
    let o = w.run(
        Who::Approver,
        &Command::RequestApprove {
            request_id: req.request_id.clone(),
            confirm_plan_digest: req.plan.plan_digest().unwrap(),
            ttl_secs: Some(999_999_999),
        },
    );
    assert_eq!(code(&o), "approved");
    let apr =
        w.rw.store
            .reservation(
                &w.rw
                    .store
                    .latest_attempt_of(req.request_id.as_str())
                    .unwrap()
                    .unwrap()
                    .reservation_id
                    .unwrap(),
            )
            .unwrap();
    assert!(apr.is_some());
}

#[test]
fn cancel_before_and_after_approval_follows_the_store_settlement_rules() {
    let w = World::new(3);
    // Pending: cancelled by its requester, final.
    let (req1, _) = w.request(1);
    w.submit(Who::Requester, 1);
    let c = w.run(
        Who::Requester,
        &Command::RequestCancel {
            request_id: req1.request_id.clone(),
        },
    );
    assert_eq!(code(&c), "cancelled");
    assert_eq!(code(&w.approve(Who::Approver, 1)), "already_decided");
    // Reserved (not started): cancelled by an operator, refunded.
    let (req2, _) = w.request(2);
    w.submit(Who::Requester, 2);
    w.approve(Who::Approver, 2);
    assert_eq!(w.budget().held, 1);
    // Another requester-level identity cannot see or cancel it.
    let other = w.run(
        Who::Agent,
        &Command::RequestCancel {
            request_id: req2.request_id.clone(),
        },
    );
    assert_eq!(code(&other), "not_found");
    let c = w.run(
        Who::Operator,
        &Command::RequestCancel {
            request_id: req2.request_id.clone(),
        },
    );
    assert_eq!(code(&c), "cancelled", "{}", c.render());
    assert_eq!(c.field("settlement").unwrap(), "refunded");
    let b = w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 1));
    assert_eq!(
        w.rw.store
            .latest_attempt_of(req2.request_id.as_str())
            .unwrap()
            .unwrap()
            .state,
        RunState::Cancelled
    );
    // A cancel by an approver (no operator role) of someone else's request.
    let (req3, _) = w.request(3);
    w.submit(Who::Requester, 3);
    assert_eq!(
        code(&w.run(
            Who::Approver,
            &Command::RequestCancel {
                request_id: req3.request_id.clone()
            }
        )),
        "forbidden"
    );
}

#[test]
fn status_hides_other_requesters_requests_and_unknown_ids_look_the_same() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    let (req, _) = w.request(1);
    let hidden = w.run(Who::Agent, &status_cmd(&req));
    let unknown = w.run(
        Who::Agent,
        &Command::RequestStatus {
            request_id: rid(500),
        },
    );
    assert_eq!(code(&hidden), "not_found");
    assert_eq!(code(&unknown), "not_found");
    assert_eq!(hidden.exit_code(), 6);
    // A failure echoes no request identifier, so the two are indistinguishable.
    assert_eq!(hidden.render(), unknown.render());
}

// ---- dry run ------------------------------------------------------------------------------

#[test]
fn dry_run_validates_everything_and_writes_nothing() {
    let w = World::new(2);
    let (req, doc) = w.request(1);
    let before = w.kinds().len();
    let d = w.dry(Who::Requester, &Command::RequestSubmit { document: doc });
    assert_eq!(code(&d), "would_submit");
    assert!(d.to_value()["dry_run"].as_bool().unwrap());
    assert_eq!(
        w.rw.store.submission(req.request_id.as_str()).unwrap(),
        None
    );
    // A dry run still enforces authorization, binding and policy.
    assert_eq!(
        code(&w.dry(
            Who::Approver,
            &Command::RequestSubmit {
                document: w.request(1).1
            }
        )),
        "forbidden"
    );
    w.submit(Who::Requester, 1);
    let a = w.dry(Who::Approver, &approve_cmd(&req));
    assert_eq!(code(&a), "would_approve");
    assert_eq!(w.budget().held, 0);
    let bad = w.dry(
        Who::Approver,
        &Command::RequestApprove {
            request_id: req.request_id.clone(),
            confirm_plan_digest: custodian_contracts::types::PlanDigest::parse(&cc::dg("x"))
                .unwrap(),
            ttl_secs: None,
        },
    );
    assert_eq!(code(&bad), "confirmation_mismatch");
    assert_eq!(
        w.kinds().len(),
        before + 1,
        "only the real submission was audited"
    );
    let v = w.dry(Who::Dual, &approve_cmd(&req));
    assert_eq!(code(&v), "would_approve");
    newer_activation(&w, 4, "active");
    assert_eq!(
        code(&w.dry(Who::Approver, &approve_cmd(&req))),
        "policy_not_current"
    );
}

#[test]
fn policy_validate_is_read_only_and_open_to_every_authenticated_role() {
    let w = World::new(1);
    let (_, doc) = w.request(1);
    let before = w.kinds().len();
    for who in [
        Who::Requester,
        Who::Approver,
        Who::Operator,
        Who::Auditor,
        Who::Agent,
    ] {
        let o = w.run(
            who,
            &Command::PolicyValidate {
                document: doc.clone(),
            },
        );
        assert_eq!(code(&o), "valid", "{who:?}");
        assert_eq!(o.field("budget_available").unwrap(), true);
    }
    assert_eq!(w.kinds().len(), before);
    let o = w.run(
        Who::Requester,
        &Command::PolicyValidate {
            document: b"{}".to_vec(),
        },
    );
    assert_eq!(code(&o), "invalid_document");
    assert_eq!(o.exit_code(), 2);
}

// ---- policy activation import ----------------------------------------------------------------

#[test]
fn only_a_human_operator_imports_an_activation_and_only_with_the_exact_ids() {
    let w = World::new(1);
    let mut v = serde_json::to_value(cc::activation()).unwrap();
    v["sequence"] = json!(4);
    let doc = serde_json::to_vec(&v).unwrap();
    let cmd = |id: &str, seq: u64| Command::PolicyImportActivation {
        document: doc.clone(),
        confirm_activation_id: id.to_owned(),
        confirm_sequence: seq,
    };
    let id = cc::id("pac_", 1);
    assert_eq!(code(&w.run(Who::Approver, &cmd(&id, 4))), "forbidden");
    assert_eq!(
        code(&w.run(Who::Service, &cmd(&id, 4))),
        "automation_not_permitted"
    );
    assert_eq!(
        code(&w.run(Who::Operator, &cmd(&id, 3))),
        "confirmation_mismatch"
    );
    assert_eq!(
        code(&w.run(Who::Operator, &cmd(&cc::id("pac_", 2), 4))),
        "confirmation_mismatch"
    );
    assert_eq!(code(&w.dry(Who::Operator, &cmd(&id, 4))), "would_import");
    assert_eq!(
        w.rw.store
            .latest_activation(&id)
            .unwrap()
            .unwrap()
            .sequence
            .get(),
        3
    );
    assert_eq!(code(&w.run(Who::Operator, &cmd(&id, 4))), "imported");
    assert_eq!(code(&w.run(Who::Operator, &cmd(&id, 4))), "unchanged");
    assert_eq!(
        w.rw.store
            .latest_activation(&id)
            .unwrap()
            .unwrap()
            .sequence
            .get(),
        4
    );
    assert!(w.kinds().iter().any(|k| k == "activation.recorded"));
}

// ---- lifecycle --------------------------------------------------------------------------------

fn retire_cmd(w: &World, n: u32) -> Command {
    Command::LifecycleRetire {
        epoch: w.rw.epoch.clone(),
        confirm_epoch: w.rw.epoch.clone(),
        reason: "operator_decision".into(),
        key: idk(n),
    }
}

#[test]
fn contamination_blocks_new_use_and_a_permanent_one_is_never_clearable() {
    let w = World::new(3);
    w.submit(Who::Requester, 1);
    let report = Command::LifecycleReport {
        epoch: w.rw.epoch.clone(),
        kind: Contaminated::Exposed,
        reason: "results_exposed".into(),
        key: idk(1),
    };
    let o = w.run(Who::Operator, &report);
    assert_eq!(code(&o), "reported", "{}", o.render());
    assert_eq!(o.field("new_contamination").unwrap(), "exposed");
    // A permanent report also retires the epoch, in the same call.
    assert_eq!(o.field("also_retired").unwrap(), true);
    assert_eq!(
        w.rw.store
            .epoch_standing(w.rw.epoch.as_str())
            .unwrap()
            .unwrap()
            .standing
            .retired,
        true
    );
    // Replay with the same key; a different change under the same key conflicts.
    assert_eq!(w.run(Who::Operator, &report).field("replay").unwrap(), true);
    // Both the pending approval and a new submission are now refused.
    assert_eq!(code(&w.approve(Who::Approver, 1)), "epoch_blocked");
    assert_eq!(code(&w.submit(Who::Requester, 2)), "epoch_blocked");
    assert_eq!(w.budget().held, 0);
    // Exposed is permanent: clearing is refused, with the exact confirmation.
    let clear = Command::LifecycleClear {
        epoch: w.rw.epoch.clone(),
        confirm_epoch: w.rw.epoch.clone(),
        key: idk(2),
    };
    assert_eq!(code(&w.run(Who::Operator, &clear)), "not_clearable");
    assert_eq!(
        w.rw.store
            .epoch_standing(w.rw.epoch.as_str())
            .unwrap()
            .unwrap()
            .standing
            .contamination,
        Contamination::Exposed
    );
}

#[test]
fn an_unreviewed_change_can_be_cleared_by_a_confirmed_human_decision_only() {
    let w = World::new(3);
    let report = Command::LifecycleReport {
        epoch: w.rw.epoch.clone(),
        kind: Contaminated::UnreviewedChange,
        reason: "integrity_alarm".into(),
        key: idk(1),
    };
    assert_eq!(code(&w.run(Who::Operator, &report)), "reported");
    assert_eq!(code(&w.submit(Who::Requester, 1)), "epoch_blocked");
    let other: EpochId = EpochId::parse(&cc::id("epo_", 9)).unwrap();
    // The confirmation must name the same epoch.
    let mismatch = Command::LifecycleClear {
        epoch: w.rw.epoch.clone(),
        confirm_epoch: other,
        key: idk(2),
    };
    assert_eq!(
        code(&w.run(Who::Operator, &mismatch)),
        "confirmation_mismatch"
    );
    let clear = Command::LifecycleClear {
        epoch: w.rw.epoch.clone(),
        confirm_epoch: w.rw.epoch.clone(),
        key: idk(3),
    };
    assert_eq!(code(&w.dry(Who::Operator, &clear)), "would_clear");
    assert_eq!(code(&w.run(Who::Operator, &clear)), "cleared");
    assert_eq!(code(&w.submit(Who::Requester, 1)), "submitted");
    // History is kept: report then clear are both on record.
    let events = w.rw.store.epoch_events(w.rw.epoch.as_str()).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn retirement_blocks_new_use_but_never_edits_spent_budget() {
    let w = World::new(2);
    w.submit(Who::Requester, 1);
    w.approve(Who::Approver, 1);
    let before = w.budget();
    let o = w.run(Who::Operator, &retire_cmd(&w, 1));
    assert_eq!(code(&o), "retired");
    assert_eq!(w.budget(), before, "retirement does not touch the budget");
    assert_eq!(code(&w.submit(Who::Requester, 2)), "epoch_blocked");
    // Retirement is one-way: the epoch is retired in the registry too.
    assert_eq!(
        w.rw.fx.pop.state(&w.rw.epoch).unwrap(),
        custodian_corpus::EpochState::Retired
    );
}

#[test]
fn rotation_gives_a_new_epoch_and_new_budget_and_leaves_the_old_untouched() {
    let w = World::new(1);
    w.submit(Who::Requester, 1);
    w.approve(Who::Approver, 1);
    let spent = w.budget();
    let next = w.rw.seal_next("b");
    let rot = |confirm_succ: EpochId, limit: u64, key| Command::LifecycleRotate {
        predecessor: w.rw.epoch.clone(),
        successor: next.clone(),
        confirm_predecessor: w.rw.epoch.clone(),
        confirm_successor: confirm_succ,
        run_budget_limit: limit,
        reason: "planned_rotation".into(),
        key,
    };
    assert_eq!(
        code(&w.run(Who::Operator, &rot(w.rw.epoch.clone(), 2, idk(1)))),
        "confirmation_mismatch"
    );
    assert_eq!(
        code(&w.dry(Who::Operator, &rot(next.clone(), 2, idk(1)))),
        "would_rotate"
    );
    let o = w.run(Who::Operator, &rot(next.clone(), 2, idk(1)));
    assert_eq!(code(&o), "rotated", "{}", o.render());
    assert_eq!(o.field("budgets_provisioned").unwrap(), 1);
    assert_eq!(w.budget(), spent, "the old epoch's budget is untouched");
    let view = w.rw.fx.pop.registry().view().unwrap();
    let (row, _) = view.get(&next).unwrap();
    let scope = custodian_contracts::common::BudgetScope::PopulationEpoch {
        corpus_id: row.corpus_id.clone(),
        epoch_id: row.epoch_id.clone(),
        family_id: row.family_id.clone(),
    };
    let nb =
        w.rw.store
            .budget_status(custodian_contracts::common::BudgetKind::Run, &scope)
            .unwrap()
            .unwrap();
    assert_eq!((nb.limit, nb.held, nb.consumed), (2, 0, 0));
    // A replay converges.
    assert_eq!(
        code(&w.run(Who::Operator, &rot(next.clone(), 2, idk(1)))),
        "rotated"
    );
    assert_eq!(w.budget(), spent);
}

// ---- feed --------------------------------------------------------------------------------------

#[test]
fn feed_record_and_publish_are_human_operator_actions() {
    let w = World::new(1);
    let record = Command::FeedRecordRevocation {
        id: "synthetic-revocation-1".into(),
        what: RevocationKind::Candidate(
            custodian_contracts::types::CandidateDigest::parse(&cc::dg("synthetic-bad")).unwrap(),
        ),
        verb: RevocationVerb::Revoked,
        reason: "error_correction".into(),
    };
    for (who, expect) in [
        (Who::Requester, "forbidden"),
        (Who::Approver, "forbidden"),
        (Who::Agent, "agent_not_permitted"),
        (Who::Service, "automation_not_permitted"),
    ] {
        assert_eq!(code(&w.run(who, &record)), expect, "{who:?}");
        assert_eq!(code(&w.run(who, &Command::FeedPublish)), expect, "{who:?}");
    }
    assert_eq!(code(&w.dry(Who::Operator, &record)), "would_record");
    assert_eq!(code(&w.run(Who::Operator, &record)), "recorded");
    assert_eq!(w.run(Who::Operator, &record).field("replay").unwrap(), true);
    // Eligibility counts the obligation before the feed carries it.
    let rf = w.run(Who::Operator, &Command::Reconcile(ReconcileTarget::Feed));
    assert_eq!(code(&rf), "pending_obligations");
    let p = w.run(Who::Operator, &Command::FeedPublish);
    assert_eq!(code(&p), "published", "{}", p.render());
    assert_eq!(p.field("sequence").unwrap(), 1);
    assert_eq!(w.feed.sequences(&lc::feed_id()), vec![1]);
    assert_eq!(
        code(&w.run(Who::Operator, &Command::Reconcile(ReconcileTarget::Feed))),
        "consistent"
    );
    // Nothing new to say and the head is fresh: no second envelope.
    assert_eq!(
        code(&w.run(Who::Operator, &Command::FeedPublish)),
        "unchanged"
    );
}

// ---- verification and reconciliation ---------------------------------------------------------

#[test]
fn verify_walks_the_ledger_the_store_the_registry_and_the_checkpoint() {
    let w = World::new(2);
    w.submit(Who::Requester, 1);
    w.approve(Who::Approver, 1);
    let id = w.rw.store.store_id().unwrap();
    let exp = w.run(
        Who::Operator,
        &Command::Repair(RepairCommand::Export {
            confirm_store_id: id,
        }),
    );
    assert_eq!(code(&exp), "exported", "{}", exp.render());
    assert_eq!(exp.field("status").unwrap(), "drained");
    assert_eq!(exp.field("checkpoint_recorded").unwrap(), true);
    for who in [Who::Auditor, Who::Operator, Who::Service] {
        let v = w.run(who, &Command::Verify(VerifyTarget::All));
        assert_eq!(code(&v), "verified", "{who:?} {}", v.render());
        assert_eq!(v.field("ledger_trustworthy").unwrap(), true);
        assert_eq!(v.field("store_intact").unwrap(), true);
        assert_eq!(v.field("store_checkpoint").unwrap(), "contained");
        assert_eq!(v.field("registry_checkpoint").unwrap(), "matches");
    }
    // Tampering with the ledger is a verification failure with fixed codes.
    w.ledger.inject("records/audit/zz-tampered.json", b"{}");
    let v = w.run(Who::Auditor, &Command::Verify(VerifyTarget::Ledger));
    assert_eq!(code(&v), "ledger_untrusted");
    assert_eq!(v.exit_code(), 8);
    assert!(v.field("ledger_finding_codes").is_some());
    // Reconcile is read-only diagnosis.
    let r = w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Store));
    assert_eq!(code(&r), "consistent");
    assert_eq!(
        r.field("store_id").unwrap(),
        &json!(w.rw.store.store_id().unwrap())
    );
}

#[test]
fn reconcile_ledger_reports_a_gap_without_repairing_it() {
    let w = World::new(2);
    w.submit(Who::Requester, 1);
    let diag = w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger));
    // Pending events are not a divergence: nothing was acknowledged yet.
    assert_eq!(code(&diag), "consistent", "{}", diag.render());
    let id = w.rw.store.store_id().unwrap();
    w.run(
        Who::Operator,
        &Command::Repair(RepairCommand::Export {
            confirm_store_id: id.clone(),
        }),
    );
    // The ledger loses a record the store believes exported.
    let paths: Vec<String> = w
        .ledger
        .paths()
        .into_iter()
        .filter(|p| p.contains("records/audit"))
        .collect();
    assert!(!paths.is_empty());
    w.ledger.remove(&paths[0]);
    let diag = w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger));
    assert_eq!(code(&diag), "verification_failed");
    assert_eq!(diag.field("missing_in_ledger").unwrap(), 1);
    // The diagnosis changed nothing; the repair group re-writes identical bytes.
    assert_eq!(
        w.ledger.file_count(),
        paths.len() + w.ledger.file_count() - paths.len()
    );
    let fixed = w.run(
        Who::Operator,
        &Command::Repair(RepairCommand::LedgerReconcile {
            confirm_store_id: id,
        }),
    );
    assert_eq!(code(&fixed), "reconciled", "{}", fixed.render());
    assert_eq!(fixed.field("repaired").unwrap(), 1);
    assert_eq!(
        code(&w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger))),
        "consistent"
    );
}

// ---- repair ---------------------------------------------------------------------------------------

#[test]
fn repair_needs_the_exact_store_id_and_never_resets_a_spent_budget() {
    let w = World::new(2);
    w.submit(Who::Requester, 1);
    w.approve(Who::Approver, 1);
    let id = w.rw.store.store_id().unwrap();
    let recover = |confirm: &str| {
        Command::Repair(RepairCommand::Recover {
            confirm_store_id: confirm.to_owned(),
        })
    };
    assert_eq!(
        code(&w.run(Who::Operator, &recover("0123456789abcdef"))),
        "confirmation_mismatch"
    );
    // Nothing lapsed: recover does nothing.
    let o = w.run(Who::Operator, &recover(&id));
    assert_eq!(code(&o), "recovered");
    assert_eq!(
        (
            o.field("expired_unstarted").unwrap(),
            o.field("failed_consumed").unwrap()
        ),
        (&json!(0), &json!(0))
    );
    // The reservation lapses unstarted: expired and refunded (no byte was
    // opened), which is the only way a reservation returns.
    w.clock.set(NOW + 10_000);
    let o = w.run(Who::Operator, &recover(&id));
    assert_eq!(o.field("expired_unstarted").unwrap(), 1);
    let b = w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 1));
    assert_eq!(b.limit, 2);
    // There is no repair command that edits a count: the command set is closed.
    for c in [
        "repair.recover",
        "repair.registry-sweep",
        "repair.export",
        "repair.ledger-reconcile",
        "repair.feed-deliver",
        "repair.clear-reconcile",
    ] {
        assert!(!c.contains("budget") && !c.contains("reset") && !c.contains("raise"));
    }
}

#[test]
fn an_exposed_attempt_that_lapses_is_consumed_and_never_refunded() {
    use custodian_core::ActorId;
    use custodian_store::StartCommand;
    let w = World::new(2);
    w.submit(Who::Requester, 1);
    let o = w.approve(Who::Approver, 1);
    let attempt =
        custodian_core::RunId::new(o.field("attempt_id").unwrap().as_str().unwrap().to_owned());
    let actor = ActorId::new("act_syntheticworker00001");
    let lease =
        w.rw.store
            .start_attempt(&StartCommand {
                attempt: &attempt,
                owner: "worker-synthetic",
                actor: &actor,
                now: NOW + 1,
                lease_secs: 60,
                observed: Some(&cc::observed(cc::activation(), NOW + 1)),
                max_state_age_secs: 300,
            })
            .unwrap();
    w.rw.store.record_exposure(&lease, &actor, NOW + 2).unwrap();
    w.clock.set(NOW + 1000);
    let id = w.rw.store.store_id().unwrap();
    let o = w.run(
        Who::Operator,
        &Command::Repair(RepairCommand::Recover {
            confirm_store_id: id,
        }),
    );
    assert_eq!(o.field("failed_consumed").unwrap(), 1);
    let b = w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
}

#[test]
fn registry_sweep_and_feed_delivery_are_idempotent_repairs() {
    let w = World::new(1);
    let id = w.rw.store.store_id().unwrap();
    let sweep = Command::Repair(RepairCommand::RegistrySweep {
        confirm_store_id: id,
    });
    assert_eq!(code(&w.run(Who::Operator, &sweep)), "swept");
    assert_eq!(code(&w.run(Who::Operator, &sweep)), "swept");
    let wrong = Command::Repair(RepairCommand::FeedDeliver {
        confirm_feed_id: cc::id("fed_", 99),
    });
    assert_eq!(code(&w.run(Who::Operator, &wrong)), "confirmation_mismatch");
    let right = Command::Repair(RepairCommand::FeedDeliver {
        confirm_feed_id: lc::feed_id().as_str().to_owned(),
    });
    assert_eq!(code(&w.run(Who::Operator, &right)), "delivered");
    assert_eq!(code(&w.dry(Who::Operator, &right)), "would_deliver");
}

// ---- output hygiene ----------------------------------------------------------------------------------

fn all_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| all_strings(x, out)),
        serde_json::Value::Object(m) => m.values().for_each(|x| all_strings(x, out)),
        _ => {}
    }
}

#[test]
fn output_carries_no_protected_canary_path_credential_or_free_text() {
    let w = World::new(2);
    // A protected epoch whose bytes are a canary, plus every command's output.
    let _canary_epoch = w.rw.fx.seal(&[("canary", lc::corpus::CANARY.as_bytes())]);
    let mut outputs = Vec::new();
    outputs.push(w.submit(Who::Requester, 1));
    outputs.push(w.submit(Who::Approver, 1));
    outputs.push(w.approve(Who::Approver, 1));
    outputs.push(w.approve(Who::Approver, 1));
    outputs.push(w.run(Who::Auditor, &status_cmd(&w.request(1).0)));
    outputs.push(w.run(Who::Auditor, &Command::RequestList { limit: 10 }));
    outputs.push(w.run(Who::Auditor, &Command::Verify(VerifyTarget::All)));
    outputs.push(w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Store)));
    outputs.push(w.run(Who::Operator, &Command::Reconcile(ReconcileTarget::Feed)));
    outputs.push(w.run(Who::Operator, &retire_cmd(&w, 1)));
    outputs.push(w.run(
        Who::Operator,
        &Command::Repair(RepairCommand::Export {
            confirm_store_id: w.rw.store.store_id().unwrap(),
        }),
    ));
    w.ledger.inject("records/audit/zz.json", b"{}");
    outputs.push(w.run(Who::Auditor, &Command::Verify(VerifyTarget::Ledger)));
    let tmp = w.rw.db.dir().to_string_lossy().into_owned();
    for o in &outputs {
        let text = o.render();
        let v: serde_json::Value = serde_json::from_str(&text).expect("one JSON object");
        for forbidden in [
            lc::corpus::CANARY,
            "synthetic-one",
            "synthetic-two",
            "synthetic-credential",
            tmp.as_str(),
            "/tmp",
            "/var",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
        for t in ["Requester", "Approver", "Operator"] {
            assert!(!text.contains(&custodian_cli::credential_digest(
                format!("synthetic-credential-{t}-00000000000000000000").as_bytes()
            )));
        }
        // Every string in the result is a fixed word or a strict identifier.
        let mut strings = Vec::new();
        all_strings(&v["result"], &mut strings);
        for s in strings {
            assert!(
                custodian_cli::output::is_safe_identifier(&s),
                "unsafe string {s:?} in {text}"
            );
        }
        // The envelope carries only these keys.
        let keys: std::collections::BTreeSet<&str> =
            v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["code", "command", "dry_run", "exit", "ok", "result", "schema"]
                .into_iter()
                .collect()
        );
        assert_eq!(v["exit"].as_u64().unwrap(), u64::from(o.exit_code()));
    }
    let _ = ActorRef::parse(&Who::Agent.actor());
}

#[test]
fn exit_codes_are_stable_and_documented() {
    let w = World::new(1);
    let (req, doc) = w.request(1);
    let cases: Vec<(custodian_cli::Output, u8, &str)> = vec![
        (submit_doc(&w, Who::Requester, doc.clone()), 0, "submitted"),
        (
            submit_doc(&w, Who::Requester, b"{}".to_vec()),
            2,
            "invalid_document",
        ),
        (w.run(Who::Approver, &Command::FeedPublish), 4, "forbidden"),
        (w.run(Who::Approver, &approve_cmd(&req)), 0, "approved"),
        (w.approve(Who::Approver, 1), 5, "already_decided"),
        (
            w.run(
                Who::Auditor,
                &Command::RequestStatus {
                    request_id: rid(404),
                },
            ),
            6,
            "not_found",
        ),
    ];
    for (o, exit, c) in cases {
        assert_eq!((o.exit_code(), o.code()), (exit, c), "{}", o.render());
    }
    // Class 3 (authentication), 7 (unavailable), 8 (integrity) and 1 (internal)
    // are asserted where they arise: authentication above, availability and
    // integrity in tests/startup.rs.
    assert_eq!(CliReason::Unauthenticated.exit_code(), 3);
    assert_eq!(CliReason::LedgerUnavailable.exit_code(), 7);
    assert_eq!(CliReason::LedgerUntrusted.exit_code(), 8);
    assert_eq!(CliReason::Internal.exit_code(), 1);
}
