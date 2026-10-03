//! Execution gate: stale commit, binding, and "App access is not approval".

mod common;

use std::sync::Arc;

use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::types::{CandidateDigest, ConfigDigest};
use custodian_contracts::Contract;
use custodian_intake::gate::{ExecutionGate, StagedCandidate};
use custodian_intake::memory::{FixedPullRequestSource, MemoryRegistry};
use custodian_intake::ports::{InstallationRegistry, QueuedRequest};
use custodian_intake::reason::IntakeReason;
use custodian_intake::webhook::Outcome;
use serde_json::json;

struct Fixture {
    gate: ExecutionGate,
    queued: QueuedRequest,
    pulls: Arc<FixedPullRequestSource>,
    registry: Arc<MemoryRegistry>,
}

/// A queued request produced by the real webhook path.
fn fixture() -> Fixture {
    let h = harness();
    assert_eq!(
        h.deliver("pull_request", 1, &pr_payload("opened", REQUESTER, "User")),
        Ok(Outcome::Queued)
    );
    let queued = h.queue.pop().unwrap();
    let pulls = fixed_head('a');
    let registry = Arc::new(MemoryRegistry::new());
    let gate = ExecutionGate::new(config(), registry.clone(), pulls.clone());
    Fixture {
        gate,
        queued,
        pulls,
        registry,
    }
}

fn staged() -> StagedCandidate {
    StagedCandidate {
        head_sha: head('a'),
        candidate: CandidateDigest::parse(&dg("synthetic-candidate")).unwrap(),
        config_digest: ConfigDigest::parse(&dg("synthetic-config")).unwrap(),
    }
}

fn approval() -> Approval {
    approval_from(&approval_json())
}

fn run(
    f: &Fixture,
    request: &[u8],
    staged: &StagedCandidate,
    approval: Option<&Approval>,
) -> Result<custodian_intake::gate::AuthorizedExecution, IntakeReason> {
    f.gate.authorize(
        &f.queued,
        request,
        staged,
        approval,
        &current_activation(),
        ts(NOW + 5),
    )
}

#[test]
fn explicit_approval_authorizes_and_freezes_the_binding() {
    let f = fixture();
    let a = approval();
    let ok = run(&f, &request_bytes(), &staged(), Some(&a)).unwrap();
    let b = ok.binding();
    assert_eq!(b.head_sha(), &head('a'));
    assert_eq!(b.candidate().as_str(), dg("synthetic-candidate"));
    assert_eq!(b.config_digest().as_str(), dg("synthetic-config"));
    assert_eq!(b.plan_digest().as_str(), plan_digest());
    assert_eq!(ok.approval_id().as_str(), id("apr_", 1));
    assert!(b.matches_staged(&staged()));

    // Deterministic digest, and it changes with any bound field.
    let d1 = b.digest().unwrap();
    assert_eq!(d1, ok.binding().digest().unwrap());
    let mut other = staged();
    other.candidate = CandidateDigest::parse(&dg("synthetic-other")).unwrap();
    assert!(!b.matches_staged(&other));
    let mut other = staged();
    other.config_digest = ConfigDigest::parse(&dg("synthetic-other")).unwrap();
    assert!(!b.matches_staged(&other));
    let mut other = staged();
    other.head_sha = head('c');
    assert!(!b.matches_staged(&other));
}

#[test]
fn app_access_is_not_protected_execution_approval() {
    // Everything App-side is valid: signed webhook, allowlisted installation,
    // repository and requester, a queued request, a current head, matching
    // staged bytes. Without an Approval record, nothing is authorized.
    let f = fixture();
    assert_eq!(
        run(&f, &request_bytes(), &staged(), None).unwrap_err(),
        IntakeReason::ApprovalRequired
    );

    // Even an actor holding the approver role does not approve by sending the
    // webhook: the queued request from the approver still needs a record.
    let h = harness();
    assert_eq!(
        h.deliver("pull_request", 2, &pr_payload("opened", APPROVER, "User")),
        Ok(Outcome::Queued)
    );
    let q = h.queue.pop().unwrap();
    let gate = ExecutionGate::new(config(), Arc::new(MemoryRegistry::new()), fixed_head('a'));
    let mut req = request_json();
    req["asserted_actor"] = json!(id("act_", 2));
    let err = gate
        .authorize(
            &q,
            &serde_json::to_vec(&req).unwrap(),
            &staged(),
            None,
            &current_activation(),
            ts(NOW + 5),
        )
        .unwrap_err();
    assert_eq!(err, IntakeReason::ApprovalRequired);
}

#[test]
fn approver_must_hold_the_approver_role() {
    let f = fixture();
    // Approval record naming the plain requester (act_1) as approver.
    let mut v = approval_json();
    v["approver"] = json!(id("act_", 1));
    v["role_separation"] = json!("single_operator_procedural");
    let a = approval_from(&v);
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::ApproverNotAuthorized
    );
    // An unlisted approver is refused the same way.
    let mut v = approval_json();
    v["approver"] = json!(id("act_", 77));
    let a = approval_from(&v);
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::ApproverNotAuthorized
    );
    // An agent can never be the approver (contract rule).
    let mut v = approval_json();
    v["approver_kind"] = json!("agent");
    assert!(Approval::decode(&serde_json::to_vec(&v).unwrap()).is_err());
}

#[test]
fn stale_commit_is_refused() {
    let f = fixture();
    let a = approval();
    // The branch moved after the event: head is now a different commit.
    f.pulls.set_head(head('c'));
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::StaleCommit
    );
    // Candidate staged from some other commit than the event named.
    f.pulls.set_head(head('a'));
    let mut s = staged();
    s.head_sha = head('c');
    assert_eq!(
        run(&f, &request_bytes(), &s, Some(&a)).unwrap_err(),
        IntakeReason::StaleCommit
    );
    // Unable to read the head: fail closed.
    f.pulls.fail_with(IntakeReason::TokenUnavailable);
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::TokenUnavailable
    );
}

#[test]
fn candidate_and_config_digest_must_match_the_staged_bytes() {
    let f = fixture();
    let a = approval();
    let mut s = staged();
    s.candidate = CandidateDigest::parse(&dg("synthetic-swapped")).unwrap();
    assert_eq!(
        run(&f, &request_bytes(), &s, Some(&a)).unwrap_err(),
        IntakeReason::CandidateMismatch
    );
    let mut s = staged();
    s.config_digest = ConfigDigest::parse(&dg("synthetic-swapped")).unwrap();
    assert_eq!(
        run(&f, &request_bytes(), &s, Some(&a)).unwrap_err(),
        IntakeReason::ConfigMismatch
    );
}

#[test]
fn asserted_actor_is_checked_not_trusted() {
    let f = fixture();
    let a = approval();
    // The request claims to be from the approver while the verified sender is
    // the requester.
    let mut req = request_json();
    req["asserted_actor"] = json!(id("act_", 2));
    assert_eq!(
        run(&f, &serde_json::to_vec(&req).unwrap(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::ActorMismatch
    );
}

#[test]
fn malformed_or_oversized_request_documents_are_refused() {
    let f = fixture();
    let a = approval();
    assert_eq!(
        run(&f, b"{}", &staged(), Some(&a)).unwrap_err(),
        IntakeReason::RequestInvalid
    );
    let mut req = request_json();
    req["unexpected"] = json!(1);
    assert_eq!(
        run(&f, &serde_json::to_vec(&req).unwrap(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::RequestInvalid
    );
    let big = vec![b' '; custodian_contracts::MAX_DOCUMENT_BYTES + 1];
    assert_eq!(
        run(&f, &big, &staged(), Some(&a)).unwrap_err(),
        IntakeReason::RequestInvalid
    );
}

#[test]
fn approval_bindings_and_freshness_are_enforced() {
    let f = fixture();

    // Different plan digest.
    let mut v = approval_json();
    v["scope"]["plan_digest"] = json!(dg("synthetic-other-plan"));
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&approval_from(&v))).unwrap_err(),
        IntakeReason::ApprovalNotBound
    );
    // Different candidate in the approval.
    let mut v = approval_json();
    v["scope"]["candidate"] = json!(dg("synthetic-other-candidate"));
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&approval_from(&v))).unwrap_err(),
        IntakeReason::ApprovalNotBound
    );
    // Expired.
    let a = approval();
    let late = f.gate.authorize(
        &f.queued,
        &request_bytes(),
        &staged(),
        Some(&a),
        &current_activation(),
        ts(NOW + 3600),
    );
    assert_eq!(late.unwrap_err(), IntakeReason::ApprovalExpired);
    // Policy activation revoked since approval.
    let mut act = activation_json();
    act["status"] = json!("revoked");
    let revoked = f.gate.authorize(
        &f.queued,
        &request_bytes(),
        &staged(),
        Some(&a),
        &observed_from(&act, NOW + 1),
        ts(NOW + 5),
    );
    assert_eq!(revoked.unwrap_err(), IntakeReason::ActivationNotCurrent);
    // Activation state read too long ago.
    let stale = f.gate.authorize(
        &f.queued,
        &request_bytes(),
        &staged(),
        Some(&a),
        &observed_from(&activation_json(), NOW - 1000),
        ts(NOW + 5),
    );
    assert_eq!(stale.unwrap_err(), IntakeReason::ActivationNotCurrent);
    // Release approvals are not execution approvals.
    let mut v = approval_json();
    v["scope"] = json!({
        "operation": "release",
        "execution_id": id("exe_", 1),
        "projection_digest": dg("synthetic-projection"),
        "disclosure_policy": {"kind":"disclosure","domain":"credential",
                              "name":"synthetic-disclosure","version":1}
    });
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&approval_from(&v))).unwrap_err(),
        IntakeReason::ApprovalNotBound
    );
}

#[test]
fn removal_between_queueing_and_gating_is_honored() {
    let f = fixture();
    let a = approval();
    f.registry.mark_installation_removed(inst()).unwrap();
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::InstallationRemoved
    );

    let f = fixture();
    f.registry.mark_repository_removed(inst(), repo()).unwrap();
    assert_eq!(
        run(&f, &request_bytes(), &staged(), Some(&a)).unwrap_err(),
        IntakeReason::RepositoryRemoved
    );
}

#[test]
fn actor_removed_from_allowlist_is_refused_at_the_gate() {
    let f = fixture();
    let a = approval();
    // A gate built from a later configuration that no longer lists the actor.
    let mut c = config_json();
    c["actors"] = json!([
        {"github_user_id": APPROVER, "actor": id("act_", 2), "roles": ["requester", "approver"]}
    ]);
    let cfg = custodian_intake::config::IntakeConfig::from_json(&serde_json::to_vec(&c).unwrap())
        .unwrap();
    let gate = ExecutionGate::new(cfg, f.registry.clone(), f.pulls.clone());
    let err = gate
        .authorize(
            &f.queued,
            &request_bytes(),
            &staged(),
            Some(&a),
            &current_activation(),
            ts(NOW + 5),
        )
        .unwrap_err();
    assert_eq!(err, IntakeReason::ActorNotAuthorized);
}
