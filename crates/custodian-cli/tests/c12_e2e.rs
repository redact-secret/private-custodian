//! C12 end-to-end synthetic scenario: intake -> approval -> reserve ->
//! dispatch -> validate -> receipt and ledger -> disclosure -> revocation
//! feed -> benchmarks-side bridge consumer verification, with the negative
//! variants that must stop at the right layer.
//!
//! Synthetic data, test-generated keys, an in-process scripted sandbox (the
//! real bubblewrap tests run in the `worker-isolation` CI job). This proves
//! the layers compose with project-maintained fixtures. It is not independent
//! validation, and a valid signature here attests origin and binding, never
//! ground truth.

mod c12;

use c12::*;
use custodian_bridge::testing::MemoryCatalog;
use custodian_bridge::{BridgeConsumer, BridgeService, ConsumerPins, Rejection};
use custodian_cli::command::{ReconcileTarget, VerifyTarget};
use custodian_contracts::common::EvaluationDomain;
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_contracts::revocation::Standing;
use custodian_contracts::types::DestinationId;
use custodian_core::{Exposure, RunState};
use custodian_disclosure::testing::RecordingSink;
use custodian_ledger::{Keyring, Verifier};

fn bridge_pins(p: &Pipe) -> ConsumerPins {
    ConsumerPins {
        domain: EvaluationDomain::Credential,
        feed_id: lc::feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
        // Pinned out of band: the public root key only, never taken from a
        // feed or a ledger.
        verifier: Verifier::new(Keyring::new().with_root(p.w.key.entry.clone())),
        accepted_populations: vec![lc::opaque(1)],
        accepted_policies: vec![disclosure_policy_ref()],
    }
}

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

/// Everything up to a completed, exported execution of request 1.
struct Run {
    attempt: custodian_core::RunId,
    approval_id: String,
    report: custodian_worker::DispatchReport,
}

fn run_to_completion(
    p: &Pipe,
    svc: &custodian_cli::Service<'_, custodian_corpus::FsEpochStore>,
) -> Run {
    let (attempt, approval_id) = p.reserve(1);
    assert_eq!(p.w.budget().held, 1, "the reservation holds one unit");
    let rep = p.dispatch(svc, 1, &attempt).unwrap();
    assert_eq!(rep.outcome, O::Success);
    assert_eq!(rep.exposure, Exposure::Exposed);
    assert!(rep.settled);
    assert_eq!(rep.roster().unwrap().expected.get(), ROSTER as u64);
    assert_eq!(p.sandbox.runs(), 1);
    assert_eq!(p.arts.staging_entries(), 0, "staging is cleaned");
    let rec = p.w.rw.store.attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Completed, Exposure::Exposed)
    );
    let b = p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
    Run {
        attempt,
        approval_id,
        report: rep,
    }
}

#[test]
fn intake_to_bridge_consumer_end_to_end() {
    let p = Pipe::with_roster();
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let (req, _) = p.request(1);

    // intake -> approval -> reserve -> dispatch -> validate
    let r = run_to_completion(&p, &svc);
    let rep_report = p.w.rw.store.attempt(&r.attempt).unwrap().unwrap();
    assert!(rep_report.reservation_id.is_some());

    // The terminal audit event must be in the private ledger before any
    // disclosure: nothing is released while it is pending.
    p.w.clock.set(NOW + 40);
    let asm = p.assemble(1, &r.attempt, &r.approval_id, &r.report);
    assert_eq!(
        prepare(&p, &svc, &req, &asm, 1, PREPARE_AT).unwrap_err(),
        "not_configured",
        "feed reference needs a published feed first"
    );
    assert_eq!(
        code(&p.w.run(Who::Operator, &custodian_cli::Command::FeedPublish)),
        "published"
    );
    assert_eq!(
        prepare(&p, &svc, &req, &asm, 1, PREPARE_AT).unwrap_err(),
        "precondition_not_met",
        "the terminal event is not exported yet"
    );
    assert_eq!(code(&p.export()), "exported");

    // receipt + ledger -> disclosure
    p.w.clock.set(PREPARE_AT);
    let prepared = prepare(&p, &svc, &req, &asm, 1, PREPARE_AT).unwrap();
    assert_eq!(
        code(&p.export()),
        "exported",
        "the charge audit must be acknowledged before release"
    );
    let approval = release_approval(&prepared);
    let sink = RecordingSink::new();
    p.w.clock.set(RELEASE_AT);
    let released = release(&p, &svc, &prepared, &approval, DEST, &sink, RELEASE_AT).unwrap();
    assert_eq!(sink.delivered().len(), 1);
    assert_eq!(
        code(&p.export()),
        "exported",
        "audit of the release is exported"
    );

    // The ledger verifies with the pinned root only, and the checkpoint holds.
    let v = p.w.run(
        Who::Auditor,
        &custodian_cli::Command::Verify(VerifyTarget::All),
    );
    assert_eq!(code(&v), "verified");
    assert_eq!(
        code(&p.w.run(
            Who::Auditor,
            &custodian_cli::Command::Reconcile(ReconcileTarget::Store)
        )),
        "consistent"
    );

    // feed -> bridge consumer, holding public inputs only
    let catalog = MemoryCatalog::new();
    catalog.add(req.plan.config_digest.clone(), released);
    let service = BridgeService {
        catalog: &catalog,
        feed: &p.w.feed,
        feed_id: lc::feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
    };
    let mut consumer = BridgeConsumer::new(bridge_pins(&p));
    let breq = consumer
        .request(
            req.plan.candidate.clone(),
            req.plan.config_digest.clone(),
            vec![],
        )
        .unwrap();
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = consumer
        .accept_response(&breq, &resp, ts(NOW + 120))
        .unwrap();
    assert_eq!(out.feed_error, None);
    assert_eq!(out.accepted.len(), 1, "{:?}", out.rejected);
    let verified = out.accepted[0].clone();
    assert_eq!(consumer.standing(&verified, ts(NOW + 120)), Standing::Valid);
    // No claim of independence or ground truth rides on the signature.
    let att = serde_json::to_value(verified.attestation()).unwrap();
    assert_eq!(att["ground_truth"], "not_established");
    assert_eq!(att["organisational_independence"], "not_claimed");

    // A later contamination reaches the consumer through the signed feed.
    p.w.clock.set(NOW + 200);
    let key = lc::idk(1);
    let report = p.w.run(
        Who::Operator,
        &custodian_cli::Command::LifecycleReport {
            epoch: p.w.rw.epoch.clone(),
            kind: custodian_cli::command::Contaminated::Exposed,
            reason: "results_exposed".into(),
            key,
        },
    );
    assert!(report.is_ok(), "{}", report.code());
    assert_eq!(
        code(&p.w.run(Who::Operator, &custodian_cli::Command::FeedPublish)),
        "published"
    );
    let breq = consumer
        .request(
            req.plan.candidate.clone(),
            req.plan.config_digest.clone(),
            vec![],
        )
        .unwrap();
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = consumer
        .accept_response(&breq, &resp, ts(NOW + 210))
        .unwrap();
    assert_eq!(out.feed_applied, 1);
    let changes = consumer.reevaluate(ts(NOW + 211));
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].to, Standing::Revoked);
    assert_eq!(
        consumer.standing(&verified, ts(NOW + 211)),
        Standing::Revoked
    );
    // Custody history is intact: the earlier receipt still verifies in the
    // ledger, and nothing was un-spent.
    assert_eq!(code(&p.export()), "exported");
    assert_eq!(
        code(&p.w.run(
            Who::Auditor,
            &custodian_cli::Command::Verify(VerifyTarget::All)
        )),
        "verified"
    );
    assert_eq!(p.w.budget().consumed, 1);
    // And the contaminated population cannot be released or run again.
    assert_eq!(
        prepare(&p, &svc, &req, &asm, 2, PREPARE_AT).unwrap_err(),
        "eligibility_denied"
    );
}

#[test]
fn negative_malicious_or_partial_worker_output_never_reaches_disclosure() {
    for (mode, expect) in [
        (Mode::Raw(b"{\"schema\":\"x\"}".to_vec()), O::Rejected),
        (
            Mode::Raw(
                serde_json::to_vec(&serde_json::json!({
                    "schema": "private-custodian.worker-result/1",
                    "domain": "credential",
                    "protocol": {"name": "synthetic-protocol", "version": "1"},
                    "status": "complete",
                    "roster": {"expected": 3, "observed": 3, "failed": 0}
                }))
                .unwrap(),
            ),
            O::Rejected,
        ),
        (Mode::Raw(vec![b'a'; 70_000]), O::Rejected),
        (Mode::Crash, O::Failed),
        (Mode::Timeout, O::Failed),
        (Mode::Flood, O::Failed),
    ] {
        let p = Pipe::with_roster();
        p.sandbox.set(mode.clone());
        let acts = p.activations();
        let svc = p.start(&acts).unwrap();
        let (attempt, approval_id) = p.reserve(1);
        let rep = p.dispatch(&svc, 1, &attempt).unwrap();
        assert_eq!(rep.outcome, expect, "{mode:?}");
        assert!(rep.result.is_none() || expect == O::Success);
        let b = p.w.budget();
        assert_eq!(
            (b.held, b.consumed, b.refunded),
            (0, 1, 0),
            "{mode:?}: exposed, consumed"
        );
        let rec = p.w.rw.store.attempt(&attempt).unwrap().unwrap();
        assert_eq!(rec.state, RunState::Failed, "{mode:?}");
        p.w.rw.store.verify_invariants().unwrap();
        // The disclosure gate is closed: the attempt did not complete.
        p.export();
        assert!(p
            .w
            .rw
            .store
            .check_disclosure_precondition(&attempt)
            .is_err());
        let _ = approval_id;
    }
}

#[test]
fn negative_stale_replayed_or_unapproved_requests_stop_before_any_charge() {
    let p = Pipe::new(1, ROSTER);
    // Unapproved: submitting charges nothing and starts nothing.
    assert!(p.submit(1).is_ok());
    assert_eq!(p.w.budget().held, 0);
    assert_eq!(p.sandbox.runs(), 0);
    // The requester cannot approve their own request.
    let (req, _) = p.request(1);
    assert_eq!(
        code(&p.w.run(Who::Requester, &approve_cmd(&req))),
        "forbidden"
    );
    assert_eq!(p.w.budget().held, 0);
    // Approval needs the exact plan digest.
    let mut wrong = approve_cmd(&req);
    if let custodian_cli::Command::RequestApprove {
        confirm_plan_digest,
        ..
    } = &mut wrong
    {
        *confirm_plan_digest =
            custodian_contracts::types::PlanDigest::parse(&cc::dg("other")).unwrap();
    }
    assert_eq!(
        code(&p.w.run(Who::Approver, &wrong)),
        "confirmation_mismatch"
    );
    // Approve once; a repeat charges nothing.
    assert!(p.approve(1).is_ok());
    assert_eq!(code(&p.approve(1)), "already_decided");
    assert_eq!(p.w.budget().held, 1);
    // A second request has no budget left: a recorded denial, never a free run.
    assert!(p.submit(2).is_ok());
    assert_eq!(code(&p.approve(2)), "budget_exhausted");
    assert_eq!(p.w.budget().held, 1);
    assert_eq!(p.sandbox.runs(), 0);
}

#[test]
fn negative_release_gates_hold_before_signing_and_delivery() {
    let p = Pipe::with_roster();
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let (req, _) = p.request(1);
    let r = run_to_completion(&p, &svc);
    let asm = p.assemble(1, &r.attempt, &r.approval_id, &r.report);
    p.w.clock.set(PREPARE_AT);
    p.w.run(Who::Operator, &custodian_cli::Command::FeedPublish);
    assert_eq!(code(&p.export()), "exported");
    let prepared = prepare(&p, &svc, &req, &asm, 1, PREPARE_AT).unwrap();
    assert_eq!(
        code(&p.export()),
        "exported",
        "the charge audit must be acknowledged before release"
    );
    let sink = RecordingSink::new();
    p.w.clock.set(RELEASE_AT);

    // The execution approval is not a release approval.
    let exec_approval = asm.approval.clone();
    assert_eq!(
        release(&p, &svc, &prepared, &exec_approval, DEST, &sink, RELEASE_AT).unwrap_err(),
        "approval_wrong_scope"
    );
    // A destination outside the policy.
    let approval = release_approval(&prepared);
    assert_eq!(
        release(
            &p,
            &svc,
            &prepared,
            &approval,
            "elsewhere",
            &sink,
            RELEASE_AT
        )
        .unwrap_err(),
        "destination_not_allowed"
    );
    // A ledger outage defers the durable decision record: nothing leaves.
    p.w.ledger.set_available(false);
    assert_eq!(
        release(&p, &svc, &prepared, &approval, DEST, &sink, RELEASE_AT).unwrap_err(),
        "ledger_unavailable"
    );
    p.w.ledger.set_available(true);
    assert!(
        sink.delivered().is_empty(),
        "nothing was delivered on any refusal"
    );
    // After the outage the same prepared release goes out exactly once.
    assert!(release(&p, &svc, &prepared, &approval, DEST, &sink, RELEASE_AT).is_ok());
    assert_eq!(sink.delivered().len(), 1);
}

#[test]
fn negative_consumer_rejects_tampered_foreign_signed_and_stale_input() {
    let p = Pipe::with_roster();
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    let (req, _) = p.request(1);
    let r = run_to_completion(&p, &svc);
    let asm = p.assemble(1, &r.attempt, &r.approval_id, &r.report);
    p.w.clock.set(PREPARE_AT);
    p.w.run(Who::Operator, &custodian_cli::Command::FeedPublish);
    p.export();
    let prepared = prepare(&p, &svc, &req, &asm, 1, PREPARE_AT).unwrap();
    assert_eq!(
        code(&p.export()),
        "exported",
        "the charge audit must be acknowledged before release"
    );
    let released = release(
        &p,
        &svc,
        &prepared,
        &release_approval(&prepared),
        DEST,
        &RecordingSink::new(),
        RELEASE_AT,
    )
    .unwrap();
    let bytes = released.to_bytes().unwrap();
    let catalog = MemoryCatalog::new();
    catalog.add(req.plan.config_digest.clone(), released);
    let service = BridgeService {
        catalog: &catalog,
        feed: &p.w.feed,
        feed_id: lc::feed_id(),
        destination: DestinationId::parse(DEST).unwrap(),
    };

    // A consumer pinned to a different key accepts nothing.
    let other = lc::test_key(9, &custodian_ledger::SignDomain::ALL);
    let mut pins = bridge_pins(&p);
    pins.verifier = Verifier::new(Keyring::new().with_root(other.entry.clone()));
    let mut c = BridgeConsumer::new(pins);
    let breq = c
        .request(
            req.plan.candidate.clone(),
            req.plan.config_digest.clone(),
            vec![],
        )
        .unwrap();
    let resp = service.answer(&breq.canonical_bytes().unwrap()).unwrap();
    let out = c.accept_response(&breq, &resp, ts(NOW + 120));
    let o = out.unwrap();
    assert!(o.accepted.is_empty());
    assert_eq!(o.rejected, vec![(0, Rejection::KeyNotAcceptable)]);
    assert_eq!(
        o.feed_error,
        Some(custodian_lifecycle::SyncError::BadSignature)
    );

    // A tampered projection fails verification.
    let c = BridgeConsumer::new(bridge_pins(&p));
    let breq = c
        .request(
            req.plan.candidate.clone(),
            req.plan.config_digest.clone(),
            vec![],
        )
        .unwrap();
    let mut bad = bytes.clone();
    let i = bad.windows(8).position(|w| w == b"reported").unwrap();
    bad[i] = b'R';
    assert_eq!(
        c.verify_projection(&breq, &bad, ts(NOW + 120)).unwrap_err(),
        Rejection::Malformed
    );

    // Before any feed has been read, nothing is valid (stale by construction).
    assert_eq!(
        c.verify_projection(&breq, &bytes, ts(NOW + 120))
            .unwrap_err(),
        Rejection::Stale
    );
}
