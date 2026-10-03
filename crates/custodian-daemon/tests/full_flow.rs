//! The full synthetic flow, end to end, as one dedicated test target (S6,
//! issue 33; the `full-synthetic-flow` CI job runs it on Linux with the real
//! bubblewrap sandbox and `CUSTODIAN_REQUIRE_ISOLATION=1`):
//!
//! request -> approval -> budget reservation -> isolated execution ->
//! signature (the isolated signer process over a real Unix socket) -> ledger
//! record (a real local Git backend) -> disclosure (the destination-bound v2
//! projection) -> consumer verification (`custodian-verify` and the bridge
//! reference consumer) -> contamination and revocation -> the consumer rejects
//! and reports which accepted projections must be re-evaluated downstream.
//!
//! Functional verification on public synthetic conformance data with
//! test-generated keys. It is not an independent protected evaluation, it says
//! nothing about corpus quality, and the repository is maintained by the
//! Redact Secret project. Where the platform cannot show isolation the
//! isolated variant logs `ISOLATION-TEST-SKIPPED` (and fails under
//! `CUSTODIAN_REQUIRE_ISOLATION=1`); the variant with the unsandboxed test
//! fake proves control flow only, never isolation.

mod common;

use common::stack::{with_stack_using, Stack};
use common::*;
use custodian_bridge::Rejection;
use custodian_contracts::public_v2::AnyProjectionEnvelope;
use custodian_contracts::revocation::Standing;
use custodian_contracts::types::{FeedId, Timestamp};
use custodian_core::{Exposure, RunId, RunState};
use custodian_ledger::walk_ledger;
use custodian_store::PipelineStep;
use custodian_verify::Verdict;

fn rid(env: &Env, n: u32) -> String {
    env.request(n).0.request_id.as_str().to_owned()
}

fn submit_through_the_edge(st: &Stack<'_>, n: u32, number: u64, delivery: u64) {
    let env = st.env;
    env.stage_request(n, number, 'a');
    assert_eq!(
        st.webhook(delivery, number, 'a'),
        (202, "queued".to_owned())
    );
    let id = rid(env, n);
    st.wait_for("the pending submission", || {
        env.store().submission(&id).unwrap().is_some()
    });
}

fn public_inputs<'a>(st: &'a Stack<'_>, feed_id: &'a FeedId) -> verify::Public<'a> {
    verify::Public {
        feed: st.feed,
        feed_id,
        key_hex: st.signer.lock().unwrap().engine.public_key_hex().to_owned(),
        key_id: cc::id("key_", 1),
        roots: st.roots,
    }
}

fn the_flow(name: &str, isolated: bool) {
    let env = Env::new(3);
    let dispatcher = if isolated {
        let Some(d) = real_worker(&env, name) else {
            return;
        };
        d
    } else {
        env.dispatcher()
    };
    let root = custodian_corpus::testing::TempRoot::new();
    let ((), exit) = with_stack_using(&env, root.path(), true, Some(dispatcher), |st| {
        // 1. Request: a signed delivery on the real listener, a pending
        // submission, and nothing reserved without a human.
        submit_through_the_edge(st, 1, 7, 1);
        let b = env.p.w.budget();
        assert_eq!((b.held, b.consumed), (0, 0));

        // 2. Hostile negatives at the edge: a forged signature never queues,
        // and a replay of the genuine delivery is refused.
        let forged = st.send(
            b"POST /webhooks/github HTTP/1.1\r\nContent-Type: application/json\r\n\
              X-Hub-Signature-256: sha256=00\r\nX-GitHub-Event: pull_request\r\n\
              X-GitHub-Delivery: 00000000-0000-4000-8000-0000000000aa\r\nContent-Length: 2\r\n\r\n",
            b"{}",
        );
        assert_eq!((forged.0, forged.1.as_str()), (401, "signature_invalid"));
        assert_eq!(st.webhook(1, 7, 'a'), (409, "delivery_replay".to_owned()));

        // 3. Approval: a human, on the control plane; the budget unit is
        // reserved (held) in the same transaction, and the operator publishes
        // the revocation feed.
        let (req, _) = env.request(1);
        let approve = st.control(Who::Approver, &approve_cmd(&req));
        assert_eq!(approve.code(), "approved", "{}", approve.render());
        let attempt = RunId::new(
            approve
                .field("attempt_id")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned(),
        );
        assert!(st
            .control(Who::Operator, &custodian_cli::Command::FeedPublish)
            .is_ok());

        // 4. Execution (inside the real sandbox when `isolated`), then the
        // receipt, the signature over the socket and the ledger record.
        st.wait_for("a prepared projection", || {
            st.run_step(&attempt) == Some(PipelineStep::Prepared)
        });
        let rec = env.store().attempt(&attempt).unwrap().unwrap();
        assert_eq!(
            (rec.state, rec.exposure),
            (RunState::Completed, Exposure::Exposed)
        );
        assert!(env.released_files().is_empty(), "nothing is out yet");

        // 5. Disclosure: a distinct human approves the release; the
        // destination-bound v2 projection is signed, ledgered and delivered
        // exactly once.
        env.at(RELEASE_AT);
        env.write_release_approval(&attempt, 1);
        st.wait_for("the release", || {
            st.run_step(&attempt) == Some(PipelineStep::Released)
        });
        st.wait_for("the export to drain", || {
            env.store().outbox_pending_count().unwrap() == 0
        });
        let files = env.released_files();
        assert_eq!(files.len(), 1);
        let envelope = AnyProjectionEnvelope::decode(&std::fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(envelope.major(), 2, "the destination-bound projection");
        assert_eq!(envelope.destination().map(|d| d.as_str()), Some(DEST));
        let b = env.p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));

        // 6. The private ledger verifies under the pinned key and holds the
        // reservation and the settlement.
        let walk = walk_ledger(st.ledger, st.roots).unwrap();
        assert!(walk.is_trustworthy(), "{:?}", walk.findings);
        assert!(walk.audit.iter().any(|e| e.kind == "reservation.created"));
        assert!(walk.audit.iter().any(|e| e.kind == "attempt.terminal"));
        assert!(st.signer.lock().unwrap().engine.stats().snapshot().signed > 0);

        // 7. Consumer verification from public inputs only: the public
        // verifier library and the bridge reference consumer both accept.
        let feed_id = st.parts.feed_config.feed_id.clone();
        let public = public_inputs(st, &feed_id);
        let t_accept = RELEASE_AT + 20;
        let report = verify::verify_released(&env, &public, &st.root, 1, false, false, t_accept);
        assert_eq!(report.verdict, Verdict::Accepted, "{}", report.render());
        let (mut consumer, request) = verify::bridge_consumer(&env, &public, 1);
        let response = verify::bridge_response(&env, &public, &request);
        let at = Timestamp::new(t_accept).unwrap();
        let outcome = consumer.accept_response(&request, &response, at).unwrap();
        assert_eq!(outcome.accepted.len(), 1, "{:?}", outcome.rejected);
        assert!(outcome.accepted[0].destination().is_some());
        let accepted = outcome.accepted[0].clone();
        assert_eq!(consumer.standing(&accepted, at), Standing::Valid);
        assert!(consumer.reevaluate(at).is_empty(), "nothing changed yet");

        // 8. Hostile negatives at the consumer: a tampered projection and a
        // verifier pinned to another key both fail.
        assert_ne!(
            verify::verify_released(&env, &public, &st.root, 1, true, false, t_accept).verdict,
            Verdict::Accepted
        );
        assert_ne!(
            verify::verify_released(&env, &public, &st.root, 1, false, true, t_accept).verdict,
            Verdict::Accepted
        );

        // 9. Contamination: the epoch is declared exposed and the feed is
        // published; the spend and the release record stand.
        let o = st.control(
            Who::Operator,
            &custodian_cli::Command::LifecycleReport {
                epoch: env.p.w.rw.epoch.clone(),
                kind: custodian_cli::command::Contaminated::Exposed,
                reason: "results_exposed".into(),
                key: lc::idk(1),
            },
        );
        assert!(o.is_ok(), "{}", o.render());
        let f = st.control(Who::Operator, &custodian_cli::Command::FeedPublish);
        assert!(f.is_ok(), "{}", f.render());
        assert_eq!(env.p.w.budget().consumed, 1);

        // 10. The consumer rejects and reports the downstream trigger.
        let t_after = RELEASE_AT + 30;
        let revoked = verify::verify_released(&env, &public, &st.root, 1, false, false, t_after);
        assert_ne!(revoked.verdict, Verdict::Accepted, "{}", revoked.render());
        let later = Timestamp::new(t_after).unwrap();
        let second = verify::bridge_response(&env, &public, &request);
        let outcome2 = consumer.accept_response(&request, &second, later).unwrap();
        assert!(outcome2.accepted.is_empty());
        assert_eq!(
            outcome2
                .rejected
                .iter()
                .map(|(_, r)| *r)
                .collect::<Vec<_>>(),
            vec![Rejection::Revoked]
        );
        assert!(outcome2.feed_applied >= 1);
        assert_eq!(consumer.standing(&accepted, later), Standing::Revoked);
        let triggers = consumer.reevaluate(later);
        assert_eq!(
            triggers.len(),
            1,
            "the product must re-evaluate this support"
        );
        assert_eq!(triggers[0].from, Standing::Valid);
        assert_eq!(triggers[0].to, Standing::Revoked);
    });
    assert!(exit.is_ok());
    env.store().integrity_check().unwrap();
    println!("FULL-FLOW-VERIFIED {name}");
}

#[test]
fn the_full_synthetic_flow_with_the_unsandboxed_test_worker() {
    // Control flow only: this variant proves no isolation.
    the_flow("full_flow_unsandboxed_control_flow_only", false);
}

#[test]
fn the_full_synthetic_flow_with_the_engine_inside_real_bubblewrap() {
    the_flow("full_flow_real_bubblewrap", true);
}
