//! The whole synthetic stack, end to end, in one process (functional
//! verification on public synthetic data, not an independent evaluation):
//!
//! signed webhook over the real loopback listener -> intake -> durable queue ->
//! consumer -> pending submission -> approval through the CLI service path ->
//! pipeline (the real synthetic engine, UNSANDBOXED test fake, not isolation)
//! -> receipt -> isolated signer over a real Unix socket -> real local Git
//! ledger -> disclosure -> a distinct human release approval -> directory
//! feed -> `custodian-verify` and the bridge consumer, with the negative and
//! hostile variants that must stop at the right layer.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::stack::{with_stack, with_stack_in, Stack};
use common::*;
use custodian_core::{Exposure, RunId, RunState};
use custodian_ledger::walk_ledger;
use custodian_ledger::LedgerBackend as _;
use custodian_store::PipelineStep;
use custodian_verify::Verdict;

fn rid(env: &Env, n: u32) -> String {
    env.request(n).0.request_id.as_str().to_owned()
}

fn attempt_of(o: &custodian_cli::Output) -> RunId {
    RunId::new(o.field("attempt_id").unwrap().as_str().unwrap().to_owned())
}

/// The webhook, then the pending submission the consumer makes of it.
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

/// Approve on the control plane (the CLI service path) and publish the feed
/// (an operator action); returns the attempt.
fn approve_and_publish(st: &Stack<'_>, n: u32) -> RunId {
    let (req, _) = st.env.request(n);
    let o = st.control(Who::Approver, &approve_cmd(&req));
    assert!(o.is_ok(), "approve: {}", o.code());
    let attempt = attempt_of(&o);
    let f = st.control(Who::Operator, &custodian_cli::Command::FeedPublish);
    assert!(f.is_ok(), "feed: {}", f.code());
    attempt
}

/// The consumer's view, from public inputs only (`common::verify`).
fn verify_bundle(
    st: &Stack<'_>,
    tamper: bool,
    wrong_key: bool,
    now: u64,
) -> custodian_verify::Report {
    let feed_id = st.parts.feed_config.feed_id.clone();
    let key_hex = st.signer.lock().unwrap().engine.public_key_hex().to_owned();
    verify::verify_released(
        st.env,
        &verify::Public {
            feed: st.feed,
            feed_id: &feed_id,
            key_hex,
            key_id: cc::id("key_", 1),
            roots: st.roots,
        },
        &st.root,
        1,
        tamper,
        wrong_key,
        now,
    )
}

#[test]
fn a_signed_webhook_becomes_a_verifiable_projection_through_every_layer() {
    let env = Env::new(3);
    let ((), exit) = with_stack(&env, |st| {
        // 1. The edge: a signed delivery over the real listener becomes a
        // pending submission through the real consumer. The Check is posted
        // through the (offline) GitHub adapter with fixed text.
        submit_through_the_edge(st, 1, 7, 1);
        let b = env.p.w.budget();
        assert_eq!(
            (b.held, b.consumed),
            (0, 0),
            "nothing is reserved without a human"
        );
        assert_eq!(st.send(b"GET /healthz HTTP/1.1\r\n\r\n", b"").0, 200);

        // 2. Approval is a human decision on the control plane, then the
        // operator publishes the revocation feed.
        let (req, _) = env.request(1);
        let o = st.control(Who::Approver, &approve_cmd(&req));
        assert_eq!(o.code(), "approved", "{}", o.render());
        let attempt = attempt_of(&o);
        let f = st.control(Who::Operator, &custodian_cli::Command::FeedPublish);
        assert!(f.is_ok(), "{}", f.render());

        // 3. The daemon runs it, assembles the receipt, exports through the
        // signer socket to the Git ledger, charges the release and waits for
        // the distinct human release approval.
        st.wait_for("a prepared projection", || {
            st.run_step(&attempt) == Some(PipelineStep::Prepared)
        });
        assert!(env.released_files().is_empty());
        let rec = env.store().attempt(&attempt).unwrap().unwrap();
        assert_eq!(
            (rec.state, rec.exposure),
            (RunState::Completed, Exposure::Exposed)
        );
        assert_eq!(st.run_reason(&attempt), "awaiting_release_approval");

        // 4. A human places the release approval; the projection is signed,
        // ledgered and delivered exactly once.
        env.at(RELEASE_AT);
        env.write_release_approval(&attempt, 1);
        st.wait_for("the release", || {
            st.run_step(&attempt) == Some(PipelineStep::Released)
        });
        assert_eq!(env.released_files().len(), 1);
        st.wait_for("the export to drain", || {
            env.store().outbox_pending_count().unwrap() == 0
        });

        // 5. The private ledger verifies with the pinned key, holds the
        // receipt's audit event and one publication decision.
        let walk = walk_ledger(st.ledger, st.roots).unwrap();
        assert!(walk.is_trustworthy(), "{:?}", walk.findings);
        let mut receipts = 0;
        let mut publications = 0;
        for p in st.ledger.list("records").unwrap() {
            let bytes = st.ledger.get(&p).unwrap().unwrap();
            let text = String::from_utf8_lossy(&bytes);
            receipts += usize::from(text.contains("receipt.issued"));
            publications += usize::from(p.as_str().contains("publication"));
        }
        assert_eq!((receipts, publications), (1, 1));
        assert!(st.signer.lock().unwrap().engine.stats().snapshot().signed > 0);

        // 6. Checks: queued, in progress, completed. Fixed text only; the
        // conclusion is never a success.
        let runs: Vec<serde_json::Value> = st
            .fake
            .seen()
            .iter()
            .filter(|s| s.path.contains("check-runs"))
            .map(|s| serde_json::from_str(s.body.as_ref().unwrap()).unwrap())
            .collect();
        let statuses: Vec<&str> = runs.iter().map(|r| r["status"].as_str().unwrap()).collect();
        assert_eq!(statuses, vec!["queued", "in_progress", "completed"]);
        assert_eq!(runs.last().unwrap()["conclusion"], "neutral");
        for r in &runs {
            let text = r["output"]["summary"].as_str().unwrap();
            assert!(text.starts_with("State: "), "{text}");
            assert!(text.ends_with("it is not a measurement result or approval."));
        }

        // 7. The consumer's view, from public inputs only.
        let report = verify_bundle(st, false, false, RELEASE_AT + 20);
        assert_eq!(report.verdict, Verdict::Accepted, "{}", report.render());
        assert_eq!(report.projections_accepted, 1);
        // A tampered projection, and a verifier pinned to another key, do not.
        assert_ne!(
            verify_bundle(st, true, false, RELEASE_AT + 20).verdict,
            Verdict::Accepted
        );
        assert_ne!(
            verify_bundle(st, false, true, RELEASE_AT + 20).verdict,
            Verdict::Accepted
        );
        // A contamination reaches the consumer through the signed feed.
        let o = st.control(
            Who::Operator,
            &custodian_cli::Command::LifecycleReport {
                epoch: env.p.w.rw.epoch.clone(),
                kind: custodian_cli::command::Contaminated::Exposed,
                reason: "results_exposed".into(),
                key: lc::idk(1),
            },
        );
        assert!(o.is_ok(), "{}", o.code());
        let f = st.control(Who::Operator, &custodian_cli::Command::FeedPublish);
        assert!(f.is_ok(), "{}", f.render());
        let revoked = verify_bundle(st, false, false, RELEASE_AT + 30);
        assert_ne!(revoked.verdict, Verdict::Accepted, "{}", revoked.render());
        // The spend and the release record stand.
        assert_eq!(env.p.w.budget().consumed, 1);
    });
    assert!(exit.is_ok());
    env.store().integrity_check().unwrap();
}

/// Hold dispatch back by moving the pinned engine out of the directory the
/// daemon reads; the run waits with `artifact_unavailable`.
fn hold(env: &Env) -> (std::path::PathBuf, std::path::PathBuf) {
    let d = custodian_worker::artifacts::hash_file(&env.p.arts.sources.engine).unwrap();
    let live = env.art_dir.join(d.strip_prefix("sha256:").unwrap());
    let held = env.art_dir.join("held-engine");
    std::fs::rename(&live, &held).unwrap();
    (live, held)
}

#[test]
fn a_dead_signer_closes_dispatch_and_nothing_is_lost_when_it_returns() {
    let env = Env::new(3);
    let (live, held) = hold(&env);
    let ((), exit) = with_stack(&env, |st| {
        submit_through_the_edge(st, 1, 7, 1);
        let attempt = approve_and_publish(st, 1);
        // The signer dies. The run was waiting for its artifact; give the
        // artifact back and watch the export gate refuse to start it.
        st.signer.lock().unwrap().down();
        std::fs::rename(&held, &live).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        let rec = env.store().attempt(&attempt).unwrap().unwrap();
        assert_eq!(
            (rec.state, rec.exposure),
            (RunState::Reserved, Exposure::NotExposed),
            "{:?}",
            st.run_reason(&attempt)
        );
        assert_eq!(env.p.w.budget().held, 1);
        assert!(env
            .store()
            .history(&attempt)
            .unwrap()
            .iter()
            .all(|t| !t.is_exposure));
        // The signer returns; the same run proceeds, once.
        st.signer.lock().unwrap().up();
        st.wait_for("the prepared projection", || {
            st.run_step(&attempt) == Some(PipelineStep::Prepared)
        });
        let b = env.p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
        let exposures = env
            .store()
            .history(&attempt)
            .unwrap()
            .iter()
            .filter(|t| t.is_exposure)
            .count();
        assert_eq!(exposures, 1);
    });
    assert!(exit.is_ok());
}

#[test]
fn an_unreachable_ledger_closes_dispatch_and_nothing_is_lost_when_it_returns() {
    let env = Env::new(3);
    let (live, held) = hold(&env);
    let ((), exit) = with_stack(&env, |st| {
        submit_through_the_edge(st, 1, 7, 1);
        let attempt = approve_and_publish(st, 1);
        // The ledger's remote goes away.
        let away = st.remote.with_extension("away");
        std::fs::rename(&st.remote, &away).unwrap();
        std::fs::rename(&held, &live).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        let rec = env.store().attempt(&attempt).unwrap().unwrap();
        assert_eq!(
            (rec.state, rec.exposure),
            (RunState::Reserved, Exposure::NotExposed),
            "dispatch is closed while the ledger cannot be reached"
        );
        assert_eq!(env.p.w.budget().held, 1);
        std::fs::rename(&away, &st.remote).unwrap();
        st.wait_for("the prepared projection", || {
            st.run_step(&attempt) == Some(PipelineStep::Prepared)
        });
        assert_eq!(env.p.w.budget().consumed, 1);
    });
    assert!(exit.is_ok());
}

#[test]
fn an_unapproved_request_runs_nothing_and_a_forged_one_never_queues() {
    let env = Env::new(3);
    let ((), exit) = with_stack(&env, |st| {
        submit_through_the_edge(st, 1, 7, 1);
        std::thread::sleep(Duration::from_millis(400));
        // Pending, not reserved, not run.
        let id = rid(&env, 1);
        assert_eq!(
            env.store().submission(&id).unwrap().unwrap().status,
            custodian_store::SubmissionStatus::Pending
        );
        assert_eq!(env.p.w.budget().held, 0);
        assert!(env.store().pipeline_runs(10).unwrap().is_empty());
        // A forged delivery is refused at the edge and reaches no queue.
        let (status, code) = st.send(
            b"POST /webhooks/github HTTP/1.1\r\nContent-Type: application/json\r\n\
              X-Hub-Signature-256: sha256=00\r\nX-GitHub-Event: pull_request\r\n\
              X-GitHub-Delivery: 00000000-0000-4000-8000-0000000000aa\r\nContent-Length: 2\r\n\r\n",
            b"{}",
        );
        assert_eq!((status, code.as_str()), (401, "signature_invalid"));
        // A replay of the genuine delivery is refused.
        assert_eq!(st.webhook(1, 7, 'a'), (409, "delivery_replay".to_owned()));
        assert_eq!(env.edge.queue_depth().unwrap(), 0);
    });
    assert!(exit.is_ok());
}

#[test]
fn a_removed_installation_stops_an_approved_request_before_it_runs() {
    use custodian_intake::ids::InstallationId;
    use custodian_intake::ports::InstallationRegistry;
    let env = Env::new(3);
    let (live, held) = hold(&env);
    let ((), exit) = with_stack(&env, |st| {
        submit_through_the_edge(st, 1, 7, 1);
        let attempt = approve_and_publish(st, 1);
        // GitHub tells us the installation was removed after the approval.
        env.edge
            .mark_installation_removed(InstallationId::new(INSTALLATION).unwrap())
            .unwrap();
        std::fs::rename(&held, &live).unwrap();
        st.wait_for("the run to close", || {
            st.run_step(&attempt) == Some(PipelineStep::Closed)
        });
        assert_eq!(st.run_reason(&attempt), "scope_removed");
        // Cancelled before any exposure: the unit is refunded, nothing ran.
        let rec = env.store().attempt(&attempt).unwrap().unwrap();
        assert_eq!(
            (rec.state, rec.exposure),
            (RunState::Cancelled, Exposure::NotExposed)
        );
        let b = env.p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 1));
    });
    assert!(exit.is_ok());
}

#[test]
fn a_restarted_daemon_neither_loses_nor_repeats_queued_work() {
    let env = Env::new(5);
    let root = custodian_corpus::testing::TempRoot::new();
    // First life: GitHub access is off, so deliveries queue and are not
    // consumed.
    let ((), exit) = with_stack_in(&env, root.path(), false, |st| {
        for n in 1..=3u32 {
            env.stage_request(n, 100 + u64::from(n), 'a');
            assert_eq!(
                st.webhook(u64::from(n), 100 + u64::from(n), 'a'),
                (202, "queued".to_owned())
            );
        }
        assert_eq!(env.edge.queue_depth().unwrap(), 3);
        assert!(env.store().submissions(10).unwrap().is_empty());
    });
    assert!(exit.is_ok());
    // Second life: the same database, key, ledger and feed.
    let ((), exit) = with_stack_in(&env, root.path(), true, |st| {
        st.wait_for("the queue to drain", || {
            env.edge.queue_depth().unwrap() == 0
        });
        assert_eq!(env.store().submissions(10).unwrap().len(), 3);
        // The same deliveries again are replays, not new work.
        assert_eq!(st.webhook(2, 102, 'a'), (409, "delivery_replay".to_owned()));
        assert_eq!(env.edge.queue_depth().unwrap(), 0);
        assert_eq!(env.edge.queue_outcomes(10).unwrap().len(), 3);
    });
    assert!(exit.is_ok());
}

#[test]
fn a_restart_between_prepare_and_release_resumes_the_same_projection() {
    let env = Env::new(3);
    let root = custodian_corpus::testing::TempRoot::new();
    let mut attempt = None;
    let (digest, exit) = with_stack_in(&env, root.path(), true, |st| {
        submit_through_the_edge(st, 1, 7, 1);
        let a = approve_and_publish(st, 1);
        st.wait_for("prepared", || {
            st.run_step(&a) == Some(PipelineStep::Prepared)
        });
        let run = env.store().pipeline_run(&a).unwrap().unwrap();
        attempt = Some(a);
        run.prepared.unwrap().projection_digest
    });
    assert!(exit.is_ok());
    let attempt = attempt.unwrap();
    // The daemon is gone. A human approves what was prepared; a new daemon
    // resumes the very same projection (the approval binds its digest).
    env.at(RELEASE_AT);
    env.write_release_approval(&attempt, 1);
    let ((), exit) = with_stack_in(&env, root.path(), true, |st| {
        st.wait_for("released", || {
            st.run_step(&attempt) == Some(PipelineStep::Released)
        });
        let run = env.store().pipeline_run(&attempt).unwrap().unwrap();
        assert_eq!(run.prepared.unwrap().projection_digest, digest);
        assert_eq!(env.released_files().len(), 1);
        let b = env.p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
        let report = verify_bundle(st, false, false, RELEASE_AT + 20);
        assert_eq!(report.verdict, Verdict::Accepted, "{}", report.render());
    });
    assert!(exit.is_ok());
    let _ = Ordering::SeqCst;
}

// ---- no protected or hostile text anywhere the stack writes or prints ----------------

/// Every file under `dir`, read as bytes.
fn all_files(dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => all_files(&p, out),
            Ok(t) if t.is_file() => out.push((
                p.display().to_string(),
                std::fs::read(&p).unwrap_or_default(),
            )),
            _ => {}
        }
    }
}

#[test]
fn nothing_protected_or_hostile_reaches_a_log_a_check_the_ledger_the_feed_or_a_projection() {
    const CANARY: &str = "SYNTHETIC-CANARY-PROTECTED-ENTRY-0000";
    for mode in ["ok", "leak"] {
        let env = Env::with_entries(3, mode, |i| format!("{CANARY}-{i}"));
        let ((), exit) = with_stack(&env, |st| {
            submit_through_the_edge(st, 1, 7, 1);
            let attempt = approve_and_publish(st, 1);
            if mode == "ok" {
                st.wait_for("prepared", || {
                    st.run_step(&attempt) == Some(PipelineStep::Prepared)
                });
                env.at(RELEASE_AT);
                env.write_release_approval(&attempt, 1);
                st.wait_for("released", || {
                    st.run_step(&attempt) == Some(PipelineStep::Released)
                });
            } else {
                st.wait_for("the run to close", || {
                    st.run_step(&attempt) == Some(PipelineStep::Closed)
                });
                assert_eq!(st.run_reason(&attempt), "execution_rejected");
            }
            st.wait_for("the export to drain", || {
                env.store().outbox_pending_count().unwrap() == 0
            });
            // Everything the stack wrote outside the protected corpus: the
            // ledger clone, the feed, the released projections, the signer's
            // directory (public material only), the request documents, the
            // store file, the log and every GitHub call.
            let mut hay: Vec<(String, Vec<u8>)> = Vec::new();
            all_files(&st.root, &mut hay);
            all_files(&env.out_dir, &mut hay);
            all_files(&env.requests_dir, &mut hay);
            hay.push(("store".into(), std::fs::read(env.p.w.rw.db.path()).unwrap()));
            hay.push(("log".into(), env.log.lines().join("\n").into_bytes()));
            for s in st.fake.seen() {
                hay.push(("github".into(), format!("{s:?}").into_bytes()));
            }
            for (what, bytes) in &hay {
                let text = String::from_utf8_lossy(bytes);
                assert!(
                    !text.contains("SYNTHETIC-CANARY"),
                    "{mode}: canary in {what}"
                );
                // The hostile pull request title and body are never read.
                assert!(
                    !text.contains("SYNTHETIC HOSTILE"),
                    "{mode}: hostile text in {what}"
                );
            }
            assert!(hay.len() > 10, "the scan covered real files");
        });
        assert!(exit.is_ok(), "{mode}");
    }
}
