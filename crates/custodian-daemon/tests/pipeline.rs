//! The request-to-projection pipeline (R-3), in process, over the C12 control
//! plane and the real synthetic engine run through the UNSANDBOXED test fake.
//! Functional verification on public synthetic data with test keys; nothing
//! here proves isolation (the Linux job does, `docs/worker-isolation.md`) and
//! nothing is an independent evaluation.

mod common;

use common::*;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::Contract;
use custodian_core::{Exposure, RunState};
use custodian_daemon::pipeline::{PassReport, PipelinePoint};
use custodian_daemon::Shutdown;
use custodian_store::PipelineStep;

fn pass(env: &Env) -> PassReport {
    env.with_pipeline(&CrashAt::default(), |pl, _| {
        pl.pass(&Shutdown::new()).expect("pass")
    })
}

fn step_of(env: &Env, a: &custodian_core::RunId) -> (PipelineStep, String) {
    let r = env.store().pipeline_run(a).unwrap().unwrap();
    (r.step, r.reason)
}

fn budget(env: &Env) -> (u64, u64, u64) {
    let b = env.p.w.budget();
    (b.held, b.consumed, b.refunded)
}

/// Drive request 1 to the point where only a human release approval is
/// missing.
fn to_prepared(env: &Env) -> (custodian_core::RunId, String) {
    let attempt = env.approved(1);
    env.publish_feed();
    let r = pass(env);
    assert_eq!(r.enrolled, 1);
    let (req, _) = env.request(1);
    assert_eq!(
        step_of(env, &attempt),
        (
            PipelineStep::Prepared,
            "awaiting_release_approval".to_owned()
        ),
        "{r:?}"
    );
    (attempt, req.request_id.as_str().to_owned())
}

#[test]
fn an_approved_request_runs_assembles_prepares_and_waits_for_only_the_human_release_approval() {
    let env = Env::new(3);
    let (attempt, _) = to_prepared(&env);

    // The engine ran once, inside the dispatcher: exposed, completed, consumed.
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Completed, Exposure::Exposed)
    );
    assert_eq!(budget(&env), (0, 1, 0));
    let exposures = env
        .store()
        .history(&attempt)
        .unwrap()
        .iter()
        .filter(|t| t.is_exposure)
        .count();
    assert_eq!(exposures, 1);

    // The records exist, are strict contract documents, and the receipt's
    // audit event is in the outbox (and exported once the pass drained it).
    let art = env.store().pipeline_artifacts(&attempt).unwrap().unwrap();
    let exe =
        custodian_contracts::execution::ExecutionRecord::decode(art.execution.unwrap().as_bytes())
            .unwrap();
    let rcp =
        custodian_contracts::execution::InternalReceipt::decode(art.receipt.unwrap().as_bytes())
            .unwrap();
    assert_eq!(exe.outcome, ExecutionOutcome::Success);
    assert!(exe.is_releasable());
    assert_eq!(rcp.outcome, ExecutionOutcome::Success);
    assert_eq!(rcp.roster.expected.get(), ROSTER as u64);
    assert_eq!(rcp.roster.observed.get(), ROSTER as u64);
    assert_eq!(rcp.roster.failed.get(), 0);
    assert_eq!(rcp.execution_id, exe.execution_id);
    // Declared, never derived from the engine; ground truth is not claimed.
    let att = serde_json::to_value(&rcp.attestation).unwrap();
    assert_eq!(att["independence"], "custodian-declared");
    assert_eq!(att["ground_truth"], "not_established");
    assert_eq!(att["organisational_independence"], "not_claimed");

    // Nothing was released and nothing can be without the human.
    assert!(env.released_files().is_empty());
    for _ in 0..3 {
        let r = pass(&env);
        assert_eq!(r.waiting.len(), 1);
        assert_eq!(r.waiting[0].1, "awaiting_release_approval");
    }
    assert!(env.released_files().is_empty());
    assert!(
        std::fs::read_dir(&env.approvals_dir)
            .unwrap()
            .next()
            .is_none(),
        "the daemon never writes an approval"
    );
}

#[test]
fn a_human_release_approval_releases_exactly_one_projection_at_a_later_time() {
    let env = Env::new(3);
    let (attempt, _) = to_prepared(&env);
    let before = env.store().pipeline_run(&attempt).unwrap().unwrap();
    env.write_release_approval(&attempt, 1);
    env.at(RELEASE_AT);
    let r = pass(&env);
    assert!(r.waiting.is_empty(), "{r:?}");
    assert_eq!(
        step_of(&env, &attempt),
        (PipelineStep::Released, "released".to_owned()),
        "{:?}",
        env.log.lines()
    );
    // The prepared mark did not move: the approval bound this very digest.
    let after = env.store().pipeline_run(&attempt).unwrap().unwrap();
    assert_eq!(before.prepared, after.prepared);
    assert_eq!(env.released_files().len(), 1);
    // The released bytes are a strict v2 envelope bound to the destination.
    let bytes = std::fs::read(&env.released_files()[0]).unwrap();
    let env2 = custodian_contracts::public_v2::AnyProjectionEnvelope::decode(&bytes).unwrap();
    assert_eq!(env2.major(), 2);
    assert_eq!(env2.destination().unwrap().as_str(), DEST);
    // Charged once at prepare, once at nothing else.
    assert_eq!(budget(&env), (0, 1, 0));
    // Repeating the pass changes nothing: no second file, no second charge.
    for _ in 0..3 {
        pass(&env);
    }
    assert_eq!(env.released_files().len(), 1);
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Released);
    env.store().integrity_check().unwrap();
    // The Check followed the process state and carried fixed text only.
    let posts = env.checks.posts();
    assert!(
        posts.is_empty(),
        "no pull request is linked to a CLI request"
    );
    let _ = PipelinePoint::AfterRelease;
}

// ---- engine failures never become a clean receipt ----------------------------------

#[test]
fn every_engine_failure_is_recorded_consumed_and_never_a_releasable_receipt() {
    // (engine mode, terminal word, outcome of the execution record, receipt kept)
    let cases: [(&str, &str, ExecutionOutcome, bool); 8] = [
        ("crash", "execution_failed", ExecutionOutcome::Failed, false),
        ("exit3", "execution_failed", ExecutionOutcome::Failed, false),
        (
            "garbage",
            "execution_rejected",
            ExecutionOutcome::Rejected,
            false,
        ),
        (
            "leak",
            "execution_rejected",
            ExecutionOutcome::Rejected,
            false,
        ),
        // Some inputs measured, not all: a valid private receipt, never releasable.
        (
            "partial",
            "partial_not_releasable",
            ExecutionOutcome::Partial,
            true,
        ),
        // Everything observed but an item failed: no valid receipt shape.
        (
            "failed-items",
            "partial_not_releasable",
            ExecutionOutcome::Partial,
            false,
        ),
        // A clean run whose engine reported no aggregate artifact.
        (
            "no-aggregates",
            "aggregates_missing",
            ExecutionOutcome::Success,
            false,
        ),
        // A clean run whose aggregate artifact disagrees with the roster.
        (
            "aggregates-wrong-roster",
            "aggregates_invalid",
            ExecutionOutcome::Success,
            false,
        ),
    ];
    for (mode, word, outcome, keeps_receipt) in cases {
        let env = Env::with_engine_mode(3, mode);
        let attempt = env.approved(1);
        env.publish_feed();
        pass(&env);
        assert_eq!(
            step_of(&env, &attempt),
            (PipelineStep::Closed, word.to_owned()),
            "{mode}: {:?}",
            env.log.lines()
        );
        // The engine ran (the unit is spent, never refunded after exposure).
        assert_eq!(budget(&env), (0, 1, 0), "{mode}");
        let art = env.store().pipeline_artifacts(&attempt).unwrap();
        match (mode, art) {
            // Nothing assembled when the records disagree with each other.
            ("aggregates-wrong-roster", a) => {
                assert!(a.is_none_or(|a| a.execution.is_none()), "{mode}");
            }
            (_, Some(a)) => {
                let exe = custodian_contracts::execution::ExecutionRecord::decode(
                    a.execution.as_deref().expect("execution record").as_bytes(),
                )
                .unwrap();
                assert_eq!(exe.outcome, outcome, "{mode}");
                assert_eq!(a.receipt.is_some(), keeps_receipt, "{mode}");
                // Only a success record is releasable, and without a receipt
                // (never built for these runs) even that cannot be projected.
                assert_eq!(exe.is_releasable(), outcome == ExecutionOutcome::Success);
            }
            (_, None) => panic!("{mode}: no records"),
        }
        // Nothing reaches a disclosure: no charge, no projection, no file.
        assert!(env.released_files().is_empty(), "{mode}");
        assert_eq!(
            env.store()
                .release_budget_status(&custodian_store::ReleaseScope::Requester(
                    Who::Requester.actor().as_str()
                ))
                .unwrap()
                .map(|b| b.consumed),
            None,
            "{mode}: no release budget was provisioned or charged"
        );
        env.store().integrity_check().unwrap();
    }
}

#[test]
fn a_hostile_engine_cannot_carry_protected_bytes_into_any_output() {
    const CANARY: &str = "SYNTHETIC-CANARY-PROTECTED-ENTRY-0000";
    let env = Env::with_entries(3, "leak", |i| format!("{CANARY}-{i}"));
    let attempt = env.approved(1);
    env.publish_feed();
    pass(&env);
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Closed);
    // Scan everything the daemon writes or prints. The corpus itself is the
    // one place the canary lives, and it is not scanned.
    let mut hay: Vec<(String, Vec<u8>)> = Vec::new();
    hay.push(("log".into(), env.log.lines().join("\n").into_bytes()));
    for post in env.checks.posts() {
        hay.push(("check".into(), format!("{post:?}").into_bytes()));
    }
    for p in env.p.w.ledger.paths() {
        hay.push((p.clone(), env.p.w.ledger.raw(&p).unwrap_or_default()));
    }
    hay.push((
        "store".into(),
        std::fs::read(env.p.w.rw.db.path()).unwrap_or_default(),
    ));
    for e in env.store().outbox_pending(1000).unwrap() {
        hay.push(("outbox".into(), e.payload.into_bytes()));
    }
    for f in std::fs::read_dir(&env.out_dir).unwrap().flatten() {
        hay.push(("released".into(), std::fs::read(f.path()).unwrap()));
    }
    for (what, bytes) in hay {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(CANARY), "canary leaked into {what}");
        assert!(
            !text.contains("SYNTHETIC-CANARY"),
            "canary leaked into {what}"
        );
    }
}

// ---- the export gate closes dispatch ---------------------------------------------

#[test]
fn dispatch_stays_closed_while_earlier_spend_is_unacknowledged_and_the_ledger_is_down() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    env.publish_feed();
    env.with_pipeline(&CrashAt::default(), |pl, _| {
        // Spend that happens after the startup export: a second request is
        // approved, so a budget-affecting audit event is pending. The ledger
        // accepts reads (the startup check passed) but not writes.
        assert!(env.p.submit(2).is_ok());
        assert!(env.p.approve(2).is_ok());
        env.p.w.ledger.fail_next_puts(1000);
        let r = pl.pass(&Shutdown::new()).unwrap();
        assert!(
            r.waiting.iter().all(|(_, w)| *w == "ledger_unavailable"),
            "{r:?}"
        );
        assert_eq!(r.waiting.len(), 2);
    });
    // Nothing started: reserved, not exposed, both units still held, no
    // engine ran.
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Reserved, Exposure::NotExposed)
    );
    assert_eq!(budget(&env), (2, 0, 0));
    assert!(env
        .store()
        .history(&attempt)
        .unwrap()
        .iter()
        .all(|t| !t.is_exposure));
    assert!(std::fs::read_dir(&env.scratch).unwrap().next().is_none());
    // The ledger comes back; the same runs proceed, once each.
    env.p.w.ledger.fail_next_puts(0);
    pass(&env);
    assert_eq!(budget(&env), (0, 2, 0));
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Prepared);
}

#[test]
fn an_outage_between_start_and_exposure_ends_the_attempt_unexposed_and_refunded() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    env.publish_feed();
    env.with_pipeline(&CrashAt::default(), |pl, _| {
        // Nothing is pending at the start, so the attempt can start; its own
        // start event must then be acknowledged before the corpus is opened,
        // and the ledger cannot take it (ADR 0116).
        env.p.w.ledger.fail_next_puts(1000);
        let r = pl.pass(&Shutdown::new()).unwrap();
        assert_eq!(r.waiting[0].1, "ledger_unavailable");
        // The next pass finds the attempt settled (no ledger is needed to
        // see that) and closes the run.
        pl.pass(&Shutdown::new()).unwrap();
    });
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Failed, Exposure::NotExposed)
    );
    assert!(env
        .store()
        .history(&attempt)
        .unwrap()
        .iter()
        .all(|t| !t.is_exposure));
    assert!(
        std::fs::read_dir(&env.scratch).unwrap().next().is_none(),
        "no engine ran"
    );
    // Nothing was exposed, so the unit comes back; the run is closed.
    assert_eq!(budget(&env), (0, 0, 1));
    assert_eq!(
        step_of(&env, &attempt),
        (PipelineStep::Closed, "execution_failed".to_owned())
    );
    env.p.w.ledger.fail_next_puts(0);
    env.store().integrity_check().unwrap();
}

#[test]
fn an_unpublished_feed_holds_the_release_and_an_operator_publishing_it_releases_the_hold() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    let r = pass(&env);
    assert_eq!(r.waiting[0].1, "feed_unpublished");
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Assembled);
    env.publish_feed();
    pass(&env);
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Prepared);
}

// ---- the human release approval is checked by the disclosure service -------------

#[test]
fn only_a_correct_distinct_human_release_approval_releases() {
    let env = Env::new(3);
    let (attempt, rid) = to_prepared(&env);
    let path = env.approvals_dir.join(format!("{rid}.json"));
    let wait = |env: &Env| {
        let r = pass(env);
        assert!(env.released_files().is_empty(), "{r:?}");
        r.waiting[0].1
    };

    // The EXECUTION approval is not a release approval.
    let run = env.store().pipeline_run(&attempt).unwrap().unwrap();
    let execution_approval = env
        .store()
        .approval_document(&rid, &run.approval_id)
        .unwrap()
        .unwrap();
    std::fs::write(&path, serde_json::to_vec(&execution_approval).unwrap()).unwrap();
    set_mode(&path, 0o600);
    assert_eq!(wait(&env), "approval_wrong_scope");

    // Garbage, an unknown field, an agent approver: not a valid approval document.
    for body in [
        b"not json".to_vec(),
        b"{}".to_vec(),
        serde_json::to_vec(&{
            let mut v = serde_json::to_value(&execution_approval).unwrap();
            v["unexpected"] = serde_json::json!(true);
            v
        })
        .unwrap(),
        serde_json::to_vec(&{
            let mut v = cc::approval_json();
            v["approver_kind"] = serde_json::json!("agent");
            v
        })
        .unwrap(),
    ] {
        std::fs::write(&path, body).unwrap();
        assert_eq!(wait(&env), "release_approval_rejected");
    }

    // A valid document that others can write is not read.
    env.write_release_approval(&attempt, 1);
    set_mode(&path, 0o666);
    assert_eq!(wait(&env), "release_approval_rejected");
    // Neither is a symlink to it.
    let real = env.root.path().join("real-approval.json");
    std::fs::copy(&path, &real).unwrap();
    set_mode(&real, 0o600);
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert_eq!(wait(&env), "release_approval_rejected");
    std::fs::remove_file(&path).unwrap();

    // Bound to another projection digest.
    let mut v = env.write_release_approval(&attempt, 1);
    v["scope"]["projection_digest"] = serde_json::json!(dc::sha_digest(b"another projection"));
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(wait(&env), "approval_not_bound");

    // Expired.
    let mut v = env.write_release_approval(&attempt, 1);
    v["issued_at"] = serde_json::json!(NOW);
    v["expires_at"] = serde_json::json!(NOW + 10);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    env.at(RELEASE_AT);
    assert_eq!(wait(&env), "approval_expired");

    // None of that charged or published anything further.
    assert_eq!(budget(&env), (0, 1, 0));
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Prepared);

    // The right one releases.
    env.write_release_approval(&attempt, 1);
    pass(&env);
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Released);
    assert_eq!(env.released_files().len(), 1);
}

// ---- standing, identity and budget --------------------------------------------------

fn report_exposed(env: &Env) {
    let o = env.p.w.run(
        Who::Operator,
        &custodian_cli::Command::LifecycleReport {
            epoch: env.p.w.rw.epoch.clone(),
            kind: custodian_cli::command::Contaminated::Exposed,
            reason: "results_exposed".into(),
            key: lc::idk(1),
        },
    );
    assert!(o.is_ok(), "{}", o.code());
}

#[test]
fn a_contaminated_epoch_stops_the_run_before_exposure_and_refunds_the_unit() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    report_exposed(&env);
    env.publish_feed();
    pass(&env);
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        rec.exposure,
        Exposure::NotExposed,
        "no protected byte was opened"
    );
    assert_eq!(budget(&env), (0, 0, 1), "refunded: nothing was exposed");
    assert_eq!(
        step_of(&env, &attempt),
        (PipelineStep::Closed, "execution_rejected".to_owned())
    );
}

#[test]
fn contamination_after_the_run_denies_the_release_at_the_gate() {
    let env = Env::new(3);
    let (attempt, _) = to_prepared(&env);
    env.write_release_approval(&attempt, 1);
    report_exposed(&env);
    env.publish_feed();
    env.at(RELEASE_AT);
    pass(&env);
    assert_eq!(
        step_of(&env, &attempt),
        (PipelineStep::Closed, "eligibility_denied".to_owned())
    );
    assert!(env.released_files().is_empty());
    // The spend stands; nothing was un-spent.
    assert_eq!(budget(&env), (0, 1, 0));
}

#[test]
fn a_pinned_artifact_that_changed_after_approval_is_refused_before_any_exposure() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    env.publish_feed();
    // Tamper with the pinned engine in the directory the dispatcher reads.
    let hex = custodian_worker::artifacts::hash_file(&env.p.arts.sources.engine).unwrap();
    let path = env.art_dir.join(hex.strip_prefix("sha256:").unwrap());
    std::fs::write(&path, b"a different engine").unwrap();
    pass(&env);
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(rec.exposure, Exposure::NotExposed);
    assert_eq!(budget(&env), (0, 0, 1));
    assert_eq!(step_of(&env, &attempt).0, PipelineStep::Closed);
}

#[test]
fn a_missing_artifact_waits_and_a_budget_denial_is_recorded_without_running_anything() {
    let env = Env::new(1);
    let first = env.approved(1);
    env.publish_feed();
    // Remove the engine file: the run waits (the reservation window may lapse
    // and recovery refunds it), it is not started.
    let hex = custodian_worker::artifacts::hash_file(&env.p.arts.sources.engine).unwrap();
    let path = env.art_dir.join(hex.strip_prefix("sha256:").unwrap());
    let saved = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let r = pass(&env);
    assert_eq!(r.waiting[0].1, "artifact_unavailable");
    assert_eq!(budget(&env), (1, 0, 0));
    std::fs::write(&path, saved).unwrap();
    set_mode(&path, 0o755);
    pass(&env);
    assert_eq!(step_of(&env, &first).0, PipelineStep::Prepared);

    // A second request meets the exhausted budget: the denial is recorded at
    // approval and the pipeline closes it without ever dispatching.
    assert!(env.p.submit(2).is_ok());
    let o = env.p.approve(2);
    assert_eq!(o.code(), "budget_exhausted");
    let r = pass(&env);
    assert!(r.enrolled <= 1);
    let (rid2, _) = (env.request(2).0.request_id.as_str().to_owned(), ());
    let second = env
        .store()
        .latest_attempt_of(&rid2)
        .unwrap()
        .expect("denial recorded")
        .attempt;
    assert_eq!(
        env.store().attempt(&second).unwrap().unwrap().state,
        RunState::Denied
    );
    let run = env.store().pipeline_run(&second).unwrap();
    if let Some(run) = run {
        assert_eq!(run.step, PipelineStep::Closed);
        assert_eq!(run.reason, "reservation_denied");
    }
    assert_eq!(budget(&env), (0, 1, 0), "the first spend is untouched");
}

#[test]
fn shutdown_requested_starts_no_new_work() {
    let env = Env::new(3);
    let attempt = env.approved(1);
    env.publish_feed();
    let down = Shutdown::new();
    down.request();
    env.with_pipeline(&CrashAt::default(), |pl, _| {
        pl.pass(&down).unwrap();
    });
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(rec.state, RunState::Reserved, "no run was started");
    assert_eq!(budget(&env), (1, 0, 0));
}

// ---- the assembly rules, directly --------------------------------------------------

mod assembly {
    use super::*;
    use custodian_daemon::config::AttestationConfig;
    use custodian_daemon::pipeline::assemble::{assemble, Assembled, Inputs, ResultMeta};

    struct Fixture {
        env: Env,
        attempt: custodian_core::RunId,
    }

    fn fixture() -> Fixture {
        let env = Env::new(3);
        let (attempt, _) = to_prepared(&env);
        Fixture { env, attempt }
    }

    fn run<R>(
        f: &Fixture,
        tweak: impl FnOnce(&mut custodian_store::AttemptRecord, &mut ResultMeta, &mut Vec<u8>),
        check: impl FnOnce(Result<Assembled, &'static str>) -> R,
    ) -> R {
        let store = f.env.store();
        let mut attempt = store.attempt(&f.attempt).unwrap().unwrap();
        let run = store.pipeline_run(&f.attempt).unwrap().unwrap();
        let request = store.reserved_request(&run.request_id).unwrap().unwrap();
        let approval = store
            .approval_document(&run.request_id, &run.approval_id)
            .unwrap()
            .unwrap();
        let reservation = store
            .reservation(attempt.reservation_id.as_deref().unwrap())
            .unwrap();
        let history = store.history(&f.attempt).unwrap();
        let art = store.pipeline_artifacts(&f.attempt).unwrap().unwrap();
        let mut meta = ResultMeta::parse(art.result_meta.as_deref().unwrap()).unwrap();
        let mut aggregates = art.aggregates.clone().unwrap();
        tweak(&mut attempt, &mut meta, &mut aggregates);
        let view = f.env.p.w.rw.fx.pop.registry().view().unwrap();
        check(assemble(&Inputs {
            request: &request,
            approval: &approval,
            reservation: reservation.as_ref(),
            attempt: &attempt,
            history: &history,
            meta: Some(&meta),
            aggregates: Some(&aggregates),
            attestation: AttestationConfig {
                authorship: custodian_contracts::common::Authorship::ProjectAuthored,
                review: custodian_contracts::common::ReviewStatus::ProjectReviewed,
            },
            registry: &view,
        }))
    }

    #[test]
    fn the_untouched_records_assemble_to_the_same_documents_every_time() {
        let f = fixture();
        let a = run(
            &f,
            |_, _, _| (),
            |r| match r.unwrap() {
                Assembled::Releasable { execution, receipt } => (execution, receipt),
                other => panic!("{other:?}"),
            },
        );
        let b = run(
            &f,
            |_, _, _| (),
            |r| match r.unwrap() {
                Assembled::Releasable { execution, receipt } => (execution, receipt),
                other => panic!("{other:?}"),
            },
        );
        assert_eq!(a, b);
        // They are what the pipeline stored.
        let art = f
            .env
            .store()
            .pipeline_artifacts(&f.attempt)
            .unwrap()
            .unwrap();
        assert_eq!(
            custodian_daemon::pipeline::assemble::canonical(&a.1).unwrap(),
            art.receipt.unwrap()
        );
    }

    #[test]
    fn a_settled_failure_never_becomes_a_clean_receipt_whatever_result_was_kept() {
        let f = fixture();
        // The result says success, the attempt says failed (a crash after the
        // result was kept): the attempt wins.
        let out = run(
            &f,
            |a, _, _| a.state = custodian_core::RunState::Failed,
            |r| r.unwrap(),
        );
        match out {
            Assembled::Closed {
                execution,
                receipt,
                reason,
            } => {
                assert_eq!(execution.outcome, ExecutionOutcome::Failed);
                assert!(receipt.is_none());
                assert_eq!(reason, "execution_failed");
            }
            other => panic!("{other:?}"),
        }
        // Cancelled and expired attempts likewise.
        for (state, want) in [
            (
                custodian_core::RunState::Cancelled,
                ExecutionOutcome::Cancelled,
            ),
            (custodian_core::RunState::Expired, ExecutionOutcome::Expired),
        ] {
            let out = run(&f, |a, _, _| a.state = state, |r| r.unwrap());
            match out {
                Assembled::Closed {
                    execution, receipt, ..
                } => {
                    assert_eq!(execution.outcome, want);
                    assert!(receipt.is_none());
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn partial_is_accepted_only_when_observed_is_below_expected() {
        let f = fixture();
        // 74 of 75 observed, nothing failed: a valid partial receipt, closed.
        let ok = run(
            &f,
            |a, m, agg| {
                a.state = custodian_core::RunState::Failed;
                m.outcome = "partial".into();
                m.observed = 74;
                // The aggregate artifact must carry the same counters.
                let mut v: serde_json::Value = serde_json::from_slice(agg).unwrap();
                v["roster"]["observed"] = serde_json::json!(74);
                *agg = serde_json::to_vec(&v).unwrap();
            },
            |r| r,
        );
        // Cells of the full roster exceed the partial observed count: the
        // aggregate artifact is refused rather than coerced.
        assert_eq!(ok.err(), Some("aggregates_invalid"));
        // Everything observed but one item failed: no receipt shape at all.
        let shape = run(
            &f,
            |a, m, _| {
                a.state = custodian_core::RunState::Failed;
                m.outcome = "partial".into();
                m.failed = 1;
            },
            |r| r.unwrap(),
        );
        match shape {
            Assembled::Closed {
                receipt, reason, ..
            } => {
                assert!(receipt.is_none());
                assert_eq!(reason, "partial_not_releasable");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn roster_population_and_aggregate_drift_are_refused() {
        let f = fixture();
        // The engine's roster is not the sealed epoch's.
        assert_eq!(
            run(
                &f,
                |_, m, _| {
                    m.expected = 76;
                    m.observed = 76;
                },
                |r| r.err()
            ),
            Some("population_drift")
        );
        // A success whose counters do not say so.
        assert_eq!(
            run(&f, |_, m, _| m.failed = 1, |r| r.err()),
            Some("result_inconsistent")
        );
        assert_eq!(
            run(&f, |_, m, _| m.outcome = "partial".into(), |r| r.err()),
            Some("result_inconsistent")
        );
        // Altered aggregate bytes do not match the digest the receipt names:
        // the artifact is whatever the receipt hashes, so a changed artifact
        // yields a different, still self-consistent receipt only if the
        // roster still matches; a changed roster inside it does not.
        assert_eq!(
            run(
                &f,
                |_, _, agg| {
                    let mut v: serde_json::Value = serde_json::from_slice(agg).unwrap();
                    v["roster"]["failed"] = serde_json::json!(1);
                    *agg = serde_json::to_vec(&v).unwrap();
                },
                |r| r.err()
            ),
            Some("aggregates_invalid")
        );
        // A different custody version of the same epoch.
        assert_eq!(
            run(
                &f,
                |_, _, agg| {
                    agg.clear();
                    agg.extend_from_slice(b"{}");
                },
                |r| r.err()
            ),
            Some("aggregates_invalid")
        );
    }
}
