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
