//! The pipeline with the REAL bubblewrap sandbox (Linux only).
//!
//! The same flow as `pipeline.rs` and `e2e.rs`, except the synthetic engine
//! runs inside the actual isolation boundary after the startup self-check
//! passed on this host. Elsewhere each test logs
//! `ISOLATION-TEST-SKIPPED <name>: <reason>` and returns; a skipped test
//! verified nothing and must not be counted as isolation evidence. CI sets
//! `CUSTODIAN_REQUIRE_ISOLATION=1`, which turns every skip into a failure, and
//! greps for `PIPELINE-ISOLATION-VERIFIED` (the `worker-isolation` job,
//! `.github/workflows/ci.yml`).
//!
//! Synthetic data and test keys only. This is functional verification that
//! the daemon drives the real worker boundary end to end; it does not turn the
//! isolation claims of `docs/worker-isolation.md` into more than they are, and
//! it is not an independent evaluation.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::*;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::Contract as _;
use custodian_core::{Exposure, RunState};
use custodian_daemon::Shutdown;
use custodian_store::PipelineStep;
use custodian_worker::artifacts::ArtifactAllowlist;
use custodian_worker::bwrap::BubblewrapSandbox;
use custodian_worker::{run_self_check, Dispatcher, DispatcherConfig};

const PROBE_BIN: &str = env!("CARGO_BIN_EXE_custodian-daemon-probe");

fn skip(name: &str, why: &str) {
    eprintln!("ISOLATION-TEST-SKIPPED {name}: {why}");
    if std::env::var("CUSTODIAN_REQUIRE_ISOLATION").as_deref() == Ok("1") {
        panic!("isolation required but unavailable for {name}: {why}");
    }
}

/// The real worker for `env`, after the real self-check, or `None` (a logged
/// skip) where isolation cannot be shown.
fn real_worker(env: &Env, name: &str) -> Option<Dispatcher> {
    if !cfg!(target_os = "linux") {
        skip(
            name,
            &format!("platform is {}, not linux", std::env::consts::OS),
        );
        return None;
    }
    let sandbox = match BubblewrapSandbox::detect() {
        Ok(s) => s,
        Err(e) => {
            skip(name, &format!("detect: {e}"));
            return None;
        }
    };
    let probe: PathBuf = env.art_dir.join("probe");
    std::fs::copy(PROBE_BIN, &probe).unwrap();
    set_mode(&probe, 0o755);
    let allowlist = ArtifactAllowlist::new(std::slice::from_ref(&env.art_dir)).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let verification = match run_self_check(
        &sandbox,
        &sandbox.launcher_version(),
        &probe,
        &allowlist,
        &env.p.arts.staging,
        now,
    ) {
        Ok(v) => v,
        Err(e) => {
            skip(name, &format!("self-check failed: {e}"));
            return None;
        }
    };
    let mut cfg = DispatcherConfig::new(env.p.arts.staging.clone(), allowlist);
    cfg.heartbeat_interval = std::time::Duration::from_millis(100);
    Some(Dispatcher::new(Arc::new(sandbox), verification, cfg).expect("verified worker"))
}

fn pass(env: &Env, d: &Dispatcher) {
    env.try_with_pipeline_using(d, &CrashAt::default(), |pl, _| {
        pl.pass(&Shutdown::new()).expect("pass")
    })
    .expect("startup");
}

#[test]
fn the_pipeline_releases_a_verifiable_projection_with_the_engine_inside_real_bubblewrap() {
    let name = "pipeline_real_bubblewrap";
    let env = Env::new(3);
    let Some(worker) = real_worker(&env, name) else {
        return;
    };
    let attempt = env.approved(1);
    env.publish_feed();
    pass(&env, &worker);
    let rec = env.store().attempt(&attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Completed, Exposure::Exposed),
        "{:?}",
        env.log.lines()
    );
    let run = env.store().pipeline_run(&attempt).unwrap().unwrap();
    assert_eq!(run.step, PipelineStep::Prepared, "{run:?}");
    // The receipt was built from what ran inside the boundary.
    let art = env.store().pipeline_artifacts(&attempt).unwrap().unwrap();
    let exe =
        custodian_contracts::execution::ExecutionRecord::decode(art.execution.unwrap().as_bytes())
            .unwrap();
    assert_eq!(exe.outcome, ExecutionOutcome::Success);

    // A human release approval; the release is delivered once.
    env.write_release_approval(&attempt, 1);
    env.at(RELEASE_AT);
    pass(&env, &worker);
    assert_eq!(
        env.store().pipeline_run(&attempt).unwrap().unwrap().step,
        PipelineStep::Released
    );
    assert_eq!(env.released_files().len(), 1);
    let b = env.p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));

    // And the public verifier accepts it from public inputs alone.
    let feed_id = lc::feed_id();
    let public = verify::Public {
        feed: &env.p.w.feed,
        feed_id: &feed_id,
        key_hex: env.p.w.key.signer.public_key_hex(),
        key_id: cc::id("key_", 1),
        roots: &env.p.w.roots,
    };
    let report = verify::verify_released(
        &env,
        &public,
        env.root.path(),
        1,
        false,
        false,
        RELEASE_AT + 20,
    );
    assert_eq!(
        report.verdict,
        custodian_verify::Verdict::Accepted,
        "{}",
        report.render()
    );
    let tampered = verify::verify_released(
        &env,
        &public,
        env.root.path(),
        1,
        true,
        false,
        RELEASE_AT + 20,
    );
    assert_ne!(tampered.verdict, custodian_verify::Verdict::Accepted);
    println!("PIPELINE-ISOLATION-VERIFIED {name}");
}

#[test]
fn a_hostile_engine_inside_real_bubblewrap_still_cannot_carry_protected_bytes_out() {
    let name = "pipeline_real_bubblewrap_hostile";
    const CANARY: &str = "SYNTHETIC-CANARY-PROTECTED-ENTRY-0000";
    let env = Env::with_entries(3, "leak", |i| format!("{CANARY}-{i}"));
    let Some(worker) = real_worker(&env, name) else {
        return;
    };
    let attempt = env.approved(1);
    env.publish_feed();
    pass(&env, &worker);
    let run = env.store().pipeline_run(&attempt).unwrap().unwrap();
    assert_eq!(
        (run.step, run.reason.as_str()),
        (PipelineStep::Closed, "execution_rejected"),
        "{:?}",
        env.log.lines()
    );
    assert_eq!(env.p.w.budget().consumed, 1);
    for line in env.log.lines() {
        assert!(!line.contains("SYNTHETIC-CANARY"), "{line}");
    }
    for p in env.p.w.ledger.paths() {
        let bytes = env.p.w.ledger.raw(&p).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&bytes).contains("SYNTHETIC-CANARY"),
            "{p}"
        );
    }
    assert!(env.released_files().is_empty());
    println!("PIPELINE-ISOLATION-VERIFIED {name}");
}
