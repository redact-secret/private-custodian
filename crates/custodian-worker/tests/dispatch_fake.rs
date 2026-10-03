//! Dispatcher logic tests over the UNSANDBOXED test fake. These run on any
//! platform and prove ordering, identity checks, bounded result validation,
//! outcome mapping and cancellation. They prove NOTHING about isolation: the
//! fake applies none. Real isolation is tested in `linux_isolation.rs`.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_core::Exposure;
use custodian_worker::fake::TestOnlyUnsandboxedFake;
use custodian_worker::isolation::IsolationVerification;
use custodian_worker::refusing::RefusingSandbox;
use custodian_worker::sandbox::{CancelToken, Sandbox, SandboxKind, Termination};
use custodian_worker::{DispatchJob, DispatchReport, Dispatcher, WorkerReason as R};

fn dispatcher(env: &Env) -> Dispatcher {
    let fake = TestOnlyUnsandboxedFake::new_not_isolated(env.scratch.clone());
    Dispatcher::new_for_tests(
        Arc::new(fake),
        IsolationVerification::test_only_not_isolated(NOW),
        env.config(),
    )
    .unwrap()
}

struct Run {
    report: DispatchReport,
    log: Log,
}

fn run_with(env: &Env, domain: &str, mode: &str, l: Limits, roster: usize) -> Run {
    let p = pinned(env, "a", mode);
    run_pinned(env, domain, &p, l, roster)
}

fn run_pinned(env: &Env, domain: &str, p: &Pinned, l: Limits, roster: usize) -> Run {
    let plan = plan(domain, p, &l);
    let lg = log();
    let ledger = RecLedger::new(&lg);
    let corpus = RecCorpus::new(&lg, &plan, roster);
    let job = DispatchJob {
        plan: &plan,
        sources: &p.sources,
    };
    let report = dispatcher(env)
        .run_attempt(&job, &ledger, &corpus, &CancelToken::new())
        .unwrap();
    Run { report, log: lg }
}

fn finish_events(l: &Log) -> Vec<String> {
    events(l)
        .into_iter()
        .filter(|e| e.starts_with("ledger:finish"))
        .collect()
}

// ---- ordering and success -------------------------------------------------

#[test]
fn both_domains_succeed_in_control_plane_order() {
    for domain in ["credential", "pii"] {
        let env = Env::new("order");
        let r = run_with(&env, domain, "ok", Limits::normal(), 3);
        assert_eq!(r.report.outcome, O::Success, "{domain}");
        assert_eq!(r.report.reason, R::Completed);
        assert_eq!(r.report.exposure, Exposure::Exposed);
        assert!(r.report.settled);
        let roster = r.report.roster().unwrap();
        assert_eq!(roster.expected.get(), 3);
        assert_eq!(roster.observed.get(), 3);
        assert_eq!(roster.failed.get(), 0);
        assert!(r.report.artifact().is_some());
        let e = events(&r.log);
        let pos = |s: &str| {
            e.iter()
                .position(|x| x == s)
                .unwrap_or_else(|| panic!("{s} in {e:?}"))
        };
        assert!(pos("ledger:start") < pos("ledger:exposure"));
        assert!(
            pos("ledger:exposure") < pos("corpus:open"),
            "exposure before corpus: {e:?}"
        );
        assert!(pos("corpus:open") < pos("ledger:begin_validation"));
        assert!(pos("ledger:begin_validation") < pos("ledger:finish:Success:Completed"));
        assert_eq!(env.staging_entries(), 0, "staging removed");
    }
}

#[test]
fn partial_and_failed_items_are_partial_never_success() {
    for mode in ["partial", "failed-items"] {
        let env = Env::new("partial");
        let r = run_with(&env, "pii", mode, Limits::normal(), 4);
        assert_eq!(r.report.outcome, O::Partial, "{mode}");
        assert_eq!(r.report.reason, R::EnginePartial);
        assert!(r.report.result.is_some());
        assert_eq!(
            finish_events(&r.log),
            vec!["ledger:finish:Partial:ExecutionFailed"]
        );
    }
}

// ---- crashes and abuse are never clean ------------------------------------

#[test]
fn crash_signal_exit_timeout_and_floods_are_failed() {
    let cases: [(&str, R, Limits); 5] = [
        ("crash", R::Signaled, Limits::normal()),
        ("exit3", R::NonZeroExit, Limits::normal()),
        (
            "sleep",
            R::Timeout,
            Limits {
                wall: 1,
                ..Limits::normal()
            },
        ),
        ("flood-stdout", R::OutputLimit, Limits::normal()),
        (
            "flood-stderr",
            R::OutputLimit,
            Limits {
                out: 65_536,
                ..Limits::normal()
            },
        ),
    ];
    for (mode, reason, limits) in cases {
        let env = Env::new("abuse");
        let r = run_with(&env, "credential", mode, limits, 2);
        assert_eq!(r.report.outcome, O::Failed, "{mode}");
        assert_eq!(r.report.reason, reason, "{mode}");
        assert!(
            r.report.result.is_none(),
            "{mode}: stdout of a failed run is not parsed"
        );
        assert_eq!(r.report.exposure, Exposure::Exposed);
        assert!(
            finish_events(&r.log)[0].starts_with("ledger:finish:Failed"),
            "{mode}"
        );
        assert!(
            !events(&r.log)
                .iter()
                .any(|e| e == "ledger:begin_validation"),
            "{mode}: no validation of a crashed run"
        );
    }
}

#[test]
fn malformed_oversized_and_mismatched_results_are_rejected() {
    let cases: [(&str, R); 4] = [
        ("garbage", R::ResultMalformed),
        ("wrong-roster", R::RosterMismatch),
        ("wrong-domain", R::ResultMismatch),
        ("unknown-field", R::ResultMalformed),
    ];
    for (mode, reason) in cases {
        let env = Env::new("reject");
        let r = run_with(&env, "credential", mode, Limits::normal(), 2);
        assert_eq!(r.report.outcome, O::Rejected, "{mode}");
        assert_eq!(r.report.reason, reason, "{mode}");
        assert!(r.report.result.is_none());
        assert_eq!(
            finish_events(&r.log),
            vec![format!("ledger:finish:Rejected:{:?}", reason.core_reason())]
        );
    }
}

#[test]
fn oversized_stdout_trips_the_output_bound() {
    let env = Env::new("oversize");
    let r = run_with(&env, "credential", "oversize", Limits::normal(), 2);
    assert_eq!(r.report.outcome, O::Failed);
    assert_eq!(r.report.reason, R::OutputLimit);
}

#[test]
fn stderr_with_secret_shaped_text_is_not_propagated() {
    let env = Env::new("stderr");
    let r = run_with(&env, "credential", "stderr-secret", Limits::normal(), 2);
    assert_eq!(r.report.outcome, O::Success);
    let shown = format!("{:?}", r.report);
    for needle in ["SYNTHETIC-SECRET", "hunter2", "password"] {
        assert!(!shown.contains(needle), "report leaked {needle}");
    }
    let logged = events(&r.log).join("\n");
    assert!(!logged.contains("SYNTHETIC-SECRET") && !logged.contains("hunter2"));
    // The raw run type keeps only a byte count of stderr.
    let rr = format!("{:?}", r.report.result.as_ref().unwrap());
    assert!(!rr.contains("hunter2"));
}

// ---- identity -------------------------------------------------------------

#[test]
fn identity_tampering_before_dispatch_fails_closed_before_exposure() {
    let kinds = ["engine", "adapter", "scanner", "candidate", "config"];
    for kind in kinds {
        let env = Env::new("tamper-pre");
        let p = pinned(&env, "a", "ok");
        let l = Limits::normal();
        let plan = plan("credential", &p, &l); // identities frozen here
        let target = match kind {
            "engine" => p.sources.engine.clone(),
            "adapter" => p.sources.adapter.clone(),
            "scanner" => p.sources.scanners[0].clone(),
            "candidate" => p.sources.candidate.clone(),
            _ => p.sources.config.clone(),
        };
        let mut bytes = fs::read(&target).unwrap();
        bytes.push(b'!'); // a changed build, dependency or configuration
        fs::write(&target, bytes).unwrap();

        let lg = log();
        let ledger = RecLedger::new(&lg);
        let corpus = RecCorpus::new(&lg, &plan, 2);
        let job = DispatchJob {
            plan: &plan,
            sources: &p.sources,
        };
        let rep = dispatcher(&env)
            .run_attempt(&job, &ledger, &corpus, &CancelToken::new())
            .unwrap();
        assert_eq!(rep.outcome, O::Rejected, "{kind}");
        assert_eq!(rep.reason, R::IdentityMismatch, "{kind}");
        assert_eq!(rep.exposure, Exposure::NotExposed);
        let e = events(&lg);
        assert_eq!(
            e,
            vec!["ledger:fail_before_start:PlanMismatch"],
            "{kind}: {e:?}"
        );
    }
}

#[test]
fn artifacts_outside_the_allowlist_or_linked_are_refused() {
    let env = Env::new("allow");
    let other = Env::new("other");
    let p = pinned(&env, "a", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    // Engine outside the allowlisted root.
    let mut s = p.sources.clone();
    s.engine = other.art.join("engine-x");
    fs::copy(&p.sources.engine, &s.engine).unwrap();
    let lg = log();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &s,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.reason, R::ArtifactNotAllowlisted);
    assert_eq!(rep.exposure, Exposure::NotExposed);

    // A symlink inside the root pointing at a legitimate artifact.
    let mut s = p.sources.clone();
    let link = env.art.join("engine-link");
    std::os::unix::fs::symlink(&p.sources.engine, &link).unwrap();
    s.engine = link;
    let lg = log();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &s,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.reason, R::ArtifactInvalid);

    // A hard-link alias and a group-writable file.
    let mut s = p.sources.clone();
    let alias = env.art.join("engine-alias");
    fs::hard_link(&p.sources.engine, &alias).unwrap();
    s.engine = alias;
    let lg = log();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &s,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.reason, R::ArtifactInvalid);
    let mut s = p.sources.clone();
    s.config = env.put("config-w", b"ok", 0o666);
    let lg = log();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &s,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.reason, R::ArtifactInvalid);
}

#[test]
fn identity_tampering_after_staging_fails_closed_and_never_runs() {
    let env = Env::new("tamper-staged");
    let p = pinned(&env, "a", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let ledger = RecLedger::new(&lg);
    let mut corpus = RecCorpus::new(&lg, &plan, 2);
    // While protected inputs are being materialized (after staging was
    // verified), rewrite the staged copy of the engine.
    let staging = env.staging.clone();
    corpus.on_read = Some(Box::new(move || {
        for e in fs::read_dir(&staging).unwrap().flatten() {
            let f = e.path().join("stage").join("config");
            if f.exists() {
                fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&f, b"crash").unwrap();
            }
        }
    }));
    let job = DispatchJob {
        plan: &plan,
        sources: &p.sources,
    };
    let rep = dispatcher(&env)
        .run_attempt(&job, &ledger, &corpus, &CancelToken::new())
        .unwrap();
    assert_eq!(rep.outcome, O::Rejected);
    assert_eq!(rep.reason, R::IdentityChangedAfterStaging);
    assert!(
        rep.termination.is_none(),
        "the tampered engine must not have run"
    );
    assert!(finish_events(&lg)[0].starts_with("ledger:finish:Rejected"));
}

#[test]
fn source_changed_during_execution_is_rejected_even_if_the_run_was_clean() {
    let env = Env::new("tamper-post");
    let p = pinned(&env, "a", "ok");
    let plan = plan("pii", &p, &Limits::normal());
    let lg = log();
    let mut corpus = RecCorpus::new(&lg, &plan, 2);
    let src = p.sources.adapter.clone();
    corpus.on_read = Some(Box::new(move || {
        fs::write(&src, b"swapped adapter").unwrap();
    }));
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &corpus,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.outcome, O::Rejected);
    assert_eq!(rep.reason, R::IdentityChangedAfterExecution);
    assert!(rep.result.is_none());
}

#[test]
fn population_binding_mismatch_is_rejected_after_exposure_is_recorded() {
    let env = Env::new("pop");
    let p = pinned(&env, "a", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let mut corpus = RecCorpus::new(&lg, &plan, 2);
    let mut v = serde_json::to_value(&corpus.binding).unwrap();
    v["population_digest"] = serde_json::Value::String(dg("another-population"));
    corpus.binding = serde_json::from_value(v).unwrap();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &corpus,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.outcome, O::Rejected);
    assert_eq!(rep.reason, R::PopulationMismatch);
    assert_eq!(rep.exposure, Exposure::Exposed);
}

#[test]
fn corpus_unavailable_and_empty_roster_fail_closed() {
    let env = Env::new("corpus");
    let p = pinned(&env, "a", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let mut corpus = RecCorpus::new(&lg, &plan, 2);
    corpus.open_fails = true;
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &corpus,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!((rep.outcome, rep.reason), (O::Failed, R::CorpusUnavailable));
    let lg = log();
    let corpus = RecCorpus::new(&lg, &plan, 0);
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &corpus,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!((rep.outcome, rep.reason), (O::Rejected, R::RosterMismatch));
}

// ---- cancellation and lease loss -------------------------------------------

#[test]
fn cancellation_kills_the_tree_and_settles_cancelled() {
    let env = Env::new("cancel");
    let token = format!("cancel-token-{}", std::process::id());
    let p = pinned(&env, "a", &format!("tree {token}"));
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    let tok = token.clone();
    let t = std::thread::spawn(move || {
        wait_running(&tok);
        c2.cancel();
    });
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &cancel,
        )
        .unwrap();
    t.join().unwrap();
    assert_eq!(rep.outcome, O::Cancelled);
    assert_eq!(rep.termination, Some(Termination::Cancelled));
    assert!(finish_events(&lg)[0].starts_with("ledger:finish:Cancelled"));
    assert!(
        wait_gone(&token),
        "worker tree must be gone after cancellation"
    );
}

#[test]
fn cancelled_before_start_is_refunded_not_run() {
    let env = Env::new("precancel");
    let p = pinned(&env, "a", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let cancel = CancelToken::new();
    cancel.cancel();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &cancel,
        )
        .unwrap();
    assert_eq!(rep.outcome, O::Cancelled);
    assert_eq!(events(&lg), vec!["ledger:fail_before_start:Cancelled"]);
}

#[test]
fn a_fenced_lease_stops_the_worker_and_does_not_finish() {
    let env = Env::new("fenced");
    let token = format!("fence-token-{}", std::process::id());
    let p = pinned(&env, "a", &format!("tree {token}"));
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let mut ledger = RecLedger::new(&lg);
    ledger.lose_lease_after_beats = Some(1);
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &ledger,
            &RecCorpus::new(&lg, &plan, 1),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.outcome, O::Cancelled);
    assert_eq!(rep.reason, R::LeaseLost);
    assert!(!rep.settled);
    assert!(
        finish_events(&lg).is_empty(),
        "a fenced holder must not settle"
    );
    assert!(wait_gone(&token));
}

#[test]
fn daemonized_children_do_not_outlive_a_clean_run() {
    let env = Env::new("daemon");
    let token = format!("daemon-token-{}", std::process::id());
    let r = run_with(
        &env,
        "credential",
        &format!("daemon {token}"),
        Limits::normal(),
        1,
    );
    assert_eq!(r.report.outcome, O::Success);
    assert!(
        wait_gone(&token),
        "supervisor must tear down the whole group"
    );
}

#[test]
fn ledger_that_cannot_start_returns_an_error_and_runs_nothing() {
    let env = Env::new("nostart");
    let p = pinned(&env, "a", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    let lg = log();
    let mut ledger = RecLedger::new(&lg);
    ledger.fail_start = Some(R::LeaseLost);
    let out = dispatcher(&env).run_attempt(
        &DispatchJob {
            plan: &plan,
            sources: &p.sources,
        },
        &ledger,
        &RecCorpus::new(&lg, &plan, 1),
        &CancelToken::new(),
    );
    assert_eq!(out.unwrap_err(), R::LeaseLost);
    assert!(events(&lg).is_empty());
}

// ---- fail-closed construction ----------------------------------------------

#[test]
fn product_constructor_refuses_the_fake_and_the_refusing_backend() {
    let env = Env::new("ctor");
    let fake: Arc<dyn Sandbox> = Arc::new(TestOnlyUnsandboxedFake::new_not_isolated(
        env.scratch.clone(),
    ));
    assert_eq!(
        Dispatcher::new(
            fake.clone(),
            IsolationVerification::test_only_not_isolated(NOW),
            env.config()
        )
        .err(),
        Some(R::IsolationNotVerified)
    );
    assert_eq!(fake.kind(), SandboxKind::TestOnlyUnsandboxedFake);
    // The self-check never accepts the fake and cannot run on the refuser.
    let launcher = "none";
    let probe = {
        let p = env.art.join("probe");
        fs::copy(PROBE_BIN, &p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    };
    let allow = env.allowlist();
    let e = custodian_worker::run_self_check(&*fake, launcher, &probe, &allow, &env.staging, NOW);
    assert_eq!(e.err().map(|x| x.reason), Some(R::IsolationNotVerified));
    let e = custodian_worker::run_self_check(
        &RefusingSandbox,
        launcher,
        &probe,
        &allow,
        &env.staging,
        NOW,
    );
    assert_eq!(e.err().map(|x| x.reason), Some(R::UnsupportedPlatform));
    // A verification for one sandbox kind is not accepted for another.
    assert_eq!(
        Dispatcher::new(
            Arc::new(RefusingSandbox),
            IsolationVerification::test_only_not_isolated(NOW),
            env.config()
        )
        .err(),
        Some(R::IsolationNotVerified)
    );
}

#[test]
fn refusing_backend_runs_nothing_and_dispatch_cannot_be_built_on_it() {
    use custodian_worker::sandbox::{Quotas, SandboxSpec};
    let spec = SandboxSpec {
        program: "/bin/true".into(),
        args: vec![],
        ro_mounts: vec![],
        env: vec![],
        launcher_env_canaries: vec![],
        quotas: Quotas {
            cpu_seconds: 1,
            wall: Duration::from_secs(1),
            memory_bytes: 1 << 20,
            storage_bytes: 1 << 20,
            max_processes: 1,
            stdout_bytes: 10,
            stderr_bytes: 10,
        },
    };
    let r = RefusingSandbox.run(&spec, &CancelToken::new(), &mut || true);
    assert_eq!(r.err(), Some(R::UnsupportedPlatform));
}

#[test]
fn environment_allowlist_refuses_credential_shaped_names() {
    use custodian_worker::sandbox::{env_name_allowed, ENV_ALLOWLIST};
    for ok in ENV_ALLOWLIST {
        assert!(env_name_allowed(ok), "{ok}");
    }
    for bad in [
        "GITHUB_TOKEN",
        "CUSTODIAN_LEDGER_SIGNING_KEY",
        "CUSTODIAN_APP_PRIVATE_KEY",
        "CUSTODIAN_DB_ADMIN_URL",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "LD_PRELOAD",
        "path",
    ] {
        assert!(!env_name_allowed(bad), "{bad}");
    }
}

#[test]
fn quotas_are_capped_by_operator_limits_and_zero_is_refused() {
    let env = Env::new("quota");
    let p = pinned(&env, "a", "ok");
    // A plan that asks for zero processes is inconsistent: refused up front.
    let plan = plan(
        "credential",
        &p,
        &Limits {
            procs: 0,
            ..Limits::normal()
        },
    );
    let lg = log();
    let rep = dispatcher(&env)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 1),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(rep.reason, R::PlanInconsistent);
    assert_eq!(events(&lg), vec!["ledger:fail_before_start:PlanMismatch"]);
}
