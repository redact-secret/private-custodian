//! Real isolation tests: synthetic malicious candidates run under the actual
//! bubblewrap backend.
//!
//! These need Linux with unprivileged user namespaces, `bwrap` and `prlimit`.
//! Elsewhere each test logs `ISOLATION-TEST-SKIPPED <name>: <reason>` and
//! returns; a skipped test verified nothing and must not be counted as
//! isolation evidence. CI sets `CUSTODIAN_REQUIRE_ISOLATION=1`, which turns
//! every skip into a failure so the Ubuntu job cannot pass silently without
//! running them. Docker presence is not accepted as evidence on a developer
//! machine; the CI Ubuntu job is.

mod common;

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::*;
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_worker::artifacts::Staging;
use custodian_worker::bwrap::BubblewrapSandbox;
use custodian_worker::isolation::{IsolationVerification, CANARY_ENV, REQUIRED_CHECKS};
use custodian_worker::sandbox::{
    env_name_allowed, CancelToken, Quotas, RawRun, RoMount, Sandbox, SandboxSpec, Termination,
};
use custodian_worker::{run_self_check, DispatchJob, Dispatcher, WorkerReason as R};

struct Host {
    sandbox: Arc<BubblewrapSandbox>,
    verification: IsolationVerification,
    env: Env,
}

static HOST: OnceLock<Result<Host, String>> = OnceLock::new();

fn host() -> &'static Result<Host, String> {
    HOST.get_or_init(|| {
        if !cfg!(target_os = "linux") {
            return Err(format!("platform is {}, not linux", std::env::consts::OS));
        }
        let sandbox = BubblewrapSandbox::detect().map_err(|e| format!("detect: {e}"))?;
        let env = Env::new("linux-host");
        let probe = env.art.join("probe");
        fs::copy(PROBE_BIN, &probe).unwrap();
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
        let v = run_self_check(
            &sandbox,
            &sandbox.launcher_version(),
            &probe,
            &env.allowlist(),
            &env.staging,
            1_800_000_000,
        )
        .map_err(|e| format!("self-check failed: {e}"))?;
        Ok(Host {
            sandbox: Arc::new(sandbox),
            verification: v,
            env,
        })
    })
}

/// Returns the host, or logs the skip (and fails when isolation is required).
fn need(name: &str) -> Option<&'static Host> {
    match host() {
        Ok(h) => Some(h),
        Err(why) => {
            eprintln!("ISOLATION-TEST-SKIPPED {name}: {why}");
            if std::env::var("CUSTODIAN_REQUIRE_ISOLATION").as_deref() == Ok("1") {
                panic!("isolation required but unavailable for {name}: {why}");
            }
            None
        }
    }
}

fn quotas(l: &Limits) -> Quotas {
    Quotas {
        cpu_seconds: l.cpu,
        wall: Duration::from_secs(l.wall),
        memory_bytes: l.mem_mib << 20,
        storage_bytes: l.storage_mib << 20,
        max_processes: l.procs,
        stdout_bytes: 65_536,
        stderr_bytes: 1 << 20,
    }
}

/// Stage the fixture as the engine, run it directly in the sandbox, and hand
/// back the bounded raw run for inspection.
fn raw(h: &Host, mode_line: &str, l: Limits, canaries: Vec<(String, String)>) -> RawRun {
    let env = &h.env;
    static N: AtomicU64 = AtomicU64::new(0);
    let p = pinned(
        env,
        &format!("raw{}", N.fetch_add(1, Ordering::SeqCst)),
        mode_line,
    );
    let mut st = Staging::create(&env.staging).unwrap();
    for (name, src) in [("engine", &p.sources.engine), ("config", &p.sources.config)] {
        let d = custodian_worker::artifacts::hash_file(src).unwrap();
        st.stage_pinned(name, src, &d, name == "engine").unwrap();
    }
    let spec = SandboxSpec {
        program: "/stage/engine".into(),
        args: vec!["--job".into(), "/job/job.json".into()],
        ro_mounts: vec![
            RoMount {
                host: st.stage_dir(),
                inner: "/stage".into(),
            },
            RoMount {
                host: st.input_dir(),
                inner: "/input".into(),
            },
            RoMount {
                host: st.job_dir(),
                inner: "/job".into(),
            },
        ],
        env: vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/scratch".into()),
            ("TMPDIR".into(), "/scratch".into()),
            ("LANG".into(), "C".into()),
        ],
        launcher_env_canaries: canaries,
        quotas: quotas(&l),
    };
    let r = h
        .sandbox
        .run(&spec, &CancelToken::new(), &mut || true)
        .unwrap();
    for f in [
        p.sources.engine,
        p.sources.config,
        p.sources.adapter,
        p.sources.candidate,
    ] {
        let _ = fs::remove_file(f);
    }
    r
}

fn stdout(r: &RawRun) -> String {
    String::from_utf8_lossy(&r.stdout).trim().to_owned()
}

fn small() -> Limits {
    Limits {
        cpu: 20,
        wall: 20,
        mem_mib: 256,
        storage_mib: 8,
        procs: 16,
        out: 65_536,
    }
}

#[test]
fn linux_self_check_records_real_verification() {
    let Some(h) = need("self_check") else { return };
    let v = &h.verification;
    assert_eq!(v.sandbox.code(), "bubblewrap");
    assert!(v.all_passed());
    assert!(v.host_listener_untouched);
    let ids: Vec<&str> = v.checks.iter().map(|c| c.id).collect();
    assert_eq!(ids, REQUIRED_CHECKS);
    assert!(v.probe_digest.starts_with("sha256:"));
    assert!(!v.launcher.is_empty());
    eprintln!(
        "ISOLATION-VERIFIED launcher={:?} platform={}",
        v.launcher, v.platform
    );
}

#[test]
fn linux_network_egress_is_denied_including_host_loopback() {
    let Some(h) = need("network") else { return };
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    let r = raw(h, &format!("net {port}"), small(), vec![]);
    assert_eq!(r.termination, Termination::Exited(0));
    assert_eq!(stdout(&r), "blocked");
    assert!(matches!(l.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn linux_host_files_are_not_reachable() {
    let Some(h) = need("host_files") else { return };
    let f = h.env.root.join("host-credential");
    fs::write(&f, b"SYNTHETIC-CANARY-HOST-CREDENTIAL").unwrap();
    for path in [
        f.to_string_lossy().into_owned(),
        "/etc/passwd".into(),
        "/root/.ssh/id_rsa".into(),
    ] {
        let r = raw(h, &format!("hostfile {path}"), small(), vec![]);
        assert_eq!(stdout(&r), "denied", "{path}");
    }
}

#[test]
fn linux_launcher_credentials_and_env_never_reach_the_worker() {
    let Some(h) = need("env") else { return };
    let canaries: Vec<(String, String)> = CANARY_ENV
        .iter()
        .map(|n| ((*n).to_owned(), "SYNTHETIC-CANARY-ENV".to_owned()))
        .collect();
    let r = raw(h, "env", small(), canaries);
    let out = stdout(&r);
    assert!(!out.is_empty());
    for name in out.split(',') {
        assert!(env_name_allowed(name), "unexpected env name {name}");
    }
    for c in CANARY_ENV {
        assert!(!out.contains(c), "{c} leaked");
    }
}

#[test]
fn linux_staged_artifacts_are_read_only_to_the_worker() {
    let Some(h) = need("readonly") else { return };
    let r = raw(h, "modify-stage", small(), vec![]);
    assert_eq!(stdout(&r), "denied");
}

#[test]
fn linux_fork_bomb_is_bounded_and_cleaned() {
    let Some(h) = need("fork") else { return };
    let token = format!("fork-token-{}", std::process::id());
    let r = raw(h, &format!("fork {token}"), small(), vec![]);
    let out = stdout(&r);
    let n: u32 = out
        .strip_prefix("spawned=")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("fork fixture did not report ({:?})", r.termination));
    assert!(n < 16, "process limit not enforced: spawned {n}");
    assert!(wait_gone(&token), "children survived the run");
}

#[test]
fn linux_memory_exhaustion_is_bounded() {
    let Some(h) = need("memory") else { return };
    let r = raw(
        h,
        "memory",
        Limits {
            mem_mib: 192,
            ..small()
        },
        vec![],
    );
    assert_ne!(stdout(&r), "alloc-ok", "allocated past the memory limit");
}

#[test]
fn linux_disk_exhaustion_is_bounded_to_the_scratch_quota() {
    let Some(h) = need("disk") else { return };
    let r = raw(h, "disk", small(), vec![]);
    // Either the tmpfs/file-size quota stopped the writes (the fixture reports
    // how much landed) or the file-size limit terminated it with a signal.
    match r.termination {
        Termination::Signaled(_) => {}
        Termination::Exited(0) => {
            let n: u64 = stdout(&r)
                .strip_prefix("written=")
                .unwrap()
                .parse()
                .unwrap();
            assert!(n <= 8 << 20, "wrote {n} bytes into an 8 MiB scratch");
        }
        t => panic!("unexpected termination {t:?}"),
    }
}

#[test]
fn linux_cpu_spin_is_stopped_by_the_cpu_limit() {
    let Some(h) = need("cpu") else { return };
    let r = raw(
        h,
        "spin",
        Limits {
            cpu: 1,
            wall: 20,
            ..small()
        },
        vec![],
    );
    assert!(
        matches!(r.termination, Termination::Signaled(_)),
        "{:?}",
        r.termination
    );
    assert!(r.elapsed < Duration::from_secs(15));
}

#[test]
fn linux_stdout_flood_is_bounded() {
    let Some(h) = need("stdout") else { return };
    let r = raw(h, "flood-stdout", small(), vec![]);
    assert_eq!(r.termination, Termination::OutputLimit);
    assert!(r.stdout.len() <= 65_536);
    assert!(r.elapsed < Duration::from_secs(15));
}

#[test]
fn linux_timeout_kills_the_whole_tree() {
    let Some(h) = need("timeout") else { return };
    let token = format!("tree-token-{}", std::process::id());
    let r = raw(
        h,
        &format!("tree {token}"),
        Limits { wall: 2, ..small() },
        vec![],
    );
    assert_eq!(r.termination, Termination::TimedOut);
    assert!(wait_gone(&token), "descendants survived the timeout");
}

fn dispatcher(h: &Host) -> Dispatcher {
    Dispatcher::new(h.sandbox.clone(), h.verification.clone(), h.env.config()).unwrap()
}

fn dispatch(
    h: &Host,
    domain: &str,
    tag: &str,
    mode: &str,
    roster: usize,
    cancel: &CancelToken,
) -> (O, R, bool) {
    let p = pinned(&h.env, tag, mode);
    let plan = plan(
        domain,
        &p,
        &Limits {
            wall: 20,
            ..Limits::normal()
        },
    );
    let lg = log();
    let rep = dispatcher(h)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, roster),
            cancel,
        )
        .unwrap();
    (rep.outcome, rep.reason, rep.result.is_some())
}

#[test]
fn linux_dispatch_maps_both_domains_and_failures_without_clean_crashes() {
    let Some(h) = need("dispatch") else { return };
    let none = CancelToken::new();
    for domain in ["credential", "pii"] {
        assert_eq!(
            dispatch(h, domain, "ok", "ok", 3, &none),
            (O::Success, R::Completed, true)
        );
        assert_eq!(
            dispatch(h, domain, "pa", "partial", 3, &none),
            (O::Partial, R::EnginePartial, true)
        );
        assert_eq!(
            dispatch(h, domain, "cr", "crash", 3, &none),
            (O::Failed, R::Signaled, false)
        );
        assert_eq!(
            dispatch(h, domain, "ex", "exit3", 3, &none),
            (O::Failed, R::NonZeroExit, false)
        );
        assert_eq!(
            dispatch(h, domain, "ga", "garbage", 3, &none),
            (O::Rejected, R::ResultMalformed, false)
        );
        assert_eq!(
            dispatch(h, domain, "wr", "wrong-roster", 3, &none),
            (O::Rejected, R::RosterMismatch, false)
        );
        assert_eq!(
            dispatch(h, domain, "uf", "unknown-field", 3, &none),
            (O::Rejected, R::ResultMalformed, false)
        );
        assert_eq!(
            dispatch(h, domain, "st", "stderr-secret", 3, &none),
            (O::Success, R::Completed, true)
        );
    }
    assert_eq!(h.env.staging_entries(), 0);
}

#[test]
fn linux_identity_tampering_fails_closed_under_the_real_sandbox() {
    let Some(h) = need("tamper") else { return };
    let p = pinned(&h.env, "tp", "ok");
    let plan = plan("credential", &p, &Limits::normal());
    fs::write(&p.sources.scanners[0], b"swapped scanner").unwrap();
    let lg = log();
    let rep = dispatcher(h)
        .run_attempt(
            &DispatchJob {
                plan: &plan,
                sources: &p.sources,
            },
            &RecLedger::new(&lg),
            &RecCorpus::new(&lg, &plan, 2),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(
        (rep.outcome, rep.reason),
        (O::Rejected, R::IdentityMismatch)
    );
    assert_eq!(events(&lg), vec!["ledger:fail_before_start:PlanMismatch"]);
}

#[test]
fn linux_cancellation_cleans_up_the_worker_tree() {
    let Some(h) = need("cancel") else { return };
    let token = format!("cancel-token-{}", std::process::id());
    let p = pinned(&h.env, "cn", &format!("tree {token}"));
    let plan = plan("pii", &p, &Limits::normal());
    let lg = log();
    let cancel = CancelToken::new();
    let c2 = cancel.clone();
    let tok = token.clone();
    let t = std::thread::spawn(move || {
        wait_running(&tok);
        c2.cancel();
    });
    let rep = dispatcher(h)
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
    assert!(wait_gone(&token));
}

#[test]
fn skipped_tests_are_reported_not_hidden() {
    // On hosts without isolation this test documents the skip policy in the
    // test output; it passes only because nothing was claimed.
    if let Err(why) = host() {
        eprintln!("ISOLATION-TESTS-NOT-RUN: {why} (CI sets CUSTODIAN_REQUIRE_ISOLATION=1)");
    }
}
