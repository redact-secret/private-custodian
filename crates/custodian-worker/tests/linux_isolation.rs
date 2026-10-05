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
use std::net::{SocketAddr, TcpListener, TcpStream};
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

/// S2 (ADR 0138), decision 2: DNS over UDP and TCP to well-known resolver
/// ports. A positive control (the same connect attempt run outside the
/// sandbox, from this test process) must succeed before the sandboxed
/// denial is asserted; if even the outside-sandbox attempt cannot connect
/// (a restricted CI network), the case is reported untested, never as a
/// passing or failing denial.
#[test]
fn linux_dns_resolver_ports_are_denied_with_a_working_positive_control() {
    let Some(h) = need("dns") else { return };
    let outside: bool = [([1u8, 1, 1, 1], 53u16), ([8, 8, 8, 8], 53)]
        .iter()
        .any(|(ip, port)| {
            TcpStream::connect_timeout(&SocketAddr::from((*ip, *port)), Duration::from_millis(800))
                .is_ok()
        });
    if !outside {
        eprintln!("PROBE-UNTESTED dns: positive control could not reach a public resolver from the CI host itself");
        return;
    }
    let r = raw(h, "dns", small(), vec![]);
    assert_eq!(stdout(&r), "blocked");
}

/// S2 (ADR 0138), decision 2: the exact link-local address ADR 0136 found
/// reachable (`169.254.169.254:80`) on the unsandboxed AWS diagnostic.
/// Positive control: GitHub-hosted runners run on cloud infrastructure that
/// commonly exposes its own metadata service on this same address, so the
/// outside-sandbox attempt is expected to succeed on CI; if it does not,
/// this is reported untested rather than asserted as a denial.
#[test]
fn linux_link_local_metadata_address_is_denied_with_a_working_positive_control() {
    let Some(h) = need("linklocal") else { return };
    let target = SocketAddr::from(([169, 254, 169, 254], 80));
    let outside = TcpStream::connect_timeout(&target, Duration::from_millis(800)).is_ok();
    if !outside {
        eprintln!("PROBE-UNTESTED linklocal: positive control could not reach 169.254.169.254:80 from the CI host itself");
        return;
    }
    let r = raw(h, "linklocal", small(), vec![]);
    assert_eq!(stdout(&r), "blocked");
}

/// S2 (ADR 0138), decision 2: IPv6. The loopback case is a positive control
/// that never depends on external routing (a listener this test binds on
/// `::1` itself); the public case is best-effort and reported untested if
/// the CI host has no IPv6 route, per issue #55's explicit acceptance rule
/// ("if an allowed IPv6 control cannot connect, mark IPv6 unverified rather
/// than denied").
#[test]
fn linux_ipv6_is_denied_or_explicitly_untested_never_silently_passed() {
    let Some(h) = need("ipv6") else { return };
    match TcpListener::bind("[::1]:0") {
        Ok(l) => {
            let port = l.local_addr().unwrap().port();
            let r = raw(h, &format!("ipv6loopback {port}"), small(), vec![]);
            assert_eq!(stdout(&r), "blocked", "IPv6 loopback positive control was reachable outside the sandbox but denial failed");
        }
        Err(e) => {
            eprintln!("PROBE-UNTESTED ipv6loopback: this host cannot bind an IPv6 loopback listener at all ({e})");
        }
    }
    let public: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
    if TcpStream::connect_timeout(&public, Duration::from_millis(800)).is_err() {
        eprintln!("PROBE-UNTESTED ipv6public: this CI host has no IPv6 route to a public address");
        return;
    }
    let r = raw(h, "ipv6public", small(), vec![]);
    assert_eq!(stdout(&r), "blocked");
}

/// S2 (ADR 0138), decision 2: inherited sockets. No descriptor beyond the
/// three explicitly redirected standard streams should be visible to the
/// payload; this counts them directly rather than relying on the
/// close-on-exec default being merely "relied upon."
#[test]
fn linux_no_extra_file_descriptor_is_inherited_by_the_payload() {
    let Some(h) = need("fdcount") else { return };
    let r = raw(h, "fdcount", small(), vec![]);
    let n: usize = stdout(&r).parse().unwrap_or(usize::MAX);
    assert_eq!(n, 3, "expected exactly stdin/stdout/stderr, counted {n}");
}

/// S2 (ADR 0138), decision 2: proxy and resolver environment variables must
/// be scrubbed the same way credential-shaped names are -- reuses the
/// existing "env" fixture mode and canary mechanism with a different name
/// list, so no new fixture behavior is introduced for this case.
#[test]
fn linux_proxy_and_resolver_environment_canaries_never_reach_the_worker() {
    let Some(h) = need("env") else { return };
    const PROXY_CANARY: &[&str] = &[
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "RES_OPTIONS",
        "HOSTALIASES",
    ];
    let canaries: Vec<(String, String)> = PROXY_CANARY
        .iter()
        .map(|n| ((*n).to_owned(), "SYNTHETIC-CANARY-PROXY".to_owned()))
        .collect();
    let r = raw(h, "env", small(), canaries);
    let out = stdout(&r);
    for name in PROXY_CANARY {
        assert!(
            !out.split(',').any(|n| n == *name),
            "{name} reached the worker environment"
        );
    }
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

/// S3 (ADR 0139), decision 2 (Filesystem): a symlink created inside the one
/// writable directory and pointing at a host path outside the sandbox must
/// not grant a new way to read that path -- the mount namespace denies the
/// target regardless of how the child tries to reach it.
#[test]
fn linux_symlink_inside_scratch_cannot_escape_to_a_host_path() {
    let Some(h) = need("symlink-escape") else {
        return;
    };
    let f = h.env.root.join("host-credential");
    fs::write(&f, b"SYNTHETIC-CANARY-HOST-CREDENTIAL").unwrap();
    let r = raw(
        h,
        &format!("symlink-escape {}", f.display()),
        small(),
        vec![],
    );
    assert_eq!(stdout(&r), "denied");
}

/// S3 (ADR 0139), decision 2 (Filesystem): a hardlink from the writable
/// scratch tmpfs to a file on the read-only staged mount must fail with a
/// cross-device error -- the separate mount itself is the boundary, not a
/// permission bit a privileged-enough caller could bypass.
#[test]
fn linux_hardlink_cannot_cross_from_scratch_to_a_staged_mount() {
    let Some(h) = need("hardlink-escape") else {
        return;
    };
    let r = raw(h, "hardlink-escape", small(), vec![]);
    assert_eq!(stdout(&r), "denied");
}

/// S3 (ADR 0139), decision 2 (Privilege): supplementary groups are an
/// explicit open risk ADR 0137 flagged as "not yet a positive control."
/// This records the count directly rather than silently assuming zero;
/// a nonzero count is reported as a finding, not hidden by the assertion
/// passing anyway.
#[test]
fn linux_supplementary_groups_are_recorded_not_assumed() {
    let Some(h) = need("groups") else { return };
    let r = raw(h, "groups", small(), vec![]);
    let n: usize = stdout(&r).parse().unwrap_or(usize::MAX);
    eprintln!("PROBE-RESULT groups: supplementary_group_count={n}");
    assert_ne!(
        n,
        usize::MAX,
        "groups probe did not report a parseable count at all"
    );
}

// The forged-attestation case lives inside
// linux_dispatch_maps_both_domains_and_failures_without_clean_crashes below,
// next to the structurally identical unknown-field case, rather than as a
// separate test -- see that function.

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
        // S3 (ADR 0139): a hostile engine printing a verification/attestation
        // -shaped claim on its result document, distinct from the generic
        // unknown-field case above -- the strict parser rejects it the same
        // way, which is the concrete answer to "forged completion or
        // isolation attestation" in issue #56's attack-category matrix.
        assert_eq!(
            dispatch(h, domain, "fa", "forged-attestation", 3, &none),
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
