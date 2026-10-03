//! The bubblewrap argument vector is structured and complete. Pure: no
//! process is started, so this runs everywhere. It checks what we ask the
//! launcher for; whether the kernel delivers it is the self-check's job.

use std::path::PathBuf;
use std::time::Duration;

use custodian_worker::bwrap::{BubblewrapSandbox, SystemRoot};
use custodian_worker::sandbox::{Quotas, RoMount, SandboxSpec};
use custodian_worker::WorkerReason;

fn sandbox() -> BubblewrapSandbox {
    BubblewrapSandbox::from_parts(
        PathBuf::from("/usr/bin/bwrap"),
        vec![
            SystemRoot::Bind("/usr".into()),
            SystemRoot::Symlink {
                path: "/lib".into(),
                target: "usr/lib".into(),
            },
        ],
    )
}

fn spec() -> SandboxSpec {
    SandboxSpec {
        program: "/stage/engine".into(),
        args: vec!["--job".into(), "/job/job.json; rm -rf /".into()],
        ro_mounts: vec![RoMount {
            host: "/tmp/run-1/stage".into(),
            inner: "/stage".into(),
        }],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        launcher_env_canaries: vec![],
        quotas: Quotas {
            cpu_seconds: 7,
            wall: Duration::from_secs(9),
            memory_bytes: 123_456_789,
            storage_bytes: 8_388_608,
            max_processes: 11,
            stdout_bytes: 100,
            stderr_bytes: 100,
        },
    }
}

fn argv(s: &SandboxSpec) -> Vec<String> {
    sandbox()
        .build_argv(s)
        .unwrap()
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

fn has_seq(a: &[String], seq: &[&str]) -> bool {
    a.windows(seq.len())
        .any(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
}

#[test]
fn isolation_flags_are_all_present() {
    let a = argv(&spec());
    for f in [
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--clearenv",
    ] {
        assert!(a.iter().any(|x| x == f), "missing {f}");
    }
    assert!(has_seq(&a, &["--cap-drop", "ALL"]));
    assert!(has_seq(&a, &["--remount-ro", "/"]));
    // Network is never shared back in.
    assert!(!a.iter().any(|x| x == "--share-net" || x == "--unshare-all"));
    // The only writable place is the size-capped scratch tmpfs.
    assert!(has_seq(&a, &["--size", "8388608", "--tmpfs", "/scratch"]));
    assert!(!a
        .iter()
        .any(|x| x == "--bind" || x == "--bind-try" || x == "--dev-bind"));
}

#[test]
fn mounts_are_read_only_and_system_roots_are_explicit() {
    let a = argv(&spec());
    assert!(has_seq(&a, &["--ro-bind", "/usr", "/usr"]));
    assert!(has_seq(&a, &["--symlink", "usr/lib", "/lib"]));
    assert!(has_seq(&a, &["--ro-bind", "/tmp/run-1/stage", "/stage"]));
    // The host home, /etc, /var and /root are never bound.
    for p in ["/home", "/etc", "/var", "/root", "/run"] {
        assert!(!a.iter().any(|x| x == p), "{p} must not be mounted");
    }
}

#[test]
fn rlimits_wrap_the_payload_inside_the_sandbox() {
    let a = argv(&spec());
    let i = a.iter().position(|x| x == "/usr/bin/prlimit").unwrap();
    assert_eq!(a[i - 1], "--");
    for want in [
        "--cpu=7",
        "--as=123456789",
        "--nproc=11",
        "--fsize=8388608",
        "--core=0",
    ] {
        assert!(a[i..].iter().any(|x| x == want), "missing {want}");
    }
    // The payload is the tail, one argv element per argument, unparsed by a shell.
    assert_eq!(
        &a[a.len() - 3..],
        ["/stage/engine", "--job", "/job/job.json; rm -rf /"]
    );
}

#[test]
fn environment_is_cleared_then_allowlisted() {
    let a = argv(&spec());
    let clear = a.iter().position(|x| x == "--clearenv").unwrap();
    let set = a.iter().position(|x| x == "--setenv").unwrap();
    assert!(clear < set);
    assert!(has_seq(&a, &["--setenv", "PATH", "/usr/bin:/bin"]));
    let mut bad = spec();
    bad.env.push(("GITHUB_TOKEN".into(), "x".into()));
    assert_eq!(
        sandbox().build_argv(&bad).err(),
        Some(WorkerReason::PathRejected)
    );
}

#[test]
fn malformed_specs_are_refused() {
    let mut s = spec();
    s.program = "relative/engine".into();
    assert!(sandbox().build_argv(&s).is_err());
    let mut s = spec();
    s.ro_mounts[0].inner = "/stage/../etc".into();
    assert!(sandbox().build_argv(&s).is_err());
    let mut s = spec();
    s.quotas.max_processes = 0;
    assert!(sandbox().build_argv(&s).is_err());
}

#[test]
fn off_linux_the_backend_refuses_to_run() {
    if cfg!(target_os = "linux") {
        return;
    }
    assert_eq!(
        BubblewrapSandbox::detect().err(),
        Some(WorkerReason::UnsupportedPlatform)
    );
    use custodian_worker::sandbox::{CancelToken, Sandbox};
    let r = sandbox().run(&spec(), &CancelToken::new(), &mut || true);
    assert_eq!(r.err(), Some(WorkerReason::UnsupportedPlatform));
}
