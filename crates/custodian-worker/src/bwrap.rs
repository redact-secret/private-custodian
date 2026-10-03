//! Linux backend: bubblewrap (`bwrap`) for namespaces and mounts, `prlimit`
//! for resource limits, structured argv only (ADR 0041).
//!
//! What this backend asks the kernel for:
//! - new user, IPC, PID, network, UTS and cgroup namespaces; the network
//!   namespace has no interface up, so there is no egress and no route to the
//!   host's loopback;
//! - a fresh tmpfs root remounted read-only, with only `/usr`, `/lib*`,
//!   `/bin`, `/sbin` (system libraries), the staged read-only mounts and a
//!   size-capped tmpfs scratch;
//! - no capabilities, a new session, `--die-with-parent`, a cleared
//!   environment plus the validated allowlist;
//! - rlimits (CPU, address space, processes, file size, no core dumps) applied
//!   by `prlimit` from inside the new namespaces.
//!
//! What it does not do: install a seccomp filter, use cgroup controllers, or
//! prove anything by itself. `isolation::run_self_check` is the evidence, and
//! the host must pass it. See docs/worker-isolation.md.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::reason::{Result, WorkerReason as R};
use crate::sandbox::{
    prepare_command, supervise, CancelToken, RawRun, Sandbox, SandboxKind, SandboxSpec, Termination,
};

/// Fixed install locations. The launcher is never found through `PATH`.
const BWRAP_LOCATIONS: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
/// `prlimit` as seen inside the sandbox (from the read-only `/usr`).
const PRLIMIT_INNER: &str = "/usr/bin/prlimit";
/// Directories that provide the dynamic loader and libraries.
const SYSTEM_ROOTS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemRoot {
    Bind(String),
    Symlink { path: String, target: String },
}

#[derive(Clone, Debug)]
pub struct BubblewrapSandbox {
    bwrap: PathBuf,
    roots: Vec<SystemRoot>,
}

impl BubblewrapSandbox {
    /// Locate `bwrap` and the system roots on this host. Fails with
    /// `UnsupportedPlatform` off Linux and `IsolationUnavailable` when the
    /// launcher or `prlimit` is missing. Success is not evidence of
    /// isolation; only the self-check is.
    pub fn detect() -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(R::UnsupportedPlatform);
        }
        let bwrap = BWRAP_LOCATIONS
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or(R::IsolationUnavailable)?;
        if !PathBuf::from(PRLIMIT_INNER).is_file() {
            return Err(R::IsolationUnavailable);
        }
        let mut roots = Vec::new();
        for r in SYSTEM_ROOTS {
            match fs::symlink_metadata(r) {
                Ok(m) if m.file_type().is_symlink() => {
                    let t = fs::read_link(r).map_err(|_| R::IsolationUnavailable)?;
                    roots.push(SystemRoot::Symlink {
                        path: (*r).to_owned(),
                        target: t.to_string_lossy().into_owned(),
                    });
                }
                Ok(m) if m.is_dir() => roots.push(SystemRoot::Bind((*r).to_owned())),
                _ => {}
            }
        }
        if !roots
            .iter()
            .any(|r| matches!(r, SystemRoot::Bind(p) if p == "/usr"))
        {
            return Err(R::IsolationUnavailable);
        }
        Ok(Self { bwrap, roots })
    }

    /// Build from explicit parts without touching the host. Used by argv unit
    /// tests; `run` still refuses off Linux.
    pub fn from_parts(bwrap: PathBuf, roots: Vec<SystemRoot>) -> Self {
        Self { bwrap, roots }
    }

    /// First line of `bwrap --version`, for the verification record.
    pub fn launcher_version(&self) -> String {
        Command::new(&self.bwrap)
            .arg("--version")
            .env_clear()
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| {
                s.lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .take(64)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The complete launcher argument vector. Pure; no shell is involved.
    pub fn build_argv(&self, spec: &SandboxSpec) -> Result<Vec<OsString>> {
        spec.validate()?;
        let q = &spec.quotas;
        let mut a: Vec<OsString> = Vec::new();
        for f in [
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--cap-drop",
            "ALL",
            "--clearenv",
        ] {
            push(&mut a, f);
        }
        for r in &self.roots {
            match r {
                SystemRoot::Bind(p) => {
                    push(&mut a, "--ro-bind");
                    push(&mut a, p);
                    push(&mut a, p);
                }
                SystemRoot::Symlink { path, target } => {
                    push(&mut a, "--symlink");
                    push(&mut a, target);
                    push(&mut a, path);
                }
            }
        }
        push(&mut a, "--proc");
        push(&mut a, "/proc");
        push(&mut a, "--dev");
        push(&mut a, "/dev");
        push(&mut a, "--size");
        push(&mut a, q.storage_bytes.to_string());
        push(&mut a, "--tmpfs");
        push(&mut a, "/scratch");
        for m in &spec.ro_mounts {
            push(&mut a, "--ro-bind");
            push(&mut a, &m.host);
            push(&mut a, &m.inner);
        }
        push(&mut a, "--remount-ro");
        push(&mut a, "/");
        push(&mut a, "--chdir");
        push(&mut a, "/scratch");
        for (k, v) in &spec.env {
            push(&mut a, "--setenv");
            push(&mut a, k);
            push(&mut a, v);
        }
        push(&mut a, "--");
        push(&mut a, PRLIMIT_INNER);
        push(&mut a, format!("--cpu={}", q.cpu_seconds));
        push(&mut a, format!("--as={}", q.memory_bytes));
        push(&mut a, format!("--nproc={}", q.max_processes));
        push(&mut a, format!("--fsize={}", q.storage_bytes));
        push(&mut a, "--core=0");
        push(&mut a, "--nofile=256");
        push(&mut a, "--");
        push(&mut a, &spec.program);
        for x in &spec.args {
            push(&mut a, x);
        }
        Ok(a)
    }
}

fn push(a: &mut Vec<OsString>, s: impl AsRef<std::ffi::OsStr>) {
    a.push(s.as_ref().to_owned());
}

impl Sandbox for BubblewrapSandbox {
    fn kind(&self) -> SandboxKind {
        SandboxKind::Bubblewrap
    }

    fn run(
        &self,
        spec: &SandboxSpec,
        cancel: &CancelToken,
        keepalive: &mut dyn FnMut() -> bool,
    ) -> Result<RawRun> {
        if !cfg!(target_os = "linux") {
            return Err(R::UnsupportedPlatform);
        }
        let argv = self.build_argv(spec)?;
        let mut cmd = Command::new(&self.bwrap);
        cmd.env_clear().args(&argv);
        // Only the self-check sets these: they must not reach the payload.
        for (k, v) in &spec.launcher_env_canaries {
            cmd.env(k, v);
        }
        prepare_command(&mut cmd);
        let child = cmd.spawn().map_err(|_| R::SpawnFailed)?;
        let mut run = supervise(child, &spec.quotas, cancel, keepalive)?;
        // bwrap reports a signaled payload as exit status 128 + signal. A
        // payload that exits with such a code is treated the same way: never
        // clean either way, and the distinction only picks the reason code.
        if let Termination::Exited(c) = run.termination {
            if (129..=192).contains(&c) {
                run.termination = Termination::Signaled(c - 128);
            }
        }
        Ok(run)
    }
}
