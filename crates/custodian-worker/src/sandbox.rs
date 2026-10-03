//! The sandbox boundary as a trait, the spec handed to it, and the shared
//! supervision loop (wall clock, bounded output, cancellation, tree kill).
//!
//! A `Sandbox` either applies real isolation or refuses. There is no mode in
//! which a candidate runs unsandboxed in a product build: the only
//! non-isolating implementation is `fake::TestOnlyUnsandboxedFake`, which
//! exists only with the `test-fakes` feature.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::reason::{Result, WorkerReason as R};

/// Environment variable names a worker may receive. Everything else is
/// cleared. Names that look like credentials are refused even if someone adds
/// them to this list (`env_name_allowed`).
pub const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    // Set by the launcher itself when it changes directory; not a secret.
    "PWD",
    "TMPDIR",
    "LANG",
    "CUSTODIAN_STAGE_ROOT",
    "CUSTODIAN_INPUT_ROOT",
    "CUSTODIAN_JOB_ROOT",
    "CUSTODIAN_SCRATCH",
];

const DENY_FRAGMENTS: &[&str] = &[
    "TOKEN", "SECRET", "KEY", "PASS", "CRED", "LEDGER", "SIGN", "DATABASE", "DB_", "APP_", "AWS",
    "GITHUB", "SSH",
];

pub fn env_name_allowed(name: &str) -> bool {
    ENV_ALLOWLIST.contains(&name)
        && !DENY_FRAGMENTS
            .iter()
            .any(|d| name.to_ascii_uppercase().contains(d))
}

/// Explicit quotas for one run. All come from the approved plan's
/// `ResourceLimits`, narrowed by operator caps in `DispatcherConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quotas {
    pub cpu_seconds: u64,
    pub wall: Duration,
    pub memory_bytes: u64,
    /// Size of the writable scratch (tmpfs) and the largest single file.
    pub storage_bytes: u64,
    pub max_processes: u64,
    /// Bound on stdout (the result channel).
    pub stdout_bytes: u64,
    /// Bound on stderr, which is counted and discarded, never retained.
    pub stderr_bytes: u64,
}

/// A host directory shown read-only at `inner` inside the sandbox.
#[derive(Clone, Debug)]
pub struct RoMount {
    pub host: PathBuf,
    pub inner: String,
}

#[derive(Clone, Debug)]
pub struct SandboxSpec {
    /// Absolute path inside the sandbox.
    pub program: String,
    pub args: Vec<String>,
    pub ro_mounts: Vec<RoMount>,
    /// Allowlisted environment (`ENV_ALLOWLIST`) given to the payload.
    pub env: Vec<(String, String)>,
    /// Environment given to the *launcher* that the sandbox must strip. Used
    /// only by the isolation self-check to prove the scrub works.
    pub launcher_env_canaries: Vec<(String, String)>,
    pub quotas: Quotas,
}

impl SandboxSpec {
    pub fn validate(&self) -> Result<()> {
        if !self.program.starts_with('/') || self.program.contains('\0') {
            return Err(R::PathRejected);
        }
        for m in &self.ro_mounts {
            if !m.inner.starts_with('/') || m.inner.contains("..") || m.inner.contains('\0') {
                return Err(R::PathRejected);
            }
            if !m.host.is_absolute() {
                return Err(R::PathRejected);
            }
        }
        for (k, v) in &self.env {
            if !env_name_allowed(k) || v.contains('\0') {
                return Err(R::PathRejected);
            }
        }
        let q = &self.quotas;
        if q.cpu_seconds == 0
            || q.wall.is_zero()
            || q.memory_bytes == 0
            || q.storage_bytes == 0
            || q.max_processes == 0
            || q.stdout_bytes == 0
            || q.stderr_bytes == 0
        {
            return Err(R::PlanInconsistent);
        }
        Ok(())
    }
}

/// How a sandboxed run ended. Only `Exited(0)` can ever lead to a clean
/// outcome; every other variant is a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    Signaled(i32),
    TimedOut,
    Cancelled,
    /// The lease was fenced (cancel or recovery) while running.
    Fenced,
    OutputLimit,
}

/// What a run produced. `stdout` is untrusted and bounded by `stdout_bytes`;
/// stderr is never retained.
pub struct RawRun {
    pub termination: Termination,
    pub stdout: Vec<u8>,
    pub stderr_bytes: u64,
    pub elapsed: Duration,
}

impl core::fmt::Debug for RawRun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawRun")
            .field("termination", &self.termination)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_bytes", &self.stderr_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SandboxKind {
    Bubblewrap,
    Refusing,
    TestOnlyUnsandboxedFake,
}

impl SandboxKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bubblewrap",
            Self::Refusing => "refusing",
            Self::TestOnlyUnsandboxedFake => "test_only_unsandboxed_fake",
        }
    }
}

/// Cooperative cancellation shared with the supervisor.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub trait Sandbox: Send + Sync {
    fn kind(&self) -> SandboxKind;

    /// Run the spec inside the boundary. `keepalive` is called about every
    /// 200 ms; returning `false` means the lease was lost and the run must be
    /// terminated. Must never run the program outside the boundary: if the
    /// boundary cannot be applied, return an error.
    fn run(
        &self,
        spec: &SandboxSpec,
        cancel: &CancelToken,
        keepalive: &mut dyn FnMut() -> bool,
    ) -> Result<RawRun>;
}

/// Spawn-side helper shared by backends: pipes, own process group.
pub(crate) fn prepare_command(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
}

/// Kill the whole process group of `pid` (the child leads its own group).
/// `kill` is the system utility; the crate forbids `unsafe`, so there is no
/// direct syscall. Failure is not an error: the sandbox's PID namespace is
/// the primary tree cleanup, this is a second line.
fn kill_group(pid: u32) {
    for bin in ["/bin/kill", "/usr/bin/kill"] {
        if std::path::Path::new(bin).exists() {
            let _ = Command::new(bin)
                .args(["-KILL", "--"])
                .arg(format!("-{pid}"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            return;
        }
    }
}

enum Drained {
    Stdout(Vec<u8>),
    Stderr(u64),
}

/// Supervise a spawned child to completion under the quotas. Reads stdout up
/// to its bound (one byte more trips `OutputLimit`), counts and discards
/// stderr, enforces the wall clock, honors cancellation and the keepalive,
/// and always kills the process group and reaps before returning.
pub(crate) fn supervise(
    mut child: Child,
    quotas: &Quotas,
    cancel: &CancelToken,
    keepalive: &mut dyn FnMut() -> bool,
) -> Result<RawRun> {
    let start = Instant::now();
    let pid = child.id();
    let over = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Drained>();

    let mut out = child.stdout.take().ok_or(R::SpawnFailed)?;
    let mut err = child.stderr.take().ok_or(R::SpawnFailed)?;
    let (cap_out, cap_err) = (quotas.stdout_bytes, quotas.stderr_bytes);
    {
        let (tx, over) = (tx.clone(), over.clone());
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match out.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if (buf.len() + n) as u64 > cap_out {
                            over.store(true, Ordering::SeqCst);
                            buf.clear();
                            // Keep draining so the child is not blocked
                            // while the supervisor kills it.
                            continue;
                        }
                        if !over.load(Ordering::SeqCst) {
                            buf.extend_from_slice(&chunk[..n]);
                        }
                    }
                }
            }
            let _ = tx.send(Drained::Stdout(buf));
        });
    }
    {
        let (tx, over) = (tx, over.clone());
        std::thread::spawn(move || {
            let mut total = 0u64;
            let mut chunk = [0u8; 8192];
            loop {
                match err.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total += n as u64;
                        if total > cap_err {
                            over.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
            let _ = tx.send(Drained::Stderr(total));
        });
    }

    let mut last_keepalive = Instant::now();
    let mut termination: Option<Termination> = None;
    let mut status = None;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                break;
            }
            Ok(None) => {}
            Err(_) => {
                termination = Some(Termination::Signaled(9));
                break;
            }
        }
        if cancel.is_cancelled() {
            termination = Some(Termination::Cancelled);
        } else if over.load(Ordering::SeqCst) {
            termination = Some(Termination::OutputLimit);
        } else if start.elapsed() >= quotas.wall {
            termination = Some(Termination::TimedOut);
        } else if last_keepalive.elapsed() >= Duration::from_millis(200) {
            last_keepalive = Instant::now();
            if !keepalive() {
                termination = Some(Termination::Fenced);
            }
        }
        if termination.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Always tear down the tree, even after a normal exit: a daemonized
    // grandchild must not outlive the run.
    kill_group(pid);
    if status.is_none() {
        let _ = child.kill();
    }
    let final_status = match status {
        Some(s) => Some(s),
        None => child.wait().ok(),
    };

    let mut stdout = Vec::new();
    let mut stderr_bytes = 0u64;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = 0;
    while got < 2 {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Drained::Stdout(b)) => {
                stdout = b;
                got += 1;
            }
            Ok(Drained::Stderr(n)) => {
                stderr_bytes = n;
                got += 1;
            }
            Err(_) => return Err(R::SandboxFailure),
        }
    }
    if over.load(Ordering::SeqCst) && termination.is_none() {
        termination = Some(Termination::OutputLimit);
    }

    let termination = match termination {
        Some(t) => t,
        None => {
            use std::os::unix::process::ExitStatusExt;
            match final_status {
                Some(s) => match (s.code(), s.signal()) {
                    (Some(c), _) => Termination::Exited(c),
                    (None, Some(sig)) => Termination::Signaled(sig),
                    _ => Termination::Signaled(9),
                },
                None => Termination::Signaled(9),
            }
        }
    };
    Ok(RawRun {
        termination,
        stdout,
        stderr_bytes,
        elapsed: start.elapsed(),
    })
}
