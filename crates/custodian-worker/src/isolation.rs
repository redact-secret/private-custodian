//! The startup isolation self-check and its verification record.
//!
//! A `Dispatcher` cannot be built without an `IsolationVerification`, and the
//! only constructor of a `Verified` one is `run_self_check`, which runs the
//! probe binary inside the very sandbox that will run engines and requires
//! every check to pass, including positive controls. A descriptive flag,
//! a config file or the presence of a container proves nothing here.

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::artifacts::{hash_file, ArtifactAllowlist, Staging};
use crate::reason::WorkerReason as R;
use crate::sandbox::{
    CancelToken, Quotas, RoMount, Sandbox, SandboxKind, SandboxSpec, Termination,
};

/// Checks the probe must report, in order. Missing, extra or failed lines
/// fail the self-check.
pub const REQUIRED_CHECKS: &[&str] = &[
    "egress_denied",
    "host_files_absent",
    "env_scrubbed",
    "write_outside_scratch_denied",
    "scratch_writable",
    "pid_namespace",
    "no_capabilities",
    "rlimits_applied",
];

/// Names set in the launcher environment that must never reach a payload.
pub const CANARY_ENV: &[&str] = &[
    "CUSTODIAN_LEDGER_SIGNING_KEY",
    "CUSTODIAN_APP_PRIVATE_KEY",
    "CUSTODIAN_DB_ADMIN_URL",
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
];

const CANARY_FILE_BODY: &[u8] = b"SYNTHETIC-CANARY-HOST-CREDENTIAL-NOT-A-SECRET";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grade {
    /// Every check passed in a real sandbox.
    Verified,
    /// The unsandboxed fake. Accepted only by `Dispatcher::new_for_tests`.
    #[cfg(feature = "test-fakes")]
    TestOnlyNotIsolated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRecord {
    pub id: &'static str,
    pub passed: bool,
}

/// What was verified, on what, and when. Fields are read-only evidence; the
/// struct cannot be constructed outside this module.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IsolationVerification {
    pub sandbox: SandboxKind,
    pub grade: Grade,
    pub checks: Vec<CheckRecord>,
    /// The host-side listener saw no connection from the probe.
    pub host_listener_untouched: bool,
    pub probe_digest: String,
    pub launcher: String,
    pub platform: String,
    pub verified_at: u64,
}

impl IsolationVerification {
    pub fn all_passed(&self) -> bool {
        self.checks.len() == REQUIRED_CHECKS.len()
            && self.checks.iter().all(|c| c.passed)
            && self.host_listener_untouched
    }

    /// Record for the unsandboxed fake. Carries no checks and cannot pass
    /// `all_passed`; `Dispatcher::new_for_tests` is its only consumer.
    #[cfg(feature = "test-fakes")]
    pub fn test_only_not_isolated(now: u64) -> Self {
        Self {
            sandbox: SandboxKind::TestOnlyUnsandboxedFake,
            grade: Grade::TestOnlyNotIsolated,
            checks: Vec::new(),
            host_listener_untouched: false,
            probe_digest: String::new(),
            launcher: String::new(),
            platform: platform(),
            verified_at: now,
        }
    }
}

fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn parse_probe_output(stdout: &[u8]) -> Option<Vec<CheckRecord>> {
    let text = std::str::from_utf8(stdout).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let (verdict, id) = line.split_once(' ')?;
        let passed = match verdict {
            "PASS" => true,
            "FAIL" => false,
            _ => return None,
        };
        let id = REQUIRED_CHECKS.iter().find(|c| **c == id)?;
        out.push(CheckRecord { id, passed });
    }
    // Exactly the required checks, once each, in order.
    let ids: Vec<&str> = out.iter().map(|c| c.id).collect();
    (ids == REQUIRED_CHECKS).then_some(out)
}

/// Why a self-check failed: a fixed reason plus the fixed ids of the checks
/// that did not pass. Safe to log; carries no probe output beyond those ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfCheckError {
    pub reason: R,
    pub failed_checks: Vec<&'static str>,
    /// How the probe ended, when it ran at all (fixed vocabulary).
    pub probe_ended: Option<String>,
}

impl From<R> for SelfCheckError {
    fn from(reason: R) -> Self {
        Self {
            reason,
            failed_checks: Vec::new(),
            probe_ended: None,
        }
    }
}

impl core::fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} failed_checks={:?}", self.reason, self.failed_checks)?;
        if let Some(e) = &self.probe_ended {
            write!(f, " probe_ended={e}")?;
        }
        Ok(())
    }
}

/// Run the probe inside `sandbox` and return a verification record, or the
/// reason isolation could not be shown. `work_base` is a private (0700)
/// directory for staging and the canary file. The record is evidence for the
/// host it ran on, at the time it ran.
pub fn run_self_check(
    sandbox: &dyn Sandbox,
    launcher_version: &str,
    probe: &Path,
    allowlist: &ArtifactAllowlist,
    work_base: &Path,
    now: u64,
) -> core::result::Result<IsolationVerification, SelfCheckError> {
    if sandbox.kind() == SandboxKind::Refusing {
        return Err(R::UnsupportedPlatform.into());
    }
    if sandbox.kind() == SandboxKind::TestOnlyUnsandboxedFake {
        return Err(R::IsolationNotVerified.into());
    }
    let probe = allowlist.resolve(probe)?;
    let probe_digest = hash_file(&probe)?;
    let mut staging = Staging::create(work_base)?;
    staging.stage_pinned("probe", &probe, &probe_digest, true)?;

    // A host file the sandbox must not be able to read.
    let canary_dir = work_base.join(format!("canary-{}", std::process::id()));
    let _ = fs::remove_dir_all(&canary_dir);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&canary_dir)
        .map_err(|_| R::StagingFailed)?;
    let canary_file: PathBuf = canary_dir.join("host-credential");
    fs::write(&canary_file, CANARY_FILE_BODY).map_err(|_| R::StagingFailed)?;
    fs::set_permissions(&canary_file, fs::Permissions::from_mode(0o600))
        .map_err(|_| R::StagingFailed)?;

    // A host loopback listener the sandbox must not reach.
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| R::IsolationCheckFailed)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| R::IsolationCheckFailed)?;
    let port = listener
        .local_addr()
        .map_err(|_| R::IsolationCheckFailed)?
        .port();

    const NPROC: u64 = 64;
    const AS: u64 = 512 * 1024 * 1024;
    const CPU: u64 = 10;
    let quotas = Quotas {
        cpu_seconds: CPU,
        wall: Duration::from_secs(30),
        memory_bytes: AS,
        storage_bytes: 8 * 1024 * 1024,
        max_processes: NPROC,
        stdout_bytes: 4096,
        stderr_bytes: 64 * 1024,
    };
    let canary_names = CANARY_ENV.join(",");
    let spec = SandboxSpec {
        program: "/stage/probe".into(),
        args: vec![
            "--canary-file".into(),
            canary_file.to_string_lossy().into_owned(),
            "--canary-env".into(),
            canary_names,
            "--port".into(),
            port.to_string(),
            "--nproc".into(),
            NPROC.to_string(),
            "--as".into(),
            AS.to_string(),
            "--cpu".into(),
            CPU.to_string(),
        ],
        ro_mounts: vec![
            RoMount {
                host: staging.stage_dir(),
                inner: "/stage".into(),
            },
            RoMount {
                host: staging.input_dir(),
                inner: "/input".into(),
            },
        ],
        env: vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/scratch".into()),
            ("TMPDIR".into(), "/scratch".into()),
            ("LANG".into(), "C".into()),
        ],
        launcher_env_canaries: CANARY_ENV
            .iter()
            .map(|n| {
                (
                    (*n).to_owned(),
                    "SYNTHETIC-CANARY-ENV-NOT-A-SECRET".to_owned(),
                )
            })
            .collect(),
        quotas,
    };
    let cancel = CancelToken::new();
    let run = sandbox.run(&spec, &cancel, &mut || true);
    let untouched = matches!(
        listener.accept(),
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
    );
    let _ = fs::remove_dir_all(&canary_dir);
    let run = run?;
    staging.verify(R::IdentityChangedAfterStaging)?;

    if run.termination != Termination::Exited(0) {
        return Err(SelfCheckError {
            reason: R::IsolationCheckFailed,
            failed_checks: Vec::new(),
            probe_ended: Some(format!("{:?}", run.termination)),
        });
    }
    let checks = parse_probe_output(&run.stdout).ok_or(SelfCheckError {
        reason: R::IsolationCheckFailed,
        failed_checks: Vec::new(),
        probe_ended: Some("unparseable_output".into()),
    })?;
    let v = IsolationVerification {
        sandbox: sandbox.kind(),
        grade: Grade::Verified,
        checks,
        host_listener_untouched: untouched,
        probe_digest,
        launcher: launcher_version.to_owned(),
        platform: platform(),
        verified_at: now,
    };
    if v.all_passed() {
        Ok(v)
    } else {
        let mut failed: Vec<&'static str> = v
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.id)
            .collect();
        if !v.host_listener_untouched {
            failed.push("host_listener_untouched");
        }
        Err(SelfCheckError {
            reason: R::IsolationCheckFailed,
            failed_checks: failed,
            probe_ended: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_output_must_be_exactly_the_required_checks() {
        let good: String = REQUIRED_CHECKS
            .iter()
            .map(|c| format!("PASS {c}\n"))
            .collect();
        assert!(parse_probe_output(good.as_bytes()).is_some());
        assert!(parse_probe_output(b"").is_none());
        assert!(parse_probe_output(b"PASS egress_denied\n").is_none());
        assert!(parse_probe_output(format!("{good}PASS extra\n").as_bytes()).is_none());
        assert!(parse_probe_output(format!("{good}PASS egress_denied\n").as_bytes()).is_none());
        assert!(parse_probe_output(b"MAYBE egress_denied\n").is_none());
        let failed = good.replacen("PASS egress_denied", "FAIL egress_denied", 1);
        let recs = parse_probe_output(failed.as_bytes()).unwrap();
        assert!(!recs[0].passed);
    }
}
