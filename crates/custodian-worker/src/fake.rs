//! TEST ONLY. `TestOnlyUnsandboxedFake` runs the program as an ordinary child
//! process with a scrubbed environment and NO isolation: no namespaces, no
//! filesystem restriction, no network denial, no resource limits other than
//! the supervisor's wall clock, output bounds and process-group kill.
//!
//! It exists so dispatcher logic (ordering, identity checks, result
//! validation, outcome mapping, ledger and corpus integration) can be tested
//! on any developer machine. It is compiled only with the `test-fakes`
//! feature, it reports `SandboxKind::TestOnlyUnsandboxedFake`, and a
//! `Dispatcher` accepts it only together with a verification that is itself
//! marked test-only. Tests using it prove nothing about isolation.

use std::process::Command;

use crate::reason::{Result, WorkerReason as R};
use crate::sandbox::{
    prepare_command, supervise, CancelToken, RawRun, Sandbox, SandboxKind, SandboxSpec,
};

#[derive(Debug)]
pub struct TestOnlyUnsandboxedFake {
    scratch: std::path::PathBuf,
}

impl TestOnlyUnsandboxedFake {
    /// `scratch` stands in for the sandbox's `/scratch`.
    pub fn new_not_isolated(scratch: std::path::PathBuf) -> Self {
        Self { scratch }
    }

    fn map(&self, spec: &SandboxSpec, s: &str) -> String {
        for m in &spec.ro_mounts {
            if s == m.inner {
                return m.host.to_string_lossy().into_owned();
            }
            if let Some(rest) = s.strip_prefix(&format!("{}/", m.inner)) {
                return m.host.join(rest).to_string_lossy().into_owned();
            }
        }
        if let Some(rest) = s.strip_prefix("/scratch/") {
            return self.scratch.join(rest).to_string_lossy().into_owned();
        }
        s.to_owned()
    }
}

impl Sandbox for TestOnlyUnsandboxedFake {
    fn kind(&self) -> SandboxKind {
        SandboxKind::TestOnlyUnsandboxedFake
    }

    fn run(
        &self,
        spec: &SandboxSpec,
        cancel: &CancelToken,
        keepalive: &mut dyn FnMut() -> bool,
    ) -> Result<RawRun> {
        spec.validate()?;
        let mut cmd = Command::new(self.map(spec, &spec.program));
        cmd.env_clear();
        for (k, v) in &spec.env {
            cmd.env(k, self.map(spec, v));
        }
        cmd.env("CUSTODIAN_SCRATCH", &self.scratch);
        for m in &spec.ro_mounts {
            let var = match m.inner.as_str() {
                "/stage" => "CUSTODIAN_STAGE_ROOT",
                "/input" => "CUSTODIAN_INPUT_ROOT",
                "/job" => "CUSTODIAN_JOB_ROOT",
                _ => continue,
            };
            cmd.env(var, &m.host);
        }
        for a in &spec.args {
            cmd.arg(self.map(spec, a));
        }
        cmd.current_dir(&self.scratch);
        prepare_command(&mut cmd);
        let child = cmd.spawn().map_err(|_| R::SpawnFailed)?;
        supervise(child, &spec.quotas, cancel, keepalive)
    }
}
