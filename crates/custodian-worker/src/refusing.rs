//! The backend for platforms with no supported isolation. It never runs
//! anything: `run` always fails closed. `Dispatcher` cannot even be built on
//! top of it, because the self-check cannot pass.

use crate::reason::{Result, WorkerReason as R};
use crate::sandbox::{CancelToken, RawRun, Sandbox, SandboxKind, SandboxSpec};

#[derive(Clone, Copy, Debug, Default)]
pub struct RefusingSandbox;

impl Sandbox for RefusingSandbox {
    fn kind(&self) -> SandboxKind {
        SandboxKind::Refusing
    }

    fn run(
        &self,
        _spec: &SandboxSpec,
        _cancel: &CancelToken,
        _keepalive: &mut dyn FnMut() -> bool,
    ) -> Result<RawRun> {
        Err(R::UnsupportedPlatform)
    }
}

/// The sandbox this host can supply: bubblewrap on Linux, otherwise the
/// refusing backend. Never an unsandboxed runner.
pub fn host_sandbox() -> Box<dyn Sandbox> {
    match crate::bwrap::BubblewrapSandbox::detect() {
        Ok(b) => Box::new(b),
        Err(_) => Box::new(RefusingSandbox),
    }
}
