//! Isolated, bounded execution of pinned credential and PII engines (C6).
//!
//! This crate is the trusted control-plane side of the worker boundary. It
//! verifies frozen identities, stages immutable inputs, launches an engine
//! binary inside a `Sandbox`, bounds and validates what comes back, and maps
//! it to an `ExecutionOutcome` while driving the run ledger in the order the
//! store requires. It contains no measurement logic.
//!
//! Status: implemented and tested with synthetic data; nothing is deployed.
//! A host is supported only if `isolation::run_self_check` passes on it.
//! `docs/worker-isolation.md` states what is and is not claimed.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("custodian-worker relies on POSIX process, mode and link semantics");

pub mod artifacts;
pub mod bwrap;
pub mod dispatcher;
#[cfg(feature = "test-fakes")]
pub mod fake;
pub mod isolation;
pub mod ports;
pub mod reason;
pub mod refusing;
pub mod result;
pub mod sandbox;

pub use dispatcher::{
    ArtifactSources, DispatchJob, DispatchReport, Dispatcher, DispatcherConfig, OperatorCaps,
};
pub use isolation::{run_self_check, IsolationVerification, SelfCheckError};
pub use reason::WorkerReason;
pub use sandbox::{CancelToken, Sandbox, SandboxKind};
