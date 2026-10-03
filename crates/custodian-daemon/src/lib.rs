//! Service daemon (S5): the process that listens for the request edge, drains
//! the durable intake queue, runs the scheduled maintenance passes and drives
//! each approved request through the pipeline to a signed, ledgered, released
//! public projection.
//!
//! It composes the components the earlier issues built and weakens none of
//! them:
//!
//! * the startup sequence, the `startup_check` (no bypass), the single
//!   eligibility, `GuardedRunLedger`, the disclosure service and the feed
//!   reference are `custodian_cli::Service` and its library functions, not
//!   copies ([`runtime`], ADR 0126);
//! * a request becomes a reservation only through a human approval on the
//!   existing control plane; the daemon holds no approval authority, never
//!   grants one, and reads a release approval from a file a human placed
//!   ([`pipeline`], ADR 0126);
//! * it runs on public synthetic data and test keys only. Nothing is
//!   deployed, the GitHub webhook stays inactive, and the real network path
//!   is off unless explicitly configured ([`github`], ADR 0124).
//!
//! Modules:
//!
//! * [`config`]: the strict, secrets-by-path configuration;
//! * [`http`]: a std-only HTTP/1.1 listener with hard limits (ADR 0123);
//! * [`github`]: the RS256 App JWT signer, the API transport behind a trait
//!   with an offline fake, and the Check and pull-request adapters;
//! * [`consumer`]: the queue consumer (leases, fencing, bounded retries with
//!   backoff, poison handling, graceful shutdown) (ADR 0125);
//! * [`pipeline`]: reserve-to-projection steps, each idempotent and
//!   resumable, and the receipt assembly (R-3) (ADR 0126, ADR 0127);
//! * [`schedule`]: the periodic recover, reconcile, deliver, export,
//!   checkpoint, startup-check and signer-liveness passes;
//! * [`runtime`]: wiring, threads and shutdown;
//! * [`source`], [`sink`]: the request, candidate and artifact directories
//!   and the idempotent delivery sink.
//!
//! Functional verification on public synthetic data, not independent
//! protected evaluation. This repository is maintained by the Redact Secret
//! project; nothing here is independent validation. Real engines do not emit
//! the aggregate artifact this pipeline consumes yet (docs/daemon.md).

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("custodian-daemon relies on POSIX file modes, signals and process semantics");

pub mod config;
pub mod consumer;
pub mod github;
pub mod http;
pub mod log;
pub mod pipeline;
pub mod reason;
pub mod runtime;
pub mod schedule;
pub mod shutdown;
pub mod sink;
pub mod source;

pub use config::DaemonConfig;
pub use log::{EventLog, RecordingLog, StderrLog};
pub use reason::DaemonReason;
pub use shutdown::Shutdown;
