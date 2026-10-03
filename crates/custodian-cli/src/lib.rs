//! Operator CLI and service startup wiring (C10).
//!
//! * [`authority`]: authenticated roles from a reviewed policy file and the
//!   real `OperatorAuthority`. Structural rules keep agent and automation
//!   identities away from approval and the restricted lifecycle actions.
//! * [`control`]: every command, going through the same store transactions,
//!   idempotency keys, epoch gates and budget accounting as the request edge.
//!   The CLI never edits the database, a budget or the ledger.
//! * [`startup`]: the startup sequence (`startup_check` first, no bypass),
//!   the single `LifecycleEligibility`, guarded run ledgers and the feed
//!   reference.
//! * [`command`], [`output`], [`reason`]: the argument grammar, sanitized
//!   JSON output, fixed reason codes and the stable exit codes.
//! * [`deploy`]: the file-based deployment the `custodian` binary opens.
//!
//! Design: ADR 0080 to 0084 and `docs/operator-runbook.md`. Status:
//! implemented and tested with synthetic data and test-generated keys; not
//! deployed. No credential, key or deployment identifier is in this
//! repository. This repository is maintained by the Redact Secret project;
//! nothing here is independent validation.

#![forbid(unsafe_code)]

pub mod authority;
pub mod command;
pub mod control;
pub mod deploy;
pub mod output;
pub mod reason;
pub mod startup;

pub use authority::{
    credential_digest, Limits, OperatorPolicy, Permission, PolicyAuthority, Principal, Role,
    MIN_CREDENTIAL_BYTES,
};
pub use command::{build_command, parse_args, Command, Parsed};
pub use control::{Control, Parts};
pub use output::Output;
pub use reason::{CliReason, ExitClass};
pub use startup::{Service, StartupConfig, StartupFailure, StoreActivations};
