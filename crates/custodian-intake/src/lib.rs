//! Request-facing GitHub App adapter (Z1, C3).
//!
//! This crate is the only place GitHub's request edge is handled. It
//! verifies signed webhooks, applies event, installation, repository and
//! actor allowlists, denies forks, cross-repository pull requests and
//! comment- or workflow-triggered requests, records delivery ids for replay
//! protection, and enqueues identifiers for the control plane. It performs
//! no evaluation. It holds the request-facing App credential only; it has no
//! access to the runtime database, protected storage, signer or ledger.
//!
//! Design and limits: ADR 0010, `docs/github-app.md`. Nothing here is
//! deployed; no HTTP listener or GitHub client exists in this crate. Real
//! network access and the App private key sit behind [`app_auth`] and
//! [`credentials`] traits supplied by the deployment.
//!
//! Requesting the evaluation is not approving it: [`gate::ExecutionGate`]
//! requires a separate `Approval` contract record that no webhook can create.

#![forbid(unsafe_code)]

pub mod app_auth;
pub mod checks;
pub mod config;
pub mod credentials;
pub mod gate;
pub mod ids;
pub mod memory;
pub mod ports;
pub mod reason;
pub mod signature;
pub mod testing;
pub mod webhook;

pub use reason::{ConfigError, IntakeReason};
