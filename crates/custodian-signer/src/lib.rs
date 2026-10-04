//! Isolated signer process and local-socket signer transport (S2).
//!
//! The control service, workers and agents never hold the receipt signing key.
//! This crate is the other side of `custodian_ledger::RemoteSigner`:
//!
//! * [`server`] and the `custodian-signer` binary: a separate process that
//!   loads the key through a [`provider::KeyProvider`], listens on an
//!   owner-only Unix socket, checks the peer's uid, and answers framed
//!   requests ([`frame`]) by re-validating every payload with
//!   `ApprovedPayload::from_wire` ([`engine`]).
//! * [`client::UnixSocketTransport`]: the `SignerTransport` the control
//!   service uses. No key, no key path.
//! * [`platform`]: peer credentials and process hardening through safe `nix`
//!   wrappers, so this crate keeps `forbid(unsafe_code)`.
//! * [`network_transport_shape`]: a shape/contract prototype of ADR 0134's
//!   "Signer Transport" section (issue #46). It does not implement or
//!   deploy a network transport; see its module doc for exactly what it
//!   proves and does not prove.
//!
//! Design: `docs/signer.md` and ADRs 0111 to 0114. Status: implemented and
//! tested with synthetic, test-generated keys; not deployed. No production key
//! exists, and this repository never contains one.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod engine;
pub mod frame;
pub mod network_transport_shape;
pub mod platform;
pub mod provider;
pub mod secret;
pub mod server;

pub use client::UnixSocketTransport;
pub use config::{ConfigError, SignerConfig, CONFIG_SCHEMA};
pub use engine::{
    silent_sink, Clock, EventSink, ManualClock, SignerSetup, SigningEngine, Stats, StatsSnapshot,
    SystemClock,
};
pub use frame::Reject;
pub use network_transport_shape::{
    CallerRole, NetworkSignerTransport, ShapeOnlyTransport, ShapeRefusal,
};
pub use platform::{harden_process, Hardening};
pub use provider::{effective_uid, FileKeyProvider, KeyProvider, KeyProviderError};
pub use secret::SecretSeed;
pub use server::{start, RunningServer, ServerConfig, ServerError};
