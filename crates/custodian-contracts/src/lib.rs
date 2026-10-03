//! Versioned request, approval, reservation, execution, receipt, public
//! projection, revocation and policy-activation contracts (C2).
//!
//! Internal contracts (`request`, `approval`, `reservation`, `execution`,
//! `policy`) never leave the control service. Public contracts (`public`,
//! `revocation`) are explicit allowlists with bounded fields. Canonical
//! serialization, digests and domain separation are in `canonical`
//! (ADR 0004); freshness and revocation semantics are in `policy` and
//! `revocation` (ADR 0005); the policy summary is `docs/contracts.md`.
//!
//! This crate defines shapes and checks only. It does no I/O, holds no keys,
//! implements no signing algorithm and decides no budget: those are C3 to C9.

#![forbid(unsafe_code)]

pub mod approval;
pub mod canonical;
pub mod common;
pub mod error;
pub mod execution;
pub mod policy;
pub mod public;
pub mod public_v2;
pub mod request;
pub mod reservation;
pub mod revocation;
pub mod schema;
pub mod types;

pub use canonical::{Contract, DomainTag, MAX_DOCUMENT_BYTES};
pub use error::{BindingError, ContractError};

/// Contract schema generation. Bumped only with a new `schemas/vN/` directory.
pub const CONTRACT_MAJOR_VERSION: u32 = 1;

/// Newest public projection major. v1 stays decodable and verifiable but has
/// no destination binding; v2 carries the destination in the signed payload
/// (ADR 0119). Its schema lives in `schemas/v2/`.
pub const PUBLIC_PROJECTION_LATEST_MAJOR: u32 = 2;
