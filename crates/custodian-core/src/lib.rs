//! Policy and state core for the private custodian.
//!
//! This crate holds deterministic rules only: identities, lifecycle state
//! machines, reason codes, budget-settlement policy and the vendor-neutral
//! ports (traits) behind which storage, corpus access, execution and
//! disclosure adapters sit. It has no I/O, no network, no GitHub, no SQLite
//! and no dependencies. The model, the engine and the scanner are never the
//! authority; these rules are.
//!
//! Status: scaffold. Identity types are opaque strings until C2 defines
//! canonical encodings and digests. Nothing here is a deployed control.

#![forbid(unsafe_code)]

pub mod ids;
pub mod lifecycle;
pub mod ports;
pub mod testing;

pub use ids::{ActorId, AuthorizationId, IdempotencyKey, PlanDigest, PopulationId, RunId};
pub use lifecycle::{budget_refundable, DisclosureState, Exposure, ReasonCode, RunState};
