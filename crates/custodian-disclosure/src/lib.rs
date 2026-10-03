//! Aggregate disclosure, small-cell and composition suppression, release
//! budgets and publication approvals (C8).
//!
//! This crate sits between the private custodian and anything public. It
//! takes the complete internal record of a finished run, validates all of it,
//! and builds a separate public projection from an explicit allowlist. It never
//! publishes an internal record by deleting fields from it.
//!
//! * [`policy`]: the versioned disclosure policy and its `policy` ledger record.
//! * [`aggregate`]: the strict private aggregate artifact the projection is
//!   built from, bound to the signed internal receipt.
//! * [`suppress`] and [`compose`]: small-cell, complementary and
//!   composition-aware suppression, including differencing across overlapping
//!   totals and across successive releases.
//! * [`service`]: prepare (validate, charge, build) and release (approval,
//!   durable audit, signing, ledger decision, delivery).
//! * [`released`]: the released envelope type and `verify_release`.
//! * [`reason`] and [`check`]: fixed reason codes and sanitized Check updates.
//!
//! Aggregate-only disclosure does not by itself guarantee privacy. What the
//! algorithm cannot prevent is stated in `docs/disclosure.md`. This repository
//! is maintained by the Redact Secret project; nothing here is independent
//! validation, and nothing establishes ground truth. Status: implemented and
//! tested with synthetic data; not deployed.

#![forbid(unsafe_code)]

pub mod aggregate;
pub mod check;
pub mod compose;
pub mod policy;
pub mod ports;
pub mod reason;
pub mod released;
pub mod service;
pub mod suppress;
pub mod testing;

pub use aggregate::PrivateAggregates;
pub use policy::DisclosurePolicy;
pub use ports::{
    DisclosureStore, EligibilityRefusal, EligibilitySubject, PublicPopulationNames,
    ReleaseEligibility, Sink,
};
pub use reason::DisclosureReason;
pub use released::{verify_release, ReleasedEnvelope, VerifiedRelease};
pub use service::{DisclosureService, PrepareInput, PreparedRelease, ReleaseRequest};
