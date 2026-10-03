//! Benchmarks bridge and legacy custody migration (C11).
//!
//! * [`wire`]: the bounded, allowlisted request and response contract
//!   (`private-custodian.bridge-request/1`, `private-custodian.bridge-response/1`).
//! * [`service`]: the custodian side. It answers with released projection
//!   envelopes (a type only a completed release produces) and public feed
//!   bytes, and nothing else.
//! * [`consumer`]: the reference consumer. It verifies with public keys and
//!   pins only and needs no private-ledger credential and no protected
//!   corpus access.
//! * [`legacy`]: a deterministic, reviewed-provenance metadata import of the
//!   existing holdout, PII protected, blind and policy-receipt lifecycles, a
//!   dry-run report, and the reviewed handoff record. It reads no file, no
//!   corpus and no ledger, and executes no cutover.
//! * [`schema`]: checked-in JSON Schemas for the public wire documents.
//!
//! Design: `docs/benchmarks-integration.md`, `docs/legacy-migration.md` and
//! ADRs 0090 to 0092. Status: implemented and tested with synthetic data and
//! test-generated keys; nothing is deployed and no legacy population has been
//! handed off. This repository is maintained by the Redact Secret project;
//! nothing here is independent validation, custody does not establish ground
//! truth, and product policy (thresholds, support status, adjudication)
//! stays with benchmarks.

#![forbid(unsafe_code)]

pub mod consumer;
pub mod legacy;
pub mod reason;
pub mod schema;
pub mod service;
pub mod tag;
pub mod testing;
pub mod wire;

pub use consumer::{BridgeConsumer, ConsumerPins, ResponseOutcome, VerifiedProjection};
pub use reason::{BridgeReason, Rejection};
pub use service::{ApprovedCatalog, BridgeService, CatalogUnavailable, ReleaseQuery};
pub use wire::{BridgeManifest, BridgeRequest, BridgeResponse};
