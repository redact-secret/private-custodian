//! `custodian-verify`: verify a signed public result bundle with public inputs
//! only (S1, ADR 0110).
//!
//! A thin, bounded front end over the C11 reference consumer
//! (`custodian_bridge::BridgeConsumer`). It takes
//!
//! * a bundle directory (a bridge manifest, released projection envelopes and
//!   revocation feed envelopes, all untrusted),
//! * a pinned public keys file,
//! * a pinned feed id,
//! * an expectations file (evaluation domain, candidate, configuration,
//!   destination label, accepted public populations and disclosure policies),
//! * and the time to judge at,
//!
//! and prints exactly one sanitized JSON object with a fixed reason code and a
//! stable exit code (see [`report`]). It has no ledger, store, corpus or
//! signer; `tests/no_private_access.rs` checks the imports, the manifest and
//! the entry-point types.
//!
//! **What a result means.** `accepted` says the bundle is functionally
//! consistent with the pins at the time given: signatures verify under the
//! pinned keys, the bundle matches what was asked for, and nothing in the
//! feed it carries revokes it. It is functional verification of public data.
//! It is not an independent protected evaluation, it does not establish
//! ground truth, and the repository that ships it is maintained by the Redact
//! Secret project. What the bundle is worth as a support claim stays with the
//! caller.

#![forbid(unsafe_code)]

pub mod input;
pub mod report;
pub mod run;

pub use input::{Bundle, Expectations, InputError, Pins, MAX_PINS_BYTES};
pub use report::{ExitClass, Report, Verdict};
pub use run::verify;
