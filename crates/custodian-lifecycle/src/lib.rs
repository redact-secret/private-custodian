//! Contamination, epoch retirement and rotation, public evidence revocation
//! (C9).
//!
//! * [`epochs`]: report contamination, clear an unreviewed change, retire,
//!   rotate to a new reviewed epoch. Rules are `custodian_core::standing`;
//!   durability is `custodian-store`; the registry is `custodian-corpus`.
//! * [`eligibility`]: the real `ReleaseEligibility`, and a dispatch guard
//!   that re-checks standing, recorded revocations and policy activation
//!   freshness before a lease is taken and before protected bytes are opened.
//! * [`feed`]: build, sign, persist and deliver the public revocation feed,
//!   and the destination contract.
//! * [`consumer`]: a reference consumer that needs no private-ledger access.
//! * [`authority`]: who may do what; agents can only report.
//!
//! Design: `docs/lifecycle-and-revocation.md` and ADRs 0070 to 0073. Status:
//! implemented and tested with synthetic data and test-generated keys; the
//! public destination, signer process and private ledger are not provisioned
//! and nothing is deployed. This repository is maintained by the Redact Secret
//! project; nothing here is independent validation, and invalidating evidence
//! does not establish ground truth either way.

#![forbid(unsafe_code)]

pub mod authority;
pub mod consumer;
pub mod eligibility;
pub mod epochs;
pub mod fault;
pub mod feed;
pub mod reason;
pub mod testing;

pub use authority::{authorize, OperatorAction, OperatorAuthority, OperatorAuthorization};
pub use consumer::{FeedConsumer, Observed, StandingChange, SyncError, SyncReport};
pub use eligibility::{
    parse_policy_key, policy_ref_key, ActivationSource, DispatchGuard, GuardedRunLedger,
    LifecycleEligibility,
};
pub use epochs::{
    ChangeRequest, EpochManager, EpochOutcome, EpochReason, RotationBudget, RotationOutcome,
    RotationRequest,
};
pub use fault::{CrashOnce, LifecycleFault, LifecyclePoint, NoFault};
pub use feed::{
    envelope_file_name, DirFeed, FeedConfig, FeedDestination, FeedPublisher, FeedSource,
    MemoryFeed, PublicPopulations, PublishReport, PutOutcome, RegistryPopulations, RevocationSpec,
};
pub use reason::LifecycleReason;
