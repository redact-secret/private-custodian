//! Protected population storage, sealing and reviewed registry (C5).
//!
//! `custodian-corpus` holds protected synthetic populations behind the
//! `custodian_core::ports::CorpusAccess` port. It owns: a storage adapter
//! contract with a filesystem implementation and a conformance suite
//! ([`store`], [`fs_store`], [`conformance`]); the exact corpus commitment and
//! seal ([`manifest`], [`seal`]); a restricted, hash-chained registry
//! ([`registry`]); and the verified access path ([`populations`]).
//!
//! It does not run engines, hold budgets, sign receipts or disclose anything
//! (C6 to C8), and it does not handle contamination (C9; see
//! [`registry::LifecycleObserver`]). Status: implemented against synthetic
//! data in tests; no protected storage is provisioned or deployed.
//!
//! Private bytes only ever appear inside [`secret::ProtectedBytes`], which
//! has no `Display`, `Clone` or `Serialize` and a redacting `Debug`. Errors
//! are the fixed [`reason::StorageReason`] codes.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("custodian-corpus relies on POSIX ownership, mode and link semantics");

pub mod conformance;
pub mod fs_store;
pub mod fsguard;
pub mod manifest;
pub mod populations;
pub mod reason;
pub mod registry;
pub mod seal;
pub mod secret;
pub mod store;
pub mod testing;

pub use fs_store::FsEpochStore;
pub use populations::{
    population_id_for, EpochWriter, ProtectedPopulations, SealInputs, SealedEpoch,
};
pub use reason::StorageReason;
pub use registry::{EpochState, LifecycleObserver, Registry, RegistryRow};
pub use secret::{CommitmentKey, ProtectedBytes};
pub use store::{EntryName, EpochBlobStore};
