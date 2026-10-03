//! Startup and post-restore checkpoint check (ADR 0054).
//!
//! The service must call [`startup_check`] before it serves, and again after
//! any restore. It walks and verifies the ledger, then compares the store
//! (and optionally the corpus registry) with the newest checkpoint the ledger
//! holds. A database or registry older than what was already exported is a
//! rollback: consumed budget may be understated, so serving is refused.
//! Unreachable, unverifiable or forked ledger state also refuses: unknown is
//! not safe.

use custodian_contracts::types::DocumentDigest;
use custodian_corpus::registry::RegistryView;
use custodian_store::{Checkpoint, StoreError};

use crate::backend::LedgerBackend;
use crate::keys::Keyring;
use crate::source::OutboxSource;
use crate::walk::{walk_ledger, Finding};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupRefusal {
    /// The ledger could not be read. Fail closed.
    LedgerUnavailable,
    /// The ledger has integrity findings (bad signature, broken chain, fork,
    /// malformed record). It cannot vouch for the store.
    LedgerUntrusted(Vec<Finding>),
    /// The store is older than, or diverged from, the ledger's checkpoint.
    /// The store has persisted its `needs_reconcile` block.
    StoreRolledBack,
    /// The store was already blocked pending reconciliation.
    StoreBlocked,
    /// The corpus registry is shorter than, or diverged from, its checkpoint.
    RegistryRolledBack,
    StoreError(StoreError),
}

impl StartupRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::LedgerUnavailable => "startup_ledger_unavailable",
            Self::LedgerUntrusted(_) => "startup_ledger_untrusted",
            Self::StoreRolledBack => "startup_store_rolled_back",
            Self::StoreBlocked => "startup_store_blocked",
            Self::RegistryRolledBack => "startup_registry_rolled_back",
            Self::StoreError(_) => "startup_store_error",
        }
    }
}

impl core::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for StartupRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupReport {
    pub ledger_records: usize,
    /// The ledger checkpoint the store was verified against; `None` when the
    /// ledger holds no store position yet (first run).
    pub store_checkpoint: Option<Checkpoint>,
    /// `(head, event_count)` verified against the registry, if one was given
    /// and the ledger holds a registry checkpoint.
    pub registry_checked: Option<(DocumentDigest, u64)>,
    /// Quarantined export conflicts awaiting operator review.
    pub quarantined: Vec<String>,
}

/// `roots` are the pinned trust anchors, obtained out of band. Pass the
/// registry to also detect registry rollback.
pub fn startup_check(
    backend: &dyn LedgerBackend,
    roots: &Keyring,
    store: &dyn OutboxSource,
    registry: Option<&RegistryView>,
) -> Result<StartupReport, StartupRefusal> {
    let walk = walk_ledger(backend, roots).map_err(|_| StartupRefusal::LedgerUnavailable)?;
    if !walk.is_trustworthy() {
        return Err(StartupRefusal::LedgerUntrusted(walk.findings));
    }
    if store
        .needs_reconcile()
        .map_err(StartupRefusal::StoreError)?
    {
        return Err(StartupRefusal::StoreBlocked);
    }
    if let Some(cp) = &walk.store_checkpoint {
        match store.verify_external_checkpoint(cp) {
            Ok(()) => {}
            Err(StoreError::NeedsReconcile) => return Err(StartupRefusal::StoreRolledBack),
            Err(e) => return Err(StartupRefusal::StoreError(e)),
        }
    }
    let mut registry_checked = None;
    if let (Some(view), Some(point)) = (registry, &walk.registry_checkpoint) {
        if view.event_count() < point.event_count
            || view.head_after(point.event_count).as_ref() != Some(&point.head)
        {
            return Err(StartupRefusal::RegistryRolledBack);
        }
        registry_checked = Some((point.head.clone(), point.event_count));
    }
    Ok(StartupReport {
        ledger_records: walk.records,
        store_checkpoint: walk.store_checkpoint,
        registry_checked,
        quarantined: walk.quarantined,
    })
}
