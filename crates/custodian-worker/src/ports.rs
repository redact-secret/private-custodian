//! The two ports the dispatcher drives, and their adapters over the real
//! `custodian-store` and `custodian-corpus`. Unit tests use recording fakes
//! of these traits; integration tests use the adapters with synthetic data.

use std::sync::{Arc, Mutex};

use custodian_contracts::common::PopulationBinding;
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::policy::ObservedActivation;
use custodian_core::ports::Authorization;
use custodian_core::{ActorId, ReasonCode, RunId};
use custodian_corpus::{EntryName, EpochBlobStore, ProtectedBytes, ProtectedPopulations};
use custodian_store::{Lease, SqliteStore, StartCommand, StoreError};

use crate::reason::{Result, WorkerReason as R};

/// The run-state operations the dispatcher needs, in the order it needs them.
/// Implementations map store failures to `LeaseLost` (fenced by cancel or
/// recovery, expired, wrong holder) or `LedgerUnavailable`.
pub trait RunLedger {
    /// `reserved -> running`; takes the lease.
    fn start(&self) -> Result<()>;
    /// Refuse before start (refunded): `reserved -> failed`.
    fn fail_before_start(&self, reason: ReasonCode) -> Result<()>;
    fn heartbeat(&self) -> Result<()>;
    /// Write-ahead exposure record. Must be committed before protected bytes
    /// are opened.
    fn record_exposure(&self) -> Result<()>;
    fn begin_validation(&self) -> Result<()>;
    fn finish(&self, outcome: ExecutionOutcome, reason: ReasonCode) -> Result<()>;
}

/// Authorized protected bytes. Opening is the exposure event.
pub trait CorpusPort {
    fn open(&self) -> Result<()>;
    fn binding(&self) -> Result<PopulationBinding>;
    fn entry_names(&self) -> Result<Vec<String>>;
    fn read_entry(&self, name: &str) -> Result<ProtectedBytes>;
    fn close(&self);
}

// ---- store adapter --------------------------------------------------------

pub struct StoreRunLedger<'a> {
    store: &'a SqliteStore,
    attempt: RunId,
    owner: String,
    actor: ActorId,
    lease_secs: u64,
    max_state_age_secs: u64,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    observed: Arc<dyn Fn() -> Option<ObservedActivation> + Send + Sync>,
    lease: Mutex<Option<Lease>>,
}

impl<'a> StoreRunLedger<'a> {
    /// `observed` supplies a fresh activation observation at start (required
    /// for attempts reserved through the contract API).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: &'a SqliteStore,
        attempt: RunId,
        owner: impl Into<String>,
        actor: ActorId,
        lease_secs: u64,
        max_state_age_secs: u64,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        observed: Arc<dyn Fn() -> Option<ObservedActivation> + Send + Sync>,
    ) -> Self {
        Self {
            store,
            attempt,
            owner: owner.into(),
            actor,
            lease_secs,
            max_state_age_secs,
            clock,
            observed,
            lease: Mutex::new(None),
        }
    }

    fn lease(&self) -> Result<Lease> {
        self.lease
            .lock()
            .map_err(|_| R::LedgerUnavailable)?
            .clone()
            .ok_or(R::LeaseLost)
    }

    fn map(e: StoreError) -> R {
        match e {
            StoreError::LeaseLost => R::LeaseLost,
            _ => R::LedgerUnavailable,
        }
    }
}

impl RunLedger for StoreRunLedger<'_> {
    fn start(&self) -> Result<()> {
        let obs = (self.observed)();
        let lease = self
            .store
            .start_attempt(&StartCommand {
                attempt: &self.attempt,
                owner: &self.owner,
                actor: &self.actor,
                now: (self.clock)(),
                lease_secs: self.lease_secs,
                observed: obs.as_ref(),
                max_state_age_secs: self.max_state_age_secs,
            })
            .map_err(Self::map)?;
        *self.lease.lock().map_err(|_| R::LedgerUnavailable)? = Some(lease);
        Ok(())
    }

    fn fail_before_start(&self, reason: ReasonCode) -> Result<()> {
        self.store
            .fail_before_start(&self.attempt, &self.actor, reason, (self.clock)())
            .map(|_| ())
            .map_err(Self::map)
    }

    fn heartbeat(&self) -> Result<()> {
        let lease = self.lease()?;
        let renewed = self
            .store
            .renew_lease(&lease, (self.clock)(), self.lease_secs)
            .map_err(Self::map)?;
        *self.lease.lock().map_err(|_| R::LedgerUnavailable)? = Some(renewed);
        Ok(())
    }

    fn record_exposure(&self) -> Result<()> {
        self.store
            .record_exposure(&self.lease()?, &self.actor, (self.clock)())
            .map_err(Self::map)
    }

    fn begin_validation(&self) -> Result<()> {
        self.store
            .begin_validation(&self.lease()?, &self.actor, (self.clock)())
            .map_err(Self::map)
    }

    fn finish(&self, outcome: ExecutionOutcome, reason: ReasonCode) -> Result<()> {
        self.store
            .finish(&self.lease()?, outcome, reason, &self.actor, (self.clock)())
            .map(|_| ())
            .map_err(Self::map)
    }
}

// ---- corpus adapter -------------------------------------------------------

pub struct PopulationsCorpus<'a, S: EpochBlobStore> {
    pop: &'a ProtectedPopulations<S>,
    authorization: Authorization,
    handle: Mutex<Option<custodian_core::ports::CorpusHandle>>,
}

impl<'a, S: EpochBlobStore> PopulationsCorpus<'a, S> {
    pub fn new(pop: &'a ProtectedPopulations<S>, authorization: Authorization) -> Self {
        Self {
            pop,
            authorization,
            handle: Mutex::new(None),
        }
    }

    fn with_handle<T>(
        &self,
        f: impl FnOnce(&custodian_core::ports::CorpusHandle) -> custodian_corpus::reason::Result<T>,
    ) -> Result<T> {
        let g = self.handle.lock().map_err(|_| R::CorpusUnavailable)?;
        let h = g.as_ref().ok_or(R::CorpusUnavailable)?;
        f(h).map_err(|_| R::CorpusUnavailable)
    }
}

impl<S: EpochBlobStore> CorpusPort for PopulationsCorpus<'_, S> {
    fn open(&self) -> Result<()> {
        let h = self
            .pop
            .open_verified(&self.authorization)
            .map_err(|_| R::CorpusUnavailable)?;
        *self.handle.lock().map_err(|_| R::CorpusUnavailable)? = Some(h);
        Ok(())
    }

    fn binding(&self) -> Result<PopulationBinding> {
        self.with_handle(|h| self.pop.binding(h))
    }

    fn entry_names(&self) -> Result<Vec<String>> {
        self.with_handle(|h| {
            Ok(self
                .pop
                .entry_names(h)?
                .iter()
                .map(|n| n.as_str().to_owned())
                .collect())
        })
    }

    fn read_entry(&self, name: &str) -> Result<ProtectedBytes> {
        let n = EntryName::parse(name).map_err(|_| R::PathRejected)?;
        self.with_handle(|h| self.pop.read_entry(h, &n))
    }

    fn close(&self) {
        if let Ok(mut g) = self.handle.lock() {
            if let Some(h) = g.take() {
                self.pop.close(h);
            }
        }
    }
}
