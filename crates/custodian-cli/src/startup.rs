//! Service startup wiring (C10, ADR 0082).
//!
//! The one place the pieces C4 to C9 built are assembled into a running
//! control plane, in the order their ADRs require:
//!
//! 1. `startup_check` against the ledger with the pinned roots, the store and
//!    the registry view (ADR 0054). There is no flag that skips it. A refusal
//!    that makes the store untrustworthy to write to (a rollback, an untrusted
//!    ledger, a registry rollback) persists the store's write block; it stays
//!    until an operator runs the audited `repair clear-reconcile`, which is
//!    itself refused unless the store is demonstrably not behind the ledger;
//! 2. store `recover` (lapsed leases settle; an exposed attempt is consumed,
//!    never refunded);
//! 3. `EpochManager::reconcile_registry` (ADR 0070);
//! 4. `FeedPublisher::deliver_pending` (ADR 0072);
//! 5. the ledger export of the outbox and the checkpoints;
//! 6. one `LifecycleEligibility`, built once and shared with the
//!    `DisclosureService`; every `RunLedger` is wrapped in `GuardedRunLedger`;
//!    `FeedPublisher::feed_ref` supplies `PrepareInput::feed`.
//!
//! Why the check comes before `recover`: `recover` writes. A store restored
//! from an older backup must not be written to before it is compared with the
//! ledger.

use std::sync::Arc;

use custodian_contracts::common::{ActivationRef, PolicyRef};
use custodian_contracts::policy::ObservedActivation;
use custodian_contracts::public::FeedRef;
use custodian_contracts::types::{CandidateDigest, EpochId, Timestamp};
use custodian_core::ActorId;
use custodian_corpus::EpochBlobStore;
use custodian_disclosure::{DisclosureService, DisclosureStore, PublicPopulationNames};
use custodian_ledger::{
    startup_check, walk_ledger, ExportReport, ExportStatus, Exporter, StartupRefusal,
    StartupReport, Verifier,
};
use custodian_lifecycle::{
    ActivationSource, DispatchGuard, EpochManager, FeedPublisher, GuardedRunLedger,
    LifecycleEligibility,
};
use custodian_store::{Clock, RecoveryReport, SqliteStore};
use custodian_worker::ports::RunLedger;

use crate::control::{export_reason, Control, Parts};
use crate::reason::CliReason;

/// The check every state-changing path runs first. Public so the daemon
/// (S5, ADR 0126) runs exactly this check, with no bypass, before each
/// scheduled pass instead of carrying a copy.
pub fn check<S: EpochBlobStore>(
    p: &Parts<'_, S>,
) -> Result<StartupReport, (CliReason, StartupRefusal)> {
    let view = p.populations.registry().view().map_err(|_| {
        (
            CliReason::StoreUnavailable,
            StartupRefusal::LedgerUnavailable,
        )
    })?;
    match startup_check(p.ledger, p.roots, p.store, Some(&view)) {
        Ok(report) => Ok(report),
        Err(refusal) => {
            if matches!(
                refusal,
                StartupRefusal::StoreRolledBack
                    | StartupRefusal::RegistryRolledBack
                    | StartupRefusal::LedgerUntrusted(_)
            ) {
                // Restrict only: nothing is lost by blocking writes, and the
                // clear path re-checks everything.
                let _ = p.store.block_for_reconcile();
            }
            Err(((&refusal).into(), refusal))
        }
    }
}

/// Export every pending outbox event, then record the store and registry
/// checkpoints. Returns the export report and whether a store checkpoint was
/// written. Public for the same reason as [`check`]: the daemon's export
/// barrier and scheduler are this function, not a second implementation.
pub fn export_all<S: EpochBlobStore>(
    p: &Parts<'_, S>,
    now: Timestamp,
) -> Result<(ExportReport, bool), CliReason> {
    let walk = walk_ledger(p.ledger, p.roots).map_err(|_| CliReason::LedgerUnavailable)?;
    let verifier = Verifier::new(walk.keyring);
    let exporter = Exporter::new(p.ledger, p.signer, &verifier);
    let report = exporter
        .export_pending(p.store, now.secs())
        .map_err(export_reason)?;
    let mut wrote = false;
    if matches!(report.status, ExportStatus::Drained) {
        wrote = exporter
            .record_store_checkpoint(p.store, now.secs())
            .map_err(export_reason)?
            .is_some();
        let view = p
            .populations
            .registry()
            .view()
            .map_err(|_| CliReason::StoreUnavailable)?;
        exporter
            .record_registry_checkpoint(&view, now.secs())
            .map_err(export_reason)?;
    }
    Ok((report, wrote))
}

/// Reads policy activation state from the store's append-only history (the
/// real activation store). It is the [`ActivationSource`] the eligibility
/// gates use.
pub struct StoreActivations<'a> {
    store: &'a SqliteStore,
    clock: Arc<dyn Clock>,
}

impl<'a> StoreActivations<'a> {
    pub fn new(store: &'a SqliteStore, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }
}

impl ActivationSource for StoreActivations<'_> {
    fn observe(&self, binding: &ActivationRef) -> Option<ObservedActivation> {
        let now = Timestamp::new(self.clock.now()).ok()?;
        self.store.observe_activation(binding, now).ok().flatten()
    }
}

/// What the deployment requires of the gates.
#[derive(Clone, Debug, Default)]
pub struct StartupConfig {
    /// Disclosure (or other) policies whose revocation must stop use.
    pub guarded_policies: Vec<PolicyRef>,
    /// Policy activations that must be current and fresh at every gate.
    pub required_activations: Vec<ActivationRef>,
    /// Freshness bound for those observations (capped by the contract).
    pub activation_max_age_secs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupFailure {
    /// Which step refused. A fixed word.
    pub step: &'static str,
    pub reason: CliReason,
}

/// A started control plane: the proof that the startup sequence ran to the
/// end, and the gates built from it.
pub struct Service<'a, S: EpochBlobStore> {
    parts: Parts<'a, S>,
    eligibility: LifecycleEligibility<'a>,
    pub ledger_report: StartupReport,
    pub recovery: RecoveryReport,
    pub registry_retired: usize,
    pub feed_delivered: usize,
    pub export_status: ExportStatus,
}

impl<'a, S: EpochBlobStore> Service<'a, S> {
    pub fn start(
        parts: Parts<'a, S>,
        config: &StartupConfig,
        activations: &'a StoreActivations<'a>,
    ) -> Result<Self, StartupFailure> {
        let fail = |step: &'static str, reason: CliReason| StartupFailure { step, reason };
        let now =
            Timestamp::new(parts.clock.now()).map_err(|_| fail("clock", CliReason::Internal))?;
        // 1. rollback and ledger check, before anything writes
        let ledger_report = check(&parts).map_err(|(r, _)| fail("startup_check", r))?;
        // 2. recover lapsed leases
        let recovery = parts
            .store
            .recover(&ActorId::new("custodian-service-startup"), now.secs())
            .map_err(|e| fail("recover", e.into()))?;
        // 3. registry mirror of the store's standing
        let registry_retired = EpochManager {
            store: parts.store,
            populations: parts.populations,
            authority: parts.authority,
            fault: parts.fault,
        }
        .reconcile_registry(now)
        .map_err(|e| fail("reconcile_registry", e.into()))?;
        // 4. deliver committed feed envelopes
        let feed_delivered = FeedPublisher {
            store: parts.store,
            populations: parts.feed_populations,
            signer: parts.signer,
            destination: parts.feed_destination,
            authority: parts.authority,
            config: parts.feed_config.clone(),
            fault: parts.fault,
        }
        .deliver_pending(now)
        .map_err(|e| fail("deliver_pending", e.into()))?;
        // 5. export
        let (export, _) = export_all(&parts, now).map_err(|r| fail("export", r))?;
        // 6. one eligibility, built once
        let mut eligibility = LifecycleEligibility::new(parts.store);
        for p in &config.guarded_policies {
            eligibility = eligibility.guarding_policy(p.clone());
        }
        for b in &config.required_activations {
            eligibility = eligibility.requiring_activation(
                b.clone(),
                activations,
                config.activation_max_age_secs,
            );
        }
        Ok(Self {
            parts,
            eligibility,
            ledger_report,
            recovery,
            registry_retired,
            feed_delivered,
            export_status: export.status,
        })
    }

    /// The one eligibility gate. Pass it to `DisclosureService` and use it as
    /// the dispatch guard; do not build a second.
    pub fn eligibility(&self) -> &LifecycleEligibility<'a> {
        &self.eligibility
    }

    /// Wrap a `RunLedger` so eligibility is re-checked at start and before
    /// exposure. Every `RunLedger` the service hands to a dispatcher goes
    /// through here.
    pub fn guard_run_ledger<'s, L: RunLedger>(
        &'s self,
        inner: L,
        candidate: CandidateDigest,
        epoch: EpochId,
    ) -> GuardedRunLedger<'s, L> {
        let clock = self.parts.clock.clone();
        let guard: &'s dyn DispatchGuard = &self.eligibility;
        GuardedRunLedger::new(
            inner,
            guard,
            candidate,
            epoch,
            Arc::new(move || clock.now()),
        )
    }

    /// The disclosure service wired to this service's eligibility, signer and
    /// naming object.
    pub fn disclosure_service<'s>(
        &'s self,
        store: &'s dyn DisclosureStore,
        exporter: &'s Exporter<'s>,
        names: &'s dyn PublicPopulationNames,
    ) -> DisclosureService<'s> {
        DisclosureService {
            store,
            exporter,
            signer: self.parts.signer,
            eligibility: &self.eligibility,
            names,
        }
    }

    /// The feed reference for `PrepareInput::feed`. Refused while any
    /// revocation obligation is unpublished, so a projection never points at
    /// a feed that is missing a known revocation.
    pub fn feed_ref(&self) -> Result<FeedRef, CliReason> {
        FeedPublisher {
            store: self.parts.store,
            populations: self.parts.feed_populations,
            signer: self.parts.signer,
            destination: self.parts.feed_destination,
            authority: self.parts.authority,
            config: self.parts.feed_config.clone(),
            fault: self.parts.fault,
        }
        .feed_ref()
        .map_err(Into::into)
    }

    /// The operator control plane over the same wiring.
    pub fn control(&self) -> Control<'a, S> {
        Control::new(self.parts.clone())
    }
}
