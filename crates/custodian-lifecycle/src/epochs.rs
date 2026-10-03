//! Contamination reports, clearance, retirement and rotation (ADR 0070 to
//! 0072).
//!
//! The rules are `custodian_core::standing`; durability and atomicity are
//! `custodian-store`; the registry is `custodian-corpus`. This module is the
//! orchestration: it authorizes the actor (agents can only report), validates
//! the change against the registry, applies it in the store, mirrors
//! retirement into the registry, and for a rotation links the successor and
//! provisions its budgets.
//!
//! Every multi-step operation is a sequence of idempotent steps ordered so
//! that each intermediate state fails closed. Re-running the same call with
//! the same idempotency key after a crash continues where it stopped.

use custodian_contracts::common::{BudgetKind, BudgetScope};
use custodian_contracts::types::{EpochId, IdempotencyKey, Timestamp};
use custodian_core::standing::Transition;
use custodian_core::{Contamination, EpochChange, EpochStanding};
use custodian_corpus::registry::EpochState;
use custodian_corpus::store::EpochBlobStore;
use custodian_corpus::ProtectedPopulations;
use custodian_store::{EpochEventCommand, EpochEventOutcome, RotationCommand, SqliteStore};

use crate::authority::{authorize, OperatorAction, OperatorAuthority, OperatorAuthorization};
use crate::fault::{LifecycleFault, LifecyclePoint};
use crate::reason::{from_store, LifecycleReason as R, Result};

/// Fixed vocabulary for why a standing changed. Recorded with every event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EpochReason {
    /// Protected results or case detail reached a party outside custody.
    ResultsExposed,
    /// A candidate or detector was adjusted using this population's results.
    TunedOnResults,
    /// An integrity check or alarm on the population or its binding.
    IntegrityAlarm,
    /// The population or its binding changed without a reviewed re-seal.
    UnreviewedPopulationChange,
    /// Review found the flagged change had no effect on the population.
    ReviewedNoImpact,
    /// Retirement that follows a permanent contamination.
    ContaminationResponse,
    /// A new reviewed population replaces this one.
    PlannedRotation,
    /// A decision by an authorized operator.
    OperatorDecision,
}

impl EpochReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::ResultsExposed => "results_exposed",
            Self::TunedOnResults => "tuned_on_results",
            Self::IntegrityAlarm => "integrity_alarm",
            Self::UnreviewedPopulationChange => "unreviewed_population_change",
            Self::ReviewedNoImpact => "reviewed_no_impact",
            Self::ContaminationResponse => "contamination_response",
            Self::PlannedRotation => "planned_rotation",
            Self::OperatorDecision => "operator_decision",
        }
    }

    fn fits_report(self, kind: Contamination) -> bool {
        use Contamination::*;
        match kind {
            Unaffected => false,
            UnreviewedChange => matches!(
                self,
                Self::UnreviewedPopulationChange | Self::IntegrityAlarm | Self::OperatorDecision
            ),
            Exposed => matches!(
                self,
                Self::ResultsExposed | Self::IntegrityAlarm | Self::OperatorDecision
            ),
            UsedForTuning => matches!(self, Self::TunedOnResults | Self::OperatorDecision),
        }
    }

    fn fits_retire(self) -> bool {
        matches!(
            self,
            Self::ContaminationResponse | Self::PlannedRotation | Self::OperatorDecision
        )
    }
}

/// A change request: which epoch, who, under which authorization, with what
/// idempotency key, when.
pub struct ChangeRequest<'a> {
    pub epoch: &'a EpochId,
    pub who: &'a OperatorAuthorization,
    pub key: &'a IdempotencyKey,
    pub reason: EpochReason,
    pub now: Timestamp,
}

/// What an operation did. Identities and states only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochOutcome {
    pub transition: Transition,
    pub changed: bool,
    pub replay: bool,
    /// Feed obligation recorded by the change, if any.
    pub obligation: Option<String>,
    /// Set when the operation also retired the epoch (automatic retirement
    /// after a permanent contamination).
    pub retirement: Option<Box<EpochOutcome>>,
}

fn outcome(o: EpochEventOutcome) -> EpochOutcome {
    EpochOutcome {
        transition: Transition {
            prior: o.prior,
            new: o.new,
        },
        changed: o.changed,
        replay: o.replay,
        obligation: o.obligation_id,
        retirement: None,
    }
}

/// One budget to provision for a rotation's successor epoch.
#[derive(Clone, Debug)]
pub struct RotationBudget {
    pub kind: BudgetKind,
    pub scope: BudgetScope,
    pub limit: u64,
}

pub struct RotationRequest<'a> {
    pub predecessor: &'a EpochId,
    pub successor: &'a EpochId,
    pub who: &'a OperatorAuthorization,
    pub key: &'a IdempotencyKey,
    pub reason: EpochReason,
    /// Budgets for the successor only. Each scope must name the successor
    /// epoch; the predecessor's budgets are never touched.
    pub budgets: &'a [RotationBudget],
    pub now: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationOutcome {
    pub retirement: EpochOutcome,
    /// True when this call recorded the link (false on a repeat).
    pub linked: bool,
    pub budgets_provisioned: usize,
    pub activated: bool,
}

pub struct EpochManager<'a, S: EpochBlobStore> {
    pub store: &'a SqliteStore,
    pub populations: &'a ProtectedPopulations<S>,
    pub authority: &'a dyn OperatorAuthority,
    pub fault: &'a dyn LifecycleFault,
}

fn secs(t: Timestamp) -> u64 {
    t.secs()
}

impl<S: EpochBlobStore> EpochManager<'_, S> {
    fn crash(&self, p: LifecyclePoint) -> Result<()> {
        if self.fault.crash_at(p) {
            Err(R::InjectedCrash)
        } else {
            Ok(())
        }
    }

    /// Registry facts for an epoch: corpus, family and state.
    fn registry_row(
        &self,
        epoch: &EpochId,
    ) -> Result<(custodian_corpus::registry::RegistryRow, EpochState)> {
        let view = self
            .populations
            .registry()
            .view()
            .map_err(|_| R::RegistryUnavailable)?;
        let (row, state) = view.get(epoch).ok_or(R::UnknownEpoch)?;
        Ok((row.clone(), state))
    }

    fn apply(
        &self,
        req: &ChangeRequest<'_>,
        change: EpochChange,
        key_suffix: &str,
    ) -> Result<EpochEventOutcome> {
        let (row, _) = self.registry_row(req.epoch)?;
        let key = format!("{}{}", req.key.as_str(), key_suffix);
        self.store
            .apply_epoch_change(&EpochEventCommand {
                epoch_id: req.epoch.as_str(),
                corpus_id: row.corpus_id.as_str(),
                family_id: row.family_id.as_ref().map(|f| f.as_str()),
                idempotency_key: &key,
                change,
                reason: req.reason.code(),
                actor: req.who.actor.as_str(),
                actor_kind: req.who.kind_str(),
                authorization_ref: req.who.authorization.as_str(),
                now: secs(req.now),
            })
            .map_err(from_store)
    }

    /// Standing of an epoch as the store holds it.
    pub fn standing(&self, epoch: &EpochId) -> Result<EpochStanding> {
        Ok(self
            .store
            .epoch_standing(epoch.as_str())
            .map_err(from_store)?
            .map_or(EpochStanding::CLEAN, |r| r.standing))
    }

    /// Report a contamination. It can only raise the epoch's severity: a
    /// weaker report on a stronger state changes nothing and is still
    /// recorded. A permanent contamination (`Exposed`, `UsedForTuning`)
    /// retires the epoch in the same call; the registry follows. An agent
    /// may report; everything after depends on the authority.
    pub fn report(&self, req: &ChangeRequest<'_>, kind: Contamination) -> Result<EpochOutcome> {
        authorize(self.authority, req.who, OperatorAction::ReportContamination)?;
        if !req.reason.fits_report(kind) {
            return Err(R::InvalidChange);
        }
        self.registry_row(req.epoch)?;
        let mut out = outcome(self.apply(req, EpochChange::Report(kind), "")?);
        self.crash(LifecyclePoint::AfterReport)?;
        if out.transition.new.contamination.is_permanent() && !out.transition.new.retired {
            let retire = ChangeRequest {
                reason: EpochReason::ContaminationResponse,
                ..*req
            };
            out.retirement = Some(Box::new(self.retire_inner(&retire, ":retire")?));
        }
        Ok(out)
    }

    /// Clear an `unreviewed_change` after review. Human actors only, never
    /// an agent, never a permanent contamination, never a retired epoch.
    pub fn clear(&self, req: &ChangeRequest<'_>) -> Result<EpochOutcome> {
        authorize(
            self.authority,
            req.who,
            OperatorAction::ClearUnreviewedChange,
        )?;
        if req.reason != EpochReason::ReviewedNoImpact {
            return Err(R::InvalidChange);
        }
        self.registry_row(req.epoch)?;
        Ok(outcome(self.apply(req, EpochChange::Clear, "")?))
    }

    /// Retire an epoch: blocked for good in the store, then in the registry.
    pub fn retire(&self, req: &ChangeRequest<'_>) -> Result<EpochOutcome> {
        authorize(self.authority, req.who, OperatorAction::RetireEpoch)?;
        if !req.reason.fits_retire() {
            return Err(R::InvalidChange);
        }
        self.retire_inner(req, "")
    }

    fn retire_inner(&self, req: &ChangeRequest<'_>, suffix: &str) -> Result<EpochOutcome> {
        self.registry_row(req.epoch)?;
        let out = outcome(self.apply(req, EpochChange::Retire, suffix)?);
        self.crash(LifecyclePoint::AfterStoreRetire)?;
        self.mirror_retirement(req.epoch, req.now)?;
        Ok(out)
    }

    /// Make the registry say what the store says: retired. Idempotent.
    fn mirror_retirement(&self, epoch: &EpochId, now: Timestamp) -> Result<()> {
        let (_, state) = self.registry_row(epoch)?;
        if state != EpochState::Retired {
            self.populations
                .retire(epoch, now)
                .map_err(|_| R::RegistryUnavailable)?;
        }
        Ok(())
    }

    /// Startup and recovery sweep: every epoch the store holds as retired or
    /// permanently contaminated must be retired in the registry too. Returns
    /// how many registry entries it retired. Safe to run repeatedly.
    pub fn reconcile_registry(&self, now: Timestamp) -> Result<usize> {
        let epochs: Vec<_> = {
            let view = self
                .populations
                .registry()
                .view()
                .map_err(|_| R::RegistryUnavailable)?;
            view.epochs()
                .map(|(row, state)| (row.epoch_id.clone(), state))
                .collect()
        };
        let mut n = 0;
        for (epoch, state) in epochs {
            if state == EpochState::Retired {
                continue;
            }
            let s = self.standing(&epoch)?;
            if s.retired || s.contamination.is_permanent() {
                self.populations
                    .retire(&epoch, now)
                    .map_err(|_| R::RegistryUnavailable)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Rotate to a new reviewed epoch. Order (each step idempotent, each
    /// intermediate state fails closed):
    ///
    /// 1. store retires the predecessor (new use is refused from here);
    /// 2. the registry retires it;
    /// 3. the store links predecessor to successor;
    /// 4. the successor's budgets are provisioned under its own scope keys;
    /// 5. the registry activates the successor (the only step that makes it
    ///    usable, so it is last).
    ///
    /// The predecessor's budgets, history and seal are never edited; its
    /// consumption stays exactly as it was. A successor must be a different,
    /// already sealed (or active) epoch of the same corpus and family.
    pub fn rotate(&self, req: &RotationRequest<'_>) -> Result<RotationOutcome> {
        authorize(self.authority, req.who, OperatorAction::RotateEpoch)?;
        if !req.reason.fits_retire() {
            return Err(R::InvalidChange);
        }
        if req.predecessor == req.successor {
            return Err(R::RotationInvalid);
        }
        let (old, _) = self.registry_row(req.predecessor)?;
        let (new, new_state) = self.registry_row(req.successor)?;
        if old.corpus_id != new.corpus_id
            || old.family_id != new.family_id
            || old.domain != new.domain
        {
            return Err(R::EpochMismatch);
        }
        // A new reviewed population: different content and a different seal.
        if old.population_digest == new.population_digest || old.seal_digest == new.seal_digest {
            return Err(R::RotationInvalid);
        }
        if new_state == EpochState::Retired || !self.standing(req.successor)?.usable() {
            return Err(R::RotationInvalid);
        }
        // Budgets: successor only, and no scope may name any other epoch.
        for b in req.budgets {
            if !b
                .scope
                .covers(&custodian_contracts::common::PopulationBinding {
                    domain: new.domain,
                    corpus_id: new.corpus_id.clone(),
                    epoch_id: new.epoch_id.clone(),
                    family_id: new.family_id.clone(),
                    population_digest: new.population_digest.clone(),
                    custody_version: new.custody_version,
                })
            {
                return Err(R::RotationInvalid);
            }
        }

        // 1 and 2.
        let retire_req = ChangeRequest {
            epoch: req.predecessor,
            who: req.who,
            key: req.key,
            reason: req.reason,
            now: req.now,
        };
        let retirement = self.retire_inner(&retire_req, ":rotate-retire")?;
        self.crash(LifecyclePoint::AfterRegistryRetire)?;

        // 3.
        let linked = self
            .store
            .record_rotation(&RotationCommand {
                predecessor: req.predecessor.as_str(),
                successor: req.successor.as_str(),
                corpus_id: old.corpus_id.as_str(),
                family_id: old.family_id.as_ref().map(|f| f.as_str()),
                actor: req.who.actor.as_str(),
                authorization_ref: req.who.authorization.as_str(),
                now: secs(req.now),
            })
            .map_err(from_store)?;
        self.crash(LifecyclePoint::AfterRotationLink)?;

        // 4.
        for b in req.budgets {
            self.store
                .provision_budget(
                    b.kind,
                    &b.scope,
                    b.limit,
                    &custodian_core::ActorId::new(req.who.actor.as_str()),
                    secs(req.now),
                )
                .map_err(from_store)?;
        }
        self.crash(LifecyclePoint::AfterRotationBudgets)?;

        // 5.
        let (_, state) = self.registry_row(req.successor)?;
        let activated = if state == EpochState::Sealed {
            self.populations
                .activate(req.successor, req.now)
                .map_err(|_| R::RegistryUnavailable)?;
            true
        } else {
            false
        };
        Ok(RotationOutcome {
            retirement,
            linked,
            budgets_provisioned: req.budgets.len(),
            activated,
        })
    }
}
