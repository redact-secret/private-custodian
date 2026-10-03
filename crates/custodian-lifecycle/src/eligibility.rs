//! Current eligibility: the real [`ReleaseEligibility`] (the C9 hook C8 left)
//! and the dispatch-time guard (ADR 0071).
//!
//! One evaluation serves both gates. It consults, in this order and from the
//! authoritative store, never from a prior receipt:
//!
//! 1. the epoch's standing (contamination, retirement);
//! 2. every recorded revocation obligation that names the epoch's population,
//!    the candidate or a guarded disclosure policy, published or not;
//! 3. the current, fresh state of each guarded policy activation.
//!
//! Anything unknown (a store error, a missing activation observation) is a
//! refusal. A historical receipt is evidence of what happened; it never
//! substitutes for this check.

use std::sync::Arc;

use custodian_contracts::common::{ActivationRef, PolicyRef};
use custodian_contracts::error::BindingError;
use custodian_contracts::policy::{check_current, ObservedActivation};
use custodian_contracts::types::{CandidateDigest, EpochId, Timestamp};
use custodian_disclosure::{EligibilityRefusal, EligibilitySubject, ReleaseEligibility};
use custodian_store::{ObligationAction, ObligationTarget, SqliteStore};
use custodian_worker::ports::RunLedger;
use custodian_worker::reason::{Result as WResult, WorkerReason};

/// Where the current state of a policy activation is read from. The control
/// service implements it over its authoritative activation store.
pub trait ActivationSource: Send + Sync {
    /// The latest state of the activation `binding` names, with the time it
    /// was read. `None` when it cannot be observed.
    fn observe(&self, binding: &ActivationRef) -> Option<ObservedActivation>;
}

/// The eligibility gate. Build one per deployment and share it.
pub struct LifecycleEligibility<'a> {
    store: &'a SqliteStore,
    policies: Vec<PolicyRef>,
    activations: Vec<(ActivationRef, &'a dyn ActivationSource, u64)>,
}

impl<'a> LifecycleEligibility<'a> {
    pub fn new(store: &'a SqliteStore) -> Self {
        Self {
            store,
            policies: Vec::new(),
            activations: Vec::new(),
        }
    }

    /// A disclosure (or other) policy whose revocation must stop use.
    pub fn guarding_policy(mut self, policy: PolicyRef) -> Self {
        self.policies.push(policy);
        self
    }

    /// A policy activation that must be current and fresh (at most
    /// `max_state_age_secs`, capped by the contract's ceiling) at the gate.
    pub fn requiring_activation(
        mut self,
        binding: ActivationRef,
        source: &'a dyn ActivationSource,
        max_state_age_secs: u64,
    ) -> Self {
        self.activations.push((binding, source, max_state_age_secs));
        self
    }

    /// The single evaluation behind both gates.
    pub fn evaluate(
        &self,
        candidate: &CandidateDigest,
        epoch: &EpochId,
        now: Timestamp,
    ) -> Result<(), EligibilityRefusal> {
        // 0. A store that may be an older restore cannot vouch for anything:
        // it could be missing a contamination recorded after its snapshot.
        if self.store.needs_reconcile().unwrap_or(true) {
            return Err(EligibilityRefusal::Unknown);
        }
        // 1. Standing.
        let standing = self
            .store
            .epoch_standing(epoch.as_str())
            .map_err(|_| EligibilityRefusal::Unknown)?;
        if let Some(s) = standing {
            if s.standing.contamination.blocks_use() {
                return Err(EligibilityRefusal::Contaminated);
            }
            if s.standing.retired {
                return Err(EligibilityRefusal::EpochRetired);
            }
        }

        // 2. Recorded revocations, whether or not the feed carries them yet.
        let policy_refs: Vec<String> = self
            .policies
            .iter()
            .map(policy_ref_key)
            .collect::<Result<_, _>>()
            .map_err(|_| EligibilityRefusal::Unknown)?;
        let mut targets: Vec<(ObligationTarget, &str)> = vec![
            (ObligationTarget::Population, epoch.as_str()),
            (ObligationTarget::Candidate, candidate.as_str()),
        ];
        targets.extend(
            policy_refs
                .iter()
                .map(|p| (ObligationTarget::Policy, p.as_str())),
        );
        let hits = self
            .store
            .obligation_hits(&targets)
            .map_err(|_| EligibilityRefusal::Unknown)?;
        if hits
            .iter()
            .any(|h| h.action == ObligationAction::Contaminated)
        {
            return Err(EligibilityRefusal::Contaminated);
        }
        if !hits.is_empty() {
            return Err(EligibilityRefusal::Revoked);
        }

        // 3. Policy activations, current and fresh.
        for (binding, source, max_age) in &self.activations {
            let observed = source.observe(binding).ok_or(EligibilityRefusal::Unknown)?;
            check_current(binding, &observed, now, *max_age).map_err(|e| match e {
                BindingError::ActivationRevoked | BindingError::ActivationSuperseded => {
                    EligibilityRefusal::Revoked
                }
                _ => EligibilityRefusal::Unknown,
            })?;
        }
        Ok(())
    }
}

/// Internal key a `Policy` obligation uses for a policy reference:
/// `kind:domain:name:version`. Every part is a snake_case word, a label
/// (letters, digits, `.`, `_`, `-`) or a number, so the key is a safe
/// identifier and parses back unambiguously.
pub fn policy_ref_key(policy: &PolicyRef) -> Result<String, custodian_contracts::ContractError> {
    let v =
        serde_json::to_value(policy).map_err(|_| custodian_contracts::ContractError::Malformed)?;
    let part = |k: &str| {
        v.get(k)
            .and_then(|x| {
                x.as_str()
                    .map(str::to_owned)
                    .or_else(|| x.as_u64().map(|n| n.to_string()))
            })
            .ok_or(custodian_contracts::ContractError::Malformed)
    };
    Ok(format!(
        "{}:{}:{}:{}",
        part("kind")?,
        part("domain")?,
        part("name")?,
        part("version")?
    ))
}

/// Inverse of [`policy_ref_key`]; `None` for anything else.
pub fn parse_policy_key(key: &str) -> Option<PolicyRef> {
    let mut it = key.split(':');
    let (kind, domain, name, version) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let v = serde_json::json!({
        "kind": kind, "domain": domain, "name": name, "version": version.parse::<u64>().ok()?,
    });
    serde_json::from_value(v).ok()
}

impl ReleaseEligibility for LifecycleEligibility<'_> {
    /// Called twice per release by `DisclosureService`: before any ledger
    /// write and again immediately before delivery. Both calls evaluate the
    /// current state; neither trusts the other.
    fn check(
        &self,
        subject: &EligibilitySubject<'_>,
        now: Timestamp,
    ) -> Result<(), EligibilityRefusal> {
        self.evaluate(subject.candidate, &subject.population.epoch_id, now)
    }
}

/// What the dispatcher is about to run, as far as eligibility is concerned.
pub trait DispatchGuard: Send + Sync {
    fn permit(
        &self,
        candidate: &CandidateDigest,
        epoch: &EpochId,
        now: Timestamp,
    ) -> Result<(), EligibilityRefusal>;
}

impl DispatchGuard for LifecycleEligibility<'_> {
    fn permit(
        &self,
        candidate: &CandidateDigest,
        epoch: &EpochId,
        now: Timestamp,
    ) -> Result<(), EligibilityRefusal> {
        self.evaluate(candidate, epoch, now)
    }
}

/// A `RunLedger` that re-checks eligibility immediately before the two
/// points that matter and otherwise delegates:
///
/// * `start`, the lease and `reserved -> running`;
/// * `record_exposure`, the last step before protected bytes are opened.
///
/// A refusal is `WorkerReason::EligibilityDenied`, which the dispatcher
/// settles as a refunded pre-exposure failure. The inner store ledger applies
/// the same standing rule again inside its own transaction, so a
/// contamination that commits between this check and the store call is still
/// caught; the guard adds the revocation and activation checks the store does
/// not know about.
pub struct GuardedRunLedger<'a, L: RunLedger> {
    inner: L,
    guard: &'a dyn DispatchGuard,
    candidate: CandidateDigest,
    epoch: EpochId,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl<'a, L: RunLedger> GuardedRunLedger<'a, L> {
    pub fn new(
        inner: L,
        guard: &'a dyn DispatchGuard,
        candidate: CandidateDigest,
        epoch: EpochId,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            inner,
            guard,
            candidate,
            epoch,
            clock,
        }
    }

    fn permit(&self) -> WResult<()> {
        let now = Timestamp::new((self.clock)()).map_err(|_| WorkerReason::EligibilityDenied)?;
        self.guard
            .permit(&self.candidate, &self.epoch, now)
            .map_err(|_| WorkerReason::EligibilityDenied)
    }
}

impl<L: RunLedger> RunLedger for GuardedRunLedger<'_, L> {
    fn start(&self) -> WResult<()> {
        self.permit()?;
        self.inner.start()
    }

    fn fail_before_start(&self, reason: custodian_core::ReasonCode) -> WResult<()> {
        self.inner.fail_before_start(reason)
    }

    fn heartbeat(&self) -> WResult<()> {
        self.inner.heartbeat()
    }

    fn record_exposure(&self) -> WResult<()> {
        self.permit()?;
        self.inner.record_exposure()
    }

    fn begin_validation(&self) -> WResult<()> {
        self.inner.begin_validation()
    }

    fn finish(
        &self,
        outcome: custodian_contracts::execution::ExecutionOutcome,
        reason: custodian_core::ReasonCode,
    ) -> WResult<()> {
        self.inner.finish(outcome, reason)
    }
}
