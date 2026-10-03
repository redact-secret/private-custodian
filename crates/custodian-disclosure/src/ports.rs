//! Ports of the disclosure service. Each is a small typed seam where the
//! durable store, a C9 eligibility source or a delivery channel plugs in, and
//! where a synthetic double replaces it. Errors are fixed
//! [`DisclosureReason`]s.

use custodian_contracts::common::PopulationBinding;
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::types::{CandidateDigest, ExecutionId, ProjectionDigest, Timestamp};
use custodian_core::{ActorId, RunId};
use custodian_store::{
    ChargeOutcome, DisclosureHistoryEntry, ReleaseCharge, ReleaseScope, SqliteStore, StoreError,
};

use crate::reason::DisclosureReason;
use crate::released::ReleasedEnvelope;

/// Durable state the disclosure service needs: the precondition gate, release
/// and query budgets, audit acknowledgement of the charge, and the history of
/// what past releases revealed.
pub trait DisclosureStore: Send + Sync {
    /// The attempt completed, settled, and its terminal audit event is
    /// durably exported; the store is not awaiting reconciliation.
    fn precondition(&self, attempt: &RunId) -> Result<(), DisclosureReason>;
    /// The request and reservation identities the store recorded for the
    /// attempt, so an execution record can be tied to the attempt whose
    /// audit trail gates disclosure.
    fn attempt_binding(&self, attempt: &RunId) -> Result<(String, String), DisclosureReason>;
    fn provision(
        &self,
        scope: &ReleaseScope<'_>,
        limit: u64,
        actor: &ActorId,
        now: u64,
    ) -> Result<(), DisclosureReason>;
    fn charge(&self, charge: &ReleaseCharge<'_>) -> Result<ChargeOutcome, DisclosureReason>;
    /// Every audit event of the charge has been acknowledged by the ledger.
    fn charge_exported(&self, charge_id: &str) -> Result<bool, DisclosureReason>;
    fn history(&self, series: &str) -> Result<Vec<DisclosureHistoryEntry>, DisclosureReason>;
    /// Append after `expected_seq`; a concurrent append is
    /// [`DisclosureReason::HistoryConflict`].
    fn append(
        &self,
        series: &str,
        expected_seq: u64,
        release_id: &str,
        payload: &str,
        now: u64,
    ) -> Result<u64, DisclosureReason>;
}

fn store_err(e: StoreError) -> DisclosureReason {
    match e {
        StoreError::Conflict | StoreError::IdentityConflict => DisclosureReason::HistoryConflict,
        _ => DisclosureReason::StoreUnavailable,
    }
}

impl DisclosureStore for SqliteStore {
    fn precondition(&self, attempt: &RunId) -> Result<(), DisclosureReason> {
        self.check_disclosure_precondition(attempt)
            .map_err(|_| DisclosureReason::PreconditionNotMet)
    }

    fn attempt_binding(&self, attempt: &RunId) -> Result<(String, String), DisclosureReason> {
        let rec = self
            .attempt(attempt)
            .map_err(store_err)?
            .ok_or(DisclosureReason::PreconditionNotMet)?;
        let reservation = rec
            .reservation_id
            .ok_or(DisclosureReason::PreconditionNotMet)?;
        Ok((rec.request_id, reservation))
    }

    fn provision(
        &self,
        scope: &ReleaseScope<'_>,
        limit: u64,
        actor: &ActorId,
        now: u64,
    ) -> Result<(), DisclosureReason> {
        self.provision_release_budget(scope, limit, actor, now)
            .map(|_| ())
            .map_err(store_err)
    }

    fn charge(&self, charge: &ReleaseCharge<'_>) -> Result<ChargeOutcome, DisclosureReason> {
        self.charge_release_query(charge).map_err(store_err)
    }

    fn charge_exported(&self, charge_id: &str) -> Result<bool, DisclosureReason> {
        self.charge_audit_exported(charge_id).map_err(store_err)
    }

    fn history(&self, series: &str) -> Result<Vec<DisclosureHistoryEntry>, DisclosureReason> {
        self.disclosure_history(series).map_err(store_err)
    }

    fn append(
        &self,
        series: &str,
        expected_seq: u64,
        release_id: &str,
        payload: &str,
        now: u64,
    ) -> Result<u64, DisclosureReason> {
        self.append_disclosure_history(series, expected_seq, release_id, payload, now)
            .map_err(store_err)
    }
}

/// Maps an internal population binding to its disclosure-safe public
/// identity: an opaque random reference, or a keyed commitment. Never a plain
/// hash of population content (docs/contracts.md). Deployments back this with
/// the corpus registry (`PopulationRegistry::public_commitment`).
pub trait PublicPopulationNames: Send + Sync {
    fn public_ref(&self, binding: &PopulationBinding) -> Option<PublicPopulationRef>;
}

/// Why the release-time eligibility recheck refused. Fieldless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EligibilityRefusal {
    Revoked,
    Contaminated,
    EpochRetired,
    Unknown,
}

/// What the eligibility hook is asked about. Internal values; the hook must
/// not copy them into anything public.
pub struct EligibilitySubject<'a> {
    pub candidate: &'a CandidateDigest,
    pub population: &'a PopulationBinding,
    pub execution: &'a ExecutionId,
    pub projection: &'a ProjectionDigest,
}

/// Release-time recheck for revocation, contamination and epoch state.
///
/// C8 defines the seam; C9 implements it over its revocation and epoch
/// records. It is called twice per release: before any ledger write and again
/// immediately before delivery. There is deliberately no `Default`: a
/// deployment must pass an implementation. [`crate::testing::UncheckedEligibility`]
/// exists for tests and states in its name that it checks nothing.
pub trait ReleaseEligibility: Send + Sync {
    fn check(
        &self,
        subject: &EligibilitySubject<'_>,
        now: Timestamp,
    ) -> Result<(), EligibilityRefusal>;
}

/// Delivery channel for a released envelope. The only argument is a
/// [`ReleasedEnvelope`], which only a completed release can construct, so no
/// internal record can be handed to a destination.
pub trait Sink: Send + Sync {
    fn deliver(&self, released: &ReleasedEnvelope) -> Result<(), DisclosureReason>;
}
