//! Vendor-neutral ports (CONVENTIONS.md, "Implementation choices").
//!
//! Core contracts name no SQLite, filesystem, GitHub, cloud or engine. Each
//! trait is the seam where an adapter plugs in and where a synthetic test
//! double replaces it. Errors are fixed [`ReasonCode`]s, never free-form text,
//! so no input value, path or secret can travel through an error.

use crate::ids::{ActorId, AuthorizationId, IdempotencyKey, PlanDigest, PopulationId, RunId};
use crate::lifecycle::{Exposure, ReasonCode, RunState};

/// A refusal carrying only a fixed reason code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal(pub ReasonCode);

/// A request to run an exact frozen plan. The plan digest is the only thing
/// authorization may bind to.
#[derive(Clone, Debug)]
pub struct RunRequest {
    pub actor: ActorId,
    pub plan: PlanDigest,
    pub population: PopulationId,
    pub idempotency_key: IdempotencyKey,
}

/// An issued authorization bound to actor, exact plan digest, population and
/// expiry. `expires_at` is a logical timestamp until C2 fixes time handling.
#[derive(Clone, Debug)]
pub struct Authorization {
    pub id: AuthorizationId,
    pub actor: ActorId,
    pub plan: PlanDigest,
    pub population: PopulationId,
    pub expires_at: u64,
}

/// Result of an atomic reservation. `replay` is true when the idempotency key
/// had already been reserved; a replay never charges the budget again.
#[derive(Clone, Debug)]
pub struct Reserved {
    pub run: RunId,
    pub replay: bool,
    pub state: RunState,
}

/// Durable record of a run. History carries prior state and reason code per
/// transition.
#[derive(Clone, Debug)]
pub struct RunRecord {
    pub run: RunId,
    pub plan: PlanDigest,
    pub population: PopulationId,
    pub state: RunState,
    pub exposure: Exposure,
    pub history: Vec<(RunState, ReasonCode)>,
    pub budget_refunded: bool,
}

/// Opaque handle to authorized protected bytes. It deliberately exposes no
/// content and implements no `Debug` of its payload.
pub struct CorpusHandle {
    token: u64,
}

impl CorpusHandle {
    pub fn new(token: u64) -> Self {
        Self { token }
    }
    pub fn token(&self) -> u64 {
        self.token
    }
}

impl core::fmt::Debug for CorpusHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CorpusHandle(<opaque>)")
    }
}

/// Validated shape of an execution result. Real measurement artifacts are a
/// C2 contract; this carries only what the lifecycle must check.
#[derive(Clone, Debug)]
pub struct ExecutionOutcome {
    pub plan: PlanDigest,
    pub roster_complete: bool,
    pub passed: u32,
    pub total: u32,
}

/// Authenticates the actor and issues or refuses an authorization.
pub trait Authorizer: Send + Sync {
    fn authorize(&self, request: &RunRequest) -> Result<Authorization, Refusal>;
}

/// Grants access to authorized protected bytes. Opening a handle is the
/// exposure event; budget must already be reserved.
pub trait CorpusAccess: Send + Sync {
    fn open(&self, authorization: &Authorization) -> Result<CorpusHandle, Refusal>;
}

/// Atomic budget and durable state. Every implementation must:
/// - make `reserve` one atomic check-and-charge, idempotent per key;
/// - reject transitions not allowed by [`RunState::can_transition`];
/// - apply [`crate::budget_refundable`] when a run reaches a terminal failure.
pub trait StateStore: Send + Sync {
    fn reserve(
        &self,
        authorization: &Authorization,
        key: &IdempotencyKey,
    ) -> Result<Reserved, Refusal>;
    fn transition(&self, run: &RunId, to: RunState, reason: ReasonCode) -> Result<(), Refusal>;
    fn record_exposure(&self, run: &RunId) -> Result<(), Refusal>;
    fn get(&self, run: &RunId) -> Option<RunRecord>;
}

/// Runs the pinned engine and scanner inside an enforced isolation boundary.
pub trait Executor: Send + Sync {
    fn execute(
        &self,
        authorization: &Authorization,
        corpus: &CorpusHandle,
    ) -> Result<ExecutionOutcome, Refusal>;
}

// Retired port (C10, ADR 0084): the `Disclosure` trait, `ProjectionId` and the
// in-memory double that lived here were a scaffold for a disclosure lifecycle
// the typed `custodian_disclosure::DisclosureService` now implements, with
// signed receipts, budgets and eligibility. Nothing in this crate depends on
// a disclosure seam, so a second, weaker one cannot be wired by mistake.
