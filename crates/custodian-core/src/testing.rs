//! Synthetic in-memory test doubles for the ports.
//!
//! These are not production adapters and hold no protected data. They exist
//! so lifecycle behavior can be tested in ordinary CI with public synthetic
//! values only.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::ids::{ActorId, AuthorizationId, IdempotencyKey, PlanDigest, PopulationId, RunId};
use crate::lifecycle::{budget_refundable, DisclosureState, Exposure, ReasonCode, RunState};
use crate::ports::{
    Authorization, Authorizer, CorpusAccess, CorpusHandle, Disclosure, ExecutionOutcome, Executor,
    ProjectionId, Refusal, Reserved, RunRecord, RunRequest, StateStore,
};

/// Authorizer approving a fixed set of plan digests.
pub struct StaticAuthorizer {
    now: u64,
    approved: Mutex<HashMap<PlanDigest, u64>>,
    /// Simulates a buggy authorizer that binds to the wrong plan.
    pub corrupt_plan_binding: bool,
}

impl StaticAuthorizer {
    pub fn new(now: u64) -> Self {
        Self {
            now,
            approved: Mutex::new(HashMap::new()),
            corrupt_plan_binding: false,
        }
    }
    pub fn approve(&self, plan: PlanDigest, expires_at: u64) {
        self.approved.lock().unwrap().insert(plan, expires_at);
    }
}

impl Authorizer for StaticAuthorizer {
    fn authorize(&self, request: &RunRequest) -> Result<Authorization, Refusal> {
        let expires_at = *self
            .approved
            .lock()
            .unwrap()
            .get(&request.plan)
            .ok_or(Refusal(ReasonCode::AuthorizationDenied))?;
        if expires_at <= self.now {
            return Err(Refusal(ReasonCode::AuthorizationExpired));
        }
        let plan = if self.corrupt_plan_binding {
            PlanDigest::new("synthetic-other-plan")
        } else {
            request.plan.clone()
        };
        Ok(Authorization {
            id: AuthorizationId::new("synthetic-authorization"),
            actor: request.actor.clone(),
            plan,
            population: request.population.clone(),
            expires_at,
        })
    }
}

/// Corpus access that returns an opaque synthetic handle and counts opens.
pub struct SyntheticCorpus {
    pub available: bool,
    opens: AtomicUsize,
}

impl SyntheticCorpus {
    pub fn new(available: bool) -> Self {
        Self {
            available,
            opens: AtomicUsize::new(0),
        }
    }
    pub fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }
}

impl CorpusAccess for SyntheticCorpus {
    fn open(&self, _authorization: &Authorization) -> Result<CorpusHandle, Refusal> {
        if !self.available {
            return Err(Refusal(ReasonCode::CorpusUnavailable));
        }
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(CorpusHandle::new(0))
    }
}

struct StoreInner {
    budgets: HashMap<PopulationId, u32>,
    runs: HashMap<RunId, RunRecord>,
    keys: HashMap<IdempotencyKey, RunId>,
    next: u64,
}

/// In-memory atomic store: one mutex makes reserve a single check-and-charge.
pub struct InMemoryStore {
    inner: Mutex<StoreInner>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(StoreInner {
                budgets: HashMap::new(),
                runs: HashMap::new(),
                keys: HashMap::new(),
                next: 0,
            }),
        }
    }
    pub fn set_budget(&self, population: PopulationId, units: u32) {
        self.inner.lock().unwrap().budgets.insert(population, units);
    }
    pub fn budget_remaining(&self, population: &PopulationId) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .budgets
            .get(population)
            .copied()
            .unwrap_or(0)
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore for InMemoryStore {
    fn reserve(
        &self,
        authorization: &Authorization,
        key: &IdempotencyKey,
    ) -> Result<Reserved, Refusal> {
        let mut g = self.inner.lock().unwrap();
        if let Some(run) = g.keys.get(key).cloned() {
            let rec = &g.runs[&run];
            // Reusing a key with a different plan is a binding violation.
            if rec.plan != authorization.plan {
                return Err(Refusal(ReasonCode::PlanMismatch));
            }
            return Ok(Reserved {
                run,
                replay: true,
                state: rec.state,
            });
        }
        let remaining = g
            .budgets
            .get(&authorization.population)
            .copied()
            .unwrap_or(0);
        if remaining == 0 {
            return Err(Refusal(ReasonCode::BudgetExhausted));
        }
        g.budgets
            .insert(authorization.population.clone(), remaining - 1);
        g.next += 1;
        let run = RunId::new(format!("synthetic-run-{}", g.next));
        g.keys.insert(key.clone(), run.clone());
        g.runs.insert(
            run.clone(),
            RunRecord {
                run: run.clone(),
                plan: authorization.plan.clone(),
                population: authorization.population.clone(),
                state: RunState::Reserved,
                exposure: Exposure::NotExposed,
                history: vec![
                    (RunState::Proposed, ReasonCode::Requested),
                    (RunState::Authorized, ReasonCode::Authorized),
                    (RunState::Reserved, ReasonCode::BudgetReserved),
                ],
                budget_refunded: false,
            },
        );
        Ok(Reserved {
            run,
            replay: false,
            state: RunState::Reserved,
        })
    }

    fn transition(&self, run: &RunId, to: RunState, reason: ReasonCode) -> Result<(), Refusal> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .runs
            .get_mut(run)
            .ok_or(Refusal(ReasonCode::InvalidTransition))?;
        if !rec.state.can_transition(to) {
            return Err(Refusal(ReasonCode::InvalidTransition));
        }
        rec.state = to;
        rec.history.push((to, reason));
        let refund = !rec.budget_refunded && budget_refundable(rec.exposure, to);
        if refund {
            rec.budget_refunded = true;
            let population = rec.population.clone();
            *g.budgets.entry(population).or_insert(0) += 1;
        }
        Ok(())
    }

    fn record_exposure(&self, run: &RunId) -> Result<(), Refusal> {
        let mut g = self.inner.lock().unwrap();
        let rec = g
            .runs
            .get_mut(run)
            .ok_or(Refusal(ReasonCode::InvalidTransition))?;
        rec.exposure = Exposure::Exposed;
        rec.history
            .push((rec.state, ReasonCode::ProtectedBytesAcquired));
        Ok(())
    }

    fn get(&self, run: &RunId) -> Option<RunRecord> {
        self.inner.lock().unwrap().runs.get(run).cloned()
    }
}

/// How the scripted executor behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMode {
    Ok,
    /// Simulates a crash or malicious exit after protected bytes were opened.
    Fail,
    /// Returns a result bound to a different plan.
    WrongPlan,
    /// Returns a result that does not cover the authorized roster.
    IncompleteRoster,
}

pub struct ScriptedExecutor {
    pub mode: ExecMode,
    runs: AtomicU64,
}

impl ScriptedExecutor {
    pub fn new(mode: ExecMode) -> Self {
        Self {
            mode,
            runs: AtomicU64::new(0),
        }
    }
    pub fn executions(&self) -> u64 {
        self.runs.load(Ordering::SeqCst)
    }
}

impl Executor for ScriptedExecutor {
    fn execute(
        &self,
        authorization: &Authorization,
        _corpus: &CorpusHandle,
    ) -> Result<ExecutionOutcome, Refusal> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            ExecMode::Fail => Err(Refusal(ReasonCode::ExecutionFailed)),
            ExecMode::WrongPlan => Ok(ExecutionOutcome {
                plan: PlanDigest::new("synthetic-other-plan"),
                roster_complete: true,
                passed: 1,
                total: 1,
            }),
            ExecMode::IncompleteRoster => Ok(ExecutionOutcome {
                plan: authorization.plan.clone(),
                roster_complete: false,
                passed: 1,
                total: 1,
            }),
            ExecMode::Ok => Ok(ExecutionOutcome {
                plan: authorization.plan.clone(),
                roster_complete: true,
                passed: 3,
                total: 4,
            }),
        }
    }
}

struct Projection {
    requester: ActorId,
    state: DisclosureState,
}

pub struct InMemoryDisclosure {
    inner: Mutex<(HashMap<ProjectionId, Projection>, u64, HashSet<RunId>)>,
}

impl InMemoryDisclosure {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new((HashMap::new(), 0, HashSet::new())),
        }
    }
}

impl Default for InMemoryDisclosure {
    fn default() -> Self {
        Self::new()
    }
}

impl Disclosure for InMemoryDisclosure {
    fn prepare(
        &self,
        run: &RunId,
        _outcome: &ExecutionOutcome,
        requester: &ActorId,
    ) -> Result<ProjectionId, Refusal> {
        let mut g = self.inner.lock().unwrap();
        // One projection per run: no duplicate publication.
        if !g.2.insert(run.clone()) {
            return Err(Refusal(ReasonCode::DuplicateRequest));
        }
        g.1 += 1;
        let id = ProjectionId(format!("synthetic-projection-{}", g.1));
        g.0.insert(
            id.clone(),
            Projection {
                requester: requester.clone(),
                state: DisclosureState::Prepared,
            },
        );
        Ok(id)
    }

    fn approve(&self, projection: &ProjectionId, approver: &ActorId) -> Result<(), Refusal> {
        let mut g = self.inner.lock().unwrap();
        let p =
            g.0.get_mut(projection)
                .ok_or(Refusal(ReasonCode::InvalidTransition))?;
        // The requester cannot approve its own disclosure.
        if &p.requester == approver || !p.state.can_transition(DisclosureState::Approved) {
            return Err(Refusal(ReasonCode::DisclosureNotPermitted));
        }
        p.state = DisclosureState::Approved;
        Ok(())
    }

    fn release(&self, projection: &ProjectionId) -> Result<(), Refusal> {
        let mut g = self.inner.lock().unwrap();
        let p =
            g.0.get_mut(projection)
                .ok_or(Refusal(ReasonCode::InvalidTransition))?;
        if !p.state.can_transition(DisclosureState::Released) {
            return Err(Refusal(ReasonCode::DisclosureNotPermitted));
        }
        p.state = DisclosureState::Released;
        Ok(())
    }

    fn state(&self, projection: &ProjectionId) -> Option<DisclosureState> {
        self.inner
            .lock()
            .unwrap()
            .0
            .get(projection)
            .map(|p| p.state)
    }
}
