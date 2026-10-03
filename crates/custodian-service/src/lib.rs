//! Control service scaffold.
//!
//! [`ControlService`] orders the lifecycle over the core ports: authorize,
//! check plan binding, reserve budget atomically, only then open protected
//! bytes, execute, validate, complete. Disclosure is a separate step that a
//! completed run does not imply. This scaffold orders the run lifecycle only;
//! disclosure is the typed `custodian_disclosure::DisclosureService` (the core
//! `Disclosure` port was retired in C10, ADR 0084). The deployed startup
//! sequence, the operator CLI and the durable adapters are in
//! `custodian-cli`.

#![forbid(unsafe_code)]

use custodian_core::ports::{
    Authorizer, CorpusAccess, ExecutionOutcome, Executor, Refusal, RunRequest, StateStore,
};
use custodian_core::{ReasonCode, RunId, RunState};

/// Result of a run request.
#[derive(Debug)]
pub struct RunReport {
    pub run: RunId,
    pub state: RunState,
    /// True when the idempotency key was already reserved; nothing re-executed.
    pub replay: bool,
    pub outcome: Option<ExecutionOutcome>,
}

pub struct ControlService<A, C, S, E> {
    pub authorizer: A,
    pub corpus: C,
    pub store: S,
    pub executor: E,
}

impl<A, C, S, E> ControlService<A, C, S, E>
where
    A: Authorizer,
    C: CorpusAccess,
    S: StateStore,
    E: Executor,
{
    pub fn new(authorizer: A, corpus: C, store: S, executor: E) -> Self {
        Self {
            authorizer,
            corpus,
            store,
            executor,
        }
    }

    /// Run an authorized plan. Every refusal is a fixed reason code.
    pub fn run(&self, request: &RunRequest) -> Result<RunReport, Refusal> {
        let authorization = self.authorizer.authorize(request)?;
        // Defense in depth: never trust the authorizer to have bound the plan.
        if authorization.plan != request.plan || authorization.population != request.population {
            return Err(Refusal(ReasonCode::PlanMismatch));
        }

        let reserved = self
            .store
            .reserve(&authorization, &request.idempotency_key)?;
        if reserved.replay {
            return Ok(RunReport {
                run: reserved.run,
                state: reserved.state,
                replay: true,
                outcome: None,
            });
        }
        let run = reserved.run;

        // Budget is reserved; only now may protected bytes be acquired.
        self.store
            .transition(&run, RunState::Running, ReasonCode::BudgetReserved)?;
        let corpus = match self.corpus.open(&authorization) {
            Ok(handle) => handle,
            Err(r) => {
                // Not exposed: the failure path may refund under core policy.
                self.store.transition(&run, RunState::Failed, r.0)?;
                return Err(r);
            }
        };
        self.store.record_exposure(&run)?;

        let outcome = match self.executor.execute(&authorization, &corpus) {
            Ok(o) => o,
            Err(r) => {
                // Exposed: core policy forbids a refund.
                self.store.transition(&run, RunState::Failed, r.0)?;
                return Err(r);
            }
        };

        self.store
            .transition(&run, RunState::Validating, ReasonCode::Completed)?;
        if outcome.plan != authorization.plan || !outcome.roster_complete {
            self.store
                .transition(&run, RunState::Failed, ReasonCode::InvalidArtifact)?;
            return Err(Refusal(ReasonCode::InvalidArtifact));
        }
        self.store
            .transition(&run, RunState::Completed, ReasonCode::Completed)?;
        Ok(RunReport {
            run,
            state: RunState::Completed,
            replay: false,
            outcome: Some(outcome),
        })
    }
}
