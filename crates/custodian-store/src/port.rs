//! Adapter for the vendor-neutral `custodian_core::ports::StateStore`.
//!
//! The port carries opaque string identities and no timestamp, so this path
//! stores `origin = 'port'` requests (no contract documents) and takes time
//! from the store's [`crate::Clock`]. It is the same transactions, the same
//! transition table, the same lease and the same settlement as the contract
//! API; only the up-front document checks differ. Budget for the port is
//! per population: provision it with [`SqliteStore::provision_port_budget`].

use custodian_core::ports::{Authorization, Refusal, Reserved, RunRecord, StateStore};
use custodian_core::{ActorId, IdempotencyKey, ReasonCode, RunId, RunState};

use custodian_contracts::execution::ExecutionOutcome;

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::model::{Lease, StartCommand};
use crate::ops::{digest_of, reserve_tx, scope_key_of, Intake};
use crate::store::*;

const PORT_OWNER: &str = "core-port";
const PORT_ACTOR: &str = "core-port";

fn port_scope(population: &str) -> (String, String) {
    let json =
        serde_json::json!({"scope": "port_population", "population": population}).to_string();
    (scope_key_of("run", json.as_bytes()), json)
}

impl SqliteStore {
    /// Provision (or raise) the run budget of a population for the port path.
    pub fn provision_port_budget(
        &self,
        population: &custodian_core::PopulationId,
        limit: u64,
        actor: &ActorId,
        now: u64,
    ) -> Result<crate::model::BudgetStatus, StoreError> {
        let (key, json) = port_scope(population.as_str());
        self.provision_raw("run", &key, &json, limit, actor, now)
    }

    /// Counters of a population's port budget.
    pub fn port_budget_status(
        &self,
        population: &custodian_core::PopulationId,
    ) -> Result<Option<crate::model::BudgetStatus>, StoreError> {
        let (key, _) = port_scope(population.as_str());
        self.budget_status_by_key(&key)
    }

    fn port_lease(&self, row: &AttemptRow) -> Lease {
        Lease {
            attempt: RunId::new(row.attempt_id.clone()),
            owner: PORT_OWNER.to_owned(),
            token: from_sql(row.lease_token),
            expires_at: row.lease_expires_at.map_or(0, from_sql),
        }
    }

    fn port_settle(
        &self,
        row: &AttemptRow,
        outcome: ExecutionOutcome,
        reason: ReasonCode,
        now: u64,
    ) -> Result<(), StoreError> {
        let actor = ActorId::new(PORT_ACTOR);
        match row.state {
            RunState::Reserved => match outcome {
                ExecutionOutcome::Cancelled => {
                    self.cancel(&RunId::new(row.attempt_id.clone()), &actor, reason, now)?;
                }
                ExecutionOutcome::Expired => {
                    // Only a lapsed window expires; recovery owns that.
                    if row.lease_expires_at.is_none_or(|e| from_sql(e) > now) {
                        return Err(StoreError::InvalidTransition);
                    }
                    self.recover(&actor, now)?;
                }
                _ => {
                    self.fail_before_start(
                        &RunId::new(row.attempt_id.clone()),
                        &actor,
                        reason,
                        now,
                    )?;
                }
            },
            RunState::Running | RunState::Validating => {
                if outcome == ExecutionOutcome::Cancelled {
                    self.cancel(&RunId::new(row.attempt_id.clone()), &actor, reason, now)?;
                } else {
                    self.finish(&self.port_lease(row), outcome, reason, &actor, now)?;
                }
            }
            _ => return Err(StoreError::InvalidTransition),
        }
        Ok(())
    }
}

impl StateStore for SqliteStore {
    fn reserve(
        &self,
        authorization: &Authorization,
        key: &IdempotencyKey,
    ) -> Result<Reserved, Refusal> {
        let now = self.cfg.clock.now();
        if authorization.expires_at <= now {
            return Err(Refusal(ReasonCode::AuthorizationExpired));
        }
        let now_i = sql_time(now)?;
        let expires = sql_time(authorization.expires_at)?;
        let window = sql_time(self.cfg.port_reservation_secs)?;
        let (scope_key, _) = port_scope(authorization.population.as_str());
        let plan = authorization.plan.as_str();
        let population = authorization.population.as_str();
        let actor = authorization.actor.as_str();
        let request_digest = digest_of(&["port-request", plan, population]);
        let intake = Intake {
            request_id: format!("port:{}", key.as_str()),
            idempotency_key: key.as_str().to_owned(),
            request_digest,
            plan_digest: plan.to_owned(),
            scope_key,
            kind: "run",
            units: 1,
            max_retries: 0,
            actor: actor.to_owned(),
            requested_at: now_i,
            origin: "port",
            subject: Some(population.to_owned()),
            document: None,
            approval_id: authorization.id.as_str().to_owned(),
            approval_digest: digest_of(&[
                "port-authorization",
                authorization.id.as_str(),
                plan,
                population,
                &expires.to_string(),
            ]),
            approver: actor.to_owned(),
            activation_id: "port".to_owned(),
            activation_seq: 0,
            issued_at: now_i,
            expires_at: expires,
            approval_doc: None,
        };
        let out = self.write(FaultOp::Reserve, |tx| {
            reserve_tx(tx, &intake, now_i, window)
        })?;
        if out.state == RunState::Denied {
            return Err(Refusal(out.reason));
        }
        Ok(Reserved {
            run: out.attempt,
            replay: out.replay,
            state: out.state,
        })
    }

    fn transition(&self, run: &RunId, to: RunState, reason: ReasonCode) -> Result<(), Refusal> {
        let now = self.cfg.clock.now();
        let row = self
            .read(|tx| load_attempt(tx, run.as_str()))?
            .ok_or(Refusal(ReasonCode::InvalidTransition))?;
        let actor = ActorId::new(PORT_ACTOR);
        match (row.state, to) {
            (RunState::Reserved, RunState::Running) => {
                self.start_attempt(&StartCommand {
                    attempt: run,
                    owner: PORT_OWNER,
                    actor: &actor,
                    now,
                    lease_secs: self.cfg.port_lease_secs,
                    observed: None,
                    max_state_age_secs: 0,
                })?;
            }
            (RunState::Running, RunState::Validating) => {
                self.begin_validation(&self.port_lease(&row), &actor, now)?;
            }
            (RunState::Validating, RunState::Completed) => {
                self.finish(
                    &self.port_lease(&row),
                    ExecutionOutcome::Success,
                    reason,
                    &actor,
                    now,
                )?;
            }
            (RunState::Reserved | RunState::Running | RunState::Validating, RunState::Failed) => {
                self.port_settle(&row, ExecutionOutcome::Failed, reason, now)?;
            }
            (RunState::Reserved | RunState::Running, RunState::Cancelled) => {
                self.port_settle(&row, ExecutionOutcome::Cancelled, reason, now)?;
            }
            (RunState::Reserved, RunState::Expired) => {
                self.port_settle(&row, ExecutionOutcome::Expired, reason, now)?;
            }
            _ => return Err(Refusal(ReasonCode::InvalidTransition)),
        }
        Ok(())
    }

    fn record_exposure(&self, run: &RunId) -> Result<(), Refusal> {
        let now = self.cfg.clock.now();
        let row = self
            .read(|tx| load_attempt(tx, run.as_str()))?
            .ok_or(Refusal(ReasonCode::InvalidTransition))?;
        SqliteStore::record_exposure(self, &self.port_lease(&row), &ActorId::new(PORT_ACTOR), now)?;
        Ok(())
    }

    fn get(&self, run: &RunId) -> Option<RunRecord> {
        self.read(|tx| {
            let Some(row) = load_attempt(tx, run.as_str())? else {
                return Ok(None);
            };
            let (plan, subject): (String, Option<String>) = tx.query_row(
                "SELECT plan_digest, subject FROM requests WHERE request_id = ?1",
                [&row.request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let history = crate::ops::history_tx(tx, &row.attempt_id)?
                .into_iter()
                .map(|t| (t.to, t.reason))
                .collect();
            let refunded: i64 = tx.query_row(
                "SELECT COUNT(*) FROM settlements WHERE attempt_id = ?1 AND result = 'refunded'",
                [&row.attempt_id],
                |r| r.get(0),
            )?;
            Ok(Some(RunRecord {
                run: run.clone(),
                plan: custodian_core::PlanDigest::new(plan),
                population: custodian_core::PopulationId::new(subject.unwrap_or_default()),
                state: row.state,
                exposure: row.exposure,
                history,
                budget_refunded: refunded > 0,
            }))
        })
        .ok()
        .flatten()
    }
}
