//! Independent janitor (ADR 0144). It reads only the provider's exact owned
//! inventory and the custodian-owned attempt store. It never consults the
//! worker, a result, a transport token or the gates, never delivers input and
//! never reuses, stops or resumes an instance: the only action is terminate,
//! and an attempt is closed only after termination is verified by `describe`.
use crate::port::*;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JanitorPolicy {
    /// Hard bound on billable lifetime of any owned instance, in provider seconds.
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Owned instances verified `Terminated` by this sweep.
    pub terminated: Vec<InstanceId>,
    /// Subset of `terminated` with no record, or not the recorded instance.
    pub orphans: Vec<InstanceId>,
    /// Subset of `terminated` killed only for exceeding max lifetime.
    pub expired: Vec<InstanceId>,
    /// Terminate failed or could not be verified; retried by the next sweep.
    pub unverified: Vec<InstanceId>,
    /// Attempts closed (termination verified or no live instance) by this sweep.
    pub closed_attempts: Vec<AttemptKey>,
    /// Owned, within lifetime, owned by an open attempt: left to the coordinator.
    pub left_running: Vec<InstanceId>,
}

pub struct Janitor<'a, P: Provider, S: AttemptStore> {
    pub provider: &'a P,
    pub store: &'a S,
    pub policy: JanitorPolicy,
}

impl<'a, P: Provider, S: AttemptStore> Janitor<'a, P, S> {
    pub fn new(provider: &'a P, store: &'a S, policy: JanitorPolicy) -> Self {
        Self {
            provider,
            store,
            policy,
        }
    }

    /// One reconciliation pass at provider time `now`. Idempotent; safe to run
    /// concurrently with a coordinator (all record writes are compare-and-swap
    /// and a lost race is simply retried by the next sweep).
    pub fn sweep(&self, now: u64) -> Result<SweepReport, ProviderError> {
        let mut report = SweepReport::default();
        let mut killed: BTreeSet<String> = BTreeSet::new();
        let records = self.store.list().map_err(|_| ProviderError::Unavailable)?;
        let inventory = self.provider.list_owned()?;
        for inst in inventory
            .iter()
            .filter(|i| i.state != InstanceState::Terminated)
        {
            let rec = records.iter().find(|(_, r)| r.token == inst.client_token);
            let expired = now.saturating_sub(inst.launched_at) > self.policy.max_lifetime_secs;
            let (kill, orphan) = match rec {
                None => (true, true),
                Some((_, r)) => {
                    let siblings = inventory
                        .iter()
                        .filter(|o| {
                            o.state != InstanceState::Terminated
                                && o.client_token == inst.client_token
                        })
                        .count();
                    // A recorded different instance, or several instances for a
                    // token with no recorded one: ambiguous, never guess.
                    let duplicate = match &r.instance {
                        Some(x) => *x != inst.instance,
                        None => siblings > 1,
                    };
                    let dead = r.terminated
                        || matches!(
                            r.phase,
                            Phase::Ambiguous | Phase::Failed | Phase::Settled | Phase::Terminated
                        );
                    (duplicate || dead || expired, duplicate)
                }
            };
            if !kill {
                report.left_running.push(inst.instance.clone());
                continue;
            }
            if self.verified_terminate(&inst.instance) {
                killed.insert(inst.client_token.clone());
                report.terminated.push(inst.instance.clone());
                if orphan {
                    report.orphans.push(inst.instance.clone());
                } else if expired && rec.is_some_and(|(_, r)| !r.terminated) {
                    report.expired.push(inst.instance.clone());
                }
            } else {
                report.unverified.push(inst.instance.clone());
            }
        }
        // Close attempts that can no longer have a live instance.
        let live: BTreeSet<String> = self
            .provider
            .list_owned()?
            .into_iter()
            .filter(|i| i.state != InstanceState::Terminated)
            .map(|i| i.client_token)
            .collect();
        for (key, rec) in records {
            // A pre-launch intent is closed only if the janitor had to kill its
            // instance(s); otherwise its coordinator may still be about to launch.
            let pending = rec.phase == Phase::LaunchIntent && !killed.contains(&rec.token);
            if rec.terminated || pending || live.contains(&rec.token) {
                continue;
            }
            let mut next = rec.clone();
            next.exposed = rec.is_exposed();
            next.terminated = true;
            next.phase = if matches!(rec.phase, Phase::Settled | Phase::Terminated) {
                Phase::Terminated
            } else {
                Phase::Failed
            };
            if self.store.update(&key, rec.version, next).is_ok() {
                report.closed_attempts.push(key);
            }
        }
        Ok(report)
    }

    fn verified_terminate(&self, id: &InstanceId) -> bool {
        self.provider.terminate(id).is_ok()
            && self
                .provider
                .describe(id)
                .is_ok_and(|r| r.state == InstanceState::Terminated)
    }
}
