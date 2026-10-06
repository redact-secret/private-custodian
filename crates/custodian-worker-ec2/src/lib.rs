//! Offline EC2 remote worker adapter: a vendor-neutral provider port, a
//! custodian-owned attempt record, and a synthetic in-memory provider double
//! (ADR 0143). No AWS client, credential, authorization, accounting or
//! isolation authority is implemented here; nothing is verified on a live host.
//!
//! Wire formats are unchanged: job bytes are `worker-job/1`, the result is the
//! `private-custodian.remote-result/1` envelope from `custodian-worker-microvm`
//! whose stdout is one `worker-result/1`. Instance identity is NOT a wire field:
//! it is established by the authenticated provider port and the durable record.

mod janitor;
mod memory;
mod port;

pub use janitor::{Janitor, JanitorPolicy, SweepReport};

pub use memory::{MemoryStore, SyntheticProvider};
pub use port::{
    AttemptKey, AttemptRecord, AttemptStore, Gates, HostPins, InstanceId, InstanceReport,
    InstanceState, Outcome, OwnedInstance, Phase, Provider, ProviderError, StoreError,
};

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_worker::result::{ValidatedResult, MAX_RESULT_BYTES};
use custodian_worker_microvm::{decode_result, sha256, AttemptBinding, Refusal};

/// Maximum job bytes delivered to an instance (same bound as results).
pub const MAX_JOB_BYTES: usize = MAX_RESULT_BYTES as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// Binding, pins, instance id or bytes are structurally invalid.
    Invalid,
    /// Same attempt key with a different binding or pins, or different result bytes.
    Conflict,
    /// Fence is not the current one for this execution.
    StaleFence,
    /// A required exposure/export/lease gate is not satisfied.
    GateClosed,
    /// Phase does not permit the operation (including ambiguous instances).
    WrongPhase,
    /// Provider-reported instance does not match the recorded identity or pins.
    InstanceMismatch,
    Oversized,
    /// Another attempt of this execution still owns the live fence.
    FenceHeld,
    /// Provider terminate was not verified by a follow-up describe.
    TerminateUnverified,
    Result(Refusal),
    Provider(ProviderError),
    Store(StoreError),
}

impl From<StoreError> for AdapterError {
    fn from(e: StoreError) -> Self {
        AdapterError::Store(e)
    }
}

/// Deterministic launch idempotency token derived from the full attempt identity.
pub fn client_token(binding: &AttemptBinding, pins: &HostPins) -> String {
    let mut m = String::from("ec2-launch/1");
    for part in [
        binding.execution.as_str(),
        &binding.attempt.get().to_string(),
        &binding.fence.get().to_string(),
        binding.plan_digest.as_str(),
        binding.candidate_digest.as_str(),
        binding.config_digest.as_str(),
        binding.job_digest.as_str(),
        &pins.ami_id,
        pins.ami_manifest_digest.as_str(),
    ] {
        m.push('|');
        m.push_str(part);
    }
    sha256(m.as_bytes()).replace("sha256:", "pc-")[..35].to_string()
}

pub struct Adapter<P: Provider, S: AttemptStore, G: Gates> {
    pub provider: P,
    pub store: S,
    pub gates: G,
}

impl<P: Provider, S: AttemptStore, G: Gates> Adapter<P, S, G> {
    pub fn new(provider: P, store: S, gates: G) -> Self {
        Self {
            provider,
            store,
            gates,
        }
    }

    /// Durably record launch intent BEFORE any provider call. Idempotent for an
    /// identical (binding, pins); a different binding for the same execution and
    /// attempt is a conflict; a lower fence than recorded is stale.
    pub fn begin(
        &self,
        binding: &AttemptBinding,
        pins: &HostPins,
    ) -> Result<AttemptKey, AdapterError> {
        binding.validate().map_err(|_| AdapterError::Invalid)?;
        pins.validate()?;
        let key = AttemptKey::of(binding);
        if let Some(existing) = self.store.load(&key)? {
            if existing.binding != *binding || existing.pins != *pins {
                return Err(if binding.fence.get() < existing.binding.fence.get() {
                    AdapterError::StaleFence
                } else {
                    AdapterError::Conflict
                });
            }
            return Ok(key);
        }
        // Single live-fence owner per execution: fences strictly increase and a
        // new attempt needs every earlier attempt closed (termination verified).
        for (other_key, other) in self.store.list()? {
            if other_key.execution != key.execution {
                continue;
            }
            if other.binding.fence.get() >= binding.fence.get() {
                return Err(AdapterError::StaleFence);
            }
            if !other.terminated {
                return Err(AdapterError::FenceHeld);
            }
        }
        let rec = AttemptRecord {
            binding: binding.clone(),
            pins: pins.clone(),
            token: client_token(binding, pins),
            phase: Phase::LaunchIntent,
            instance: None,
            result_digest: None,
            exposed: false,
            terminated: false,
            version: 0,
        };
        self.store.insert(&key, rec)?;
        Ok(key)
    }

    /// Launch (or re-launch after restart: the provider is idempotent on the
    /// token). A provider error leaves the attempt `Ambiguous`; inputs are never
    /// delivered until `reconcile` resolves it.
    pub fn launch(&self, key: &AttemptKey) -> Result<InstanceId, AdapterError> {
        let rec = self.require(key)?;
        match (&rec.phase, &rec.instance) {
            (Phase::Launched | Phase::Delivered | Phase::Settled, Some(i)) => return Ok(i.clone()),
            (Phase::LaunchIntent, None) => {}
            _ => return Err(AdapterError::WrongPhase),
        }
        match self.provider.launch(&rec.token, &rec.pins) {
            Ok(id) => {
                let mut next = rec.clone();
                next.phase = Phase::Launched;
                next.instance = Some(id.clone());
                self.store.update(key, rec.version, next)?;
                Ok(id)
            }
            Err(e) => {
                let mut next = rec.clone();
                next.phase = Phase::Ambiguous;
                self.store.update(key, rec.version, next)?;
                Err(AdapterError::Provider(e))
            }
        }
    }

    /// Deliver exact job bytes only after exposure, export and lease gates, and
    /// only to the exact recorded instance whose provider-reported identity and
    /// pins match. The `Delivering` phase is durably written before the send, so
    /// a crash afterwards is treated as possible exposure and never redelivered.
    pub fn deliver(&self, key: &AttemptKey, job: &[u8]) -> Result<(), AdapterError> {
        let rec = self.require(key)?;
        if rec.phase != Phase::Launched {
            return Err(AdapterError::WrongPhase);
        }
        if job.len() > MAX_JOB_BYTES {
            return Err(AdapterError::Oversized);
        }
        rec.binding.check_job(job).map_err(AdapterError::Result)?;
        self.live_fence(&rec)?;
        if !self.gates.exposure_acknowledged(&rec.binding)
            || !self.gates.export_acknowledged(&rec.binding)
        {
            return Err(AdapterError::GateClosed);
        }
        let instance = rec.instance.clone().ok_or(AdapterError::WrongPhase)?;
        self.check_instance(&rec, &instance)?;
        let mut next = rec.clone();
        next.phase = Phase::Delivering;
        next.exposed = true;
        let version = self.store.update(key, rec.version, next.clone())?;
        self.provider
            .deliver(&instance, &rec.token, job)
            .map_err(AdapterError::Provider)?;
        next.phase = Phase::Delivered;
        self.store.update(key, version, next)?;
        Ok(())
    }

    /// Fetch and verify the result for a delivered attempt. Verifies the lease
    /// is still current, the provider-reported instance equals the record, and
    /// the envelope binding equals the durable binding before any parsing result
    /// is trusted. Idempotent for identical bytes; different bytes conflict.
    pub fn collect(
        &self,
        key: &AttemptKey,
        domain: EvaluationDomain,
        protocol: &ProtocolRef,
        roster: u64,
    ) -> Result<ValidatedResult, AdapterError> {
        let rec = self.require(key)?;
        if !matches!(rec.phase, Phase::Delivered | Phase::Settled) {
            return Err(AdapterError::WrongPhase);
        }
        self.live_fence(&rec)?;
        let instance = rec.instance.clone().ok_or(AdapterError::WrongPhase)?;
        self.check_instance(&rec, &instance)?;
        let bytes = self
            .provider
            .fetch_result(&instance, &rec.token)
            .map_err(AdapterError::Provider)?;
        let digest = sha256(&bytes);
        if let Some(prev) = &rec.result_digest {
            if *prev != digest {
                return Err(AdapterError::Conflict);
            }
        }
        let validated = decode_result(&bytes, &rec.binding, domain, protocol, roster)
            .map_err(AdapterError::Result)?;
        if rec.result_digest.is_none() {
            let mut next = rec.clone();
            next.phase = Phase::Settled;
            next.result_digest = Some(digest);
            self.store.update(key, rec.version, next)?;
        }
        Ok(validated)
    }

    /// Idempotent, verified terminate; legal in every phase and the way an
    /// ambiguous, failed or settled attempt ends. The attempt only counts as
    /// closed (`terminated`) after a follow-up describe reports `Terminated`, or
    /// when no instance can be found. Never stops or reuses an instance, never
    /// clears exposure.
    pub fn terminate(&self, key: &AttemptKey) -> Result<(), AdapterError> {
        let rec = self.require(key)?;
        if rec.terminated {
            return Ok(());
        }
        let instance = match &rec.instance {
            Some(i) => Some(i.clone()),
            None => self
                .provider
                .find_by_token(&rec.token)
                .map_err(AdapterError::Provider)?,
        };
        if let Some(i) = &instance {
            self.provider.terminate(i).map_err(AdapterError::Provider)?;
            let report = self.provider.describe(i).map_err(AdapterError::Provider)?;
            if report.state != InstanceState::Terminated {
                return Err(AdapterError::TerminateUnverified);
            }
        }
        let mut next = rec.clone();
        next.instance = instance;
        next.exposed = rec.is_exposed();
        next.terminated = true;
        next.phase = if matches!(rec.phase, Phase::Settled | Phase::Terminated) {
            Phase::Terminated
        } else {
            Phase::Failed
        };
        self.store.update(key, rec.version, next)?;
        Ok(())
    }

    /// Cancellation: verified terminate, then the deterministic outcome. An
    /// exposed run stays `ExposedConsumed`; this crate never refunds, and a late
    /// result for a cancelled attempt is refused (`collect` needs `Delivered`).
    pub fn cancel(&self, key: &AttemptKey) -> Result<Outcome, AdapterError> {
        self.terminate(key)?;
        self.outcome(key)
    }

    pub fn outcome(&self, key: &AttemptKey) -> Result<Outcome, AdapterError> {
        Ok(self.require(key)?.outcome())
    }

    /// Restart reconciliation from custodian-owned state only. Intent without an
    /// instance adopts a provider instance found by token or stays retryable;
    /// `Ambiguous` and `Delivering` fail closed (terminate, attempt not
    /// evaluated, a retry is a new attempt and new instance).
    pub fn reconcile(&self, key: &AttemptKey) -> Result<Phase, AdapterError> {
        let rec = self.require(key)?;
        match rec.phase {
            Phase::LaunchIntent | Phase::Ambiguous => {
                let found = self
                    .provider
                    .find_by_token(&rec.token)
                    .map_err(AdapterError::Provider)?;
                match (found, rec.phase) {
                    (None, Phase::LaunchIntent) => {}
                    (Some(id), Phase::LaunchIntent) => {
                        let mut next = rec.clone();
                        next.instance = Some(id);
                        next.phase = Phase::Launched;
                        self.store.update(key, rec.version, next)?;
                    }
                    (found, _) => {
                        let mut next = rec.clone();
                        next.instance = found;
                        next.phase = Phase::Failed;
                        self.store.update(key, rec.version, next)?;
                        self.terminate(key)?;
                    }
                }
            }
            Phase::Delivering => self.terminate(key)?,
            _ => {}
        }
        Ok(self.require(key)?.phase)
    }

    fn require(&self, key: &AttemptKey) -> Result<AttemptRecord, AdapterError> {
        self.store.load(key)?.ok_or(AdapterError::WrongPhase)
    }

    fn live_fence(&self, rec: &AttemptRecord) -> Result<(), AdapterError> {
        if self.gates.lease_current(&rec.binding) {
            Ok(())
        } else {
            Err(AdapterError::StaleFence)
        }
    }

    fn check_instance(&self, rec: &AttemptRecord, id: &InstanceId) -> Result<(), AdapterError> {
        let report = self.provider.describe(id).map_err(AdapterError::Provider)?;
        if report.instance != *id
            || report.client_token != rec.token
            || report.ami_id != rec.pins.ami_id
            || report.ami_manifest_digest != rec.pins.ami_manifest_digest
            || report.state != InstanceState::Running
        {
            return Err(AdapterError::InstanceMismatch);
        }
        Ok(())
    }
}
