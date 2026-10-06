//! Vendor-neutral ports: provider, custodian-owned attempt store, gates.
use crate::AdapterError;
use custodian_contracts::types::ArtifactDigest;
use custodian_worker_microvm::AttemptBinding;

/// Provider instance id, validated as `i-` plus 8 to 17 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceId(String);

impl InstanceId {
    pub fn parse(s: &str) -> Result<Self, AdapterError> {
        valid_prefixed(s, "i-")
            .then(|| Self(s.into()))
            .ok_or(AdapterError::Invalid)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_prefixed(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|h| {
        (8..=17).contains(&h.len())
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Immutable host image pins beyond what `AttemptBinding` already carries
/// (runner image, engine, adapter, scanners, config, candidate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPins {
    pub ami_id: String,
    /// Digest of the reviewed AMI build manifest (kernel, bwrap, tool versions).
    pub ami_manifest_digest: ArtifactDigest,
}

impl HostPins {
    pub fn validate(&self) -> Result<(), AdapterError> {
        if valid_prefixed(&self.ami_id, "ami-") {
            Ok(())
        } else {
            Err(AdapterError::Invalid)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    Pending,
    Running,
    Terminated,
}

/// What the authenticated provider reports about an instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceReport {
    pub instance: InstanceId,
    pub client_token: String,
    pub ami_id: String,
    pub ami_manifest_digest: ArtifactDigest,
    pub state: InstanceState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    Unavailable,
    Unknown,
    /// Token reused with different pins.
    TokenConflict,
    Refused,
}

/// Authenticated transport and lifecycle. Implementations must be idempotent on
/// `token` for launch, and terminate must be idempotent. Inputs are delivered
/// to, and results fetched from, exactly one named instance.
pub trait Provider {
    fn launch(&self, token: &str, pins: &HostPins) -> Result<InstanceId, ProviderError>;
    fn find_by_token(&self, token: &str) -> Result<Option<InstanceId>, ProviderError>;
    fn describe(&self, id: &InstanceId) -> Result<InstanceReport, ProviderError>;
    fn deliver(&self, id: &InstanceId, token: &str, job: &[u8]) -> Result<(), ProviderError>;
    fn fetch_result(&self, id: &InstanceId, token: &str) -> Result<Vec<u8>, ProviderError>;
    fn terminate(&self, id: &InstanceId) -> Result<(), ProviderError>;
}

/// Custodian-owned gates, answered from the durable store/ledger, never from
/// the worker or a result: exposure acknowledged, export acknowledged, and the
/// lease fence for this execution is still the current one.
pub trait Gates {
    fn exposure_acknowledged(&self, b: &AttemptBinding) -> bool;
    fn export_acknowledged(&self, b: &AttemptBinding) -> bool;
    fn lease_current(&self, b: &AttemptBinding) -> bool;
}

impl<T: Gates + ?Sized> Gates for std::sync::Arc<T> {
    fn exposure_acknowledged(&self, b: &AttemptBinding) -> bool {
        (**self).exposure_acknowledged(b)
    }
    fn export_acknowledged(&self, b: &AttemptBinding) -> bool {
        (**self).export_acknowledged(b)
    }
    fn lease_current(&self, b: &AttemptBinding) -> bool {
        (**self).lease_current(b)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttemptKey {
    pub execution: String,
    pub attempt: u64,
}

impl AttemptKey {
    pub fn of(b: &AttemptBinding) -> Self {
        Self {
            execution: b.execution.as_str().into(),
            attempt: b.attempt.get(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    LaunchIntent,
    Launched,
    /// Input send started; possible exposure. Never redelivered.
    Delivering,
    Delivered,
    Settled,
    Terminated,
    /// Provider outcome unknown; no input is ever delivered.
    Ambiguous,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    pub binding: AttemptBinding,
    pub pins: HostPins,
    pub token: String,
    pub phase: Phase,
    pub instance: Option<InstanceId>,
    pub result_digest: Option<String>,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Record exists (insert) or version moved (update): concurrent writer.
    Conflict,
    Unavailable,
}

/// Durable, compare-and-swap attempt mapping. `update` returns the new version.
pub trait AttemptStore {
    fn load(&self, key: &AttemptKey) -> Result<Option<AttemptRecord>, StoreError>;
    fn insert(&self, key: &AttemptKey, rec: AttemptRecord) -> Result<(), StoreError>;
    fn update(
        &self,
        key: &AttemptKey,
        expected: u64,
        rec: AttemptRecord,
    ) -> Result<u64, StoreError>;
}
