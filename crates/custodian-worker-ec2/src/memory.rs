//! Synthetic in-memory doubles. Test-grade only: no durability, no auth, no
//! isolation. `MemoryStore::snapshot`/`restore` model a restart.
use crate::port::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<BTreeMap<AttemptKey, AttemptRecord>>>);

impl MemoryStore {
    pub fn snapshot(&self) -> BTreeMap<AttemptKey, AttemptRecord> {
        self.0.lock().unwrap().clone()
    }
    pub fn restore(s: BTreeMap<AttemptKey, AttemptRecord>) -> Self {
        Self(Arc::new(Mutex::new(s)))
    }
}

impl AttemptStore for MemoryStore {
    fn load(&self, k: &AttemptKey) -> Result<Option<AttemptRecord>, StoreError> {
        Ok(self.0.lock().unwrap().get(k).cloned())
    }
    fn insert(&self, k: &AttemptKey, rec: AttemptRecord) -> Result<(), StoreError> {
        let mut m = self.0.lock().unwrap();
        if m.contains_key(k) {
            return Err(StoreError::Conflict);
        }
        m.insert(k.clone(), rec);
        Ok(())
    }
    fn update(
        &self,
        k: &AttemptKey,
        expected: u64,
        mut rec: AttemptRecord,
    ) -> Result<u64, StoreError> {
        let mut m = self.0.lock().unwrap();
        match m.get(k) {
            Some(cur) if cur.version == expected => {
                rec.version = expected + 1;
                m.insert(k.clone(), rec);
                Ok(expected + 1)
            }
            _ => Err(StoreError::Conflict),
        }
    }
}

struct Inst {
    token: String,
    pins: HostPins,
    state: InstanceState,
    inputs: Vec<Vec<u8>>,
    result: Option<Vec<u8>>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    instances: BTreeMap<String, Inst>,
    /// Create the instance but report an error (lost response).
    fail_after_create: bool,
    launches: u64,
}

/// Synthetic provider: idempotent on token, records every delivery.
#[derive(Clone, Default)]
pub struct SyntheticProvider(Arc<Mutex<Inner>>);

impl SyntheticProvider {
    pub fn lose_next_launch_response(&self) {
        self.0.lock().unwrap().fail_after_create = true;
    }
    pub fn launches(&self) -> u64 {
        self.0.lock().unwrap().launches
    }
    pub fn deliveries(&self, id: &InstanceId) -> usize {
        self.0.lock().unwrap().instances[id.as_str()].inputs.len()
    }
    pub fn delivered(&self, id: &InstanceId) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().instances[id.as_str()].inputs.clone()
    }
    pub fn is_terminated(&self, id: &InstanceId) -> bool {
        self.0.lock().unwrap().instances[id.as_str()].state == InstanceState::Terminated
    }
    /// Test hook: the worker (untrusted) writes a result.
    pub fn set_result(&self, id: &InstanceId, bytes: Vec<u8>) {
        self.0
            .lock()
            .unwrap()
            .instances
            .get_mut(id.as_str())
            .unwrap()
            .result = Some(bytes);
    }
    pub fn set_state(&self, id: &InstanceId, s: InstanceState) {
        self.0
            .lock()
            .unwrap()
            .instances
            .get_mut(id.as_str())
            .unwrap()
            .state = s;
    }
    /// Test hook: pretend the instance runs a different image.
    pub fn swap_pins(&self, id: &InstanceId, pins: HostPins) {
        self.0
            .lock()
            .unwrap()
            .instances
            .get_mut(id.as_str())
            .unwrap()
            .pins = pins;
    }
    /// Test hook: an unrelated instance, as if from another attempt.
    pub fn plant_foreign(&self, pins: &HostPins) -> InstanceId {
        let mut g = self.0.lock().unwrap();
        g.next += 1;
        let id = format!("i-{:08x}", 0xf000_0000u64 + g.next);
        g.instances.insert(
            id.clone(),
            Inst {
                token: "pc-foreign".into(),
                pins: pins.clone(),
                state: InstanceState::Running,
                inputs: vec![],
                result: None,
            },
        );
        InstanceId::parse(&id).unwrap()
    }
}

impl Provider for SyntheticProvider {
    fn launch(&self, token: &str, pins: &HostPins) -> Result<InstanceId, ProviderError> {
        let mut g = self.0.lock().unwrap();
        if let Some((id, i)) = g.instances.iter().find(|(_, i)| i.token == token) {
            return if i.pins == *pins {
                Ok(InstanceId::parse(id).unwrap())
            } else {
                Err(ProviderError::TokenConflict)
            };
        }
        g.next += 1;
        g.launches += 1;
        let id = format!("i-{:08x}", g.next);
        g.instances.insert(
            id.clone(),
            Inst {
                token: token.into(),
                pins: pins.clone(),
                state: InstanceState::Running,
                inputs: vec![],
                result: None,
            },
        );
        if std::mem::take(&mut g.fail_after_create) {
            return Err(ProviderError::Unavailable);
        }
        Ok(InstanceId::parse(&id).unwrap())
    }
    fn find_by_token(&self, token: &str) -> Result<Option<InstanceId>, ProviderError> {
        let g = self.0.lock().unwrap();
        Ok(g.instances
            .iter()
            .find(|(_, i)| i.token == token)
            .map(|(id, _)| InstanceId::parse(id).unwrap()))
    }
    fn describe(&self, id: &InstanceId) -> Result<InstanceReport, ProviderError> {
        let g = self.0.lock().unwrap();
        let i = g.instances.get(id.as_str()).ok_or(ProviderError::Unknown)?;
        Ok(InstanceReport {
            instance: id.clone(),
            client_token: i.token.clone(),
            ami_id: i.pins.ami_id.clone(),
            ami_manifest_digest: i.pins.ami_manifest_digest.clone(),
            state: i.state,
        })
    }
    fn deliver(&self, id: &InstanceId, token: &str, job: &[u8]) -> Result<(), ProviderError> {
        let mut g = self.0.lock().unwrap();
        let i = g
            .instances
            .get_mut(id.as_str())
            .ok_or(ProviderError::Unknown)?;
        if i.token != token || i.state != InstanceState::Running {
            return Err(ProviderError::Refused);
        }
        i.inputs.push(job.to_vec());
        Ok(())
    }
    fn fetch_result(&self, id: &InstanceId, token: &str) -> Result<Vec<u8>, ProviderError> {
        let g = self.0.lock().unwrap();
        let i = g.instances.get(id.as_str()).ok_or(ProviderError::Unknown)?;
        if i.token != token {
            return Err(ProviderError::Refused);
        }
        i.result.clone().ok_or(ProviderError::Unknown)
    }
    fn terminate(&self, id: &InstanceId) -> Result<(), ProviderError> {
        let mut g = self.0.lock().unwrap();
        g.instances
            .get_mut(id.as_str())
            .ok_or(ProviderError::Unknown)?
            .state = InstanceState::Terminated;
        Ok(())
    }
}
