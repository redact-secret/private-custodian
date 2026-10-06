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
    fn list(&self) -> Result<Vec<(AttemptKey, AttemptRecord)>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
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
    launched_at: u64,
    ended_at: Option<u64>,
}

#[derive(Default)]
struct Inner {
    next: u64,
    instances: BTreeMap<String, Inst>,
    /// Create the instance but report an error (lost response).
    fail_after_create: bool,
    launches: u64,
    clock: u64,
    /// Accept the send, record it, but report an error (lost response).
    lose_delivery_response: bool,
    /// Drop the send entirely and report an error.
    drop_delivery: bool,
    /// Terminate calls that fail, and ones that claim success but do nothing.
    fail_terminates: u32,
    lie_terminates: u32,
}

/// Synthetic provider: idempotent on token, records every delivery.
#[derive(Clone, Default)]
pub struct SyntheticProvider(Arc<Mutex<Inner>>);

impl SyntheticProvider {
    pub fn lose_next_launch_response(&self) {
        self.0.lock().unwrap().fail_after_create = true;
    }
    /// Logical provider clock in seconds (deterministic; no wall time).
    pub fn set_clock(&self, t: u64) {
        self.0.lock().unwrap().clock = t;
    }
    pub fn lose_next_delivery_response(&self) {
        self.0.lock().unwrap().lose_delivery_response = true;
    }
    pub fn drop_next_delivery(&self) {
        self.0.lock().unwrap().drop_delivery = true;
    }
    pub fn fail_next_terminates(&self, n: u32) {
        self.0.lock().unwrap().fail_terminates = n;
    }
    pub fn lie_next_terminates(&self, n: u32) {
        self.0.lock().unwrap().lie_terminates = n;
    }
    /// Test hook: a second instance answering to an existing token.
    pub fn plant_duplicate(&self, token: &str, pins: &HostPins) -> InstanceId {
        let mut g = self.0.lock().unwrap();
        g.next += 1;
        g.launches += 1;
        let id = format!("i-{:08x}", g.next);
        let now = g.clock;
        g.instances.insert(
            id.clone(),
            Inst {
                token: token.into(),
                pins: pins.clone(),
                state: InstanceState::Running,
                inputs: vec![],
                result: None,
                launched_at: now,
                ended_at: None,
            },
        );
        InstanceId::parse(&id).unwrap()
    }
    /// Every instance ever created, terminated or not.
    pub fn owned_ids(&self) -> Vec<InstanceId> {
        let g = self.0.lock().unwrap();
        g.instances
            .keys()
            .map(|id| InstanceId::parse(id).unwrap())
            .collect()
    }
    /// Instances currently not terminated.
    pub fn running(&self) -> Vec<InstanceId> {
        let g = self.0.lock().unwrap();
        g.instances
            .iter()
            .filter(|(_, i)| i.state != InstanceState::Terminated)
            .map(|(id, _)| InstanceId::parse(id).unwrap())
            .collect()
    }
    /// Billable seconds so far for an instance: launch to termination, or to the clock.
    pub fn billable_secs(&self, id: &InstanceId) -> u64 {
        let g = self.0.lock().unwrap();
        let i = &g.instances[id.as_str()];
        i.ended_at.unwrap_or(g.clock).saturating_sub(i.launched_at)
    }
    pub fn total_deliveries(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .instances
            .values()
            .map(|i| i.inputs.len())
            .sum()
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
        let now = g.clock;
        let id = format!("i-{:08x}", 0xf000_0000u64 + g.next);
        g.instances.insert(
            id.clone(),
            Inst {
                token: "pc-foreign".into(),
                pins: pins.clone(),
                state: InstanceState::Running,
                inputs: vec![],
                result: None,
                launched_at: now,
                ended_at: None,
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
        let now = g.clock;
        let id = format!("i-{:08x}", g.next);
        g.instances.insert(
            id.clone(),
            Inst {
                token: token.into(),
                pins: pins.clone(),
                state: InstanceState::Running,
                inputs: vec![],
                result: None,
                launched_at: now,
                ended_at: None,
            },
        );
        if std::mem::take(&mut g.fail_after_create) {
            return Err(ProviderError::Unavailable);
        }
        Ok(InstanceId::parse(&id).unwrap())
    }
    fn find_by_token(&self, token: &str) -> Result<Option<InstanceId>, ProviderError> {
        let g = self.0.lock().unwrap();
        let mut hits = g.instances.iter().filter(|(_, i)| i.token == token);
        let first = hits.next().map(|(id, _)| InstanceId::parse(id).unwrap());
        if hits.next().is_some() {
            return Err(ProviderError::Ambiguous);
        }
        Ok(first)
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
        let (drop_it, lose) = (g.drop_delivery, g.lose_delivery_response);
        let i = g
            .instances
            .get_mut(id.as_str())
            .ok_or(ProviderError::Unknown)?;
        if i.token != token || i.state != InstanceState::Running {
            return Err(ProviderError::Refused);
        }
        if drop_it {
            g.drop_delivery = false;
            return Err(ProviderError::Unavailable);
        }
        i.inputs.push(job.to_vec());
        if lose {
            g.lose_delivery_response = false;
            return Err(ProviderError::Unavailable);
        }
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
        if !g.instances.contains_key(id.as_str()) {
            return Err(ProviderError::Unknown);
        }
        if g.fail_terminates > 0 {
            g.fail_terminates -= 1;
            return Err(ProviderError::Unavailable);
        }
        if g.lie_terminates > 0 {
            g.lie_terminates -= 1;
            return Ok(());
        }
        let now = g.clock;
        let i = g.instances.get_mut(id.as_str()).unwrap();
        if i.state != InstanceState::Terminated {
            i.state = InstanceState::Terminated;
            i.ended_at = Some(now);
        }
        Ok(())
    }
    fn list_owned(&self) -> Result<Vec<OwnedInstance>, ProviderError> {
        let g = self.0.lock().unwrap();
        // Foreign (planted) instances carry no ownership tag in the double.
        Ok(g.instances
            .iter()
            .filter(|(_, i)| i.token != "pc-foreign")
            .map(|(id, i)| OwnedInstance {
                instance: InstanceId::parse(id).unwrap(),
                client_token: i.token.clone(),
                state: i.state,
                launched_at: i.launched_at,
            })
            .collect())
    }
}
