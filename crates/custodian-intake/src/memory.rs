//! In-memory doubles for the intake ports. Synthetic and process-local: they
//! are for tests and for wiring before C4 provides the durable stores. They
//! are bounded so a flood cannot exhaust memory; at capacity they refuse
//! (`StoreUnavailable` / `QueueUnavailable`) rather than evict, because
//! evicting a delivery id would re-open a replay window.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;

use crate::ids::{DeliveryId, HeadSha, InstallationId, PullRequestNumber, RepositoryId};
use crate::ports::{
    Claim, DeliveryStore, InstallationRegistry, IntakeQueue, PullRequestSource, QueuedRequest,
};
use crate::reason::IntakeReason;

fn lock<T>(m: &Mutex<T>, err: IntakeReason) -> Result<std::sync::MutexGuard<'_, T>, IntakeReason> {
    m.lock().map_err(|_| err)
}

#[derive(Debug)]
pub struct MemoryDeliveryStore {
    seen: Mutex<BTreeSet<DeliveryId>>,
    capacity: usize,
}

impl MemoryDeliveryStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(BTreeSet::new()),
            capacity,
        }
    }
}

impl DeliveryStore for MemoryDeliveryStore {
    fn claim(&self, id: &DeliveryId) -> Result<Claim, IntakeReason> {
        let mut seen = lock(&self.seen, IntakeReason::StoreUnavailable)?;
        if seen.contains(id) {
            return Ok(Claim::Seen);
        }
        if seen.len() >= self.capacity {
            return Err(IntakeReason::StoreUnavailable);
        }
        seen.insert(id.clone());
        Ok(Claim::New)
    }

    fn release(&self, id: &DeliveryId) -> Result<(), IntakeReason> {
        lock(&self.seen, IntakeReason::StoreUnavailable)?.remove(id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryRegistry {
    installations: Mutex<BTreeSet<InstallationId>>,
    repositories: Mutex<BTreeSet<(InstallationId, RepositoryId)>>,
}

impl MemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl InstallationRegistry for MemoryRegistry {
    fn installation_removed(&self, installation: InstallationId) -> Result<bool, IntakeReason> {
        Ok(lock(&self.installations, IntakeReason::StoreUnavailable)?.contains(&installation))
    }
    fn repository_removed(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<bool, IntakeReason> {
        Ok(lock(&self.repositories, IntakeReason::StoreUnavailable)?
            .contains(&(installation, repository)))
    }
    fn mark_installation_removed(&self, installation: InstallationId) -> Result<(), IntakeReason> {
        lock(&self.installations, IntakeReason::StoreUnavailable)?.insert(installation);
        Ok(())
    }
    fn mark_repository_removed(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<(), IntakeReason> {
        lock(&self.repositories, IntakeReason::StoreUnavailable)?
            .insert((installation, repository));
        Ok(())
    }
}

#[derive(Debug)]
pub struct MemoryQueue {
    items: Mutex<VecDeque<QueuedRequest>>,
    capacity: usize,
}

impl MemoryQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            capacity,
        }
    }

    /// Take the oldest queued request (what the control plane would do).
    pub fn pop(&self) -> Option<QueuedRequest> {
        self.items.lock().ok()?.pop_front()
    }

    pub fn len(&self) -> usize {
        self.items.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl IntakeQueue for MemoryQueue {
    fn enqueue(&self, request: QueuedRequest) -> Result<(), IntakeReason> {
        let mut q = lock(&self.items, IntakeReason::QueueUnavailable)?;
        if q.len() >= self.capacity {
            return Err(IntakeReason::QueueUnavailable);
        }
        q.push_back(request);
        Ok(())
    }
}

/// Pull request source returning one fixed head (or a fixed failure).
#[derive(Debug)]
pub struct FixedPullRequestSource {
    head: Mutex<Result<HeadSha, IntakeReason>>,
}

impl FixedPullRequestSource {
    pub fn new(head: HeadSha) -> Self {
        Self {
            head: Mutex::new(Ok(head)),
        }
    }

    /// Simulate a new push: later reads return `head`.
    pub fn set_head(&self, head: HeadSha) {
        if let Ok(mut h) = self.head.lock() {
            *h = Ok(head);
        }
    }

    pub fn fail_with(&self, reason: IntakeReason) {
        if let Ok(mut h) = self.head.lock() {
            *h = Err(reason);
        }
    }
}

impl PullRequestSource for FixedPullRequestSource {
    fn current_head(
        &self,
        _installation: InstallationId,
        _repository: RepositoryId,
        _pull_request: PullRequestNumber,
    ) -> Result<HeadSha, IntakeReason> {
        lock(&self.head, IntakeReason::TokenUnavailable)?.clone()
    }
}
