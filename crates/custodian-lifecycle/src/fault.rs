//! Crash seam for the multi-step lifecycle operations, in the style of the
//! store's `FaultInjector`. Each point sits between two durable steps; a test
//! fires one, drops everything, reopens the same files and re-runs the
//! operation to prove it converges. `NoFault` never fires.

use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecyclePoint {
    /// Report recorded (contamination durable), automatic retirement not yet.
    AfterReport,
    /// Store retirement durable, registry retirement not yet.
    AfterStoreRetire,
    /// Registry retirement durable, rotation link not yet.
    AfterRegistryRetire,
    /// Rotation link durable, budgets not yet provisioned.
    AfterRotationLink,
    /// Budgets provisioned, successor not yet activated.
    AfterRotationBudgets,
    /// Envelope signed, nothing durable yet.
    BeforeFeedAppend,
    /// Envelope durable in the store, not yet at the destination.
    AfterFeedAppend,
    /// Destination holds the bytes, delivery not yet recorded.
    AfterDestinationPut,
}

impl LifecyclePoint {
    pub const ALL: [LifecyclePoint; 8] = [
        Self::AfterReport,
        Self::AfterStoreRetire,
        Self::AfterRegistryRetire,
        Self::AfterRotationLink,
        Self::AfterRotationBudgets,
        Self::BeforeFeedAppend,
        Self::AfterFeedAppend,
        Self::AfterDestinationPut,
    ];
}

pub trait LifecycleFault: Send + Sync {
    fn crash_at(&self, point: LifecyclePoint) -> bool;
}

/// The production injector: never fires.
#[derive(Debug, Default)]
pub struct NoFault;

impl LifecycleFault for NoFault {
    fn crash_at(&self, _: LifecyclePoint) -> bool {
        false
    }
}

/// Fires once at a chosen point, then disarms.
#[derive(Debug)]
pub struct CrashOnce {
    armed: Mutex<Option<LifecyclePoint>>,
}

impl CrashOnce {
    pub fn new(point: LifecyclePoint) -> Self {
        Self {
            armed: Mutex::new(Some(point)),
        }
    }

    pub fn fired(&self) -> bool {
        self.armed.lock().map(|g| g.is_none()).unwrap_or(true)
    }
}

impl LifecycleFault for CrashOnce {
    fn crash_at(&self, point: LifecyclePoint) -> bool {
        let mut g = self.armed.lock().unwrap_or_else(|e| e.into_inner());
        if *g == Some(point) {
            *g = None;
            true
        } else {
            false
        }
    }
}
