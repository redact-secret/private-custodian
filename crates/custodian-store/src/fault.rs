//! Fault-injection seam for crash testing.
//!
//! Every mutating store operation is one transaction. A [`FaultInjector`] can
//! simulate a process crash at the two boundaries that matter for a
//! transaction: just before commit (everything the operation did is rolled
//! back) and just after commit (the change is durable but the caller never
//! learns of it). The caller drops the store and reopens the file to model a
//! restart. The default injector never fires.

use std::sync::Mutex;

/// Mutating operation, used to name a crash boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultOp {
    ProvisionBudget,
    Reserve,
    Retry,
    Start,
    RenewLease,
    RecordExposure,
    BeginValidation,
    Finish,
    Cancel,
    FailBeforeStart,
    Recover,
    OutboxAck,
    Reconcile,
}

impl FaultOp {
    pub const ALL: [FaultOp; 13] = [
        Self::ProvisionBudget,
        Self::Reserve,
        Self::Retry,
        Self::Start,
        Self::RenewLease,
        Self::RecordExposure,
        Self::BeginValidation,
        Self::Finish,
        Self::Cancel,
        Self::FailBeforeStart,
        Self::Recover,
        Self::OutboxAck,
        Self::Reconcile,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultPhase {
    /// Crash before commit: the operation leaves no trace.
    BeforeCommit,
    /// Crash after commit: the operation is durable, the caller saw an error.
    AfterCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FaultPoint {
    pub op: FaultOp,
    pub phase: FaultPhase,
}

pub trait FaultInjector: Send + Sync {
    /// Return true to simulate a crash at this point.
    fn crash_at(&self, point: FaultPoint) -> bool;
}

/// The production injector: never fires.
#[derive(Debug, Default)]
pub struct NoFault;

impl FaultInjector for NoFault {
    fn crash_at(&self, _point: FaultPoint) -> bool {
        false
    }
}

/// Fires once at a chosen point, then disarms.
#[derive(Debug)]
pub struct CrashOnce {
    armed: Mutex<Option<FaultPoint>>,
}

impl CrashOnce {
    pub fn new(point: FaultPoint) -> Self {
        Self {
            armed: Mutex::new(Some(point)),
        }
    }
    pub fn fired(&self) -> bool {
        self.armed.lock().map(|g| g.is_none()).unwrap_or(true)
    }
}

impl FaultInjector for CrashOnce {
    fn crash_at(&self, point: FaultPoint) -> bool {
        let mut g = self.armed.lock().unwrap_or_else(|e| e.into_inner());
        if *g == Some(point) {
            *g = None;
            true
        } else {
            false
        }
    }
}
