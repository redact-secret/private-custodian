//! Time source for the core `StateStore` port, which carries no timestamp.
//! The richer store API takes `now` from the caller explicitly (contracts
//! carry no clock); this trait only backs the port adapter and tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Settable clock for deterministic tests.
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
