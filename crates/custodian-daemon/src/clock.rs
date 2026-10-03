//! A clock that can be held at one instant for the duration of a replay.
//!
//! The pipeline prepares a release at some instant and stores it. The digest
//! of the prepared projection includes that instant (`issued_at`,
//! `fresh_until`), and a human's release approval binds the digest, so a
//! resumed pipeline must prepare again **as of the stored instant** to
//! produce the very projection the approval names. The disclosure service and
//! the single shared eligibility read their time from the control plane's
//! clock, so replaying "as of then" means holding that clock still while the
//! replay runs.
//!
//! That is all this does, and it is narrow on purpose:
//!
//! * the pin is held only around `prepare_bound` (a guard, released on drop),
//!   on the control thread, whose clock this is; the listener and the
//!   consumers have their own clocks;
//! * only *time* is replayed. Whether the epoch is contaminated or retired,
//!   whether a revocation was recorded and whether the store awaits
//!   reconciliation are read live from the store whatever the clock says, so a
//!   replay cannot revive anything that was withdrawn;
//! * the release itself is never pinned: `release` runs on the live clock and
//!   re-checks the approval window, the current activation and the
//!   eligibility, twice.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use custodian_store::Clock;

/// The shared handle that pins a [`PinnableClock`].
#[derive(Clone, Debug, Default)]
pub struct ClockPin(Arc<AtomicU64>);

impl ClockPin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold the clock at `at` until the guard is dropped.
    pub fn pin(&self, at: u64) -> PinGuard<'_> {
        self.0.store(at.max(1), Ordering::SeqCst);
        PinGuard(self)
    }
}

pub struct PinGuard<'a>(&'a ClockPin);

impl Drop for PinGuard<'_> {
    fn drop(&mut self) {
        (self.0).0.store(0, Ordering::SeqCst);
    }
}

/// `inner`'s time, or the pinned instant while a pin is held.
pub struct PinnableClock {
    inner: Arc<dyn Clock>,
    pin: ClockPin,
}

impl PinnableClock {
    pub fn new(inner: Arc<dyn Clock>, pin: ClockPin) -> Self {
        Self { inner, pin }
    }
}

impl Clock for PinnableClock {
    fn now(&self) -> u64 {
        match self.pin.0.load(Ordering::SeqCst) {
            0 => self.inner.now(),
            pinned => pinned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use custodian_store::ManualClock;

    #[test]
    fn the_pin_holds_the_clock_only_while_the_guard_lives() {
        let manual = Arc::new(ManualClock::new(100));
        let pin = ClockPin::new();
        let c = PinnableClock::new(manual.clone(), pin.clone());
        assert_eq!(c.now(), 100);
        {
            let _g = pin.pin(40);
            manual.set(200);
            assert_eq!(c.now(), 40);
        }
        assert_eq!(c.now(), 200);
    }
}
