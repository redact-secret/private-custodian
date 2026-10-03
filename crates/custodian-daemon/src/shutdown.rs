//! Cooperative shutdown. One flag, set once, read everywhere.
//!
//! The binary sets it from a dedicated signal thread (`SIGTERM`, `SIGINT`
//! blocked in every thread and waited for with `sigwait`, so no handler runs
//! in an arbitrary context and no `unsafe` is needed); tests set it directly.
//! Setting it never kills anything: the listener stops accepting, the
//! consumers stop claiming and finish or release what they hold, and the
//! control loop stops starting work.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Sleep up to `d`, returning early (true) as soon as shutdown is
    /// requested.
    pub fn sleep(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        loop {
            if self.is_requested() {
                return true;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            std::thread::sleep(left.min(Duration::from_millis(20)));
        }
    }
}
