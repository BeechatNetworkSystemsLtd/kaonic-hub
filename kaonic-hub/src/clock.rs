//! Time. Wall-clock seconds for what is stored and shown; [`mono`] for timers,
//! which must not jump when the device first learns the date.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Unix seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// Unix milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

/// Seconds since the hub started, never going backwards.
pub fn mono() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs()
}

/// How often a log line that a peer or client can trigger at will is written at its level;
/// in between it goes to debug.
pub const LOG_EVERY: u64 = 300;

/// Lets something happen at most once per interval: `static NOTED: Every = Every::secs(LOG_EVERY);`.
pub struct Every {
    interval: u64,
    /// `mono() + 1` when it last happened; 0 for never.
    last: AtomicU64,
}

impl Every {
    pub const fn secs(interval: u64) -> Self {
        Self { interval, last: AtomicU64::new(0) }
    }

    /// True at most once per interval.
    pub fn due(&self) -> bool {
        self.due_at(mono() + 1)
    }

    fn due_at(&self, now: u64) -> bool {
        let last = self.last.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < self.interval {
            return false;
        }
        self.last.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_lets_one_through_per_interval() {
        let every = Every::secs(10);
        assert!(every.due_at(1));
        assert!(!every.due_at(1));
        assert!(!every.due_at(10));
        assert!(every.due_at(11));
        assert!(!every.due_at(12));
    }
}
