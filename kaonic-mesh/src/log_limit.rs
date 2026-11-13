//! A log line that a fault could repeat for every packet, written at most once per interval.

use std::time::{Duration, Instant};

pub struct LogLimit {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogLimit {
    pub const fn new(every: Duration) -> Self {
        Self { every, last: None, suppressed: 0 }
    }

    /// Whether to log now: Some(lines skipped since the last one), or None to skip this one.
    pub fn allow(&mut self, now: Instant) -> Option<u64> {
        if self.last.is_some_and(|last| now.saturating_duration_since(last) < self.every) {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_per_interval_and_the_rest_counted() {
        let (mut limit, now) = (LogLimit::new(Duration::from_secs(10)), Instant::now());
        assert_eq!(limit.allow(now), Some(0));
        let logged = (1..=1000).filter(|ms| limit.allow(now + Duration::from_millis(*ms)).is_some()).count();
        assert_eq!(logged, 0);
        assert_eq!(limit.allow(now + Duration::from_secs(10)), Some(1000));
        assert_eq!(limit.allow(now + Duration::from_secs(11)), None);
    }
}
