//! Playout of one burst: frames are held for a target delay
//! (120 ms), put back in order, and played one every 20 ms. A frame that never came is
//! played as `Lost`, so the decoder conceals it (Opus PLC or in-band FEC). A new burst
//! replaces the old one; frames that arrive after their turn are dropped.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::FRAME_MS;

/// Without frames for this long and nothing left to play, the burst is over.
const IDLE_END: Duration = Duration::from_millis(500);
/// Frames further ahead than this (5 s) are not of this burst.
const MAX_AHEAD: i32 = 250;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Playout {
    Frame(Vec<u8>),
    /// Conceal one frame.
    Lost,
    /// The burst is over.
    End,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JitterStats {
    pub played: u64,
    pub lost: u64,
    pub late: u64,
    /// Frames dropped because the queue grew past its maximum.
    pub shed: u64,
}

struct Burst {
    id: u16,
    next_seq: u16,
    next_at: Instant,
    frames: HashMap<u16, Vec<u8>>,
    /// The seq after the last frame, once the burst's END is known.
    end: Option<u16>,
    last_push: Instant,
}

pub struct Jitter {
    target: Duration,
    /// Queue depth past which audio is shed (the plugin's `jitter_max_ms`); None: never.
    max: Option<Duration>,
    burst: Option<Burst>,
    stats: JitterStats,
}

/// How far `seq` is after `from`, wrapping.
fn ahead(seq: u16, from: u16) -> i32 {
    i32::from(seq.wrapping_sub(from) as i16)
}

impl Jitter {
    pub fn new(target: Duration) -> Self {
        Self { target, max: None, burst: None, stats: JitterStats::default() }
    }

    /// The plugin's `jitter_target_ms` and `jitter_max_ms`, for the bursts that follow (the
    /// maximum applies at once).
    pub fn set_limits(&mut self, target: Duration, max: Duration) {
        self.target = target;
        self.max = Some(max.max(target));
    }

    fn frame_time() -> Duration {
        Duration::from_millis(FRAME_MS)
    }

    pub fn push(&mut self, burst: u16, seq: u16, frame: Vec<u8>, now: Instant) {
        if self.burst.as_ref().is_none_or(|current| current.id != burst) {
            self.burst = Some(Burst { id: burst, next_seq: seq, next_at: now + self.target, frames: HashMap::new(), end: None, last_push: now });
        }
        let current = self.burst.as_mut().expect("set above");
        current.last_push = now;
        let offset = ahead(seq, current.next_seq);
        if offset < 0 {
            self.stats.late += 1;
            return;
        }
        if offset <= MAX_AHEAD {
            current.frames.insert(seq, frame);
        }
        // A queue past its maximum is pure latency: skip ahead to the target depth.
        if let Some(max) = self.max {
            let frame_ms = FRAME_MS as u128;
            let max_frames = (max.as_millis() / frame_ms).max(1) as i32;
            let target_frames = (self.target.as_millis() / frame_ms).max(1) as i32;
            let newest = current.frames.keys().map(|seq| ahead(*seq, current.next_seq)).max().unwrap_or(0);
            if newest >= max_frames {
                let skip = newest + 1 - target_frames;
                let new_next = current.next_seq.wrapping_add(skip as u16);
                let before = current.frames.len();
                current.frames.retain(|seq, _| ahead(*seq, new_next) >= 0);
                self.stats.shed += (before - current.frames.len()) as u64;
                current.next_seq = new_next;
            }
        }
    }

    /// The burst `burst` has no frames from `end_seq` on (its END packet arrived).
    pub fn end(&mut self, burst: u16, end_seq: u16) {
        if let Some(current) = self.burst.as_mut().filter(|current| current.id == burst) {
            current.end = Some(end_seq);
        }
    }

    /// The next thing to play, if its time has come. Call until it returns None.
    pub fn pop(&mut self, now: Instant) -> Option<Playout> {
        let current = self.burst.as_mut()?;
        if now < current.next_at {
            return None;
        }
        let finished = current.end.is_some_and(|end| ahead(end, current.next_seq) <= 0);
        let gone_quiet = current.frames.is_empty() && now.saturating_duration_since(current.last_push) >= IDLE_END;
        if finished || gone_quiet {
            self.burst = None;
            return Some(Playout::End);
        }
        let seq = current.next_seq;
        current.next_seq = seq.wrapping_add(1);
        current.next_at += Self::frame_time();
        match current.frames.remove(&seq) {
            Some(frame) => {
                self.stats.played += 1;
                Some(Playout::Frame(frame))
            }
            None => {
                self.stats.lost += 1;
                Some(Playout::Lost)
            }
        }
    }

    /// When `pop` next has something.
    pub fn next_at(&self) -> Option<Instant> {
        self.burst.as_ref().map(|current| current.next_at)
    }

    pub fn stats(&self) -> JitterStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn drain(jitter: &mut Jitter, now: Instant) -> Vec<Playout> {
        std::iter::from_fn(|| jitter.pop(now)).collect()
    }

    #[test]
    fn frames_come_out_in_order_after_the_target_delay() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(1, 10, vec![10], now);
        jitter.push(1, 12, vec![12], now + ms(5));
        jitter.push(1, 11, vec![11], now + ms(6));
        assert_eq!(jitter.pop(now + ms(119)), None);
        assert_eq!(drain(&mut jitter, now + ms(160)), vec![Playout::Frame(vec![10]), Playout::Frame(vec![11]), Playout::Frame(vec![12])]);
        assert_eq!(jitter.next_at(), Some(now + ms(180)));
    }

    #[test]
    fn missing_frames_are_lost_and_late_ones_dropped() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(1, 0, vec![0], now);
        jitter.push(1, 2, vec![2], now);
        assert_eq!(drain(&mut jitter, now + ms(160)), vec![Playout::Frame(vec![0]), Playout::Lost, Playout::Frame(vec![2])]);
        jitter.push(1, 1, vec![1], now + ms(161));
        assert_eq!(jitter.stats(), JitterStats { played: 2, lost: 1, late: 1, shed: 0 });
    }

    #[test]
    fn the_end_and_a_new_burst() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(1, 0, vec![0], now);
        jitter.push(1, 1, vec![1], now);
        jitter.end(1, 2);
        assert_eq!(drain(&mut jitter, now + ms(200)), vec![Playout::Frame(vec![0]), Playout::Frame(vec![1]), Playout::End]);
        assert_eq!(jitter.pop(now + ms(300)), None);
        // A new burst replaces one still playing.
        jitter.push(2, 100, vec![100], now + ms(300));
        jitter.push(3, 5, vec![5], now + ms(310));
        assert_eq!(drain(&mut jitter, now + ms(430)), vec![Playout::Frame(vec![5])]);
    }

    #[test]
    fn a_burst_that_goes_quiet_ends() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(1, 0, vec![0], now);
        let played = drain(&mut jitter, now + ms(120));
        assert_eq!(played, vec![Playout::Frame(vec![0])]);
        assert_eq!(jitter.pop(now + ms(140)), Some(Playout::Lost));
        assert_eq!(jitter.pop(now + ms(600)), Some(Playout::End));
    }

    #[test]
    fn sequence_numbers_wrap() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(0));
        jitter.push(1, u16::MAX, vec![1], now);
        jitter.push(1, 0, vec![2], now);
        assert_eq!(drain(&mut jitter, now + ms(20)), vec![Playout::Frame(vec![1]), Playout::Frame(vec![2])]);
    }

    #[test]
    fn a_queue_past_its_maximum_sheds_back_to_the_target() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.set_limits(ms(60), ms(100));
        // 5 frames (100 ms) arrive at once: past the maximum, the oldest go.
        for seq in 0..6u16 {
            jitter.push(1, seq, vec![seq as u8], now);
        }
        let played: Vec<Playout> = drain(&mut jitter, now + ms(200)).into_iter().take(3).collect();
        assert_eq!(played[0], Playout::Frame(vec![3]), "shed down to 3 frames (60 ms)");
        assert!(jitter.stats().shed >= 3);
    }
}
