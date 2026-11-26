//! Playout of one burst: frames are held for a target delay
//! (120 ms), put back in order, and played one every 20 ms. A frame that never came is
//! played as `Lost`, so the decoder conceals it (Opus PLC or in-band FEC). A new burst
//! replaces the old one; frames that arrive after their turn are dropped. Bursts are told
//! apart by talker and burst id: two talkers' random ids can be the same.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::FRAME_MS;

/// Without frames for this long and nothing left to play, the burst is over.
const IDLE_END: Duration = Duration::from_millis(500);
/// Frames further ahead than this (5 s) are not of this burst.
const MAX_AHEAD: i32 = 250;
/// Concealed frames remembered for counting late ones.
const CONCEALED: usize = 32;

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

/// A burst: its talker and burst id.
pub type BurstKey = ([u8; 4], u16);

struct Burst {
    id: BurstKey,
    next_seq: u16,
    next_at: Instant,
    frames: HashMap<u16, Vec<u8>>,
    /// The seq after the last frame, once the burst's END is known.
    end: Option<u16>,
    last_push: Instant,
    /// Frames recently played as `Lost`: one of them arriving now is late. Other frames behind
    /// the playout are repeats already played.
    concealed: Vec<u16>,
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

    pub fn push(&mut self, burst: BurstKey, seq: u16, frame: Vec<u8>, now: Instant) {
        if self.burst.as_ref().is_none_or(|current| current.id != burst) {
            self.burst = Some(Burst { id: burst, next_seq: seq, next_at: now + self.target, frames: HashMap::new(), end: None, last_push: now, concealed: Vec::new() });
        }
        let current = self.burst.as_mut().expect("set above");
        current.last_push = now;
        let offset = ahead(seq, current.next_seq);
        if offset < 0 {
            if let Some(index) = current.concealed.iter().position(|lost| *lost == seq) {
                current.concealed.swap_remove(index);
                self.stats.late += 1;
            }
            return;
        }
        if offset <= MAX_AHEAD && !current.frames.contains_key(&seq) {
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
    pub fn end(&mut self, burst: BurstKey, end_seq: u16) {
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
                if current.concealed.len() >= CONCEALED {
                    current.concealed.remove(0);
                }
                current.concealed.push(seq);
                Some(Playout::Lost)
            }
        }
    }

    /// Frames waiting to be played, as time: the buffer's depth.
    pub fn depth(&self) -> Duration {
        let Some(current) = &self.burst else { return Duration::ZERO };
        let newest = current.frames.keys().map(|seq| ahead(*seq, current.next_seq)).max().map_or(0, |ahead| ahead + 1);
        Self::frame_time() * newest.max(0) as u32
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

    /// Talker 1's burst.
    fn b(burst: u16) -> BurstKey {
        ([1; 4], burst)
    }

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
        jitter.push(b(1), 10, vec![10], now);
        jitter.push(b(1), 12, vec![12], now + ms(5));
        jitter.push(b(1), 11, vec![11], now + ms(6));
        assert_eq!(jitter.pop(now + ms(119)), None);
        assert_eq!(drain(&mut jitter, now + ms(160)), vec![Playout::Frame(vec![10]), Playout::Frame(vec![11]), Playout::Frame(vec![12])]);
        assert_eq!(jitter.next_at(), Some(now + ms(180)));
    }

    #[test]
    fn missing_frames_are_lost_and_late_ones_dropped() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(b(1), 0, vec![0], now);
        jitter.push(b(1), 2, vec![2], now);
        assert_eq!(drain(&mut jitter, now + ms(160)), vec![Playout::Frame(vec![0]), Playout::Lost, Playout::Frame(vec![2])]);
        jitter.push(b(1), 1, vec![1], now + ms(161));
        assert_eq!(jitter.stats(), JitterStats { played: 2, lost: 1, late: 1, shed: 0 });
    }

    #[test]
    fn the_end_and_a_new_burst() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(b(1), 0, vec![0], now);
        jitter.push(b(1), 1, vec![1], now);
        jitter.end(b(1), 2);
        assert_eq!(drain(&mut jitter, now + ms(200)), vec![Playout::Frame(vec![0]), Playout::Frame(vec![1]), Playout::End]);
        assert_eq!(jitter.pop(now + ms(300)), None);
        // A new burst replaces one still playing.
        jitter.push(b(2), 100, vec![100], now + ms(300));
        jitter.push(b(3), 5, vec![5], now + ms(310));
        assert_eq!(drain(&mut jitter, now + ms(430)), vec![Playout::Frame(vec![5])]);
    }

    #[test]
    fn a_talker_starting_right_after_an_end_cuts_the_tail_still_queued() {
        // A's last frames are queued (120 ms) when B starts: B replaces them at once, so the
        // end of A's sentence is not played. The 300 ms rule normally prevents it; the admin
        // preempting does not wait.
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        for seq in 0..5 {
            jitter.push(b(1), seq, vec![seq as u8], now + ms(20 * u64::from(seq)));
        }
        jitter.end(b(1), 5);
        assert_eq!(drain(&mut jitter, now + ms(140)), vec![Playout::Frame(vec![0]), Playout::Frame(vec![1])]);
        jitter.push(b(2), 0, vec![100], now + ms(141));
        let after = drain(&mut jitter, now + ms(300));
        assert_eq!(after.first(), Some(&Playout::Frame(vec![100])), "{after:?}");
        assert!(!after.contains(&Playout::Frame(vec![4])), "A's tail is gone");
    }

    #[test]
    fn repeated_frames_fill_holes_and_only_concealed_ones_count_as_late() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        // Packets of 4 that repeat the 3 frames before: the second packet (4-7) is lost, the
        // third brings 5-7 again.
        for seq in 0..4 {
            jitter.push(b(1), seq, vec![seq as u8], now);
        }
        assert_eq!(jitter.depth(), ms(80));
        for seq in 5..12 {
            jitter.push(b(1), seq, vec![seq as u8], now + ms(80));
        }
        let played = drain(&mut jitter, now + ms(120 + 20 * 11));
        assert_eq!(played.iter().filter(|playout| **playout == Playout::Lost).count(), 1, "only frame 4 is missing");
        // A copy of a frame already played is not late; the concealed frame 4 arriving is.
        jitter.push(b(1), 9, vec![9], now + ms(400));
        assert_eq!(jitter.stats().late, 0);
        jitter.push(b(1), 4, vec![4], now + ms(400));
        assert_eq!(jitter.stats().late, 1);
        jitter.push(b(1), 4, vec![4], now + ms(401));
        assert_eq!(jitter.stats().late, 1, "counted once");
    }

    #[test]
    fn a_new_talker_reusing_the_burst_id_is_not_dropped_as_late() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        // Talker 1's burst 5 is 200 frames in, and its END was lost.
        jitter.push(b(5), 200, vec![1], now);
        drain(&mut jitter, now + ms(120));
        // Talker 2 starts its own burst 5.
        for seq in 0..10 {
            jitter.push(([2; 4], 5), seq, vec![2], now + ms(200 + 20 * u64::from(seq)));
        }
        assert_eq!(jitter.stats().late, 0);
    }

    #[test]
    fn a_burst_that_goes_quiet_ends() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.push(b(1), 0, vec![0], now);
        let played = drain(&mut jitter, now + ms(120));
        assert_eq!(played, vec![Playout::Frame(vec![0])]);
        assert_eq!(jitter.pop(now + ms(140)), Some(Playout::Lost));
        assert_eq!(jitter.pop(now + ms(600)), Some(Playout::End));
    }

    #[test]
    fn sequence_numbers_wrap() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(0));
        jitter.push(b(1), u16::MAX, vec![1], now);
        jitter.push(b(1), 0, vec![2], now);
        assert_eq!(drain(&mut jitter, now + ms(20)), vec![Playout::Frame(vec![1]), Playout::Frame(vec![2])]);
    }

    #[test]
    fn a_queue_past_its_maximum_sheds_back_to_the_target() {
        let now = Instant::now();
        let mut jitter = Jitter::new(ms(120));
        jitter.set_limits(ms(60), ms(100));
        // 5 frames (100 ms) arrive at once: past the maximum, the oldest go.
        for seq in 0..6u16 {
            jitter.push(b(1), seq, vec![seq as u8], now);
        }
        let played: Vec<Playout> = drain(&mut jitter, now + ms(200)).into_iter().take(3).collect();
        assert_eq!(played[0], Playout::Frame(vec![3]), "shed down to 3 frames (60 ms)");
        assert!(jitter.stats().shed >= 3);
    }
}
