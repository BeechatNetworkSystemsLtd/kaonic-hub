//! Refusing a recorded burst played again. The GROUP encryption keeps outsiders from making
//! or changing packets, but a packet recorded off the air decrypts again later: each talker
//! numbers its bursts with a counter that only grows (kept across restarts), and a listener
//! takes a burst only while its counter is above every counter it saw from that talker.
//!
//! A talker has one burst at a time:
//!
//! - Packets of its current burst pass, each once (by `seq`). Any earlier burst is refused,
//!   including the one just before.
//! - A burst first seen mid-way (its START lost) opens the same way as with its START.
//! - A burst closes at its END, or after [`BURST_CLOSE`] without packets: nothing more of it
//!   is taken, so a recording of it cannot be played again.
//!
//! Pure: the hub keeps the admin's highest counter across its own restarts with
//! [`Replay::highest`] and [`Replay::restore`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::Packet;

/// Talkers remembered; past this the least recently heard is forgotten.
const TALKERS: usize = 256;
/// A burst with no packets for this long is closed.
pub const BURST_CLOSE: Duration = Duration::from_secs(2);
/// Packets of the current burst remembered, counting back from the highest `seq`.
const WINDOW: u16 = 128;

#[derive(Default)]
struct Talker {
    /// The highest counter taken.
    highest: u32,
    /// The burst that came with it, while it is open (None after a restore, or once closed).
    current: Option<Burst>,
    heard: u64,
}

struct Burst {
    id: u16,
    /// The highest `seq` taken, and which of the `WINDOW` before it were (bit `n`: `seq - n`).
    top: u16,
    taken: u128,
    last: Instant,
}

impl Burst {
    fn new(id: u16, seq: u16, now: Instant) -> Self {
        Self { id, top: seq, taken: 1, last: now }
    }

    /// Takes `seq` unless it was taken before or is too old to tell.
    fn take(&mut self, seq: u16, now: Instant) -> bool {
        let ahead = seq.wrapping_sub(self.top) as i16;
        if ahead > 0 {
            self.taken = if ahead as u16 >= WINDOW { 1 } else { (self.taken << ahead) | 1 };
            self.top = seq;
        } else {
            let back = ahead.unsigned_abs();
            if back >= WINDOW || self.taken & (1 << back) != 0 {
                return false;
            }
            self.taken |= 1 << back;
        }
        self.last = now;
        true
    }
}

#[derive(Default)]
pub struct Replay {
    talkers: HashMap<[u8; 4], Talker>,
    clock: u64,
}

impl Replay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this packet may be played (and relayed). A refused one is a replay, or a
    /// packet of a burst that is older than one already heard or already closed.
    pub fn check(&mut self, packet: &Packet, now: Instant) -> bool {
        self.clock += 1;
        if !self.talkers.contains_key(&packet.talker) && self.talkers.len() >= TALKERS {
            let oldest = self.talkers.iter().min_by_key(|(_, talker)| talker.heard).map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                self.talkers.remove(&oldest);
            }
        }
        let talker = self.talkers.entry(packet.talker).or_default();
        talker.heard = self.clock;
        if talker.current.as_ref().is_some_and(|burst| now.saturating_duration_since(burst.last) >= BURST_CLOSE) {
            talker.current = None;
        }
        let taken = if packet.counter > talker.highest {
            talker.highest = packet.counter;
            talker.current = Some(Burst::new(packet.burst, packet.seq, now));
            true
        } else {
            match &mut talker.current {
                Some(burst) if packet.counter == talker.highest && burst.id == packet.burst => burst.take(packet.seq, now),
                _ => false,
            }
        };
        if taken && packet.is_end() {
            talker.current = None;
        }
        taken
    }

    /// The highest counter taken from `talker` (to keep across restarts).
    pub fn highest(&self, talker: &[u8; 4]) -> Option<u32> {
        self.talkers.get(talker).map(|talker| talker.highest)
    }

    /// A counter kept from before a restart: only bursts above it are taken.
    pub fn restore(&mut self, talker: [u8; 4], highest: u32) {
        let entry = self.talkers.entry(talker).or_default();
        entry.highest = entry.highest.max(highest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec, flags};

    fn packet(talker: u8, burst: u16, seq: u16, counter: u32, start: bool) -> Packet {
        Packet { flags: if start { flags::START } else { 0 }, ttl: 4, epoch: 1, talker: [talker; 4], burst, seq, counter, codec: codec::OPUS16, frames: vec![vec![1; 10]], signature: None }
    }

    fn end(talker: u8, burst: u16, seq: u16, counter: u32) -> Packet {
        Packet { flags: flags::END, ..packet(talker, burst, seq, counter, false) }
    }

    #[test]
    fn a_recorded_burst_is_refused_once_a_newer_one_was_heard() {
        let (mut replay, now) = (Replay::new(), Instant::now());
        assert!(replay.check(&packet(1, 10, 0, 100, true), now));
        assert!(replay.check(&packet(1, 10, 1, 100, false), now), "the rest of the burst");
        assert!(replay.check(&packet(1, 11, 0, 101, true), now));
        assert!(!replay.check(&packet(1, 10, 2, 100, false), now), "the old burst again");
        assert!(!replay.check(&packet(1, 12, 0, 99, true), now), "an older counter under a new burst id");
        assert!(replay.check(&packet(1, 11, 1, 101, false), now), "the current burst goes on");
        assert!(replay.check(&packet(2, 10, 0, 5, true), now), "talkers are separate");
    }

    #[test]
    fn each_packet_of_the_current_burst_is_taken_once() {
        let (mut replay, now) = (Replay::new(), Instant::now());
        assert!(replay.check(&packet(1, 10, 0, 100, true), now));
        assert!(replay.check(&packet(1, 10, 2, 100, false), now));
        assert!(!replay.check(&packet(1, 10, 2, 100, false), now), "played again");
        assert!(replay.check(&packet(1, 10, 1, 100, false), now), "late, but not taken yet");
        assert!(!replay.check(&packet(1, 10, 0, 100, true), now));
        // Far ahead, then one too old to tell is refused rather than risked.
        assert!(replay.check(&packet(1, 10, 500, 100, false), now));
        assert!(!replay.check(&packet(1, 10, 3, 100, false), now));
        // seq wraps past 65535.
        for seq in [30_000, 60_000, u16::MAX, 0, 1] {
            assert!(replay.check(&packet(1, 10, seq, 100, false), now), "{seq}");
        }
        assert!(!replay.check(&packet(1, 10, u16::MAX, 100, false), now));
    }

    #[test]
    fn a_closed_burst_takes_nothing_more() {
        let (mut replay, now) = (Replay::new(), Instant::now());
        assert!(replay.check(&packet(1, 10, 0, 100, true), now));
        assert!(replay.check(&end(1, 10, 1, 100), now));
        assert!(!replay.check(&packet(1, 10, 2, 100, false), now), "after its END");
        assert!(replay.check(&packet(1, 11, 0, 101, true), now));
        assert!(replay.check(&packet(1, 11, 1, 101, false), now + Duration::from_secs(1)));
        let later = now + Duration::from_secs(1) + BURST_CLOSE;
        assert!(!replay.check(&packet(1, 11, 2, 101, false), later), "silent too long");
        assert!(replay.check(&packet(1, 12, 0, 102, true), later), "the talker's next burst");
    }

    #[test]
    fn a_burst_heard_mid_way_opens_and_a_lost_start_arriving_late_still_fits() {
        let (mut replay, now) = (Replay::new(), Instant::now());
        assert!(replay.check(&packet(1, 10, 3, 100, false), now));
        assert!(replay.check(&packet(1, 10, 0, 100, true), now));
    }

    #[test]
    fn the_counter_survives_a_listener_restart() {
        let (mut before, now) = (Replay::new(), Instant::now());
        assert!(before.check(&packet(1, 10, 0, 100, true), now));
        let mut after = Replay::new();
        after.restore([1; 4], before.highest(&[1; 4]).unwrap());
        assert!(!after.check(&packet(1, 10, 1, 100, false), now));
        assert!(after.check(&packet(1, 3, 0, 101, true), now), "the talker's next burst, whatever its id");
    }

    #[test]
    fn memory_is_bounded() {
        let (mut replay, now) = (Replay::new(), Instant::now());
        for talker in 0..=255u8 {
            for burst in 0..3u16 {
                replay.check(&Packet { talker: [talker, 1, 2, 3], ..packet(0, burst, 0, u32::from(burst) + 1, true) }, now);
            }
        }
        replay.check(&packet(9, 1, 0, 1, true), now);
        assert!(replay.talkers.len() <= TALKERS);
    }
}
