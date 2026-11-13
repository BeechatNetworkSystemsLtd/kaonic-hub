//! Relaying voice across hops. Reticulum does not forward
//! GROUP packets, so every node re-sends each new packet once, after a random 10-40 ms
//! delay, with the ttl lowered. A node that hears the same packet relayed by enough others
//! during its delay drops its own copy (counter-based flooding), so in a dense cluster only
//! a few nodes relay. Packets are told apart by `(talker, burst, seq)`, remembered 10 s.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::packet::Packet;

/// Packets remembered at most; past this the oldest are forgotten (about 30 s of a busy
/// group's traffic, so only a flood reaches it).
const SEEN: usize = 2048;

type Key = ([u8; 4], u16, u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayConfig {
    pub min_delay: Duration,
    pub max_delay: Duration,
    /// Copies heard from others during the delay that cancel our own relay.
    pub suppress_after: u8,
    /// How long a packet is remembered for spotting copies.
    pub memory: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self { min_delay: Duration::from_millis(10), max_delay: Duration::from_millis(40), suppress_after: 2, memory: Duration::from_secs(10) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Heard {
    /// First time: play it.
    New,
    /// A copy of one already heard.
    Duplicate,
    /// Our own packet, relayed back to us.
    Own,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub relayed: u64,
    pub suppressed: u64,
    pub duplicates: u64,
}

struct Seen {
    first: Instant,
    own: bool,
    /// Copies heard after the first.
    copies: u8,
    /// Our relay of it, and when it goes out.
    pending: Option<(Instant, Packet)>,
}

pub struct Relay {
    config: RelayConfig,
    me: [u8; 4],
    enabled: bool,
    seen: HashMap<Key, Seen>,
    /// `seen` keys in the order they came, so forgetting is not a scan of all of them. Holds
    /// stale keys too (forgotten or overwritten), told apart by `first`.
    order: VecDeque<(Instant, Key)>,
    stats: RelayStats,
}

impl Relay {
    pub fn new(config: RelayConfig, me: [u8; 4]) -> Self {
        Self { config, me, enabled: true, seen: HashMap::new(), order: VecDeque::new(), stats: RelayStats::default() }
    }

    fn forget_old(&mut self, now: Instant) {
        while let Some(&(first, key)) = self.order.front() {
            if now.saturating_duration_since(first) < self.config.memory {
                break;
            }
            match self.seen.get(&key) {
                Some(seen) if seen.first == first && seen.pending.is_some() => break,
                Some(seen) if seen.first == first => {
                    self.seen.remove(&key);
                }
                _ => {}
            }
            self.order.pop_front();
        }
    }

    fn remember(&mut self, key: Key, seen: Seen) {
        while self.order.len() >= SEEN {
            let Some((first, old)) = self.order.pop_front() else { break };
            if self.seen.get(&old).is_some_and(|seen| seen.first == first) {
                self.seen.remove(&old);
            }
        }
        self.order.push_back((seen.first, key));
        self.seen.insert(key, seen);
    }

    /// A packet heard (and decrypted). New packets with ttl > 1 are scheduled for one relay
    /// after a random delay (`roll` in [0, 1) picks it).
    pub fn on_heard(&mut self, packet: &Packet, now: Instant, roll: f64) -> Heard {
        self.forget_old(now);
        if let Some(seen) = self.seen.get_mut(&packet.key()) {
            if seen.own {
                return Heard::Own;
            }
            seen.copies = seen.copies.saturating_add(1);
            self.stats.duplicates += 1;
            if seen.copies >= self.config.suppress_after && seen.pending.take().is_some() {
                self.stats.suppressed += 1;
            }
            return Heard::Duplicate;
        }
        if packet.talker == self.me {
            // Our own from before a restart, or one we did not record: never relay it.
            self.remember(packet.key(), Seen { first: now, own: true, copies: 0, pending: None });
            return Heard::Own;
        }
        let pending = (self.enabled && packet.ttl > 1).then(|| {
            let spread = self.config.max_delay.saturating_sub(self.config.min_delay);
            let at = now + self.config.min_delay + spread.mul_f64(roll.clamp(0.0, 1.0));
            let mut relay = packet.clone();
            relay.ttl -= 1;
            (at, relay)
        });
        // The copy just heard counts: in a group that all hears the talker, the first relay is
        // the second copy everyone hears, and it suppresses the other relays.
        self.remember(packet.key(), Seen { first: now, own: false, copies: 1, pending });
        Heard::New
    }

    /// A packet `on_heard` took as new turned out to be refused (forged, or a replay): it is
    /// neither relayed nor remembered, so the genuine packet with the same key still counts
    /// as new when it arrives.
    pub fn forget(&mut self, packet: &Packet) {
        if self.seen.get(&packet.key()).is_some_and(|seen| !seen.own) {
            self.seen.remove(&packet.key());
        }
    }

    /// Our own packets, so their echoes are recognised.
    pub fn on_sent(&mut self, packet: &Packet, now: Instant) {
        self.forget_old(now);
        self.remember(packet.key(), Seen { first: now, own: true, copies: 0, pending: None });
    }

    /// Relays to send now, ttl already lowered.
    pub fn due(&mut self, now: Instant) -> Vec<Packet> {
        let mut out: Vec<(Instant, Packet)> = Vec::new();
        for seen in self.seen.values_mut() {
            if seen.pending.as_ref().is_some_and(|(at, _)| *at <= now) {
                out.extend(seen.pending.take());
            }
        }
        self.stats.relayed += out.len() as u64;
        self.forget_old(now);
        out.sort_by_key(|(at, packet)| (*at, packet.seq));
        out.into_iter().map(|(_, packet)| packet).collect()
    }

    /// When the next relay is due.
    pub fn next_due(&self) -> Option<Instant> {
        self.seen.values().filter_map(|seen| seen.pending.as_ref().map(|(at, _)| *at)).min()
    }

    /// Off: nothing is relayed (scheduled relays are dropped); packets are still recognised.
    pub fn set_enabled(&mut self, relay: bool) {
        self.enabled = relay;
        if !relay {
            self.seen.values_mut().for_each(|seen| seen.pending = None);
        }
    }

    pub fn stats(&self) -> RelayStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{codec, flags};

    fn packet(talker: u8, seq: u16, ttl: u8) -> Packet {
        Packet { flags: flags::START, ttl, epoch: 1, talker: [talker; 4], burst: 1, seq, counter: 1, codec: codec::OPUS16, frames: vec![vec![1; 20]], signature: None }
    }

    #[test]
    fn a_new_packet_is_relayed_once_within_the_delay() {
        let now = Instant::now();
        let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
        assert_eq!(relay.on_heard(&packet(1, 0, 4), now, 0.5), Heard::New);
        let at = relay.next_due().unwrap();
        assert_eq!(at, now + Duration::from_millis(25));
        assert!(relay.due(now + Duration::from_millis(24)).is_empty());
        let sent = relay.due(at);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].ttl, 3);
        assert!(relay.due(at + Duration::from_secs(1)).is_empty());
        // Our relay heard back is a copy, and is not relayed again.
        assert_eq!(relay.on_heard(&sent[0], at, 0.0), Heard::Duplicate);
        assert_eq!(relay.next_due(), None);
        assert_eq!(relay.stats().relayed, 1);
        for roll in [0.0, 0.999] {
            let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
            relay.on_heard(&packet(1, 0, 4), now, roll);
            let delay = relay.next_due().unwrap() - now;
            assert!(delay >= Duration::from_millis(10) && delay <= Duration::from_millis(40));
        }
    }

    #[test]
    fn copies_from_others_suppress_our_relay() {
        let now = Instant::now();
        let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
        // The talker's own transmission counts as the first copy: one relay heard from someone
        // else makes two (suppress_after) and ours is dropped.
        relay.on_heard(&packet(1, 0, 4), now, 0.9);
        assert!(relay.next_due().is_some());
        assert_eq!(relay.on_heard(&packet(1, 0, 3), now + Duration::from_millis(5), 0.0), Heard::Duplicate);
        assert_eq!(relay.next_due(), None);
        assert!(relay.due(now + Duration::from_secs(1)).is_empty());
        assert_eq!(relay.stats(), RelayStats { relayed: 0, suppressed: 1, duplicates: 1 });
        // With suppress_after 3, one relay from someone else is not enough.
        let mut patient = Relay::new(RelayConfig { suppress_after: 3, ..RelayConfig::default() }, [9; 4]);
        patient.on_heard(&packet(2, 0, 4), now, 0.9);
        patient.on_heard(&packet(2, 0, 3), now + Duration::from_millis(5), 0.0);
        assert!(patient.next_due().is_some(), "two copies are not enough for 3");
    }

    #[test]
    fn a_refused_packet_is_not_relayed_and_does_not_shadow_the_genuine_one() {
        let now = Instant::now();
        let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
        let forged = packet(1, 5, 4);
        assert_eq!(relay.on_heard(&forged, now, 0.5), Heard::New);
        relay.forget(&forged);
        assert!(relay.due(now + Duration::from_secs(1)).is_empty(), "not relayed");
        assert_eq!(relay.on_heard(&packet(1, 5, 4), now, 0.5), Heard::New, "the genuine one is new");
    }

    #[test]
    fn last_hop_own_echoes_and_disabled_relay() {
        let now = Instant::now();
        let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
        assert_eq!(relay.on_heard(&packet(1, 0, 1), now, 0.5), Heard::New);
        assert_eq!(relay.next_due(), None, "ttl 1 goes no further");
        let own = packet(9, 0, 4);
        relay.on_sent(&own, now);
        assert_eq!(relay.on_heard(&own, now, 0.5), Heard::Own);
        assert_eq!(relay.on_heard(&packet(9, 5, 4), now, 0.5), Heard::Own, "ours even when not recorded");
        relay.on_heard(&packet(2, 0, 4), now, 0.5);
        relay.set_enabled(false);
        assert_eq!(relay.next_due(), None);
        assert_eq!(relay.on_heard(&packet(2, 1, 4), now, 0.5), Heard::New);
        assert_eq!(relay.next_due(), None);
    }

    #[test]
    fn packets_are_forgotten_after_the_memory() {
        let now = Instant::now();
        let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
        relay.on_heard(&packet(1, 0, 4), now, 0.0);
        relay.due(now + Duration::from_millis(50));
        assert_eq!(relay.on_heard(&packet(1, 0, 4), now + Duration::from_secs(9), 0.0), Heard::Duplicate);
        assert_eq!(relay.on_heard(&packet(1, 0, 4), now + Duration::from_secs(11), 0.0), Heard::New);
    }

    #[test]
    fn memory_is_bounded_under_a_flood() {
        let now = Instant::now();
        let mut relay = Relay::new(RelayConfig::default(), [9; 4]);
        for n in 0..30_000u32 {
            let forged = Packet { talker: (n >> 16).to_be_bytes()[2..].iter().chain(&[1, 2]).copied().collect::<Vec<_>>().try_into().unwrap(), seq: n as u16, ..packet(0, 0, 1) };
            assert_eq!(relay.on_heard(&forged, now, 0.0), Heard::New);
            if n % 2 == 0 {
                relay.forget(&forged);
            }
        }
        assert!(relay.seen.len() <= SEEN && relay.order.len() <= SEEN);
        // The newest are still recognised.
        let last = Packet { talker: [0, 0, 1, 2], seq: 29_999u32 as u16, ..packet(0, 0, 1) };
        assert_eq!(relay.on_heard(&last, now, 0.0), Heard::Duplicate);
    }
}
