//! Packet-level selective-repeat ARQ between two hubs.
//!
//! Every mux packet a [`Sender`] numbers is kept until the peer's [`Ack`] covers it, and sent
//! again after a timeout (RTO from the measured round trip) or as soon as the acknowledgement
//! shows later packets arrived without it. The [`Receiver`] hands packets on in order, holding
//! a gap for a short while before giving up on it, and says what arrived in an [`Ack`] that
//! rides on the next packet going the other way, or alone after a short delay.
//!
//! The point is to repair a lost radio frame in tens of milliseconds, before TCP notices: on a
//! radio losing a few percent of frames, TCP otherwise spends its time backing off. A packet
//! that still fails after a few tries is given up, and TCP repairs it as before.
//!
//! Pure: time is passed in.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::Ack;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Packets in flight before new ones go out unnumbered.
    pub window: u16,
    /// Sends after the first before a packet is given up.
    pub max_retries: u8,
    pub rto_initial: Duration,
    pub rto_min: Duration,
    pub rto_max: Duration,
    /// How long the receiver waits for a missing packet before passing later ones on.
    pub hold: Duration,
    /// How long an acknowledgement may wait for a packet going the other way.
    pub ack_delay: Duration,
    /// Packets received before an acknowledgement goes out anyway.
    pub ack_every: u16,
    /// Later packets acknowledged before a missing one is sent again at once.
    pub dup_threshold: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            window: 64,
            max_retries: 3,
            rto_initial: Duration::from_millis(400),
            rto_min: Duration::from_millis(60),
            rto_max: Duration::from_secs(2),
            hold: Duration::from_millis(300),
            ack_delay: Duration::from_millis(20),
            ack_every: 4,
            dup_threshold: 2,
        }
    }
}

/// `a - b` in sequence space.
fn ahead(a: u16, b: u16) -> i32 {
    i32::from(a.wrapping_sub(b) as i16)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SenderStats {
    pub sent: u64,
    pub retransmitted: u64,
    pub given_up: u64,
    pub unnumbered: u64,
}

struct Pending {
    packet: Vec<u8>,
    first_sent: Instant,
    last_sent: Instant,
    retries: u8,
    acked: bool,
    fast: bool,
}

pub struct Sender {
    config: Config,
    /// Seq of the front of `flight`.
    base: u16,
    flight: VecDeque<Pending>,
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    stats: SenderStats,
}

impl Sender {
    pub fn new(config: Config, initial_seq: u16) -> Self {
        Self { config, base: initial_seq, flight: VecDeque::new(), srtt: None, rttvar: Duration::ZERO, rto: config.rto_initial, stats: SenderStats::default() }
    }

    fn next_seq(&self) -> u16 {
        self.base.wrapping_add(self.flight.len() as u16)
    }

    /// Numbers `packet` (unstamped) and keeps it for repair; None when the window is full
    /// (send it unnumbered).
    pub fn send(&mut self, packet: Vec<u8>, now: Instant) -> Option<u16> {
        if self.flight.len() >= usize::from(self.config.window) {
            self.stats.unnumbered += 1;
            return None;
        }
        let seq = self.next_seq();
        self.flight.push_back(Pending { packet, first_sent: now, last_sent: now, retries: 0, acked: false, fast: false });
        self.stats.sent += 1;
        Some(seq)
    }

    fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + delta) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
        let srtt = self.srtt.expect("set above");
        self.rto = (srtt + self.rttvar * 4).max(srtt * 3 / 2).clamp(self.config.rto_min, self.config.rto_max);
    }

    fn acknowledge(&mut self, index: usize, now: Instant) {
        let pending = &mut self.flight[index];
        if pending.acked {
            return;
        }
        pending.acked = true;
        // Karn: only a packet sent once gives a round trip.
        if pending.retries == 0 {
            let rtt = now.duration_since(pending.first_sent);
            self.sample(rtt);
        }
    }

    /// The peer's acknowledgement.
    pub fn on_ack(&mut self, ack: Ack, now: Instant) {
        let in_flight = self.flight.len() as i32;
        let below = ahead(ack.cum, self.base);
        if below < 0 || below > in_flight {
            return;
        }
        for index in 0..below as usize {
            self.acknowledge(index, now);
        }
        let mut later = 0;
        for bit in 0..16 {
            if ack.bitmap & (1 << bit) == 0 {
                continue;
            }
            let index = below + 1 + bit;
            if index < in_flight {
                self.acknowledge(index as usize, now);
                later += 1;
            }
        }
        // The missing one at `cum`, with later ones through: lost, not late.
        if later >= self.config.dup_threshold
            && let Some(missing) = self.flight.get_mut(below as usize)
            && !missing.acked
            && now.duration_since(missing.last_sent) >= self.srtt.unwrap_or(self.config.rto_min)
        {
            missing.fast = true;
        }
        self.trim();
    }

    fn trim(&mut self) {
        while self.flight.front().is_some_and(|pending| pending.acked) {
            self.flight.pop_front();
            self.base = self.base.wrapping_add(1);
        }
    }

    fn timeout_of(&self, pending: &Pending) -> Duration {
        (self.rto * (1 << pending.retries.min(4))).min(self.config.rto_max)
    }

    /// Packets to send again now: (seq, unstamped packet).
    pub fn due(&mut self, now: Instant) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        for index in 0..self.flight.len() {
            let timeout = self.timeout_of(&self.flight[index]);
            let seq = self.base.wrapping_add(index as u16);
            let pending = &mut self.flight[index];
            if pending.acked || !(pending.fast || now.duration_since(pending.last_sent) >= timeout) {
                continue;
            }
            if pending.retries >= self.config.max_retries {
                pending.acked = true;
                self.stats.given_up += 1;
                continue;
            }
            pending.retries += 1;
            pending.fast = false;
            pending.last_sent = now;
            self.stats.retransmitted += 1;
            out.push((seq, pending.packet.clone()));
        }
        self.trim();
        out
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.flight.iter().filter(|pending| !pending.acked).map(|pending| pending.last_sent + self.timeout_of(pending)).min()
    }

    pub fn in_flight(&self) -> usize {
        self.flight.iter().filter(|pending| !pending.acked).count()
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn stats(&self) -> SenderStats {
        self.stats
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiverStats {
    pub delivered: u64,
    pub duplicates: u64,
    pub skipped: u64,
    pub resyncs: u64,
}

pub struct Receiver {
    config: Config,
    expected: Option<u16>,
    /// Packets after a gap: seq → (packet, arrived).
    held: BTreeMap<i32, (u16, Vec<u8>, Instant)>,
    ack_pending: bool,
    received_since_ack: u16,
    ack_due_at: Option<Instant>,
    stats: ReceiverStats,
}

impl Receiver {
    pub fn new(config: Config) -> Self {
        Self { config, expected: None, held: BTreeMap::new(), ack_pending: false, received_since_ack: 0, ack_due_at: None, stats: ReceiverStats::default() }
    }

    fn note_ack(&mut self, now: Instant) {
        self.ack_pending = true;
        self.received_since_ack = self.received_since_ack.saturating_add(1);
        self.ack_due_at.get_or_insert(now + self.config.ack_delay);
    }

    /// Passes on, in order, what can be passed on.
    fn drain(&mut self, out: &mut Vec<Vec<u8>>) {
        let Some(mut expected) = self.expected else { return };
        while let Some((_, (seq, _, _))) = self.held.first_key_value() {
            if *seq != expected {
                break;
            }
            let (_, (_, packet, _)) = self.held.pop_first().expect("checked above");
            out.push(packet);
            self.stats.delivered += 1;
            expected = expected.wrapping_add(1);
        }
        self.expected = Some(expected);
        // Re-key what is still held against the new expected seq.
        let held = std::mem::take(&mut self.held);
        self.held = held.into_values().map(|(seq, packet, arrived)| (ahead(seq, expected), (seq, packet, arrived))).collect();
    }

    /// A numbered packet arrived; returns the packets that may be passed on now, in order.
    pub fn on_packet(&mut self, seq: u16, packet: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        self.note_ack(now);
        let expected = *self.expected.get_or_insert(seq);
        let mut offset = ahead(seq, expected);
        let far = 4 * i32::from(self.config.window);
        if offset > far || offset < -far {
            // The sender restarted, or we did: start again from here.
            self.stats.resyncs += 1;
            self.held.clear();
            self.expected = Some(seq);
            offset = 0;
        }
        if offset < 0 || self.held.contains_key(&offset) {
            self.stats.duplicates += 1;
            return Vec::new();
        }
        self.held.insert(offset, (seq, packet, now));
        let mut out = Vec::new();
        if offset == 0 {
            self.drain(&mut out);
        }
        out
    }

    /// The acknowledgement to send, if any is pending; it is then no longer pending.
    pub fn take_ack(&mut self) -> Option<Ack> {
        if !self.ack_pending {
            return None;
        }
        self.ack_pending = false;
        self.received_since_ack = 0;
        self.ack_due_at = None;
        let cum = self.expected?;
        let mut bitmap = 0u16;
        for bit in 0..16 {
            if self.held.contains_key(&(bit + 1)) {
                bitmap |= 1 << bit;
            }
        }
        Some(Ack { cum, bitmap })
    }

    /// Whether an acknowledgement must go out alone now.
    pub fn ack_due(&self, now: Instant) -> bool {
        self.ack_pending && (self.received_since_ack >= self.config.ack_every || self.ack_due_at.is_some_and(|due| now >= due))
    }

    /// After the hold time, gives up on a gap and passes on what follows it.
    pub fn release(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(oldest) = self.held.values().map(|(_, _, arrived)| *arrived).min() {
            if now.duration_since(oldest) < self.config.hold {
                break;
            }
            let Some((_, (seq, _, _))) = self.held.first_key_value() else { break };
            let skipped = ahead(*seq, self.expected.expect("held implies expected"));
            self.stats.skipped += skipped.max(0) as u64;
            self.expected = Some(*seq);
            self.drain(&mut out);
        }
        out
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        let ack = if self.ack_pending { self.ack_due_at } else { None };
        let hold = self.held.values().map(|(_, _, arrived)| *arrived + self.config.hold).min();
        match (ack, hold) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn stats(&self) -> ReceiverStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn in_order_packets_pass_straight_through_and_are_acknowledged() {
        let now = Instant::now();
        let mut sender = Sender::new(Config::default(), 65534);
        let mut receiver = Receiver::new(Config::default());
        for i in 0..4u8 {
            let seq = sender.send(vec![i], now).unwrap();
            assert_eq!(receiver.on_packet(seq, vec![i], now), vec![vec![i]]);
        }
        assert!(receiver.ack_due(now), "4 packets make an acknowledgement due");
        let ack = receiver.take_ack().unwrap();
        assert_eq!(ack, Ack { cum: 2, bitmap: 0 }, "seq wrapped: 65534, 65535, 0, 1 arrived");
        sender.on_ack(ack, now + ms(30));
        assert_eq!(sender.in_flight(), 0);
        assert_eq!(sender.srtt(), Some(ms(30)));
        assert!(sender.due(now + ms(5000)).is_empty());
    }

    #[test]
    fn a_lost_packet_is_repaired_fast_and_delivery_stays_in_order() {
        let now = Instant::now();
        let mut sender = Sender::new(Config::default(), 0);
        let mut receiver = Receiver::new(Config::default());
        // Establish a round trip first.
        let seq = sender.send(b"a".to_vec(), now).unwrap();
        receiver.on_packet(seq, b"a".to_vec(), now);
        sender.on_ack(receiver.take_ack().unwrap(), now + ms(40));
        let t = now + ms(100);
        let lost = sender.send(b"b".to_vec(), t).unwrap();
        let c = sender.send(b"c".to_vec(), t).unwrap();
        let d = sender.send(b"d".to_vec(), t).unwrap();
        let _ = lost;
        assert!(receiver.on_packet(c, b"c".to_vec(), t).is_empty(), "held behind the gap");
        assert!(receiver.on_packet(d, b"d".to_vec(), t).is_empty());
        let ack = receiver.take_ack().unwrap();
        assert_eq!(ack.bitmap, 0b11);
        sender.on_ack(ack, t + ms(45));
        let again = sender.due(t + ms(45));
        assert_eq!(again, vec![(lost, b"b".to_vec())], "sent again at once, not after the RTO");
        assert_eq!(receiver.on_packet(lost, b"b".to_vec(), t + ms(80)), vec![b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]);
    }

    #[test]
    fn timeouts_back_off_and_a_hopeless_packet_is_given_up() {
        let now = Instant::now();
        let config = Config { rto_initial: ms(100), ..Config::default() };
        let mut sender = Sender::new(config, 7);
        sender.send(b"x".to_vec(), now).unwrap();
        assert!(sender.due(now + ms(99)).is_empty());
        assert_eq!(sender.due(now + ms(100)).len(), 1, "first RTO");
        assert!(sender.due(now + ms(299)).is_empty(), "backed off to 200 ms");
        assert_eq!(sender.due(now + ms(300)).len(), 1);
        assert_eq!(sender.due(now + ms(700)).len(), 1);
        assert!(sender.due(now + ms(2000)).is_empty(), "given up after 3 retries");
        assert_eq!(sender.stats().given_up, 1);
        assert_eq!(sender.in_flight(), 0);
    }

    #[test]
    fn the_receiver_gives_up_on_a_gap_after_the_hold() {
        let now = Instant::now();
        let mut receiver = Receiver::new(Config::default());
        assert_eq!(receiver.on_packet(10, b"a".to_vec(), now), vec![b"a".to_vec()]);
        assert!(receiver.on_packet(12, b"c".to_vec(), now).is_empty());
        assert!(receiver.release(now + ms(299)).is_empty());
        assert_eq!(receiver.release(now + ms(300)), vec![b"c".to_vec()]);
        assert_eq!(receiver.stats().skipped, 1);
        assert!(receiver.on_packet(11, b"b".to_vec(), now + ms(400)).is_empty(), "too late: a duplicate now");
        assert_eq!(receiver.stats().duplicates, 1);
    }

    #[test]
    fn a_full_window_sends_unnumbered_and_a_restart_resyncs() {
        let now = Instant::now();
        let config = Config { window: 2, ..Config::default() };
        let mut sender = Sender::new(config, 0);
        assert!(sender.send(vec![1], now).is_some());
        assert!(sender.send(vec![2], now).is_some());
        assert_eq!(sender.send(vec![3], now), None);
        assert_eq!(sender.stats().unnumbered, 1);
        let mut receiver = Receiver::new(config);
        receiver.on_packet(100, vec![1], now);
        assert_eq!(receiver.on_packet(40000, vec![2], now), vec![vec![2]], "far away: the sender restarted");
        assert_eq!(receiver.stats().resyncs, 1);
    }

    #[test]
    fn duplicates_are_dropped_but_still_acknowledged() {
        let now = Instant::now();
        let mut receiver = Receiver::new(Config::default());
        receiver.on_packet(5, vec![1], now);
        receiver.take_ack();
        assert!(receiver.on_packet(5, vec![1], now).is_empty());
        assert_eq!(receiver.take_ack(), Some(Ack { cum: 6, bitmap: 0 }), "the sender's copy of our ack was lost: say it again");
        assert!(receiver.ack_due(now + ms(25)) || receiver.take_ack().is_none());
    }

    #[test]
    fn a_lossy_link_still_delivers_everything_in_order() {
        // 20 % loss each way, both data and acknowledgements; everything arrives once, in order.
        let mut rng = 12345u64;
        let mut lose = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % 100 < 20
        };
        let start = Instant::now();
        let mut sender = Sender::new(Config::default(), 60000);
        let mut receiver = Receiver::new(Config::default());
        let mut delivered = Vec::new();
        let mut wire: Vec<(Instant, u16, Vec<u8>)> = Vec::new();
        let mut acks: Vec<(Instant, Ack)> = Vec::new();
        let mut next = 0u32;
        for step in 0..4000u64 {
            let now = start + ms(step);
            if step % 10 == 0 && next < 200 {
                let packet = next.to_be_bytes().to_vec();
                if let Some(seq) = sender.send(packet.clone(), now) {
                    next += 1;
                    if !lose() {
                        wire.push((now + ms(15), seq, packet));
                    }
                }
            }
            for (seq, packet) in sender.due(now) {
                if !lose() {
                    wire.push((now + ms(15), seq, packet));
                }
            }
            let (arrived, rest): (Vec<_>, Vec<_>) = wire.drain(..).partition(|(at, _, _)| *at <= now);
            wire = rest;
            for (_, seq, packet) in arrived {
                delivered.extend(receiver.on_packet(seq, packet, now));
            }
            delivered.extend(receiver.release(now));
            if receiver.ack_due(now)
                && let Some(ack) = receiver.take_ack()
                && !lose()
            {
                acks.push((now + ms(15), ack));
            }
            let (arrived, rest): (Vec<_>, Vec<_>) = acks.drain(..).partition(|(at, _)| *at <= now);
            acks = rest;
            for (_, ack) in arrived {
                sender.on_ack(ack, now);
            }
        }
        let numbers: Vec<u32> = delivered.iter().map(|p| u32::from_be_bytes(p[..4].try_into().unwrap())).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(numbers, sorted, "in order, no duplicates");
        // With 3 retries at 20 % loss, about 0.2^4 = 0.16 % are given up.
        assert!(numbers.len() >= 197, "delivered {} of 200", numbers.len());
    }
}
