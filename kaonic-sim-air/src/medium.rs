//! The shared channel, without I/O or clocks: who hears a frame, when it ends, and
//! whether it survives (range, random loss, collisions, half duplex). Time is in
//! microseconds from any origin; the caller passes it in.

use std::collections::{HashMap, HashSet};

/// 802.15.4's backoff period: 20 symbols of 16 µs.
const BACKOFF_PERIOD_US: u64 = 320;
/// macMinBE and macMaxBE.
const MIN_BE: u32 = 3;
const MAX_BE: u32 = 5;

/// What one receiver makes of a frame from one sender.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkParams {
    /// Probability that the frame is lost (fading, noise), 0 to 1.
    pub loss: f64,
    pub rssi: i8,
}

impl Default for LinkParams {
    fn default() -> Self {
        Self { loss: 0.0, rssi: -60 }
    }
}

#[derive(Clone, Debug)]
pub struct MediumConfig {
    /// PHY bit rate: MR-OFDM option 1, MCS 6 by default (the fielded setting).
    pub bit_rate: u64,
    /// Preamble and PHY header of each frame.
    pub preamble_us: u64,
    /// What a sender spends per frame beyond its time on air (frame load, TX pacing, CCA):
    /// it cannot send again sooner, but the channel is free for others meanwhile.
    pub tx_gap_us: u64,
    /// A sender holds at most this many frames' worth of time in its queue; more are dropped,
    /// as the driver drops frames when its queue is full. Hub nodes pace themselves to 4
    /// (their socket buffer), so a little more leaves room for UDP timing jitter.
    pub queue_frames: u64,
    /// Listen before talk: a sender that hears the channel busy waits until it is free.
    pub carrier_sense: bool,
    /// For node pairs not listed.
    pub default_link: LinkParams,
}

impl Default for MediumConfig {
    fn default() -> Self {
        Self { bit_rate: 2_400_000, preamble_us: 1080, tx_gap_us: 9000, queue_frames: 6, carrier_sense: true, default_link: LinkParams::default() }
    }
}

impl MediumConfig {
    pub fn airtime_us(&self, bytes: usize) -> u64 {
        self.preamble_us + (bytes as u64 * 8 * 1_000_000).div_ceil(self.bit_rate.max(1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    Received,
    /// Lost to the link's random loss.
    Lost,
    /// Overlapped another frame at the receiver.
    Collided,
    /// The receiver was sending at the time.
    Deaf,
}

/// A frame on its way to one receiver.
#[derive(Clone, Debug)]
pub struct Reception {
    pub id: u64,
    pub from: String,
    pub to: String,
    pub start: u64,
    pub end: u64,
    pub rssi: i8,
    fate: Fate,
}

/// What a transmission became: dropped at the sender, or on the air from `start` to `end`.
#[derive(Clone, Debug, PartialEq)]
pub enum Transmission {
    Dropped,
    OnAir { start: u64, end: u64, receptions: Vec<(u64, String, u64)> },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeStats {
    pub sent: u64,
    pub dropped: u64,
    pub received: u64,
    pub lost: u64,
    pub collided: u64,
    pub deaf: u64,
}

#[derive(Default)]
struct Node {
    /// The sender's own last frame on the air, and when it can send again.
    tx_start: u64,
    tx_end: u64,
    busy_until: u64,
    stats: NodeStats,
}

fn pair(a: &str, b: &str) -> (String, String) {
    if a <= b { (a.to_owned(), b.to_owned()) } else { (b.to_owned(), a.to_owned()) }
}

pub struct Medium {
    config: MediumConfig,
    links: HashMap<(String, String), LinkParams>,
    blocked: HashSet<(String, String)>,
    nodes: HashMap<String, Node>,
    receptions: HashMap<u64, Reception>,
    next_id: u64,
}

impl Medium {
    pub fn new(config: MediumConfig) -> Self {
        Self { config, links: HashMap::new(), blocked: HashSet::new(), nodes: HashMap::new(), receptions: HashMap::new(), next_id: 1 }
    }

    pub fn config(&self) -> &MediumConfig {
        &self.config
    }

    pub fn add_node(&mut self, name: &str) {
        self.nodes.entry(name.to_owned()).or_default();
    }

    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.nodes.keys().map(String::as_str)
    }

    /// Both directions of the pair `a`–`b`.
    pub fn set_link(&mut self, a: &str, b: &str, params: LinkParams) {
        self.links.insert(pair(a, b), params);
    }

    /// `a` and `b` cannot hear each other (out of range).
    pub fn block(&mut self, a: &str, b: &str) {
        self.blocked.insert(pair(a, b));
    }

    pub fn unblock(&mut self, a: &str, b: &str) {
        self.blocked.remove(&pair(a, b));
    }

    pub fn hears(&self, a: &str, b: &str) -> bool {
        a != b && !self.blocked.contains(&pair(a, b))
    }

    pub fn link(&self, a: &str, b: &str) -> LinkParams {
        self.links.get(&pair(a, b)).copied().unwrap_or(self.config.default_link)
    }

    pub fn stats(&self) -> Vec<(String, NodeStats)> {
        let mut stats: Vec<_> = self.nodes.iter().map(|(name, node)| (name.clone(), node.stats.clone())).collect();
        stats.sort_by(|a, b| a.0.cmp(&b.0));
        stats
    }

    /// `from` sends a frame of `bytes` at `now`. `roll` gives uniform numbers in [0, 1)
    /// for random loss and backoff.
    pub fn transmit(&mut self, from: &str, now: u64, bytes: usize, roll: &mut impl FnMut() -> f64) -> Transmission {
        self.add_node(from);
        // Forget frames long over.
        self.receptions.retain(|_, reception| reception.end + 5_000_000 > now);
        let airtime = self.config.airtime_us(bytes);
        let mut start = now.max(self.nodes[from].busy_until);
        // Each queued frame holds the sender for its airtime and the per-frame gap.
        if start - now > (airtime + self.config.tx_gap_us).max(1) * self.config.queue_frames {
            self.nodes.get_mut(from).expect("sender").stats.dropped += 1;
            return Transmission::Dropped;
        }
        if self.config.carrier_sense {
            // IEEE 802.15.4 unslotted CSMA-CA: while the sender hears the channel busy, it waits
            // until it is free, then 0..2^BE-1 backoff periods, BE growing from 3 to 5 with each
            // busy channel it finds. Senders that deferred to the same frame then start apart.
            for attempt in 0..64u32 {
                let busy = self.receptions.values().filter(|reception| reception.to == from && reception.start <= start && start < reception.end).map(|reception| reception.end).max();
                let Some(end) = busy else { break };
                let exponent = (MIN_BE + attempt).min(MAX_BE);
                let periods = ((roll() * f64::from(1u32 << exponent)) as u64).min((1 << exponent) - 1);
                start = end + periods * BACKOFF_PERIOD_US;
            }
        }
        let end = start + airtime;
        {
            let node = self.nodes.get_mut(from).expect("sender");
            node.tx_start = start;
            node.tx_end = end;
            node.busy_until = end + self.config.tx_gap_us;
            node.stats.sent += 1;
        }
        // Half duplex: what the sender was receiving meanwhile is lost to it.
        for reception in self.receptions.values_mut() {
            if reception.to == from && reception.start < end && start < reception.end && reception.fate == Fate::Received {
                reception.fate = Fate::Deaf;
            }
        }
        let receivers: Vec<String> = self.nodes.keys().filter(|name| self.hears(from, name)).cloned().collect();
        let mut receptions = Vec::new();
        for to in receivers {
            let params = self.link(from, &to);
            let receiver = &self.nodes[&to];
            let mut fate = if receiver.tx_start < end && start < receiver.tx_end {
                Fate::Deaf
            } else if roll() < params.loss {
                Fate::Lost
            } else {
                Fate::Received
            };
            // Two frames overlapping at one receiver: neither can be decoded.
            for other in self.receptions.values_mut() {
                if other.to == to && other.start < end && start < other.end {
                    if other.fate == Fate::Received {
                        other.fate = Fate::Collided;
                    }
                    if fate == Fate::Received {
                        fate = Fate::Collided;
                    }
                }
            }
            let id = self.next_id;
            self.next_id += 1;
            self.receptions.insert(id, Reception { id, from: from.to_owned(), to: to.clone(), start, end, rssi: params.rssi, fate });
            receptions.push((id, to, end));
        }
        Transmission::OnAir { start, end, receptions }
    }

    /// The frame `id` has ended: did it get through? Counts it, once.
    pub fn finish(&mut self, id: u64) -> Option<(Fate, i8)> {
        let reception = self.receptions.get(&id)?;
        let (fate, rssi, to) = (reception.fate, reception.rssi, reception.to.clone());
        let stats = &mut self.nodes.get_mut(&to)?.stats;
        match fate {
            Fate::Received => stats.received += 1,
            Fate::Lost => stats.lost += 1,
            Fate::Collided => stats.collided += 1,
            Fate::Deaf => stats.deaf += 1,
        }
        Some((fate, rssi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn medium(nodes: &[&str], carrier_sense: bool) -> Medium {
        let mut medium = Medium::new(MediumConfig { carrier_sense, tx_gap_us: 0, ..MediumConfig::default() });
        for node in nodes {
            medium.add_node(node);
        }
        medium
    }

    fn never() -> impl FnMut() -> f64 {
        || 0.99
    }

    fn fates(medium: &mut Medium, transmission: &Transmission) -> Vec<(String, Fate)> {
        let Transmission::OnAir { receptions, .. } = transmission else { panic!("dropped") };
        let mut fates: Vec<_> = receptions.iter().map(|(id, to, _)| (to.clone(), medium.finish(*id).unwrap().0)).collect();
        fates.sort_by(|a, b| a.0.cmp(&b.0));
        fates
    }

    #[test]
    fn a_frame_reaches_everyone_in_range_after_its_airtime() {
        let mut medium = medium(&["a", "b", "c"], true);
        medium.block("a", "c");
        let sent = medium.transmit("a", 1000, 300, &mut never());
        let Transmission::OnAir { start, end, .. } = sent else { panic!() };
        assert_eq!((start, end), (1000, 1000 + 1080 + 1000));
        assert_eq!(fates(&mut medium, &sent), vec![("b".to_owned(), Fate::Received)]);
    }

    #[test]
    fn loss_zero_and_one() {
        let mut medium = medium(&["a", "b"], true);
        medium.set_link("a", "b", LinkParams { loss: 1.0, rssi: -90 });
        let sent = medium.transmit("a", 0, 100, &mut never());
        assert_eq!(fates(&mut medium, &sent), vec![("b".to_owned(), Fate::Lost)]);
        medium.set_link("b", "a", LinkParams { loss: 0.0, rssi: -70 });
        let sent = medium.transmit("a", 1_000_000, 100, &mut never());
        let Transmission::OnAir { receptions, .. } = &sent else { panic!() };
        assert_eq!(medium.finish(receptions[0].0), Some((Fate::Received, -70)));
    }

    #[test]
    fn hidden_nodes_collide_at_the_middle() {
        // a and c cannot hear each other, so carrier sense does not help: both frames are lost at b.
        let mut medium = medium(&["a", "b", "c"], true);
        medium.block("a", "c");
        let first = medium.transmit("a", 0, 500, &mut never());
        let second = medium.transmit("c", 500, 500, &mut never());
        assert_eq!(fates(&mut medium, &first), vec![("b".to_owned(), Fate::Collided)]);
        assert_eq!(fates(&mut medium, &second), vec![("b".to_owned(), Fate::Collided)]);
        assert_eq!(medium.stats().iter().find(|(name, _)| name == "b").unwrap().1.collided, 2);
    }

    #[test]
    fn carrier_sense_waits_for_a_free_channel() {
        let mut medium = medium(&["a", "b", "c"], true);
        let first = medium.transmit("a", 0, 500, &mut never());
        let second = medium.transmit("c", 500, 500, &mut never());
        let (Transmission::OnAir { end: first_end, .. }, Transmission::OnAir { start: second_start, .. }) = (&first, &second) else { panic!() };
        assert!(second_start >= first_end);
        assert_eq!(fates(&mut medium, &first), vec![("b".to_owned(), Fate::Received), ("c".to_owned(), Fate::Received)]);
    }

    #[test]
    fn senders_that_deferred_to_one_frame_start_at_different_backoffs() {
        // b and c both wait for a's frame; their backoffs differ, so their frames do not overlap
        // at d, which hears both (but neither hears the other, so carrier sense cannot help them).
        let mut medium = medium(&["a", "b", "c", "d"], true);
        medium.block("b", "c");
        let first = medium.transmit("a", 0, 500, &mut never());
        let Transmission::OnAir { end: busy_end, .. } = first else { panic!() };
        // The first roll of each is its backoff; the rest decide loss (none on these links).
        let mut rolls = [0.9].into_iter();
        let b = medium.transmit("b", 100, 100, &mut || rolls.next().unwrap_or(0.5));
        let mut rolls = [0.1].into_iter();
        let c = medium.transmit("c", 100, 100, &mut || rolls.next().unwrap_or(0.5));
        let (Transmission::OnAir { start: b_start, .. }, Transmission::OnAir { start: c_start, .. }) = (&b, &c) else { panic!() };
        // BE 3: 8 periods; roll 0.1 gives period 0, roll 0.9 gives period 7.
        assert_eq!(*b_start, busy_end + 7 * BACKOFF_PERIOD_US);
        assert_eq!(*c_start, busy_end);
        let d = |medium: &mut Medium, transmission: &Transmission| fates(medium, transmission).into_iter().find(|(to, _)| to == "d").unwrap().1;
        assert_eq!(d(&mut medium, &b), Fate::Received);
        assert_eq!(d(&mut medium, &c), Fate::Received);
    }

    #[test]
    fn without_carrier_sense_overlapping_senders_collide_and_are_deaf() {
        let mut medium = medium(&["a", "b", "c"], false);
        let first = medium.transmit("a", 0, 500, &mut never());
        let second = medium.transmit("c", 500, 500, &mut never());
        // c was sending while a's frame arrived; b got both at once.
        assert_eq!(fates(&mut medium, &first), vec![("b".to_owned(), Fate::Collided), ("c".to_owned(), Fate::Deaf)]);
        assert_eq!(fates(&mut medium, &second), vec![("a".to_owned(), Fate::Deaf), ("b".to_owned(), Fate::Collided)]);
    }

    #[test]
    fn a_sender_queues_its_own_frames_and_drops_past_its_queue() {
        let mut medium = Medium::new(MediumConfig { queue_frames: 2, tx_gap_us: 0, ..MediumConfig::default() });
        medium.add_node("b");
        let airtime = medium.config().airtime_us(100);
        let mut ends = Vec::new();
        let mut dropped = 0;
        for _ in 0..5 {
            match medium.transmit("a", 0, 100, &mut never()) {
                Transmission::OnAir { start, end, .. } => {
                    assert!(start >= ends.last().copied().unwrap_or(0));
                    ends.push(end);
                }
                Transmission::Dropped => dropped += 1,
            }
        }
        assert_eq!(ends, vec![airtime, 2 * airtime, 3 * airtime]);
        assert_eq!(dropped, 2);
    }
}
