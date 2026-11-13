//! A burst flooded over small topologies with the real relay logic: every node hears every
//! packet exactly once, and suppression keeps the number of relays down where nodes are dense.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{Heard, Packer, Packet, Relay, RelayConfig, codec};

/// A small deterministic random source.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Outcome {
    /// Per node, how many times each packet was heard as new.
    new: Vec<HashMap<u16, u32>>,
    /// Per packet, how many relays went out.
    relays: HashMap<u16, u32>,
}

/// Node 0 talks a burst of `packets` packets (one every 60 ms) with `ttl`; a packet sent by a
/// node reaches its neighbours at once. Runs 2 s in 1 ms steps.
fn flood(neighbours: &[Vec<usize>], packets: usize, ttl: u8, seed: u64) -> Outcome {
    let start = Instant::now();
    let mut rng = Rng(seed);
    let ids: Vec<[u8; 4]> = (0..neighbours.len()).map(|node| [node as u8, 0xAA, 0xBB, 0xCC]).collect();
    let mut relays: Vec<Relay> = ids.iter().map(|id| Relay::new(RelayConfig::default(), *id)).collect();
    let mut packer = Packer::new(ids[0], 1, codec::OPUS16, ttl, 3);
    packer.start(1, false, 1);
    let mut burst: Vec<Packet> = Vec::new();
    for frame in 0..(packets * 3) {
        burst.extend(packer.push(vec![frame as u8; 40]));
    }
    let mut outcome = Outcome { new: vec![HashMap::new(); neighbours.len()], relays: HashMap::new() };
    // (time, from, packet) in flight, delivered to the sender's neighbours.
    let mut air: Vec<(Instant, usize, Packet)> = Vec::new();
    for ms in 0..2000u64 {
        let now = start + Duration::from_millis(ms);
        if ms % 60 == 0
            && let Some(packet) = burst.get((ms / 60) as usize)
        {
            relays[0].on_sent(packet, now);
            air.push((now, 0, packet.clone()));
        }
        for (node, relay) in relays.iter_mut().enumerate() {
            for packet in relay.due(now) {
                *outcome.relays.entry(packet.seq).or_default() += 1;
                air.push((now, node, packet));
            }
        }
        let (arriving, later): (Vec<_>, Vec<_>) = air.into_iter().partition(|(at, _, _)| *at <= now);
        air = later;
        for (_, from, packet) in arriving {
            for &to in &neighbours[from] {
                if relays[to].on_heard(&packet, now, rng.next()) == Heard::New {
                    *outcome.new[to].entry(packet.seq).or_default() += 1;
                }
            }
        }
    }
    outcome
}

fn every_node_hears_every_packet_once(outcome: &Outcome, nodes: usize, packets: usize) {
    for node in 1..nodes {
        assert_eq!(outcome.new[node].len(), packets, "node {node} missed packets");
        assert!(outcome.new[node].values().all(|count| *count == 1), "node {node} heard a packet twice");
    }
}

#[test]
fn a_chain_of_five_hears_the_burst_four_hops_out() {
    let chain: Vec<Vec<usize>> = (0..5).map(|node: usize| [node.checked_sub(1), Some(node + 1).filter(|next| *next < 5)].into_iter().flatten().collect()).collect();
    let outcome = flood(&chain, 10, 4, 1);
    every_node_hears_every_packet_once(&outcome, 5, 10);
    // Nodes 1-3 relay; node 4 hears it with ttl 1 and does not.
    assert!(outcome.relays.values().all(|count| *count == 3));
    // A ttl of 3 stops a hop short.
    let short = flood(&chain, 4, 3, 2);
    assert!(short.new[4].is_empty());
    assert_eq!(short.new[3].len(), 4);
}

#[test]
fn three_nodes_in_range_of_each_other_relay_at_most_once_per_packet() {
    // Three nodes that all hear each other. Both listeners hear the talker; the
    // first to relay suppresses the other, so each packet goes out at most twice in all.
    let full: Vec<Vec<usize>> = (0..3).map(|node| (0..3).filter(|other| *other != node).collect()).collect();
    let mut relays = 0;
    for seed in 1..40 {
        let outcome = flood(&full, 10, 4, seed);
        every_node_hears_every_packet_once(&outcome, 3, 10);
        relays += outcome.relays.values().sum::<u32>();
    }
    // Without counting the talker's copy this was 2 per packet. Both listeners still relay
    // when their delays fall within one step of each other (here 1 ms; on the air, within a
    // frame's airtime): about 3 % of packets.
    let per_packet = f64::from(relays) / (39.0 * 10.0);
    assert!(per_packet <= 1.1, "{per_packet:.2} relays per packet");
}

#[test]
fn in_a_grid_suppression_keeps_relays_below_the_node_count() {
    // 3 × 3, each node hears its horizontal and vertical neighbours; node 0 is a corner.
    let grid: Vec<Vec<usize>> = (0..9)
        .map(|node: usize| {
            let (row, col) = (node / 3, node % 3);
            let mut near = Vec::new();
            if row > 0 { near.push(node - 3) }
            if row < 2 { near.push(node + 3) }
            if col > 0 { near.push(node - 1) }
            if col < 2 { near.push(node + 1) }
            near
        })
        .collect();
    for seed in 1..20 {
        let outcome = flood(&grid, 10, 6, seed);
        every_node_hears_every_packet_once(&outcome, 9, 10);
        assert!(outcome.relays.values().all(|count| *count < 9), "seed {seed}: {:?}", outcome.relays);
    }
    // A full mesh: one or two relays reach nobody new, and the rest are suppressed.
    let full: Vec<Vec<usize>> = (0..9).map(|node| (0..9).filter(|other| *other != node).collect()).collect();
    let outcome = flood(&full, 10, 6, 3);
    every_node_hears_every_packet_once(&outcome, 9, 10);
    assert!(outcome.relays.values().all(|count| *count <= 2), "{:?}", outcome.relays);
}
