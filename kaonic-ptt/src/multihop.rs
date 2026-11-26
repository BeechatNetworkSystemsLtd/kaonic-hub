//! Talkers on a small mesh, with each node's real relay, replay check and floor: what every
//! node plays when people key at once several hops apart.
//!
//! A packet sent by a node reaches its neighbours `HOP` later (about the airtime of a voice
//! packet); relays add their own 10-40 ms. A talker sends a packet of 5 frames every 100 ms,
//! the first one 100 ms after the press (the packing delay), and repeats its END three times
//! 30 ms apart, as the hub does. A talker whose floor says `Preempted` stops at once and sends
//! its END, as the hub does. `loss` is the share of packets lost on each link.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::{Floor, FloorEvent, FloorState, Heard, Packer, Packet, Relay, RelayConfig, Replay, codec};

const HOP: Duration = Duration::from_millis(35);
const PACKET_EVERY_MS: u64 = 100;
const FRAMES_PER_PACKET: usize = 5;
const RUN_MS: u64 = 5000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Someone presses on `node` at `at_ms` and talks for `packets` packets.
#[derive(Clone, Copy)]
struct Press {
    node: usize,
    at_ms: u64,
    packets: usize,
}

#[derive(Default)]
struct NodeLog {
    /// Voice packets that passed relay and replay here, per talker node.
    heard: HashMap<usize, usize>,
    /// Voice packets the floor played here, per talker node.
    played: HashMap<usize, usize>,
    first_played: Option<usize>,
    last_played: Option<usize>,
    /// Remote bursts that ended here: the talker node, and whether by its END (false: the
    /// 500 ms timeout).
    ended: Vec<(usize, bool)>,
    /// The press here was refused.
    busy: bool,
    /// Our talk was stopped by someone else's.
    yielded: bool,
    /// Voice packets we sent.
    sent: usize,
    /// The presses here that were refused, by time.
    refused: Vec<u64>,
    /// Voice packets played here, per talker node and burst id.
    bursts: HashMap<(usize, u16), usize>,
    final_state: Option<FloorState>,
    /// Relays this node sent, and those it dropped because others relayed first.
    relayed: u64,
    suppressed: u64,
}

impl NodeLog {
    fn played(&self, talker: usize) -> usize {
        self.played.get(&talker).copied().unwrap_or(0)
    }

    fn heard(&self, talker: usize) -> usize {
        self.heard.get(&talker).copied().unwrap_or(0)
    }

    /// Voice packets played here of press `turn` of `presses` (none of them refused): a node's
    /// burst ids start at `first_burst` and grow by one a press.
    fn turn(&self, presses: &[Press], turn: usize) -> usize {
        let node = presses[turn].node;
        let earlier = presses[..turn].iter().filter(|press| press.node == node).count() as u16;
        self.bursts.get(&(node, first_burst(node) + earlier)).copied().unwrap_or(0)
    }

    /// The talker this node played most of.
    fn mostly_played(&self) -> Option<usize> {
        self.played.iter().max_by_key(|(talker, count)| (**count, std::cmp::Reverse(**talker))).map(|(talker, _)| *talker)
    }
}

enum Out {
    Send(Packet),
    Release,
}

/// The id of a node's first burst.
fn first_burst(node: usize) -> u16 {
    100 + 7 * node as u16
}

fn chain(nodes: usize) -> Vec<Vec<usize>> {
    (0..nodes).map(|node: usize| [node.checked_sub(1), Some(node + 1).filter(|next| *next < nodes)].into_iter().flatten().collect()).collect()
}

fn cell(nodes: usize) -> Vec<Vec<usize>> {
    (0..nodes).map(|node| (0..nodes).filter(|other| *other != node).collect()).collect()
}

fn run(neighbours: &[Vec<usize>], presses: &[Press], seed: u64) -> Vec<NodeLog> {
    run_for(neighbours, presses, seed, RUN_MS, 0.0)
}

fn run_for(neighbours: &[Vec<usize>], presses: &[Press], seed: u64, run_ms: u64, loss: f64) -> Vec<NodeLog> {
    let start = Instant::now();
    let at = |ms: u64| start + Duration::from_millis(ms);
    let mut rng = Rng(seed);
    let nodes = neighbours.len();
    let ids: Vec<[u8; 4]> = (0..nodes).map(|node| [node as u8, 0xAA, 0xBB, 0xCC]).collect();
    let mut relays: Vec<Relay> = ids.iter().map(|id| Relay::new(RelayConfig::default(), *id)).collect();
    let mut replays: Vec<Replay> = (0..nodes).map(|_| Replay::new()).collect();
    let mut floors: Vec<Floor> = ids.iter().map(|id| Floor::new(*id)).collect();
    for (node, floor) in floors.iter_mut().enumerate() {
        floor.set_next_burst(first_burst(node));
    }
    let mut logs: Vec<NodeLog> = (0..nodes).map(|_| NodeLog::default()).collect();
    let mut end_heard: Vec<HashSet<([u8; 4], u16)>> = vec![HashSet::new(); nodes];
    // What talkers send, by time; what is in the air, by arrival.
    let mut outbox: Vec<(Instant, usize, Out)> = Vec::new();
    let mut ends: HashMap<usize, Packet> = HashMap::new();
    let mut air: Vec<(Instant, usize, Packet)> = Vec::new();
    // Each talker's burst counter grows with every burst, as the hub's does.
    let mut counters: Vec<u32> = vec![1; nodes];

    for ms in 0..run_ms {
        let now = at(ms);
        for press in presses.iter().filter(|press| press.at_ms == ms) {
            let Ok(keyed) = floors[press.node].request(now, false) else {
                logs[press.node].busy = true;
                logs[press.node].refused.push(ms);
                continue;
            };
            let mut packer = Packer::new(ids[press.node], 1, codec::OPUS16, 4, FRAMES_PER_PACKET);
            packer.start(keyed.burst, false, counters[press.node]);
            counters[press.node] += 1;
            let mut packets = Vec::new();
            for frame in 0..press.packets * FRAMES_PER_PACKET {
                packets.extend(packer.push(vec![frame as u8; 50]));
            }
            assert_eq!(packets.len(), press.packets);
            for (index, packet) in packets.into_iter().enumerate() {
                outbox.push((at(ms + PACKET_EVERY_MS * (index as u64 + 1)), press.node, Out::Send(packet)));
            }
            let end_ms = ms + PACKET_EVERY_MS * (press.packets as u64 + 1);
            let end = packer.finish().expect("an END");
            for copy in 0..3 {
                outbox.push((at(end_ms + 30 * copy), press.node, Out::Send(end.clone())));
            }
            outbox.push((at(end_ms + 60), press.node, Out::Release));
            ends.insert(press.node, end);
        }

        let (due, later): (Vec<_>, Vec<_>) = outbox.into_iter().partition(|(when, _, _)| *when <= now);
        outbox = later;
        for (_, node, out) in due {
            match out {
                Out::Send(packet) => {
                    if !packet.frames.is_empty() {
                        logs[node].sent += 1;
                    }
                    relays[node].on_sent(&packet, now);
                    air.push((now + HOP, node, packet));
                }
                Out::Release => floors[node].release(now),
            }
        }
        for (node, relay) in relays.iter_mut().enumerate() {
            for packet in relay.due(now) {
                air.push((now + HOP, node, packet));
            }
        }

        let (arriving, later): (Vec<_>, Vec<_>) = air.into_iter().partition(|(when, _, _)| *when <= now);
        air = later;
        for (_, from, packet) in arriving {
            let talker = packet.talker[0] as usize;
            for &to in &neighbours[from] {
                if loss > 0.0 && rng.next() < loss {
                    continue;
                }
                if relays[to].on_heard(&packet, now, rng.next()) != Heard::New {
                    continue;
                }
                if !replays[to].check(&packet, now) {
                    relays[to].forget(&packet);
                    continue;
                }
                if packet.is_end() {
                    end_heard[to].insert((packet.talker, packet.burst));
                }
                let voice = !packet.frames.is_empty();
                if voice {
                    *logs[to].heard.entry(talker).or_default() += 1;
                }
                let event = floors[to].on_packet(&packet, false, now);
                if event == FloorEvent::Preempted {
                    // Stop talking: what was left is not sent, the END goes now.
                    logs[to].yielded = true;
                    outbox.retain(|(_, node, _)| *node != to);
                    let end = ends.remove(&to).expect("we were talking");
                    for copy in 0..3 {
                        outbox.push((now + Duration::from_millis(30 * copy), to, Out::Send(end.clone())));
                    }
                }
                if matches!(event, FloorEvent::Play | FloorEvent::Preempted) && voice {
                    let log = &mut logs[to];
                    *log.played.entry(talker).or_default() += 1;
                    *log.bursts.entry((talker, packet.burst)).or_default() += 1;
                    log.first_played.get_or_insert(talker);
                    log.last_played = Some(talker);
                }
            }
        }

        for (node, floor) in floors.iter_mut().enumerate() {
            while let Some(FloorEvent::Ended(ended)) = floor.tick(now) {
                logs[node].ended.push((ended.talker[0] as usize, end_heard[node].contains(&(ended.talker, ended.burst))));
            }
        }
    }
    for (log, floor) in logs.iter_mut().zip(&floors) {
        log.final_state = Some(floor.state());
    }
    for (log, relay) in logs.iter_mut().zip(&relays) {
        log.relayed = relay.stats().relayed;
        log.suppressed = relay.stats().suppressed;
    }
    logs
}

#[test]
fn one_talker_is_played_four_hops_out_and_the_floor_frees_everywhere() {
    for seed in 1..30 {
        let logs = run(&chain(5), &[Press { node: 0, at_ms: 0, packets: 10 }], seed);
        for (node, log) in logs.iter().enumerate().skip(1) {
            assert_eq!(log.played(0), 10, "seed {seed}: node {node} missed packets");
            assert_eq!(log.ended.iter().map(|(talker, _)| *talker).collect::<Vec<_>>(), vec![0], "seed {seed}: node {node}");
            assert_eq!(log.final_state, Some(FloorState::Idle), "seed {seed}: node {node}");
        }
        assert_eq!(logs[0].final_state, Some(FloorState::Idle));
    }
}

#[test]
fn the_end_reaches_every_hop_so_no_node_waits_for_the_timeout() {
    for seed in 1..30 {
        let logs = run(&chain(5), &[Press { node: 0, at_ms: 0, packets: 10 }], seed);
        for (node, log) in logs.iter().enumerate().skip(1) {
            assert_eq!(log.ended, vec![(0, true)], "seed {seed}: node {node} ended by timeout");
        }
    }
}

#[test]
fn pressing_after_the_floor_was_taken_far_away_is_refused() {
    // Node 4 presses a second after node 0 began: its first packet reached node 4 long ago.
    let logs = run(&chain(5), &[Press { node: 0, at_ms: 0, packets: 20 }, Press { node: 4, at_ms: 1000, packets: 10 }], 7);
    assert!(logs[4].busy, "told the floor is taken");
    for (node, log) in logs.iter().enumerate() {
        assert_eq!(log.heard(4), 0, "node {node} heard the refused talker");
    }
    for log in &logs[1..] {
        assert_eq!(log.played(0), 20);
    }
}

#[test]
fn a_neighbour_pressing_after_the_first_packet_arrived_is_refused() {
    // In one radio cell the first packet arrives 135 ms after the press.
    let logs = run(&cell(3), &[Press { node: 0, at_ms: 0, packets: 10 }, Press { node: 2, at_ms: 200, packets: 10 }], 3);
    assert!(logs[2].busy);
    assert_eq!(logs[1].played(0), 10);
    assert_eq!(logs[1].heard(2), 0);
}

#[test]
fn talkers_keying_at_once_in_one_cell_are_resolved_to_one() {
    // Within the 100 ms packing delay neither neighbour has heard the other: the lower id
    // wins and the other stops after its first packet.
    for seed in 1..20 {
        let logs = run(&cell(3), &[Press { node: 2, at_ms: 0, packets: 10 }, Press { node: 0, at_ms: 50, packets: 10 }], seed);
        assert!(logs[2].yielded && !logs[0].yielded, "seed {seed}");
        assert_eq!(logs[1].mostly_played(), Some(0), "seed {seed}");
        assert_eq!(logs[1].played(0), 10, "seed {seed}");
        assert!(logs[2].sent <= 2, "seed {seed}: the loser sent {}", logs[2].sent);
    }
}

#[test]
fn two_far_talkers_keying_together_are_resolved_to_one_talker_everywhere() {
    // On a chain 0-1-2-3-4, nodes 0 and 4 press together, before either can hear the other.
    // The lower id (node 0) wins on every node; node 4 stops when node 0's first packet
    // reaches it, and sends its END.
    for seed in 1..20 {
        let logs = run(&chain(5), &[Press { node: 0, at_ms: 0, packets: 10 }, Press { node: 4, at_ms: 0, packets: 10 }], seed);
        check_one_winner(&logs, 0, 4, seed);
    }
}

#[test]
fn a_lower_id_keying_before_it_could_hear_the_first_talker_still_wins() {
    // Node 4 presses first; node 0 presses 200 ms later, before node 4's first packet has
    // crossed the four hops. They keyed at once as far as anyone can tell: node 0 wins.
    for seed in 1..20 {
        let logs = run(&chain(5), &[Press { node: 4, at_ms: 0, packets: 10 }, Press { node: 0, at_ms: 200, packets: 10 }], seed);
        assert!(!logs[0].busy, "seed {seed}: node 0 had not heard node 4 yet");
        check_one_winner(&logs, 0, 4, seed);
    }
}

fn check_one_winner(logs: &[NodeLog], winner: usize, loser: usize, seed: u64) {
    assert!(!logs[winner].yielded, "seed {seed}: the winner kept talking");
    assert_eq!(logs[winner].sent, 10, "seed {seed}");
    assert!(logs[loser].yielded, "seed {seed}: the loser stopped");
    assert!(logs[loser].sent <= 6, "seed {seed}: the loser sent {} packets", logs[loser].sent);
    for (node, log) in logs.iter().enumerate().filter(|(node, _)| *node != winner) {
        assert_eq!(log.played(winner), 10, "seed {seed}: node {node} missed the winner");
        assert_eq!(log.mostly_played(), Some(winner), "seed {seed}: node {node}");
        assert_eq!(log.final_state, Some(FloorState::Idle), "seed {seed}: node {node}");
    }
}

#[test]
fn talkers_taking_turns_are_each_played_everywhere() {
    // Nobody is shut out after the first talker: each talks 1 s, 800 ms after the one before
    // let go, some of them twice, the highest id first.
    for (name, net) in [("chain", chain(5)), ("cell", cell(4))] {
        let nodes = net.len();
        let order = [nodes - 1, 0, 1, nodes - 1, 0];
        let presses: Vec<Press> = order.iter().enumerate().map(|(turn, node)| Press { node: *node, at_ms: 100 + 2000 * turn as u64, packets: 10 }).collect();
        for seed in 1..20 {
            let logs = run_for(&net, &presses, seed, 11_000, 0.0);
            for (node, log) in logs.iter().enumerate() {
                assert!(log.refused.is_empty() && !log.yielded, "{name}, seed {seed}: node {node} was refused or stopped");
                for (turn, press) in presses.iter().enumerate().filter(|(_, press)| press.node != node) {
                    assert_eq!(log.turn(&presses, turn), press.packets, "{name}, seed {seed}: node {node} missed turn {turn} of node {}", press.node);
                }
                assert_eq!(log.final_state, Some(FloorState::Idle), "{name}, seed {seed}: node {node}");
            }
        }
    }
}

#[test]
fn with_lost_packets_every_turn_is_still_heard_by_every_neighbour() {
    // One packet in five lost on every link, ENDs too: a burst that lost its END times out,
    // and the next talker is neither refused nor ignored.
    let net = cell(4);
    for seed in 1..10u64 {
        let mut pick = Rng(seed * 77);
        let presses: Vec<Press> = (0..8).map(|turn| Press { node: (pick.next() * net.len() as f64) as usize, at_ms: 100 + 2500 * turn as u64, packets: 10 }).collect();
        let logs = run_for(&net, &presses, seed, 21_000, 0.2);
        for (turn, press) in presses.iter().enumerate() {
            assert!(logs[press.node].refused.is_empty(), "seed {seed}: turn {turn} was refused");
            for (node, log) in logs.iter().enumerate().filter(|(node, _)| *node != press.node) {
                assert!(log.turn(&presses, turn) >= 8, "seed {seed}: node {node} played {} of 10 packets of turn {turn}", log.turn(&presses, turn));
            }
        }
    }
}

#[test]
fn in_one_cell_every_listener_relays_every_packet() {
    // A known limit, not the aim: a relay waits 10-40 ms, and a relay heard from someone
    // else cancels it only once it has arrived, a packet's airtime (`HOP`) after it was sent.
    // So nobody is suppressed, and in a cell of n nodes every packet is on the air n times
    // (`flooding`, where packets arrive at once, shows the suppression that was meant).
    // At 64 kbit/s of air per stream (`airtime`) three nodes in range already fill the
    // channel with one talker.
    for nodes in [3, 6, 10] {
        let logs = run(&cell(nodes), &[Press { node: 0, at_ms: 0, packets: 10 }], 5);
        let relayed: u64 = logs.iter().map(|log| log.relayed).sum();
        // 10 voice packets and the END.
        assert_eq!(relayed, 11 * (nodes as u64 - 1), "{nodes} nodes");
        assert_eq!(logs.iter().map(|log| log.suppressed).sum::<u64>(), 0, "{nodes} nodes");
    }
}
