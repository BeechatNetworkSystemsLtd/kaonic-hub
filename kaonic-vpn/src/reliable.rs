//! Retransmission (ARQ, [`kaonic_mux::arq`]) for VPN packets between hubs.
//!
//! Sits between the links and the VPN. Outgoing packets go through [`Reliable::send`].
//! Incoming packets are put back in order and published on the channel from
//! [`Reliable::start`]. Packets without a sequence number (HELLOs, other services, peers
//! without ARQ) pass through unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kaonic_mesh::links::{Links, Received};
use kaonic_mux::arq::{self, Receiver, Sender};
use kaonic_mux::{Stamp, stamp, stamp_of};
use tokio::sync::{Notify, broadcast};

/// Max timer sleep when nothing is due.
const IDLE: Duration = Duration::from_millis(200);
/// The VPN's IP stream (`service::STREAM_IP`).
const IP_STREAM: u8 = 1;
/// UDP packets up to this size (DNS, control) are retransmitted; larger ones are not.
const SMALL_UDP: usize = 300;

/// A TCP segment with no data and no SYN, FIN or RST. Not worth retransmitting: the next
/// ACK covers a lost one.
fn is_pure_ack(ip: &[u8]) -> bool {
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let Some(tcp) = ip.get(header..total.min(ip.len())) else { return false };
    if tcp.len() < 20 {
        return false;
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    let flags = tcp[13];
    tcp.len() <= data_offset && flags & 0x07 == 0
}

/// Whether a mux packet should be retransmitted if lost: TCP (not pure ACKs), ICMP, or small UDP.
pub fn worth_repairing(packet: &[u8]) -> bool {
    let Ok(frames) = kaonic_mux::parse(packet) else { return false };
    frames.iter().filter(|frame| frame.kind == kaonic_mux::Kind::Data && frame.stream == IP_STREAM).any(|frame| {
        let payload = frame.payload;
        if payload.len() < 20 || payload[0] >> 4 != 4 {
            return false;
        }
        match payload[9] {
            1 => true,
            6 => !is_pure_ack(payload),
            17 => payload.len() <= SMALL_UDP,
            _ => false,
        }
    })
}

struct Peer {
    sender: Sender,
    receiver: Receiver,
}

/// Per-peer ARQ figures for the API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerArq {
    pub srtt_ms: Option<u64>,
    pub in_flight: usize,
    pub sent: u64,
    pub retransmitted: u64,
    pub given_up: u64,
    pub duplicates: u64,
    pub skipped: u64,
}

pub struct Reliable {
    links: Arc<Links>,
    config: arq::Config,
    enabled: bool,
    peers: Mutex<HashMap<String, Peer>>,
    out: broadcast::Sender<Received>,
    wake: Notify,
}

fn initial_seq() -> u16 {
    // Random start, so peers resync after a restart.
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.subsec_nanos());
    (nanos ^ (nanos >> 16)) as u16
}

impl Reliable {
    /// Starts reading the links. Returns the layer and the in-order packet channel.
    pub fn start(links: Arc<Links>, enabled: bool) -> (Arc<Self>, broadcast::Receiver<Received>) {
        let (out, received) = broadcast::channel(4096);
        // ACKs usually ride on return traffic; a bare ACK goes after 8 packets or 40 ms.
        let config = arq::Config { ack_every: 8, ack_delay: Duration::from_millis(40), ..arq::Config::default() };
        let reliable = Arc::new(Self { links: links.clone(), config, enabled, peers: Mutex::new(HashMap::new()), out, wake: Notify::new() });
        let mut incoming = links.subscribe();
        let reader = reliable.clone();
        tokio::spawn(async move {
            loop {
                match incoming.recv().await {
                    Ok(message) => reader.on_received(message),
                    Err(broadcast::error::RecvError::Lagged(missed)) => log::warn!("vpn: arq missed {missed} packets"),
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        let timer = reliable.clone();
        tokio::spawn(async move { timer.run_timers().await });
        (reliable, received)
    }

    fn peer<'a>(&self, peers: &'a mut HashMap<String, Peer>, peer: &str) -> &'a mut Peer {
        peers.entry(peer.to_owned()).or_insert_with(|| Peer { sender: Sender::new(self.config, initial_seq()), receiver: Receiver::new(self.config) })
    }

    fn on_received(&self, message: Received) {
        let Some(found) = stamp_of(&message.packet) else {
            let _ = self.out.send(message);
            return;
        };
        if found.seq.is_none() && found.ack.is_none() {
            let _ = self.out.send(message);
            return;
        }
        let now = Instant::now();
        let deliver = {
            let mut peers = self.peers.lock().expect("arq lock");
            let peer = self.peer(&mut peers, &message.peer);
            if let Some(ack) = found.ack {
                peer.sender.on_ack(ack, now);
            }
            match found.seq {
                Some(seq) => {
                    let bare = stamp(&message.packet, Stamp::default()).unwrap_or_else(|_| message.packet.to_vec());
                    peer.receiver.on_packet(seq, bare, now)
                }
                // Unnumbered packet with an ACK: pass it on (it may carry frames).
                None => vec![stamp(&message.packet, Stamp::default()).unwrap_or_else(|_| message.packet.to_vec())],
            }
        };
        for packet in deliver {
            if kaonic_mux::parse(&packet).is_ok_and(|frames| !frames.is_empty()) {
                let _ = self.out.send(Received { peer: message.peer.clone(), packet: Arc::new(packet) });
            }
        }
        self.wake.notify_one();
    }

    /// Sends a mux packet to `peer`, with a sequence number and our ACK.
    pub async fn send(&self, peer: &str, packet: &[u8]) -> bool {
        if !self.enabled {
            return self.links.send(peer, packet).await;
        }
        let stamped = {
            let now = Instant::now();
            let mut peers = self.peers.lock().expect("arq lock");
            let state = self.peer(&mut peers, peer);
            let seq = if worth_repairing(packet) { state.sender.send(packet.to_vec(), now) } else { None };
            let ack = state.receiver.take_ack();
            stamp(packet, Stamp { seq, ack }).unwrap_or_else(|_| packet.to_vec())
        };
        self.wake.notify_one();
        self.links.send(peer, &stamped).await
    }

    /// Runs retransmissions, delayed ACKs and gap timeouts.
    async fn run_timers(&self) {
        loop {
            let deadline = {
                let peers = self.peers.lock().expect("arq lock");
                peers.values().flat_map(|peer| [peer.sender.next_deadline(), peer.receiver.next_deadline()]).flatten().min()
            };
            let sleep = deadline.map_or(IDLE, |at| at.saturating_duration_since(Instant::now()).min(IDLE));
            tokio::select! {
                _ = tokio::time::sleep(sleep) => {}
                _ = self.wake.notified() => {}
            }
            let now = Instant::now();
            let mut sends: Vec<(String, Vec<u8>)> = Vec::new();
            let mut deliver: Vec<(String, Vec<u8>)> = Vec::new();
            {
                let mut peers = self.peers.lock().expect("arq lock");
                for (id, peer) in peers.iter_mut() {
                    for (seq, packet) in peer.sender.due(now) {
                        let ack = peer.receiver.take_ack();
                        if let Ok(stamped) = stamp(&packet, Stamp { seq: Some(seq), ack }) {
                            sends.push((id.clone(), stamped));
                        }
                    }
                    for packet in peer.receiver.release(now) {
                        deliver.push((id.clone(), packet));
                    }
                    if peer.receiver.ack_due(now)
                        && let Some(ack) = peer.receiver.take_ack()
                    {
                        sends.push((id.clone(), kaonic_mux::ack_only(ack)));
                    }
                }
            }
            for (peer, packet) in deliver {
                let _ = self.out.send(Received { peer, packet: Arc::new(packet) });
            }
            for (peer, packet) in sends {
                self.links.send(&peer, &packet).await;
            }
        }
    }

    /// Forgets the state of peers whose link is down (a new link starts afresh, as after a
    /// restart).
    pub fn forget_closed(&self, established: &[String]) {
        self.peers.lock().expect("arq lock").retain(|peer, _| established.contains(peer));
    }

    /// ARQ figures per peer.
    pub fn stats(&self) -> HashMap<String, PeerArq> {
        let peers = self.peers.lock().expect("arq lock");
        peers
            .iter()
            .map(|(id, peer)| {
                let (sent, received) = (peer.sender.stats(), peer.receiver.stats());
                let stats = PeerArq {
                    srtt_ms: peer.sender.srtt().map(|srtt| srtt.as_millis() as u64),
                    in_flight: peer.sender.in_flight(),
                    sent: sent.sent,
                    retransmitted: sent.retransmitted,
                    given_up: sent.given_up,
                    duplicates: received.duplicates,
                    skipped: received.skipped,
                };
                (id.clone(), stats)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use kaonic_mux::{Kind, Message};

    use super::*;

    fn ip(proto: u8, len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[9] = proto;
        if proto == 6 && len >= 40 {
            packet[20 + 12] = 5 << 4;
            packet[20 + 13] = 0x10;
        }
        packet
    }

    fn mux(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut queue: VecDeque<Message> = packets.iter().map(|payload| Message { kind: Kind::Data, stream: IP_STREAM, payload: payload.clone() }).collect();
        kaonic_mux::pack(&mut queue, 799).0.unwrap()
    }

    #[test]
    fn tcp_icmp_and_small_udp_are_repaired_bulk_udp_is_not() {
        assert!(worth_repairing(&mux(&[ip(6, 60)])), "TCP with data");
        assert!(!worth_repairing(&mux(&[ip(6, 40)])), "a pure TCP ACK");
        let mut syn = ip(6, 40);
        syn[20 + 13] = 0x02;
        assert!(worth_repairing(&mux(&[syn])), "SYN");
        assert!(worth_repairing(&mux(&[ip(1, 84)])));
        assert!(worth_repairing(&mux(&[ip(17, 80)])), "DNS");
        assert!(!worth_repairing(&mux(&[ip(17, 700)])), "bulk UDP");
        assert!(worth_repairing(&mux(&[ip(17, 500), ip(6, 60)])), "TCP data riding with bulk UDP");
        let mut control: VecDeque<Message> = [Message { kind: Kind::Control, stream: 2, payload: b"KVH1....".to_vec() }].into();
        assert!(!worth_repairing(&kaonic_mux::pack(&mut control, 799).0.unwrap()));
    }
}
