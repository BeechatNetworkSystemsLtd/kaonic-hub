//! Reticulum over one radio: a reticulum-rs interface whose packets travel as
//! LDPC-coded `kaonic-net` frames.
//!
//! A packet becomes one to three frames (LDPC segments); received frames are
//! decoded and reassembled before Reticulum sees them. Every packet is
//! broadcast on the air: the radio has no addressing of its own.
//!
//! Decoding runs on its own thread: a damaged frame costs ~20 ms of LDPC on the
//! board's single core, which must not stall the runtime (radio, voice, HTTP).
//! Sending goes through a queue in three classes, voice first, then control
//! (announces, link setup, keepalives), then bulk link data; Reticulum hands over
//! a packet without waiting for the radio, and bulk is dropped, oldest first,
//! rather than holding up voice or control when the channel is full.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kaonic_frame::frame::{Frame, FrameSegment};
use kaonic_net::coder::LdpcPacketCoder;
use kaonic_net::error::NetworkError;
use kaonic_net::network::Network;
use rand::rngs::OsRng;
use reticulum::buffer::{InputBuffer, OutputBuffer};
use reticulum::hash::AddressHash;
use reticulum::iface::{Interface, InterfaceContext, RxMessage, TxMessage};
use reticulum::packet::{DestinationType, Packet, PacketContext, PacketType};
use reticulum::serde::Serialize;

use crate::log_limit::LogLimit;
use crate::radio::{FRAME_SIZE, RadioSocket};
use crate::settings::RadioSettings;
use crate::traffic::{Direction, FrameKind, FrameRecord, PacketInfo, Traffic};

/// The largest Reticulum packet: two header bytes, a transport and a destination hash, a
/// context byte, and the data.
const MAX_PACKET: usize = 2 + 16 + 16 + 1 + reticulum::packet::PACKET_MDU;
const SEGMENTS: usize = 3;
/// Quiet time after each frame's airtime before the next: a receiver still reading out one frame
/// drops the next if it starts at once (measured on boards: 21-38 % of frames sent back to back
/// were lost, 3-5 % with 15 ms or more between them).
const FRAME_GUARD: Duration = Duration::from_millis(8);
const REASSEMBLY_QUEUE: usize = 32;
/// Frames waiting for the decode thread; more are dropped (the radio outran the CPU).
const DECODE_QUEUE: usize = 64;
/// Packets waiting to go on the air, per class: voice, control, bulk.
const TX_LIMITS: [usize; 3] = [16, 64, 24];
/// Bulk that waited longer than this is stale: dropped, so queues do not turn into delay
/// (TCP and the VPN's repair react to a loss far sooner than to a growing round trip).
const BULK_SOJOURN: std::time::Duration = std::time::Duration::from_millis(150);
/// A radio fault repeats for every packet: it is logged at most this often.
const FAULT_LOG_EVERY: Duration = Duration::from_secs(10);

type RadioNetwork = Network<FRAME_SIZE, SEGMENTS, REASSEMBLY_QUEUE, LdpcPacketCoder<FRAME_SIZE>>;

/// What the radio heard from each direct neighbour, by destination hash.
/// The signal of the last first-hand announce from each destination, until the transport has
/// checked the announce's signature and the mesh takes it (`node.rs`). Anyone can transmit
/// announce-shaped frames, so it holds at most `NEIGHBOURS_MAX` entries, the newest.
pub type Neighbours = Arc<Mutex<HashMap<AddressHash, (i8, std::time::Instant)>>>;
pub const NEIGHBOURS_MAX: usize = 64;

/// Counters for the API and for finding faults in the field.
#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub rx_frames: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_decode_errors: u64,
    pub tx_frames: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub last_rssi: Option<i8>,
    /// Estimated time on air, microseconds.
    pub rx_airtime_us: u64,
    pub tx_airtime_us: u64,
    /// Frames dropped because decoding fell behind.
    pub rx_queue_drops: u64,
    /// Packets dropped from a full send queue (bulk first).
    pub tx_queue_drops: u64,
}

/// The send queue's class of a packet: 0 voice (group), 1 control, 2 bulk link data.
fn class_of(packet: &Packet) -> usize {
    match (packet.header.packet_type, packet.header.destination_type) {
        (PacketType::Data, DestinationType::Group) => 0,
        (PacketType::Data, DestinationType::Link) if packet.context == PacketContext::None => 2,
        _ => 1,
    }
}

/// Packets waiting for the radio, by class.
#[derive(Default)]
struct TxQueue {
    classes: [VecDeque<(std::time::Instant, TxMessage)>; 3],
}

impl TxQueue {
    /// Queues a packet; returns whether one had to be dropped to make room.
    fn push(&mut self, message: TxMessage) -> bool {
        let class = class_of(&message.packet);
        let queue = &mut self.classes[class];
        let dropped = queue.len() >= TX_LIMITS[class];
        if dropped {
            queue.pop_front();
        }
        queue.push_back((std::time::Instant::now(), message));
        dropped
    }

    /// The next packet to send, and how many stale bulk packets were dropped to get to it.
    fn pop(&mut self, now: std::time::Instant) -> (Option<TxMessage>, u64) {
        let mut stale = 0;
        while self.classes[2].front().is_some_and(|(queued, _)| now.duration_since(*queued) > BULK_SOJOURN) {
            self.classes[2].pop_front();
            stale += 1;
        }
        (self.classes.iter_mut().find_map(VecDeque::pop_front).map(|(_, message)| message), stale)
    }
}

/// A received frame on its way to the decode thread.
struct Heard {
    bytes: Vec<u8>,
    rssi: Option<i8>,
    now: u128,
}

pub struct RadioInterface {
    socket: Arc<RadioSocket>,
    neighbours: Neighbours,
    counters: Arc<Mutex<Counters>>,
    traffic: Arc<Traffic>,
    /// For estimating time on air; None when unknown.
    settings: Option<RadioSettings>,
}

impl RadioInterface {
    pub fn new(socket: RadioSocket, neighbours: Neighbours, counters: Arc<Mutex<Counters>>, traffic: Arc<Traffic>, settings: Option<RadioSettings>) -> Self {
        Self { socket: Arc::new(socket), neighbours, counters, traffic, settings }
    }

    /// The interface's worker, for `InterfaceManager::spawn`.
    pub async fn spawn(context: InterfaceContext<Self>) {
        let (socket, neighbours, counters, traffic, settings) = {
            let inner = context.inner.lock().expect("interface lock");
            (inner.socket.clone(), inner.neighbours.clone(), inner.counters.clone(), inner.traffic.clone(), inner.settings)
        };
        let airtime = move |bytes: usize| settings.as_ref().map_or(0, |settings| settings.airtime_us(bytes));
        let address = context.channel.address;
        let (rx_channel, mut tx_channel) = context.channel.split();
        let cancel = context.cancel;

        // Frames go to a decode thread; what it decodes goes straight to the transport.
        let (heard_tx, heard_rx) = std::sync::mpsc::sync_channel::<Heard>(DECODE_QUEUE);
        {
            let counters = counters.clone();
            let traffic = traffic.clone();
            let neighbours = neighbours.clone();
            let rx_channel = rx_channel.clone();
            let name = format!("radio-rx-{}", socket.iface());
            let spawned = std::thread::Builder::new().name(name).spawn(move || {
                decode(heard_rx, address, rx_channel, counters, traffic, neighbours, airtime);
            });
            if let Err(error) = spawned {
                log::error!("radio {}: cannot start the decode thread: {error}", socket.iface());
            }
        }
        let receive = {
            let socket = socket.clone();
            let counters = counters.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; FRAME_SIZE];
                let mut fault_log = LogLimit::new(FAULT_LOG_EVERY);
                loop {
                    let received = tokio::select! {
                        _ = cancel.cancelled() => break,
                        received = socket.recv(&mut buffer) => received,
                    };
                    let length = match received {
                        Ok(Some(length)) => length,
                        Ok(None) => continue,
                        Err(error) => {
                            if let Some(skipped) = fault_log.allow(std::time::Instant::now()) {
                                log::error!("radio {}: receive: {error} ({skipped} more not logged)", socket.iface());
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                    };
                    let heard = Heard { bytes: buffer[..length].to_vec(), rssi: socket.last_rssi(), now: now_ms() };
                    if heard_tx.try_send(heard).is_err() {
                        counters.lock().expect("counters lock").rx_queue_drops += 1;
                    }
                }
            })
        };

        // Reticulum's channel holds one packet: always take it at once, so the transport never
        // waits for the radio; the queue orders and bounds what waits.
        let queue: Arc<Mutex<TxQueue>> = Arc::default();
        let ready = Arc::new(tokio::sync::Notify::new());
        let pull = {
            let queue = queue.clone();
            let ready = ready.clone();
            let counters = counters.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let message = tokio::select! {
                        _ = cancel.cancelled() => break,
                        message = tx_channel.recv() => match message {
                            Some(message) => message,
                            None => break,
                        },
                    };
                    if queue.lock().expect("tx queue lock").push(message) {
                        counters.lock().expect("counters lock").tx_queue_drops += 1;
                    }
                    ready.notify_one();
                }
            })
        };

        let transmit = tokio::spawn(async move {
            let mut network = RadioNetwork::new(LdpcPacketCoder::new());
            let mut serialized = vec![0u8; reticulum::packet::PACKET_MDU * 2];
            let mut frames = [Frame::<FRAME_SIZE>::new(); SEGMENTS];
            let mut quiet_until = tokio::time::Instant::now();
            let mut fault_log = LogLimit::new(FAULT_LOG_EVERY);
            loop {
                let (next, stale) = queue.lock().expect("tx queue lock").pop(std::time::Instant::now());
                if stale > 0 {
                    counters.lock().expect("counters lock").tx_queue_drops += stale;
                }
                let Some(message) = next else {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = ready.notified() => continue,
                    }
                };
                let mut output = OutputBuffer::new(&mut serialized);
                if message.packet.serialize(&mut output).is_err() {
                    counters.lock().expect("counters lock").tx_errors += 1;
                    continue;
                }
                let length = output.as_slice().len();
                let encoded = match network.transmit(output.as_slice(), OsRng, &mut frames) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        if let Some(skipped) = fault_log.allow(std::time::Instant::now()) {
                            log::warn!("radio {}: encode: {error:?} ({skipped} more not logged)", socket.iface());
                        }
                        counters.lock().expect("counters lock").tx_errors += 1;
                        continue;
                    }
                };
                let info = PacketInfo::of(&message.packet, length);
                let count = encoded.len();
                let mut sent = 0;
                for (index, frame) in encoded.iter().enumerate() {
                    tokio::time::sleep_until(quiet_until).await;
                    let started = tokio::time::Instant::now();
                    let airtime_us = airtime(frame.as_slice().len());
                    quiet_until = started + Duration::from_micros(airtime_us) + FRAME_GUARD;
                    match socket.send(frame.as_slice()).await {
                        Ok(()) => {
                            sent += 1;
                            counters.lock().expect("counters lock").tx_airtime_us += airtime_us;
                            // Like a received packet: the last frame says what the packet was.
                            let last = index + 1 == count;
                            traffic.record(FrameRecord {
                                seq: 0,
                                ts_ms: now_ms() as i64,
                                direction: Direction::Tx,
                                len: frame.as_slice().len(),
                                rssi: None,
                                airtime_us,
                                kind: if last { info.kind } else { FrameKind::Segment },
                                packet: last.then_some(info),
                            });
                        }
                        Err(error) => {
                            if let Some(skipped) = fault_log.allow(std::time::Instant::now()) {
                                log::warn!("radio {}: send: {error} ({skipped} more not logged)", socket.iface());
                            }
                            counters.lock().expect("counters lock").tx_errors += 1;
                            break;
                        }
                    }
                }
                {
                    let mut stats = counters.lock().expect("counters lock");
                    stats.tx_frames += sent;
                    stats.tx_packets += 1;
                    stats.tx_bytes += length as u64;
                }
                // Let Reticulum's own tasks run between packets under load.
                tokio::task::yield_now().await;
            }
        });
        let _ = tokio::join!(receive, pull, transmit);
    }
}

impl Interface for RadioInterface {
    fn mtu() -> usize {
        FRAME_SIZE
    }
}

/// The decode thread: LDPC, reassembly and parsing of received frames, off the runtime.
fn decode(
    heard: std::sync::mpsc::Receiver<Heard>,
    address: AddressHash,
    rx_channel: reticulum::iface::InterfaceRxSender,
    counters: Arc<Mutex<Counters>>,
    traffic: Arc<Traffic>,
    neighbours: Neighbours,
    airtime: impl Fn(usize) -> u64,
) {
    let mut network = RadioNetwork::new(LdpcPacketCoder::new());
    let mut assembled = FrameSegment::<FRAME_SIZE, SEGMENTS>::new();
    while let Ok(Heard { bytes, rssi, now }) = heard.recv() {
        let length = bytes.len();
        let airtime_us = airtime(length);
        let mut record = FrameRecord { seq: 0, ts_ms: now as i64, direction: Direction::Rx, len: length, rssi, airtime_us, kind: FrameKind::Segment, packet: None };
        let mut frame = Frame::<FRAME_SIZE>::new();
        frame.copy_from_slice(&bytes);
        {
            let mut counters = counters.lock().expect("counters lock");
            counters.rx_frames += 1;
            counters.rx_airtime_us += airtime_us;
            counters.last_rssi = rssi.or(counters.last_rssi);
        }
        if network.receive(now, &frame).is_err() {
            counters.lock().expect("counters lock").rx_decode_errors += 1;
            traffic.record(FrameRecord { kind: FrameKind::Corrupt, ..record });
            continue;
        }
        loop {
            match network.process(now, &mut assembled) {
                Ok(segment) => {
                    let bytes = segment.as_slice();
                    // Larger than a Reticulum packet can be: dropped here, before it reaches a
                    // decoder that may not check (an older reticulum panicked on it).
                    let too_large = bytes.len() > MAX_PACKET;
                    let decoded = if too_large { None } else { Packet::deserialize(&mut InputBuffer::new(bytes)).ok() };
                    let Some(packet) = decoded else {
                        counters.lock().expect("counters lock").rx_decode_errors += 1;
                        if record.packet.is_none() {
                            record.kind = FrameKind::Corrupt;
                        }
                        continue;
                    };
                    // The frame that completes a packet carries what the packet was.
                    if record.packet.is_none() {
                        let info = PacketInfo::of(&packet, bytes.len());
                        record.kind = info.kind;
                        record.packet = Some(info);
                    }
                    {
                        let mut counters = counters.lock().expect("counters lock");
                        counters.rx_packets += 1;
                        counters.rx_bytes += bytes.len() as u64;
                    }
                    // An announce heard first-hand says who is a direct neighbour, and how loud.
                    if packet.header.packet_type == PacketType::Announce
                        && packet.header.hops == 0
                        && let Some(rssi) = rssi
                    {
                        let mut neighbours = neighbours.lock().expect("neighbours lock");
                        neighbours.insert(packet.destination, (rssi, std::time::Instant::now()));
                        if neighbours.len() > NEIGHBOURS_MAX {
                            let oldest = neighbours.iter().min_by_key(|(_, (_, at))| *at).map(|(destination, _)| *destination);
                            if let Some(oldest) = oldest {
                                neighbours.remove(&oldest);
                            }
                        }
                    }
                    // A plain thread may block on the transport's channel.
                    if rx_channel.blocking_send(RxMessage { address, packet }).is_err() {
                        return;
                    }
                }
                Err(NetworkError::TryAgain) => break,
                Err(_) => {
                    counters.lock().expect("counters lock").rx_decode_errors += 1;
                    if record.packet.is_none() {
                        record.kind = FrameKind::Corrupt;
                    }
                    break;
                }
            }
        }
        traffic.record(record);
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum::iface::TxMessageType;
    use reticulum::packet::Header;

    fn message(packet_type: PacketType, destination_type: DestinationType, context: PacketContext, tag: u8) -> TxMessage {
        let mut packet = Packet { header: Header { packet_type, destination_type, ..Default::default() }, context, ..Default::default() };
        packet.data.safe_write(&[tag]);
        TxMessage { tx_type: TxMessageType::Broadcast(None), packet }
    }

    #[test]
    fn voice_then_control_then_bulk_and_bulk_drops_oldest() {
        let mut queue = TxQueue::default();
        for tag in 0..TX_LIMITS[2] as u8 + 2 {
            queue.push(message(PacketType::Data, DestinationType::Link, PacketContext::None, tag));
        }
        assert!(queue.push(message(PacketType::Data, DestinationType::Link, PacketContext::None, 99)), "full bulk drops one");
        queue.push(message(PacketType::Announce, DestinationType::Single, PacketContext::None, 1));
        queue.push(message(PacketType::Data, DestinationType::Group, PacketContext::None, 2));
        queue.push(message(PacketType::Data, DestinationType::Link, PacketContext::KeepAlive, 3));
        let now = std::time::Instant::now();
        let first = queue.pop(now).0.unwrap();
        assert_eq!(first.packet.header.destination_type, DestinationType::Group, "voice first");
        assert_eq!(queue.pop(now).0.unwrap().packet.header.packet_type, PacketType::Announce);
        assert_eq!(queue.pop(now).0.unwrap().packet.context, PacketContext::KeepAlive);
        let bulk = queue.pop(now).0.unwrap();
        assert_eq!(bulk.packet.data.as_slice(), &[3], "the oldest bulk packets were dropped");
        let (next, stale) = queue.pop(now + BULK_SOJOURN * 2);
        assert!(next.is_none());
        assert_eq!(stale, TX_LIMITS[2] as u64 - 1, "bulk that waited too long is dropped");
    }
}
