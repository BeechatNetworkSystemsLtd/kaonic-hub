//! What the radio sends and hears, frame by frame, for the traffic analyser:
//! the last frames in a ring, and a live feed of new ones.

use std::collections::VecDeque;
use std::sync::Mutex;

use reticulum::hash::AddressHash;
use reticulum::packet::{DestinationType, Packet, PacketType};
use tokio::sync::broadcast;

/// Frames kept for `GET /radio/frames` and for new subscribers.
const RECENT: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Rx,
    Tx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Announce,
    Data,
    LinkRequest,
    Proof,
    /// Part of a packet not yet complete.
    Segment,
    /// Received, but could not be decoded.
    Corrupt,
}

/// What a complete packet's header says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    pub kind: FrameKind,
    pub hops: u8,
    pub destination: AddressHash,
    pub destination_type: DestinationType,
    pub len: usize,
}

impl PacketInfo {
    pub fn of(packet: &Packet, len: usize) -> Self {
        let kind = match packet.header.packet_type {
            PacketType::Data => FrameKind::Data,
            PacketType::Announce => FrameKind::Announce,
            PacketType::LinkRequest => FrameKind::LinkRequest,
            PacketType::Proof => FrameKind::Proof,
        };
        Self { kind, hops: packet.header.hops, destination: packet.destination, destination_type: packet.header.destination_type, len }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRecord {
    /// Numbers frames in the order recorded, from 1; 0 until recorded.
    pub seq: u64,
    /// Unix milliseconds.
    pub ts_ms: i64,
    pub direction: Direction,
    /// Bytes on the air.
    pub len: usize,
    pub rssi: Option<i8>,
    pub airtime_us: u64,
    pub kind: FrameKind,
    pub packet: Option<PacketInfo>,
}

pub struct Traffic {
    /// The last frames, and the last sequence number given.
    recent: Mutex<(VecDeque<FrameRecord>, u64)>,
    feed: broadcast::Sender<FrameRecord>,
}

impl Default for Traffic {
    fn default() -> Self {
        Self { recent: Mutex::new((VecDeque::with_capacity(RECENT), 0)), feed: broadcast::channel(1024).0 }
    }
}

impl Traffic {
    pub fn record(&self, mut frame: FrameRecord) {
        {
            let (recent, seq) = &mut *self.recent.lock().expect("traffic lock");
            *seq += 1;
            frame.seq = *seq;
            if recent.len() == RECENT {
                recent.pop_front();
            }
            recent.push_back(frame);
        }
        // Sent under no lock: a frame recorded meanwhile may reach the feed first.
        let _ = self.feed.send(frame);
    }

    /// The last frames, oldest first.
    pub fn recent(&self) -> Vec<FrameRecord> {
        self.recent.lock().expect("traffic lock").0.iter().copied().collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FrameRecord> {
        self.feed.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ts_ms: i64) -> FrameRecord {
        FrameRecord { seq: 0, ts_ms, direction: Direction::Rx, len: 100, rssi: Some(-60), airtime_us: 1400, kind: FrameKind::Corrupt, packet: None }
    }

    #[test]
    fn keeps_the_latest_frames_and_feeds_new_ones() {
        let traffic = Traffic::default();
        let mut feed = traffic.subscribe();
        for ts in 0..(RECENT as i64 + 5) {
            traffic.record(frame(ts));
        }
        let recent = traffic.recent();
        assert_eq!(recent.len(), RECENT);
        assert_eq!(recent.first().unwrap().ts_ms, 5);
        assert_eq!(recent.first().unwrap().seq, 6);
        assert_eq!(recent.last().unwrap().ts_ms, RECENT as i64 + 4);
        assert_eq!(feed.try_recv().unwrap().ts_ms, 0);
    }
}
