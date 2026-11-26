//! Our own burst, frame by frame into packets of a few frames each. As in the
//! kaonic-audio-ptt plugin, a packet holds `target` frames (the latency floor) and, with
//! alignment, keeps taking frames up to `max` while they still fit the LDPC blocks it already
//! occupies ([`crate::airtime`]); it never grows past one radio frame.
//!
//! With redundancy, each packet also repeats the last frames of the one before, so a lost
//! packet costs a frame or two that concealment hides. The repeat is shorter than the packet
//! it comes from, so each packet starts at a later seq and `(talker, burst, seq)` stays
//! unique; older versions take the repeats as duplicates.

use crate::airtime;
use crate::packet::{Packet, flags};

/// Bytes of a packet's fixed header.
const HEADER_BYTES: usize = crate::packet::HEADER;
/// The admin's signature, on every packet of its burst.
const SIGNATURE_BYTES: usize = 64;

pub struct Packer {
    me: [u8; 4],
    epoch: u8,
    codec: u8,
    ttl: u8,
    /// Frames a packet holds before it may go (the latency floor).
    target: usize,
    /// Frames it may grow to while they ride free in its blocks (the cap).
    max: usize,
    align: bool,
    /// Bytes a packet may never exceed (one radio frame).
    cap: usize,
    /// The largest frame of this burst so far: the estimate of the next one's size.
    largest: usize,
    burst: u16,
    /// This burst's counter (see [`crate::Packet::counter`]).
    counter: u32,
    admin: bool,
    /// The seq of the next frame.
    seq: u16,
    pending: Vec<Vec<u8>>,
    started: bool,
    /// Frames of the previous packet to repeat at the front of the next one, at most.
    redundancy: usize,
    /// The new frames of the last packet sent.
    previous: Vec<Vec<u8>>,
}

impl Packer {
    pub fn new(me: [u8; 4], epoch: u8, codec: u8, ttl: u8, per_packet: usize) -> Self {
        let per_packet = per_packet.clamp(1, crate::packet::MAX_FRAMES);
        Self {
            me,
            epoch,
            codec,
            ttl,
            target: per_packet,
            max: per_packet,
            align: false,
            cap: airtime::max_packet_for_blocks(airtime::BLOCKS_PER_FRAME),
            counter: 0,
            largest: 0,
            burst: 0,
            admin: false,
            seq: 0,
            pending: Vec::new(),
            started: false,
            redundancy: 0,
            previous: Vec::new(),
        }
    }

    /// How many of the previous packet's frames each packet repeats (0: none).
    pub fn set_redundancy(&mut self, frames: usize) {
        self.redundancy = frames;
    }

    /// The previous packet's frames the next packet repeats: fewer than that packet had, so
    /// the next one starts at a later seq.
    fn repeat(&self) -> &[Vec<u8>] {
        let count = self.redundancy.min(self.previous.len().saturating_sub(1));
        &self.previous[self.previous.len() - count..]
    }

    /// The plugin's packing settings (`packet_frames`, `packet_frames_max`,
    /// `packet_align_ldpc`) and the size limit of one packet.
    pub fn set_packing(&mut self, target: usize, max: usize, align: bool, cap: usize) {
        self.target = target.clamp(1, crate::packet::MAX_FRAMES);
        self.max = max.clamp(self.target, crate::packet::MAX_FRAMES);
        self.align = align;
        self.cap = cap;
    }

    /// What the packet being built would encode to.
    fn pending_len(&self) -> usize {
        let signature = if self.admin { SIGNATURE_BYTES } else { 0 };
        HEADER_BYTES + signature + self.repeat().iter().chain(&self.pending).map(|frame| frame.len().min(255) + 1).sum::<usize>()
    }

    /// A new key epoch for the bursts that follow.
    pub fn set_epoch(&mut self, epoch: u8) {
        self.epoch = epoch;
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    /// Begins a burst; frames of the previous one not yet sent are dropped.
    /// A new burst. `counter` must be higher than any this talker used before, across restarts
    /// (listeners refuse lower ones as replays).
    pub fn start(&mut self, burst: u16, admin: bool, counter: u32) {
        self.burst = burst;
        self.counter = counter;
        self.admin = admin;
        self.seq = 0;
        self.pending.clear();
        self.previous.clear();
        self.started = false;
        self.largest = 0;
    }

    fn packet(&mut self, end: bool) -> Packet {
        let new = std::mem::take(&mut self.pending);
        let room = crate::packet::MAX_FRAMES.saturating_sub(new.len());
        let repeat = self.repeat();
        let mut frames = repeat[repeat.len().saturating_sub(room)..].to_vec();
        frames.extend(new.iter().cloned());
        let seq = self.seq.wrapping_sub(frames.len() as u16);
        self.previous = new;
        let mut packet_flags = if self.started { 0 } else { flags::START };
        if end {
            packet_flags |= flags::END;
        }
        if self.admin {
            packet_flags |= flags::ADMIN;
        }
        self.started = true;
        Packet { flags: packet_flags, ttl: self.ttl, epoch: self.epoch, talker: self.me, burst: self.burst, seq, counter: self.counter, codec: self.codec, frames, signature: None }
    }

    /// One encoded frame; the packets that are ready (usually none or one). The admin signs
    /// every packet of its bursts with [`crate::sign_admin`].
    pub fn push(&mut self, frame: Vec<u8>) -> Vec<Packet> {
        let mut ready = Vec::new();
        let cost = frame.len().min(255) + 1;
        // A frame that would not fit goes into the next packet.
        if !self.pending.is_empty() && self.pending_len() + cost > self.cap {
            ready.push(self.packet(false));
        }
        self.largest = self.largest.max(cost);
        self.pending.push(frame);
        self.seq = self.seq.wrapping_add(1);
        if airtime::should_flush(self.pending.len(), self.target, self.max, self.pending_len(), self.largest, self.align, self.cap) {
            ready.push(self.packet(false));
        }
        ready
    }

    /// The end of the burst: what is left, flagged END (an empty END packet if nothing is).
    pub fn finish(&mut self) -> Option<Packet> {
        Some(self.packet(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_redundancy_each_packet_repeats_the_last_frames_of_the_one_before() {
        let mut packer = Packer::new([1; 4], 1, 1, 4, 4);
        packer.set_redundancy(3);
        packer.start(7, false, 1);
        let mut packets = Vec::new();
        for frame in 0..12u8 {
            packets.extend(packer.push(vec![frame; 30]));
        }
        packets.extend(packer.finish());
        let seqs: Vec<(u16, Vec<u8>)> = packets.iter().map(|packet| (packet.seq, packet.frames.iter().map(|frame| frame[0]).collect())).collect();
        assert_eq!(
            seqs,
            vec![(0, vec![0, 1, 2, 3]), (1, vec![1, 2, 3, 4, 5, 6, 7]), (5, vec![5, 6, 7, 8, 9, 10, 11]), (9, vec![9, 10, 11])],
            "frames follow from each seq; the END repeats too"
        );
        // Every packet starts later than the one before: relays tell them apart by seq.
        assert!(packets.windows(2).all(|pair| pair[1].seq > pair[0].seq));
        assert!(packets.last().unwrap().is_end() && packets[0].is_start() && !packets[1].is_start());
        // A one-frame packet is not repeated, so the next does not share its seq.
        let mut single = Packer::new([1; 4], 1, 1, 4, 1);
        single.set_redundancy(3);
        single.start(1, false, 1);
        let seqs: Vec<u16> = (0..4u8).flat_map(|frame| single.push(vec![frame; 30])).map(|packet| packet.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3]);
        // A new burst does not repeat the old one.
        packer.start(8, false, 2);
        let first = (0..4u8).flat_map(|frame| packer.push(vec![frame; 30])).next().unwrap();
        assert_eq!((first.seq, first.frames.len()), (0, 4));
    }

    #[test]
    fn frames_are_packed_three_at_a_time_and_the_burst_ends() {
        let mut packer = Packer::new([9; 4], 2, crate::codec::OPUS16, 4, 3);
        packer.start(7, true, 7);
        assert!(packer.push(vec![0]).is_empty());
        assert!(packer.push(vec![1]).is_empty());
        let first = packer.push(vec![2]).remove(0);
        assert_eq!((first.seq, first.frames.len(), first.burst, first.epoch, first.ttl), (0, 3, 7, 2, 4));
        assert_eq!(first.flags, flags::START | flags::ADMIN);
        packer.push(vec![3]);
        let last = packer.finish().unwrap();
        assert_eq!((last.seq, last.frames, last.flags), (3, vec![vec![3]], flags::END | flags::ADMIN));
        // Nothing left: an empty END packet still says the burst is over.
        packer.start(8, false, 8);
        let mut packer_frames = Vec::new();
        for frame in 0..3u8 {
            packer_frames.extend(packer.push(vec![frame]));
        }
        let end = packer.finish().unwrap();
        assert_eq!((end.seq, end.frames.len(), end.flags), (3, 0, flags::END));
        assert_eq!(packer_frames[0].flags, flags::START);
        // A burst of nothing is START and END at once.
        packer.start(9, false, 9);
        assert_eq!(packer.finish().unwrap().flags, flags::START | flags::END);
    }

    #[test]
    fn aligned_packets_take_frames_that_ride_free_up_to_the_cap() {
        // 40-byte frames: 4 frames make a 178-byte packet (two blocks hold 189).
        let mut packer = Packer::new([1; 4], 1, crate::codec::OPUS16, 4, 4);
        packer.set_packing(4, 8, true, 814);
        packer.start(1, false, 1);
        let mut packets = Vec::new();
        for _ in 0..16 {
            packets.extend(packer.push(vec![0; 40]));
        }
        // Each packet goes as soon as the next 41 bytes would spill its blocks.
        assert!(packets.iter().all(|packet| packet.frames.len() >= 4 && packet.frames.len() <= 8));
        for packet in &packets {
            let len = packet.encode().len();
            assert!(len + 41 > crate::airtime::max_packet_for_blocks(crate::airtime::blocks_for(len)) || packet.frames.len() == 8);
        }
        // Without alignment: exactly the floor.
        packer.set_packing(4, 8, false, 814);
        packer.start(2, false, 2);
        let plain: Vec<Packet> = (0..8).flat_map(|_| packer.push(vec![0; 40])).collect();
        assert_eq!(plain.iter().map(|packet| packet.frames.len()).collect::<Vec<_>>(), vec![4, 4]);
    }

    #[test]
    fn a_packet_never_grows_past_one_radio_frame() {
        let mut packer = Packer::new([1; 4], 1, crate::codec::OPUS16, 4, 4);
        packer.set_packing(8, 16, true, 814);
        packer.start(3, true, 3);
        let packets: Vec<Packet> = (0..20).flat_map(|_| packer.push(vec![7; 200])).collect();
        assert!(!packets.is_empty());
        for packet in &packets {
            let signature = if packet.flags & flags::ADMIN != 0 { 64 } else { 0 };
            assert!(packet.encode().len() + signature <= 814, "{} bytes", packet.encode().len());
        }
        // The seqs follow on without a gap.
        for pair in packets.windows(2) {
            assert_eq!(pair[1].seq, pair[0].seq.wrapping_add(pair[0].frames.len() as u16));
        }
    }
}
