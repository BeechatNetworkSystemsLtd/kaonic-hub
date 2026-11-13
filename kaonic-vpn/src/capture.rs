//! Packet capture of the tunnel for the VPN page and pcap download. Records packets in both
//! directions, cut to `snaplen`, with what the VPN did with each. Off until an admin starts
//! it, kept in memory only, and costs one atomic load per packet while off.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::service::Direction;

/// Max bytes of packet data held.
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
/// A stopped capture's packets are freed this long after it stopped (time to download it).
pub const KEEP_STOPPED: Duration = Duration::from_secs(30 * 60);
/// pcap link type for raw IPv4 packets.
pub const LINKTYPE_IPV4: u32 = 228;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Sent to a peer (or every peer).
    Sent,
    /// From a peer, written to the TUN device.
    Delivered,
    Dropped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedPacket {
    pub seq: u64,
    /// Unix microseconds.
    pub ts_us: i64,
    pub direction: Direction,
    pub peer: Option<String>,
    pub flood: bool,
    /// Original length.
    pub len: usize,
    /// The packet, cut to snaplen. Shared, so snapshots don't copy it.
    pub data: Arc<[u8]>,
    pub verdict: Verdict,
    pub reason: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureConfig {
    pub snaplen: usize,
    pub max_packets: usize,
    pub max_secs: u64,
    /// When full: keep the newest if true, else stop.
    pub ring: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self { snaplen: 128, max_packets: 5000, max_secs: 600, ring: true }
    }
}

impl CaptureConfig {
    /// Clamps to the allowed ranges, with `max_packets × snaplen` within [`MAX_BYTES`].
    pub fn clamped(self) -> Self {
        let snaplen = self.snaplen.clamp(64, 1500);
        let max_packets = self.max_packets.clamp(100, 20_000).min(MAX_BYTES / snaplen);
        Self { snaplen, max_packets, max_secs: self.max_secs.clamp(10, 3600), ring: self.ring }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureState {
    pub running: bool,
    pub started_ts_ms: Option<i64>,
    pub stopped_ts_ms: Option<i64>,
    /// Settings after clamping.
    pub config: CaptureConfig,
    pub packets: usize,
    pub dropped: u64,
    pub bytes: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
}

#[derive(Default)]
struct Inner {
    config: CaptureConfig,
    started: Option<Instant>,
    started_ts_ms: Option<i64>,
    stopped_ts_ms: Option<i64>,
    stopped: Option<Instant>,
    packets: VecDeque<CapturedPacket>,
    next_seq: u64,
    dropped: u64,
    /// Original length of the packets held.
    bytes: u64,
}

#[derive(Default)]
pub struct Capture {
    running: AtomicBool,
    inner: Mutex<Inner>,
}

fn now_us() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_micros() as i64)
}

impl Inner {
    fn state(&self, running: bool) -> CaptureState {
        CaptureState {
            running,
            started_ts_ms: self.started_ts_ms,
            stopped_ts_ms: self.stopped_ts_ms,
            config: self.config,
            packets: self.packets.len(),
            dropped: self.dropped,
            bytes: self.bytes,
            first_seq: self.packets.front().map(|packet| packet.seq),
            last_seq: self.packets.back().map(|packet| packet.seq),
        }
    }
}

impl Capture {
    /// Starts a new capture, dropping the previous one.
    pub fn start(&self, config: CaptureConfig) -> CaptureState {
        let mut inner = self.inner.lock().expect("capture lock");
        *inner = Inner { config: config.clamped(), started: Some(Instant::now()), started_ts_ms: Some(now_us() / 1000), next_seq: 1, ..Inner::default() };
        self.running.store(true, Ordering::Release);
        inner.state(true)
    }

    fn stop_locked(&self, inner: &mut Inner) {
        if self.running.swap(false, Ordering::AcqRel) {
            inner.stopped_ts_ms = Some(now_us() / 1000);
            inner.stopped = Some(Instant::now());
        }
    }

    pub fn stop(&self) -> CaptureState {
        let mut inner = self.inner.lock().expect("capture lock");
        self.stop_locked(&mut inner);
        inner.state(false)
    }

    /// The state. Stops the capture if its time is up.
    pub fn state(&self) -> CaptureState {
        let mut inner = self.inner.lock().expect("capture lock");
        self.expire(&mut inner);
        let running = self.running.load(Ordering::Acquire);
        inner.state(running)
    }

    fn expire(&self, inner: &mut Inner) {
        if inner.started.is_some_and(|started| started.elapsed() >= Duration::from_secs(inner.config.max_secs)) {
            self.stop_locked(inner);
        }
    }

    /// Stops a capture whose time is up, and frees one stopped for [`KEEP_STOPPED`]. Called
    /// now and then: a capture nobody looks at must not hold its memory for good.
    pub fn tidy(&self) {
        let mut inner = self.inner.lock().expect("capture lock");
        self.expire(&mut inner);
        if inner.stopped.is_some_and(|stopped| stopped.elapsed() >= KEEP_STOPPED) && !inner.packets.is_empty() {
            inner.packets = VecDeque::new();
            inner.bytes = 0;
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Records a packet. Nearly free while stopped.
    #[inline]
    pub fn record(&self, direction: Direction, peer: Option<&str>, flood: bool, packet: &[u8], verdict: Verdict, reason: Option<&'static str>) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }
        self.record_slow(direction, peer, flood, packet, verdict, reason);
    }

    #[cold]
    fn record_slow(&self, direction: Direction, peer: Option<&str>, flood: bool, packet: &[u8], verdict: Verdict, reason: Option<&'static str>) {
        let mut inner = self.inner.lock().expect("capture lock");
        self.expire(&mut inner);
        if !self.running.load(Ordering::Acquire) {
            return;
        }
        if inner.packets.len() >= inner.config.max_packets {
            if !inner.config.ring {
                inner.dropped += 1;
                self.stop_locked(&mut inner);
                return;
            }
            if let Some(old) = inner.packets.pop_front() {
                inner.bytes -= old.len as u64;
                inner.dropped += 1;
            }
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.bytes += packet.len() as u64;
        let data: Arc<[u8]> = Arc::from(&packet[..packet.len().min(inner.config.snaplen)]);
        inner.packets.push_back(CapturedPacket { seq, ts_us: now_us(), direction, peer: peer.map(str::to_owned), flood, len: packet.len(), data, verdict, reason });
    }

    /// Packets with a seq above `after`, oldest first.
    pub fn packets(&self, after: u64, limit: usize) -> Vec<CapturedPacket> {
        let inner = self.inner.lock().expect("capture lock");
        // Seqs are consecutive, so skip straight to the first one wanted.
        let skip = inner.packets.front().map_or(0, |first| after.saturating_sub(first.seq - 1) as usize);
        inner.packets.iter().skip(skip).filter(|packet| packet.seq > after).take(limit).cloned().collect()
    }

    /// Everything held, as a pcap file.
    pub fn write_pcap(&self, out: &mut impl Write) -> io::Result<()> {
        // Snapshot, so the lock is not held while writing.
        let (snaplen, packets) = {
            let inner = self.inner.lock().expect("capture lock");
            (inner.config.snaplen, inner.packets.iter().cloned().collect::<Vec<_>>())
        };
        out.write_all(&pcap_header(snaplen as u32))?;
        for packet in &packets {
            out.write_all(&pcap_record_header(packet.ts_us, packet.data.len(), packet.len))?;
            out.write_all(&packet.data)?;
        }
        Ok(())
    }
}

/// The pcap global header: microsecond timestamps, raw IPv4.
pub fn pcap_header(snaplen: u32) -> [u8; 24] {
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    header[4..6].copy_from_slice(&2u16.to_le_bytes());
    header[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone and sigfigs stay 0.
    header[16..20].copy_from_slice(&snaplen.to_le_bytes());
    header[20..24].copy_from_slice(&LINKTYPE_IPV4.to_le_bytes());
    header
}

pub fn pcap_record_header(ts_us: i64, captured: usize, original: usize) -> [u8; 16] {
    let mut header = [0u8; 16];
    let ts_us = ts_us.max(0) as u64;
    header[0..4].copy_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
    header[4..8].copy_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
    header[8..12].copy_from_slice(&(captured as u32).to_le_bytes());
    header[12..16].copy_from_slice(&(original as u32).to_le_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    #[test]
    fn nothing_is_kept_while_stopped() {
        let capture = Capture::default();
        capture.record(Direction::Tx, Some("a"), false, &packet(100), Verdict::Sent, None);
        assert_eq!(capture.state().packets, 0);
        assert!(!capture.state().running);
    }

    #[test]
    fn packets_are_cut_to_snaplen_and_numbered() {
        let capture = Capture::default();
        capture.start(CaptureConfig { snaplen: 64, ..CaptureConfig::default() });
        capture.record(Direction::Tx, Some("a"), false, &packet(200), Verdict::Sent, None);
        capture.record(Direction::Rx, None, true, &packet(40), Verdict::Dropped, Some("source_not_allowed"));
        let packets = capture.packets(0, 10);
        assert_eq!(packets.len(), 2);
        assert_eq!((packets[0].seq, packets[0].len, packets[0].data.len()), (1, 200, 64));
        assert_eq!((packets[1].seq, packets[1].data.len(), packets[1].reason), (2, 40, Some("source_not_allowed")));
        assert_eq!(capture.packets(1, 10).len(), 1);
        assert_eq!(capture.packets(0, 1).len(), 1);
        let state = capture.state();
        assert_eq!((state.bytes, state.first_seq, state.last_seq), (240, Some(1), Some(2)));
    }

    #[test]
    fn a_ring_keeps_the_newest_and_a_full_capture_without_ring_stops() {
        let capture = Capture::default();
        capture.start(CaptureConfig { max_packets: 100, ..CaptureConfig::default() });
        for _ in 0..150 {
            capture.record(Direction::Tx, None, false, &packet(70), Verdict::Sent, None);
        }
        let state = capture.state();
        assert_eq!((state.packets, state.dropped, state.first_seq, state.last_seq), (100, 50, Some(51), Some(150)));
        assert_eq!(capture.packets(120, 1000).first().map(|packet| packet.seq), Some(121));
        assert!(state.running);

        capture.start(CaptureConfig { max_packets: 100, ring: false, ..CaptureConfig::default() });
        for _ in 0..150 {
            capture.record(Direction::Tx, None, false, &packet(70), Verdict::Sent, None);
        }
        let state = capture.state();
        assert_eq!((state.packets, state.dropped, state.running), (100, 1, false));
        assert!(state.stopped_ts_ms.is_some());
    }

    #[test]
    fn settings_are_clamped_to_the_memory_cap() {
        let config = CaptureConfig { snaplen: 1500, max_packets: 20_000, max_secs: 5, ring: true }.clamped();
        assert_eq!(config.max_packets, MAX_BYTES / 1500);
        assert_eq!(config.max_secs, 10);
        assert_eq!(CaptureConfig { snaplen: 10, ..CaptureConfig::default() }.clamped().snaplen, 64);
    }

    #[test]
    fn a_capture_stops_after_its_time() {
        let capture = Capture::default();
        capture.start(CaptureConfig::default());
        capture.inner.lock().unwrap().started = Instant::now().checked_sub(Duration::from_secs(700));
        capture.record(Direction::Tx, None, false, &packet(70), Verdict::Sent, None);
        let state = capture.state();
        assert!(!state.running);
        assert_eq!(state.packets, 0);
    }

    #[test]
    fn a_stopped_capture_is_freed_after_a_while() {
        let capture = Capture::default();
        capture.start(CaptureConfig::default());
        for _ in 0..100 {
            capture.record(Direction::Tx, None, false, &packet(70), Verdict::Sent, None);
        }
        capture.stop();
        capture.tidy();
        assert_eq!(capture.state().packets, 100, "kept for downloading");
        capture.inner.lock().unwrap().stopped = Instant::now().checked_sub(KEEP_STOPPED);
        capture.tidy();
        let state = capture.state();
        assert_eq!((state.packets, state.bytes, state.running), (0, 0, false));
        assert_eq!(capture.inner.lock().unwrap().packets.capacity(), 0);
        // A capture past its time with no packets coming is stopped too.
        capture.start(CaptureConfig::default());
        capture.inner.lock().unwrap().started = Instant::now().checked_sub(Duration::from_secs(700));
        capture.tidy();
        assert!(!capture.is_running());
    }

    #[test]
    fn the_pcap_file_reads_back() {
        let capture = Capture::default();
        capture.start(CaptureConfig { snaplen: 64, ..CaptureConfig::default() });
        capture.record(Direction::Tx, Some("a"), false, &packet(100), Verdict::Sent, None);
        let mut file = Vec::new();
        capture.write_pcap(&mut file).unwrap();
        assert_eq!(file.len(), 24 + 16 + 64);
        let word = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
        assert_eq!(word(0), 0xa1b2_c3d4);
        assert_eq!(u16::from_le_bytes([file[4], file[5]]), 2);
        assert_eq!(u16::from_le_bytes([file[6], file[7]]), 4);
        assert_eq!((word(16), word(20)), (64, LINKTYPE_IPV4));
        let ts_us = capture.packets(0, 1)[0].ts_us;
        assert_eq!(word(24) as i64, ts_us / 1_000_000);
        assert_eq!(word(28) as i64, ts_us % 1_000_000);
        assert_eq!((word(32), word(36)), (64, 100));
        assert_eq!(&file[40..], &packet(64)[..]);
    }
}
