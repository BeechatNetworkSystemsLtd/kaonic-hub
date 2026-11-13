//! One direction pair of a shell's bytes over the radio: ordered, reliable, flow-controlled.
//! Go-back-N with a small window — a terminal moves little data, and a radio frame lost now and
//! then is repaired by sending again from the last acknowledged byte. Pure: time is passed in.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Bytes in one DATA message.
pub const CHUNK: usize = 480;
/// Chunks sent per `poll`.
const PER_POLL: usize = 1;
/// Bytes sent and not yet acknowledged.
const WINDOW: usize = 8 * CHUNK;
/// Bytes waiting to be sent: past this, the writer must wait (backpressure).
pub const CAPACITY: usize = 64 * 1024;
/// Sent again after this long without an acknowledgement...
const RTO: Duration = Duration::from_millis(1000);
/// ...or as soon as an acknowledgement this long after a send shows nothing new arrived:
/// the receiver acknowledges what it has as data comes in, so a gap shows at once.
const REPEAT_ACK: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
pub struct ByteStream {
    /// Unacknowledged and unsent bytes, starting at `base`.
    out: VecDeque<u8>,
    base: u32,
    /// Offset up to which bytes have been sent.
    sent: u32,
    last_send: Option<Instant>,
    /// Next byte expected from the other side.
    received: u32,
    /// An acknowledgement the other side has not had yet.
    ack_owed: bool,
}

impl ByteStream {
    /// Room for more outgoing bytes.
    pub fn room(&self) -> usize {
        CAPACITY.saturating_sub(self.out.len())
    }

    /// Queues bytes to send; false (nothing queued) when they do not fit.
    pub fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.room() {
            return false;
        }
        self.out.extend(bytes);
        true
    }

    /// The peer has everything before `ack`.
    pub fn on_ack(&mut self, ack: u32, now: Instant) {
        let acked = ack.wrapping_sub(self.base) as usize;
        if acked == 0 {
            let in_flight = self.sent != self.base;
            if in_flight && self.last_send.is_some_and(|sent| now.duration_since(sent) >= REPEAT_ACK) {
                // Go back now rather than at the timeout.
                self.sent = self.base;
            }
            return;
        }
        if acked > self.out.len() {
            return;
        }
        self.out.drain(..acked);
        self.base = ack;
        if self.sent.wrapping_sub(self.base) as usize > self.out.len() {
            self.sent = self.base;
        }
    }

    /// Bytes from the peer at `offset`; returns what is new, in order. A gap is dropped and
    /// re-acknowledged, so the peer sends again from where we are.
    pub fn on_data(&mut self, offset: u32, bytes: &[u8]) -> Vec<u8> {
        // An empty DATA only carries an acknowledgement (or keeps the session alive): it is
        // not acknowledged, or two sides would answer each other forever.
        if bytes.is_empty() {
            return Vec::new();
        }
        self.ack_owed = true;
        let skip = self.received.wrapping_sub(offset) as usize;
        // Not past what we have (offset <= received) and not entirely old.
        if offset.wrapping_sub(self.received) as i32 > 0 || skip >= bytes.len() {
            return Vec::new();
        }
        let fresh = bytes[skip..].to_vec();
        self.received = self.received.wrapping_add(fresh.len() as u32);
        fresh
    }

    /// What to acknowledge.
    pub fn ack(&self) -> u32 {
        self.received
    }

    /// DATA to send now: new bytes within the window, everything unacknowledged again after a
    /// timeout, or an empty one when only an acknowledgement is owed. Each is (offset, bytes).
    pub fn poll(&mut self, now: Instant) -> Vec<(u32, Vec<u8>)> {
        let in_flight = self.sent.wrapping_sub(self.base) as usize;
        if in_flight > 0 && self.last_send.is_some_and(|sent| now.duration_since(sent) >= RTO) {
            // Go back: send again from the last acknowledged byte.
            self.sent = self.base;
        }
        let mut out = Vec::new();
        // One chunk per call: the caller polls on a short clock, so frames go out spaced, not
        // in a burst that a relay a hop away (half duplex) would partly miss.
        while out.len() < PER_POLL {
            let start = self.sent.wrapping_sub(self.base) as usize;
            if start >= self.out.len() || start >= WINDOW {
                break;
            }
            let end = (start + CHUNK).min(self.out.len()).min(WINDOW.max(start + 1));
            let bytes: Vec<u8> = self.out.range(start..end).copied().collect();
            out.push((self.sent, bytes));
            self.sent = self.sent.wrapping_add((end - start) as u32);
        }
        if !out.is_empty() {
            self.last_send = Some(now);
            self.ack_owed = false;
        } else if self.ack_owed {
            self.ack_owed = false;
            out.push((self.sent, Vec::new()));
        }
        out
    }

    /// Nothing left to send or confirm.
    pub fn idle(&self) -> bool {
        self.out.is_empty() && !self.ack_owed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Carries every DATA from `a` to `b` (dropping those `drop` picks) and acknowledges back.
    fn deliver(a: &mut ByteStream, b: &mut ByteStream, now: Instant, received: &mut Vec<u8>, drop: &mut impl FnMut() -> bool) {
        for (offset, bytes) in a.poll(now) {
            if !drop() {
                received.extend(b.on_data(offset, &bytes));
            }
        }
        for (_, _) in b.poll(now) {
            a.on_ack(b.ack(), now);
        }
    }

    #[test]
    fn bytes_arrive_once_and_in_order_even_with_losses() {
        let (mut a, mut b) = (ByteStream::default(), ByteStream::default());
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
        assert!(a.push(&data));
        let mut received = Vec::new();
        let start = Instant::now();
        // A quarter of the messages lost, pseudo-randomly (a fixed pattern could hit the same chunk every time).
        let mut seed = 12345u32;
        let mut drop = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (seed >> 16).is_multiple_of(4)
        };
        for step in 0..2000u64 {
            deliver(&mut a, &mut b, start + Duration::from_millis(step * 200), &mut received, &mut drop);
            if received.len() == data.len() {
                break;
            }
        }
        assert_eq!(received, data);
        assert!(a.out.is_empty(), "everything acknowledged");
    }

    #[test]
    fn the_window_and_capacity_hold() {
        let mut a = ByteStream::default();
        assert!(a.push(&vec![1u8; CAPACITY]));
        assert!(!a.push(&[1]), "full: the writer must wait");
        let mut sent = 0;
        for _ in 0..10 {
            sent += a.poll(Instant::now()).iter().map(|(_, bytes)| bytes.len()).sum::<usize>();
        }
        assert_eq!(sent, WINDOW);
        assert!(a.poll(Instant::now()).is_empty(), "nothing more until acknowledged");
        a.on_ack(WINDOW as u32, Instant::now());
        assert_eq!(a.room(), WINDOW);
    }

    #[test]
    fn old_and_future_data_is_not_delivered_but_acknowledged() {
        let mut b = ByteStream::default();
        assert_eq!(b.on_data(0, b"hello"), b"hello");
        assert!(b.on_data(0, b"hello").is_empty(), "a repeat");
        assert_eq!(b.on_data(3, b"lo world"), b" world", "overlap: only the new part");
        assert!(b.on_data(50, b"later").is_empty(), "a gap");
        assert_eq!(b.ack(), 11);
        assert_eq!(b.poll(Instant::now()), vec![(0, Vec::new())], "an empty DATA carries the ack");
        assert!(b.on_data(11, b"").is_empty());
        assert!(b.poll(Instant::now()).is_empty(), "an empty DATA is not answered");
    }
}
