//! The mux framing: messages of several streams
//! packed into one Reticulum link packet, so the link's 68-83 B overhead and the radio
//! frame are paid once for many small messages.
//!
//! ```text
//! packet = 0xB0 | version:4 flags:4 | [seq u16] | [ack: cum u16 | bitmap u16] | frame { frame }
//! flags  : 1 SEQ (seq present) · 0 ACK (ack present)
//! frame  = hdr u8 | stream u8 | [len varint] | payload
//! hdr    : 7-6 kind (00 data, 01 control) · 5 MORE (another frame follows; len present)
//! ```
//! The last frame runs to the end of the packet. `seq` and `ack` are the packet-level ARQ of
//! [`arq`]: a packet with ACK and no frames is an
//! acknowledgement alone. [`pack`] always leaves room for both, so any packet can be
//! [`stamp`]ed afterwards. Pure, no I/O.

pub mod arq;

use std::collections::VecDeque;

pub const MUX: u8 = 0xB0;
const VERSION: u8 = 1;
const KIND_DATA: u8 = 0b00 << 6;
const KIND_CONTROL: u8 = 0b01 << 6;
const MORE: u8 = 1 << 5;
const PACKET_HEADER: usize = 2;
const FLAG_ACK: u8 = 0x01;
const FLAG_SEQ: u8 = 0x02;
/// Room [`pack`] leaves for a sequence number and an acknowledgement.
pub const STAMP_ROOM: usize = 2 + 4;
/// hdr, stream and the longest length a packet needs.
const FRAME_HEADER_MAX: usize = 2 + 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Data,
    Control,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub stream: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub stream: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotMux,
    Version,
    Truncated,
}

/// Whether link data is a mux packet.
pub fn is_mux(data: &[u8]) -> bool {
    data.first() == Some(&MUX)
}

fn put_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn get_varint(data: &[u8]) -> Option<(usize, &[u8])> {
    let mut value = 0usize;
    for (index, &byte) in data.iter().enumerate().take(3) {
        value |= ((byte & 0x7f) as usize) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, &data[index + 1..]));
        }
    }
    None
}

/// The largest payload one message may have in packets of `max_packet` bytes.
pub fn max_payload(max_packet: usize) -> usize {
    max_packet.saturating_sub(PACKET_HEADER + STAMP_ROOM + FRAME_HEADER_MAX)
}

/// The receiver's view sent back: every seq before `cum` arrived, and bit i of `bitmap` says
/// whether `cum + 1 + i` did (`cum` itself is missing by definition).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub cum: u16,
    pub bitmap: u16,
}

/// What a packet's header carries besides its frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stamp {
    pub seq: Option<u16>,
    pub ack: Option<Ack>,
}

/// Reads a mux packet's stamp; None if it is not a mux packet of this version.
pub fn stamp_of(packet: &[u8]) -> Option<Stamp> {
    let (stamp, _) = split_header(packet).ok()?;
    Some(stamp)
}

fn split_header(packet: &[u8]) -> Result<(Stamp, &[u8]), Error> {
    let rest = packet.strip_prefix(&[MUX]).ok_or(Error::NotMux)?;
    let (&version_flags, mut rest) = rest.split_first().ok_or(Error::Truncated)?;
    if version_flags >> 4 != VERSION {
        return Err(Error::Version);
    }
    let mut stamp = Stamp::default();
    if version_flags & FLAG_SEQ != 0 {
        let (seq, after) = rest.split_first_chunk::<2>().ok_or(Error::Truncated)?;
        stamp.seq = Some(u16::from_be_bytes(*seq));
        rest = after;
    }
    if version_flags & FLAG_ACK != 0 {
        let (ack, after) = rest.split_first_chunk::<4>().ok_or(Error::Truncated)?;
        stamp.ack = Some(Ack { cum: u16::from_be_bytes([ack[0], ack[1]]), bitmap: u16::from_be_bytes([ack[2], ack[3]]) });
        rest = after;
    }
    Ok((stamp, rest))
}

/// The packet with this stamp instead of its own (frames unchanged).
pub fn stamp(packet: &[u8], stamp: Stamp) -> Result<Vec<u8>, Error> {
    let (_, frames) = split_header(packet)?;
    let mut flags = 0;
    let mut out = Vec::with_capacity(packet.len() + STAMP_ROOM);
    out.extend_from_slice(&[MUX, 0]);
    if let Some(seq) = stamp.seq {
        flags |= FLAG_SEQ;
        out.extend_from_slice(&seq.to_be_bytes());
    }
    if let Some(ack) = stamp.ack {
        flags |= FLAG_ACK;
        out.extend_from_slice(&ack.cum.to_be_bytes());
        out.extend_from_slice(&ack.bitmap.to_be_bytes());
    }
    out[1] = VERSION << 4 | flags;
    out.extend_from_slice(frames);
    Ok(out)
}

/// An acknowledgement alone (no frames).
pub fn ack_only(ack: Ack) -> Vec<u8> {
    stamp(&[MUX, VERSION << 4], Stamp { seq: None, ack: Some(ack) }).expect("a bare header parses")
}

/// Takes messages from the front of `queue` while they fit in one packet of at most
/// `max_packet` bytes. A message too large for any packet is dropped (and counted in the
/// returned number); None when the queue is empty.
pub fn pack(queue: &mut VecDeque<Message>, max_packet: usize) -> (Option<Vec<u8>>, usize) {
    let mut dropped = 0;
    while queue.front().is_some_and(|message| message.payload.len() > max_payload(max_packet)) {
        queue.pop_front();
        dropped += 1;
    }
    let Some(first) = queue.pop_front() else { return (None, dropped) };
    let mut packet = vec![MUX, VERSION << 4];
    let mut current = first;
    loop {
        let hdr = match current.kind {
            Kind::Data => KIND_DATA,
            Kind::Control => KIND_CONTROL,
        };
        // Does the next message fit after this one, with this one's length in front?
        let mut with_length = Vec::new();
        put_varint(&mut with_length, current.payload.len());
        let after = packet.len() + 2 + with_length.len() + current.payload.len();
        let next_fits = queue.front().is_some_and(|next| after + 2 + next.payload.len() + STAMP_ROOM <= max_packet);
        if next_fits {
            packet.extend_from_slice(&[hdr | MORE, current.stream]);
            packet.extend_from_slice(&with_length);
            packet.extend_from_slice(&current.payload);
            current = queue.pop_front().expect("checked above");
        } else {
            packet.extend_from_slice(&[hdr, current.stream]);
            packet.extend_from_slice(&current.payload);
            return (Some(packet), dropped);
        }
    }
}

/// The frames of a mux packet (none for an acknowledgement alone).
pub fn parse(packet: &[u8]) -> Result<Vec<Frame<'_>>, Error> {
    let (stamp, mut rest) = split_header(packet)?;
    let mut frames = Vec::new();
    if rest.is_empty() && stamp.ack.is_some() {
        return Ok(frames);
    }
    loop {
        let (&[hdr, stream], after) = rest.split_first_chunk::<2>().ok_or(Error::Truncated)?;
        let kind = if hdr >> 6 == 0 { Kind::Data } else { Kind::Control };
        if hdr & MORE == 0 {
            frames.push(Frame { kind, stream, payload: after });
            return Ok(frames);
        }
        let (length, after) = get_varint(after).ok_or(Error::Truncated)?;
        let (payload, after) = after.split_at_checked(length).ok_or(Error::Truncated)?;
        frames.push(Frame { kind, stream, payload });
        rest = after;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(stream: u8, len: usize) -> Message {
        Message { kind: Kind::Data, stream, payload: (0..len).map(|i| i as u8).collect() }
    }

    #[test]
    fn small_messages_share_a_packet_and_come_back_whole() {
        let mut queue: VecDeque<Message> = [data(1, 40), Message { kind: Kind::Control, stream: 2, payload: b"hello".to_vec() }, data(1, 300)].into();
        let (packet, dropped) = pack(&mut queue, 1000);
        let packet = packet.unwrap();
        assert_eq!(dropped, 0);
        assert!(queue.is_empty());
        let frames = parse(&packet).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], Frame { kind: Kind::Data, stream: 1, payload: &data(1, 40).payload });
        assert_eq!(frames[1].kind, Kind::Control);
        assert_eq!(frames[1].payload, b"hello");
        assert_eq!(frames[2].payload.len(), 300);
        assert!(packet.len() <= 1000);
    }

    #[test]
    fn what_does_not_fit_waits_for_the_next_packet() {
        let mut queue: VecDeque<Message> = [data(1, 600), data(1, 600), data(1, 10)].into();
        let (first, _) = pack(&mut queue, 1000);
        assert_eq!(parse(&first.unwrap()).unwrap().len(), 1);
        let (second, _) = pack(&mut queue, 1000);
        assert_eq!(parse(&second.unwrap()).unwrap().len(), 2);
        assert_eq!(pack(&mut queue, 1000), (None, 0));
    }

    #[test]
    fn a_message_filling_a_whole_packet_fits_and_a_larger_one_is_dropped() {
        let mut queue: VecDeque<Message> = [data(1, max_payload(1000) + 1), data(1, max_payload(1000))].into();
        let (packet, dropped) = pack(&mut queue, 1000);
        assert_eq!(dropped, 1);
        assert!(packet.unwrap().len() <= 1000);
    }

    #[test]
    fn lengths_above_127_use_two_bytes() {
        let mut queue: VecDeque<Message> = [data(1, 200), data(3, 1)].into();
        let packet = pack(&mut queue, 1000).0.unwrap();
        let frames = parse(&packet).unwrap();
        assert_eq!(frames[0].payload.len(), 200);
        assert_eq!(frames[1].stream, 3);
    }

    #[test]
    fn stamps_ride_in_the_header_and_parse_skips_them() {
        let mut queue: VecDeque<Message> = [data(1, 40), data(2, 5)].into();
        let packet = pack(&mut queue, 1000).0.unwrap();
        let stamped = stamp(&packet, Stamp { seq: Some(513), ack: Some(Ack { cum: 7, bitmap: 0b101 }) }).unwrap();
        assert_eq!(stamped.len(), packet.len() + STAMP_ROOM);
        assert_eq!(stamp_of(&stamped), Some(Stamp { seq: Some(513), ack: Some(Ack { cum: 7, bitmap: 0b101 }) }));
        assert_eq!(parse(&stamped).unwrap(), parse(&packet).unwrap());
        let restamped = stamp(&stamped, Stamp { seq: Some(513), ack: None }).unwrap();
        assert_eq!(stamp_of(&restamped).unwrap().ack, None);
        assert_eq!(parse(&restamped).unwrap(), parse(&packet).unwrap());
        let ack = ack_only(Ack { cum: 1, bitmap: 0 });
        assert_eq!(parse(&ack).unwrap(), Vec::new());
        assert_eq!(stamp_of(&ack).unwrap().seq, None);
        // A full packet still fits its limit once stamped.
        let mut big: VecDeque<Message> = [data(1, max_payload(799))].into();
        let full = pack(&mut big, 799).0.unwrap();
        assert!(stamp(&full, Stamp { seq: Some(1), ack: Some(Ack { cum: 0, bitmap: 0 }) }).unwrap().len() <= 799);
    }

    #[test]
    fn garbage_is_refused() {
        assert_eq!(parse(&[0xA0]), Err(Error::NotMux));
        assert_eq!(parse(&[MUX, 0x20, 0, 1]), Err(Error::Version));
        assert_eq!(parse(&[MUX, 0x10]), Err(Error::Truncated));
        assert_eq!(parse(&[MUX, 0x10, MORE, 1, 50, 1, 2]), Err(Error::Truncated));
        assert_eq!(parse(&[MUX, 0x10, 0, 1]).unwrap()[0].payload, &[] as &[u8]);
    }
}
