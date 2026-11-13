//! The remote-management messages, carried as mux control messages on stream 5 of the
//! authenticated link between the Kaonic Admin and a node. Pure.
//!
//! ```text
//! message  = "KRM1" | type u8 | body
//! REQUEST  = 1 | req u32 | op (JSON)                         admin → node
//! RESPONSE = 2 | req u32 | part u8 | parts u8 | status u8 | JSON part   node → admin
//! OPEN     = 3 | session u32 | cols u16 | rows u16           admin → node: start a shell
//! OPENED   = 4 | session u32 | ok u8 | message (UTF-8)       node → admin
//! DATA     = 5 | session u32 | offset u32 | ack u32 | bytes  both ways (bytes may be empty: an ack)
//! RESIZE   = 6 | session u32 | cols u16 | rows u16           admin → node
//! CLOSE    = 7 | session u32 | reason (UTF-8)                both ways
//! ```
//! A response too large for one radio frame is cut into parts; the admin reassembles them.

pub const STREAM: u8 = 5;
const MAGIC: &[u8; 4] = b"KRM1";
/// Largest message body: what fits a mux packet in one radio frame, with room to spare.
pub const MAX_BODY: usize = 600;
/// Largest JSON part of one RESPONSE.
pub const PART: usize = MAX_BODY - 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Request { req: u32, op: Vec<u8> },
    Response { req: u32, part: u8, parts: u8, ok: bool, body: Vec<u8> },
    Open { session: u32, cols: u16, rows: u16 },
    Opened { session: u32, ok: bool, message: String },
    Data { session: u32, offset: u32, ack: u32, bytes: Vec<u8> },
    Resize { session: u32, cols: u16, rows: u16 },
    Close { session: u32, reason: String },
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().filter(|c| !c.is_control()).take(200).collect()
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        match self {
            Message::Request { req, op } => {
                out.push(1);
                out.extend_from_slice(&req.to_be_bytes());
                out.extend_from_slice(op);
            }
            Message::Response { req, part, parts, ok, body } => {
                out.push(2);
                out.extend_from_slice(&req.to_be_bytes());
                out.extend_from_slice(&[*part, *parts, u8::from(!*ok)]);
                out.extend_from_slice(body);
            }
            Message::Open { session, cols, rows } | Message::Resize { session, cols, rows } => {
                out.push(if matches!(self, Message::Open { .. }) { 3 } else { 6 });
                out.extend_from_slice(&session.to_be_bytes());
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
            }
            Message::Opened { session, ok, message } => {
                out.push(4);
                out.extend_from_slice(&session.to_be_bytes());
                out.push(u8::from(*ok));
                out.extend_from_slice(message.as_bytes());
            }
            Message::Data { session, offset, ack, bytes } => {
                out.push(5);
                out.extend_from_slice(&session.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&ack.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Message::Close { session, reason } => {
                out.push(7);
                out.extend_from_slice(&session.to_be_bytes());
                out.extend_from_slice(reason.as_bytes());
            }
        }
        out
    }

    /// Strict: anything malformed or too large is None.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() > MAGIC.len() + 1 + MAX_BODY + 16 {
            return None;
        }
        let rest = data.strip_prefix(MAGIC)?;
        let (&kind, rest) = rest.split_first()?;
        let (id, rest) = rest.split_first_chunk::<4>()?;
        let id = u32::from_be_bytes(*id);
        Some(match kind {
            1 => Message::Request { req: id, op: rest.to_vec() },
            2 => {
                let (&[part, parts, status], body) = rest.split_first_chunk::<3>()?;
                if parts == 0 || part >= parts || status > 1 {
                    return None;
                }
                Message::Response { req: id, part, parts, ok: status == 0, body: body.to_vec() }
            }
            3 | 6 => {
                let (cols, rest) = rest.split_first_chunk::<2>()?;
                let (rows, rest) = rest.split_first_chunk::<2>()?;
                if !rest.is_empty() {
                    return None;
                }
                let (cols, rows) = (u16::from_be_bytes(*cols), u16::from_be_bytes(*rows));
                if kind == 3 { Message::Open { session: id, cols, rows } } else { Message::Resize { session: id, cols, rows } }
            }
            4 => {
                let (&ok, message) = rest.split_first()?;
                Message::Opened { session: id, ok: ok == 1, message: utf8(message) }
            }
            5 => {
                let (offset, rest) = rest.split_first_chunk::<4>()?;
                let (ack, bytes) = rest.split_first_chunk::<4>()?;
                Message::Data { session: id, offset: u32::from_be_bytes(*offset), ack: u32::from_be_bytes(*ack), bytes: bytes.to_vec() }
            }
            7 => Message::Close { session: id, reason: utf8(rest) },
            _ => return None,
        })
    }
}

/// A JSON response cut into parts that each fit a RESPONSE.
pub fn split_response(req: u32, ok: bool, body: &[u8]) -> Vec<Message> {
    let chunks: Vec<&[u8]> = if body.is_empty() { vec![&[][..]] } else { body.chunks(PART).collect() };
    let parts = chunks.len().min(255) as u8;
    chunks.into_iter().take(255).enumerate().map(|(index, chunk)| Message::Response { req, part: index as u8, parts, ok, body: chunk.to_vec() }).collect()
}

/// Collects the parts of one response.
#[derive(Debug, Default)]
pub struct Reassembly {
    parts: Vec<Option<Vec<u8>>>,
    ok: bool,
}

impl Reassembly {
    /// Adds a part; returns the whole body once every part is in.
    pub fn add(&mut self, part: u8, parts: u8, ok: bool, body: Vec<u8>) -> Option<(bool, Vec<u8>)> {
        if self.parts.len() != usize::from(parts) {
            self.parts = vec![None; usize::from(parts)];
        }
        self.ok = ok;
        *self.parts.get_mut(usize::from(part))? = Some(body);
        if self.parts.iter().all(Option::is_some) {
            let body = self.parts.iter_mut().flat_map(|part| part.take().unwrap_or_default()).collect();
            Some((self.ok, body))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_round_trips() {
        for message in [
            Message::Request { req: 7, op: br#"{"op":"info"}"#.to_vec() },
            Message::Response { req: 7, part: 1, parts: 3, ok: false, body: b"{}".to_vec() },
            Message::Open { session: 9, cols: 80, rows: 24 },
            Message::Opened { session: 9, ok: true, message: "shell".into() },
            Message::Data { session: 9, offset: 100, ack: 42, bytes: b"ls\r".to_vec() },
            Message::Data { session: 9, offset: 0, ack: 0, bytes: Vec::new() },
            Message::Resize { session: 9, cols: 120, rows: 40 },
            Message::Close { session: 9, reason: "idle".into() },
        ] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
    }

    #[test]
    fn garbage_and_oversized_messages_are_refused() {
        assert_eq!(Message::decode(b"KRM1"), None);
        assert_eq!(Message::decode(b"KRM2\x01\0\0\0\x01{}"), None);
        assert_eq!(Message::decode(b"KRM1\x09\0\0\0\x01"), None);
        assert_eq!(Message::decode(b"KRM1\x02\0\0\0\x01\x03\x02\x00{}"), None, "part past parts");
        assert_eq!(Message::decode(b"KRM1\x03\0\0\0\x01\0\x50\0\x18\0"), None, "trailing bytes");
        let mut big = Message::Request { req: 1, op: vec![b'x'; MAX_BODY + 100] }.encode();
        assert_eq!(Message::decode(&big), None);
        big.truncate(10);
        assert!(Message::decode(&big).is_some());
        let Some(Message::Close { reason, .. }) = Message::decode(b"KRM1\x07\0\0\0\x01bye\x1b[2J") else { panic!() };
        assert_eq!(reason, "bye[2J");
    }

    #[test]
    fn large_responses_are_split_and_reassembled_in_any_order() {
        let body: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let mut parts = split_response(5, true, &body);
        assert_eq!(parts.len(), body.len().div_ceil(PART));
        for part in &parts {
            assert!(part.encode().len() <= MAX_BODY + 16);
        }
        parts.reverse();
        let mut whole = Reassembly::default();
        let mut result = None;
        for part in parts {
            let Message::Response { part, parts, ok, body, .. } = part else { panic!() };
            result = whole.add(part, parts, ok, body).or(result);
        }
        assert_eq!(result, Some((true, body)));
        assert_eq!(split_response(1, false, b"").len(), 1);
    }
}
