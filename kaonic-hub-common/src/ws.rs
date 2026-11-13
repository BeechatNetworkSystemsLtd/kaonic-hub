//! A minimal WebSocket client (RFC 6455): the handshake, masked client frames, text and
//! binary messages in fragments, ping, pong and close. No extensions. Over any tokio
//! stream; limits are the caller's.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::{base64, http};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const CONTINUATION: u8 = 0x0;
pub const TEXT: u8 = 0x1;
pub const BINARY: u8 = 0x2;
pub const CLOSE: u8 = 0x8;
pub const PING: u8 = 0x9;
pub const PONG: u8 = 0xA;

/// What went wrong.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The server closed, or the connection broke, before a byte of the handshake's answer.
    Unanswered,
    /// The server answered the handshake with another status than 101: that status and the
    /// body, as much of it as came.
    Refused { status: u16, body: Vec<u8> },
    /// The server closed the connection.
    Closed,
    /// A frame was to be sent after our close.
    CloseSent,
    /// Not WebSocket as expected, or over a limit.
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;

fn protocol(why: &str) -> Error {
    Error::Protocol(why.to_owned())
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(error) => write!(f, "{error}"),
            Error::Unanswered => f.write_str("closed before answering the handshake"),
            Error::Refused { status, .. } => write!(f, "the handshake was answered {status}"),
            Error::Closed => f.write_str("the server closed the WebSocket"),
            Error::CloseSent => f.write_str("the WebSocket is closed"),
            Error::Protocol(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// `Sec-WebSocket-Accept` for a key.
pub fn accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(GUID.as_bytes());
    base64::encode(&hash.finalize())
}

/// Masks and handshake keys: not secret, only not predictable by whoever is on the path.
pub struct Rng(u64);

impl Rng {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        use std::hash::{BuildHasher, Hasher};
        // Seeded randomly by the standard library, per process and per instance.
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|time| time.as_nanos()).unwrap_or_default());
        Self(hasher.finish())
    }

    /// splitmix64.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// One frame as read.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// A client frame: final, masked with `mask`.
pub fn encode(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    match payload.len() {
        length @ 0..=125 => out.push(0x80 | length as u8),
        length @ 126..=0xffff => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(index, byte)| byte ^ mask[index % 4]));
    out
}

/// A server frame from the start of `buffer` and its length in bytes; None until it is all
/// there. Server frames are never masked; a frame larger than `max` is refused at once.
pub fn parse(buffer: &[u8], max: usize) -> Result<Option<(Frame, usize)>> {
    let [first, second, ..] = *buffer else { return Ok(None) };
    if first & 0x70 != 0 {
        return Err(protocol("reserved bits set"));
    }
    if second & 0x80 != 0 {
        return Err(protocol("the server masked a frame"));
    }
    let (fin, opcode) = (first & 0x80 != 0, first & 0x0f);
    let (length, mut at) = match second & 0x7f {
        126 => match buffer.get(2..4) {
            Some(bytes) => (u16::from_be_bytes([bytes[0], bytes[1]]) as u64, 4),
            None => return Ok(None),
        },
        127 => match buffer.get(2..10) {
            Some(bytes) => (u64::from_be_bytes(bytes.try_into().expect("8 bytes")), 10),
            None => return Ok(None),
        },
        length => (length as u64, 2),
    };
    match opcode {
        CONTINUATION | TEXT | BINARY => {}
        CLOSE | PING | PONG => {
            if !fin || length > 125 {
                return Err(protocol("bad control frame"));
            }
        }
        _ => return Err(protocol("unknown opcode")),
    }
    if length > max as u64 {
        return Err(protocol("message too large"));
    }
    let length = length as usize;
    let Some(payload) = buffer.get(at..at + length) else { return Ok(None) };
    let frame = Frame { fin, opcode, payload: payload.to_vec() };
    at += length;
    Ok(Some((frame, at)))
}

/// A whole message or a control frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    /// With its status code, if any.
    Close(Option<u16>),
}

/// Puts fragments together into messages.
#[derive(Default)]
pub struct Assembler {
    partial: Option<(u8, Vec<u8>)>,
}

impl Assembler {
    pub fn push(&mut self, frame: Frame, max: usize) -> Result<Option<Incoming>> {
        let message = match frame.opcode {
            PING => return Ok(Some(Incoming::Ping(frame.payload))),
            PONG => return Ok(Some(Incoming::Pong)),
            CLOSE => {
                let code = frame.payload.get(..2).map(|code| u16::from_be_bytes([code[0], code[1]]));
                return Ok(Some(Incoming::Close(code)));
            }
            CONTINUATION => {
                let (_, data) = self.partial.as_mut().ok_or_else(|| protocol("continuation without a start"))?;
                if data.len() + frame.payload.len() > max {
                    return Err(protocol("message too large"));
                }
                data.extend_from_slice(&frame.payload);
                if !frame.fin {
                    return Ok(None);
                }
                self.partial.take().expect("checked above")
            }
            opcode => {
                if self.partial.is_some() {
                    return Err(protocol("a new message inside a fragmented one"));
                }
                if !frame.fin {
                    self.partial = Some((opcode, frame.payload));
                    return Ok(None);
                }
                (opcode, frame.payload)
            }
        };
        Ok(Some(match message {
            (TEXT, data) => Incoming::Text(String::from_utf8(data).map_err(|_| protocol("text that is not UTF-8"))?),
            (_, data) => Incoming::Binary(data),
        }))
    }
}

/// The reading side: cancel-safe, so `next` may be used in `select!`.
pub struct Reader<R> {
    stream: R,
    buffer: Vec<u8>,
    assembler: Assembler,
    max_message: usize,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    /// Reads from `stream`, after what is already in `buffer`.
    pub fn new(stream: R, buffer: Vec<u8>, max_message: usize) -> Self {
        Self { stream, buffer, assembler: Assembler::default(), max_message }
    }

    pub async fn next(&mut self) -> Result<Incoming> {
        loop {
            if let Some((frame, used)) = parse(&self.buffer, self.max_message)? {
                self.buffer.drain(..used);
                if let Some(message) = self.assembler.push(frame, self.max_message)? {
                    return Ok(message);
                }
                continue;
            }
            self.buffer.reserve(4096);
            // `read_buf` only adds what it read: nothing is lost if this is cancelled.
            if self.stream.read_buf(&mut self.buffer).await? == 0 {
                return Err(Error::Closed);
            }
        }
    }
}

/// The writing side.
pub struct Writer<W> {
    stream: W,
    rng: Rng,
    closed: bool,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(stream: W, rng: Rng) -> Self {
        Self { stream, rng, closed: false }
    }

    /// One final frame, masked; after a [`CLOSE`] nothing more is sent.
    pub async fn send(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        if self.closed {
            return Err(Error::CloseSent);
        }
        if opcode == CLOSE {
            self.closed = true;
        }
        let mask = (self.rng.next_u64() as u32).to_be_bytes();
        self.stream.write_all(&encode(opcode, payload, mask)).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Whether a close was sent.
    pub fn closed(&self) -> bool {
        self.closed
    }
}

/// Limits of a client.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The handshake's answer head, in bytes.
    pub max_head: usize,
    /// A message, put together from its fragments, in bytes.
    pub max_message: usize,
    /// How long to wait for the body of a refused handshake.
    pub refusal_wait: Duration,
}

/// Opens a WebSocket at `target` on a connected `stream`, with `headers` after `host`.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    target: &str,
    host: &str,
    headers: &[(&str, &str)],
    limits: Limits,
) -> Result<(Reader<ReadHalf<S>>, Writer<WriteHalf<S>>)> {
    let mut rng = Rng::new();
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
    nonce[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
    let key = base64::encode(&nonce);
    let mut all = vec![("host", host)];
    all.extend_from_slice(headers);
    all.extend_from_slice(&[("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-key", &key), ("sec-websocket-version", "13")]);
    http::write_request(&mut stream, &http::request_head("GET", target, &all), &[]).await?;

    let mut answer = Vec::new();
    let head = http::read_head(&mut stream, &mut answer, limits.max_head).await.map_err(|error| match error {
        http::Error::Unanswered(_) => Error::Unanswered,
        http::Error::Io(error) => Error::Io(error),
        http::Error::Protocol(why) => Error::Protocol(why),
    })?;
    if head.status != 101 {
        // Read the rest of the answer, for the server's error.
        let wanted = head.length + head.header("content-length").and_then(|value| value.parse::<usize>().ok()).unwrap_or(0).min(limits.max_head);
        let _ = tokio::time::timeout(limits.refusal_wait, async {
            while answer.len() < wanted {
                if !matches!(stream.read_buf(&mut answer).await, Ok(1..)) {
                    break;
                }
            }
        })
        .await;
        let (status, body) = http::parse(&answer).unwrap_or((head.status, Vec::new()));
        return Err(Error::Refused { status, body });
    }
    let upgraded = head.header("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = head.header("connection").is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade")));
    if !upgraded || !connection {
        return Err(protocol("the server did not upgrade the connection"));
    }
    if head.header("sec-websocket-accept") != Some(accept_key(&key).as_str()) {
        return Err(protocol("wrong Sec-WebSocket-Accept"));
    }
    if head.header("sec-websocket-extensions").is_some_and(|value| !value.is_empty()) {
        return Err(protocol("an extension was not asked for"));
    }
    let (read, write) = tokio::io::split(stream);
    // Frames that came with the head.
    let buffer = answer.split_off(head.length);
    Ok((Reader::new(read, buffer, limits.max_message), Writer::new(write, rng)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_MESSAGE: usize = 1024 * 1024;
    const LIMITS: Limits = Limits { max_head: 16 * 1024, max_message: MAX_MESSAGE, refusal_wait: Duration::from_secs(2) };

    /// A server frame (unmasked).
    fn server(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![first];
        match payload.len() {
            length @ 0..=125 => out.push(length as u8),
            length @ 126..=0xffff => {
                out.push(126);
                out.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                out.push(127);
                out.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn the_accept_key_is_the_rfc_example() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn client_frames_are_masked() {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        // RFC 6455 5.7: a masked "Hello".
        assert_eq!(encode(TEXT, b"Hello", mask), [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
        for length in [0, 125, 126, 300, 0xffff, 0x10000] {
            let payload: Vec<u8> = (0..length).map(|n| n as u8).collect();
            let frame = encode(BINARY, &payload, mask);
            let (header, length_bytes) = match length {
                0..=125 => (2, 0),
                126..=0xffff => (2, 2),
                _ => (2, 8),
            };
            assert_eq!(frame[0], 0x82);
            assert_eq!(frame[1] & 0x80, 0x80, "masked");
            let start = header + length_bytes;
            assert_eq!(&frame[start..start + 4], &mask);
            let unmasked: Vec<u8> = frame[start + 4..].iter().enumerate().map(|(index, byte)| byte ^ mask[index % 4]).collect();
            assert_eq!(unmasked, payload);
        }
    }

    #[test]
    fn server_frames_parse_whole_or_wait() {
        let frame = server(0x81, b"hi");
        assert_eq!(parse(&frame, MAX_MESSAGE).unwrap(), Some((Frame { fin: true, opcode: TEXT, payload: b"hi".to_vec() }, 4)));
        for cut in 0..frame.len() {
            assert_eq!(parse(&frame[..cut], MAX_MESSAGE).unwrap(), None, "{cut}");
        }
        let long = vec![7u8; 70_000];
        let frame = server(0x82, &long);
        assert_eq!(parse(&frame, MAX_MESSAGE).unwrap().unwrap().1, 10 + 70_000);
        assert_eq!(parse(&frame[..9], MAX_MESSAGE).unwrap(), None);
        let medium = server(0x82, &[1u8; 200]);
        assert_eq!(parse(&medium, MAX_MESSAGE).unwrap().unwrap().0.payload.len(), 200);
        // Two frames back to back: the first, then the rest.
        let mut two = server(0x89, b"p");
        two.extend_from_slice(&server(0x81, b"x"));
        let (first, used) = parse(&two, MAX_MESSAGE).unwrap().unwrap();
        assert_eq!((first.opcode, used), (PING, 3));
        assert_eq!(parse(&two[used..], MAX_MESSAGE).unwrap().unwrap().0.payload, b"x");
    }

    #[test]
    fn bad_server_frames_are_refused() {
        // Too large, known from the header alone.
        assert!(parse(&server(0x82, &[0; 200]), 100).is_err());
        assert!(parse(&[0x82, 127, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], MAX_MESSAGE).is_err());
        // Masked by the server.
        assert!(parse(&[0x81, 0x81, 1, 2, 3, 4, 5], MAX_MESSAGE).is_err());
        // Reserved bits, unknown opcodes, a fragmented or long control frame.
        assert!(parse(&server(0xc1, b"x"), MAX_MESSAGE).is_err());
        assert!(parse(&server(0x83, b"x"), MAX_MESSAGE).is_err());
        assert!(parse(&server(0x09, b"x"), MAX_MESSAGE).is_err());
        assert!(parse(&server(0x89, &[0; 126]), MAX_MESSAGE).is_err());
    }

    #[test]
    fn fragments_make_one_message_and_control_frames_come_between() {
        let mut assembler = Assembler::default();
        let frame = |fin: bool, opcode: u8, payload: &[u8]| Frame { fin, opcode, payload: payload.to_vec() };
        assert_eq!(assembler.push(frame(false, TEXT, b"hel"), MAX_MESSAGE).unwrap(), None);
        assert_eq!(assembler.push(frame(true, PING, b"?"), MAX_MESSAGE).unwrap(), Some(Incoming::Ping(b"?".to_vec())));
        assert_eq!(assembler.push(frame(false, CONTINUATION, b"lo "), MAX_MESSAGE).unwrap(), None);
        assert_eq!(assembler.push(frame(true, CONTINUATION, b"there"), MAX_MESSAGE).unwrap(), Some(Incoming::Text("hello there".into())));
        assert_eq!(assembler.push(frame(true, BINARY, &[1, 2]), MAX_MESSAGE).unwrap(), Some(Incoming::Binary(vec![1, 2])));
        assert_eq!(assembler.push(frame(true, CLOSE, &[0x03, 0xe8]), MAX_MESSAGE).unwrap(), Some(Incoming::Close(Some(1000))));
        assert_eq!(assembler.push(frame(true, CLOSE, &[]), MAX_MESSAGE).unwrap(), Some(Incoming::Close(None)));

        // A continuation without a start, a new message inside one, too large, bad UTF-8.
        assert!(Assembler::default().push(frame(true, CONTINUATION, b"x"), MAX_MESSAGE).is_err());
        let mut started = Assembler::default();
        started.push(frame(false, TEXT, b"a"), MAX_MESSAGE).unwrap();
        assert!(started.push(frame(true, TEXT, b"b"), MAX_MESSAGE).is_err());
        let mut growing = Assembler::default();
        growing.push(frame(false, BINARY, &[0; 8]), 10).unwrap();
        assert!(growing.push(frame(true, CONTINUATION, &[0; 8]), 10).is_err());
        assert!(Assembler::default().push(frame(true, TEXT, &[0xff, 0xfe]), MAX_MESSAGE).is_err());
    }

    #[test]
    fn masks_vary() {
        let mut rng = Rng::new();
        let (a, b) = (rng.next_u64(), rng.next_u64());
        assert_ne!(a, b);
        assert_ne!(Rng::new().next_u64(), Rng::new().next_u64());
    }

    /// The server's side of a handshake on `far`: the request it got, then `answer` (the
    /// accept key put in for `{accept}`) and `frames`.
    async fn serve(mut far: tokio::io::DuplexStream, answer: &'static str, frames: &'static [u8]) -> (String, tokio::io::DuplexStream) {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            far.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let request = String::from_utf8(request).unwrap();
        let key = request.lines().find_map(|line| line.strip_prefix("sec-websocket-key: ")).unwrap();
        far.write_all(answer.replace("{accept}", &accept_key(key)).as_bytes()).await.unwrap();
        far.write_all(frames).await.unwrap();
        (request, far)
    }

    #[tokio::test]
    async fn a_handshake_opens_the_socket() {
        let (near, far) = tokio::io::duplex(4096);
        let answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n";
        let server = tokio::spawn(serve(far, answer, b"\x81\x02hi"));
        let (mut reader, mut writer) = handshake(near, "/api/events", "localhost", &[("authorization", "Bearer t")], LIMITS).await.unwrap();
        let (request, mut far) = server.await.unwrap();
        assert!(request.starts_with("GET /api/events HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer t\r\nupgrade: websocket\r\nconnection: Upgrade\r\n"), "{request}");
        assert_eq!(reader.next().await.unwrap(), Incoming::Text("hi".into()));
        writer.send(CLOSE, &1000u16.to_be_bytes()).await.unwrap();
        assert!(writer.closed() && matches!(writer.send(TEXT, b"x").await, Err(Error::CloseSent)));
        let mut close = [0u8; 8];
        far.read_exact(&mut close).await.unwrap();
        assert_eq!(close[0], 0x88);
        drop(far);
        assert!(matches!(reader.next().await, Err(Error::Closed)));
    }

    #[tokio::test]
    async fn a_refused_or_wrong_handshake_is_an_error() {
        let (near, far) = tokio::io::duplex(4096);
        tokio::spawn(serve(far, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}", b""));
        match handshake(near, "/", "h", &[], LIMITS).await {
            Err(Error::Refused { status, body }) => assert_eq!((status, body.as_slice()), (401, &b"{}"[..])),
            other => panic!("{:?}", other.err()),
        }
        let (near, far) = tokio::io::duplex(4096);
        tokio::spawn(serve(far, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n", b""));
        assert!(matches!(handshake(near, "/", "h", &[], LIMITS).await.err(), Some(Error::Protocol(_))));
        let (near, far) = tokio::io::duplex(4096);
        drop(far);
        assert!(matches!(handshake(near, "/", "h", &[], LIMITS).await.err(), Some(Error::Io(_) | Error::Unanswered)));
    }
}
