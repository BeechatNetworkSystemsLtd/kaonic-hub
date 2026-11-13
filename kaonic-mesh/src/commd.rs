//! A small client for commd: read and set each radio's sub-GHz filter.
//!
//! Speaks commd's control protocol over UDP (`127.0.0.1:9090`), written here so the hub does
//! not build commd's crates.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kaonic_frame::frame::{Frame, FrameSegment};
use kaonic_net::coder::BinaryPacketCoder;
use kaonic_net::network::Network;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::UdpSocket;

/// Where commd listens.
pub const DEFAULT_ADDR: &str = "127.0.0.1:9090";
/// commd's packet size and segments per message.
const MTU: usize = 1400;
const SEGMENTS: usize = 5;
/// One message in flight at a time.
const QUEUE: usize = 2;
const PATTERN: u16 = 0xBACE;
/// After no answer, commd is not asked again for this long.
const QUIET: Duration = Duration::from_secs(10);

type CtrlNetwork = Network<MTU, SEGMENTS, QUEUE, BinaryPacketCoder<MTU>>;

/// A filter and its passband.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub label: String,
    pub min_khz: u32,
    pub max_khz: u32,
}

/// A module's filters, the selection (`None` is auto), the one in use, and its band ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filters {
    pub filters: Vec<Filter>,
    pub selected: Option<u8>,
    pub active: Option<u8>,
    pub sub_ghz: Option<(u32, u32)>,
    pub band_24: Option<(u32, u32)>,
}

#[derive(Debug)]
pub enum Error {
    /// No answer, or no daemon.
    Unreachable,
    /// commd answered `Error`: no such module or filter.
    Refused,
    /// An answer this client does not understand.
    Protocol,
}

pub struct Commd {
    addr: SocketAddr,
    timeout: Duration,
    /// One socket for the hub's life.
    socket: tokio::sync::Mutex<Option<UdpSocket>>,
    quiet_until: Mutex<Option<Instant>>,
}

impl Commd {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, timeout: Duration::from_millis(300), socket: tokio::sync::Mutex::new(None), quiet_until: Mutex::new(None) }
    }

    pub async fn filters(&self, module: usize) -> Result<Filters, Error> {
        // GetFiltersRequest { module }
        let mut request = Vec::new();
        variant(&mut request, "GetFiltersRequest");
        array(&mut request, 1);
        uint(&mut request, module as u64);
        let reply = self.request(&request).await?;
        let mut reader = Reader(&reply);
        let (name, value) = reader.variant()?;
        match (name.as_str(), value) {
            ("GetFiltersResponse", true) => {
                // GetFiltersResponse { module, filters, selected, active, ranges }
                if reader.array()? != 5 {
                    return Err(Error::Protocol);
                }
                reader.uint()?;
                let count = reader.array()?;
                let mut filters = Vec::with_capacity(count.min(16));
                for _ in 0..count {
                    // FilterInfo { label, min_khz, max_khz }
                    if reader.array()? != 3 {
                        return Err(Error::Protocol);
                    }
                    let label = reader.str()?;
                    let min_khz = reader.u32()?;
                    let max_khz = reader.u32()?;
                    filters.push(Filter { label, min_khz, max_khz });
                }
                let selected = reader.option_u8()?;
                let active = reader.option_u8()?;
                let mut answer = Filters { filters, selected, active, sub_ghz: None, band_24: None };
                for _ in 0..reader.array()? {
                    // BandRangeInfo { band, min_khz, max_khz }
                    if reader.array()? != 3 {
                        return Err(Error::Protocol);
                    }
                    let band = reader.str()?;
                    let range = Some((reader.u32()?, reader.u32()?));
                    match band.as_str() {
                        "Band09" => answer.sub_ghz = range,
                        "Band24" => answer.band_24 = range,
                        _ => {}
                    }
                }
                Ok(answer)
            }
            ("Error", false) => Err(Error::Refused),
            _ => Err(Error::Protocol),
        }
    }

    /// Selects a filter (`None` is auto).
    pub async fn set_filter(&self, module: usize, filter: Option<u8>) -> Result<(), Error> {
        // SetFilterRequest { module, filter }
        let mut request = Vec::new();
        variant(&mut request, "SetFilterRequest");
        array(&mut request, 2);
        uint(&mut request, module as u64);
        match filter {
            Some(index) => uint(&mut request, u64::from(index)),
            None => request.push(0xc0),
        }
        let reply = self.request(&request).await?;
        let (name, value) = Reader(&reply).variant()?;
        match (name.as_str(), value) {
            ("SetFilterResponse", false) => Ok(()),
            ("Error", false) => Err(Error::Refused),
            _ => Err(Error::Protocol),
        }
    }

    async fn request(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.quiet_until.lock().expect("commd lock").is_some_and(|until| Instant::now() < until) {
            return Err(Error::Unreachable);
        }
        let result = tokio::time::timeout(self.timeout, self.exchange(payload)).await;
        match result {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(error)) => {
                log::debug!("commd {}: {error}", self.addr);
                self.go_quiet();
                Err(Error::Unreachable)
            }
            Err(_) => {
                log::debug!("commd {}: no answer", self.addr);
                self.go_quiet();
                Err(Error::Unreachable)
            }
        }
    }

    fn go_quiet(&self) {
        *self.quiet_until.lock().expect("commd lock") = Some(Instant::now() + QUIET);
    }

    async fn exchange(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut socket = self.socket.lock().await;
        if socket.is_none() {
            let local: SocketAddr = if self.addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("valid address");
            let opened = UdpSocket::bind(local).await?;
            opened.connect(self.addr).await?;
            *socket = Some(opened);
        }
        let socket = socket.as_ref().expect("socket opened");
        // Drop what commd pushed meanwhile (it sends frames to its clients).
        let mut buffer = vec![0u8; MTU];
        while socket.try_recv(&mut buffer).is_ok() {}

        let id = OsRng.next_u32();
        let mut message = Vec::with_capacity(12 + payload.len());
        message.extend_from_slice(&PATTERN.to_le_bytes());
        message.extend_from_slice(&0u16.to_le_bytes());
        message.extend_from_slice(&id.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.extend_from_slice(payload);

        let mut network = Box::new(CtrlNetwork::new(BinaryPacketCoder::new()));
        let mut frames = Box::new([Frame::<MTU>::new(); SEGMENTS]);
        let segments = network.transmit(&message, OsRng, &mut frames[..]).map_err(|_| io::Error::other("message too large"))?;
        for segment in segments {
            socket.send(segment.as_slice()).await?;
        }

        let mut assembled = Box::new(FrameSegment::<MTU, SEGMENTS>::new());
        loop {
            let length = socket.recv(&mut buffer).await?;
            let now = now_ms();
            let mut frame = Frame::<MTU>::new();
            frame.copy_from_slice(&buffer[..length]);
            if network.receive(now, &frame).is_err() {
                continue;
            }
            while let Ok(packet) = network.process(now, &mut assembled) {
                let bytes = packet.as_slice();
                if bytes.len() < 12 || u16::from_le_bytes([bytes[0], bytes[1]]) != PATTERN {
                    continue;
                }
                if u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) == id {
                    return Ok(bytes[12..].to_vec());
                }
            }
        }
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis())
}

/* ── the MessagePack this needs ── */

fn array(out: &mut Vec<u8>, len: usize) {
    if len < 16 {
        out.push(0x90 | len as u8);
    } else {
        out.push(0xdc);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn uint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x7f => out.push(value as u8),
        0x80..=0xff => out.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn string(out: &mut Vec<u8>, text: &str) {
    let len = text.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0xd9, len as u8]);
    } else {
        out.push(0xda);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(text.as_bytes());
}

/// The start of a variant with a value: a one-entry map from its name.
fn variant(out: &mut Vec<u8>, name: &str) {
    out.push(0x81);
    string(out, name);
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        let (&first, rest) = self.0.split_first().ok_or(Error::Protocol)?;
        self.0 = rest;
        Ok(first)
    }

    fn bytes(&mut self, len: usize) -> Result<&[u8], Error> {
        if self.0.len() < len {
            return Err(Error::Protocol);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn be(&mut self, len: usize) -> Result<u64, Error> {
        Ok(self.bytes(len)?.iter().fold(0u64, |value, byte| value << 8 | u64::from(*byte)))
    }

    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn uint(&mut self) -> Result<u64, Error> {
        match self.byte()? {
            byte @ 0x00..=0x7f => Ok(u64::from(byte)),
            0xcc => self.be(1),
            0xcd => self.be(2),
            0xce => self.be(4),
            0xcf => self.be(8),
            _ => Err(Error::Protocol),
        }
    }

    fn array(&mut self) -> Result<usize, Error> {
        match self.byte()? {
            byte @ 0x90..=0x9f => Ok(usize::from(byte & 0x0f)),
            0xdc => Ok(self.be(2)? as usize),
            0xdd => Ok(self.be(4)? as usize),
            _ => Err(Error::Protocol),
        }
    }

    fn str(&mut self) -> Result<String, Error> {
        let len = match self.byte()? {
            byte @ 0xa0..=0xbf => usize::from(byte & 0x1f),
            0xd9 => self.be(1)? as usize,
            0xda => self.be(2)? as usize,
            0xdb => self.be(4)? as usize,
            _ => return Err(Error::Protocol),
        };
        String::from_utf8(self.bytes(len)?.to_vec()).map_err(|_| Error::Protocol)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        u32::try_from(self.uint()?).map_err(|_| Error::Protocol)
    }

    fn option_u8(&mut self) -> Result<Option<u8>, Error> {
        if self.peek() == Some(0xc0) {
            self.byte()?;
            return Ok(None);
        }
        u8::try_from(self.uint()?).map(Some).map_err(|_| Error::Protocol)
    }

    /// A variant's name, and whether a value follows.
    fn variant(&mut self) -> Result<(String, bool), Error> {
        if self.peek() == Some(0x81) {
            self.byte()?;
            return Ok((self.str()?, true));
        }
        Ok((self.str()?, false))
    }
}

/// A fake commd for tests: answers the filter messages from a fixed table.
pub struct FakeCommd {
    pub addr: SocketAddr,
    /// The selection per module, as last set.
    pub selected: std::sync::Arc<Mutex<Vec<Option<u8>>>>,
}

impl FakeCommd {
    /// Listens on `addr`; needs a tokio runtime.
    pub async fn spawn(addr: SocketAddr, modules: usize, filters: Vec<Filter>, sub_ghz: (u32, u32)) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let addr = socket.local_addr()?;
        let selected = std::sync::Arc::new(Mutex::new(vec![None; modules]));
        let state = selected.clone();
        tokio::spawn(async move {
            let mut network = Box::new(CtrlNetwork::new(BinaryPacketCoder::new()));
            let mut assembled = Box::new(FrameSegment::<MTU, SEGMENTS>::new());
            let mut buffer = vec![0u8; MTU];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let now = now_ms();
                let mut frame = Frame::<MTU>::new();
                frame.copy_from_slice(&buffer[..length]);
                if network.receive(now, &frame).is_err() {
                    continue;
                }
                let Ok(packet) = network.process(now, &mut assembled) else { continue };
                let bytes = packet.as_slice().to_vec();
                if bytes.len() < 12 {
                    continue;
                }
                let reply = Self::answer(&state, &filters, sub_ghz, &bytes[12..]);
                let mut message = bytes[..12].to_vec();
                message.extend_from_slice(&reply);
                let mut frames = Box::new([Frame::<MTU>::new(); SEGMENTS]);
                let Ok(segments) = network.transmit(&message, OsRng, &mut frames[..]) else { continue };
                for segment in segments {
                    let _ = socket.send_to(segment.as_slice(), peer).await;
                }
            }
        });
        Ok(Self { addr, selected })
    }

    fn answer(state: &Mutex<Vec<Option<u8>>>, filters: &[Filter], sub_ghz: (u32, u32), payload: &[u8]) -> Vec<u8> {
        let mut reply = Vec::new();
        let mut reader = Reader(payload);
        let mut selected = state.lock().expect("fake commd lock");
        match reader.variant() {
            Ok((name, true)) if name == "GetFiltersRequest" => {
                let module = reader.array().and_then(|_| reader.uint()).ok().map(|module| module as usize);
                let Some(&current) = module.and_then(|module| selected.get(module)) else {
                    string(&mut reply, "Error");
                    return reply;
                };
                variant(&mut reply, "GetFiltersResponse");
                array(&mut reply, 5);
                uint(&mut reply, module.unwrap_or_default() as u64);
                array(&mut reply, filters.len());
                for filter in filters {
                    array(&mut reply, 3);
                    string(&mut reply, &filter.label);
                    uint(&mut reply, u64::from(filter.min_khz));
                    uint(&mut reply, u64::from(filter.max_khz));
                }
                let active = current.or((!filters.is_empty()).then_some(0));
                for value in [current, active] {
                    match value {
                        Some(index) => uint(&mut reply, u64::from(index)),
                        None => reply.push(0xc0),
                    }
                }
                array(&mut reply, 2);
                for (band, (min, max)) in [("Band09", sub_ghz), ("Band24", (2_400_000, 2_483_500))] {
                    array(&mut reply, 3);
                    string(&mut reply, band);
                    uint(&mut reply, u64::from(min));
                    uint(&mut reply, u64::from(max));
                }
            }
            Ok((name, true)) if name == "SetFilterRequest" => {
                let request = reader.array().and_then(|_| Ok((reader.uint()? as usize, reader.option_u8()?)));
                match request {
                    Ok((module, filter)) if module < selected.len() && filter.is_none_or(|index| usize::from(index) < filters.len()) => {
                        selected[module] = filter;
                        string(&mut reply, "SetFilterResponse");
                    }
                    _ => string(&mut reply, "Error"),
                }
            }
            _ => string(&mut reply, "NotImplemented"),
        }
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// kaonic-ctrl's own encoding (rmp-serde), as its protocol tests pin it.
    #[test]
    fn requests_are_encoded_as_commd_expects() {
        let mut get = Vec::new();
        variant(&mut get, "GetFiltersRequest");
        array(&mut get, 1);
        uint(&mut get, 1);
        let mut expected = vec![0x81, 0xb1];
        expected.extend_from_slice(b"GetFiltersRequest");
        expected.extend_from_slice(&[0x91, 0x01]);
        assert_eq!(get, expected);

        let mut set = Vec::new();
        variant(&mut set, "SetFilterRequest");
        array(&mut set, 2);
        uint(&mut set, 1);
        uint(&mut set, 2);
        let mut expected = vec![0x81, 0xb0];
        expected.extend_from_slice(b"SetFilterRequest");
        expected.extend_from_slice(&[0x92, 0x01, 0x02]);
        assert_eq!(set, expected);
    }

    #[test]
    fn a_filters_response_from_rmp_serde_is_read() {
        // rmp-serde's bytes for GetFiltersResponse { module: 1, filters: [{ "Wide", 730000,
        // 960000 }], selected: None, active: Some(0), ranges: [{ Band09, 863000, 928000 }] }.
        let mut bytes = vec![0x81, 0xb2];
        bytes.extend_from_slice(b"GetFiltersResponse");
        bytes.extend_from_slice(&[0x95, 0x01, 0x91, 0x93, 0xa4]);
        bytes.extend_from_slice(b"Wide");
        bytes.extend_from_slice(&[0xce, 0x00, 0x0b, 0x23, 0x90, 0xce, 0x00, 0x0e, 0xa6, 0x00, 0xc0, 0x00, 0x91, 0x93, 0xa6]);
        bytes.extend_from_slice(b"Band09");
        bytes.extend_from_slice(&[0xce, 0x00, 0x0d, 0x2b, 0x18, 0xce, 0x00, 0x0e, 0x29, 0x00]);
        let mut reader = Reader(&bytes);
        assert_eq!(reader.variant().unwrap(), ("GetFiltersResponse".to_owned(), true));
        assert_eq!(reader.array().unwrap(), 5);
        assert_eq!(reader.uint().unwrap(), 1);
        assert_eq!(reader.array().unwrap(), 1);
        assert_eq!(reader.array().unwrap(), 3);
        assert_eq!(reader.str().unwrap(), "Wide");
        assert_eq!(reader.u32().unwrap(), 730_000);
        assert_eq!(reader.u32().unwrap(), 960_000);
        assert_eq!(reader.option_u8().unwrap(), None);
        assert_eq!(reader.option_u8().unwrap(), Some(0));
        assert_eq!(reader.array().unwrap(), 1);
        assert_eq!(reader.array().unwrap(), 3);
        assert_eq!(reader.str().unwrap(), "Band09");
        assert_eq!(reader.u32().unwrap(), 863_000);
        assert_eq!(reader.u32().unwrap(), 928_000);
        assert!(reader.0.is_empty());
    }

    #[test]
    fn integers_and_strings_round_trip() {
        for value in [0, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            let mut out = Vec::new();
            uint(&mut out, value);
            assert_eq!(Reader(&out).uint().unwrap(), value);
        }
        for len in [0, 31, 32, 255, 256] {
            let text = "x".repeat(len);
            let mut out = Vec::new();
            string(&mut out, &text);
            assert_eq!(Reader(&out).str().unwrap(), text);
        }
        assert!(Reader(&[0xa5, b'a']).str().is_err());
        assert!(Reader(&[0xcd, 0x01, 0x00]).option_u8().is_err());
    }

    #[tokio::test]
    async fn the_client_talks_to_a_commd_over_udp() {
        let table = vec![
            Filter { label: "Wide 730–960 MHz".into(), min_khz: 730_000, max_khz: 960_000 },
            Filter { label: "868 MHz".into(), min_khz: 862_000, max_khz: 876_000 },
        ];
        let fake = FakeCommd::spawn("127.0.0.1:0".parse().unwrap(), 2, table.clone(), (863_000, 928_000)).await.unwrap();
        let commd = Commd::new(fake.addr);
        let filters = commd.filters(1).await.unwrap();
        assert_eq!(filters, Filters { filters: table, selected: None, active: Some(0), sub_ghz: Some((863_000, 928_000)), band_24: Some((2_400_000, 2_483_500)) });
        commd.set_filter(1, Some(1)).await.unwrap();
        assert_eq!(commd.filters(1).await.unwrap().selected, Some(1));
        assert!(matches!(commd.set_filter(1, Some(5)).await, Err(Error::Refused)));
        assert!(matches!(commd.filters(5).await, Err(Error::Refused)));
        commd.set_filter(1, None).await.unwrap();
        assert_eq!(fake.selected.lock().unwrap()[1], None);

        // Nobody there: unreachable, and not asked again for a while.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let nobody = Commd::new(silent.local_addr().unwrap());
        let started = Instant::now();
        assert!(matches!(nobody.filters(0).await, Err(Error::Unreachable)));
        assert!(matches!(nobody.filters(0).await, Err(Error::Unreachable)));
        assert!(started.elapsed() < Duration::from_millis(600));
    }
}
