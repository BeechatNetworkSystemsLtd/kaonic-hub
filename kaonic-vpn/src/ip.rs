//! IPv4 prefixes and header parsing.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An IPv4 prefix, e.g. `10.77.0.0/16`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidr {
    network: u32,
    len: u8,
}

impl Cidr {
    pub fn new(address: Ipv4Addr, len: u8) -> Option<Self> {
        (len <= 32).then(|| Self { network: u32::from(address) & Self::mask_of(len), len })
    }

    fn mask_of(len: u8) -> u32 {
        if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) }
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | !Self::mask_of(self.len))
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & Self::mask_of(self.len) == self.network
    }

    /// The `index`th address of the prefix.
    pub fn host(&self, index: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.network | (index & !Self::mask_of(self.len)))
    }

    /// Whether the two prefixes share any address.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.contains(other.network()) || other.contains(self.network())
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.len)
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let (address, len) = text.split_once('/').ok_or_else(|| format!("{text}: not a prefix like 192.168.10.0/24"))?;
        let address: Ipv4Addr = address.parse().map_err(|_| format!("{text}: not an IPv4 address"))?;
        let len: u8 = len.parse().map_err(|_| format!("{text}: bad prefix length"))?;
        Cidr::new(address, len).ok_or_else(|| format!("{text}: bad prefix length"))
    }
}

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMP: u8 = 1;

/// Fields from an IPv4 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    /// Source and destination ports for TCP and UDP; None for later fragments.
    pub ports: Option<(u16, u16)>,
    pub len: usize,
}

impl Summary {
    pub fn proto_name(&self) -> String {
        match self.proto {
            TCP => "TCP".into(),
            UDP => "UDP".into(),
            ICMP => "ICMP".into(),
            other => format!("IP {other}"),
        }
    }
}

/// Reads an IPv4 header; None for anything else (no IPv6 yet).
pub fn summarize(packet: &[u8]) -> Option<Summary> {
    let &first = packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total < header_len || total > packet.len() {
        return None;
    }
    let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
    let proto = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let ports = (matches!(proto, TCP | UDP) && fragment_offset == 0 && total >= header_len + 4).then(|| {
        let at = header_len;
        (u16::from_be_bytes([packet[at], packet[at + 1]]), u16::from_be_bytes([packet[at + 2], packet[at + 3]]))
    });
    Some(Summary { src, dst, proto, ports, len: total })
}

/// Whether `dst` is sent to every peer: broadcast or multicast.
pub fn is_flooded(dst: Ipv4Addr, tunnel: &Cidr) -> bool {
    dst.is_broadcast() || dst.is_multicast() || dst == tunnel.broadcast()
}

#[cfg(test)]
pub(crate) fn packet(src: [u8; 4], dst: [u8; 4], proto: u8, payload_len: usize) -> Vec<u8> {
    let total = 20 + 8 + payload_len;
    let mut out = vec![0u8; total];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[8] = 64;
    out[9] = proto;
    out[12..16].copy_from_slice(&src);
    out[16..20].copy_from_slice(&dst);
    out[20..22].copy_from_slice(&40000u16.to_be_bytes());
    out[22..24].copy_from_slice(&53u16.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let net: Cidr = "10.77.12.34/16".parse().unwrap();
        assert_eq!(net.to_string(), "10.77.0.0/16");
        assert_eq!(net.broadcast(), Ipv4Addr::new(10, 77, 255, 255));
        assert!(net.contains(Ipv4Addr::new(10, 77, 1, 1)) && !net.contains(Ipv4Addr::new(10, 78, 0, 1)));
        assert_eq!(net.host(0x0102), Ipv4Addr::new(10, 77, 1, 2));
        assert!(net.overlaps(&"10.77.5.0/24".parse().unwrap()));
        assert!(!net.overlaps(&"192.168.1.0/24".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err() && "10.0.0.0".parse::<Cidr>().is_err());
        assert!("0.0.0.0/0".parse::<Cidr>().unwrap().contains(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn headers() {
        let udp = packet([10, 77, 0, 1], [10, 77, 0, 2], UDP, 12);
        let summary = summarize(&udp).unwrap();
        assert_eq!((summary.src, summary.dst, summary.proto, summary.ports, summary.len), (Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(10, 77, 0, 2), UDP, Some((40000, 53)), 40));
        assert_eq!(summary.proto_name(), "UDP");
        let mut later_fragment = udp.clone();
        later_fragment[7] = 1;
        assert_eq!(summarize(&later_fragment).unwrap().ports, None);
        assert_eq!(summarize(&[0x60; 40]), None);
        assert_eq!(summarize(&udp[..10]), None);
        let net: Cidr = "10.77.0.0/16".parse().unwrap();
        assert!(is_flooded(Ipv4Addr::new(10, 77, 255, 255), &net));
        assert!(is_flooded(Ipv4Addr::new(239, 2, 3, 1), &net) && is_flooded(Ipv4Addr::BROADCAST, &net));
        assert!(!is_flooded(Ipv4Addr::new(10, 77, 0, 2), &net));
    }
}
