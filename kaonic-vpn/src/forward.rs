//! Forwards UDP multicast and broadcast between the nodes' client networks, by rule. The
//! kernel routes neither, so apps that find peers by multicast (e.g. ATAK) would not see
//! anyone behind another node without this.
//!
//! A rule names a multicast group (or range, or the LAN broadcast), a UDP port or range, a
//! direction, and the client interfaces it serves. Nothing is forwarded without a rule, and
//! each node applies its own rules. The [`defaults`] carry every multicast group and every
//! broadcast on any port. Wide rules like these skip LAN control chatter (224.0.0.0/24,
//! SSDP, NetBIOS). DHCP is never carried.
//!
//! A datagram heard on a client network becomes an IPv4/UDP packet to the group (or the
//! broadcast address) and is flooded to every peer like any other VPN broadcast, under the
//! node's flood budget. Datagrams larger than the tunnel MTU are sent as IPv4 fragments.
//! The far node checks it like any VPN packet and re-sends it on its LAN if a rule matches.
//!
//! Loop and flood protection:
//! - Tunnel packets have TTL 1 and are never passed on to another peer. Every node is one
//!   link away.
//! - The LAN side ignores datagrams this node sent (`crate::lan`).
//! - The same datagram (by content) seen within the rule's `dedup_secs` is dropped in
//!   either direction.
//! - Each rule has a size limit and a token bucket per sender and destination. All rules
//!   together stay under the node's flood budget.
//!
//! No I/O here: sockets are in `crate::lan`, wiring in [`crate::service`].
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use crate::flood::Limiter;
use crate::ip::{Cidr, UDP};

pub const MAX_RULES: usize = 16;
/// Rules over more ports than this are wide ([`Rule::is_wide`]).
pub const MAX_PORTS: u16 = 16;
/// DHCP is never carried.
const DHCP_PORTS: (u16, u16) = (67, 68);
/// NetBIOS name and datagram ports (Windows broadcast chatter).
const NETBIOS_PORTS: (u16, u16) = (137, 138);
const SSDP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const MAX_INTERFACES: usize = 8;
/// Max datagram size a rule may allow.
pub const MAX_BYTES: usize = 2048;
pub const MAX_RATE: u32 = 50;
pub const MAX_BURST: u32 = 100;
pub const MAX_DEDUP_SECS: u32 = 60;
pub const MAX_TTL: u8 = 16;
/// TTL of forwarded datagrams in the tunnel: one hop.
pub const TUNNEL_TTL: u8 = 1;
/// Max datagrams remembered for duplicate detection.
const MAX_SEEN: usize = 1024;
/// Max datagrams being reassembled at once, and the timeout.
const MAX_PARTIALS: usize = 16;
const PARTIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// LAN to mesh and mesh to LAN.
    Both,
    /// LAN to mesh only.
    ToMesh,
    /// Mesh to LAN only.
    FromMesh,
    /// Not forwarded, whatever later rules say.
    Block,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::ToMesh => "to_mesh",
            Self::FromMesh => "from_mesh",
            Self::Block => "block",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "both" => Some(Self::Both),
            "to_mesh" => Some(Self::ToMesh),
            "from_mesh" => Some(Self::FromMesh),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    fn to_mesh(self) -> bool {
        matches!(self, Self::Both | Self::ToMesh)
    }

    fn from_mesh(self) -> bool {
        matches!(self, Self::Both | Self::FromMesh)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Unique name; counters are keyed by it.
    pub name: String,
    pub enabled: bool,
    /// A multicast group (`/32`), a range of groups, or `255.255.255.255/32` for LAN
    /// broadcast (both limited and subnet broadcast).
    pub address: Cidr,
    /// First and last UDP port ([`ANY_PORT`] for all).
    pub ports: (u16, u16),
    pub direction: Direction,
    /// Interfaces served; empty means the VPN's client interfaces.
    pub interfaces: Vec<String>,
    /// Datagrams per second to the mesh, and burst, per sender and destination.
    pub rate: u32,
    pub burst: u32,
    /// Larger datagrams are dropped.
    pub max_bytes: usize,
    /// Duplicates within this many seconds are dropped.
    pub dedup_secs: u32,
    /// TTL of datagrams re-sent on the LAN (1: stay on it).
    pub ttl: u8,
    /// Re-send with the original sender's address and port (via a raw socket). If false,
    /// datagrams come from this node's LAN address.
    pub keep_source: bool,
}

/// Every UDP port.
pub const ANY_PORT: (u16, u16) = (1, u16::MAX);

fn single(address: Ipv4Addr) -> Cidr {
    Cidr::new(address, 32).expect("valid prefix")
}

impl Rule {
    /// A rule for one group (or `255.255.255.255`) and port, with defaults: both ways, client
    /// interfaces, 5 datagrams/s.
    pub fn new(name: &str, address: Ipv4Addr, port: u16) -> Self {
        Self { name: name.to_owned(), enabled: true, address: single(address), ports: (port, port), direction: Direction::Both, interfaces: Vec::new(), rate: 5, burst: 10, max_bytes: 1472, dedup_secs: 5, ttl: 1, keep_source: true }
    }

    /// A rule for any port on a range of groups (or broadcast, as `/32`).
    pub fn range(name: &str, address: Cidr) -> Self {
        Self { address, ports: ANY_PORT, ..Self::new(name, address.network(), 1) }
    }

    pub fn is_broadcast(&self) -> bool {
        self.address.network().is_broadcast()
    }

    /// A rule over a range of groups or more than [`MAX_PORTS`] ports. Wide rules skip LAN
    /// control chatter.
    pub fn is_wide(&self) -> bool {
        self.address.prefix_len() < 32 || self.ports.1 - self.ports.0 >= MAX_PORTS
    }

    fn has_port(&self, port: u16) -> bool {
        (self.ports.0..=self.ports.1).contains(&port)
    }

    /// Whether the rule matches a datagram to `dst` (or any broadcast, if `broadcast`) and `port`.
    fn names(&self, broadcast: bool, dst: Ipv4Addr, port: u16) -> bool {
        if !self.enabled || !self.has_port(port) || broadcast != self.is_broadcast() || (!broadcast && !self.address.contains(dst)) {
            return false;
        }
        if broadcast && (DHCP_PORTS.0..=DHCP_PORTS.1).contains(&port) {
            return false;
        }
        !(self.is_wide() && is_control(broadcast, dst, port))
    }
}

/// LAN control chatter, carried only by a narrow rule: 224.0.0.0/24 (mDNS, LLMNR, routing
/// protocols), SSDP, and NetBIOS broadcast.
pub fn is_control(broadcast: bool, dst: Ipv4Addr, port: u16) -> bool {
    if broadcast {
        (NETBIOS_PORTS.0..=NETBIOS_PORTS.1).contains(&port)
    } else {
        dst.octets()[..3] == [224, 0, 0] || dst == SSDP
    }
}

/// A validation error: rule index, field and message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid {
    pub rule: usize,
    pub field: &'static str,
    pub message: String,
}

pub fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// Checks rules. [`Forward::set_rules`] does not validate.
pub fn validate(rules: &[Rule]) -> Result<(), Invalid> {
    let invalid = |rule: usize, field: &'static str, message: &str| Err(Invalid { rule, field, message: message.to_owned() });
    if rules.len() > MAX_RULES {
        return invalid(MAX_RULES, "rules", &format!("At most {MAX_RULES} rules."));
    }
    for (index, rule) in rules.iter().enumerate() {
        let name_ok = !rule.name.is_empty() && rule.name.len() <= 32 && rule.name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b" _.-".contains(&byte));
        if !name_ok {
            return invalid(index, "name", "1 to 32 letters, digits, spaces, _ . or -.");
        }
        if rules[..index].iter().any(|other| other.name == rule.name) {
            return invalid(index, "name", "Another rule has this name.");
        }
        let multicast = rule.address.network().is_multicast() && rule.address.prefix_len() >= 4;
        if !multicast && !(rule.is_broadcast() && rule.address.prefix_len() == 32) {
            return invalid(index, "address", "A multicast group (224.0.0.0 to 239.255.255.255), a range of groups like 239.0.0.0/8, or 255.255.255.255 for the LAN's broadcast.");
        }
        let (first, last) = rule.ports;
        if first == 0 || last < first {
            return invalid(index, "port", "A UDP port from 1 to 65535, and a last port not below it.");
        }
        // A wider port range is fine: [`Rule::names`] skips DHCP.
        if rule.is_broadcast() && first >= DHCP_PORTS.0 && last <= DHCP_PORTS.1 {
            return invalid(index, "port", "DHCP (ports 67 and 68) is not carried between networks.");
        }
        if rule.interfaces.len() > MAX_INTERFACES || !rule.interfaces.iter().all(|name| valid_interface(name)) {
            return invalid(index, "interfaces", &format!("Up to {MAX_INTERFACES} interface names (letters, digits, _ . -)."));
        }
        if !(1..=MAX_RATE).contains(&rule.rate) {
            return invalid(index, "rate", &format!("1 to {MAX_RATE} datagrams per second."));
        }
        if !(1..=MAX_BURST).contains(&rule.burst) {
            return invalid(index, "burst", &format!("1 to {MAX_BURST} datagrams."));
        }
        if !(1..=MAX_BYTES).contains(&rule.max_bytes) {
            return invalid(index, "max_bytes", &format!("1 to {MAX_BYTES} bytes."));
        }
        if !(1..=MAX_DEDUP_SECS).contains(&rule.dedup_secs) {
            return invalid(index, "dedup_secs", &format!("1 to {MAX_DEDUP_SECS} seconds."));
        }
        if !(1..=MAX_TTL).contains(&rule.ttl) {
            return invalid(index, "ttl", &format!("1 to {MAX_TTL}."));
        }
    }
    Ok(())
}

/// Default rules: every multicast group and every broadcast, any port, both ways. The rate
/// is low (2/s per sender and destination): enough for periodic announcements, not streams.
pub fn defaults() -> Vec<Rule> {
    vec![
        Rule { rate: 2, ..Rule::range("multicast", Cidr::new(Ipv4Addr::new(224, 0, 0, 0), 4).expect("valid prefix")) },
        Rule { rate: 2, ..Rule::range("broadcast", single(Ipv4Addr::BROADCAST)) },
    ]
}

/// Ready-made rule sets. Not used unless saved as rules.
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rules: Vec<Rule>,
}

pub fn presets() -> Vec<Preset> {
    vec![
        Preset {
            id: "default",
            title: "Everything (default)",
            description: "Every multicast group and every broadcast of the client networks, any UDP port: applications that find each other on a LAN work across the mesh unchanged. Not carried: DHCP, the link-local control groups (224.0.0.0/24, mDNS and LLMNR among them), SSDP and NetBIOS.",
            rules: defaults(),
        },
        Preset {
            id: "atak",
            title: "ATAK only",
            description: "Situational awareness (239.2.3.1:6969) and GeoChat (224.10.10.1:17012) of ATAK, WinTAK and iTAK in their default mesh setup, and nothing else.",
            rules: vec![
                Rule::new("atak-sa", Ipv4Addr::new(239, 2, 3, 1), 6969),
                Rule { rate: 2, ..Rule::new("atak-chat", Ipv4Addr::new(224, 10, 10, 1), 17012) },
            ],
        },
    ]
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// LAN datagrams sent to the mesh.
    pub to_mesh_packets: u64,
    pub to_mesh_bytes: u64,
    /// Mesh datagrams re-emitted on the LAN.
    pub from_mesh_packets: u64,
    pub from_mesh_bytes: u64,
    /// Over the rule's rate.
    pub rate_limited: u64,
    /// Duplicates within `dedup_secs` (either direction).
    pub duplicates: u64,
    /// Over `max_bytes`.
    pub too_large: u64,
    /// Our own datagram, heard back on the LAN.
    pub looped: u64,
    /// Source not on the interface's networks.
    pub foreign_source: u64,
    /// Refused by the VPN: no linked peer, or over the flood budget.
    pub not_sent: u64,
    /// Sending on the LAN failed, or there was no socket.
    pub emit_errors: u64,
    /// Unix milliseconds.
    pub last_to_mesh_ms: Option<i64>,
    pub last_from_mesh_ms: Option<i64>,
}

/// A rule's state on one interface, for the API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanState {
    pub rule: String,
    pub interface: String,
    /// `ready`, `waiting` (no such interface yet) or `error` (socket failed to open).
    pub state: &'static str,
    pub detail: Option<String>,
}

/// A datagram to send on the LAN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emit {
    pub rule: String,
    pub interfaces: Vec<String>,
    /// The group, or `255.255.255.255`.
    pub address: Ipv4Addr,
    /// Sent to a subnet broadcast: use each interface's own broadcast address.
    pub directed: bool,
    pub port: u16,
    pub ttl: u8,
    /// Original sender, if the rule keeps it and the mesh can route to it.
    pub source: Option<SocketAddrV4>,
    pub payload: Vec<u8>,
}

/// A datagram for the mesh, as tunnel packets (several if fragmented).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub rule: String,
    pub bytes: usize,
    pub packets: Vec<Vec<u8>>,
}

/// Why the LAN side dropped a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Looped,
    ForeignSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleStatus {
    pub rule: Rule,
    pub counters: Counters,
    pub lan: Vec<LanState>,
}

struct Slot {
    rule: Rule,
    /// Per sender and destination.
    bucket: Limiter<(Ipv4Addr, Ipv4Addr, u16)>,
}

/// A client network of this node and its prefix on the mesh (`mapped` equals `subnet` if
/// not mapped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lan {
    pub interface: String,
    pub subnet: Cidr,
    pub mapped: Cidr,
}

struct Partial {
    started: Instant,
    data: Vec<u8>,
    /// Byte ranges received.
    have: Vec<(usize, usize)>,
    total: Option<usize>,
    ttl: u8,
}

pub struct Forward {
    me: Ipv4Addr,
    tunnel: Cidr,
    mtu: usize,
    slots: Vec<Slot>,
    counters: HashMap<String, Counters>,
    /// The VPN's client interfaces, used by rules with no interfaces.
    lan_interfaces: Vec<String>,
    /// Recent datagrams, by content hash.
    seen: HashMap<u64, Instant>,
    partials: HashMap<(Ipv4Addr, Ipv4Addr, u16), Partial>,
    next_id: u16,
    lan: Vec<LanState>,
    lans: Vec<Lan>,
}

fn sum(mut total: u32, bytes: &[u8]) -> u32 {
    for pair in bytes.chunks(2) {
        total += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    total
}

fn fold(mut total: u32) -> u16 {
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

/// Builds IPv4 packets for a UDP datagram, fragmented to fit `mtu`.
pub fn packets(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8], id: u16, ttl: u8, mtu: usize) -> Vec<Vec<u8>> {
    let length = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(usize::from(length));
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&src.ip().octets());
    pseudo[4..8].copy_from_slice(&dst.ip().octets());
    pseudo[9] = UDP;
    pseudo[10..].copy_from_slice(&length.to_be_bytes());
    let checksum = match fold(sum(sum(0, &pseudo), &udp)) {
        0 => 0xffff,
        checksum => checksum,
    };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    // Every fragment but the last carries a multiple of 8 bytes.
    let room = (mtu.max(68) - 20) / 8 * 8;
    let count = udp.len().div_ceil(room);
    udp.chunks(room)
        .enumerate()
        .map(|(index, piece)| {
            let mut packet = vec![0u8; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&((20 + piece.len()) as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&id.to_be_bytes());
            let more = if index + 1 < count { 0x2000 } else { 0 };
            packet[6..8].copy_from_slice(&(more | (index * room / 8) as u16).to_be_bytes());
            packet[8] = ttl;
            packet[9] = UDP;
            packet[12..16].copy_from_slice(&src.ip().octets());
            packet[16..20].copy_from_slice(&dst.ip().octets());
            let checksum = fold(sum(0, &packet));
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet.extend_from_slice(piece);
            packet
        })
        .collect()
}

/// A parsed IPv4 header and its payload.
struct Header<'a> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    ttl: u8,
    more: bool,
    /// Byte offset of `body` in the datagram.
    offset: usize,
    body: &'a [u8],
}

fn header(packet: &[u8]) -> Option<Header<'_>> {
    let &first = packet.first()?;
    let header_len = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || header_len < 20 || packet.len() < header_len || packet[9] != UDP {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total < header_len || total > packet.len() {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    Some(Header {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        id: u16::from_be_bytes([packet[4], packet[5]]),
        ttl: packet[8],
        more: fragment & 0x2000 != 0,
        offset: usize::from(fragment & 0x1fff) * 8,
        body: &packet[header_len..total],
    })
}

/// Source port, destination port and payload of a whole UDP datagram.
fn datagram(udp: &[u8]) -> Option<(u16, u16, &[u8])> {
    if udp.len() < 8 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if length < 8 || length > udp.len() {
        return None;
    }
    Some((u16::from_be_bytes([udp[0], udp[1]]), u16::from_be_bytes([udp[2], udp[3]]), &udp[8..length]))
}

impl Forward {
    /// `me` is this node's tunnel address; tunnel packets are at most `mtu` bytes.
    pub fn new(me: Ipv4Addr, tunnel: Cidr, mtu: usize, rules: Vec<Rule>, lan_interfaces: Vec<String>) -> Self {
        let mut forward = Self { me, tunnel, mtu, slots: Vec::new(), counters: HashMap::new(), lan_interfaces, seen: HashMap::new(), partials: HashMap::new(), next_id: 0, lan: Vec::new(), lans: Vec::new() };
        forward.set_rules(rules);
        forward
    }

    /// Replaces the rules. Counters are kept for rules with the same name.
    pub fn set_rules(&mut self, rules: Vec<Rule>) {
        self.counters.retain(|name, _| rules.iter().any(|rule| &rule.name == name));
        self.lan.retain(|state| rules.iter().any(|rule| rule.name == state.rule));
        self.slots = rules.into_iter().map(|rule| Slot { bucket: Limiter::new(rule.rate, rule.burst), rule }).collect();
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.slots.iter().map(|slot| slot.rule.clone()).collect()
    }

    pub fn set_lan_interfaces(&mut self, interfaces: Vec<String>) {
        self.lan_interfaces = interfaces;
    }

    fn interfaces<'a>(&'a self, rule: &'a Rule) -> &'a [String] {
        if rule.interfaces.is_empty() { &self.lan_interfaces } else { &rule.interfaces }
    }

    fn counters(&mut self, rule: &str) -> &mut Counters {
        self.counters.entry(rule.to_owned()).or_default()
    }

    /// Interfaces to listen on: those of rules that forward LAN to mesh.
    pub fn listen_interfaces(&self) -> Vec<String> {
        let mut out: Vec<String> = self.slots.iter().filter(|slot| slot.rule.enabled && slot.rule.direction.to_mesh()).flat_map(|slot| self.interfaces(&slot.rule).iter().cloned()).collect();
        out.sort();
        out.dedup();
        out
    }

    /// Sets the client networks and their mesh prefixes.
    pub fn set_lans(&mut self, lans: Vec<Lan>) {
        self.lans = lans;
    }

    /// The broadcast address of the client network served on `interface`.
    pub fn broadcast_of(&self, interface: &str) -> Option<Ipv4Addr> {
        self.lans.iter().find(|lan| lan.interface == interface && lan.subnet.prefix_len() <= 30).map(|lan| lan.subnet.broadcast())
    }

    /// A LAN sender's address as seen on the mesh, if it has one.
    fn routed(&self, interface: &str, address: Ipv4Addr) -> Option<Ipv4Addr> {
        let lan = self.lans.iter().find(|lan| lan.interface == interface && lan.subnet.contains(address))?;
        Some(lan.mapped.host(u32::from(address) - u32::from(lan.subnet.network())))
    }

    /// Active rules and the interfaces each serves.
    pub fn served(&self) -> Vec<(Rule, Vec<String>)> {
        self.slots.iter().filter(|slot| slot.rule.enabled).map(|slot| (slot.rule.clone(), self.interfaces(&slot.rule).to_vec())).collect()
    }

    /// Interfaces to send on.
    pub fn emit_interfaces(&self) -> Vec<String> {
        let mut out: Vec<String> = self.slots.iter().filter(|slot| slot.rule.enabled && slot.rule.direction.from_mesh()).flat_map(|slot| self.interfaces(&slot.rule).iter().cloned()).collect();
        out.sort();
        out.dedup();
        out
    }

    /// Whether a rule carries group `dst` in that direction. Such a group is flooded even if
    /// it counts as chatter ([`crate::flood::is_chatter`]).
    pub fn carries(&self, dst: Ipv4Addr, to_mesh: bool) -> bool {
        self.slots.iter().any(|slot| slot.rule.enabled && slot.rule.address == single(dst) && if to_mesh { slot.rule.direction.to_mesh() } else { slot.rule.direction.from_mesh() })
    }

    /// The first matching rule decides: it carries the datagram in this direction, or nothing does.
    fn rule_for(&self, interface: Option<&str>, broadcast: bool, dst: Ipv4Addr, port: u16, to_mesh: bool) -> Option<usize> {
        let index = self.slots.iter().position(|slot| slot.rule.names(broadcast, dst, port) && interface.is_none_or(|interface| self.interfaces(&slot.rule).iter().any(|name| name == interface)))?;
        let direction = self.slots[index].rule.direction;
        (if to_mesh { direction.to_mesh() } else { direction.from_mesh() }).then_some(index)
    }

    fn key(broadcast: bool, address: Ipv4Addr, port: u16, payload: &[u8]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (broadcast, if broadcast { Ipv4Addr::BROADCAST } else { address }, port, payload).hash(&mut hasher);
        hasher.finish()
    }

    /// Whether the datagram was seen within `window`. If not and `remember`, records it.
    fn seen(&mut self, key: u64, window: Duration, now: Instant, remember: bool) -> bool {
        if self.seen.get(&key).is_some_and(|at| now.saturating_duration_since(*at) < window) {
            return true;
        }
        if remember {
            if self.seen.len() >= MAX_SEEN {
                let longest = Duration::from_secs(u64::from(MAX_DEDUP_SECS));
                self.seen.retain(|_, at| now.saturating_duration_since(*at) < longest);
            }
            if self.seen.len() >= MAX_SEEN
                && let Some(oldest) = self.seen.iter().min_by_key(|(_, at)| **at).map(|(key, _)| *key)
            {
                self.seen.remove(&oldest);
            }
            self.seen.insert(key, now);
        }
        false
    }

    /// A datagram heard on `interface` from `src` to `dst:port`. Returns tunnel packets if a
    /// rule carries it.
    pub fn from_lan(&mut self, interface: &str, src: SocketAddrV4, dst: Ipv4Addr, port: u16, payload: &[u8], now: Instant) -> Option<Outgoing> {
        let broadcast = !dst.is_multicast();
        let index = self.rule_for(Some(interface), broadcast, dst, port, true)?;
        let (name, max_bytes, window, keep_source) = {
            let rule = &self.slots[index].rule;
            (rule.name.clone(), rule.max_bytes, Duration::from_secs(u64::from(rule.dedup_secs)), rule.keep_source)
        };
        if payload.len() > max_bytes {
            self.counters(&name).too_large += 1;
            return None;
        }
        let key = Self::key(broadcast, dst, port, payload);
        if self.seen(key, window, now, false) {
            self.counters(&name).duplicates += 1;
            return None;
        }
        // A subnet broadcast becomes the tunnel's broadcast address.
        let to = if dst.is_multicast() || dst.is_broadcast() { dst } else { self.tunnel.broadcast() };
        if !self.slots[index].bucket.allow(&(*src.ip(), to, port), now) {
            self.counters(&name).rate_limited += 1;
            return None;
        }
        self.seen(key, window, now, true);
        self.next_id = self.next_id.wrapping_add(1);
        let from = keep_source.then(|| self.routed(interface, *src.ip())).flatten().unwrap_or(self.me);
        let packets = packets(SocketAddrV4::new(from, src.port()), SocketAddrV4::new(to, port), payload, self.next_id, TUNNEL_TTL, self.mtu);
        Some(Outgoing { rule: name, bytes: payload.len(), packets })
    }

    /// An IPv4 packet captured on `interface` in a multicast or broadcast frame. `networks`
    /// are the interface's connected networks. Fragments are reassembled first. Returns tunnel
    /// packets if a rule carries it.
    pub fn from_lan_packet(&mut self, interface: &str, link_broadcast: bool, packet: &[u8], networks: &[Cidr], local: &[Ipv4Addr], now: Instant) -> Option<Outgoing> {
        let header = header(packet)?;
        let broadcast = !header.dst.is_multicast();
        if broadcast && !(link_broadcast && (header.dst.is_broadcast() || networks.iter().any(|network| network.prefix_len() <= 30 && network.broadcast() == header.dst))) {
            return None;
        }
        // Skip reassembly if no rule could match.
        if !self.slots.iter().any(|slot| slot.rule.enabled && slot.rule.direction.to_mesh() && slot.rule.is_broadcast() == broadcast && (broadcast || slot.rule.address.contains(header.dst))) {
            return None;
        }
        let whole: Vec<u8>;
        let udp = if header.more || header.offset != 0 {
            whole = self.reassemble(&header, now)?.0;
            whole.as_slice()
        } else {
            header.body
        };
        let (source_port, port, payload) = datagram(udp)?;
        let index = self.rule_for(Some(interface), broadcast, header.dst, port, true)?;
        let name = self.slots[index].rule.name.clone();
        if local.contains(&header.src) {
            self.counters(&name).looped += 1;
            return None;
        }
        // Only from the interface's own networks. This drops what another node sent here for a
        // sender behind it, and spoofed addresses.
        if !networks.iter().any(|network| network.contains(header.src)) {
            self.counters(&name).foreign_source += 1;
            return None;
        }
        self.from_lan(interface, SocketAddrV4::new(header.src, source_port), header.dst, port, payload, now)
    }

    /// Records whether the VPN sent an [`Outgoing`] or refused it.
    pub fn sent(&mut self, outgoing: &Outgoing, sent: bool) {
        let bytes = outgoing.bytes as u64;
        let counters = self.counters(&outgoing.rule);
        if sent {
            counters.to_mesh_packets += 1;
            counters.to_mesh_bytes += bytes;
            counters.last_to_mesh_ms = Some(crate::service::now_ms());
        } else {
            counters.not_sent += 1;
        }
    }

    /// Counts a datagram the LAN side dropped, under the matching rule.
    pub fn refused(&mut self, rule: &str, why: Refused) {
        if !self.slots.iter().any(|slot| slot.rule.name == rule) {
            return;
        }
        let counters = self.counters(rule);
        match why {
            Refused::Looped => counters.looped += 1,
            Refused::ForeignSource => counters.foreign_source += 1,
        }
    }

    pub fn emit_failed(&mut self, rule: &str) {
        if self.slots.iter().any(|slot| slot.rule.name == rule) {
            self.counters(rule).emit_errors += 1;
        }
    }

    /// Adds a fragment. Returns the datagram when complete.
    fn reassemble(&mut self, header: &Header, now: Instant) -> Option<(Vec<u8>, u8)> {
        self.partials.retain(|_, partial| now.saturating_duration_since(partial.started) < PARTIAL_TIMEOUT);
        let key = (header.src, header.dst, header.id);
        let end = header.offset + header.body.len();
        if end > 8 + MAX_BYTES || header.body.is_empty() {
            self.partials.remove(&key);
            return None;
        }
        if !self.partials.contains_key(&key) && self.partials.len() >= MAX_PARTIALS {
            let oldest = self.partials.iter().min_by_key(|(_, partial)| partial.started).map(|(key, _)| *key)?;
            self.partials.remove(&oldest);
        }
        let partial = self.partials.entry(key).or_insert_with(|| Partial { started: now, data: Vec::new(), have: Vec::new(), total: None, ttl: header.ttl });
        if partial.data.len() < end {
            partial.data.resize(end, 0);
        }
        partial.data[header.offset..end].copy_from_slice(header.body);
        partial.have.push((header.offset, end));
        partial.ttl = partial.ttl.min(header.ttl);
        if !header.more {
            partial.total = Some(end);
        }
        let total = partial.total?;
        partial.have.sort_unstable();
        let mut covered = 0;
        for &(from, to) in &partial.have {
            if from > covered {
                return None;
            }
            covered = covered.max(to);
        }
        if covered < total {
            return None;
        }
        let partial = self.partials.remove(&key)?;
        let mut data = partial.data;
        data.truncate(total);
        Some((data, partial.ttl))
    }

    /// A flooded packet from a peer, already accepted by the VPN. Returns what to send on the
    /// LAN if a rule carries it.
    pub fn from_mesh(&mut self, packet: &[u8], now: Instant) -> Option<Emit> {
        let header = header(packet)?;
        let directed = header.dst == self.tunnel.broadcast();
        let broadcast = header.dst.is_broadcast() || directed;
        if !broadcast && !header.dst.is_multicast() {
            return None;
        }
        let takes = |rule: &Rule| rule.enabled && rule.direction.from_mesh() && if broadcast { rule.is_broadcast() } else { rule.address.contains(header.dst) };
        if !self.slots.iter().any(|slot| takes(&slot.rule)) {
            return None;
        }
        let whole: Vec<u8>;
        let (udp, ttl) = if header.more || header.offset != 0 {
            let (data, ttl) = self.reassemble(&header, now)?;
            whole = data;
            (whole.as_slice(), ttl)
        } else {
            (header.body, header.ttl)
        };
        // TTL 0: drop.
        if ttl == 0 {
            return None;
        }
        let (source_port, port, payload) = datagram(udp)?;
        let rule = self.slots[self.rule_for(None, broadcast, header.dst, port, false)?].rule.clone();
        if payload.len() > rule.max_bytes {
            self.counters(&rule.name).too_large += 1;
            return None;
        }
        let interfaces = self.interfaces(&rule).to_vec();
        if interfaces.is_empty() {
            return None;
        }
        let key = Self::key(broadcast, header.dst, port, payload);
        if self.seen(key, Duration::from_secs(u64::from(rule.dedup_secs)), now, true) {
            self.counters(&rule.name).duplicates += 1;
            return None;
        }
        let counters = self.counters(&rule.name);
        counters.from_mesh_packets += 1;
        counters.from_mesh_bytes += payload.len() as u64;
        counters.last_from_mesh_ms = Some(crate::service::now_ms());
        // Keep the source only if it is a real sender, not a node's tunnel address.
        let source = (rule.keep_source && !self.tunnel.contains(header.src) && !header.src.is_unspecified()).then(|| SocketAddrV4::new(header.src, source_port));
        Some(Emit { rule: rule.name, interfaces, address: if broadcast { Ipv4Addr::BROADCAST } else { header.dst }, directed, port, ttl: rule.ttl, source, payload: payload.to_vec() })
    }

    /// Sets the rules' LAN state, from the LAN side.
    pub fn set_lan(&mut self, lan: Vec<LanState>) {
        self.lan = lan;
    }

    pub fn status(&self) -> Vec<RuleStatus> {
        self.slots
            .iter()
            .map(|slot| RuleStatus {
                rule: slot.rule.clone(),
                counters: self.counters.get(&slot.rule.name).copied().unwrap_or_default(),
                lan: self.lan.iter().filter(|state| state.rule == slot.rule.name).cloned().collect(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::summarize;

    const SA: Ipv4Addr = Ipv4Addr::new(239, 2, 3, 1);
    const PHONE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 10, 23), 40123);

    fn node(host: u8, rules: Vec<Rule>) -> Forward {
        Forward::new(Ipv4Addr::new(10, 77, 0, host), "10.77.0.0/16".parse().unwrap(), 792, rules, vec!["br0".into()])
    }

    fn atak() -> Vec<Rule> {
        presets().into_iter().find(|preset| preset.id == "atak").unwrap().rules
    }

    #[test]
    fn a_lan_datagram_becomes_a_tunnel_packet_and_comes_out_on_the_far_lan() {
        let (mut a, mut b) = (node(1, atak()), node(2, atak()));
        let now = Instant::now();
        let out = a.from_lan("br0", PHONE, SA, 6969, b"<event/>", now).expect("the rule carries it");
        assert_eq!((out.rule.as_str(), out.bytes, out.packets.len()), ("atak-sa", 8, 1));
        let summary = summarize(&out.packets[0]).unwrap();
        assert_eq!((summary.src, summary.dst, summary.proto, summary.ports), (Ipv4Addr::new(10, 77, 0, 1), SA, UDP, Some((40123, 6969))));
        assert_eq!(out.packets[0][8], TUNNEL_TTL);
        // Both checksums hold: summed with themselves they give zero.
        assert_eq!(fold(sum(0, &out.packets[0][..20])), 0);
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&[10, 77, 0, 1]);
        pseudo[4..8].copy_from_slice(&SA.octets());
        pseudo[9] = UDP;
        pseudo[11] = 16;
        assert_eq!(fold(sum(sum(0, &pseudo), &out.packets[0][20..])), 0);

        let emit = b.from_mesh(&out.packets[0], now).expect("the far rule takes it");
        assert_eq!(emit, Emit { rule: "atak-sa".into(), interfaces: vec!["br0".into()], address: SA, directed: false, port: 6969, ttl: 1, source: None, payload: b"<event/>".to_vec() });
        a.sent(&out, true);
        assert_eq!((a.status()[0].counters.to_mesh_packets, a.status()[0].counters.to_mesh_bytes), (1, 8));
        assert_eq!((b.status()[0].counters.from_mesh_packets, b.status()[0].counters.from_mesh_bytes), (1, 8));
    }

    #[test]
    fn nothing_is_forwarded_without_a_rule_for_it() {
        let mut a = node(1, atak());
        let now = Instant::now();
        assert!(a.from_lan("br0", PHONE, SA, 6970, b"x", now).is_none(), "another port");
        assert!(a.from_lan("br0", PHONE, Ipv4Addr::new(239, 2, 3, 2), 6969, b"x", now).is_none(), "another group");
        assert!(a.from_lan("wlan0", PHONE, SA, 6969, b"x", now).is_none(), "another interface");
        assert!(a.from_lan("br0", PHONE, Ipv4Addr::BROADCAST, 6969, b"x", now).is_none(), "broadcast is not the group");
        assert!(node(1, Vec::new()).from_lan("br0", PHONE, SA, 6969, b"x", now).is_none());
        let off = Rule { enabled: false, ..atak().remove(0) };
        assert!(node(1, vec![off]).from_lan("br0", PHONE, SA, 6969, b"x", now).is_none());

        // The mesh side: a node with no rule, or a one-way one, emits nothing.
        let out = a.from_lan("br0", PHONE, SA, 6969, b"x", now).unwrap();
        assert!(node(2, Vec::new()).from_mesh(&out.packets[0], now).is_none());
        let to_mesh_only = Rule { direction: Direction::ToMesh, ..atak().remove(0) };
        assert!(node(2, vec![to_mesh_only]).from_mesh(&out.packets[0], now).is_none());
        let from_mesh_only = Rule { direction: Direction::FromMesh, ..atak().remove(0) };
        let mut listener = node(2, vec![from_mesh_only]);
        assert!(listener.from_mesh(&out.packets[0], now).is_some());
        assert!(listener.from_lan("br0", PHONE, SA, 6969, b"y", now).is_none(), "from_mesh only: the LAN's own stay local");
        assert!(listener.listen_interfaces().is_empty());
    }

    #[test]
    fn what_was_emitted_or_already_forwarded_is_not_forwarded_again() {
        let (mut a, mut b) = (node(1, atak()), node(2, atak()));
        let now = Instant::now();
        let out = a.from_lan("br0", PHONE, SA, 6969, b"position", now).unwrap();
        assert!(b.from_mesh(&out.packets[0], now).is_some());
        // b's emission comes back on its LAN.
        let echoed = SocketAddrV4::new(Ipv4Addr::new(192, 168, 10, 1), 51000);
        assert!(b.from_lan("br0", echoed, SA, 6969, b"position", now + Duration::from_millis(50)).is_none());
        // Two nodes on the sender's LAN both forwarded it: the second copy is dropped.
        let mut twin = node(3, atak());
        let copy = twin.from_lan("br0", PHONE, SA, 6969, b"position", now).unwrap();
        assert!(b.from_mesh(&copy.packets[0], now + Duration::from_millis(80)).is_none());
        // The twin's copy reaching a, which heard the datagram itself, is not emitted.
        assert!(a.from_mesh(&copy.packets[0], now + Duration::from_millis(80)).is_none());
        assert_eq!(b.status()[0].counters.duplicates, 2);
        assert_eq!(a.status()[0].counters.duplicates, 1);
        // The app repeats later: carried again.
        let later = now + Duration::from_secs(6);
        let again = a.from_lan("br0", PHONE, SA, 6969, b"position", later).expect("past the dedup window");
        assert!(b.from_mesh(&again.packets[0], later).is_some());
        // Other content is never a duplicate.
        assert!(a.from_lan("br0", PHONE, SA, 6969, b"position 2", later).is_some());
    }

    #[test]
    fn a_tunnel_packet_out_of_hops_is_dropped() {
        let (mut a, mut b) = (node(1, atak()), node(2, atak()));
        let now = Instant::now();
        let mut packet = a.from_lan("br0", PHONE, SA, 6969, b"x", now).unwrap().packets.remove(0);
        packet[8] = 0;
        assert!(b.from_mesh(&packet, now).is_none());
        packet[8] = 1;
        assert!(b.from_mesh(&packet, now).is_some());
    }

    #[test]
    fn a_rule_has_its_own_rate_and_duplicates_do_not_spend_it() {
        let rule = Rule { rate: 2, burst: 4, ..Rule::new("chatty", SA, 6969) };
        let mut a = node(1, vec![rule, Rule::new("other", Ipv4Addr::new(239, 9, 9, 9), 7000)]);
        let start = Instant::now();
        let sent = (0..20u8).filter(|n| a.from_lan("br0", PHONE, SA, 6969, &[*n], start).is_some()).count();
        assert_eq!(sent, 4, "the burst, then nothing");
        assert!(a.from_lan("br0", PHONE, Ipv4Addr::new(239, 9, 9, 9), 7000, b"x", start).is_some(), "rules are limited separately");
        // A duplicate is counted and takes no token.
        assert!(a.from_lan("br0", PHONE, SA, 6969, &[0], start).is_none());
        let later = start + Duration::from_secs(1);
        let sent = (100..120u8).filter(|n| a.from_lan("br0", PHONE, SA, 6969, &[*n], later).is_some()).count();
        assert_eq!(sent, 2, "two a second");
        let counters = a.status()[0].counters;
        assert_eq!((counters.rate_limited, counters.duplicates), (16 + 18, 1));
        // A rate-limited datagram is not remembered, so it can go later.
        assert!(a.from_lan("br0", PHONE, SA, 6969, &[19], start + Duration::from_secs(3)).is_some());
    }

    #[test]
    fn a_large_datagram_travels_as_fragments_in_any_order() {
        let rule = Rule { max_bytes: 2048, ..Rule::new("big", SA, 6969) };
        let (mut a, mut b) = (node(1, vec![rule.clone()]), node(2, vec![rule]));
        let now = Instant::now();
        let payload: Vec<u8> = (0..1800u32).map(|n| (n % 251) as u8).collect();
        let out = a.from_lan("br0", PHONE, SA, 6969, &payload, now).unwrap();
        assert_eq!(out.packets.len(), 3);
        assert!(out.packets.iter().all(|packet| packet.len() <= 792 && summarize(packet).is_some()));
        assert_eq!(summarize(&out.packets[1]).unwrap().ports, None, "a later fragment");
        assert!(b.from_mesh(&out.packets[2], now).is_none());
        assert!(b.from_mesh(&out.packets[0], now).is_none());
        assert!(b.from_mesh(&out.packets[0], now).is_none(), "a repeated fragment does not complete it");
        let emit = b.from_mesh(&out.packets[1], now).expect("whole");
        assert_eq!((emit.port, emit.payload), (6969, payload.clone()));
        assert!(b.partials.is_empty());

        // An incomplete datagram times out and is not completed by a later one's fragments.
        let other: Vec<u8> = payload.iter().map(|byte| byte ^ 0xff).collect();
        let lost = a.from_lan("br0", PHONE, SA, 6969, &other, now).unwrap();
        assert!(b.from_mesh(&lost.packets[0], now).is_none());
        let late = now + PARTIAL_TIMEOUT + Duration::from_secs(1);
        assert!(b.from_mesh(&lost.packets[2], late).is_none());
        assert!(b.from_mesh(&lost.packets[1], late).is_none());
        assert_eq!(b.partials.len(), 1);

        // Over the rule's size: dropped and counted on the LAN side, never sent.
        let mut small = node(1, atak());
        assert!(small.from_lan("br0", PHONE, SA, 6969, &payload, now).is_none());
        assert_eq!(small.status()[0].counters.too_large, 1);
        // Fragments for a group nobody here takes are not kept.
        let mut deaf = node(3, Vec::new());
        assert!(deaf.from_mesh(&out.packets[0], now).is_none());
        assert!(deaf.partials.is_empty());
    }

    #[test]
    fn fragments_cannot_grow_memory() {
        let rule = Rule { max_bytes: 2048, ..Rule::new("big", SA, 6969) };
        let mut b = node(2, vec![rule]);
        let now = Instant::now();
        for id in 0..200u16 {
            let first = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 1), SocketAddrV4::new(SA, 6969), &[0u8; 1500], id, 1, 792).remove(0);
            assert!(b.from_mesh(&first, now).is_none());
        }
        assert!(b.partials.len() <= MAX_PARTIALS);
        // A fragment beyond the max datagram size is refused.
        let mut far = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 1), SocketAddrV4::new(SA, 6969), &[0u8; 1500], 999, 1, 792).remove(1);
        far[6..8].copy_from_slice(&(0x2000u16 | 0x1fff).to_be_bytes());
        assert!(b.from_mesh(&far, now).is_none());
        assert!(!b.partials.contains_key(&(Ipv4Addr::new(10, 77, 0, 1), SA, 999)));
        for n in 0..5000u32 {
            b.seen(u64::from(n), Duration::from_secs(5), now, true);
        }
        assert!(b.seen.len() <= MAX_SEEN);
    }

    #[test]
    fn broadcast_is_carried_as_limited_broadcast_and_matched_by_port() {
        let rule = Rule::new("lan-discovery", Ipv4Addr::BROADCAST, 4000);
        let (mut a, mut b) = (node(1, vec![rule.clone()]), node(2, vec![rule]));
        let now = Instant::now();
        // The subnet's own broadcast address on the LAN.
        let out = a.from_lan("br0", PHONE, Ipv4Addr::new(192, 168, 10, 255), 4000, b"hello", now).unwrap();
        assert_eq!(summarize(&out.packets[0]).unwrap().dst, Ipv4Addr::new(10, 77, 255, 255), "a subnet broadcast travels as the tunnel network's");
        let emit = b.from_mesh(&out.packets[0], now).unwrap();
        assert_eq!((emit.address, emit.port), (Ipv4Addr::BROADCAST, 4000));
        // The tunnel broadcast matches too; another port does not.
        let tunnel = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 9), SocketAddrV4::new(Ipv4Addr::new(10, 77, 255, 255), 4000), b"other", 7, 1, 792).remove(0);
        assert!(b.from_mesh(&tunnel, now).is_some());
        let elsewhere = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 9), SocketAddrV4::new(Ipv4Addr::BROADCAST, 4001), b"other", 8, 1, 792).remove(0);
        assert!(b.from_mesh(&elsewhere, now).is_none());
        // Unicast is never ours.
        let unicast = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 9), SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 4000), b"other", 9, 1, 792).remove(0);
        assert!(b.from_mesh(&unicast, now).is_none());
    }

    #[test]
    fn rules_are_checked_and_listeners_follow_them() {
        assert_eq!(validate(&atak()), Ok(()));
        let base = || Rule::new("r", SA, 6969);
        let field = |rule: Rule| validate(&[rule]).unwrap_err().field;
        assert_eq!(field(Rule { name: String::new(), ..base() }), "name");
        assert_eq!(field(Rule { address: single(Ipv4Addr::new(192, 168, 10, 255)), ..base() }), "address");
        assert_eq!(field(Rule { address: "128.0.0.0/1".parse().unwrap(), ..base() }), "address");
        assert_eq!(field(Rule { address: "255.255.255.0/24".parse().unwrap(), ..base() }), "address");
        assert_eq!(validate(&defaults()), Ok(()));
        assert_eq!(field(Rule { ports: (0, 0), ..base() }), "port");
        assert_eq!(field(Rule { ports: (7000, 6999), ..base() }), "port");
        assert_eq!(field(Rule { ports: (67, 68), ..Rule::new("dhcp", Ipv4Addr::BROADCAST, 67) }), "port");
        assert_eq!(field(Rule { interfaces: vec!["br0; reboot".into()], ..base() }), "interfaces");
        assert_eq!(field(Rule { rate: 0, ..base() }), "rate");
        assert_eq!(field(Rule { rate: MAX_RATE + 1, ..base() }), "rate");
        assert_eq!(field(Rule { burst: 0, ..base() }), "burst");
        assert_eq!(field(Rule { max_bytes: MAX_BYTES + 1, ..base() }), "max_bytes");
        assert_eq!(field(Rule { dedup_secs: 0, ..base() }), "dedup_secs");
        assert_eq!(field(Rule { ttl: 0, ..base() }), "ttl");
        assert_eq!(validate(&[base(), base()]).unwrap_err(), Invalid { rule: 1, field: "name", message: "Another rule has this name.".into() });
        assert_eq!(validate(&vec![base(); MAX_RULES + 1]).unwrap_err().field, "rules");

        let range = Rule { ports: (7000, 7002), interfaces: vec!["usb0".into(), "br0".into()], ..Rule::new("range", Ipv4Addr::BROADCAST, 7000) };
        let mut forward = node(1, vec![base(), range, Rule { direction: Direction::FromMesh, interfaces: vec!["eth1".into()], ..Rule::new("in", SA, 7100) }]);
        assert_eq!(forward.listen_interfaces(), vec!["br0".to_owned(), "usb0".to_owned()]);
        assert_eq!(forward.emit_interfaces(), vec!["br0".to_owned(), "eth1".to_owned(), "usb0".to_owned()]);
        assert!(forward.carries(SA, true) && forward.carries(SA, false) && !forward.carries(Ipv4Addr::new(224, 0, 0, 251), true));

        // Counters survive a change of the rules for the rules that stay.
        forward.from_lan("br0", PHONE, SA, 6969, &[0u8; 2000], Instant::now());
        forward.refused("r", Refused::Looped);
        forward.refused("gone", Refused::Looped);
        forward.set_rules(vec![Rule { rate: 9, ..base() }]);
        assert_eq!((forward.status()[0].counters.too_large, forward.status()[0].counters.looped), (1, 1));
        forward.set_rules(Vec::new());
        assert!(forward.status().is_empty() && forward.counters.is_empty());
    }

    const LAN: &str = "10.78.7.0/24";
    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 78, 7, 23), 40123);

    #[test]
    fn out_of_the_box_any_group_and_any_broadcast_cross_but_not_the_lans_chatter() {
        let (mut a, mut b) = (node(1, defaults()), node(2, defaults()));
        let now = Instant::now();
        // Any application's group and port, ATAK's among them.
        for (group, port) in [(SA, 6969), (Ipv4Addr::new(224, 10, 10, 1), 17012), (Ipv4Addr::new(239, 77, 1, 9), 41000), (Ipv4Addr::new(225, 1, 2, 3), 5)] {
            let out = a.from_lan("br0", PHONE, group, port, b"hello", now).unwrap_or_else(|| panic!("{group}:{port} is carried"));
            let emit = b.from_mesh(&out.packets[0], now).expect("and comes out");
            assert_eq!((emit.rule.as_str(), emit.address, emit.port), ("multicast", group, port));
        }
        let out = a.from_lan("br0", PHONE, Ipv4Addr::new(192, 168, 10, 255), 30303, b"who", now).expect("a subnet's broadcast");
        assert_eq!(summarize(&out.packets[0]).unwrap().dst, Ipv4Addr::new(10, 77, 255, 255), "as the tunnel's own broadcast");
        let emit = b.from_mesh(&out.packets[0], now).unwrap();
        assert_eq!((emit.rule.as_str(), emit.address, emit.directed, emit.port), ("broadcast", Ipv4Addr::BROADCAST, true, 30303));
        let out = a.from_lan("br0", PHONE, Ipv4Addr::BROADCAST, 30303, b"who else", now).expect("the limited broadcast");
        assert!(!b.from_mesh(&out.packets[0], now).unwrap().directed);

        // Not the control chatter of a LAN, and never DHCP.
        for (dst, port) in [(Ipv4Addr::new(224, 0, 0, 251), 5353), (Ipv4Addr::new(224, 0, 0, 252), 5355), (Ipv4Addr::new(224, 0, 0, 1), 9), (SSDP, 1900), (Ipv4Addr::BROADCAST, 67), (Ipv4Addr::BROADCAST, 68), (Ipv4Addr::BROADCAST, 137), (Ipv4Addr::new(192, 168, 10, 255), 138)] {
            assert!(a.from_lan("br0", PHONE, dst, port, b"chatter", now).is_none(), "{dst}:{port}");
            let packet = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 9), SocketAddrV4::new(dst, port), b"chatter in", 3, 1, 792).remove(0);
            assert!(b.from_mesh(&packet, now).is_none(), "{dst}:{port} from the mesh");
        }
        assert!(!a.carries(Ipv4Addr::new(224, 0, 0, 251), true), "a wide rule does not open the VPN's chatter filter");
        // A rule written for one of them carries it, before the wide one.
        let mut named = node(1, [vec![Rule::new("mdns", Ipv4Addr::new(224, 0, 0, 251), 5353)], defaults()].concat());
        assert_eq!(named.from_lan("br0", PHONE, Ipv4Addr::new(224, 0, 0, 251), 5353, b"q", now).unwrap().rule, "mdns");
        // Never DHCP, even with a rule covering its ports.
        let mut wide = node(1, vec![Rule { ports: (60, 70), ..Rule::new("low", Ipv4Addr::BROADCAST, 60) }]);
        assert!(wide.from_lan("br0", PHONE, Ipv4Addr::BROADCAST, 67, b"discover", now).is_none());
        assert!(wide.from_lan("br0", PHONE, Ipv4Addr::BROADCAST, 69, b"tftp", now).is_some());
    }

    #[test]
    fn the_first_rule_naming_a_datagram_decides() {
        let noisy = Ipv4Addr::new(239, 9, 9, 9);
        let block = Rule { direction: Direction::Block, ..Rule::range("no-video", "239.9.0.0/16".parse().unwrap()) };
        let mut a = node(1, [vec![block], defaults()].concat());
        let now = Instant::now();
        assert!(a.from_lan("br0", PHONE, noisy, 5004, b"frame", now).is_none(), "blocked before the wide rule");
        assert!(a.from_lan("br0", PHONE, SA, 6969, b"sa", now).is_some());
        let packet = packets(SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 9), SocketAddrV4::new(noisy, 5004), b"frame in", 3, 1, 792).remove(0);
        assert!(a.from_mesh(&packet, now).is_none());
        assert!(a.listen_interfaces() == vec!["br0".to_owned()] && a.emit_interfaces() == vec!["br0".to_owned()]);
        // A narrow rule for one app; the wide rule for the rest.
        let mut b = node(2, [vec![Rule { rate: 1, burst: 1, ..Rule::new("sa", SA, 6969) }], defaults()].concat());
        assert_eq!((0..5).filter(|n| b.from_lan("br0", PHONE, SA, 6969, &[*n], now).is_some()).count(), 1);
        assert_eq!((b.status()[0].counters.rate_limited, b.status()[1].counters.rate_limited), (4, 0));
    }

    #[test]
    fn the_budget_is_per_sender_and_destination() {
        let mut a = node(1, defaults());
        let now = Instant::now();
        let other = SocketAddrV4::new(Ipv4Addr::new(192, 168, 10, 24), 40123);
        let passed = |a: &mut Forward, src: SocketAddrV4, group: Ipv4Addr, tag: u8| (0..30u8).filter(|n| a.from_lan("br0", src, group, 6969, &[tag, *n], now).is_some()).count();
        assert_eq!(passed(&mut a, PHONE, SA, 0), 10, "the burst");
        assert_eq!(passed(&mut a, PHONE, SA, 1), 0, "one sender's chatter to one group stops there");
        assert_eq!(passed(&mut a, other, SA, 2), 10, "another phone is not starved by it");
        assert_eq!(passed(&mut a, PHONE, Ipv4Addr::new(239, 5, 5, 5), 3), 10, "nor another application");
        // 2 a second after that.
        assert_eq!((0..30u8).filter(|n| a.from_lan("br0", PHONE, SA, 6969, &[9, *n], now + Duration::from_secs(2)).is_some()).count(), 4);
    }

    #[test]
    fn a_routed_sender_keeps_its_address_across_the_mesh() {
        let (mut a, mut b) = (node(1, defaults()), node(2, defaults()));
        a.set_lans(vec![Lan { interface: "br0".into(), subnet: LAN.parse().unwrap(), mapped: LAN.parse().unwrap() }]);
        b.set_lans(vec![Lan { interface: "br0".into(), subnet: "10.78.9.0/24".parse().unwrap(), mapped: "10.78.9.0/24".parse().unwrap() }]);
        let now = Instant::now();
        let out = a.from_lan("br0", CLIENT, SA, 6969, b"<event/>", now).unwrap();
        assert_eq!(summarize(&out.packets[0]).unwrap().src, *CLIENT.ip());
        let emit = b.from_mesh(&out.packets[0], now).unwrap();
        assert_eq!(emit.source, Some(CLIENT), "re-emitted as the phone sent it");
        assert_eq!(b.broadcast_of("br0"), Some(Ipv4Addr::new(10, 78, 9, 255)));
        // A sender on a mapped network appears under its mapped address. Otherwise (or if the
        // rule doesn't keep sources) it appears as the node.
        let mut mapped = node(3, defaults());
        mapped.set_lans(vec![Lan { interface: "br0".into(), subnet: "192.168.10.0/24".parse().unwrap(), mapped: "10.78.40.0/24".parse().unwrap() }]);
        let out = mapped.from_lan("br0", PHONE, SA, 6969, b"mapped", now).unwrap();
        assert_eq!(summarize(&out.packets[0]).unwrap().src, Ipv4Addr::new(10, 78, 40, 23));
        let out = node(4, defaults()).from_lan("br0", PHONE, SA, 6969, b"unshared", now).unwrap();
        assert_eq!(summarize(&out.packets[0]).unwrap().src, Ipv4Addr::new(10, 77, 0, 4));
        assert_eq!(b.from_mesh(&out.packets[0], now).unwrap().source, None, "a tunnel address is nobody's phone");
        let plain: Vec<Rule> = defaults().into_iter().map(|rule| Rule { keep_source: false, ..rule }).collect();
        let (mut c, mut d) = (node(5, plain.clone()), node(6, plain));
        c.set_lans(vec![Lan { interface: "br0".into(), subnet: LAN.parse().unwrap(), mapped: LAN.parse().unwrap() }]);
        let out = c.from_lan("br0", CLIENT, SA, 6969, b"plain", now).unwrap();
        assert_eq!(summarize(&out.packets[0]).unwrap().src, Ipv4Addr::new(10, 77, 0, 5));
        let routed = a.from_lan("br0", CLIENT, SA, 6969, b"routed to plain", now).unwrap();
        assert_eq!(d.from_mesh(&routed.packets[0], now).unwrap().source, None);
    }

    #[test]
    fn captured_packets_are_checked_and_put_together() {
        let mut a = node(1, defaults());
        let networks: Vec<Cidr> = vec![LAN.parse().unwrap(), "192.168.10.0/24".parse().unwrap()];
        let local = [Ipv4Addr::new(10, 78, 7, 1), Ipv4Addr::new(192, 168, 10, 1)];
        let now = Instant::now();
        let to = |dst: Ipv4Addr, port: u16, src: SocketAddrV4, payload: &[u8]| packets(src, SocketAddrV4::new(dst, port), payload, 77, 1, 1500);
        let take = |a: &mut Forward, broadcast: bool, packet: &[u8]| a.from_lan_packet("br0", broadcast, packet, &networks, &local, now);
        assert_eq!(take(&mut a, false, &to(SA, 6969, CLIENT, b"sa")[0]).expect("multicast").bytes, 2);
        assert!(take(&mut a, true, &to(Ipv4Addr::new(10, 78, 7, 255), 4000, CLIENT, b"subnet")[0]).is_some());
        assert!(take(&mut a, true, &to(Ipv4Addr::BROADCAST, 4000, CLIENT, b"limited")[0]).is_some());
        // Unicast in a broadcast frame, or to another network's broadcast address: not ours.
        assert!(take(&mut a, true, &to(Ipv4Addr::new(10, 78, 7, 40), 4000, CLIENT, b"unicast")[0]).is_none());
        assert!(take(&mut a, false, &to(Ipv4Addr::new(10, 78, 7, 255), 4000, CLIENT, b"not a broadcast frame")[0]).is_none());
        // TCP, and anything that is not IPv4.
        let mut tcp = to(SA, 6969, CLIENT, b"tcp").remove(0);
        tcp[9] = crate::ip::TCP;
        assert!(take(&mut a, false, &tcp).is_none() && take(&mut a, false, &[0x60; 60]).is_none());
        // Sent here by another node for a client behind it, or sent by us.
        let far = SocketAddrV4::new(Ipv4Addr::new(10, 78, 9, 23), 40123);
        assert!(take(&mut a, false, &to(SA, 6969, far, b"from afar")[0]).is_none());
        assert!(take(&mut a, false, &to(SA, 6969, SocketAddrV4::new(local[0], 50000), b"ours")[0]).is_none());
        let counters = a.status()[0].counters;
        assert_eq!((counters.foreign_source, counters.looped), (1, 1));
        // A fragmented datagram: whole or not at all.
        let large = vec![7u8; 1400];
        let fragments = packets(CLIENT, SocketAddrV4::new(SA, 6969), &large, 78, 1, 1000);
        assert_eq!(fragments.len(), 2);
        assert!(take(&mut a, false, &fragments[1]).is_none());
        let out = take(&mut a, false, &fragments[0]).expect("whole now");
        assert_eq!((out.bytes, out.packets.len()), (1400, 2));
    }
}
