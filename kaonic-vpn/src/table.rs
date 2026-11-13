//! The VPN routing table: each peer's tunnel address and advertised prefixes, learned from
//! the `HELLO` it sends on its link. No I/O.
//!
//! ```text
//! HELLO = "KVH1" | tunnel address[4] | count u8 (≤ 32) | (prefix address[4] | length u8) * count
//! ```
//!
//! Security rules:
//! - A peer's tunnel address comes from its identity ([`tunnel_address`]). A HELLO with any
//!   other address is dropped.
//! - A prefix is refused if it is too short, overlaps the tunnel network, overlaps one of
//!   ours, or overlaps a route the kernel has on another interface. So a peer can never take
//!   over this hub's traffic.
//! - If two peers advertise overlapping prefixes, both are in conflict and unused. A refused
//!   prefix never puts another peer's prefix in conflict.
//!
//! The table is rebuilt when a HELLO changes, not per packet.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

use crate::ip::Cidr;

const HELLO: &[u8; 4] = b"KVH1";
/// Max prefixes per peer (and per HELLO).
pub const MAX_PREFIXES_PER_PEER: usize = 32;
/// Min seconds between changes to a peer's prefixes, so routes don't flap.
pub const CHANGE_COOLDOWN_SECS: i64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub tunnel: Ipv4Addr,
    pub advertised: Vec<Cidr>,
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = HELLO.to_vec();
        out.extend_from_slice(&self.tunnel.octets());
        out.push(self.advertised.len().min(MAX_PREFIXES_PER_PEER) as u8);
        for prefix in self.advertised.iter().take(MAX_PREFIXES_PER_PEER) {
            out.extend_from_slice(&prefix.network().octets());
            out.push(prefix.prefix_len());
        }
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let rest = data.strip_prefix(HELLO)?;
        let (tunnel, rest) = rest.split_first_chunk::<4>()?;
        let (&count, mut rest) = rest.split_first()?;
        if usize::from(count) > MAX_PREFIXES_PER_PEER {
            return None;
        }
        let mut advertised = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (entry, after) = rest.split_first_chunk::<5>()?;
            advertised.push(Cidr::new(Ipv4Addr::new(entry[0], entry[1], entry[2], entry[3]), entry[4])?);
            rest = after;
        }
        rest.is_empty().then_some(Self { tunnel: Ipv4Addr::from(*tunnel), advertised })
    }
}

/// A node's tunnel address, picked by its identity hash. Never the network or broadcast address.
pub fn tunnel_address(network: &Cidr, identity_hex: &str) -> Ipv4Addr {
    let bits = 32 - u32::from(network.prefix_len());
    let hosts = if bits >= 32 { u64::from(u32::MAX) } else { (1u64 << bits).saturating_sub(2).max(1) };
    let value = u32::from_str_radix(identity_hex.get(..8).unwrap_or("0"), 16).unwrap_or(0);
    network.host((u64::from(value) % hosts + 1) as u32)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEntry {
    pub tunnel: Ipv4Addr,
    pub advertised: Vec<Cidr>,
    /// Unix seconds of the last HELLO.
    pub last_seen: i64,
    /// Unix seconds of the last prefix change.
    pub changed_at: i64,
}

/// A remote prefix and whether it is usable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRoute {
    pub prefix: Cidr,
    pub peer: String,
    /// Not used: refused, or overlapping another peer.
    pub conflict: bool,
    /// Why, when `conflict`.
    pub reason: Option<&'static str>,
}

/// What a HELLO did to the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Update {
    /// Prefixes changed: kernel routes need syncing.
    Changed,
    Unchanged,
    /// Changed again within the cooldown; the old prefixes stay for now.
    Throttled,
    /// Wrong tunnel address for this peer; dropped.
    WrongTunnel { claimed: Ipv4Addr, expected: Ipv4Addr },
}

pub struct Table {
    pub me: Ipv4Addr,
    pub local: Vec<Cidr>,
    network: Cidr,
    min_prefix_len: u8,
    max_prefixes: usize,
    /// Kernel routes on other interfaces (no default route).
    system: Vec<Cidr>,
    peers: HashMap<String, PeerEntry>,
    // Rebuilt whenever anything above changes.
    routes: Vec<RemoteRoute>,
    /// Usable prefixes, longest first.
    usable: Vec<(Cidr, String)>,
    /// Tunnel addresses held by exactly one peer.
    tunnels: HashMap<Ipv4Addr, String>,
    /// Destinations this node forwards for peers, as their gateway.
    gateway: Vec<Cidr>,
    /// Gateway peer this node uses, and the destinations sent to it.
    uplink: Option<(String, Vec<Cidr>)>,
}

impl Table {
    pub fn new(me: Ipv4Addr, local: Vec<Cidr>, network: Cidr, min_prefix_len: u8, max_prefixes: usize) -> Self {
        Self { me, local, network, min_prefix_len, max_prefixes, system: Vec::new(), peers: HashMap::new(), routes: Vec::new(), usable: Vec::new(), tunnels: HashMap::new(), gateway: Vec::new(), uplink: None }
    }

    /// Sets our advertised prefixes. Returns whether they changed.
    pub fn set_local(&mut self, mut local: Vec<Cidr>) -> bool {
        local.sort();
        local.dedup();
        let mut current = self.local.clone();
        current.sort();
        if local == current {
            return false;
        }
        self.local = local;
        self.rebuild();
        true
    }

    /// Destinations forwarded for peers as a gateway (empty: not a gateway).
    pub fn set_gateway(&mut self, routes: Vec<Cidr>) {
        self.gateway = routes;
    }

    /// Gateway peer and destinations to send it (None: no uplink).
    pub fn set_uplink(&mut self, uplink: Option<(String, Vec<Cidr>)>) {
        self.uplink = uplink;
    }

    /// Peers advertising anything overlapping `prefix`, refused or not.
    pub fn advertisers_overlapping(&self, prefix: &Cidr) -> Vec<String> {
        let mut peers: Vec<String> = self.peers.iter().filter(|(_, entry)| entry.advertised.iter().any(|theirs| theirs.overlaps(prefix))).map(|(peer, _)| peer.clone()).collect();
        peers.sort();
        peers
    }

    pub fn hello(&self) -> Hello {
        Hello { tunnel: self.me, advertised: self.local.clone() }
    }

    /// Applies a HELLO from `peer` (identity hash, hex).
    pub fn update(&mut self, peer: &str, hello: Hello, now: i64) -> Update {
        let expected = tunnel_address(&self.network, peer);
        if hello.tunnel != expected {
            return Update::WrongTunnel { claimed: hello.tunnel, expected };
        }
        let mut advertised = hello.advertised;
        advertised.truncate(MAX_PREFIXES_PER_PEER);
        advertised.sort();
        advertised.dedup();
        match self.peers.get_mut(peer) {
            Some(entry) if entry.advertised == advertised => {
                entry.last_seen = now;
                Update::Unchanged
            }
            Some(entry) if now - entry.changed_at < CHANGE_COOLDOWN_SECS => {
                entry.last_seen = now;
                Update::Throttled
            }
            _ => {
                self.peers.insert(peer.to_owned(), PeerEntry { tunnel: expected, advertised, last_seen: now, changed_at: now });
                self.rebuild();
                Update::Changed
            }
        }
    }

    pub fn remove(&mut self, peer: &str) {
        if self.peers.remove(peer).is_some() {
            self.rebuild();
        }
    }

    /// Sets the kernel's routes on other interfaces. Returns whether they changed.
    pub fn set_system_routes(&mut self, mut routes: Vec<Cidr>) -> bool {
        routes.retain(|route| route.prefix_len() > 0);
        routes.sort();
        routes.dedup();
        if routes == self.system {
            return false;
        }
        self.system = routes;
        self.rebuild();
        true
    }

    pub fn peer(&self, peer: &str) -> Option<&PeerEntry> {
        self.peers.get(peer)
    }

    pub fn peers(&self) -> impl Iterator<Item = (&String, &PeerEntry)> {
        self.peers.iter()
    }

    /// Why no peer may route `prefix`, if refused.
    fn refusal(&self, prefix: &Cidr) -> Option<&'static str> {
        if prefix.prefix_len() < self.min_prefix_len {
            return Some("too short a prefix");
        }
        if prefix.overlaps(&self.network) {
            return Some("overlaps the tunnel network");
        }
        if self.local.iter().any(|local| local.overlaps(prefix)) {
            return Some("overlaps a prefix of this node");
        }
        if self.system.iter().any(|route| route.overlaps(prefix)) {
            return Some("overlaps a network this node already reaches");
        }
        None
    }

    fn rebuild(&mut self) {
        let mut peers: Vec<&String> = self.peers.keys().collect();
        peers.sort();
        let mut routes: Vec<RemoteRoute> = Vec::new();
        let mut accepted = 0usize;
        for peer in peers {
            for prefix in &self.peers[peer].advertised {
                let mut reason = self.refusal(prefix);
                if reason.is_none() {
                    if accepted >= self.max_prefixes {
                        reason = Some("too many prefixes on the VPN");
                    } else {
                        accepted += 1;
                    }
                }
                routes.push(RemoteRoute { prefix: *prefix, peer: peer.clone(), conflict: reason.is_some(), reason });
            }
        }
        // Overlap between accepted prefixes is a conflict for both (no first-come-wins).
        let candidates: Vec<(usize, Cidr, String)> = routes.iter().enumerate().filter(|(_, route)| !route.conflict).map(|(index, route)| (index, route.prefix, route.peer.clone())).collect();
        for (index, prefix, peer) in &candidates {
            if candidates.iter().any(|(_, other, owner)| owner != peer && other.overlaps(prefix)) {
                routes[*index].conflict = true;
                routes[*index].reason = Some("overlaps a prefix of another node");
            }
        }
        routes.sort_by(|a, b| (a.prefix, &a.peer).cmp(&(b.prefix, &b.peer)));
        let mut usable: Vec<(Cidr, String)> = routes.iter().filter(|route| !route.conflict).map(|route| (route.prefix, route.peer.clone())).collect();
        usable.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.prefix_len()));
        let mut owners: HashMap<Ipv4Addr, Vec<&String>> = HashMap::new();
        for (peer, entry) in &self.peers {
            owners.entry(entry.tunnel).or_default().push(peer);
        }
        self.tunnels = owners.into_iter().filter(|(address, owners)| owners.len() == 1 && *address != self.me).map(|(address, owners)| (address, owners[0].clone())).collect();
        self.routes = routes;
        self.usable = usable;
    }

    /// Every advertised prefix, with refusals and conflicts marked.
    pub fn remote_routes(&self) -> Vec<RemoteRoute> {
        self.routes.clone()
    }

    /// Prefixes to install as kernel routes to the TUN device.
    pub fn installed(&self) -> BTreeSet<Cidr> {
        self.usable.iter().map(|(prefix, _)| *prefix).collect()
    }

    /// The peer a packet for `dst` goes to.
    pub fn route(&self, dst: Ipv4Addr) -> Option<&str> {
        if let Some(peer) = self.tunnels.get(&dst) {
            return Some(peer);
        }
        if self.network.contains(dst) {
            return None;
        }
        if let Some((_, peer)) = self.usable.iter().find(|(prefix, _)| prefix.contains(dst)) {
            return Some(peer);
        }
        // Otherwise, the uplink's destinations go to the gateway.
        self.uplink.as_ref().filter(|(_, routes)| routes.iter().any(|route| route.contains(dst))).map(|(peer, _)| peer.as_str())
    }

    /// Whether `peer` may send packets from `src`: its tunnel address or one of its usable prefixes.
    pub fn allowed_source(&self, peer: &str, src: Ipv4Addr) -> bool {
        if self.tunnels.get(&src).is_some_and(|owner| owner == peer) {
            return true;
        }
        if self.usable.iter().any(|(prefix, owner)| owner == peer && prefix.contains(src)) {
            return true;
        }
        // Replies through our gateway come from internet addresses.
        self.uplink.as_ref().is_some_and(|(gateway, routes)| gateway == peer && !self.network.contains(src) && routes.iter().any(|route| route.contains(src)))
    }

    /// Whether a packet from a peer may enter: it is for us, for a network we advertise, a
    /// flood, or a gateway destination. Otherwise this hub would route anywhere it reaches.
    pub fn accepts_destination(&self, dst: Ipv4Addr) -> bool {
        dst == self.me
            || self.local.iter().any(|local| local.contains(dst))
            || crate::ip::is_flooded(dst, &self.network)
            // As a gateway: offered destinations, never the tunnel network.
            || (!self.network.contains(dst) && self.gateway.iter().any(|route| route.contains(dst)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    const NET: &str = "10.77.0.0/16";
    const B: &str = "00000002bbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "00000003cccccccccccccccccccccccc";

    fn table(local: &[&str]) -> Table {
        Table::new(Ipv4Addr::new(10, 77, 0, 1), local.iter().map(|text| cidr(text)).collect(), cidr(NET), 8, 256)
    }

    fn hello(peer: &str, advertised: &[&str]) -> Hello {
        Hello { tunnel: tunnel_address(&cidr(NET), peer), advertised: advertised.iter().map(|text| cidr(text)).collect() }
    }

    fn reason(table: &Table, prefix: &str) -> Option<&'static str> {
        table.remote_routes().into_iter().find(|route| route.prefix == cidr(prefix)).and_then(|route| route.reason)
    }

    #[test]
    fn hello_round_trips_and_carries_at_most_32_prefixes() {
        let hello = Hello { tunnel: Ipv4Addr::new(10, 77, 1, 2), advertised: vec![cidr("192.168.20.0/24"), cidr("10.1.0.0/16")] };
        assert_eq!(Hello::decode(&hello.encode()), Some(hello.clone()));
        let mut bad = hello.encode();
        bad.push(0);
        assert_eq!(Hello::decode(&bad), None);
        assert_eq!(Hello::decode(b"KVH1\x0a\x4d"), None);
        let mut many = b"KVH1\x0a\x4d\x00\x02".to_vec();
        many.push(33);
        many.extend(std::iter::repeat_n([192, 168, 0, 0, 24], 33).flatten());
        assert_eq!(Hello::decode(&many), None);
    }

    #[test]
    fn tunnel_addresses_are_hosts_of_the_network() {
        let net = cidr(NET);
        let a = tunnel_address(&net, "c2b3d952f91803b4890804e0aa16d84e");
        assert!(net.contains(a) && a != net.network() && a != net.broadcast());
        assert_ne!(a, tunnel_address(&net, "f6a2d6196f686da0e005c701f1d484fb"));
        assert_eq!(tunnel_address(&net, "0000ffff"), net.host(0xffff % 65534 + 1));
        let tiny = cidr("10.0.0.0/30");
        for id in ["00000000", "00000001", "ffffffff"] {
            let host = tunnel_address(&tiny, id);
            assert!(host == Ipv4Addr::new(10, 0, 0, 1) || host == Ipv4Addr::new(10, 0, 0, 2));
        }
    }

    #[test]
    fn routes_by_tunnel_address_then_longest_prefix() {
        let mut table = table(&["192.168.10.0/24"]);
        assert_eq!(table.update(B, hello(B, &["192.168.20.0/24", "172.16.0.0/12"]), 1), Update::Changed);
        assert_eq!(table.update(C, hello(C, &["172.16.5.0/24"]), 1), Update::Changed);
        let c_tunnel = tunnel_address(&cidr(NET), C);
        assert_eq!(table.route(c_tunnel), Some(C));
        assert_eq!(table.route(Ipv4Addr::new(192, 168, 20, 9)), Some(B));
        assert_eq!(table.route(Ipv4Addr::new(10, 77, 0, 9)), None);
        assert!(table.allowed_source(B, Ipv4Addr::new(192, 168, 20, 9)));
        assert!(!table.allowed_source(B, c_tunnel));
        // 172.16.0.0/12 and 172.16.5.0/24 overlap: both are refused.
        assert_eq!(table.route(Ipv4Addr::new(172, 16, 5, 1)), None);
        assert_eq!(table.installed().into_iter().collect::<Vec<_>>(), vec![cidr("192.168.20.0/24")]);
        table.remove(C);
        assert_eq!(table.route(Ipv4Addr::new(172, 16, 5, 1)), Some(B));
    }

    #[test]
    fn a_hello_with_someone_elses_tunnel_address_is_dropped() {
        let mut table = table(&[]);
        let mut spoofed = hello(B, &[]);
        spoofed.tunnel = tunnel_address(&cidr(NET), C);
        assert!(matches!(table.update(B, spoofed, 1), Update::WrongTunnel { .. }));
        assert!(table.peer(B).is_none());
        // B can no longer knock C off by claiming its address.
        table.update(C, hello(C, &[]), 1);
        assert_eq!(table.route(tunnel_address(&cidr(NET), C)), Some(C));
        let mut lan = hello(B, &[]);
        lan.tunnel = Ipv4Addr::new(192, 168, 10, 5);
        assert!(matches!(table.update(B, lan, 1), Update::WrongTunnel { .. }));
    }

    #[test]
    fn hijacking_prefixes_are_refused_without_hurting_anyone_else() {
        let mut table = table(&["192.168.10.0/24"]);
        table.set_system_routes(vec![cidr("0.0.0.0/0"), cidr("192.168.12.0/24")]);
        table.update(C, hello(C, &["192.168.30.0/24"]), 1);
        table.update(B, hello(B, &["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.77.0.0/16", "10.77.5.0/24", "192.168.10.0/25", "192.168.12.0/24", "10.0.0.0/8"]), 1);
        assert_eq!(reason(&table, "0.0.0.0/0"), Some("too short a prefix"));
        assert_eq!(reason(&table, "0.0.0.0/1"), Some("too short a prefix"));
        assert_eq!(reason(&table, "128.0.0.0/1"), Some("too short a prefix"));
        assert_eq!(reason(&table, "10.77.0.0/16"), Some("overlaps the tunnel network"));
        assert_eq!(reason(&table, "10.77.5.0/24"), Some("overlaps the tunnel network"));
        assert_eq!(reason(&table, "10.0.0.0/8"), Some("overlaps the tunnel network"));
        assert_eq!(reason(&table, "192.168.10.0/25"), Some("overlaps a prefix of this node"));
        assert_eq!(reason(&table, "192.168.12.0/24"), Some("overlaps a network this node already reaches"));
        // C's prefix is untouched by B's refused ones.
        assert_eq!(table.route(Ipv4Addr::new(192, 168, 30, 7)), Some(C));
        assert_eq!(table.installed().into_iter().collect::<Vec<_>>(), vec![cidr("192.168.30.0/24")]);
        assert!(!table.allowed_source(B, Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn overlapping_peers_conflict_and_the_total_is_capped() {
        let mut capped = Table::new(Ipv4Addr::new(10, 77, 0, 1), Vec::new(), cidr(NET), 8, 2);
        capped.update(B, hello(B, &["192.168.20.0/24", "192.168.21.0/24", "192.168.22.0/24"]), 1);
        assert_eq!(reason(&capped, "192.168.22.0/24"), Some("too many prefixes on the VPN"));
        let mut table = table(&[]);
        table.update(B, hello(B, &["192.168.20.0/24"]), 1);
        table.update(C, hello(C, &["192.168.20.128/25"]), 1);
        assert_eq!(reason(&table, "192.168.20.0/24"), Some("overlaps a prefix of another node"));
        assert_eq!(table.route(Ipv4Addr::new(192, 168, 20, 200)), None);
    }

    #[test]
    fn prefix_changes_are_throttled() {
        let mut table = table(&[]);
        assert_eq!(table.update(B, hello(B, &["192.168.20.0/24"]), 100), Update::Changed);
        assert_eq!(table.update(B, hello(B, &["192.168.20.0/24"]), 101), Update::Unchanged);
        assert_eq!(table.update(B, hello(B, &["192.168.21.0/24"]), 102), Update::Throttled);
        assert_eq!(table.route(Ipv4Addr::new(192, 168, 20, 1)), Some(B));
        assert_eq!(table.update(B, hello(B, &["192.168.21.0/24"]), 106), Update::Changed);
        assert_eq!(table.route(Ipv4Addr::new(192, 168, 21, 1)), Some(B));
    }

    #[test]
    fn a_gateway_accepts_what_it_offers_and_an_uplink_routes_to_it() {
        let mut gateway = table(&["10.78.7.0/24"]);
        assert!(!gateway.accepts_destination(Ipv4Addr::new(8, 8, 8, 8)));
        gateway.set_gateway(vec![cidr("0.0.0.0/0")]);
        assert!(gateway.accepts_destination(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!gateway.accepts_destination(Ipv4Addr::new(10, 77, 0, 9)), "never another node's tunnel address");

        let mut node = table(&["10.78.9.0/24"]);
        node.update(B, hello(B, &["10.78.7.0/24"]), 1);
        assert_eq!(node.route(Ipv4Addr::new(8, 8, 8, 8)), None);
        assert!(!node.allowed_source(B, Ipv4Addr::new(8, 8, 8, 8)));
        node.set_uplink(Some((B.to_owned(), vec![cidr("0.0.0.0/0")])));
        assert_eq!(node.route(Ipv4Addr::new(8, 8, 8, 8)), Some(B));
        assert_eq!(node.route(Ipv4Addr::new(10, 78, 7, 5)), Some(B), "advertised prefixes still win");
        assert!(node.allowed_source(B, Ipv4Addr::new(8, 8, 8, 8)), "replies from the internet");
        assert!(!node.allowed_source(C, Ipv4Addr::new(8, 8, 8, 8)), "only from the gateway");
        assert_eq!(node.route(Ipv4Addr::new(10, 77, 9, 9)), None, "not the tunnel network");
        node.set_uplink(Some((B.to_owned(), vec![cidr("192.168.50.0/24")])));
        assert_eq!(node.route(Ipv4Addr::new(8, 8, 8, 8)), None);
        assert_eq!(node.route(Ipv4Addr::new(192, 168, 50, 1)), Some(B));
    }

    #[test]
    fn local_prefixes_and_overlapping_advertisers() {
        let mut table = table(&[]);
        table.update(B, hello(B, &["10.78.7.0/24"]), 1);
        assert_eq!(table.advertisers_overlapping(&cidr("10.78.7.0/24")), vec![B.to_owned()]);
        assert!(table.advertisers_overlapping(&cidr("10.78.8.0/24")).is_empty());
        assert!(table.set_local(vec![cidr("10.78.7.0/24")]));
        assert!(!table.set_local(vec![cidr("10.78.7.0/24")]));
        assert_eq!(reason(&table, "10.78.7.0/24"), Some("overlaps a prefix of this node"));
    }

    #[test]
    fn only_traffic_for_us_our_networks_or_floods_enters() {
        let table = table(&["192.168.10.0/24"]);
        assert!(table.accepts_destination(Ipv4Addr::new(10, 77, 0, 1)));
        assert!(table.accepts_destination(Ipv4Addr::new(192, 168, 10, 20)));
        assert!(table.accepts_destination(Ipv4Addr::new(10, 77, 255, 255)));
        assert!(!table.accepts_destination(Ipv4Addr::new(192, 168, 12, 1)));
        assert!(!table.accepts_destination(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!table.accepts_destination(Ipv4Addr::new(10, 77, 0, 2)));
    }
}
