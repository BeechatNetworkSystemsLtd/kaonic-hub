//! The running VPN. Packets from the TUN device go to the peer that owns the destination,
//! or to every peer for broadcast and multicast. Packets from a peer go into the TUN device
//! only if their source belongs to that peer. LAN multicast and broadcast are forwarded by
//! rule ([`crate::forward`]).

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use kaonic_mesh::links::{Links, Received};
use kaonic_mesh::log_limit::LogLimit;
use kaonic_mux::{Kind, Message};
use tokio::sync::{Notify, broadcast, mpsc};

use crate::ip::{self, Cidr, Summary};
use crate::capture::Verdict;
use crate::forward::{self, Emit, Forward};
use crate::table::{Hello, RemoteRoute, Table, Update, tunnel_address};
use crate::tun::{self, Tun};
use crate::share::{self, GatewaySettings, LanNet, Plan, PlanInput, ShareSettings, UplinkRoutes, UplinkSettings};
use crate::{firewall, flood, kernel};

/// Mux streams.
const STREAM_IP: u8 = 1;
const STREAM_CONTROL: u8 = 2;
/// HELLO interval. HELLOs are not acknowledged; a lost one is covered by the next.
const HELLO_EVERY: Duration = Duration::from_secs(30);
/// A gateway not heard from for this long is dropped.
const GATEWAY_STALE: Duration = Duration::from_secs(100);
/// Max packets read from the TUN device per flush, so they can share link packets.
const BATCH: usize = 64;
/// Size of the packet log for the API.
const LOG: usize = 256;
/// Max datagrams queued for the LAN sockets; more are dropped and counted.
const EMIT_QUEUE: usize = 256;
/// A fault that repeats for every packet (TUN reads and writes) is logged at most this often.
const FAULT_LOG_EVERY: Duration = Duration::from_secs(10);
/// How often the route and network threads look for work besides new plans (exit, dnsmasq).
const WORKER_POLL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct VpnConfig {
    pub network: Cidr,
    pub interface: String,
    /// Extra prefixes we advertise to peers.
    pub advertise: Vec<Cidr>,
    /// Max mux packet size on a link; sets the TUN MTU.
    pub max_packet: usize,
    pub limits: VpnLimits,
    /// Client networks, gateway and uplink settings (can change while running).
    pub share: ShareSettings,
    /// Multicast and broadcast forwarding rules (can change while running).
    pub forward: Vec<forward::Rule>,
}

/// Limits on what peers may do to this node.
#[derive(Clone, Debug)]
pub struct VpnLimits {
    /// Shorter advertised prefixes are refused.
    pub min_prefix_len: u8,
    /// Max advertised prefixes accepted from all peers together.
    pub max_prefixes: usize,
    /// Broadcast and multicast per source: packets per second, and burst.
    pub flood_rate: u32,
    pub flood_burst: u32,
    /// Chatter groups (mDNS, SSDP, 224.0.0.0/24) to flood anyway.
    pub flood_allow: Vec<Cidr>,
    /// Management ports blocked on the tunnel.
    pub protected_tcp: Vec<u16>,
    pub protected_udp: Vec<u16>,
    /// Retransmit lost packets between hubs ([`crate::reliable`]). All nodes must agree.
    pub arq: bool,
}

impl Default for VpnLimits {
    fn default() -> Self {
        Self { min_prefix_len: 8, max_prefixes: 256, flood_rate: 10, flood_burst: 20, flood_allow: Vec::new(), protected_tcp: vec![80, 443], protected_udp: vec![8781], arq: false }
    }
}

/// The newest value for a worker thread. Values set while it is busy replace each other, so
/// nothing queues up however often they change.
struct Latest<T> {
    value: Mutex<Option<T>>,
    ready: Condvar,
}

impl<T> Latest<T> {
    fn new() -> Self {
        Self { value: Mutex::new(None), ready: Condvar::new() }
    }

    fn set(&self, value: T) {
        *self.value.lock().expect("latest lock") = Some(value);
        self.ready.notify_one();
    }

    /// The newest value, or None if none came within `wait`.
    fn take(&self, wait: Duration) -> Option<T> {
        let value = self.value.lock().expect("latest lock");
        let (mut value, _) = self.ready.wait_timeout_while(value, wait, |value| value.is_none()).expect("latest lock");
        value.take()
    }
}

impl VpnConfig {
    pub fn mtu(&self) -> u16 {
        kaonic_mux::max_payload(self.max_packet).min(1500) as u16
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped: u64,
    /// Unix milliseconds.
    pub last_tx_ms: Option<i64>,
    pub last_rx_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Tx,
    Rx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketLog {
    pub ts_ms: i64,
    pub direction: Direction,
    pub summary: Summary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerStatus {
    pub peer: String,
    pub tunnel: Option<Ipv4Addr>,
    /// `active` (link up, HELLO heard), `pending` (link up, no HELLO yet), `closed`.
    pub state: &'static str,
    pub advertised: Vec<Cidr>,
    pub counters: Counters,
}

/// Gateway state for the API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayStatus {
    pub settings: GatewaySettings,
    pub active: bool,
    pub egress: Option<String>,
    pub available_interfaces: Vec<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UplinkStatus {
    pub settings: UplinkSettings,
    pub active: bool,
    pub peer: Option<String>,
    pub routes: Vec<Cidr>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub interface: String,
    pub network: Cidr,
    pub tunnel: Ipv4Addr,
    pub mtu: u16,
    pub advertised: Vec<Cidr>,
    pub remote: Vec<RemoteRoute>,
    pub installed: BTreeSet<Cidr>,
    pub counters: Counters,
    pub peers: Vec<PeerStatus>,
    pub last_error: Option<String>,
    pub share: ShareSettings,
    /// Our client networks and their mapped prefixes.
    pub lans: Vec<LanNet>,
    pub gateway: GatewayStatus,
    pub uplink: UplinkStatus,
    /// Peers offering to be a gateway, with their destinations.
    pub gateways: Vec<(String, Vec<Cidr>)>,
}

/// Sharing state: settings, detected networks, and what is active.
struct Share {
    settings: ShareSettings,
    lans: Vec<LanNet>,
    /// Mapping attempts per client subnet (bumped on a clash with another node).
    attempts: HashMap<Cidr, u32>,
    /// Gateways heard, with their destinations and when.
    gateways: HashMap<String, (Vec<Cidr>, Instant)>,
    gateway: GatewayStatus,
    uplink: UplinkStatus,
    /// The last plan sent to the network thread.
    planned: Plan,
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis() as i64)
}

struct State {
    table: Table,
    installed: BTreeSet<Cidr>,
    counters: Counters,
    peers: HashMap<String, Counters>,
    log: VecDeque<PacketLog>,
    last_error: Option<String>,
    /// Flood limits: per source address (outgoing) and per peer (incoming).
    flood_out: flood::Limiter<Ipv4Addr>,
    flood_in: flood::Limiter<String>,
    /// Peers whose wrong tunnel address was already logged.
    wrong_tunnel: HashSet<String>,
}

pub struct Vpn {
    links: Arc<Links>,
    config: VpnConfig,
    tun: Tun,
    state: Mutex<State>,
    /// The routes the kernel should have, for the route thread.
    routes: Arc<Latest<BTreeSet<Cidr>>>,
    /// TUN read and write failures, logged at most every [`FAULT_LOG_EVERY`].
    fault_log: Mutex<LogLimit>,
    /// Packet capture (off until started).
    pub capture: crate::capture::Capture,
    /// Retransmission between hubs.
    pub reliable: Arc<crate::reliable::Reliable>,
    identity: String,
    share: Mutex<Share>,
    /// The newest sharing plan, for the network thread.
    net: Arc<Latest<Plan>>,
    /// Forwarding rules and counters. Taken only after `state` is released, except in the
    /// flood checks, which take `state` then this.
    forward: Mutex<Forward>,
    /// Datagrams for the LAN sockets (`crate::lan`).
    emits: mpsc::Sender<Emit>,
    forward_changed: Notify,
}

/// Test handles for a VPN started with [`Vpn::start_detached`].
pub struct Detached {
    /// The kernel end of the in-memory TUN device.
    pub tun: tun::TunPipe,
    /// Datagrams the LAN sockets would send.
    pub emits: mpsc::Receiver<Emit>,
}

impl State {
    fn record(&mut self, peer: Option<&str>, direction: Direction, summary: Summary) {
        let now = now_ms();
        let bytes = summary.len as u64;
        let count = |counters: &mut Counters| match direction {
            Direction::Tx => {
                counters.tx_packets += 1;
                counters.tx_bytes += bytes;
                counters.last_tx_ms = Some(now);
            }
            Direction::Rx => {
                counters.rx_packets += 1;
                counters.rx_bytes += bytes;
                counters.last_rx_ms = Some(now);
            }
        };
        count(&mut self.counters);
        if let Some(peer) = peer {
            count(self.peers.entry(peer.to_owned()).or_default());
        }
        if self.log.len() == LOG {
            self.log.pop_back();
        }
        self.log.push_front(PacketLog { ts_ms: now, direction, summary });
    }

    fn drop_one(&mut self, peer: Option<&str>) {
        self.counters.dropped += 1;
        if let Some(peer) = peer {
            self.peers.entry(peer.to_owned()).or_default().dropped += 1;
        }
    }
}

impl Vpn {
    /// Opens and configures the TUN device and starts the VPN.
    pub async fn start(links: Arc<Links>, identity_hash: &str, config: VpnConfig) -> std::io::Result<Arc<Self>> {
        let tun = Tun::open(&config.interface)?;
        let me = tunnel_address(&config.network, identity_hash);
        // `ip` and firewall tools are blocking processes; run them off the async runtime.
        let (interface, network, mtu) = (config.interface.clone(), config.network, config.mtu());
        tokio::task::spawn_blocking(move || tun::configure(&interface, me, &network, mtu)).await.map_err(std::io::Error::other)??;
        log::info!("vpn: {} is {me} on {}, MTU {}", config.interface, config.network, config.mtu());
        let (interface, tcp, udp) = (config.interface.clone(), config.limits.protected_tcp.clone(), config.limits.protected_udp.clone());
        match tokio::task::spawn_blocking(move || firewall::protect(&interface, &tcp, &udp)).await.map_err(std::io::Error::other)? {
            Ok(tool) => log::info!("vpn: management ports closed to {} ({tool})", config.interface),
            Err(error) => log::warn!("vpn: {error}"),
        }
        let (vpn, emits) = Self::launch(links, identity_hash, config, tun, true)?;
        #[cfg(target_os = "linux")]
        tokio::spawn(crate::lan::run(vpn.clone(), emits));
        #[cfg(not(target_os = "linux"))]
        drop(emits);
        Ok(vpn)
    }

    /// Starts the VPN on an in-memory TUN device, without touching the system. For tests.
    pub fn start_detached(links: Arc<Links>, identity_hash: &str, config: VpnConfig) -> std::io::Result<(Arc<Self>, Detached)> {
        let (tun, pipe) = Tun::pipe(&config.interface);
        let (vpn, emits) = Self::launch(links, identity_hash, config, tun, false)?;
        Ok((vpn, Detached { tun: pipe, emits }))
    }

    /// Starts the VPN on `tun`. Kernel routes and sharing plans are applied only if `system`.
    fn launch(links: Arc<Links>, identity_hash: &str, config: VpnConfig, tun: Tun, system: bool) -> std::io::Result<(Arc<Self>, mpsc::Receiver<Emit>)> {
        let me = tunnel_address(&config.network, identity_hash);
        let mut table = Table::new(me, config.advertise.clone(), config.network, config.limits.min_prefix_len, config.limits.max_prefixes);
        table.set_system_routes(kernel::routes(&config.interface));
        let state = State {
            table,
            installed: BTreeSet::new(),
            counters: Counters::default(),
            peers: HashMap::new(),
            log: VecDeque::with_capacity(LOG),
            last_error: None,
            flood_out: flood::Limiter::new(config.limits.flood_rate, config.limits.flood_burst),
            flood_in: flood::Limiter::new(config.limits.flood_rate, config.limits.flood_burst),
            wrong_tunnel: HashSet::new(),
        };
        let routes = Arc::new(Latest::new());
        let net = Arc::new(Latest::new());
        let share = Share {
            settings: config.share.clone(),
            lans: Vec::new(),
            attempts: HashMap::new(),
            gateways: HashMap::new(),
            gateway: GatewayStatus { settings: config.share.gateway.clone(), active: false, egress: None, available_interfaces: Vec::new(), detail: None },
            uplink: UplinkStatus { settings: config.share.uplink.clone(), active: false, peer: None, routes: Vec::new(), detail: None },
            planned: Plan::default(),
        };
        let (reliable, received) = crate::reliable::Reliable::start(links.clone(), config.limits.arq);
        let forward = Forward::new(me, config.network, usize::from(config.mtu()), config.forward.clone(), config.share.lan_interfaces.clone());
        let (emits, emitted) = mpsc::channel(EMIT_QUEUE);
        let vpn = Arc::new(Self {
            links,
            config,
            tun,
            state: Mutex::new(state),
            routes: routes.clone(),
            fault_log: Mutex::new(LogLimit::new(FAULT_LOG_EVERY)),
            capture: Default::default(),
            reliable,
            identity: identity_hash.to_owned(),
            share: Mutex::new(share),
            net: net.clone(),
            forward: Mutex::new(forward),
            emits,
            forward_changed: Notify::new(),
        });
        if system {
            let worker = Arc::downgrade(&vpn);
            let interface = vpn.config.interface.clone();
            std::thread::Builder::new().name("vpn-routes".into()).spawn(move || route_worker(interface, routes, worker))?;
            let worker = Arc::downgrade(&vpn);
            let interface = vpn.config.interface.clone();
            std::thread::Builder::new().name("vpn-net".into()).spawn(move || net_worker(interface, net, worker))?;
        }
        vpn.refresh_share();

        let outgoing = vpn.clone();
        tokio::spawn(async move { outgoing.carry_out().await });
        let incoming = vpn.clone();
        tokio::spawn(async move { incoming.carry_in(received).await });
        let hellos = vpn.clone();
        let changes = vpn.links.changes();
        tokio::spawn(async move { hellos.keep_peers(changes).await });
        Ok((vpn, emitted))
    }

    fn error(&self, error: String) {
        log::warn!("vpn: {error}");
        self.state.lock().expect("vpn lock").last_error = Some(error);
    }

    /// Like [`Self::error`], for a fault that may repeat for every packet.
    fn packet_error(&self, error: String) {
        if let Some(skipped) = self.fault_log.lock().expect("vpn fault log lock").allow(Instant::now()) {
            log::warn!("vpn: {error} ({skipped} more not logged)");
        }
        self.state.lock().expect("vpn lock").last_error = Some(error);
    }

    /// TUN → links.
    async fn carry_out(&self) {
        let mut buffer = vec![0u8; 65536];
        let mut queues: HashMap<String, VecDeque<Message>> = HashMap::new();
        loop {
            let first = match self.tun.read(&mut buffer).await {
                Ok(length) => length,
                Err(error) => {
                    self.packet_error(format!("reading {}: {error}", self.config.interface));
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let mut length = Some(first);
            let mut taken = 0;
            let established = self.links.established();
            while let Some(len) = length {
                let _ = self.route_out(&buffer[..len], &established, &mut queues);
                taken += 1;
                length = if taken < BATCH { self.tun.try_read(&mut buffer).ok().flatten() } else { None };
            }
            self.flush(&mut queues).await;
        }
    }

    /// Sends the queued messages, packing several per link packet.
    async fn flush(&self, queues: &mut HashMap<String, VecDeque<Message>>) {
        for (peer, queue) in queues.iter_mut() {
            loop {
                let (packet, too_large) = kaonic_mux::pack(queue, self.config.max_packet);
                if too_large > 0 {
                    let mut state = self.state.lock().expect("vpn lock");
                    (0..too_large).for_each(|_| state.drop_one(Some(peer)));
                }
                let Some(packet) = packet else { break };
                if !self.reliable.send(peer, &packet).await {
                    self.state.lock().expect("vpn lock").drop_one(Some(peer));
                }
            }
        }
        queues.retain(|_, queue| !queue.is_empty());
    }

    /// Whether a forwarding rule carries this group, even if it is chatter.
    fn forwarded(&self, dst: Ipv4Addr, to_mesh: bool) -> bool {
        self.forward.lock().expect("vpn forward lock").carries(dst, to_mesh)
    }

    /// Queues a packet for the destination's peer, or every peer. Err gives the drop reason.
    fn route_out(&self, packet: &[u8], established: &[String], queues: &mut HashMap<String, VecDeque<Message>>) -> Result<(), &'static str> {
        self.route_out_for(packet, None, established, queues)
    }

    /// Like [`Self::route_out`], but floods count against `budget` instead of the packet's source.
    fn route_out_for(&self, packet: &[u8], budget: Option<Ipv4Addr>, established: &[String], queues: &mut HashMap<String, VecDeque<Message>>) -> Result<(), &'static str> {
        let mut state = self.state.lock().expect("vpn lock");
        let Some(summary) = ip::summarize(packet) else {
            state.drop_one(None);
            self.capture.record(Direction::Tx, None, false, packet, Verdict::Dropped, Some("not_ipv4"));
            return Err("not_ipv4");
        };
        let targets: Vec<String> = if ip::is_flooded(summary.dst, &self.config.network) {
            // Each peer is a separate transmission: drop chatter and rate-limit per source.
            if flood::is_chatter(&summary, &self.config.limits.flood_allow) && !self.forwarded(summary.dst, true) {
                state.drop_one(None);
                self.capture.record(Direction::Tx, None, true, packet, Verdict::Dropped, Some("destination_not_allowed"));
                return Err("destination_not_allowed");
            }
            if !state.flood_out.allow(&budget.unwrap_or(summary.src), Instant::now()) {
                state.drop_one(None);
                self.capture.record(Direction::Tx, None, true, packet, Verdict::Dropped, Some("rate_limited"));
                return Err("rate_limited");
            }
            established.to_vec()
        } else {
            match state.table.route(summary.dst) {
                Some(peer) if established.iter().any(|up| up == peer) => vec![peer.to_owned()],
                _ => Vec::new(),
            }
        };
        let flood = ip::is_flooded(summary.dst, &self.config.network);
        if targets.is_empty() {
            let reason = if flood { "no_peers" } else { "no_route" };
            state.drop_one(None);
            self.capture.record(Direction::Tx, None, flood, packet, Verdict::Dropped, Some(reason));
            return Err(reason);
        }
        self.capture.record(Direction::Tx, (!flood).then(|| targets[0].as_str()), flood, packet, Verdict::Sent, None);
        for peer in &targets {
            state.record(Some(peer), Direction::Tx, summary);
            queues.entry(peer.clone()).or_default().push_back(Message { kind: Kind::Data, stream: STREAM_IP, payload: packet.to_vec() });
        }
        Ok(())
    }

    /// A multicast or broadcast datagram from a client network (`crate::lan`). Flooded to
    /// peers if a rule carries it.
    pub async fn lan_datagram(&self, interface: &str, src: SocketAddrV4, dst: Ipv4Addr, port: u16, payload: &[u8]) {
        let Some(outgoing) = self.forward.lock().expect("vpn forward lock").from_lan(interface, src, dst, port, payload, Instant::now()) else { return };
        self.send_forwarded(outgoing).await;
    }

    /// Like [`Self::lan_datagram`], from a captured IPv4 packet (fragments are reassembled).
    pub async fn lan_packet(&self, interface: &str, link_broadcast: bool, packet: &[u8], networks: &[Cidr], local: &[Ipv4Addr]) {
        let Some(outgoing) = self.forward.lock().expect("vpn forward lock").from_lan_packet(interface, link_broadcast, packet, networks, local, Instant::now()) else { return };
        self.send_forwarded(outgoing).await;
    }

    async fn send_forwarded(&self, outgoing: forward::Outgoing) {
        // Counted against this node's flood budget, whatever the source address.
        let me = self.state.lock().expect("vpn lock").table.me;
        let established = self.links.established();
        let mut queues: HashMap<String, VecDeque<Message>> = HashMap::new();
        // Send all fragments or none; a partial datagram only wastes air time.
        let sent = outgoing.packets.iter().all(|packet| self.route_out_for(packet, Some(me), &established, &mut queues).is_ok());
        if sent {
            self.flush(&mut queues).await;
        }
        self.forward.lock().expect("vpn forward lock").sent(&outgoing, sent);
    }

    /// Sets forwarding rules (validated by the API with [`forward::validate`]).
    pub fn set_forward(&self, rules: Vec<forward::Rule>) {
        self.forward.lock().expect("vpn forward lock").set_rules(rules);
        self.forward_changed.notify_one();
    }

    pub fn forward_rules(&self) -> Vec<forward::Rule> {
        self.forward.lock().expect("vpn forward lock").rules()
    }

    /// The rules with counters and LAN state.
    pub fn forward_status(&self) -> Vec<forward::RuleStatus> {
        self.forward.lock().expect("vpn forward lock").status()
    }

    /// For the LAN side: the forwarding state.
    #[cfg(target_os = "linux")]
    pub(crate) fn forward(&self) -> std::sync::MutexGuard<'_, Forward> {
        self.forward.lock().expect("vpn forward lock")
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn forward_changed(&self) {
        self.forward_changed.notified().await;
    }

    /// Links → TUN.
    async fn carry_in(&self, mut received: broadcast::Receiver<Received>) {
        loop {
            let message = match received.recv().await {
                Ok(message) => message,
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    let mut state = self.state.lock().expect("vpn lock");
                    (0..missed).for_each(|_| state.drop_one(None));
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Ok(frames) = kaonic_mux::parse(&message.packet) else { continue };
            let mut routes_changed = false;
            for frame in frames {
                match (frame.kind, frame.stream) {
                    (Kind::Data, STREAM_IP) => {
                        let accepted = {
                            let mut state = self.state.lock().expect("vpn lock");
                            let verdict = match ip::summarize(frame.payload) {
                                None => Err("not_ipv4"),
                                Some(summary) if !state.table.allowed_source(&message.peer, summary.src) => Err("source_not_allowed"),
                                // Don't relay to every network this hub reaches.
                                Some(summary) if !state.table.accepts_destination(summary.dst) => Err("destination_not_allowed"),
                                Some(summary) if ip::is_flooded(summary.dst, &self.config.network) && flood::is_chatter(&summary, &self.config.limits.flood_allow) && !self.forwarded(summary.dst, false) => Err("destination_not_allowed"),
                                Some(summary) if ip::is_flooded(summary.dst, &self.config.network) && !state.flood_in.allow(&message.peer, Instant::now()) => Err("rate_limited"),
                                Some(summary) => Ok(summary),
                            };
                            match verdict {
                                Ok(summary) => {
                                    state.record(Some(&message.peer), Direction::Rx, summary);
                                    let flood = ip::is_flooded(summary.dst, &self.config.network);
                                    self.capture.record(Direction::Rx, Some(&message.peer), flood, frame.payload, Verdict::Delivered, None);
                                    Some(flood)
                                }
                                Err(reason) => {
                                    state.drop_one(Some(&message.peer));
                                    self.capture.record(Direction::Rx, Some(&message.peer), false, frame.payload, Verdict::Dropped, Some(reason));
                                    None
                                }
                            }
                        };
                        if accepted.is_some() && let Err(error) = self.tun.write(frame.payload).await {
                            self.packet_error(format!("writing {}: {error}", self.config.interface));
                        }
                        // Also to client networks if a rule says so. Never to another peer.
                        if accepted == Some(true) {
                            let mut forward = self.forward.lock().expect("vpn forward lock");
                            if let Some(emit) = forward.from_mesh(frame.payload, Instant::now())
                                && let Err(mpsc::error::TrySendError::Full(emit) | mpsc::error::TrySendError::Closed(emit)) = self.emits.try_send(emit)
                            {
                                forward.emit_failed(&emit.rule);
                            }
                        }
                    }
                    (Kind::Control, STREAM_CONTROL) if frame.payload.starts_with(b"KVG1") => {
                        if let Some(routes) = share::decode_gateway(frame.payload) {
                            let mut share = self.share.lock().expect("vpn share lock");
                            let changed = share.gateways.get(&message.peer).map(|(known, _)| known) != Some(&routes);
                            if routes.is_empty() {
                                share.gateways.remove(&message.peer);
                            } else {
                                share.gateways.insert(message.peer.clone(), (routes, Instant::now()));
                            }
                            routes_changed |= changed;
                        }
                    }
                    (Kind::Control, STREAM_CONTROL) => {
                        if let Some(hello) = Hello::decode(frame.payload) {
                            let mut state = self.state.lock().expect("vpn lock");
                            let described = format!("{}{}", hello.tunnel, if hello.advertised.is_empty() { String::new() } else { format!(", routes {:?}", hello.advertised.iter().map(ToString::to_string).collect::<Vec<_>>()) });
                            let known = state.table.peer(&message.peer).is_some();
                            match state.table.update(&message.peer, hello, now_ms() / 1000) {
                                Update::Changed => {
                                    // A peer's first HELLO is news; its later changes are route churn.
                                    let level = if known { log::Level::Debug } else { log::Level::Info };
                                    log::log!(level, "vpn: {} is {described}", message.peer);
                                    routes_changed = true;
                                }
                                Update::WrongTunnel { claimed, expected } => {
                                    if state.wrong_tunnel.insert(message.peer.clone()) {
                                        log::warn!("vpn: {} claims tunnel address {claimed}, but its identity gives {expected}: ignoring its HELLO", message.peer);
                                    }
                                }
                                Update::Unchanged | Update::Throttled => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            if routes_changed {
                self.sync_routes();
                if self.refresh_share() {
                    self.send_hello(self.links.established()).await;
                }
            }
        }
    }

    /// Sends HELLO to new peers and periodically to all. Removes peers whose link closed.
    async fn keep_peers(&self, mut changes: broadcast::Receiver<String>) {
        let mut every = tokio::time::interval(HELLO_EVERY);
        loop {
            let to: Vec<String> = tokio::select! {
                change = changes.recv() => match change {
                    Ok(peer) => {
                        let established = self.links.established();
                        if established.contains(&peer) {
                            vec![peer]
                        } else {
                            self.forget_closed(&established);
                            Vec::new()
                        }
                    }
                    // A missed close would leave its peer's routes: check every peer.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let established = self.links.established();
                        self.forget_closed(&established);
                        established
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = every.tick() => {
                    // Kernel routes may have changed, which changes what peers may advertise.
                    let changed = self.state.lock().expect("vpn lock").table.set_system_routes(kernel::routes(&self.config.interface));
                    if changed {
                        self.sync_routes();
                    }
                    self.refresh_share();
                    self.capture.tidy();
                    self.links.established()
                }
            };
            self.send_hello(to).await;
        }
    }

    /// Forgets the routes, counters and retransmission state of peers whose link is down.
    fn forget_closed(&self, established: &[String]) {
        {
            let mut state = self.state.lock().expect("vpn lock");
            let gone: Vec<String> = state.table.peers().map(|(peer, _)| peer.clone()).filter(|peer| !established.contains(peer)).collect();
            for peer in &gone {
                state.table.remove(peer);
            }
            state.peers.retain(|peer, _| established.contains(peer));
            state.wrong_tunnel.retain(|peer| established.contains(peer));
        }
        self.reliable.forget_closed(established);
        self.sync_routes();
    }

    /// Sends our HELLO and gateway announcement to `to`.
    async fn send_hello(&self, to: Vec<String>) {
        let hello = self.state.lock().expect("vpn lock").table.hello().encode();
        let gateway = {
            let share = self.share.lock().expect("vpn share lock");
            share::encode_gateway(if share.gateway.active { &share.gateway.settings.routes } else { &[] })
        };
        for peer in to {
            let mut queue: VecDeque<Message> = [
                Message { kind: Kind::Control, stream: STREAM_CONTROL, payload: hello.clone() },
                Message { kind: Kind::Control, stream: STREAM_CONTROL, payload: gateway.clone() },
            ]
            .into();
            while let (Some(packet), _) = kaonic_mux::pack(&mut queue, self.config.max_packet) {
                self.links.send(&peer, &packet).await;
            }
        }
    }

    /// Applies new sharing settings and tells peers.
    pub async fn set_share(&self, settings: ShareSettings) {
        {
            let mut share = self.share.lock().expect("vpn share lock");
            share.gateway.settings = settings.gateway.clone();
            share.uplink.settings = settings.uplink.clone();
            self.forward.lock().expect("vpn forward lock").set_lan_interfaces(settings.lan_interfaces.clone());
            share.settings = settings;
        }
        self.forward_changed.notify_one();
        self.refresh_share();
        self.send_hello(self.links.established()).await;
    }

    pub fn share_settings(&self) -> ShareSettings {
        self.share.lock().expect("vpn share lock").settings.clone()
    }

    /// Recomputes client networks, mapped prefixes, gateway and uplink. Sends the plan to the
    /// network thread if it changed. Returns whether our HELLO changed.
    fn refresh_share(&self) -> bool {
        let routes = kernel::all_routes();
        let addresses = kernel::interface_addresses();
        let tun = self.config.interface.as_str();
        let mut share = self.share.lock().expect("vpn share lock");
        let mut state = self.state.lock().expect("vpn lock");
        let settings = share.settings.clone();

        // Client networks: connected routes on the client interfaces.
        let mut lans: Vec<LanNet> = Vec::new();
        if settings.share_lans {
            // The node's own pool subnet is served by the hub's DHCP.
            let routed = settings.route_lans && settings.push_routes;
            for interface in &settings.lan_interfaces {
                let mut own = false;
                for route in routes.iter().filter(|route| &route.interface == interface && route.connected && route.prefix.prefix_len() > 0) {
                    // Skip subnets the hub added itself.
                    if routed && settings.mapping_pool.overlaps(&route.prefix) {
                        continue;
                    }
                    let mapped = loop {
                        let attempt = share.attempts.get(&route.prefix).copied().unwrap_or(0);
                        if !(settings.map_lans || routed) || attempt >= share::MAX_ATTEMPTS {
                            break route.prefix;
                        }
                        let mapped = share::mapped_subnet(&self.identity, &route.prefix, &settings.mapping_pool, attempt);
                        // Clash with another node: the higher identity picks again.
                        if state.table.advertisers_overlapping(&mapped).iter().any(|peer| peer.as_str() < self.identity.as_str()) {
                            share.attempts.insert(route.prefix, attempt + 1);
                            continue;
                        }
                        break mapped;
                    };
                    // The interface's first /24 is replaced by the node's own subnet.
                    if routed && !own && mapped != route.prefix && mapped.prefix_len() == 24 {
                        own = true;
                        lans.push(LanNet { interface: interface.clone(), subnet: mapped, mapped, address: Some(mapped.host(1)), base: Some(route.prefix) });
                        continue;
                    }
                    let mapped = if settings.map_lans { mapped } else { route.prefix };
                    let address = addresses.iter().find(|(name, address)| name == interface && route.prefix.contains(*address)).map(|(_, address)| *address);
                    lans.push(LanNet { interface: interface.clone(), subnet: route.prefix, mapped, address, base: None });
                }
            }
        }
        let local: Vec<Cidr> = lans.iter().map(|lan| lan.mapped).chain(settings.advertise.iter().copied()).collect();
        let hello_changed = state.table.set_local(local);

        // Gateway: share our uplink.
        let available: Vec<String> = {
            let mut names: Vec<String> = routes.iter().map(|route| route.interface.clone()).filter(|name| name != tun && name != "lo").collect();
            names.sort();
            names.dedup();
            names
        };
        let egress = if settings.gateway.enabled {
            settings.gateway.egress_interface.clone().or_else(|| routes.iter().find(|route| route.prefix.prefix_len() == 0 && route.interface != tun).map(|route| route.interface.clone()))
        } else {
            None
        };
        let gateway_was = share.gateway.active;
        share.gateway.active = egress.is_some() && !settings.gateway.routes.is_empty();
        share.gateway.detail = match (settings.gateway.enabled, &egress) {
            (false, _) => None,
            (true, None) => Some("This node has no uplink (no default route) to share.".to_owned()),
            (true, Some(_)) if settings.gateway.routes.is_empty() => Some("No destinations to forward.".to_owned()),
            (true, Some(egress)) => Some(format!("Forwarding for the mesh through {egress}.")),
        };
        share.gateway.egress = egress.clone().filter(|_| share.gateway.active);
        share.gateway.available_interfaces = available;
        state.table.set_gateway(if share.gateway.active { settings.gateway.routes.clone() } else { Vec::new() });

        // Uplink: through a linked gateway peer.
        let established = self.links.established();
        share.gateways.retain(|_, (_, heard)| heard.elapsed() < GATEWAY_STALE);
        let mut offered: Vec<&String> = share.gateways.keys().filter(|peer| established.contains(peer)).collect();
        offered.sort();
        let chosen = if settings.uplink.enabled {
            match &settings.uplink.peer {
                Some(peer) => offered.iter().find(|offer| *offer == &peer).map(|peer| (*peer).clone()),
                None => offered.first().map(|peer| (*peer).clone()),
            }
        } else {
            None
        };
        let uplink_routes: Vec<Cidr> = if settings.uplink.default_route { vec![Cidr::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid prefix")] } else { settings.uplink.routes.clone() };
        let uplink = chosen.as_ref().filter(|_| !uplink_routes.is_empty()).map(|peer| UplinkRoutes { peer: peer.clone(), default_route: settings.uplink.default_route, routes: uplink_routes.clone() });
        share.uplink.active = uplink.is_some();
        share.uplink.peer = uplink.as_ref().map(|uplink| uplink.peer.clone());
        share.uplink.routes = uplink.as_ref().map(|uplink| uplink.routes.clone()).unwrap_or_default();
        share.uplink.detail = match (settings.uplink.enabled, &uplink) {
            (false, _) => None,
            (true, Some(uplink)) => Some(format!("Through {}.", &uplink.peer[..8.min(uplink.peer.len())])),
            (true, None) if uplink_routes.is_empty() => Some("No destinations to send to the gateway.".to_owned()),
            (true, None) => Some(match &settings.uplink.peer {
                Some(peer) => format!("{} is not offering to be a gateway (or is not linked).", &peer[..8.min(peer.len())]),
                None => "No node is offering to be a gateway.".to_owned(),
            }),
        };
        state.table.set_uplink(uplink.as_ref().map(|uplink| (uplink.peer.clone(), uplink.routes.clone())));

        // Clash counts of client subnets that are gone.
        share.attempts.retain(|prefix, _| routes.iter().any(|route| route.prefix == *prefix && route.connected && settings.lan_interfaces.contains(&route.interface)));

        let remote_sources: Vec<Cidr> = state.table.installed().into_iter().collect();
        let plan = share::plan(&PlanInput {
            tun,
            mtu: self.config.mtu(),
            tunnel_network: self.config.network,
            lans: &lans,
            settings: &settings,
            egress: share.gateway.egress.as_deref(),
            remote_sources: &remote_sources,
            uplink,
        });
        let forward_lans: Vec<forward::Lan> = lans.iter().map(|lan| forward::Lan { interface: lan.interface.clone(), subnet: lan.subnet, mapped: lan.mapped }).collect();
        share.lans = lans;
        // Re-apply if one of our addresses has gone missing.
        let missing = plan.addresses.iter().any(|(interface, wanted, _)| !addresses.iter().any(|(name, address)| name == interface && address == wanted));
        if plan != share.planned || missing {
            share.planned = plan.clone();
            self.net.set(plan);
        }
        let changed = hello_changed || gateway_was != share.gateway.active;
        drop(state);
        drop(share);
        self.forward.lock().expect("vpn forward lock").set_lans(forward_lans);
        changed
    }

    /// Syncs kernel routes to the TUN device with the table.
    fn sync_routes(&self) {
        let wanted = {
            let mut state = self.state.lock().expect("vpn lock");
            let wanted = state.table.installed();
            if wanted == state.installed {
                return;
            }
            state.installed = wanted.clone();
            wanted
        };
        self.routes.set(wanted);
    }

    pub fn status(&self) -> Status {
        let established = self.links.established();
        let share = self.share.lock().expect("vpn share lock");
        let state = self.state.lock().expect("vpn lock");
        let mut peers: Vec<PeerStatus> = state
            .table
            .peers()
            .map(|(peer, entry)| PeerStatus {
                peer: peer.clone(),
                tunnel: Some(entry.tunnel),
                state: if established.contains(peer) { "active" } else { "closed" },
                advertised: entry.advertised.clone(),
                counters: state.peers.get(peer).copied().unwrap_or_default(),
            })
            .collect();
        for peer in &established {
            if state.table.peer(peer).is_none() {
                peers.push(PeerStatus { peer: peer.clone(), tunnel: None, state: "pending", advertised: Vec::new(), counters: state.peers.get(peer).copied().unwrap_or_default() });
            }
        }
        peers.sort_by(|a, b| a.peer.cmp(&b.peer));
        Status {
            interface: self.config.interface.clone(),
            network: self.config.network,
            tunnel: state.table.me,
            mtu: self.config.mtu(),
            advertised: state.table.local.clone(),
            remote: state.table.remote_routes(),
            installed: state.installed.clone(),
            counters: state.counters,
            peers,
            last_error: state.last_error.clone(),
            share: share.settings.clone(),
            lans: share.lans.clone(),
            gateway: share.gateway.clone(),
            uplink: share.uplink.clone(),
            gateways: {
                let mut gateways: Vec<(String, Vec<Cidr>)> = share.gateways.iter().map(|(peer, (routes, _))| (peer.clone(), routes.clone())).collect();
                gateways.sort();
                gateways
            },
        }
    }

    /// The last tunnel packets, newest first.
    pub fn packets(&self, limit: usize) -> Vec<PacketLog> {
        self.state.lock().expect("vpn lock").log.iter().take(limit).copied().collect()
    }
}

/// Applies the newest sharing plan on its own thread, since the tools it runs are slow.
/// Restarts our own dnsmasq if it exits.
fn net_worker(interface: String, plans: Arc<Latest<Plan>>, vpn: Weak<Vpn>) {
    let mut applier = share::Applier::default();
    let mut logged = String::new();
    loop {
        let plan = plans.take(WORKER_POLL);
        let Some(lan_interfaces) = vpn.upgrade().map(|vpn| vpn.share.lock().expect("vpn share lock").settings.lan_interfaces.clone()) else { return };
        let Some(plan) = plan else {
            if let Err(error) = applier.tend(&lan_interfaces) {
                match vpn.upgrade() {
                    Some(vpn) => vpn.error(format!("sharing: {error}")),
                    None => return,
                }
            }
            continue;
        };
        match applier.apply(&interface, &plan, &lan_interfaces) {
            Ok(()) => {
                let summary = format!(
                    "{} client network(s), routes pushed by DHCP {}, gateway {}, uplink {}",
                    plan.dhcp.as_ref().map_or(0, |dhcp| dhcp.nets.len()),
                    plan.dhcp.as_ref().map_or("off".to_owned(), |dhcp| format!("{} ({}router)", dhcp.routes.len(), if dhcp.router { "" } else { "no " })),
                    if plan.nat_post.iter().any(|rule| rule.iter().any(|part| part == "MASQUERADE") && !rule.iter().any(|part| part == &interface)) { "on" } else { "off" },
                    if plan.uplink.is_some() { "on" } else { "off" },
                );
                // Remote routes changing alone is route churn.
                let level = if summary == logged { log::Level::Debug } else { log::Level::Info };
                log::log!(level, "vpn: sharing: {summary}");
                logged = summary;
            }
            Err(error) => match vpn.upgrade() {
                Some(vpn) => vpn.error(format!("sharing: {error}")),
                None => return,
            },
        }
    }
}

/// Routes to remove and to add to go from `applied` to `wanted`.
fn route_changes(applied: &BTreeSet<Cidr>, wanted: &BTreeSet<Cidr>) -> (Vec<Cidr>, Vec<Cidr>) {
    (applied.difference(wanted).copied().collect(), wanted.difference(applied).copied().collect())
}

/// Makes the kernel's routes match the newest wanted set on its own thread, so `ip` never
/// stalls packet handling. Sets that come while it works are merged into the next one.
fn route_worker(interface: String, wanted: Arc<Latest<BTreeSet<Cidr>>>, vpn: Weak<Vpn>) {
    let mut applied: BTreeSet<Cidr> = BTreeSet::new();
    loop {
        let Some(wanted) = wanted.take(WORKER_POLL) else {
            if vpn.strong_count() == 0 {
                return;
            }
            continue;
        };
        let (remove, add) = route_changes(&applied, &wanted);
        let mut errors: Vec<String> = Vec::new();
        // Removals first, so a prefix moving between peers never has two routes.
        for prefix in remove {
            if let Err(error) = tun::remove_route(&interface, &prefix) {
                errors.push(error.to_string());
            }
            applied.remove(&prefix);
        }
        for prefix in add {
            // One that fails is tried again with the next set.
            match tun::add_route(&interface, &prefix) {
                Ok(()) => {
                    log::debug!("vpn: route {prefix} via {interface}");
                    applied.insert(prefix);
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        if let Some(first) = errors.first() {
            match vpn.upgrade() {
                Some(vpn) => vpn.error(if errors.len() == 1 { first.clone() } else { format!("{first} (and {} more route errors)", errors.len() - 1) }),
                None => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_worker_gets_only_the_newest_value() {
        let latest = Latest::new();
        for n in 0..10_000 {
            latest.set(n);
        }
        assert_eq!(latest.take(Duration::ZERO), Some(9_999));
        assert_eq!(latest.take(Duration::from_millis(10)), None);
        let latest = Arc::new(latest);
        let setter = latest.clone();
        std::thread::spawn(move || setter.set(7));
        assert_eq!(latest.take(Duration::from_secs(5)), Some(7));
    }

    #[test]
    fn routes_change_by_difference() {
        let set = |prefixes: &[&str]| prefixes.iter().map(|prefix| prefix.parse().unwrap()).collect::<BTreeSet<Cidr>>();
        let (remove, add) = route_changes(&set(&["192.168.20.0/24", "192.168.30.0/24"]), &set(&["192.168.30.0/24", "192.168.40.0/24"]));
        assert_eq!(remove, vec!["192.168.20.0/24".parse().unwrap()]);
        assert_eq!(add, vec!["192.168.40.0/24".parse().unwrap()]);
        // A peer flapping between two sets many times while the worker was busy: one change.
        let latest = Latest::new();
        for n in 0..64 {
            latest.set(if n % 2 == 0 { set(&["192.168.20.0/24"]) } else { set(&["192.168.21.0/24"]) });
        }
        let (remove, add) = route_changes(&set(&["192.168.21.0/24"]), &latest.take(Duration::ZERO).unwrap());
        assert!(remove.is_empty() && add.is_empty());
    }
}
