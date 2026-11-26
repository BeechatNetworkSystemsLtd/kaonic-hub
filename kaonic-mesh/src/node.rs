//! This node on the mesh: one Reticulum transport, the radio under it, one
//! destination (`kaonic.node`) announced regularly, and the table of the nodes
//! heard announcing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reticulum::destination::{DestinationDesc, DestinationName};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{GroupRelayConfig, GroupRelayStats, NetworkProfile, TimerConfig, Transport, TransportConfig};
use tokio::sync::broadcast;

use crate::announce::{self, Announced, NodeInfo};
use crate::iface::{Counters, Neighbours, RadioInterface};
use crate::radio::RadioSocket;
use crate::settings::RadioSettings;
use crate::traffic::Traffic;

pub const APP_NAME: &str = "kaonic";
pub const ASPECT: &str = "node";
/// A node that heard nothing for this long was cut off. It announces soon after it hears
/// the air again ([`Mesh::announce_soon`]), so peers relink at once.
const SILENCE: Duration = Duration::from_secs(15);
/// Announces out of turn are sent at most this often.
const EARLY_ANNOUNCE_EVERY: Duration = Duration::from_secs(60);

/// GROUP packets are relayed only while they have travelled fewer hops than this (a relay
/// counts): three relays, so a packet reaches four hops out, as push-to-talk's ttl 4 did.
pub const GROUP_MAX_HOPS: u8 = 4;
/// Seconds between updates of the GROUP relay's neighbour count.
const NEIGHBOURS_EVERY: u64 = 10;

#[derive(Clone, Debug)]
pub struct MeshConfig {
    /// The radio interface to carry Reticulum (`rf09_a`: module A, sub-GHz).
    pub radio: String,
    /// Seconds between this node's announces (with up to 25 % jitter), after two quick ones at
    /// start. Every node rebroadcasts every announce, so on one shared channel announces cost
    /// about N² frames per interval: keep it long.
    pub announce_secs: u64,
    /// A node not heard from for this long is out of range: a few announce intervals, so one
    /// lost announce does not take a node offline.
    pub offline_secs: u64,
    /// Applied to the radio before the mesh starts; None leaves the driver as it is.
    pub settings: Option<crate::settings::RadioSettings>,
    /// A node not heard from for this long is forgotten (peer table and destination).
    pub forget_secs: u64,
    /// At most this many nodes are remembered; past it the longest unheard go first. Every
    /// announce from a new identity adds one, and identities cost an attacker nothing.
    pub max_peers: usize,
    /// Keepalive interval of each link, sent by the opener and answered by the peer: two
    /// frames per link and interval when idle.
    pub keepalive_secs: u64,
    /// A link that heard nothing from its peer for this long is closed and opened again;
    /// at least `keepalive_secs` + 4.
    pub link_dead_secs: u64,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self { radio: "rf09_a".into(), announce_secs: 120, offline_secs: 480, settings: None, forget_secs: 3600, max_peers: 512, keepalive_secs: 10, link_dead_secs: 20 }
    }
}

/// A node this one has heard of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Identity hash, 32 lowercase hex characters.
    pub id: String,
    pub destination: String,
    pub announced: Announced,
    pub hops: u8,
    /// The relay it was heard through (identity hash), when not a direct neighbour.
    pub via: Option<String>,
    /// For direct neighbours, the last announce's signal.
    pub rssi: Option<i8>,
    /// Unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
}

pub struct Mesh {
    transport: Arc<tokio::sync::Mutex<Transport>>,
    identity_hash: String,
    own_destination: AddressHash,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    /// Each peer's announced destination, for opening links to it.
    destinations: Arc<Mutex<HashMap<String, DestinationDesc>>>,
    counters: Arc<Mutex<Counters>>,
    traffic: Arc<Traffic>,
    /// What the driver has: read when the mesh started, updated when the band is reconfigured.
    settings: Mutex<Option<RadioSettings>>,
    info: Arc<Mutex<NodeInfo>>,
    updates: broadcast::Sender<Peer>,
    config: MeshConfig,
    /// The announcer and the announce listener, stopped by [`Mesh::stop`].
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    /// This start of the hub, as its announces say ([`announce::Boot`]).
    boot_id: u32,
    started: Instant,
    /// When each peer last announced, on the monotonic clock: the wall clock jumps when the
    /// hub learns the date.
    heard: Mutex<HashMap<String, Instant>>,
    /// Each peer's boot id and when (here) that start of it began.
    starts: Mutex<HashMap<String, (u32, Instant)>>,
    /// Wakes the announcer for an announce out of turn, and when it last was.
    early: Arc<tokio::sync::Notify>,
    last_early: Mutex<Option<Instant>>,
}

/// Link timers for a shared, lossy, half-duplex radio. Reticulum's defaults (a keepalive
/// every 5 s, closed after 15 s without one) cost a frame per link every 5 s and close links
/// whenever two keepalives in a row are lost.
///
/// With the defaults (10 s, 20 s): a keepalive every 10 s (±10 %); stale after 12 s of
/// silence, then a probe every 2 s; closed 20 s after the peer was last heard. The other
/// side closes after 24 s. An unanswered link request is repeated after 3 s, then 6 and 8 s.
///
/// Neighbours hear an announce at the same moment, so rebroadcasts wait up to 0.5 s and path
/// responses up to 1.5 s, and link timers vary by 10 %; otherwise relays that cannot hear
/// each other collide. A path not refreshed for 10 minutes takes an older announce, from a
/// node that rebooted with its clock behind.
fn radio_timers(config: &MeshConfig) -> TimerConfig {
    let keep = config.keepalive_secs.max(1);
    let dead = config.link_dead_secs.max(keep + 4);
    let stale = Duration::from_secs(keep + 2);
    let close = Duration::from_secs(dead) - stale;
    TimerConfig {
        out_link_keep: Duration::from_secs(keep),
        out_link_stale: stale,
        out_link_close: close,
        out_link_probe: (close / 4).max(Duration::from_secs(1)),
        // a lost request costs 3 s, not 6; a peer out of reach one request every 8 s
        out_link_repeat: Duration::from_secs(3),
        out_link_repeat_max: Duration::from_secs(8),
        in_link_stale: Duration::from_secs(dead - 4),
        in_link_close: Duration::from_secs(8),
        jitter_percent: 10,
        rebroadcast_window: Duration::from_millis(500),
        path_response_window: Duration::from_millis(1500),
        path_refresh: Some(Duration::from_secs(600)),
        ..TimerConfig::default()
    }
}

pub fn hex(hash: &AddressHash) -> String {
    hash.as_slice().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs() as i64)
}

impl Mesh {
    /// Starts the transport on the radio and begins announcing. Must run inside a tokio runtime.
    pub async fn start(identity: PrivateIdentity, info: NodeInfo, config: MeshConfig) -> std::io::Result<Arc<Self>> {
        let settings = if crate::radio::is_emulated(&config.radio) {
            // The air emulator has no driver to set; it times frames like the fielded default.
            Some(config.settings.unwrap_or_else(crate::settings::RadioSettings::sub_ghz_default))
        } else {
            if let Some(settings) = &config.settings {
                let written = crate::settings::apply(&crate::settings::sysfs_dir(&config.radio), settings)?;
                if !written.is_empty() {
                    log::info!("radio {}: set {}", config.radio, written.join(", "));
                }
            }
            crate::settings::read(&crate::settings::sysfs_dir(&config.radio))
                .inspect_err(|error| log::warn!("radio {}: cannot read its settings: {error}", config.radio))
                .ok()
        };
        let socket = RadioSocket::open(&config.radio)?;
        let identity_hash = hex(identity.address_hash());
        let mut transport = TransportConfig::new("kaonic-hub", &identity)
            .set_retransmit(true)
            .set_network_profile(NetworkProfile::MultiHop)
            .set_timer_config(radio_timers(&config))
            // a stale link still carries data, and its path is replaced or asked for again
            .set_link_recovery(true)
            // GROUP packets (push-to-talk, plugin broadcasts) reach nodes several hops away:
            // relayed once by each node after a random wait, unless enough neighbours already did
            .set_group_forwarding(true)
            .set_group_relay(GroupRelayConfig::shared_medium(GROUP_MAX_HOPS))
            .build();
        let destination = transport.add_destination(identity, DestinationName::new(APP_NAME, ASPECT)).await;
        let own_destination = destination.lock().await.desc.address_hash;

        let neighbours: Neighbours = Arc::default();
        let counters: Arc<Mutex<Counters>> = Arc::default();
        let traffic: Arc<Traffic> = Arc::default();
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(RadioInterface::new(socket, neighbours.clone(), counters.clone(), traffic.clone(), settings), RadioInterface::spawn);

        let (updates, _) = broadcast::channel(64);
        let mesh = Arc::new(Self {
            transport: Arc::new(tokio::sync::Mutex::new(transport)),
            identity_hash,
            own_destination,
            peers: Arc::default(),
            destinations: Arc::default(),
            counters,
            traffic,
            settings: Mutex::new(settings),
            info: Arc::new(Mutex::new(info)),
            updates,
            config: config.clone(),
            tasks: Mutex::default(),
            boot_id: rand::random(),
            started: Instant::now(),
            heard: Mutex::default(),
            starts: Mutex::default(),
            early: Arc::new(tokio::sync::Notify::new()),
            last_early: Mutex::default(),
        });

        // Announce now, again after about 5 and 15 s (neighbours learn a restarted node quickly
        // although a frame is lost), then regularly. Jitter keeps neighbours that booted together
        // from colliding. A node that was cut off announces again soon after it hears the air.
        let announcer = mesh.clone();
        let early = mesh.early.clone();
        let announcing = tokio::spawn(async move {
            let mut quick = [5, 10].into_iter();
            loop {
                let boot = announce::Boot { id: announcer.boot_id, uptime_secs: u32::try_from(announcer.started.elapsed().as_secs()).unwrap_or(u32::MAX) };
                let data = announce::encode_with_boot(&announcer.info.lock().expect("info lock"), Some(boot));
                announcer.transport.lock().await.send_announce(&destination, Some(&data)).await;
                let secs = quick.next().unwrap_or(announcer.config.announce_secs).min(announcer.config.announce_secs);
                let jitter = rand::random::<u64>() % (secs * 250 + 1);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(secs * 1000 + jitter)) => {}
                    _ = early.notified() => {
                        tokio::time::sleep(Duration::from_millis(300 + rand::random::<u64>() % 1200)).await;
                    }
                }
            }
        });
        let watcher = mesh.clone();
        let watching = tokio::spawn(async move {
            let mut last = (watcher.counters().rx_packets, Instant::now());
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut ticks: u64 = 0;
            loop {
                tick.tick().await;
                if ticks % NEIGHBOURS_EVERY == 0 {
                    watcher.update_group_neighbours().await;
                }
                ticks += 1;
                let heard = watcher.counters().rx_packets;
                if heard == last.0 {
                    continue;
                }
                let silent = last.1.elapsed() >= SILENCE;
                last = (heard, Instant::now());
                if silent {
                    log::debug!("mesh: hearing the air again after {} s of silence", SILENCE.as_secs());
                    watcher.announce_soon();
                }
            }
        });

        // Learn nodes from their announces.
        let listener = mesh.clone();
        let mut announces = mesh.transport.lock().await.recv_announces().await;
        let listening = tokio::spawn(async move {
            loop {
                let event = match announces.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        log::warn!("mesh: missed {missed} announces");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let (id, destination) = {
                    let destination = event.destination.lock().await;
                    let id = hex(&destination.desc.identity.address_hash);
                    listener.destinations.lock().expect("destinations lock").insert(id.clone(), destination.desc);
                    (id, destination.desc.address_hash)
                };
                // The name tells a hub from anything else that happens to announce.
                let announced = announce::decode(event.app_data.as_slice());
                listener.heard.lock().expect("heard lock").insert(id.clone(), Instant::now());
                if let Some(boot) = announce::boot_of(event.app_data.as_slice()) {
                    listener.note_boot(&id, boot);
                }
                // The announce is verified now: its first-hand signal moves into the peer table.
                let heard = neighbours.lock().expect("neighbours lock").remove(&destination).map(|(rssi, _)| rssi);
                let rssi = (event.hops == 0).then_some(heard).flatten();
                let peer = {
                    let mut peers = listener.peers.lock().expect("peers lock");
                    let first_seen = peers.get(&id).map_or_else(now, |known| known.first_seen);
                    let peer = Peer {
                        id: id.clone(),
                        destination: hex(&destination),
                        announced,
                        hops: event.hops,
                        via: event.transport_id.as_ref().map(hex),
                        rssi,
                        first_seen,
                        last_seen: now(),
                    };
                    peers.insert(id, peer.clone());
                    peer
                };
                listener.prune();
                log::debug!("mesh: heard {} ({} hops, rssi {:?})", peer.id, peer.hops, peer.rssi);
                let _ = listener.updates.send(peer);
            }
        });
        mesh.tasks.lock().expect("tasks lock").extend([announcing.abort_handle(), listening.abort_handle(), watching.abort_handle()]);
        Ok(mesh)
    }

    /// Stops announcing and takes the radio off the transport, as if the process ended (tests
    /// restart nodes in-process).
    pub async fn stop(&self) {
        for task in self.tasks.lock().expect("tasks lock").drain(..) {
            task.abort();
        }
        self.transport.lock().await.iface_manager().lock().await.shutdown();
    }

    /// Announces within a second or two, at most once per `EARLY_ANNOUNCE_EVERY`, so relays
    /// and peers learn this node's path again.
    pub fn announce_soon(&self) {
        let mut last = self.last_early.lock().expect("early lock");
        if last.is_some_and(|at| at.elapsed() < EARLY_ANNOUNCE_EVERY) {
            return;
        }
        *last = Some(Instant::now());
        self.early.notify_one();
    }

    /// When `peer` announced from a new start (or the first time): when that start began here.
    /// The estimate from an announce that travelled longer is later, so the earliest one of
    /// a start is kept.
    fn note_boot(&self, peer: &str, boot: announce::Boot) {
        let Some(began) = Instant::now().checked_sub(Duration::from_secs(u64::from(boot.uptime_secs))) else { return };
        let mut starts = self.starts.lock().expect("starts lock");
        match starts.get_mut(peer) {
            Some((id, at)) if *id == boot.id => *at = (*at).min(began),
            Some(known) => {
                log::info!("mesh: {peer} restarted {} s ago", boot.uptime_secs);
                *known = (boot.id, began);
            }
            None => {
                starts.insert(peer.to_owned(), (boot.id, began));
            }
        }
    }

    /// When the running start of `peer` began, as far as its announces tell (on this node's
    /// monotonic clock; None for a hub too old to say).
    pub fn started_of(&self, peer: &str) -> Option<Instant> {
        self.starts.lock().expect("starts lock").get(peer).map(|(_, at)| *at)
    }

    /// How long ago `peer` was last heard announcing.
    fn unheard_for(&self, peer: &Peer) -> Duration {
        match self.heard.lock().expect("heard lock").get(&peer.id) {
            Some(at) => at.elapsed(),
            None => Duration::from_secs(u64::try_from(now() - peer.last_seen).unwrap_or(0)),
        }
    }

    /// Forgets nodes unheard for `forget_secs`, and the longest unheard past `max_peers`.
    fn prune(&self) {
        let forget = Duration::from_secs(self.config.forget_secs);
        let gone: Vec<String> = {
            let mut peers = self.peers.lock().expect("peers lock");
            let mut gone: Vec<String> = peers.values().filter(|peer| self.unheard_for(peer) > forget).map(|peer| peer.id.clone()).collect();
            let excess = (peers.len() - gone.len()).saturating_sub(self.config.max_peers);
            if excess > 0 {
                let mut remaining: Vec<(&String, i64)> = peers.iter().filter(|(id, _)| !gone.contains(id)).map(|(id, peer)| (id, peer.last_seen)).collect();
                remaining.sort_by_key(|(_, last_seen)| *last_seen);
                gone.extend(remaining.into_iter().take(excess).map(|(id, _)| id.clone()));
            }
            for id in &gone {
                peers.remove(id);
            }
            gone
        };
        if !gone.is_empty() {
            let mut destinations = self.destinations.lock().expect("destinations lock");
            let (mut heard, mut starts) = (self.heard.lock().expect("heard lock"), self.starts.lock().expect("starts lock"));
            for id in &gone {
                destinations.remove(id);
                heard.remove(id);
                starts.remove(id);
            }
            log::debug!("mesh: forgot {} nodes", gone.len());
        }
    }

    /// The announced destination of the peer `id`.
    pub fn destination_of(&self, id: &str) -> Option<DestinationDesc> {
        self.destinations.lock().expect("destinations lock").get(id).copied()
    }

    /// The peer's public keys as it announced them: X25519 then Ed25519.
    pub fn public_keys(&self, id: &str) -> Option<([u8; 32], [u8; 32])> {
        let desc = self.destination_of(id)?;
        Some((desc.identity.public_key.to_bytes(), desc.identity.verifying_key.to_bytes()))
    }

    pub fn identity_hash(&self) -> &str {
        &self.identity_hash
    }

    /// Every node heard of, most recently heard first.
    pub fn peers(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self.peers.lock().expect("peers lock").values().cloned().collect();
        peers.sort_by_key(|peer| std::cmp::Reverse(peer.last_seen));
        peers
    }

    /// Tells the GROUP relay how many direct neighbours are online, so a node bridging two
    /// groups still relays when only one side has the packet already.
    async fn update_group_neighbours(&self) {
        let direct = self.peers().iter().filter(|peer| peer.via.is_none() && self.is_online(peer)).count();
        self.transport.lock().await.set_group_neighbours(u8::try_from(direct).unwrap_or(u8::MAX));
    }

    /// GROUP packets relayed by this node, and relays cancelled by copies from others.
    pub async fn group_relay_stats(&self) -> GroupRelayStats {
        self.transport.lock().await.group_relay_stats()
    }

    pub fn is_online(&self, peer: &Peer) -> bool {
        self.unheard_for(peer) <= Duration::from_secs(self.config.offline_secs)
    }

    /// Each peer as it is heard again.
    pub fn subscribe(&self) -> broadcast::Receiver<Peer> {
        self.updates.subscribe()
    }

    /// What this node announces about itself.
    pub fn info(&self) -> NodeInfo {
        self.info.lock().expect("info lock").clone()
    }

    /// What the next announces say (new codename, provisioned…).
    pub fn set_info(&self, info: NodeInfo) {
        *self.info.lock().expect("info lock") = info;
    }

    pub fn counters(&self) -> Counters {
        self.counters.lock().expect("counters lock").clone()
    }

    /// Every frame sent and heard.
    pub fn traffic(&self) -> &Traffic {
        &self.traffic
    }

    /// The radio interface carrying the mesh, e.g. `rf09_b`.
    pub fn radio(&self) -> &str {
        &self.config.radio
    }

    pub fn radio_settings(&self) -> Option<RadioSettings> {
        *self.settings.lock().expect("settings lock")
    }

    /// After the mesh band was reconfigured (frequency, bit rate for airtime).
    pub fn set_radio_settings(&self, settings: Option<RadioSettings>) {
        *self.settings.lock().expect("settings lock") = settings;
    }

    /// The node whose announced destination this is (this node's own included).
    pub fn owner_of(&self, destination: &AddressHash) -> Option<String> {
        if *destination == self.own_destination {
            return Some(self.identity_hash.clone());
        }
        let destinations = self.destinations.lock().expect("destinations lock");
        destinations.iter().find(|(_, desc)| desc.address_hash == *destination).map(|(id, _)| id.clone())
    }

    pub fn transport(&self) -> &Arc<tokio::sync::Mutex<Transport>> {
        &self.transport
    }
}
