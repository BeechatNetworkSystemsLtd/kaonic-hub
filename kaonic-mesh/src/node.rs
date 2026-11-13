//! This node on the mesh: one Reticulum transport, the radio under it, one
//! destination (`kaonic.node`) announced regularly, and the table of the nodes
//! heard announcing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reticulum::destination::{DestinationDesc, DestinationName};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{NetworkProfile, TimerConfig, Transport, TransportConfig};
use tokio::sync::broadcast;

use crate::announce::{self, Announced, NodeInfo};
use crate::iface::{Counters, Neighbours, RadioInterface};
use crate::radio::RadioSocket;
use crate::settings::RadioSettings;
use crate::traffic::Traffic;

pub const APP_NAME: &str = "kaonic";
pub const ASPECT: &str = "node";

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
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self { radio: "rf09_a".into(), announce_secs: 120, offline_secs: 480, settings: None, forget_secs: 3600, max_peers: 512 }
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
}

/// Link timers for a shared, lossy, half-duplex radio. Reticulum's defaults (a keepalive
/// every 5 s, closed after 15 s without one) cost a frame per link every 5 s and close links
/// whenever two keepalives in a row are lost.
fn radio_timers() -> TimerConfig {
    TimerConfig {
        out_link_keep: Duration::from_secs(10),
        // a lost request or proof costs a few seconds, not six (RTT is about 40 ms a hop)
        out_link_repeat: Duration::from_secs(3),
        out_link_stale: Duration::from_secs(40),
        out_link_close: Duration::from_secs(20),
        in_link_stale: Duration::from_secs(40),
        in_link_close: Duration::from_secs(20),
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
            .set_timer_config(radio_timers())
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
        });

        // Announce now, again after about 5 and 15 s (neighbours learn a restarted node quickly
        // although a frame is lost), then regularly. Jitter keeps neighbours that booted together
        // from colliding.
        let announcer = mesh.clone();
        tokio::spawn(async move {
            let mut quick = [5, 10].into_iter();
            loop {
                let data = announce::encode(&announcer.info.lock().expect("info lock"));
                announcer.transport.lock().await.send_announce(&destination, Some(&data)).await;
                let secs = quick.next().unwrap_or(announcer.config.announce_secs).min(announcer.config.announce_secs);
                let jitter = rand::random::<u64>() % (secs * 250 + 1);
                tokio::time::sleep(Duration::from_millis(secs * 1000 + jitter)).await;
            }
        });

        // Learn nodes from their announces.
        let listener = mesh.clone();
        let mut announces = mesh.transport.lock().await.recv_announces().await;
        tokio::spawn(async move {
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
        Ok(mesh)
    }

    /// Forgets nodes unheard for `forget_secs`, and the longest unheard past `max_peers`.
    fn prune(&self) {
        let now = now();
        let forget = i64::try_from(self.config.forget_secs).unwrap_or(i64::MAX);
        let gone: Vec<String> = {
            let mut peers = self.peers.lock().expect("peers lock");
            let mut gone: Vec<String> = peers.values().filter(|peer| now - peer.last_seen > forget).map(|peer| peer.id.clone()).collect();
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
            for id in &gone {
                destinations.remove(id);
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

    pub fn is_online(&self, peer: &Peer) -> bool {
        now() - peer.last_seen <= self.config.offline_secs as i64
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
