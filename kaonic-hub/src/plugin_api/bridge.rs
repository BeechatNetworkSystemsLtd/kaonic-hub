//! The mesh bridge: plugins' messages over the hub's authenticated links and the GROUP
//! channel ([`super::wire`] is the format).
//!
//! A plugin reaches only the same plugin on other nodes. Plugins come last on the air:
//! each has an airtime budget (a token bucket, [`DEFAULT_SHARE`] of the channel by default),
//! a bounded queue (the oldest message goes first when it is full) and waits while the
//! channel is busy with the hub's own traffic. A plugin counts as running on the mesh while
//! its event socket is open; hubs tell each other which plugins run on their side.
//!
//! Nothing is delivered on a mesh hash two installed plugins share. A broadcast heard twice
//! (the same sender and nonce, within [`SEEN_FOR`]) is dropped. Counts per node are kept for
//! linked nodes only (at most [`MAX_NODES`]); everyone else is counted as [`OTHER`].
//!
//! [`Bridge`] is the state and decisions, without I/O; [`spawn`] connects it to the links.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kaonic_mesh::settings::RadioSettings;
use kaonic_mux::{Kind, Message};
use serde::Serialize;
use tokio::sync::{Notify, broadcast};

use super::wire;
use crate::app::App;

/// Messages waiting per plugin; more drop the oldest.
pub const QUEUE: usize = 64;
/// Event sockets one plugin may hold open.
pub const MAX_EVENT_SOCKETS: usize = 4;
/// Nodes counted one by one in a plugin's stats.
pub const MAX_NODES: usize = 64;
/// The stats entry for every node that is not linked.
pub const OTHER: &str = "other";
/// Broadcasts remembered, against replays: this many, for this long.
const SEEN: usize = 4096;
pub const SEEN_FOR: Duration = Duration::from_secs(30 * 60);
/// The link packet the hub's links carry (one radio frame over relays).
pub const LINK_PACKET: usize = 799;
/// A plugin's share of the channel unless set otherwise.
pub const DEFAULT_SHARE: f64 = 0.10;
/// A message waiting longer than this is dropped as over budget.
const STALE: Duration = Duration::from_secs(30);
/// Reticulum's bytes around a link payload, counted in airtime.
const LINK_OVERHEAD: usize = 83;
/// The rate assumed while the radio's settings are not known.
const NOMINAL_BPS: u64 = 100_000;
/// Above this the channel is the hub's: plugins wait.
const PAUSE_ABOVE: f64 = 0.9;
/// Plugins are told to slow down above this.
const CONGESTED: f64 = 0.7;
/// The largest GROUP payload of one radio frame (`GroupChannel::max_payload`).
const GROUP_PAYLOAD: usize = 814;

/// The largest message to one node: one link packet.
pub fn max_message() -> usize {
    kaonic_mux::max_payload(LINK_PACKET) - wire::DATA_HEADER
}

/// The largest broadcast: one GROUP packet.
pub fn max_broadcast() -> usize {
    GROUP_PAYLOAD - wire::BROADCAST_HEADER
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Node(String),
    Broadcast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    QueueFull,
    TooLarge,
    NoLink,
    OverBudget,
    NotRunning,
    /// Another installed plugin has the same mesh hash.
    Ambiguous,
}

/// What a plugin hears on its event socket.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Received {
        from: String,
        channel: u8,
        /// Base64.
        data: String,
        broadcast: bool,
        rssi: Option<i8>,
    },
    NodeUp { node: String },
    NodeDown { node: String },
    PluginUp { node: String },
    PluginDown { node: String },
    Sent { id: u64, node: Option<String> },
    Dropped { id: u64, node: Option<String>, reason: Reason },
    Congestion { level: f64 },
}

/// A message waiting to go.
#[derive(Clone, Debug)]
pub struct Pending {
    pub id: u64,
    pub plugin: String,
    pub hash: u64,
    pub to: Target,
    pub channel: u8,
    pub data: Vec<u8>,
    queued: Instant,
}

impl Pending {
    fn node(&self) -> Option<String> {
        match &self.to {
            Target::Node(node) => Some(node.clone()),
            Target::Broadcast => None,
        }
    }
}

pub enum Next {
    Ready(Pending),
    /// Something waits for its budget, or for the channel.
    Wait(Duration),
    Idle,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub airtime_ms: u64,
    pub queue: usize,
    /// The budget: this plugin's share of the channel, 0-1.
    pub airtime_share: f64,
    pub per_node: BTreeMap<String, Counts>,
}

struct Local {
    hash: u64,
    mesh: bool,
    sockets: usize,
    events: broadcast::Sender<Event>,
    queue: VecDeque<Pending>,
    /// Airtime it may use now, in microseconds.
    tokens: f64,
    refilled: Option<Instant>,
    airtime_us: u64,
    stats: Stats,
}

impl Local {
    fn new(id: &str) -> Self {
        Self {
            hash: wire::id_hash(id),
            mesh: false,
            sockets: 0,
            events: broadcast::channel(256).0,
            queue: VecDeque::new(),
            tokens: f64::MAX,
            refilled: None,
            airtime_us: 0,
            stats: Stats::default(),
        }
    }

    /// Running on the mesh: it may use it and listens.
    fn listening(&self) -> bool {
        self.mesh && self.sockets > 0
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    /// The counts of `node`: its own if it is linked and there is room, else [`OTHER`]'s.
    fn counts(&mut self, linked: &HashSet<String>, node: &str) -> &mut Counts {
        let own = linked.contains(node) && (self.stats.per_node.contains_key(node) || self.stats.per_node.len() < MAX_NODES);
        let key = if own { node } else { OTHER };
        self.stats.per_node.entry(key.to_owned()).or_default()
    }

    fn count_dropped(&mut self, linked: &HashSet<String>, node: Option<&str>) {
        self.stats.dropped += 1;
        if let Some(node) = node {
            self.counts(linked, node).dropped += 1;
        }
    }
}

struct State {
    me: Option<[u8; 16]>,
    share: f64,
    settings: Option<RadioSettings>,
    plugins: BTreeMap<String, Local>,
    /// What each linked node said runs there.
    remote: HashMap<String, HashSet<u64>>,
    /// How many installed plugins have each mesh hash; None until the list is known.
    installed: Option<HashMap<u64, usize>>,
    /// Broadcasts heard lately, by sender and nonce, oldest first.
    seen: HashSet<([u8; 16], u64)>,
    seen_order: VecDeque<(Instant, [u8; 16], u64)>,
    linked: HashSet<String>,
    next_id: u64,
    congestion: f64,
    /// The level plugins were last told.
    told: f64,
    turn: usize,
    /// Messages for plugins that do not run here.
    unrouted: u64,
}

pub struct Bridge {
    state: Mutex<State>,
    /// Something was queued.
    wake: Notify,
    /// The set of plugins running here changed.
    advertise: Notify,
}

impl Bridge {
    pub fn new(share: f64) -> Self {
        let state = State {
            me: None,
            share: share.clamp(0.0, 1.0),
            settings: None,
            plugins: BTreeMap::new(),
            remote: HashMap::new(),
            installed: None,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            linked: HashSet::new(),
            next_id: 1,
            congestion: 0.0,
            told: 0.0,
            turn: 0,
            unrouted: 0,
        };
        Self { state: Mutex::new(state), wake: Notify::new(), advertise: Notify::new() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("bridge lock")
    }

    /// This node's id (32 hex), the sender of its broadcasts.
    pub fn set_node(&self, id: &str) {
        self.lock().me = wire::node_bytes(id);
    }

    /// The radio's settings, for airtime.
    pub fn set_radio(&self, settings: Option<RadioSettings>) {
        self.lock().settings = settings;
    }

    pub fn share(&self) -> f64 {
        self.lock().share
    }

    /// An event socket of `plugin` opened; `mesh` is its permission. None if it holds
    /// [`MAX_EVENT_SOCKETS`] already.
    pub fn attach(&self, plugin: &str, mesh: bool) -> Option<broadcast::Receiver<Event>> {
        let mut state = self.lock();
        let local = state.plugins.entry(plugin.to_owned()).or_insert_with(|| Local::new(plugin));
        if local.sockets >= MAX_EVENT_SOCKETS {
            return None;
        }
        let was = local.listening();
        local.mesh = mesh;
        local.sockets += 1;
        let receiver = local.events.subscribe();
        if local.listening() != was {
            self.advertise.notify_one();
        }
        Some(receiver)
    }

    /// One of its event sockets closed.
    pub fn detach(&self, plugin: &str) {
        let mut state = self.lock();
        let Some(local) = state.plugins.get_mut(plugin) else { return };
        let was = local.listening();
        local.sockets = local.sockets.saturating_sub(1);
        if local.listening() != was {
            self.advertise.notify_one();
        }
    }

    /// The plugins installed here, from the installer's list. Forgets plugins no longer in it.
    pub fn set_installed<'a>(&self, ids: impl IntoIterator<Item = &'a str>) {
        let ids: HashSet<&str> = ids.into_iter().collect();
        let mut counts = HashMap::new();
        for id in &ids {
            *counts.entry(wire::id_hash(id)).or_insert(0) += 1;
        }
        let mut state = self.lock();
        state.installed = Some(counts);
        let before = state.plugins.len();
        state.plugins.retain(|id, _| ids.contains(id.as_str()));
        if state.plugins.len() != before {
            self.advertise.notify_one();
        }
    }

    /// A plugin was removed: its queue, stats and sockets' state go.
    pub fn forget(&self, plugin: &str) {
        if self.lock().plugins.remove(plugin).is_some() {
            self.advertise.notify_one();
        }
    }

    /// Whether `hash` names more than one plugin here.
    fn ambiguous(state: &State, hash: u64) -> bool {
        let installed = state.installed.as_ref().and_then(|counts| counts.get(&hash)).copied().unwrap_or(0);
        installed > 1 || state.plugins.values().filter(|local| local.hash == hash).count() > 1
    }

    /// The plugins running here on the mesh, as their hashes.
    pub fn running(&self) -> Vec<u64> {
        let state = self.lock();
        let mut hashes: Vec<u64> = state.plugins.values().filter(|local| local.listening() && !Self::ambiguous(&state, local.hash)).map(|local| local.hash).collect();
        hashes.sort_unstable();
        hashes.dedup();
        hashes
    }

    /// Nodes with an authenticated link.
    pub fn linked(&self) -> Vec<String> {
        let mut nodes: Vec<String> = self.lock().linked.iter().cloned().collect();
        nodes.sort();
        nodes
    }

    /// Whether `node` said `plugin` runs there.
    pub fn runs(&self, node: &str, plugin: &str) -> bool {
        let state = self.lock();
        let hash = wire::id_hash(plugin);
        !Self::ambiguous(&state, hash) && state.remote.get(node).is_some_and(|hashes| hashes.contains(&hash))
    }

    /// Queues a message of `plugin` to each of `to`; one id for all. Refused whole if too large.
    pub fn send(&self, plugin: &str, to: Vec<Target>, channel: u8, data: Vec<u8>) -> Result<u64, Reason> {
        self.send_at(plugin, to, channel, data, Instant::now())
    }

    fn send_at(&self, plugin: &str, to: Vec<Target>, channel: u8, data: Vec<u8>, now: Instant) -> Result<u64, Reason> {
        let limit = if to.contains(&Target::Broadcast) { max_broadcast() } else { max_message() };
        if data.len() > limit {
            return Err(Reason::TooLarge);
        }
        let mut state = self.lock();
        let state = &mut *state;
        if Self::ambiguous(state, wire::id_hash(plugin)) {
            return Err(Reason::Ambiguous);
        }
        let id = state.next_id;
        state.next_id += 1;
        let local = state.plugins.entry(plugin.to_owned()).or_insert_with(|| Local::new(plugin));
        for target in to {
            local.queue.push_back(Pending { id, plugin: plugin.to_owned(), hash: local.hash, to: target, channel, data: data.clone(), queued: now });
            if local.queue.len() > QUEUE
                && let Some(old) = local.queue.pop_front()
            {
                local.count_dropped(&state.linked, old.node().as_deref());
                local.emit(Event::Dropped { id: old.id, node: old.node(), reason: Reason::QueueFull });
            }
        }
        local.stats.queue = local.queue.len();
        self.wake.notify_one();
        Ok(id)
    }

    /// Airtime of a message of `bytes`, in microseconds.
    fn cost(settings: &Option<RadioSettings>, bytes: usize) -> u64 {
        let on_air = bytes + LINK_OVERHEAD;
        match settings.map(|settings| settings.airtime_us(on_air)).filter(|airtime| *airtime > 0) {
            Some(airtime) => airtime,
            None => 1080 + (on_air as u64 * 8 * 1_000_000).div_ceil(NOMINAL_BPS),
        }
    }

    /// The next message allowed on the air now, in turn between plugins.
    pub fn next(&self, now: Instant) -> Next {
        let mut state = self.lock();
        let state = &mut *state;
        let rate = state.share * 1_000_000.0;
        let capacity = (2.0 * rate).max(2.0 * Self::cost(&state.settings, LINK_PACKET) as f64);
        let busy = state.congestion > PAUSE_ABOVE;
        let ids: Vec<String> = state.plugins.iter().filter(|(_, local)| !local.queue.is_empty()).map(|(id, _)| id.clone()).collect();
        if ids.is_empty() {
            return Next::Idle;
        }
        let mut wait: Option<Duration> = None;
        for offset in 0..ids.len() {
            let id = &ids[(state.turn + offset) % ids.len()];
            let local = state.plugins.get_mut(id).expect("listed above");
            // Too old: dropped as over its budget.
            while local.queue.front().is_some_and(|pending| now.saturating_duration_since(pending.queued) > STALE) {
                let old = local.queue.pop_front().expect("checked");
                local.count_dropped(&state.linked, old.node().as_deref());
                local.emit(Event::Dropped { id: old.id, node: old.node(), reason: Reason::OverBudget });
            }
            let Some(front) = local.queue.front() else { continue };
            let elapsed = local.refilled.map_or(0.0, |at| now.saturating_duration_since(at).as_secs_f64());
            local.tokens = (local.tokens + rate * elapsed).min(capacity);
            local.refilled = Some(now);
            let cost = Self::cost(&state.settings, front.data.len() + wire::DATA_HEADER) as f64;
            if busy || local.tokens < cost {
                let needed = if busy || rate <= 0.0 { 0.1 } else { (cost - local.tokens) / rate };
                let needed = Duration::from_secs_f64(needed.clamp(0.001, 1.0));
                wait = Some(wait.map_or(needed, |wait| wait.min(needed)));
                continue;
            }
            local.tokens -= cost;
            local.airtime_us += cost as u64;
            local.stats.airtime_ms = local.airtime_us / 1000;
            let pending = local.queue.pop_front().expect("checked");
            local.stats.queue = local.queue.len();
            state.turn = state.turn.wrapping_add(offset + 1);
            return Next::Ready(pending);
        }
        wait.map_or(Next::Idle, Next::Wait)
    }

    /// After a message went out (or could not).
    pub fn finished(&self, pending: &Pending, sent: bool) {
        let mut state = self.lock();
        let state = &mut *state;
        let Some(local) = state.plugins.get_mut(&pending.plugin) else { return };
        let node = pending.node();
        if sent {
            local.stats.sent += 1;
            local.stats.bytes_sent += pending.data.len() as u64;
            if let Some(node) = &node {
                local.counts(&state.linked, node).sent += 1;
            }
            local.emit(Event::Sent { id: pending.id, node });
        } else {
            local.count_dropped(&state.linked, node.as_deref());
            local.emit(Event::Dropped { id: pending.id, node, reason: Reason::NoLink });
        }
    }

    /// A frame on the plugin stream from `peer`.
    pub fn on_frame(&self, peer: &str, kind: Kind, payload: &[u8], rssi: Option<i8>) {
        match kind {
            Kind::Data => {
                if let Some((plugin, channel, data)) = wire::decode_data(payload) {
                    self.deliver(peer, plugin, channel, data, false, rssi);
                }
            }
            Kind::Control => {
                if let Some(hashes) = wire::decode_running(payload) {
                    self.remote_running(peer, hashes.into_iter().collect());
                }
            }
        }
    }

    /// A packet heard on the GROUP channel; false if it is not a plugin's.
    pub fn on_group(&self, packet: &[u8], rssi: Option<i8>) -> bool {
        self.on_group_at(packet, rssi, Instant::now())
    }

    fn on_group_at(&self, packet: &[u8], rssi: Option<i8>, now: Instant) -> bool {
        let Some(heard) = wire::decode_broadcast(packet) else { return false };
        if self.lock().me == Some(heard.sender) || !self.first_time(heard.sender, heard.nonce, now) {
            return true;
        }
        self.deliver(&wire::node_hex(&heard.sender), heard.plugin, heard.channel, heard.data, true, rssi);
        true
    }

    /// Remembers a broadcast; false if it was heard already (a replay, or a relayed copy).
    fn first_time(&self, sender: [u8; 16], nonce: u64, now: Instant) -> bool {
        let mut state = self.lock();
        let state = &mut *state;
        while let Some(&(at, old_sender, old_nonce)) = state.seen_order.front() {
            if state.seen_order.len() < SEEN && now.saturating_duration_since(at) < SEEN_FOR {
                break;
            }
            state.seen_order.pop_front();
            state.seen.remove(&(old_sender, old_nonce));
        }
        if !state.seen.insert((sender, nonce)) {
            return false;
        }
        state.seen_order.push_back((now, sender, nonce));
        true
    }

    fn deliver(&self, from: &str, plugin: u64, channel: u8, data: &[u8], broadcast: bool, rssi: Option<i8>) {
        let mut state = self.lock();
        let state = &mut *state;
        if Self::ambiguous(state, plugin) {
            state.unrouted += 1;
            return;
        }
        let Some(local) = state.plugins.values_mut().find(|local| local.hash == plugin && local.mesh) else {
            state.unrouted += 1;
            return;
        };
        if !local.listening() {
            local.count_dropped(&state.linked, Some(from));
            return;
        }
        local.stats.received += 1;
        local.stats.bytes_received += data.len() as u64;
        local.counts(&state.linked, from).received += 1;
        local.emit(Event::Received { from: from.to_owned(), channel, data: kaonic_hub_common::base64::encode(data), broadcast, rssi });
    }

    fn remote_running(&self, peer: &str, now: HashSet<u64>) {
        let mut state = self.lock();
        let before = state.remote.insert(peer.to_owned(), now.clone()).unwrap_or_default();
        for local in state.plugins.values().filter(|local| local.listening()) {
            match (before.contains(&local.hash), now.contains(&local.hash)) {
                (false, true) => local.emit(Event::PluginUp { node: peer.to_owned() }),
                (true, false) => local.emit(Event::PluginDown { node: peer.to_owned() }),
                _ => {}
            }
        }
    }

    /// A link came up or went down.
    pub fn link_changed(&self, peer: &str, up: bool) {
        let mut state = self.lock();
        let changed = if up { state.linked.insert(peer.to_owned()) } else { state.linked.remove(peer) };
        if !changed {
            return;
        }
        let gone = if up { HashSet::new() } else { state.remote.remove(peer).unwrap_or_default() };
        for local in state.plugins.values().filter(|local| local.listening()) {
            if up {
                local.emit(Event::NodeUp { node: peer.to_owned() });
            } else {
                if gone.contains(&local.hash) {
                    local.emit(Event::PluginDown { node: peer.to_owned() });
                }
                local.emit(Event::NodeDown { node: peer.to_owned() });
            }
        }
    }

    /// How busy the channel is, 0-1. Plugins hear of it when it crosses [`CONGESTED`].
    pub fn set_congestion(&self, level: f64) {
        let mut state = self.lock();
        state.congestion = level.clamp(0.0, 1.0);
        let crossed = (state.congestion > CONGESTED) != (state.told > CONGESTED);
        if crossed || (state.congestion > CONGESTED && (state.congestion - state.told).abs() >= 0.1) {
            state.told = state.congestion;
            let level = (state.congestion * 100.0).round() / 100.0;
            for local in state.plugins.values().filter(|local| local.listening()) {
                local.emit(Event::Congestion { level });
            }
        }
    }

    pub fn stats(&self, plugin: &str) -> Stats {
        let state = self.lock();
        let mut stats = state.plugins.get(plugin).map(|local| local.stats.clone()).unwrap_or_default();
        stats.airtime_share = state.share;
        stats
    }

    /// Messages that arrived for plugins this node does not run.
    pub fn unrouted(&self) -> u64 {
        self.lock().unrouted
    }
}

/// The plugin stream's packet for a message (one mux frame).
fn data_packet(pending: &Pending) -> Option<Vec<u8>> {
    let payload = wire::encode_data(pending.hash, pending.channel, &pending.data);
    let mut queue: VecDeque<Message> = [Message { kind: Kind::Data, stream: wire::STREAM, payload }].into();
    kaonic_mux::pack(&mut queue, LINK_PACKET).0
}

fn running_packet(hashes: &[u64]) -> Option<Vec<u8>> {
    let mut queue: VecDeque<Message> = [Message { kind: Kind::Control, stream: wire::STREAM, payload: wire::encode_running(hashes) }].into();
    kaonic_mux::pack(&mut queue, LINK_PACKET).0
}

/// Connects the bridge to the links and the GROUP channel. Does nothing without links.
pub fn spawn(app: &App, bridge: Arc<Bridge>) {
    let (Some(links), Some(mesh)) = (app.links.get().cloned(), app.mesh.clone()) else { return };
    bridge.set_node(mesh.identity_hash());
    bridge.set_radio(mesh.radio_settings());

    // Frames on the plugin stream.
    let mut received = links.subscribe();
    let (incoming, incoming_mesh) = (bridge.clone(), mesh.clone());
    tokio::spawn(async move {
        loop {
            let message = match received.recv().await {
                Ok(message) => message,
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    log::warn!("plugins: bridge missed {missed} link packets");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Ok(frames) = kaonic_mux::parse(&message.packet) else { continue };
            for frame in frames.iter().filter(|frame| frame.stream == wire::STREAM) {
                incoming.on_frame(&message.peer, frame.kind, frame.payload, incoming_mesh.counters().last_rssi);
            }
        }
    });

    // Links up and down; a new link hears what runs here.
    let mut changes = links.changes();
    let (watcher, watched) = (bridge.clone(), links.clone());
    tokio::spawn(async move {
        for peer in watched.established() {
            watcher.link_changed(&peer, true);
            if let Some(packet) = running_packet(&watcher.running()) {
                watched.send(&peer, &packet).await;
            }
        }
        loop {
            let peer = match changes.recv().await {
                Ok(peer) => peer,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let up = watched.established().contains(&peer);
            watcher.link_changed(&peer, up);
            if up && let Some(packet) = running_packet(&watcher.running()) {
                watched.send(&peer, &packet).await;
            }
        }
    });

    // What runs here changed: every linked node hears it.
    let (announcer, announced) = (bridge.clone(), links.clone());
    tokio::spawn(async move {
        loop {
            announcer.advertise.notified().await;
            let Some(packet) = running_packet(&announcer.running()) else { continue };
            for peer in announced.established() {
                announced.send(&peer, &packet).await;
            }
        }
    });

    // Broadcasts, once this node has the group key.
    let (listener, group_app) = (bridge.clone(), app.clone());
    tokio::spawn(async move {
        let group = loop {
            if let Some(group) = group_app.ptt_group.get() {
                break group.clone();
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        };
        let mut messages = group.subscribe();
        loop {
            match messages.recv().await {
                Ok(message) => {
                    listener.on_group(&message.payload, message.rssi);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    });

    // How busy the channel is, from the radio's airtime counters.
    let (sampler, sampled) = (bridge.clone(), mesh.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut last: Option<(Instant, u64)> = None;
        let mut level = 0.0;
        loop {
            tick.tick().await;
            let counters = sampled.counters();
            let airtime = counters.tx_airtime_us + counters.rx_airtime_us;
            let now = Instant::now();
            if let Some((then, before)) = last {
                let elapsed = now.duration_since(then).as_micros().max(1) as f64;
                let busy = (airtime.saturating_sub(before) as f64 / elapsed).min(1.0);
                level = 0.7 * level + 0.3 * busy;
                sampler.set_congestion(level);
            }
            last = Some((now, airtime));
            sampler.set_radio(sampled.radio_settings());
        }
    });

    // The sender: one message at a time, when its plugin's budget allows.
    let (sender, app) = (bridge, app.clone());
    tokio::spawn(async move {
        loop {
            match sender.next(Instant::now()) {
                Next::Ready(pending) => {
                    let me = sender.lock().me;
                    let sent = match &pending.to {
                        Target::Node(node) => match data_packet(&pending) {
                            Some(packet) => links.send(node, &packet).await,
                            None => false,
                        },
                        Target::Broadcast => match (app.ptt_group.get(), me, crate::random::bytes::<8>()) {
                            (Some(group), Some(me), Ok(nonce)) => {
                                group.send(&wire::encode_broadcast(&me, u64::from_be_bytes(nonce), pending.hash, pending.channel, &pending.data)).await
                            }
                            _ => false,
                        },
                    };
                    sender.finished(&pending, sent);
                }
                Next::Wait(wait) => {
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = sender.wake.notified() => {}
                    }
                }
                Next::Idle => sender.wake.notified().await,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(receiver: &mut broadcast::Receiver<Event>) -> Vec<Event> {
        std::iter::from_fn(|| receiver.try_recv().ok()).collect()
    }

    const NODE: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn a_message_reaches_only_the_plugin_it_was_sent_to() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let mut echo = bridge.attach("echo", true).unwrap();
        let mut other = bridge.attach("other", true).unwrap();
        // Without the mesh permission, a plugin with the right name still gets nothing.
        let mut quiet = bridge.attach("quiet", false).unwrap();

        let frame = wire::encode_data(wire::id_hash("echo"), 9, b"hi");
        bridge.on_frame(NODE, Kind::Data, &frame, Some(-70));
        assert_eq!(
            events(&mut echo),
            vec![Event::Received { from: NODE.into(), channel: 9, data: "aGk=".into(), broadcast: false, rssi: Some(-70) }]
        );
        assert!(events(&mut other).is_empty());
        bridge.on_frame(NODE, Kind::Data, &wire::encode_data(wire::id_hash("quiet"), 0, b"x"), None);
        assert!(events(&mut quiet).is_empty());
        bridge.on_frame(NODE, Kind::Data, &wire::encode_data(wire::id_hash("nobody"), 0, b"x"), None);
        assert_eq!(bridge.unrouted(), 2);
        // Not linked: counted with every other such node.
        assert_eq!(bridge.stats("echo").per_node[OTHER].received, 1);

        // A plugin's broadcast on the group channel; our own is not heard back.
        bridge.set_node("ffeeddccbbaa99887766554433221100");
        assert!(bridge.on_group(&wire::encode_broadcast(&wire::node_bytes(NODE).unwrap(), 1, wire::id_hash("echo"), 1, b"all"), None));
        assert!(matches!(&events(&mut echo)[..], [Event::Received { broadcast: true, .. }]));
        let own = wire::encode_broadcast(&wire::node_bytes("ffeeddccbbaa99887766554433221100").unwrap(), 2, wire::id_hash("echo"), 1, b"me");
        assert!(bridge.on_group(&own, None));
        assert!(events(&mut echo).is_empty());
        assert!(!bridge.on_group(&[kaonic_ptt::VERSION, 0, 0], None), "voice is not the bridge's");

        // Closed sockets: not running any more, so no longer listed or delivered to.
        assert_eq!(bridge.running().len(), 2);
        bridge.detach("echo");
        assert!(!bridge.running().contains(&wire::id_hash("echo")));
    }

    #[test]
    fn nodes_say_what_runs_there_and_links_going_down_say_it_stopped() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let mut echo = bridge.attach("echo", true).unwrap();
        bridge.link_changed(NODE, true);
        bridge.on_frame(NODE, Kind::Control, &wire::encode_running(&[wire::id_hash("echo"), 7]), None);
        assert!(bridge.runs(NODE, "echo") && !bridge.runs(NODE, "other"));
        assert_eq!(events(&mut echo), vec![Event::NodeUp { node: NODE.into() }, Event::PluginUp { node: NODE.into() }]);
        bridge.on_frame(NODE, Kind::Control, &wire::encode_running(&[7]), None);
        assert_eq!(events(&mut echo), vec![Event::PluginDown { node: NODE.into() }]);
        bridge.on_frame(NODE, Kind::Control, &wire::encode_running(&[wire::id_hash("echo")]), None);
        bridge.link_changed(NODE, false);
        assert_eq!(
            events(&mut echo),
            vec![Event::PluginUp { node: NODE.into() }, Event::PluginDown { node: NODE.into() }, Event::NodeDown { node: NODE.into() }]
        );
        assert!(!bridge.runs(NODE, "echo"));
    }

    #[test]
    fn the_budget_spaces_messages_and_a_full_queue_drops_the_oldest() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let mut events_of = bridge.attach("chatty", true).unwrap();
        let start = Instant::now();
        let to = || vec![Target::Node(NODE.into())];
        assert_eq!(bridge.send_at("chatty", to(), 0, vec![0; max_message() + 1], start), Err(Reason::TooLarge));

        let first = bridge.send_at("chatty", to(), 0, vec![0; max_message()], start).unwrap();
        for n in 1..QUEUE + 2 {
            bridge.send_at("chatty", to(), 0, vec![n as u8; max_message()], start).unwrap();
        }
        // 66 queued into 64 places: the first two are gone.
        let dropped: Vec<Event> = events(&mut events_of);
        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped[0], Event::Dropped { id: first, node: Some(NODE.into()), reason: Reason::QueueFull });
        assert_eq!(bridge.stats("chatty").queue, QUEUE);

        // The bucket starts full (two seconds of budget), then lets one through per its cost.
        let cost = Bridge::cost(&None, max_message() + wire::DATA_HEADER) as f64;
        let mut at = start;
        let mut sent = 0;
        let mut on_air_us = 0.0;
        while at < start + Duration::from_secs(10) {
            match bridge.next(at) {
                Next::Ready(pending) => {
                    assert_eq!(pending.data[0] as usize, sent + 2, "oldest first");
                    bridge.finished(&pending, true);
                    sent += 1;
                    on_air_us += cost;
                }
                Next::Wait(wait) => at += wait,
                Next::Idle => break,
            }
        }
        let elapsed = at.duration_since(start).as_secs_f64();
        let used = on_air_us / 1e6;
        // Ten seconds at 10 %, plus the two seconds' burst of a full bucket.
        assert!(used <= 0.1 * elapsed + 0.2 + cost / 1e6, "{used} s on air in {elapsed} s");
        assert!(sent > 5 && sent < QUEUE, "{sent}");
        assert_eq!(bridge.stats("chatty").sent, sent as u64);

        // Whatever waited too long is dropped as over budget.
        let late = start + STALE + Duration::from_secs(1);
        assert!(matches!(bridge.next(late), Next::Ready(_) | Next::Wait(_) | Next::Idle));
        assert!(events(&mut events_of).iter().any(|event| matches!(event, Event::Dropped { reason: Reason::OverBudget, .. })));
    }

    #[test]
    fn plugins_take_turns_and_wait_while_the_channel_is_busy() {
        let bridge = Bridge::new(1.0);
        let now = Instant::now();
        for plugin in ["a", "b"] {
            for _ in 0..3 {
                bridge.send_at(plugin, vec![Target::Node(NODE.into())], 0, vec![0; 10], now).unwrap();
            }
        }
        let order: Vec<String> = (0..4)
            .filter_map(|_| match bridge.next(now) {
                Next::Ready(pending) => Some(pending.plugin),
                _ => None,
            })
            .collect();
        assert_eq!(order, ["a", "b", "a", "b"]);
        let mut listener = bridge.attach("a", true).unwrap();
        bridge.set_congestion(0.95);
        assert!(matches!(bridge.next(now), Next::Wait(_)));
        assert_eq!(events(&mut listener), vec![Event::Congestion { level: 0.95 }]);
        bridge.set_congestion(0.2);
        assert!(matches!(bridge.next(now), Next::Ready(_)));
        assert_eq!(events(&mut listener), vec![Event::Congestion { level: 0.2 }]);
    }

    #[test]
    fn packets_are_one_mux_frame_on_the_plugin_stream() {
        let pending = Pending { id: 1, plugin: "echo".into(), hash: wire::id_hash("echo"), to: Target::Node(NODE.into()), channel: 4, data: vec![5; max_message()], queued: Instant::now() };
        let packet = data_packet(&pending).unwrap();
        assert!(packet.len() <= LINK_PACKET);
        let frames = kaonic_mux::parse(&packet).unwrap();
        assert_eq!((frames.len(), frames[0].stream, frames[0].kind), (1, wire::STREAM, Kind::Data));
        assert_eq!(wire::decode_data(frames[0].payload), Some((pending.hash, 4, &pending.data[..])));
        let running = running_packet(&[1, 2]).unwrap();
        let frames = kaonic_mux::parse(&running).unwrap();
        assert_eq!(wire::decode_running(frames[0].payload), Some(vec![1, 2]));
    }
}

#[cfg(test)]
mod security {
    use super::*;

    fn events(receiver: &mut broadcast::Receiver<Event>) -> Vec<Event> {
        std::iter::from_fn(|| receiver.try_recv().ok()).collect()
    }

    const PEER: &str = "00112233445566778899aabbccddeeff";

    /// Two plugins whose 4-byte hashes collided (`a-tool-a6ffd208` and `kaonic-sample`) have
    /// different 8-byte ones; and two that share one get nothing, and cannot send.
    #[test]
    fn a_shared_mesh_hash_is_never_delivered_to() {
        assert_ne!(wire::id_hash("kaonic-sample"), wire::id_hash("a-tool-a6ffd208"));
        let bridge = Bridge::new(DEFAULT_SHARE);
        bridge.link_changed(PEER, true);
        let mut victim = bridge.attach("kaonic-sample", true).unwrap();
        bridge.on_frame(PEER, Kind::Data, &wire::encode_data(wire::id_hash("kaonic-sample"), 1, b"mine"), None);
        assert!(matches!(&events(&mut victim)[..], [Event::Received { .. }]));
        bridge.on_frame(PEER, Kind::Control, &wire::encode_running(&[wire::id_hash("kaonic-sample")]), None);
        assert!(bridge.runs(PEER, "kaonic-sample") && !bridge.runs(PEER, "a-tool-a6ffd208"));
        events(&mut victim);

        // The installer should refuse it; if two installed plugins share a hash anyway, neither
        // hears anything on it, nor is it listed as running, nor may it send.
        let shared = wire::id_hash("kaonic-sample");
        let mut state = bridge.lock();
        state.installed = Some(HashMap::from([(shared, 2)]));
        drop(state);
        let before = bridge.unrouted();
        bridge.on_frame(PEER, Kind::Data, &wire::encode_data(shared, 1, b"for whom?"), None);
        assert!(events(&mut victim).is_empty());
        assert_eq!(bridge.unrouted(), before + 1);
        assert!(!bridge.running().contains(&shared) && !bridge.runs(PEER, "kaonic-sample"));
        assert_eq!(bridge.send("kaonic-sample", vec![Target::Node(PEER.into())], 1, b"x".to_vec()), Err(Reason::Ambiguous));

        // Once the list has one again, it is delivered.
        bridge.set_installed(["kaonic-sample", "other"]);
        bridge.on_frame(PEER, Kind::Data, &wire::encode_data(shared, 1, b"mine"), None);
        assert!(matches!(&events(&mut victim)[..], [Event::Received { .. }]));
    }

    #[test]
    fn spoofed_broadcast_senders_share_one_entry() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let _events = bridge.attach("chat", true).unwrap();
        bridge.link_changed(PEER, true);
        let hash = wire::id_hash("chat");
        for n in 0..10_000u32 {
            let mut sender = [0u8; 16];
            sender[..4].copy_from_slice(&n.to_be_bytes());
            sender[15] = 1;
            assert!(bridge.on_group(&wire::encode_broadcast(&sender, n.into(), hash, 0, b""), None));
        }
        bridge.on_group(&wire::encode_broadcast(&wire::node_bytes(PEER).unwrap(), 1, hash, 0, b""), None);
        let stats = bridge.stats("chat");
        assert_eq!(stats.received, 10_001);
        assert_eq!(stats.per_node.len(), 2, "{:?}", stats.per_node.keys().collect::<Vec<_>>());
        assert_eq!((stats.per_node[OTHER].received, stats.per_node[PEER].received), (10_000, 1));
    }

    #[test]
    fn a_removed_plugin_leaves_nothing_behind() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let _events = bridge.attach("chat", true).unwrap();
        bridge.send("chat", vec![Target::Node(PEER.into())], 0, vec![1]).unwrap();
        bridge.set_installed(["other"]);
        assert_eq!(bridge.stats("chat").queue, 0);
        assert!(bridge.lock().plugins.is_empty());
        bridge.send("again", vec![Target::Node(PEER.into())], 0, vec![1]).unwrap();
        bridge.forget("again");
        assert!(bridge.lock().plugins.is_empty());
    }

    #[test]
    fn a_plugin_holds_at_most_four_event_sockets() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let held: Vec<_> = (0..MAX_EVENT_SOCKETS).map(|_| bridge.attach("chat", true).unwrap()).collect();
        assert!(bridge.attach("chat", true).is_none());
        assert!(bridge.attach("other", true).is_some());
        bridge.detach("chat");
        assert!(bridge.attach("chat", true).is_some());
        drop(held);
    }

    #[test]
    fn a_replayed_broadcast_is_dropped_until_it_is_forgotten() {
        let bridge = Bridge::new(DEFAULT_SHARE);
        let mut chat = bridge.attach("chat", true).unwrap();
        let packet = wire::encode_broadcast(&wire::node_bytes(PEER).unwrap(), 77, wire::id_hash("chat"), 0, b"once");
        let start = Instant::now();
        assert!(bridge.on_group_at(&packet, None, start));
        assert!(bridge.on_group_at(&packet, None, start + Duration::from_secs(60)));
        assert_eq!(events(&mut chat).len(), 1, "the replay is dropped");
        // Another nonce is another broadcast.
        let other = wire::encode_broadcast(&wire::node_bytes(PEER).unwrap(), 78, wire::id_hash("chat"), 0, b"once");
        assert!(bridge.on_group_at(&other, None, start));
        assert_eq!(events(&mut chat).len(), 1);
        // The window: after SEEN_FOR, or SEEN later broadcasts, it is taken again.
        assert!(bridge.on_group_at(&packet, None, start + SEEN_FOR + Duration::from_secs(1)));
        assert_eq!(events(&mut chat).len(), 1);
        for nonce in 0..SEEN as u64 {
            bridge.first_time([1; 16], nonce, start + SEEN_FOR * 2);
        }
        assert!(bridge.lock().seen.len() <= SEEN);
    }
}
