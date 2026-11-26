//! One authenticated Reticulum link per trusted peer.
//!
//! Every node of our network that announces is linked: the node with the lower identity
//! hash opens the link, both use it in both directions. A fresh link carries only the
//! handshake ([`kaonic_handshake`]) until both sides have accepted each other; then it
//! carries mux packets ([`kaonic_mux`]) for the services (the VPN). A link that fails
//! authentication is closed and its peer backed off. Unprovisioned nodes have no
//! credentials and link nobody; provisioning has its own messages (`KPV1`).
//!
//! Links come back by themselves after the radio loses them. Reticulum closes a link that
//! stops hearing its peer (timers in `node.rs`); the opener then opens a new one at once and
//! keeps trying while the peer is online, without the backoff used for failed logins. A peer
//! that restarted (a new boot id) loses its old links at once, and if it is the opener, we
//! open the link instead. Of two links to one peer, the one the lower hash opened stays.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kaonic_handshake::{Credentials, Event, Handshake, Role};
use kaonic_trust::Trust;
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkId, LinkStatus};
use reticulum::hash::AddressHash;
use tokio::sync::broadcast;

use crate::announce::Announced;
use crate::node::{Mesh, hex};

/// How often the manager looks for peers to link and runs handshake timers.
const TICK: Duration = Duration::from_secs(1);
/// After a failed authentication, the first wait before trying that peer again; doubled each time.
const BACKOFF_FIRST: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// An unanswered link request is replaced by a fresh one (new keys) after this long.
const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
/// Relinking waits a random time up to this, so nodes relinking to one peer do not send at
/// once.
const RELINK_SPREAD: Duration = Duration::from_millis(1500);
/// A peer that started this recently may not know us yet, so we open the link even when it
/// is the opener, after waiting a few seconds for it to: a link opened from both sides costs
/// a second setup.
const TAKEOVER_WINDOW: Duration = Duration::from_secs(60);
const TAKEOVER_AFTER: Duration = Duration::from_secs(4);
/// An offline peer we were linked to is still tried for this long, with one short attempt
/// about every `OFFLINE_RETRY`.
const REMEMBER_LINKED: Duration = Duration::from_secs(3600);
const OFFLINE_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const OFFLINE_RETRY: Duration = Duration::from_secs(30);
/// A link authenticated more than this before the peer's current start belongs to its
/// previous start and is gone. The start time is known to a second or so.
const RESTART_MARGIN: Duration = Duration::from_secs(3);
/// Links we opened that are not yet authenticated: announces that merely claim our admin
/// cannot make us send link requests to more peers than this at once.
const MAX_OPENING: usize = 16;
/// Links others opened that are not yet authenticated; past this the oldest is closed.
const MAX_IN_HANDSHAKES: usize = 64;
/// Failed peers remembered (the peer table's default size); past this the oldest is forgotten.
const MAX_FAILURES: usize = 512;

/// This node's credentials and trust; None while unprovisioned.
pub struct Auth {
    pub credentials: Credentials,
    pub trust: Trust,
}

/// A mux packet from an authenticated peer.
#[derive(Clone, Debug)]
pub struct Received {
    pub peer: String,
    pub packet: Arc<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// We opened it, to this destination.
    Out(AddressHash),
    In,
}

struct Entry {
    side: Side,
    /// The peer: known when we opened the link, learnt from its AUTH when it did.
    peer: Option<String>,
    /// None until Reticulum activated the link (and we had credentials).
    handshake: Option<Handshake>,
    opened: Instant,
}

/// A link as `view` reads it: id, side, peer, handshake started, authenticated, opened, role.
type Snapshot = (LinkId, Side, Option<String>, bool, bool, Instant, Option<&'static str>);

/// A peer's link as the API shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkView {
    pub peer: String,
    /// The Reticulum link id, hex; empty for a peer whose last attempt failed.
    pub link_id: String,
    /// We opened it.
    pub initiator: bool,
    /// What AUTH proved the peer to be: `admin` or `node`.
    pub role: Option<&'static str>,
    /// `opening`, `authenticating`, `up`, `failed`.
    pub state: &'static str,
    pub rtt_ms: Option<u64>,
    pub since: Instant,
    pub detail: Option<String>,
}

struct Failure {
    count: u32,
    retry_at: Option<Instant>,
    detail: String,
    at: Instant,
    /// The peer did not answer (radio): retried soon, not backed off.
    unreachable: bool,
}

#[derive(Default)]
struct State {
    auth: Option<Auth>,
    links: HashMap<LinkId, Entry>,
    /// The authenticated link of each peer.
    up: HashMap<String, (LinkId, Instant)>,
    failures: HashMap<String, Failure>,
    /// Peers not to open a link to before the instant ([`RELINK_SPREAD`]).
    not_before: HashMap<String, Instant>,
    /// When each peer last had an authenticated link (it came up, or was lost).
    last_up: HashMap<String, Instant>,
}

/// Stores an allowlist a peer handed us (the caller's keystore).
pub type AllowlistSink = Box<dyn Fn(Vec<u8>) + Send + Sync>;

pub struct Links {
    /// Ourselves, for work spawned from `&self`.
    me: std::sync::Weak<Links>,
    mesh: Arc<Mesh>,
    state: Mutex<State>,
    received: broadcast::Sender<Received>,
    changes: broadcast::Sender<String>,
    store_allowlist: AllowlistSink,
}

impl Links {
    /// Starts linking on `mesh`. Must run inside a tokio runtime.
    pub async fn start(mesh: Arc<Mesh>, auth: Option<Auth>, store_allowlist: AllowlistSink) -> Arc<Self> {
        let links = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            mesh: mesh.clone(),
            state: Mutex::new(State { auth, ..State::default() }),
            received: broadcast::channel(4096).0,
            changes: broadcast::channel(256).0,
            store_allowlist,
        });
        let (mut ins, mut outs) = {
            let transport = mesh.transport().lock().await;
            (transport.in_link_events(), transport.out_link_events())
        };
        let mut heard = mesh.subscribe();
        let manager = links.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TICK);
            loop {
                tokio::select! {
                    event = ins.recv() => match event {
                        Ok(event) => manager.on_event(event, false).await,
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            log::warn!("links: missed {missed} in-link events");
                            manager.reconcile().await;
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    event = outs.recv() => match event {
                        Ok(event) => manager.on_event(event, true).await,
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            log::warn!("links: missed {missed} out-link events");
                            manager.reconcile().await;
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    peer = heard.recv() => match peer {
                        Ok(peer) => manager.on_heard(&peer.id).await,
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    _ = tick.tick() => manager.on_tick().await,
                }
            }
        });
        links
    }

    /// New credentials or trust (provisioned, re-provisioned, allowlist changed by the admin).
    /// Links whose peer is no longer trusted are closed.
    pub async fn set_auth(&self, mut auth: Option<Auth>) {
        let to_close = {
            let mut state = self.state.lock().expect("links lock");
            let newer = match (&state.auth, &mut auth) {
                (Some(old), Some(new)) => {
                    // Never back to an older list: a peer may have handed us a newer one since
                    // the caller read its copy. Only a list of the new root replaces it.
                    let _ = new.trust.update_allowlist(old.trust.allowlist().as_bytes());
                    new.trust.allowlist().seq() > old.trust.allowlist().seq()
                }
                _ => false,
            };
            state.auth = auth;
            if newer {
                drop(state);
                self.push_allowlist();
                state = self.state.lock().expect("links lock");
            }
            state.failures.clear();
            let State { auth, links, .. } = &mut *state;
            let mut to_close = Vec::new();
            for (id, entry) in links.iter_mut() {
                let still = match (auth.as_ref(), entry.handshake.as_mut()) {
                    (Some(auth), Some(handshake)) => handshake.recheck(&auth.trust).is_none(),
                    (None, _) => false,
                    (Some(_), None) => true,
                };
                if !still {
                    to_close.push(*id);
                }
            }
            to_close
        };
        for id in to_close {
            self.close(id, "trust changed").await;
        }
    }

    /// Mux packets from authenticated peers.
    pub fn subscribe(&self) -> broadcast::Receiver<Received> {
        self.received.subscribe()
    }

    /// The peer whose link changed state.
    pub fn changes(&self) -> broadcast::Receiver<String> {
        self.changes.subscribe()
    }

    /// Peers with an authenticated link.
    pub fn established(&self) -> Vec<String> {
        self.state.lock().expect("links lock").up.keys().cloned().collect()
    }

    /// Sends a mux packet to `peer` over its authenticated link. False if there is none.
    pub async fn send(&self, peer: &str, packet: &[u8]) -> bool {
        let target = {
            let state = self.state.lock().expect("links lock");
            state.up.get(peer).and_then(|(id, _)| state.links.get(id).map(|entry| (*id, entry.side)))
        };
        match target {
            Some((id, side)) => self.send_on(id, side, packet).await,
            None => false,
        }
    }

    /// Sends on exactly this link, also while stale: it has only missed keepalives.
    async fn send_on(&self, id: LinkId, side: Side, payload: &[u8]) -> bool {
        let transport = self.mesh.transport().lock().await;
        let link = match side {
            Side::Out(_) => transport.find_out_link(&id).await,
            Side::In => transport.find_in_link(&id).await,
        };
        let Some(link) = link else { return false };
        let packet = {
            let link = link.lock().await;
            if *link.id() != id {
                return false;
            }
            link.data_packet(payload)
        };
        match packet {
            Ok(packet) => {
                transport.send_packet(packet).await;
                true
            }
            Err(_) => false,
        }
    }

    /// Every peer's link, for the API.
    pub async fn view(&self) -> Vec<LinkView> {
        let (entries, failures): (Vec<Snapshot>, Vec<(String, String)>) = {
            let state = self.state.lock().expect("links lock");
            let entries = state
                .links
                .iter()
                .map(|(id, entry)| {
                    let up = entry.handshake.as_ref().is_some_and(Handshake::is_established);
                    let role = entry.handshake.as_ref().and_then(Handshake::peer_kind).map(|kind| match kind {
                        kaonic_trust::Peer::Admin => "admin",
                        kaonic_trust::Peer::Node => "node",
                    });
                    (*id, entry.side, entry.peer.clone(), entry.handshake.is_some(), up, entry.opened, role)
                })
                .collect();
            let failures = state.failures.iter().filter(|(_, failure)| failure.count > 0).map(|(peer, failure)| (peer.clone(), failure.detail.clone())).collect();
            (entries, failures)
        };
        let transport = self.mesh.transport().lock().await;
        let mut views: Vec<LinkView> = Vec::new();
        for (id, side, peer, started, up, opened, role) in entries {
            let Some(peer) = peer else { continue };
            let link = match side {
                Side::Out(_) => transport.find_out_link(&id).await,
                Side::In => transport.find_in_link(&id).await,
            };
            let rtt_ms = match link {
                // zero until the initiator's RTT packet arrives (the responder does not time it)
                Some(link) => Some(link.lock().await.rtt().as_millis() as u64).filter(|rtt| *rtt > 0),
                None => None,
            };
            let state = if up { "up" } else if started { "authenticating" } else { "opening" };
            views.push(LinkView { peer, link_id: hex(&id), initiator: matches!(side, Side::Out(_)), role, state, rtt_ms: rtt_ms.filter(|_| up), since: opened, detail: None });
        }
        for (peer, detail) in failures {
            if !views.iter().any(|view| view.peer == peer) {
                views.push(LinkView { peer, link_id: String::new(), initiator: false, role: None, state: "failed", rtt_ms: None, since: Instant::now(), detail: Some(detail) });
            }
        }
        views
    }

    /// Peers we should be linked to and are the opener for.
    fn wanted(&self, state: &State) -> Vec<String> {
        let Some(auth) = &state.auth else { return Vec::new() };
        let ours = auth.trust.root().identity_hash().0;
        let me = self.mesh.identity_hash();
        let now = Instant::now();
        self.mesh
            .peers()
            .into_iter()
            .filter(|peer| self.mesh.is_online(peer) || state.last_up.get(&peer.id).is_some_and(|at| at.elapsed() < REMEMBER_LINKED))
            .filter(|peer| matches!(&peer.announced, Announced::Hub(info) if info.admin_id == Some(ours)))
            // The admin blocked it: its AUTH would be refused anyway.
            .filter(|peer| kaonic_trust::IdentityHash::from_hex(&peer.id).is_none_or(|hash| !auth.trust.allowlist().is_blocked(&hash)))
            // The lower identity hash opens the link, unless the other one just started.
            .filter(|peer| me < peer.id.as_str() || self.mesh.started_of(&peer.id).is_some_and(|at| (TAKEOVER_AFTER..TAKEOVER_WINDOW).contains(&at.elapsed())))
            .filter(|peer| !state.up.contains_key(&peer.id) && !state.links.values().any(|entry| entry.peer.as_deref() == Some(peer.id.as_str())))
            .filter(|peer| state.failures.get(&peer.id).and_then(|failure| failure.retry_at).is_none_or(|at| now >= at))
            .filter(|peer| state.not_before.get(&peer.id).is_none_or(|at| now >= *at))
            .take(MAX_OPENING.saturating_sub(opening(&state.links)))
            .map(|peer| peer.id)
            .collect()
    }

    async fn on_tick(&self) {
        // Links of a peer's previous start are gone: close them now, not when they time out.
        let restarted: Vec<(LinkId, String)> = {
            let state = self.state.lock().expect("links lock");
            state
                .up
                .iter()
                .filter(|(peer, (_, since))| self.mesh.started_of(peer).is_some_and(|started| *since + RESTART_MARGIN < started))
                .map(|(peer, (id, _))| (*id, peer.clone()))
                .collect()
        };
        for (id, peer) in restarted {
            log::info!("links {}: {peer} restarted, its link {} is gone", &self.mesh.identity_hash()[..8], hex(&id));
            self.close(id, "the peer restarted").await;
        }
        let wanted = {
            let mut state = self.state.lock().expect("links lock");
            // Peers the mesh forgot are not backed off any more.
            let known: HashSet<String> = self.mesh.peers().into_iter().map(|peer| peer.id).collect();
            state.failures.retain(|peer, _| known.contains(peer));
            state.last_up.retain(|peer, at| known.contains(peer) && at.elapsed() < REMEMBER_LINKED);
            let now = Instant::now();
            state.not_before.retain(|_, at| *at > now);
            self.wanted(&state)
        };
        for peer in wanted {
            self.open(peer).await;
        }
        // Handshake resends and deadlines; links stuck opening.
        let now = Instant::now();
        let mut actions: Vec<(LinkId, Side, Vec<Event>)> = Vec::new();
        let mut stuck = Vec::new();
        let online: HashSet<String> = self.mesh.peers().into_iter().filter(|peer| self.mesh.is_online(peer)).map(|peer| peer.id).collect();
        {
            let mut state = self.state.lock().expect("links lock");
            let State { auth, links, .. } = &mut *state;
            for (id, entry) in links.iter_mut() {
                let offline = entry.peer.as_ref().is_some_and(|peer| !online.contains(peer));
                let timeout = if offline { OFFLINE_OPEN_TIMEOUT } else { OPEN_TIMEOUT };
                match (entry.handshake.as_mut(), auth.as_ref()) {
                    (Some(handshake), Some(auth)) => actions.push((*id, entry.side, handshake.tick(&auth.trust, now))),
                    (None, _) if now.duration_since(entry.opened) > timeout => stuck.push(*id),
                    _ => {}
                }
            }
        }
        for (id, side, events) in actions {
            self.act(id, side, events).await;
        }
        for id in stuck {
            self.unreachable(id, "the link did not come up");
            self.close(id, "not activated").await;
        }
    }

    /// Whether the mesh has not heard `peer` announcing for its offline time.
    fn is_offline(&self, peer: &str) -> bool {
        self.mesh.peers().iter().find(|known| known.id == peer).is_none_or(|known| !self.mesh.is_online(known))
    }

    /// The peer announced: if we were trying to reach it, retry now with a fresh request.
    async fn on_heard(&self, peer: &str) {
        let stale_attempt = {
            let mut state = self.state.lock().expect("links lock");
            if state.failures.get(peer).is_some_and(|failure| failure.unreachable) {
                state.failures.remove(peer);
            }
            let now = Instant::now();
            // Heard for the first time or after a while: every node that heard it may link
            // now, so each waits a random moment.
            let linked = state.up.contains_key(peer) || state.links.values().any(|entry| entry.peer.as_deref() == Some(peer));
            if !linked && !state.not_before.contains_key(peer) {
                let wait = Duration::from_millis(rand::random::<u64>() % (RELINK_SPREAD.as_millis() as u64 + 1));
                state.not_before.insert(peer.to_owned(), now + wait);
            }
            state
                .links
                .iter()
                .find(|(_, entry)| entry.peer.as_deref() == Some(peer) && matches!(entry.side, Side::Out(_)) && entry.handshake.is_none() && now.duration_since(entry.opened) > Duration::from_secs(2))
                .map(|(id, _)| *id)
        };
        if let Some(id) = stale_attempt {
            log::debug!("links {}: heard {peer} while trying to reach it: a fresh request", &self.mesh.identity_hash()[..8]);
            self.spread(peer);
            self.close(id, "the peer announced").await;
        }
    }

    /// The next attempt to open a link to `peer` waits a random part of [`RELINK_SPREAD`].
    fn spread(&self, peer: &str) {
        let wait = Duration::from_millis(rand::random::<u64>() % (RELINK_SPREAD.as_millis() as u64 + 1));
        self.state.lock().expect("links lock").not_before.insert(peer.to_owned(), Instant::now() + wait);
    }

    async fn open(&self, peer: String) {
        let Some(desc) = self.mesh.destination_of(&peer) else { return };
        let link = self.mesh.transport().lock().await.link(desc).await;
        let (id, active) = {
            let link = link.lock().await;
            (*link.id(), link.status() == LinkStatus::Active)
        };
        log::debug!("links {}: opening {} to {peer}", &self.mesh.identity_hash()[..8], hex(&id));
        {
            let mut state = self.state.lock().expect("links lock");
            state.links.entry(id).or_insert(Entry { side: Side::Out(desc.address_hash), peer: Some(peer), handshake: None, opened: Instant::now() });
        }
        if active {
            self.begin(id).await;
        }
    }

    /// Reticulum activated the link: start authenticating.
    async fn begin(&self, id: LinkId) {
        let started = {
            let mut state = self.state.lock().expect("links lock");
            let State { auth, links, .. } = &mut *state;
            let (Some(auth), Some(entry)) = (auth.as_ref(), links.get_mut(&id)) else { return };
            if entry.handshake.is_some() {
                return;
            }
            let (role, expected) = match entry.side {
                Side::Out(_) => (Role::Initiator, entry.peer.as_deref().and_then(kaonic_trust::IdentityHash::from_hex)),
                Side::In => (Role::Responder, None),
            };
            let mut handshake = Handshake::new(role, id.as_slice().try_into().expect("link ids are 16 bytes"), auth.credentials.clone(), expected, Instant::now());
            let events = handshake.start(&auth.trust, Instant::now());
            entry.handshake = Some(handshake);
            Some((entry.side, events))
        };
        if let Some((side, events)) = started {
            self.act(id, side, events).await;
        }
    }

    async fn on_event(&self, event: LinkEventData, out: bool) {
        let id = event.id;
        match event.event {
            LinkEvent::Activated => {
                if !out {
                    let (has_auth, excess) = {
                        let mut state = self.state.lock().expect("links lock");
                        let has_auth = state.auth.is_some();
                        if has_auth {
                            state.links.entry(id).or_insert(Entry { side: Side::In, peer: None, handshake: None, opened: Instant::now() });
                        }
                        (has_auth, excess_in_handshakes(&state.links))
                    };
                    for old in excess {
                        log::debug!("links {}: too many links authenticating, closing {}", &self.mesh.identity_hash()[..8], hex(&old));
                        self.close(old, "too many links authenticating").await;
                    }
                    if !has_auth || !self.state.lock().expect("links lock").links.contains_key(&id) {
                        return;
                    }
                }
                self.begin(id).await;
            }
            LinkEvent::Data(payload) => self.on_data(id, payload.as_slice()).await,
            LinkEvent::Closed => self.on_closed(id).await,
            LinkEvent::Proof(_) | LinkEvent::RemoteIdentified(_) => {}
        }
    }

    /// Reticulum closed the link.
    async fn on_closed(&self, id: LinkId) {
        let (peer, was_up, side) = {
            let mut state = self.state.lock().expect("links lock");
            let entry = state.links.remove(&id);
            let side = entry.as_ref().map(|entry| entry.side);
            let peer = entry.and_then(|entry| entry.peer);
            let mut was_up = false;
            if let Some(peer) = &peer
                && state.up.get(peer).is_some_and(|(up, _)| *up == id)
            {
                state.up.remove(peer);
                was_up = true;
            }
            (peer, was_up, side)
        };
        if let Some(peer) = peer {
            log::info!("links {}: link to {peer} closed", &self.mesh.identity_hash()[..8]);
            if was_up {
                self.lost(&peer, side == Some(Side::In)).await;
            }
            let _ = self.changes.send(peer);
        }
    }

    /// The authenticated link to `peer` is gone: its path is in doubt and a new link is opened
    /// soon. If the peer opened it through relays (`answered`), we announce so a relay can carry
    /// the next one.
    async fn lost(&self, peer: &str, answered: bool) {
        if answered && self.mesh.peers().iter().any(|known| known.id == peer && known.hops > 0) {
            self.mesh.announce_soon();
        }
        self.spread(peer);
        self.state.lock().expect("links lock").last_up.insert(peer.to_owned(), Instant::now());
        if let Some(desc) = self.mesh.destination_of(peer) {
            self.mesh.transport().lock().await.mark_path_unresponsive(&desc.address_hash).await;
        }
    }

    /// Link events were missed: forgets links Reticulum no longer has open, so their peers
    /// are linked again.
    async fn reconcile(&self) {
        let entries: Vec<(LinkId, Side)> = self.state.lock().expect("links lock").links.iter().map(|(id, entry)| (*id, entry.side)).collect();
        let mut gone = Vec::new();
        {
            let transport = self.mesh.transport().lock().await;
            for (id, side) in entries {
                let link = match side {
                    Side::Out(_) => transport.find_out_link(&id).await,
                    Side::In => transport.find_in_link(&id).await,
                };
                let closed = match link {
                    Some(link) => link.lock().await.status() == LinkStatus::Closed,
                    None => true,
                };
                if closed {
                    gone.push(id);
                }
            }
        }
        for id in gone {
            self.on_closed(id).await;
        }
    }

    async fn on_data(&self, id: LinkId, data: &[u8]) {
        if kaonic_handshake::is_handshake(data) {
            let outcome = {
                let mut state = self.state.lock().expect("links lock");
                let State { auth, links, .. } = &mut *state;
                match (auth.as_mut(), links.get_mut(&id)) {
                    (Some(auth), Some(entry)) => entry.handshake.as_mut().map(|handshake| (entry.side, handshake.receive(data, &mut auth.trust, Instant::now()))),
                    _ => None,
                }
            };
            if let Some((side, events)) = outcome {
                self.act(id, side, events).await;
            }
        } else if kaonic_mux::is_mux(data) {
            let outcome = {
                let mut state = self.state.lock().expect("links lock");
                let Some(entry) = state.links.get_mut(&id) else { return };
                let side = entry.side;
                match entry.handshake.as_mut().map(Handshake::on_traffic) {
                    Some(Ok(events)) => Ok((side, events)),
                    Some(Err(reason)) => Err(reason.to_string()),
                    None => Err("traffic before the link was activated".to_owned()),
                }
            };
            match outcome {
                Ok((side, events)) => {
                    self.act(id, side, events).await;
                    let peer = {
                        let state = self.state.lock().expect("links lock");
                        state.links.get(&id).filter(|entry| entry.handshake.as_ref().is_some_and(Handshake::is_established)).and_then(|entry| entry.peer.clone())
                    };
                    if let Some(peer) = peer {
                        let _ = self.received.send(Received { peer, packet: Arc::new(data.to_vec()) });
                    }
                }
                Err(why) => {
                    self.fail(id, &why);
                    self.close(id, &why).await;
                }
            }
        }
        // Anything else (provisioning's `KPV1`) is not ours.
    }

    async fn act(&self, id: LinkId, side: Side, events: Vec<Event>) {
        for event in events {
            match event {
                Event::Send(bytes) => {
                    self.send_on(id, side, &bytes).await;
                }
                Event::AllowlistUpdated => {
                    let bytes = {
                        let state = self.state.lock().expect("links lock");
                        state.auth.as_ref().map(|auth| auth.trust.allowlist().as_bytes().to_vec())
                    };
                    if let Some(bytes) = bytes {
                        log::info!("links {}: a peer gave us a newer allowlist", &self.mesh.identity_hash()[..8]);
                        (self.store_allowlist)(bytes);
                    }
                    self.recheck_all().await;
                    // Pass it on to peers that hold an older one (not the one it came from).
                    self.push_allowlist();
                }
                Event::Established { peer, .. } => {
                    let peer = peer.hash().to_hex();
                    // A second link to a peer means the first is likely dead on its side.
                    // Both sides keep the same one: the lower hash's, else the newer.
                    let outcome = {
                        let mut state = self.state.lock().expect("links lock");
                        let we_are_lower = self.mesh.identity_hash() < peer.as_str();
                        let by_lower = |side: Option<Side>| side.is_some_and(|side| matches!(side, Side::Out(_)) == we_are_lower);
                        let old = state.up.get(&peer).map(|(up, _)| *up).filter(|up| *up != id);
                        let keep_new = old.is_none_or(|old| by_lower(state.links.get(&id).map(|entry| entry.side)) || !by_lower(state.links.get(&old).map(|entry| entry.side)));
                        if keep_new {
                            state.up.insert(peer.clone(), (id, Instant::now()));
                            state.last_up.insert(peer.clone(), Instant::now());
                            state.failures.remove(&peer);
                            state.not_before.remove(&peer);
                            if let Some(entry) = state.links.get_mut(&id) {
                                entry.peer = Some(peer.clone());
                            }
                        }
                        (keep_new, old)
                    };
                    match outcome {
                        (false, _) => self.close(id, "a link to this peer is already up").await,
                        (true, old) => {
                            log::info!("links {}: {peer} authenticated ({})", &self.mesh.identity_hash()[..8], hex(&id));
                            if let Some(old) = old {
                                self.close(old, "replaced by a newer link").await;
                            }
                            let _ = self.changes.send(peer);
                        }
                    }
                }
                Event::Close(reason) => {
                    let why = reason.to_string();
                    // Anyone can open a link to us: only an authenticated one is worth a warning.
                    let was_up = self.state.lock().expect("links lock").up.values().any(|(up, _)| *up == id);
                    let level = if was_up { log::Level::Warn } else { log::Level::Debug };
                    log::log!(level, "links {}: closing {}: {why}", &self.mesh.identity_hash()[..8], hex(&id));
                    // No AUTH in time is the radio, not the peer's credentials.
                    if matches!(reason, kaonic_handshake::Reason::Timeout) {
                        self.unreachable(id, &why);
                    } else {
                        self.fail(id, &why);
                    }
                    self.close(id, &why).await;
                }
            }
        }
    }

    /// Our allowlist changed: every link sends it on if its peer holds an older one (and
    /// keeps resending until the peer has it).
    fn push_allowlist(&self) {
        let actions: Vec<(LinkId, Side, Vec<Event>)> = {
            let mut state = self.state.lock().expect("links lock");
            let State { auth, links, .. } = &mut *state;
            let Some(auth) = auth.as_ref() else { return };
            let now = Instant::now();
            links.iter_mut().filter_map(|(id, entry)| entry.handshake.as_mut().map(|handshake| (*id, entry.side, handshake.list_changed(&auth.trust, now)))).collect()
        };
        let Some(this) = self.me.upgrade() else { return };
        tokio::spawn(async move {
            for (id, side, events) in actions {
                this.act(id, side, events).await;
            }
        });
    }

    async fn recheck_all(&self) {
        let to_close: Vec<LinkId> = {
            let mut state = self.state.lock().expect("links lock");
            let State { auth, links, .. } = &mut *state;
            let Some(auth) = auth.as_ref() else { return };
            links.iter_mut().filter_map(|(id, entry)| entry.handshake.as_mut().and_then(|handshake| handshake.recheck(&auth.trust)).map(|_| *id)).collect()
        };
        for id in to_close {
            self.close(id, "revoked").await;
        }
    }

    /// Backs off the link's peer.
    fn fail(&self, id: LinkId, why: &str) {
        let mut state = self.state.lock().expect("links lock");
        let Some(peer) = state.links.get(&id).and_then(|entry| entry.peer.clone()) else { return };
        record_failure(&mut state.failures, peer, why, Instant::now(), false);
    }

    /// The peer did not answer: shown as failed and retried soon (an offline one after
    /// about [`OFFLINE_RETRY`]).
    fn unreachable(&self, id: LinkId, why: &str) {
        let peer = self.state.lock().expect("links lock").links.get(&id).and_then(|entry| entry.peer.clone());
        let Some(peer) = peer else { return };
        let offline = self.is_offline(&peer);
        let now = Instant::now();
        let mut state = self.state.lock().expect("links lock");
        record_failure(&mut state.failures, peer.clone(), why, now, true);
        if offline {
            let spread = OFFLINE_RETRY.as_millis() as u64 * (80 + rand::random::<u64>() % 41) / 100;
            if let Some(failure) = state.failures.get_mut(&peer) {
                failure.retry_at = Some(now + Duration::from_millis(spread));
            }
        }
    }

    async fn close(&self, id: LinkId, why: &str) {
        let peer = {
            let mut state = self.state.lock().expect("links lock");
            let peer = state.links.remove(&id).and_then(|entry| entry.peer);
            if let Some(peer) = &peer
                && state.up.get(peer).is_some_and(|(up, _)| *up == id)
            {
                state.up.remove(peer);
            }
            peer
        };
        log::debug!("links {}: close {} ({why})", &self.mesh.identity_hash()[..8], hex(&id));
        let _ = self.mesh.transport().lock().await.link_close(id).await;
        if let Some(peer) = peer {
            let _ = self.changes.send(peer);
        }
    }
}

/// Counts a failure of `peer` and backs it off (an unreachable one only by up to
/// [`RELINK_SPREAD`]), forgetting the oldest failure past [`MAX_FAILURES`].
fn record_failure(failures: &mut HashMap<String, Failure>, peer: String, why: &str, now: Instant, unreachable: bool) {
    if !failures.contains_key(&peer) && failures.len() >= MAX_FAILURES {
        let oldest = failures.iter().min_by_key(|(_, failure)| failure.at).map(|(peer, _)| peer.clone());
        if let Some(oldest) = oldest {
            failures.remove(&oldest);
        }
    }
    let failure = failures.entry(peer).or_insert(Failure { count: 0, retry_at: None, detail: String::new(), at: now, unreachable });
    failure.count += 1;
    let wait = if unreachable {
        Duration::from_millis(rand::random::<u64>() % (RELINK_SPREAD.as_millis() as u64 + 1))
    } else {
        BACKOFF_FIRST.saturating_mul(1 << failure.count.min(6)).min(BACKOFF_MAX)
    };
    failure.unreachable = unreachable;
    failure.retry_at = Some(now + wait);
    failure.detail = why.to_owned();
    failure.at = now;
}

fn authenticated(entry: &Entry) -> bool {
    entry.handshake.as_ref().is_some_and(Handshake::is_established)
}

/// Links we opened that are not authenticated yet.
fn opening(links: &HashMap<LinkId, Entry>) -> usize {
    links.values().filter(|entry| matches!(entry.side, Side::Out(_)) && !authenticated(entry)).count()
}

/// The oldest links others opened that are past [`MAX_IN_HANDSHAKES`] unauthenticated.
fn excess_in_handshakes(links: &HashMap<LinkId, Entry>) -> Vec<LinkId> {
    let mut waiting: Vec<(Instant, LinkId)> = links.iter().filter(|(_, entry)| entry.side == Side::In && !authenticated(entry)).map(|(id, entry)| (entry.opened, *id)).collect();
    let excess = waiting.len().saturating_sub(MAX_IN_HANDSHAKES);
    waiting.sort();
    waiting.into_iter().take(excess).map(|(_, id)| id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> LinkId {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        AddressHash::new(bytes)
    }

    fn entry(side: Side, opened: Instant) -> Entry {
        Entry { side, peer: None, handshake: None, opened }
    }

    #[test]
    fn failures_are_bounded_and_the_oldest_goes_first() {
        let (mut failures, now) = (HashMap::new(), Instant::now());
        for n in 0..MAX_FAILURES * 3 {
            record_failure(&mut failures, format!("peer{n}"), "no", now + Duration::from_millis(n as u64), false);
        }
        assert_eq!(failures.len(), MAX_FAILURES);
        assert!(!failures.contains_key("peer0"));
        assert!(failures.contains_key(&format!("peer{}", MAX_FAILURES * 3 - 1)));
        // A peer failing again is counted, not added.
        record_failure(&mut failures, format!("peer{}", MAX_FAILURES * 3 - 1), "again", now, false);
        assert_eq!(failures.len(), MAX_FAILURES);
        assert_eq!(failures[&format!("peer{}", MAX_FAILURES * 3 - 1)].count, 2);
    }

    #[test]
    fn opening_links_are_counted_and_unauthenticated_in_links_are_capped() {
        let now = Instant::now();
        let mut links = HashMap::new();
        for n in 0..5 {
            links.insert(id(n), entry(Side::Out(id(1000 + n)), now));
        }
        assert_eq!(opening(&links), 5);
        for n in 0..MAX_IN_HANDSHAKES as u32 + 10 {
            links.insert(id(100 + n), entry(Side::In, now + Duration::from_millis(u64::from(n))));
        }
        let excess = excess_in_handshakes(&links);
        assert_eq!(excess, (100..110).map(id).collect::<Vec<_>>(), "the oldest ten");
        for old in excess {
            links.remove(&old);
        }
        assert!(excess_in_handshakes(&links).is_empty());
        assert_eq!(opening(&links), 5, "in-links are not ours");
    }
}
