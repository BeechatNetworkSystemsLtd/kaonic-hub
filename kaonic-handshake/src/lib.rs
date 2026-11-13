//! Link authentication: what two provisioned nodes say on
//! a fresh Reticulum link before anything else may cross it.
//!
//! ```text
//! AUTH      = 0xA0 | version u8 | role u8 | flags u8 | identity[64] | allowlist seq u64
//!             | cert_len u16 | certificate DER | sig[64]
//! sig       = Ed25519(identity key, "kaonic-link-auth v1\0" | link id[16] | role | flags
//!             | identity | seq | SHA-256(cert))
//! ALLOWLIST = 0xA1 | version 2 | seq u64 | size u32 | index u16 | part of the list
//! LISTSTATE = 0xA2 | version 1 | held seq u64 | receiving seq u64 | parts u16 | bitmap
//! ```
//! Each side sends `AUTH` first. `flags` bit 0 says "I have accepted you", bit 1 "this answers
//! your AUTH" (a reply is never answered, so the exchange ends). A side resends
//! its `AUTH` every few seconds until it has accepted the peer and seen the peer's AUTH
//! with that bit, so a frame lost on the radio delays the link instead of failing it.
//!
//! Allowlists spread from node to node:
//!
//! - A side that learns its peer holds an older list (from its `AUTH` or `LISTSTATE`) sends
//!   its own, in parts of [`PART_DATA`] bytes, but only to a peer whose certificate our
//!   admin issued.
//! - The receiver answers with `LISTSTATE`: the list it holds and the parts it has of the one
//!   it is receiving (bit `i` of the bitmap is part `i`). The sender resends the missing
//!   parts, waiting longer each time, until the peer holds the list.
//! - This runs on established links too, so a revocation reaches every node.
//!
//! [`Handshake`] is the per-link state machine. It does no I/O: the caller feeds it what
//! arrives and the time, and acts on the [`Event`]s it returns. Pure, so it is tested here.

use std::fmt;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use kaonic_trust::{Certificate, Identity, IdentityHash, Peer, Trust};
use sha2::{Digest, Sha256};

pub const AUTH: u8 = 0xA0;
pub const ALLOWLIST: u8 = 0xA1;
pub const LIST_STATE: u8 = 0xA2;
const VERSION: u8 = 1;
/// `ALLOWLIST` in parts. Version 1 carried the whole list in one message; it is still read.
const PART_VERSION: u8 = 2;
const STATE_VERSION: u8 = 1;
/// Allowlist bytes per part: a part is at most 784 bytes, so it fits any link packet.
pub const PART_DATA: usize = 768;
/// The largest allowlist taken from a peer (about 16 000 identities).
pub const MAX_LIST: usize = 256 * 1024;
const MAX_PARTS: usize = MAX_LIST.div_ceil(PART_DATA);
/// Missing parts are sent again after `RESEND`, then after twice as long, up to this.
const LIST_RESEND_MAX: Duration = Duration::from_secs(60);
/// A list being received is acknowledged this long after its last part arrived...
const PART_QUIET: Duration = Duration::from_secs(1);
/// ...and given up after this long without one.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(60);
const CONTEXT: &[u8] = b"kaonic-link-auth v1\0";
const FLAG_ACCEPTED: u8 = 0x01;
/// This AUTH answers one of the peer's: it is never answered itself, so two established
/// sides do not bounce AUTHs back and forth.
const FLAG_REPLY: u8 = 0x02;

/// Without both sides accepted by then, the link is closed.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Our AUTH again, until the peer says it accepted us.
pub const RESEND: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Opened the link.
    Initiator = 0,
    /// Answered it.
    Responder = 1,
}

impl Role {
    fn other(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// Why a link must be closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    Malformed,
    BadSignature,
    /// The AUTH was signed for the wrong end of the link.
    WrongRole,
    /// The initiator reached a different node than it opened the link to.
    WrongPeer,
    /// The peer's certificate or allowlist entry does not pass (text from `kaonic-trust`).
    Untrusted(String),
    /// Other traffic before both sides accepted.
    DataBeforeAuth,
    Timeout,
    /// Accepted once, then taken off the allowlist.
    Revoked,
    /// Accepted once, then blocked by the admin.
    Blocked,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed handshake message"),
            Self::BadSignature => f.write_str("AUTH signature does not verify"),
            Self::WrongRole => f.write_str("AUTH signed for the wrong role"),
            Self::WrongPeer => f.write_str("the link reached a different node"),
            Self::Untrusted(why) => write!(f, "untrusted peer: {why}"),
            Self::DataBeforeAuth => f.write_str("traffic before authentication"),
            Self::Timeout => f.write_str("no authentication in time"),
            Self::Revoked => f.write_str("peer was taken off the allowlist"),
            Self::Blocked => f.write_str("peer was blocked by the admin"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Send these bytes on the link.
    Send(Vec<u8>),
    /// The peer gave us a newer allowlist; `Trust` already holds it. The caller stores it.
    AllowlistUpdated,
    /// Both sides accepted each other: the link may carry traffic now.
    Established { peer: Identity, kind: Peer },
    /// Close the link.
    Close(Reason),
}

/// What this node proves itself with.
#[derive(Clone)]
pub struct Credentials {
    pub identity: Identity,
    pub key: SigningKey,
    /// Our certificate (on the admin device, the root).
    pub cert: Certificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Auth {
    role: u8,
    flags: u8,
    identity: Identity,
    seq: u64,
    cert: Vec<u8>,
    sig: [u8; 64],
}

fn signed_bytes(link_id: &[u8; 16], role: u8, flags: u8, identity: &Identity, seq: u64, cert: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTEXT.len() + 16 + 2 + 64 + 8 + 32);
    out.extend_from_slice(CONTEXT);
    out.extend_from_slice(link_id);
    out.push(role);
    out.push(flags);
    out.extend_from_slice(&identity.to_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&Sha256::digest(cert));
    out
}

impl Auth {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 64 + 8 + 2 + self.cert.len() + 64);
        out.extend_from_slice(&[AUTH, VERSION, self.role, self.flags]);
        out.extend_from_slice(&self.identity.to_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.cert.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.cert);
        out.extend_from_slice(&self.sig);
        out
    }

    fn decode(data: &[u8]) -> Option<Self> {
        let rest = data.strip_prefix(&[AUTH, VERSION])?;
        let (&[role, flags], rest) = rest.split_first_chunk::<2>()?;
        let (identity, rest) = rest.split_first_chunk::<64>()?;
        let (seq, rest) = rest.split_first_chunk::<8>()?;
        let (length, rest) = rest.split_first_chunk::<2>()?;
        let (cert, rest) = rest.split_at_checked(u16::from_be_bytes(*length) as usize)?;
        let sig: [u8; 64] = rest.try_into().ok()?;
        Some(Self { role, flags, identity: Identity::from_bytes(identity), seq: u64::from_be_bytes(*seq), cert: cert.to_vec(), sig })
    }

    fn signed(link_id: &[u8; 16], role: Role, flags: u8, credentials: &Credentials, seq: u64) -> Self {
        let cert = credentials.cert.der().to_vec();
        let message = signed_bytes(link_id, role as u8, flags, &credentials.identity, seq, &cert);
        let sig = credentials.key.sign(&message).to_bytes();
        Self { role: role as u8, flags, identity: credentials.identity, seq, cert, sig }
    }

    fn verify(&self, link_id: &[u8; 16]) -> Result<(), Reason> {
        let key = VerifyingKey::from_bytes(&self.identity.ed25519).map_err(|_| Reason::BadSignature)?;
        let message = signed_bytes(link_id, self.role, self.flags, &self.identity, self.seq, &self.cert);
        key.verify_strict(&message, &Signature::from_bytes(&self.sig)).map_err(|_| Reason::BadSignature)
    }
}

/// Whether link data is a handshake message rather than traffic.
pub fn is_handshake(data: &[u8]) -> bool {
    matches!(data.first(), Some(&AUTH | &ALLOWLIST | &LIST_STATE))
}

/// Part `index` of the allowlist `list` (`seq`).
fn part_message(list: &[u8], seq: u64, index: usize) -> Vec<u8> {
    let data = &list[index * PART_DATA..list.len().min((index + 1) * PART_DATA)];
    let mut out = Vec::with_capacity(16 + data.len());
    out.extend_from_slice(&[ALLOWLIST, PART_VERSION]);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(list.len() as u32).to_be_bytes());
    out.extend_from_slice(&(index as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

struct Part<'a> {
    seq: u64,
    size: usize,
    index: usize,
    data: &'a [u8],
}

impl<'a> Part<'a> {
    fn decode(data: &'a [u8]) -> Option<Self> {
        let rest = data.strip_prefix(&[ALLOWLIST, PART_VERSION])?;
        let (seq, rest) = rest.split_first_chunk::<8>()?;
        let (size, rest) = rest.split_first_chunk::<4>()?;
        let (index, data) = rest.split_first_chunk::<2>()?;
        let size = u32::from_be_bytes(*size) as usize;
        let index = u16::from_be_bytes(*index) as usize;
        if size == 0 || size > MAX_LIST || index >= size.div_ceil(PART_DATA) {
            return None;
        }
        let expected = (size - index * PART_DATA).min(PART_DATA);
        (data.len() == expected).then_some(Self { seq: u64::from_be_bytes(*seq), size, index, data })
    }
}

/// What a peer said it holds: its list, and the parts it has of the one it is receiving.
#[derive(Debug, PartialEq, Eq)]
struct ListState {
    held: u64,
    receiving: u64,
    have: Vec<bool>,
}

impl ListState {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![LIST_STATE, STATE_VERSION];
        out.extend_from_slice(&self.held.to_be_bytes());
        out.extend_from_slice(&self.receiving.to_be_bytes());
        out.extend_from_slice(&(self.have.len() as u16).to_be_bytes());
        let mut bitmap = vec![0u8; self.have.len().div_ceil(8)];
        for (index, _) in self.have.iter().enumerate().filter(|(_, have)| **have) {
            bitmap[index / 8] |= 1 << (index % 8);
        }
        out.extend_from_slice(&bitmap);
        out
    }

    fn decode(data: &[u8]) -> Option<Self> {
        let rest = data.strip_prefix(&[LIST_STATE, STATE_VERSION])?;
        let (held, rest) = rest.split_first_chunk::<8>()?;
        let (receiving, rest) = rest.split_first_chunk::<8>()?;
        let (parts, bitmap) = rest.split_first_chunk::<2>()?;
        let parts = u16::from_be_bytes(*parts) as usize;
        if parts > MAX_PARTS || bitmap.len() != parts.div_ceil(8) {
            return None;
        }
        let have = (0..parts).map(|index| bitmap[index / 8] & (1 << (index % 8)) != 0).collect();
        Some(Self { held: u64::from_be_bytes(*held), receiving: u64::from_be_bytes(*receiving), have })
    }
}

/// Our allowlist on its way to the peer.
struct Outgoing {
    seq: u64,
    /// The parts the peer said it has.
    have: Vec<bool>,
    next_at: Instant,
    wait: Duration,
}

/// The peer's allowlist on its way to us.
struct Incoming {
    seq: u64,
    size: usize,
    parts: Vec<Option<Vec<u8>>>,
    last_part: Instant,
}

/// One link's authentication.
pub struct Handshake {
    role: Role,
    link_id: [u8; 16],
    credentials: Credentials,
    /// The node the initiator opened the link to.
    expected: Option<IdentityHash>,
    started: Instant,
    last_sent: Option<Instant>,
    /// The peer, once we accepted it.
    accepted: Option<(Identity, Peer)>,
    /// The peer's AUTH that failed only because our allowlist may be older than its.
    pending: Option<Auth>,
    peer_accepted_us: bool,
    /// The peer's certificate was issued by our admin: allowlists go both ways.
    peer_ours: bool,
    /// The newest allowlist `seq` the peer said it holds.
    peer_seq: Option<u64>,
    outgoing: Option<Outgoing>,
    incoming: Option<Incoming>,
    last_state: Option<Instant>,
    established: bool,
    closed: bool,
}

impl Handshake {
    pub fn new(role: Role, link_id: [u8; 16], credentials: Credentials, expected: Option<IdentityHash>, now: Instant) -> Self {
        Self {
            role,
            link_id,
            credentials,
            expected,
            started: now,
            last_sent: None,
            accepted: None,
            pending: None,
            peer_accepted_us: false,
            peer_ours: false,
            peer_seq: None,
            outgoing: None,
            incoming: None,
            last_state: None,
            established: false,
            closed: false,
        }
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    /// What the peer proved to be, once accepted.
    pub fn peer_kind(&self) -> Option<Peer> {
        self.accepted.map(|(_, kind)| kind)
    }

    /// The peer, once established.
    pub fn peer(&self) -> Option<&Identity> {
        self.established.then(|| self.accepted.as_ref().map(|(identity, _)| identity)).flatten()
    }

    fn auth(&mut self, trust: &Trust, now: Instant) -> Event {
        self.auth_flagged(trust, now, 0)
    }

    fn reply(&mut self, trust: &Trust, now: Instant) -> Event {
        self.auth_flagged(trust, now, FLAG_REPLY)
    }

    fn auth_flagged(&mut self, trust: &Trust, now: Instant, extra: u8) -> Event {
        let flags = if self.accepted.is_some() { FLAG_ACCEPTED } else { 0 } | extra;
        self.last_sent = Some(now);
        Event::Send(Auth::signed(&self.link_id, self.role, flags, &self.credentials, trust.allowlist().seq()).encode())
    }

    fn close(&mut self, reason: Reason) -> Vec<Event> {
        self.closed = true;
        self.established = false;
        vec![Event::Close(reason)]
    }

    /// Our first AUTH, as soon as Reticulum has activated the link.
    pub fn start(&mut self, trust: &Trust, now: Instant) -> Vec<Event> {
        vec![self.auth(trust, now)]
    }

    fn establish_if_ready(&mut self, events: &mut Vec<Event>) {
        if !self.established
            && self.peer_accepted_us
            && let Some((peer, kind)) = self.accepted
        {
            self.established = true;
            events.push(Event::Established { peer, kind });
        }
    }

    /// Decides on the peer's AUTH: accept, wait for a newer allowlist, or close.
    fn judge(&mut self, auth: Auth, trust: &Trust, now: Instant, events: &mut Vec<Event>) {
        let cert = match Certificate::from_der(&auth.cert) {
            Ok(cert) => cert,
            Err(_) => return events.extend(self.close(Reason::Malformed)),
        };
        let verdict = trust.verify_peer(&auth.identity, &cert);
        // Only a node of our admin may see our list, or hand us its own. A blocked one still
        // gets it, before the link closes, so it learns that it is blocked.
        self.peer_ours = match &verdict {
            Ok(_) | Err(kaonic_trust::Error::NotAllowed) => true,
            Err(kaonic_trust::Error::Blocked) => cert.verify_issued_by(trust.root()).is_ok(),
            Err(_) => false,
        };
        self.send_parts(trust, now, events);
        match verdict {
            Ok(kind) => {
                let first = self.accepted.is_none();
                self.accepted = Some((auth.identity, kind));
                self.pending = None;
                // Tell the peer at once, rather than at the next resend.
                if first {
                    events.push(self.reply(trust, now));
                }
            }
            // It may be on a newer list than ours (allowed, or no longer blocked), which it is
            // about to send.
            Err(kaonic_trust::Error::NotAllowed | kaonic_trust::Error::Blocked) if auth.seq > trust.allowlist().seq() => self.pending = Some(auth),
            Err(error) => events.extend(self.close(Reason::Untrusted(error.to_string()))),
        }
    }

    /// A handshake message from the peer.
    pub fn receive(&mut self, data: &[u8], trust: &mut Trust, now: Instant) -> Vec<Event> {
        if self.closed {
            return Vec::new();
        }
        let mut events = Vec::new();
        match data.first() {
            // From a peer that is not (yet) known to be ours, lists are ignored.
            Some(&ALLOWLIST) if !self.peer_ours => return events,
            Some(&LIST_STATE) if !self.peer_ours => return events,
            Some(&ALLOWLIST) => {
                if let Some(list) = data.strip_prefix(&[ALLOWLIST, VERSION]) {
                    self.take_list(list, trust, now, &mut events);
                } else if let Some(part) = Part::decode(data) {
                    self.on_part(part, trust, now, &mut events);
                } else {
                    return self.close(Reason::Malformed);
                }
            }
            Some(&LIST_STATE) => {
                let Some(state) = ListState::decode(data) else { return self.close(Reason::Malformed) };
                self.on_state(state, trust, now, &mut events);
            }
            Some(&AUTH) => {
                let Some(auth) = Auth::decode(data) else { return self.close(Reason::Malformed) };
                if auth.role != self.role.other() as u8 {
                    return self.close(Reason::WrongRole);
                }
                if let Err(reason) = auth.verify(&self.link_id) {
                    return self.close(reason);
                }
                if self.expected.is_some_and(|expected| expected != auth.identity.hash()) {
                    return self.close(Reason::WrongPeer);
                }
                if self.accepted.as_ref().is_some_and(|(identity, _)| *identity != auth.identity) {
                    return self.close(Reason::WrongPeer);
                }
                self.peer_holds(auth.seq);
                if auth.flags & FLAG_ACCEPTED != 0 {
                    self.peer_accepted_us = true;
                }
                if self.accepted.is_none() {
                    self.judge(auth, trust, now, &mut events);
                } else {
                    self.send_parts(trust, now, &mut events);
                    // The peer resends its AUTH only until it has seen ours with the flag: ours
                    // was lost, so send it again (even when we are already established). A reply
                    // is not answered, or two established sides would bounce AUTHs forever.
                    if auth.flags & FLAG_REPLY == 0 {
                        events.push(self.reply(trust, now));
                    }
                }
                if self.closed {
                    return events;
                }
            }
            _ => return self.close(Reason::Malformed),
        }
        self.establish_if_ready(&mut events);
        events
    }

    /// Traffic (not a handshake message) arrived. The peer sends traffic only once it has
    /// accepted us, so it also completes the handshake when its flagged AUTH was lost.
    pub fn on_traffic(&mut self) -> Result<Vec<Event>, Reason> {
        if self.closed || self.established {
            return Ok(Vec::new());
        }
        if self.accepted.is_none() {
            self.closed = true;
            return Err(Reason::DataBeforeAuth);
        }
        self.peer_accepted_us = true;
        let mut events = Vec::new();
        self.establish_if_ready(&mut events);
        Ok(events)
    }

    /// Resends and the deadline. Call it every second or so, also once established.
    pub fn tick(&mut self, trust: &Trust, now: Instant) -> Vec<Event> {
        if self.closed {
            return Vec::new();
        }
        let mut events = Vec::new();
        self.send_parts(trust, now, &mut events);
        let mut receiving = false;
        if let Some(incoming) = &self.incoming {
            let quiet = now.duration_since(incoming.last_part);
            receiving = quiet < RESEND;
            if quiet >= RECEIVE_TIMEOUT {
                self.incoming = None;
            } else if quiet >= PART_QUIET && self.last_state.is_none_or(|sent| now.duration_since(sent) >= RESEND) {
                events.push(self.list_state(trust, now));
            }
        }
        if self.established {
            return events;
        }
        // A big list may take longer than the handshake would: wait while it keeps coming.
        let waited = now.duration_since(self.started);
        if waited >= TIMEOUT && (!receiving || waited >= 4 * TIMEOUT) {
            events.extend(self.close(Reason::Timeout));
            return events;
        }
        if self.last_sent.is_none_or(|sent| now.duration_since(sent) >= RESEND) {
            events.push(self.auth(trust, now));
        }
        events
    }

    /// Our allowlist changed: send it to the peer if it holds an older one.
    pub fn list_changed(&mut self, trust: &Trust, now: Instant) -> Vec<Event> {
        let mut events = Vec::new();
        if !self.closed {
            self.send_parts(trust, now, &mut events);
        }
        events
    }

    fn peer_holds(&mut self, seq: u64) {
        self.peer_seq = Some(self.peer_seq.map_or(seq, |held| held.max(seq)));
    }

    /// Sends the parts of our list the peer lacks, if it is ours and holds an older list, and
    /// it is time to.
    fn send_parts(&mut self, trust: &Trust, now: Instant, events: &mut Vec<Event>) {
        let ours = trust.allowlist().seq();
        if !self.peer_ours || self.peer_seq.is_none_or(|held| held >= ours) {
            self.outgoing = None;
            return;
        }
        let list = trust.allowlist().as_bytes();
        let outgoing = match &mut self.outgoing {
            Some(outgoing) if outgoing.seq == ours => outgoing,
            _ => self.outgoing.insert(Outgoing { seq: ours, have: vec![false; list.len().div_ceil(PART_DATA)], next_at: now, wait: RESEND }),
        };
        if now < outgoing.next_at {
            return;
        }
        for (index, _) in outgoing.have.iter().enumerate().filter(|(_, have)| !**have) {
            events.push(Event::Send(part_message(list, ours, index)));
        }
        outgoing.next_at = now + outgoing.wait;
        outgoing.wait = (outgoing.wait * 2).min(LIST_RESEND_MAX);
    }

    fn list_state(&mut self, trust: &Trust, now: Instant) -> Event {
        self.last_state = Some(now);
        let (receiving, have) = match &self.incoming {
            Some(incoming) => (incoming.seq, incoming.parts.iter().map(Option::is_some).collect()),
            None => (0, Vec::new()),
        };
        Event::Send(ListState { held: trust.allowlist().seq(), receiving, have }.encode())
    }

    /// Tells the peer what we hold, at most once per `PART_QUIET`.
    fn acknowledge(&mut self, trust: &Trust, now: Instant, events: &mut Vec<Event>) {
        if self.last_state.is_none_or(|sent| now.duration_since(sent) >= PART_QUIET) {
            events.push(self.list_state(trust, now));
        }
    }

    fn on_part(&mut self, part: Part<'_>, trust: &mut Trust, now: Instant, events: &mut Vec<Event>) {
        if part.seq <= trust.allowlist().seq() {
            // The peer thinks we lack a list we hold: tell it, so it stops.
            self.peer_holds(part.seq);
            return self.acknowledge(trust, now, events);
        }
        let incoming = match &mut self.incoming {
            Some(incoming) if incoming.seq == part.seq && incoming.size == part.size => incoming,
            Some(incoming) if incoming.seq > part.seq => return,
            _ => self.incoming.insert(Incoming { seq: part.seq, size: part.size, parts: vec![None; part.size.div_ceil(PART_DATA)], last_part: now }),
        };
        incoming.parts[part.index] = Some(part.data.to_vec());
        incoming.last_part = now;
        if incoming.parts.iter().all(Option::is_some) {
            let list: Vec<u8> = incoming.parts.iter().flatten().flatten().copied().collect();
            self.incoming = None;
            self.peer_holds(part.seq);
            self.take_list(&list, trust, now, events);
            self.last_state = None;
            self.acknowledge(trust, now, events);
        }
    }

    /// A whole list from the peer. One our admin did not sign, or not newer, is ignored.
    fn take_list(&mut self, list: &[u8], trust: &mut Trust, now: Instant, events: &mut Vec<Event>) {
        if let Ok(true) = trust.update_allowlist(list) {
            events.push(Event::AllowlistUpdated);
            if let Some(auth) = self.pending.take() {
                self.judge(auth, trust, now, events);
            }
        }
    }

    fn on_state(&mut self, state: ListState, trust: &Trust, now: Instant, events: &mut Vec<Event>) {
        self.peer_holds(state.held);
        if let Some(outgoing) = &mut self.outgoing
            && state.receiving == outgoing.seq
            && state.have.len() == outgoing.have.len()
        {
            let before = outgoing.have.iter().filter(|have| **have).count();
            for (mine, theirs) in outgoing.have.iter_mut().zip(&state.have) {
                *mine |= *theirs;
            }
            // Progress: send the rest now, and start the waits over.
            if outgoing.have.iter().filter(|have| **have).count() > before {
                outgoing.next_at = now;
                outgoing.wait = RESEND;
            }
        }
        self.send_parts(trust, now, events);
    }

    /// After our allowlist changed: is the established peer still trusted?
    pub fn recheck(&mut self, trust: &Trust) -> Option<Event> {
        let (identity, kind) = self.accepted?;
        if kind == Peer::Admin || trust.allowlist().contains(&identity.hash()) {
            return None;
        }
        self.closed = true;
        self.established = false;
        let blocked = trust.allowlist().is_blocked(&identity.hash());
        Some(Event::Close(if blocked { Reason::Blocked } else { Reason::Revoked }))
    }
}

#[cfg(test)]
mod tests;
