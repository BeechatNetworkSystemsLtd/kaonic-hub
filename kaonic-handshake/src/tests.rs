use std::time::{Duration, Instant};

use kaonic_trust::{Allowlist, Certificate, Identity, Peer, Trust};

use super::*;

const ISSUED_AT: u64 = 1_792_000_000;
const LINK: [u8; 16] = [7; 16];

struct Node {
    credentials: Credentials,
    trust: Trust,
}

fn identity(seed: u8) -> (Identity, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    (Identity { x25519: [seed.wrapping_add(100); 32], ed25519: key.verifying_key().to_bytes() }, key)
}

struct Admin {
    identity: Identity,
    key: SigningKey,
    root: Certificate,
}

impl Admin {
    fn new(seed: u8) -> Self {
        let (identity, key) = identity(seed);
        let root = Certificate::new_root(&identity, &key, ISSUED_AT).unwrap();
        Self { identity, key, root }
    }

    fn allowlist(&self, seq: u64, nodes: &[u8]) -> Allowlist {
        Allowlist::sign(&self.key, seq, nodes.iter().map(|seed| identity(*seed).0.hash())).unwrap()
    }

    /// A node of this admin holding the allowlist `seq` listing `listed`.
    fn node(&self, seed: u8, seq: u64, listed: &[u8]) -> Node {
        let (identity, key) = identity(seed);
        let request = kaonic_pki::CertRequest::create(&identity, &key, b"link").unwrap();
        let cert = self.root.issue(&self.key, &request, &identity, ISSUED_AT).unwrap();
        let trust = Trust::from_der(self.root.der(), cert.der(), self.allowlist(seq, listed).as_bytes()).unwrap();
        Node { credentials: Credentials { identity, key, cert }, trust }
    }

    fn itself(&self, seq: u64, listed: &[u8]) -> Node {
        let trust = Trust::from_der(self.root.der(), self.root.der(), self.allowlist(seq, listed).as_bytes()).unwrap();
        Node { credentials: Credentials { identity: self.identity, key: self.key.clone(), cert: self.root.clone() }, trust }
    }
}

struct Side {
    node: Node,
    handshake: Handshake,
    established: Option<Identity>,
    closed: Option<Reason>,
    allowlist_updates: usize,
}

fn side(node: Node, role: Role, expected: Option<&Node>, now: Instant) -> Side {
    let expected = expected.map(|peer| peer.credentials.identity.hash());
    let handshake = Handshake::new(role, LINK, node.credentials.clone(), expected, now);
    Side { node, handshake, established: None, closed: None, allowlist_updates: 0 }
}

/// Applies events; returns what to send to the other side.
fn apply(side: &mut Side, events: Vec<Event>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for event in events {
        match event {
            Event::Send(bytes) => out.push(bytes),
            Event::AllowlistUpdated => side.allowlist_updates += 1,
            Event::Established { peer, .. } => side.established = Some(peer),
            Event::Close(reason) => side.closed = Some(reason),
        }
    }
    out
}

/// Runs both sides for `seconds`, in 1 s steps, dropping messages `drop` picks (by index of
/// message sent, from 1, and content).
fn run(a: &mut Side, b: &mut Side, start: Instant, seconds: u64, drop: impl Fn(usize, &[u8]) -> bool) {
    let events = a.handshake.start(&a.node.trust, start);
    let to_b = apply(a, events);
    let events = b.handshake.start(&b.node.trust, start);
    let to_a = apply(b, events);
    pump(a, b, start, seconds, to_a, to_b, drop);
}

/// Delivers `to_a` and `to_b`, then runs both sides for `seconds` more, like `run`.
fn pump(a: &mut Side, b: &mut Side, start: Instant, seconds: u64, mut to_a: Vec<Vec<u8>>, mut to_b: Vec<Vec<u8>>, drop: impl Fn(usize, &[u8]) -> bool) {
    let mut sent = 0;
    for second in 0..=seconds {
        let now = start + Duration::from_secs(second);
        // Deliver until quiet, then tick. An exchange that never goes quiet is a bug (two sides
        // answering each other forever), not something to cut off.
        for round in 0.. {
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
            assert!(round < 50, "the handshake never goes quiet");
            for message in std::mem::take(&mut to_b) {
                sent += 1;
                if !drop(sent, &message) {
                    let events = b.handshake.receive(&message, &mut b.node.trust, now);
                    to_a.extend(apply(b, events));
                }
            }
            for message in std::mem::take(&mut to_a) {
                sent += 1;
                if !drop(sent, &message) {
                    let events = a.handshake.receive(&message, &mut a.node.trust, now);
                    to_b.extend(apply(a, events));
                }
            }
        }
        let events = a.handshake.tick(&a.node.trust, now);
        to_b.extend(apply(a, events));
        let events = b.handshake.tick(&b.node.trust, now);
        to_a.extend(apply(b, events));
    }
}

fn pair(a: Node, b: Node) -> (Side, Side, Instant) {
    let now = Instant::now();
    let b_identity = Node { credentials: b.credentials.clone(), trust: b.trust.clone() };
    (side(a, Role::Initiator, Some(&b_identity), now), side(b, Role::Responder, None, now), now)
}

#[test]
fn two_listed_nodes_accept_each_other() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert_eq!(a.established, Some(b.node.credentials.identity));
    assert_eq!(b.established, Some(a.node.credentials.identity));
    assert!(a.closed.is_none() && b.closed.is_none());
}

#[test]
fn lost_messages_only_delay_the_link() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    // The first three messages are lost: both first AUTHs and the first answer.
    run(&mut a, &mut b, now, 10, |index, _| index <= 3);
    assert!(a.handshake.is_established() && b.handshake.is_established());
}

#[test]
fn established_sides_go_quiet_even_when_an_auth_arrives_late() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert!(a.handshake.is_established() && b.handshake.is_established());
    // A late copy of a's first AUTH (a resend, not a reply) reaches b once both are up: b answers
    // once, and its answer (a reply) is not answered.
    let Event::Send(late) = Handshake::new(Role::Initiator, LINK, a.node.credentials.clone(), None, now).start(&a.node.trust, now).remove(0) else { panic!() };
    let answers = b.handshake.receive(&late, &mut b.node.trust, now);
    let [Event::Send(answer)] = answers.as_slice() else { panic!("b answers a resend once: {answers:?}") };
    assert!(a.handshake.receive(answer, &mut a.node.trust, now).is_empty(), "a reply is never answered");
}

#[test]
fn a_lost_answer_after_the_peer_is_established_is_repaired() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    // Message 4 is a's flagged AUTH, the last one b needs: a is established, b is not yet.
    run(&mut a, &mut b, now, 10, |index, _| index == 4);
    assert!(a.handshake.is_established() && b.handshake.is_established());
}

#[test]
fn the_admin_is_trusted_without_being_listed() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.itself(1, &[11]), admin.node(11, 1, &[11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert!(a.handshake.is_established() && b.handshake.is_established());
}

#[test]
fn a_node_off_the_allowlist_is_refused() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10]), admin.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert!(matches!(a.closed, Some(Reason::Untrusted(_))));
    assert!(!b.handshake.is_established());
}

#[test]
fn a_node_of_another_admin_is_refused() {
    let ours = Admin::new(1);
    let theirs = Admin::new(2);
    let (mut a, mut b, now) = pair(ours.node(10, 1, &[10, 11]), theirs.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert!(matches!(a.closed, Some(Reason::Untrusted(_))));
    assert!(matches!(b.closed, Some(Reason::Untrusted(_))));
}

#[test]
fn a_newer_allowlist_spreads_and_lets_the_new_node_in() {
    let admin = Admin::new(1);
    // a was provisioned first (seq 1, only itself); b later, with seq 2 listing both.
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10]), admin.node(11, 2, &[10, 11]));
    run(&mut a, &mut b, now, 2, |_, _| false);
    assert_eq!(a.allowlist_updates, 1);
    assert_eq!(a.node.trust.allowlist().seq(), 2);
    assert!(a.handshake.is_established() && b.handshake.is_established());
}

#[test]
fn an_auth_recorded_on_another_link_does_not_verify() {
    let admin = Admin::new(1);
    let a = admin.node(10, 1, &[10, 11]);
    let mut b = admin.node(11, 1, &[10, 11]);
    let now = Instant::now();
    let mut elsewhere = Handshake::new(Role::Initiator, [9; 16], a.credentials.clone(), None, now);
    let Event::Send(recorded) = elsewhere.start(&a.trust, now).remove(0) else { panic!() };
    let mut here = Handshake::new(Role::Responder, LINK, b.credentials.clone(), None, now);
    assert_eq!(here.receive(&recorded, &mut b.trust, now), vec![Event::Close(Reason::BadSignature)]);
}

#[test]
fn an_auth_for_the_wrong_role_is_refused() {
    let admin = Admin::new(1);
    let a = admin.node(10, 1, &[10, 11]);
    let mut b = admin.node(11, 1, &[10, 11]);
    let now = Instant::now();
    let mut same_role = Handshake::new(Role::Responder, LINK, a.credentials.clone(), None, now);
    let Event::Send(auth) = same_role.start(&a.trust, now).remove(0) else { panic!() };
    let mut here = Handshake::new(Role::Responder, LINK, b.credentials.clone(), None, now);
    assert_eq!(here.receive(&auth, &mut b.trust, now), vec![Event::Close(Reason::WrongRole)]);
}

#[test]
fn the_initiator_refuses_a_different_node_than_it_called() {
    let admin = Admin::new(1);
    let a = admin.node(10, 1, &[10, 11, 12]);
    let b = admin.node(11, 1, &[10, 11, 12]);
    let c = admin.node(12, 1, &[10, 11, 12]);
    let now = Instant::now();
    let mut a = side(a, Role::Initiator, Some(&b), now);
    let mut c = side(c, Role::Responder, None, now);
    run(&mut a, &mut c, now, 1, |_, _| false);
    assert_eq!(a.closed, Some(Reason::WrongPeer));
}

#[test]
fn traffic_before_acceptance_closes_and_after_it_completes_the_handshake() {
    let admin = Admin::new(1);
    let mut a = admin.node(10, 1, &[10, 11]);
    let b = admin.node(11, 1, &[10, 11]);
    let now = Instant::now();
    let mut early = Handshake::new(Role::Responder, LINK, a.credentials.clone(), None, now);
    assert_eq!(early.on_traffic(), Err(Reason::DataBeforeAuth));

    // a accepts b's AUTH, but b's flagged answer is lost; b's first traffic completes it.
    let mut here = Handshake::new(Role::Responder, LINK, a.credentials.clone(), None, now);
    let mut there = Handshake::new(Role::Initiator, LINK, b.credentials.clone(), None, now);
    let Event::Send(auth) = there.start(&b.trust, now).remove(0) else { panic!() };
    here.receive(&auth, &mut a.trust, now);
    assert!(!here.is_established());
    let events = here.on_traffic().unwrap();
    assert!(matches!(events.as_slice(), [Event::Established { kind: Peer::Node, .. }]));
}

#[test]
fn no_answer_times_out() {
    let admin = Admin::new(1);
    let a = admin.node(10, 1, &[10, 11]);
    let now = Instant::now();
    let mut handshake = Handshake::new(Role::Initiator, LINK, a.credentials.clone(), None, now);
    handshake.start(&a.trust, now);
    assert!(matches!(handshake.tick(&a.trust, now + RESEND).as_slice(), [Event::Send(_)]));
    assert_eq!(handshake.tick(&a.trust, now + TIMEOUT), vec![Event::Close(Reason::Timeout)]);
}

#[test]
fn revocation_closes_an_established_link() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert!(a.handshake.is_established());
    assert!(a.node.trust.update_allowlist(admin.allowlist(2, &[10]).as_bytes()).unwrap());
    assert_eq!(a.handshake.recheck(&a.node.trust), Some(Event::Close(Reason::Revoked)));
}

#[test]
fn blocking_closes_an_established_link() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 1, |_, _| false);
    assert!(a.handshake.is_established());
    let blocked = Allowlist::sign_with_blocked(&admin.key, 2, [identity(10).0.hash()], [identity(11).0.hash()]).unwrap();
    assert!(a.node.trust.update_allowlist(blocked.as_bytes()).unwrap());
    assert_eq!(a.handshake.recheck(&a.node.trust), Some(Event::Close(Reason::Blocked)));
}

#[test]
fn a_blocked_node_is_refused_and_learns_the_list() {
    let admin = Admin::new(1);
    // b holds the newer list that blocks a; a still has the one that lists it.
    let mut b = admin.node(11, 1, &[]);
    let blocked = Allowlist::sign_with_blocked(&admin.key, 2, [identity(11).0.hash()], [identity(10).0.hash()]).unwrap();
    assert!(b.trust.update_allowlist(blocked.as_bytes()).unwrap());
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), b);
    run(&mut a, &mut b, now, 2, |_, _| false);
    assert!(matches!(&b.closed, Some(Reason::Untrusted(why)) if why.contains("blocked")));
    assert!(!a.handshake.is_established() && !b.handshake.is_established());
}

#[test]
fn garbage_is_malformed_and_auth_round_trips() {
    let admin = Admin::new(1);
    let mut a = admin.node(10, 1, &[10]);
    let now = Instant::now();
    let auth = Auth::signed(&LINK, Role::Initiator, FLAG_ACCEPTED, &a.credentials, 5);
    assert_eq!(Auth::decode(&auth.encode()), Some(auth.clone()));
    let mut truncated = auth.encode();
    truncated.pop();
    let mut handshake = Handshake::new(Role::Responder, LINK, a.credentials.clone(), None, now);
    assert_eq!(handshake.receive(&truncated, &mut a.trust, now), vec![Event::Close(Reason::Malformed)]);
    assert!(is_handshake(&auth.encode()) && !is_handshake(&[0xB0]));
}

/// A list allowing `nodes` and `extra` made-up identities, too big for one link packet.
fn big_list(admin: &Admin, seq: u64, nodes: &[u8], extra: u16) -> Allowlist {
    let made_up = (0..extra).map(|n| {
        let mut hash = [0xEE; 16];
        hash[..2].copy_from_slice(&n.to_be_bytes());
        kaonic_trust::IdentityHash(hash)
    });
    Allowlist::sign(&admin.key, seq, nodes.iter().map(|seed| identity(*seed).0.hash()).chain(made_up)).unwrap()
}

fn sends(events: &[Event], kind: u8) -> usize {
    events.iter().filter(|event| matches!(event, Event::Send(bytes) if bytes.first() == Some(&kind))).count()
}

#[test]
fn a_stranger_never_gets_our_list() {
    let admin = Admin::new(1);
    let mut a = admin.node(10, 5, &[10]);
    // A node of another admin, holding an older list.
    let stranger = Admin::new(2).node(20, 0, &[20]);
    let now = Instant::now();
    let mut handshake = Handshake::new(Role::Responder, LINK, a.credentials.clone(), None, now);
    let auth = Auth::signed(&LINK, Role::Initiator, 0, &stranger.credentials, 0).encode();
    let events = handshake.receive(&auth, &mut a.trust, now);
    assert_eq!(sends(&events, ALLOWLIST), 0);
    assert!(matches!(events.last(), Some(Event::Close(Reason::Untrusted(_)))));
}

#[test]
fn a_list_too_big_for_one_packet_spreads_in_parts() {
    let admin = Admin::new(1);
    let mut b = admin.node(11, 1, &[]);
    let list = big_list(&admin, 2, &[10, 11], 300);
    assert!(list.as_bytes().len() > 4 * PART_DATA);
    assert!(b.trust.update_allowlist(list.as_bytes()).unwrap());
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10]), b);
    run(&mut a, &mut b, now, 3, |_, _| false);
    assert_eq!(a.node.trust.allowlist().seq(), 2);
    assert_eq!(a.allowlist_updates, 1);
    assert!(a.handshake.is_established() && b.handshake.is_established());
}

#[test]
fn lost_parts_are_sent_again() {
    let admin = Admin::new(1);
    let mut b = admin.node(11, 1, &[]);
    assert!(b.trust.update_allowlist(big_list(&admin, 2, &[10, 11], 300).as_bytes()).unwrap());
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10]), b);
    // Every other part is lost, until the first 10 parts have been sent.
    let parts = std::cell::Cell::new(0);
    run(&mut a, &mut b, now, 25, |_, message| {
        if message.first() != Some(&ALLOWLIST) {
            return false;
        }
        parts.set(parts.get() + 1);
        parts.get() <= 10 && parts.get() % 2 == 1
    });
    assert!(parts.get() > 10, "the lost parts were sent again");
    assert_eq!(a.node.trust.allowlist().seq(), 2);
    assert!(a.handshake.is_established() && b.handshake.is_established());
}

#[test]
fn a_revocation_reaches_an_established_peer_even_when_its_parts_are_lost() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11, 12]), admin.node(11, 1, &[10, 11, 12]));
    run(&mut a, &mut b, now, 2, |_, _| false);
    assert!(a.handshake.is_established() && b.handshake.is_established());

    // b gets a newer list (12 revoked) and tells a; every part of the first try is lost.
    let later = now + Duration::from_secs(10);
    assert!(b.node.trust.update_allowlist(big_list(&admin, 2, &[10, 11], 200).as_bytes()).unwrap());
    let events = b.handshake.list_changed(&b.node.trust, later);
    let parts = sends(&events, ALLOWLIST);
    assert!(parts > 1);
    apply(&mut b, events);
    pump(&mut a, &mut b, later, 20, Vec::new(), Vec::new(), |_, _| false);
    assert_eq!(a.node.trust.allowlist().seq(), 2);
    assert!(!a.node.trust.allowlist().contains(&identity(12).0.hash()));
    // Once a holds it, b stops sending.
    let quiet = later + Duration::from_secs(120);
    assert_eq!(b.handshake.tick(&b.node.trust, quiet), Vec::new());
}

#[test]
fn a_closed_handshake_stays_closed() {
    let admin = Admin::new(1);
    let (mut a, mut b, now) = pair(admin.node(10, 1, &[10, 11]), admin.node(11, 1, &[10, 11]));
    run(&mut a, &mut b, now, 2, |_, _| false);
    let events = a.handshake.receive(&[ALLOWLIST, 9], &mut a.node.trust, now);
    assert_eq!(events, vec![Event::Close(Reason::Malformed)]);
    assert!(!a.handshake.is_established() && a.handshake.peer().is_none());
    assert_eq!(a.handshake.on_traffic(), Ok(Vec::new()));
    assert!(!a.handshake.is_established());
    assert_eq!(a.handshake.tick(&a.node.trust, now + Duration::from_secs(60)), Vec::new());
}

#[test]
fn parts_and_list_states_round_trip_and_bad_ones_are_refused() {
    let list = vec![7u8; 2 * PART_DATA + 10];
    let last = part_message(&list, 3, 2);
    let part = Part::decode(&last).unwrap();
    assert_eq!((part.seq, part.size, part.index, part.data.len()), (3, list.len(), 2, 10));
    // Wrong length, index past the end, a size over the limit.
    assert!(Part::decode(&last[..last.len() - 1]).is_none());
    let mut past = last.clone();
    past[14..16].copy_from_slice(&3u16.to_be_bytes());
    assert!(Part::decode(&past).is_none());
    let mut huge = last.clone();
    huge[10..14].copy_from_slice(&((MAX_LIST + 1) as u32).to_be_bytes());
    assert!(Part::decode(&huge).is_none());

    let state = ListState { held: 4, receiving: 5, have: vec![true, false, false, true, true, false, false, false, true] };
    assert_eq!(ListState::decode(&state.encode()), Some(state));
    assert!(ListState::decode(&[LIST_STATE, STATE_VERSION, 0]).is_none());
}
