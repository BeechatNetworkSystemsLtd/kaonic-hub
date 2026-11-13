//! What a listener takes from the group: every packet heard passes here before it is played
//! or relayed.
//!
//! - An admin packet must carry the admin's signature (all of an admin burst's packets do),
//!   under the admin's talker id.
//! - An unsigned packet must not use the admin's talker id, nor claim a burst the admin
//!   opened (a member adding its own audio to it). So only the admin's own packets move its
//!   replay counter: a member cannot lock the admin out with a forged high one.
//! - Nothing is taken twice, and no burst older than one already heard from its talker
//!   ([`Replay`]).
//!
//! Members share the group key, so one member can still forge another member's packets; that
//! is the limit of a shared key. Pure, like the rest of the crate.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{Packet, Replay, verify_admin};

/// Admin bursts are remembered this long after their last packet.
const ADMIN_BURST_MEMORY: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A member's packet: play without priority.
    Member,
    /// The admin's, signature verified: play with priority.
    Admin,
    /// Forged or replayed: neither play nor relay.
    Refused,
}

#[derive(Default)]
pub struct Gate {
    admin_key: Option<[u8; 32]>,
    /// The admin's talker id (the first 4 bytes of its identity hash).
    admin_talker: Option<[u8; 4]>,
    admin_bursts: HashMap<([u8; 4], u16), Instant>,
    replay: Replay,
}

impl Gate {
    pub fn new() -> Self {
        Self::default()
    }

    /// The admin's Ed25519 key (from the root certificate); None while unprovisioned.
    pub fn set_admin_key(&mut self, key: Option<[u8; 32]>) {
        self.admin_key = key;
    }

    /// The admin's talker id; None while unknown.
    pub fn set_admin_talker(&mut self, talker: Option<[u8; 4]>) {
        self.admin_talker = talker;
        self.replay.protect(talker);
    }

    pub fn replay(&mut self) -> &mut Replay {
        &mut self.replay
    }

    pub fn check(&mut self, packet: &Packet, now: Instant) -> Verdict {
        self.admin_bursts.retain(|_, at| now.duration_since(*at) < ADMIN_BURST_MEMORY);
        let key = (packet.talker, packet.burst);
        let is_admin_talker = self.admin_talker == Some(packet.talker);
        let admin = if packet.is_admin() {
            let Some(admin_key) = &self.admin_key else { return Verdict::Refused };
            if self.admin_talker.is_some_and(|admin| admin != packet.talker) || !verify_admin(packet, admin_key) {
                return Verdict::Refused;
            }
            true
        } else if is_admin_talker || self.admin_bursts.contains_key(&key) {
            return Verdict::Refused;
        } else {
            false
        };
        if !self.replay.check(packet, now) {
            return Verdict::Refused;
        }
        if admin {
            self.admin_bursts.insert(key, now);
            Verdict::Admin
        } else {
            Verdict::Member
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{codec, flags, sign_admin};

    fn packet(burst: u16, seq: u16, counter: u32, start: bool) -> Packet {
        Packet { flags: if start { flags::START } else { 0 }, ttl: 4, epoch: 1, talker: [7; 4], burst, seq, counter, codec: codec::OPUS16, frames: vec![vec![3; 40]], signature: None }
    }

    fn admin_packet(key: &SigningKey, burst: u16, seq: u16, counter: u32, start: bool) -> Packet {
        let mut packet = packet(burst, seq, counter, start);
        sign_admin(&mut packet, key);
        packet
    }

    fn admin_gate(key: &SigningKey) -> Gate {
        let mut gate = Gate::new();
        gate.set_admin_key(Some(key.verifying_key().to_bytes()));
        gate.set_admin_talker(Some([7; 4]));
        gate
    }

    #[test]
    fn every_admin_packet_is_verified_and_a_member_cannot_join_an_admin_burst() {
        let admin = SigningKey::from_bytes(&[1; 32]);
        let member = SigningKey::from_bytes(&[2; 32]);
        let now = Instant::now();
        let mut gate = admin_gate(&admin);
        assert_eq!(gate.check(&admin_packet(&admin, 5, 0, 10, true), now), Verdict::Admin);
        assert_eq!(gate.check(&admin_packet(&admin, 5, 4, 10, false), now), Verdict::Admin);
        // A member with the group key: an unsigned packet in the admin's burst, and one signed
        // with its own key claiming to be the admin's.
        assert_eq!(gate.check(&packet(5, 8, 10, false), now), Verdict::Refused);
        assert_eq!(gate.check(&admin_packet(&member, 5, 8, 10, false), now), Verdict::Refused);
        let mut tampered = admin_packet(&admin, 5, 8, 10, false);
        tampered.frames[0][0] ^= 1;
        assert_eq!(gate.check(&tampered, now), Verdict::Refused);
        assert_eq!(gate.check(&admin_packet(&admin, 5, 8, 10, false), now), Verdict::Admin);
    }

    #[test]
    fn a_recorded_admin_burst_is_refused_after_a_newer_one() {
        let admin = SigningKey::from_bytes(&[1; 32]);
        let now = Instant::now();
        let mut gate = admin_gate(&admin);
        let recorded = admin_packet(&admin, 5, 0, 10, true);
        assert_eq!(gate.check(&recorded, now), Verdict::Admin);
        assert_eq!(gate.check(&admin_packet(&admin, 6, 0, 11, true), now), Verdict::Admin);
        assert_eq!(gate.check(&recorded, now + Duration::from_secs(300)), Verdict::Refused);

        // And after this listener restarts, with the counter it kept.
        let mut restarted = admin_gate(&admin);
        restarted.replay().restore([7; 4], 11);
        assert_eq!(restarted.check(&recorded, now), Verdict::Refused);
        assert_eq!(restarted.check(&admin_packet(&admin, 7, 0, 12, true), now), Verdict::Admin);
    }

    #[test]
    fn without_an_admin_key_nothing_passes_as_admin() {
        let admin = SigningKey::from_bytes(&[1; 32]);
        let mut gate = Gate::new();
        assert_eq!(gate.check(&admin_packet(&admin, 5, 0, 10, true), Instant::now()), Verdict::Refused);
        assert_eq!(gate.check(&packet(6, 0, 1, true), Instant::now()), Verdict::Member);
    }

    #[test]
    fn the_admins_last_burst_cannot_be_played_again() {
        let admin = SigningKey::from_bytes(&[1; 32]);
        let now = Instant::now();
        let mut gate = admin_gate(&admin);
        let recorded: Vec<Packet> = (0..3).map(|seq| admin_packet(&admin, 5, seq, 10, seq == 0)).collect();
        let mut end = packet(5, 3, 10, false);
        end.flags |= crate::flags::END;
        sign_admin(&mut end, &admin);
        for packet in recorded.iter().chain([&end]) {
            assert_eq!(gate.check(packet, now), Verdict::Admin);
        }
        // Long after the relay forgot it, with no newer admin burst in between.
        let later = now + Duration::from_secs(3600);
        for packet in recorded.iter().chain([&end]) {
            assert_eq!(gate.check(packet, later), Verdict::Refused);
        }
    }

    #[test]
    fn a_member_cannot_use_the_admins_talker_id() {
        let admin = SigningKey::from_bytes(&[1; 32]);
        let now = Instant::now();
        let mut gate = admin_gate(&admin);
        // An unsigned packet under the admin's id, with the highest counter there is: refused,
        // and it does not lock the admin out.
        assert_eq!(gate.check(&packet(9, 0, u32::MAX, true), now), Verdict::Refused);
        assert_eq!(gate.check(&admin_packet(&admin, 10, 0, 11, true), now), Verdict::Admin);
        // The admin's signature under another talker id is refused too.
        let mut elsewhere = packet(11, 0, 12, true);
        elsewhere.talker = [8; 4];
        sign_admin(&mut elsewhere, &admin);
        assert_eq!(gate.check(&elsewhere, now), Verdict::Refused);
    }
}
