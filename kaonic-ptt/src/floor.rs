//! Who has the floor: one talker per group.
//!
//! - A node keys only after 300 ms without voice; the caller may wait a further random
//!   0-100 ms ([`recheck_delay`]) and ask again, so two nodes keying together rarely collide.
//! - A burst ends at its END packet, or after 500 ms without packets of its own (other
//!   talkers' packets do not keep it alive).
//! - A verified admin burst takes the floor: a member talking here is preempted.
//! - Bursts that started within [`CONTEND`] of each other: the lower talker id wins on every
//!   node, and the other talker stops when it hears the winner. Further apart, the earlier
//!   burst wins. A burst's start comes from its seq, not from when it was heard, so nodes at
//!   different distances agree.
//! - A newer burst of the talker holding the floor replaces the old one at once (the old
//!   one's END was lost).

use std::time::{Duration, Instant};

use crate::packet::Packet;

/// Silence needed before keying.
pub const CLEAR_FOR: Duration = Duration::from_millis(300);
/// A remote burst with no packets for this long has ended.
pub const BURST_TIMEOUT: Duration = Duration::from_millis(500);
/// Bursts that started closer together than this count as keyed at once: the lower talker
/// id wins. Well above the time a packet takes to cross the mesh at ttl 4.
pub const CONTEND: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorState {
    Idle,
    /// This node talks.
    Talking,
    /// Another node talks.
    Receiving,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Talker {
    pub talker: [u8; 4],
    pub burst: u16,
    /// A verified admin burst (or our own, keyed as admin).
    pub admin: bool,
    /// When it was first heard here (our own: when we keyed).
    pub since: Instant,
    /// When the burst began, on our clock: its first packet's arrival less the frames before it.
    pub started: Instant,
}

impl Talker {
    /// Whether member burst `self` takes the floor from member burst `holder`.
    fn beats(&self, holder: &Talker) -> bool {
        let apart = if self.started > holder.started { self.started - holder.started } else { holder.started - self.started };
        if apart < CONTEND { self.talker < holder.talker } else { self.started < holder.started }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorEvent {
    /// Play this packet.
    Play,
    /// Not the burst holding the floor (or our own echo): drop it.
    Ignore,
    /// Someone else took the floor while we talked: stop, send our END, and play this packet.
    Preempted,
    /// The remote burst holding the floor ended.
    Ended(Talker),
}

/// The floor is ours: the burst to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyedBurst {
    pub burst: u16,
    pub seq: u16,
}

/// The floor is not free: who holds it (None: voice heard less than 300 ms ago).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy {
    pub talker: Option<Talker>,
}

/// The random wait before asking for the floor a second time (`roll` in [0, 1)).
pub fn recheck_delay(roll: f64) -> Duration {
    Duration::from_millis(100).mul_f64(roll.clamp(0.0, 1.0))
}

pub struct Floor {
    me: [u8; 4],
    state: FloorState,
    talker: Option<Talker>,
    /// Any voice heard, for the 300 ms rule.
    last_voice: Option<Instant>,
    /// The last packet of the remote burst holding the floor, for its timeout.
    holder_last: Option<Instant>,
    next_burst: u16,
    ended: Option<Talker>,
}

impl Floor {
    pub fn new(me: [u8; 4]) -> Self {
        Self { me, state: FloorState::Idle, talker: None, last_voice: None, holder_last: None, next_burst: 0, ended: None }
    }

    /// The burst id our next burst gets. Start it at random, so bursts after a restart are
    /// not mistaken for copies of earlier ones.
    pub fn set_next_burst(&mut self, burst: u16) {
        self.next_burst = burst;
    }

    pub fn state(&self) -> FloorState {
        self.state
    }

    pub fn talker(&self) -> Option<Talker> {
        self.talker
    }

    fn end_remote(&mut self) -> Option<Talker> {
        let ended = self.talker.take().filter(|_| self.state == FloorState::Receiving);
        self.state = FloorState::Idle;
        ended
    }

    /// A packet heard from the group (new, not a copy). `admin_verified`: its burst was
    /// opened by a packet the admin signed.
    pub fn on_packet(&mut self, packet: &Packet, admin_verified: bool, now: Instant) -> FloorEvent {
        if packet.talker == self.me {
            return FloorEvent::Ignore;
        }
        self.last_voice = Some(now);
        let frames = u32::from(packet.seq) + packet.frames.len() as u32;
        let started = now.checked_sub(Duration::from_millis(crate::FRAME_MS) * frames).unwrap_or(now);
        let incoming = Talker { talker: packet.talker, burst: packet.burst, admin: admin_verified, since: now, started };
        let event = match (self.state, self.talker) {
            (FloorState::Talking, Some(ours)) => {
                if (admin_verified && !ours.admin) || (!admin_verified && !ours.admin && incoming.beats(&ours)) {
                    self.state = FloorState::Receiving;
                    self.talker = Some(incoming);
                    FloorEvent::Preempted
                } else {
                    FloorEvent::Ignore
                }
            }
            (FloorState::Receiving, Some(current)) if current.talker == packet.talker && current.burst == packet.burst => {
                // The burst that opened with the admin's signature stays the admin's.
                if admin_verified && !current.admin {
                    self.talker = Some(Talker { admin: true, ..current });
                }
                FloorEvent::Play
            }
            // The same talker's next burst (the gate let it through, so it is newer): the old
            // one ended without its END reaching us.
            (FloorState::Receiving, Some(current)) if current.talker == packet.talker && (admin_verified || !current.admin) => {
                self.ended = Some(current);
                self.talker = Some(incoming);
                FloorEvent::Play
            }
            (FloorState::Receiving, Some(current)) => {
                if (admin_verified && !current.admin) || (!admin_verified && !current.admin && incoming.beats(&current)) {
                    self.talker = Some(incoming);
                    FloorEvent::Play
                } else {
                    FloorEvent::Ignore
                }
            }
            _ => {
                self.state = FloorState::Receiving;
                self.talker = Some(incoming);
                FloorEvent::Play
            }
        };
        if matches!(event, FloorEvent::Play | FloorEvent::Preempted) {
            self.holder_last = Some(now);
        }
        if event == FloorEvent::Play
            && packet.is_end()
            && self.talker.is_some_and(|current| current.talker == packet.talker && current.burst == packet.burst)
        {
            self.ended = self.end_remote();
        }
        event
    }

    /// Asks for the floor. An admin takes it from a member who is talking.
    pub fn request(&mut self, now: Instant, as_admin: bool) -> Result<KeyedBurst, Busy> {
        match (self.state, self.talker) {
            (FloorState::Talking, Some(ours)) => return Ok(KeyedBurst { burst: ours.burst, seq: 0 }),
            (FloorState::Receiving, Some(current)) if !(as_admin && !current.admin) => return Err(Busy { talker: Some(current) }),
            (FloorState::Idle, _) if !as_admin && self.last_voice.is_some_and(|last| now.saturating_duration_since(last) < CLEAR_FOR) => {
                return Err(Busy { talker: None });
            }
            _ => {}
        }
        let burst = self.next_burst;
        self.next_burst = self.next_burst.wrapping_add(1);
        self.state = FloorState::Talking;
        self.talker = Some(Talker { talker: self.me, burst, admin: as_admin, since: now, started: now });
        Ok(KeyedBurst { burst, seq: 0 })
    }

    /// We stop talking. Our own talk is not voice to wait out: the 300 ms rule keeps us from
    /// talking over someone else, so we may key again at once (a held button whose hold timed
    /// out, a squelch reopening).
    pub fn release(&mut self, _now: Instant) {
        if self.state == FloorState::Talking {
            self.state = FloorState::Idle;
            self.talker = None;
        }
    }

    /// A remote burst that ended (by END, or silent for 500 ms).
    pub fn tick(&mut self, now: Instant) -> Option<FloorEvent> {
        if let Some(ended) = self.ended.take() {
            return Some(FloorEvent::Ended(ended));
        }
        if self.state == FloorState::Receiving && self.holder_last.is_some_and(|last| now.saturating_duration_since(last) >= BURST_TIMEOUT) {
            return self.end_remote().map(FloorEvent::Ended);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{codec, flags};

    fn packet(talker: u8, burst: u16, flags: u8) -> Packet {
        Packet { flags, ttl: 4, epoch: 1, talker: [talker; 4], burst, seq: 0, counter: 1, codec: codec::OPUS16, frames: vec![vec![1]], signature: None }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn keying_waits_for_silence() {
        let now = Instant::now();
        let mut floor = Floor::new([9; 4]);
        floor.set_next_burst(40);
        assert_eq!(floor.request(now, false), Ok(KeyedBurst { burst: 40, seq: 0 }));
        assert_eq!(floor.state(), FloorState::Talking);
        floor.release(now);
        // Our own talk is not waited out.
        assert_eq!(floor.request(now + ms(100), false), Ok(KeyedBurst { burst: 41, seq: 0 }));
        floor.release(now + ms(100));
        // Someone else's voice is: 300 ms of silence after its last packet.
        let heard = now + ms(200);
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START | flags::END), false, heard), FloorEvent::Play);
        assert!(floor.tick(heard).is_some());
        assert_eq!(floor.request(heard + ms(100), false), Err(Busy { talker: None }));
        assert_eq!(floor.request(heard + ms(300), false), Ok(KeyedBurst { burst: 42, seq: 0 }));
        assert!(recheck_delay(0.5) == ms(50) && recheck_delay(2.0) == ms(100));
    }

    #[test]
    fn a_remote_talker_holds_the_floor_until_its_end() {
        let now = Instant::now();
        let mut floor = Floor::new([9; 4]);
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START), false, now), FloorEvent::Play);
        assert_eq!(floor.state(), FloorState::Receiving);
        let busy = floor.request(now + ms(10), false).unwrap_err();
        assert_eq!(busy.talker.unwrap().talker, [1; 4]);
        assert_eq!(floor.on_packet(&packet(1, 5, flags::END), false, now + ms(60)), FloorEvent::Play);
        assert!(matches!(floor.tick(now + ms(61)), Some(FloorEvent::Ended(Talker { talker: [1, 1, 1, 1], burst: 5, .. }))));
        assert_eq!(floor.state(), FloorState::Idle);
        assert_eq!(floor.tick(now + ms(62)), None);
    }

    #[test]
    fn a_silent_burst_times_out() {
        let now = Instant::now();
        let mut floor = Floor::new([9; 4]);
        floor.on_packet(&packet(1, 5, flags::START), false, now);
        assert_eq!(floor.tick(now + ms(499)), None);
        assert!(matches!(floor.tick(now + ms(500)), Some(FloorEvent::Ended(_))));
        assert_eq!(floor.request(now + ms(800), false).map(|keyed| keyed.seq), Ok(0));
    }

    #[test]
    fn the_earlier_member_burst_wins_and_the_admin_preempts() {
        let now = Instant::now();
        let mut floor = Floor::new([9; 4]);
        floor.on_packet(&packet(1, 5, flags::START), false, now);
        assert_eq!(floor.on_packet(&packet(2, 7, flags::START), false, now + ms(5)), FloorEvent::Ignore);
        assert_eq!(floor.on_packet(&packet(1, 5, 0), false, now + ms(60)), FloorEvent::Play);
        // A verified admin burst takes over from the member.
        assert_eq!(floor.on_packet(&packet(3, 1, flags::START | flags::ADMIN), true, now + ms(70)), FloorEvent::Play);
        assert_eq!(floor.talker().unwrap().talker, [3; 4]);
        assert_eq!(floor.on_packet(&packet(1, 5, 0), false, now + ms(80)), FloorEvent::Ignore);
        // An unverified "admin" flag gives no priority.
        let mut floor = Floor::new([9; 4]);
        floor.on_packet(&packet(1, 5, flags::START), false, now);
        assert_eq!(floor.on_packet(&packet(4, 1, flags::START | flags::ADMIN), false, now + ms(5)), FloorEvent::Ignore);
    }

    #[test]
    fn the_admin_preempts_our_talk_and_we_preempt_as_admin() {
        let now = Instant::now();
        let mut floor = Floor::new([9; 4]);
        floor.request(now, false).unwrap();
        // A member with a higher id keying at the same time does not take it from us.
        assert_eq!(floor.on_packet(&packet(12, 5, flags::START), false, now + ms(10)), FloorEvent::Ignore);
        assert_eq!(floor.on_packet(&packet(3, 1, flags::START | flags::ADMIN), true, now + ms(20)), FloorEvent::Preempted);
        assert_eq!(floor.state(), FloorState::Receiving);
        // The admin device keys over a member who is talking.
        let mut admin = Floor::new([3; 4]);
        admin.on_packet(&packet(1, 5, flags::START), false, now);
        assert!(admin.request(now + ms(10), true).is_ok());
        assert_eq!(admin.state(), FloorState::Talking);
        // Our own echo changes nothing.
        assert_eq!(admin.on_packet(&packet(3, 0, flags::START), false, now + ms(20)), FloorEvent::Ignore);
    }

    #[test]
    fn we_may_key_again_right_after_our_own_release() {
        let now = Instant::now();
        let mut floor = Floor::new([1; 4]);
        let first = floor.request(now, false).unwrap();
        floor.release(now + Duration::from_millis(10));
        let second = floor.request(now + Duration::from_millis(20), false).expect("no 300 ms wait after our own burst");
        assert_ne!(first.burst, second.burst, "a new burst");
    }

    #[test]
    fn a_lost_end_does_not_hold_the_floor_against_the_same_talker() {
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START), false, t), FloorEvent::Play);
        // Burst 5's END is lost; 100 ms later the same talker keys burst 6.
        assert_eq!(floor.on_packet(&packet(1, 6, flags::START), false, t + ms(100)), FloorEvent::Play);
        assert!(matches!(floor.tick(t + ms(100)), Some(FloorEvent::Ended(Talker { burst: 5, .. }))));
        for n in 1..50 {
            assert_eq!(floor.on_packet(&packet(1, 6, 0), false, t + ms(100 + 20 * n)), FloorEvent::Play);
        }
        assert_eq!(floor.talker().map(|talker| talker.burst), Some(6));
    }

    #[test]
    fn a_lost_end_does_not_hold_the_floor_while_someone_else_talks() {
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START), false, t), FloorEvent::Play);
        // Its END is lost; talker 2 starts 100 ms later and keeps going.
        let mut played = 0;
        for n in 0..100 {
            let now = t + ms(100 + 20 * n);
            if floor.on_packet(&packet(2, 7, if n == 0 { flags::START } else { 0 }), false, now) == FloorEvent::Play {
                played += 1;
            }
            floor.tick(now);
        }
        // Talker 1 timed out 500 ms after its last packet, while talker 2 was talking.
        assert!(played >= 70, "talker 2 played {played} of 100");
        assert_eq!(floor.talker().map(|talker| talker.talker), Some([2; 4]));
    }

    #[test]
    fn a_burst_heard_mid_way_takes_the_floor() {
        // Its START was lost, or we came into range while it talked.
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        assert_eq!(floor.on_packet(&packet(1, 5, 0), false, t), FloorEvent::Play);
        assert_eq!(floor.state(), FloorState::Receiving);
        assert_eq!(floor.talker().map(|talker| (talker.talker, talker.burst)), Some(([1; 4], 5)));
        // A START of it arriving late changes nothing.
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START), false, t + ms(20)), FloorEvent::Play);
        assert_eq!(floor.tick(t + ms(20)), None);
    }

    #[test]
    fn a_lone_end_opens_and_closes_the_floor() {
        // All of a short burst lost but its END.
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        assert_eq!(floor.on_packet(&packet(1, 5, flags::END), false, t), FloorEvent::Play);
        assert!(matches!(floor.tick(t), Some(FloorEvent::Ended(Talker { burst: 5, .. }))));
        assert_eq!(floor.state(), FloorState::Idle);
        // It was voice all the same: 300 ms before we may key.
        assert!(floor.request(t + ms(100), false).is_err());
    }

    #[test]
    fn of_two_members_keying_at_once_the_lower_id_wins_and_the_other_yields() {
        let t = Instant::now();
        // We (9) keyed; talker 1 keyed at the same time far away, and its first packet
        // reaches us 250 ms later: we stop and play it.
        let mut floor = Floor::new([9; 4]);
        floor.request(t, false).unwrap();
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START), false, t + ms(250)), FloorEvent::Preempted);
        assert_eq!(floor.state(), FloorState::Receiving);
        assert_eq!(floor.talker().map(|talker| talker.talker), Some([1; 4]));
        // Talker 1's own floor ignores us, so it keeps talking.
        let mut winner = Floor::new([1; 4]);
        winner.request(t, false).unwrap();
        for n in 0..10 {
            assert_eq!(winner.on_packet(&packet(9, 7, if n == 0 { flags::START } else { 0 }), false, t + ms(250 + 20 * n)), FloorEvent::Ignore);
        }
        assert_eq!(winner.state(), FloorState::Talking);
    }

    #[test]
    fn a_member_keying_well_after_the_holder_does_not_take_the_floor_whatever_its_id() {
        // Talker 9 has talked for 2 s here; talker 1 keys now (it could not hear 9): the
        // earlier burst keeps the floor, and while we talk, so do we.
        let t = Instant::now();
        let mut floor = Floor::new([5; 4]);
        floor.on_packet(&packet(9, 5, flags::START), false, t);
        assert_eq!(floor.on_packet(&packet(1, 7, flags::START), false, t + ms(2000)), FloorEvent::Ignore);
        assert_eq!(floor.talker().map(|talker| talker.talker), Some([9; 4]));
        let mut talking = Floor::new([5; 4]);
        talking.request(t, false).unwrap();
        assert_eq!(talking.on_packet(&packet(1, 7, flags::START), false, t + ms(2000)), FloorEvent::Ignore);
        assert_eq!(talking.state(), FloorState::Talking);
    }

    #[test]
    fn a_burst_heard_mid_way_counts_from_its_start_not_from_when_it_was_heard() {
        // Talker 9 started 2 s ago (seq 100); we hear it only now, after talker 1, which
        // started a moment ago: talker 9 started first and takes the floor.
        let t = Instant::now() + ms(5000);
        let mut floor = Floor::new([5; 4]);
        floor.on_packet(&packet(1, 7, flags::START), false, t);
        let old = Packet { seq: 100, ..packet(9, 5, 0) };
        assert_eq!(floor.on_packet(&old, false, t + ms(20)), FloorEvent::Play);
        assert_eq!(floor.talker().map(|talker| talker.talker), Some([9; 4]));
        // And talker 1, which started later, stays out.
        assert_eq!(floor.on_packet(&packet(1, 7, 0), false, t + ms(40)), FloorEvent::Ignore);
    }

    #[test]
    fn two_starts_heard_in_opposite_order_pick_the_same_talker() {
        // Two listeners between two talkers hear their first packets in opposite order; both
        // give the floor to the lower id.
        let t = Instant::now();
        let (mut near_1, mut near_2) = (Floor::new([8; 4]), Floor::new([9; 4]));
        near_1.on_packet(&packet(1, 5, flags::START), false, t);
        near_1.on_packet(&packet(2, 7, flags::START), false, t + ms(40));
        assert_eq!(near_2.on_packet(&packet(2, 7, flags::START), false, t), FloorEvent::Play);
        assert_eq!(near_2.on_packet(&packet(1, 5, flags::START), false, t + ms(40)), FloorEvent::Play);
        assert_eq!(near_2.on_packet(&packet(2, 7, 0), false, t + ms(60)), FloorEvent::Ignore);
        assert_eq!(near_1.talker().map(|talker| talker.talker), Some([1; 4]));
        assert_eq!(near_2.talker().map(|talker| talker.talker), Some([1; 4]));
    }

    #[test]
    fn the_end_of_an_ignored_burst_does_not_end_the_holder() {
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        floor.on_packet(&packet(1, 5, flags::START), false, t);
        assert_eq!(floor.on_packet(&packet(2, 7, flags::START | flags::END), false, t + ms(10)), FloorEvent::Ignore);
        assert_eq!(floor.tick(t + ms(10)), None);
        assert_eq!(floor.talker().map(|talker| talker.talker), Some([1; 4]));
        // Nor do the ignored talker's packets keep the holder alive past its timeout.
        for n in 1..30 {
            floor.on_packet(&packet(2, 8, 0), false, t + ms(20 * n));
        }
        assert!(matches!(floor.tick(t + ms(600)), Some(FloorEvent::Ended(Talker { talker: [1, 1, 1, 1], .. }))));
    }

    #[test]
    fn ended_after_a_rekey_leaves_the_floor_receiving_the_new_burst() {
        // F3: `Ended` of the old burst comes while the new one holds the floor, so whoever
        // handles `Ended` must not take it for "the floor is free".
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        floor.on_packet(&packet(1, 5, flags::START), false, t);
        floor.on_packet(&packet(1, 6, flags::START), false, t + ms(100));
        assert!(matches!(floor.tick(t + ms(100)), Some(FloorEvent::Ended(Talker { burst: 5, .. }))));
        assert_eq!(floor.state(), FloorState::Receiving);
        assert_eq!(floor.talker().map(|talker| talker.burst), Some(6));
        assert!(floor.request(t + ms(110), false).is_err());
    }

    #[test]
    fn a_member_preempted_by_the_admin_takes_the_floor_back_after_the_admin() {
        // The member's node stops at the admin's first packet, but a listener that heard the
        // member's tail after the admin's END plays it.
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        floor.on_packet(&packet(1, 5, flags::START), false, t);
        assert_eq!(floor.on_packet(&packet(3, 1, flags::START | flags::ADMIN), true, t + ms(20)), FloorEvent::Play);
        assert_eq!(floor.on_packet(&packet(1, 5, 0), false, t + ms(40)), FloorEvent::Ignore);
        floor.on_packet(&packet(3, 1, flags::END | flags::ADMIN), true, t + ms(200));
        assert!(matches!(floor.tick(t + ms(200)), Some(FloorEvent::Ended(Talker { admin: true, .. }))));
        assert_eq!(floor.on_packet(&packet(1, 5, 0), false, t + ms(220)), FloorEvent::Play);
        assert_eq!(floor.talker().map(|talker| talker.talker), Some([1; 4]));
    }

    #[test]
    fn our_burst_ids_wrap() {
        let mut floor = Floor::new([9; 4]);
        let t = Instant::now();
        floor.set_next_burst(u16::MAX);
        assert_eq!(floor.request(t, false).map(|keyed| keyed.burst), Ok(u16::MAX));
        floor.release(t);
        assert_eq!(floor.request(t, false).map(|keyed| keyed.burst), Ok(0));
    }
}
