//! Who has the floor: one talker per group.
//!
//! - A node keys only after 300 ms without voice; the caller may wait a further random
//!   0-100 ms ([`recheck_delay`]) and ask again, so two nodes keying together rarely collide.
//! - A burst ends at its END packet, or after 500 ms without packets of its own (other
//!   talkers' packets do not keep it alive).
//! - A verified admin burst takes the floor: a member talking here is preempted.
//! - Of two remote members, the burst that started first keeps the floor. A newer burst of
//!   the talker holding it replaces the old one at once (the old one's END was lost).

use std::time::{Duration, Instant};

use crate::packet::Packet;

/// Silence needed before keying.
pub const CLEAR_FOR: Duration = Duration::from_millis(300);
/// A remote burst with no packets for this long has ended.
pub const BURST_TIMEOUT: Duration = Duration::from_millis(500);

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
    pub since: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorEvent {
    /// Play this packet.
    Play,
    /// Not the burst holding the floor (or our own echo): drop it.
    Ignore,
    /// We were talking and the admin took the floor: stop, and play this packet.
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
        let incoming = Talker { talker: packet.talker, burst: packet.burst, admin: admin_verified, since: now };
        let event = match (self.state, self.talker) {
            (FloorState::Talking, Some(ours)) => {
                if admin_verified && !ours.admin {
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
                if admin_verified && !current.admin {
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
        self.talker = Some(Talker { talker: self.me, burst, admin: as_admin, since: now });
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
        assert_eq!(floor.on_packet(&packet(1, 5, flags::START), false, now + ms(10)), FloorEvent::Ignore);
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
}
