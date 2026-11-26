//! The level gate in front of the encoder, ported from the kaonic-audio-ptt plugin
//! (`squelch.rs`) with its behaviour and tests.
//!
//! On Kaonic hardware the PTT button mutes the microphone, so between overs the capture
//! stream carries a steady near-silent signal rather than speech. The gate holds
//! transmission until the level rises; frames captured while closed are kept as pre-roll
//! and sent when it opens, so the start of a word is not clipped; it stays open for the
//! hangover after the level drops, so pauses mid-sentence do not chop the tail off.
//!
//! An input that is not muted between overs, such as a USB sound card, hisses steadily. The
//! gate follows the input's noise floor and opens only well above it, so steady noise stops
//! keying the radio after a while.

use std::collections::VecDeque;

use crate::FRAME_MS;

/// Level reported for a frame that is digitally silent.
pub const SILENT_DBFS: f32 = -120.0;
/// The noise floor is not followed below this: anything quieter counts as silence.
const NOISE_FLOOR_MIN_DBFS: f32 = -70.0;
/// The gate opens only on sound this far above the noise floor.
const NOISE_MARGIN_DB: f32 = 10.0;
/// The noise floor rises 3 dB a second under steady sound: hiss 35 dB above silence is
/// learned in about 12 s, while speech, which dips between words, is not.
const NOISE_RISE_DB_PER_FRAME: f32 = 3.0 * FRAME_MS as f32 / 1000.0;
/// It falls this fast: a pause brings it down at once, a dropped frame barely moves it.
const NOISE_FALL_DB_PER_FRAME: f32 = 1.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SquelchConfig {
    pub open_dbfs: f32,
    pub hysteresis_db: f32,
    pub hangover_ms: u32,
    pub preroll_ms: u32,
}

impl Default for SquelchConfig {
    /// The plugin's defaults.
    fn default() -> Self {
        Self { open_dbfs: -45.0, hysteresis_db: 6.0, hangover_ms: 600, preroll_ms: 120 }
    }
}

/// What to do with the frame just handed to [`Squelch::push`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SquelchDecision {
    /// Encode and transmit this frame.
    pub pass: bool,
    /// The gate opened on this frame: send [`Squelch::take_preroll`] first.
    pub opened: bool,
    /// The gate closed on this frame: end the burst.
    pub closed: bool,
    /// Measured level of the frame.
    pub level_dbfs: f32,
}

pub struct Squelch {
    open_threshold_dbfs: f32,
    close_threshold_dbfs: f32,
    hangover_frames: u32,
    preroll_capacity: usize,
    preroll: VecDeque<Vec<i16>>,
    open: bool,
    low_frames: u32,
    noise_dbfs: f32,
    /// Closed by [`Squelch::lock_out`]: stays closed until the level drops below the close
    /// threshold.
    locked: bool,
}

fn frames_for(ms: u32) -> u32 {
    ms.div_ceil(FRAME_MS as u32)
}

impl Squelch {
    pub fn new(config: SquelchConfig) -> Self {
        Self {
            open_threshold_dbfs: config.open_dbfs,
            close_threshold_dbfs: config.open_dbfs - config.hysteresis_db,
            hangover_frames: frames_for(config.hangover_ms),
            preroll_capacity: frames_for(config.preroll_ms) as usize,
            preroll: VecDeque::new(),
            open: false,
            low_frames: 0,
            noise_dbfs: NOISE_FLOOR_MIN_DBFS,
            locked: false,
        }
    }

    /// New settings while running: the threshold takes effect on the over in progress.
    pub fn configure(&mut self, config: SquelchConfig) {
        if self.open_threshold_dbfs != config.open_dbfs {
            // Judge the new threshold from a clean run of low frames.
            self.low_frames = 0;
        }
        self.open_threshold_dbfs = config.open_dbfs;
        self.close_threshold_dbfs = config.open_dbfs - config.hysteresis_db;
        self.hangover_frames = frames_for(config.hangover_ms);
        self.preroll_capacity = frames_for(config.preroll_ms) as usize;
        while self.preroll.len() > self.preroll_capacity {
            self.preroll.pop_front();
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    /// The noise floor the gate follows, in dBFS.
    pub fn noise_dbfs(&self) -> f32 {
        self.noise_dbfs
    }

    /// The level that opens the gate now: the threshold, or more above a noisy input.
    pub fn open_dbfs(&self) -> f32 {
        self.open_threshold_dbfs.max(self.noise_dbfs + NOISE_MARGIN_DB)
    }

    fn close_dbfs(&self) -> f32 {
        self.open_dbfs() - (self.open_threshold_dbfs - self.close_threshold_dbfs)
    }

    fn follow_noise(&mut self, level_dbfs: f32) {
        let level = level_dbfs.max(NOISE_FLOOR_MIN_DBFS);
        self.noise_dbfs = if level > self.noise_dbfs {
            (self.noise_dbfs + NOISE_RISE_DB_PER_FRAME).min(level)
        } else {
            (self.noise_dbfs - NOISE_FALL_DB_PER_FRAME).max(level)
        };
    }

    pub fn push(&mut self, frame: &[i16]) -> SquelchDecision {
        let level_dbfs = frame_level_dbfs(frame);
        self.follow_noise(level_dbfs);
        if self.locked {
            if level_dbfs < self.close_dbfs() {
                self.locked = false;
            }
            self.retain_preroll(frame);
            return SquelchDecision { pass: false, opened: false, closed: false, level_dbfs };
        }
        if self.open {
            if level_dbfs < self.close_dbfs() {
                self.low_frames += 1;
            } else {
                self.low_frames = 0;
            }
            if self.low_frames > self.hangover_frames {
                self.open = false;
                self.low_frames = 0;
                self.retain_preroll(frame);
                return SquelchDecision { pass: false, opened: false, closed: true, level_dbfs };
            }
            return SquelchDecision { pass: true, opened: false, closed: false, level_dbfs };
        }
        if level_dbfs >= self.open_dbfs() {
            self.open = true;
            self.low_frames = 0;
            return SquelchDecision { pass: true, opened: true, closed: false, level_dbfs };
        }
        self.retain_preroll(frame);
        SquelchDecision { pass: false, opened: false, closed: false, level_dbfs }
    }

    /// Frames buffered while closed, oldest first. Call after a decision with `opened`.
    pub fn take_preroll(&mut self) -> Vec<Vec<i16>> {
        self.preroll.drain(..).collect()
    }

    /// Forget the pre-roll and close the gate (the burst was ended another way).
    pub fn reset(&mut self) {
        self.preroll.clear();
        self.open = false;
        self.low_frames = 0;
    }

    /// Close the gate and keep it closed until the input goes quiet (the over ran too long).
    pub fn lock_out(&mut self) {
        self.reset();
        self.locked = true;
    }

    fn retain_preroll(&mut self, frame: &[i16]) {
        if self.preroll_capacity == 0 {
            return;
        }
        while self.preroll.len() >= self.preroll_capacity {
            self.preroll.pop_front();
        }
        self.preroll.push_back(frame.to_vec());
    }
}

/// Keying from the armed microphone. When the gate opens the node asks for the floor; if it
/// is taken, it asks again on every frame of speech until it gets it or the gate closes, so a
/// reply that starts early is sent once the floor is free.
///
/// It asks only on speech, not during the hangover, and only while the device's own speaker
/// is quiet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArmedKey {
    /// An over is in progress that has not got the floor.
    waiting: bool,
}

impl ArmedKey {
    /// Whether to ask for the floor on this frame, while not keyed. `open_dbfs` is the gate's
    /// open threshold; `speaker_quiet`: the device's speaker is quiet.
    pub fn wants_floor(&mut self, decision: &SquelchDecision, open_dbfs: f32, speaker_quiet: bool) -> bool {
        if decision.closed {
            self.waiting = false;
            return false;
        }
        if decision.opened {
            self.waiting = true;
        }
        self.waiting && decision.pass && decision.level_dbfs >= open_dbfs && speaker_quiet
    }

    /// The floor was given: the over is being sent.
    pub fn granted(&mut self) {
        self.waiting = false;
    }

    /// The gate was closed another way ([`Squelch::reset`]).
    pub fn reset(&mut self) {
        self.waiting = false;
    }

    /// An over waits for the floor.
    pub fn is_waiting(&self) -> bool {
        self.waiting
    }
}

/// RMS level of a frame in dBFS, with the DC component removed first: a muted input often
/// sits at a constant offset, which would otherwise read as loud and hold the gate open.
pub fn frame_level_dbfs(frame: &[i16]) -> f32 {
    if frame.is_empty() {
        return SILENT_DBFS;
    }
    let mean = frame.iter().map(|sample| f64::from(*sample)).sum::<f64>() / frame.len() as f64;
    let energy = frame.iter().map(|sample| (f64::from(*sample) - mean).powi(2)).sum::<f64>();
    let rms = (energy / frame.len() as f64).sqrt() / f64::from(i16::MAX);
    if rms <= 0.0 {
        return SILENT_DBFS;
    }
    (20.0 * rms.log10()).max(f64::from(SILENT_DBFS)) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES: usize = 320;

    fn config() -> SquelchConfig {
        // 5 frames of hangover, 2 of pre-roll at 20 ms.
        SquelchConfig { open_dbfs: -45.0, hysteresis_db: 6.0, hangover_ms: 100, preroll_ms: 40 }
    }

    fn tone(amplitude: i16) -> Vec<i16> {
        (0..SAMPLES).map(|i| if i % 2 == 0 { amplitude } else { -amplitude }).collect()
    }

    #[test]
    fn digital_silence_and_dc_offset_read_as_silent() {
        assert_eq!(frame_level_dbfs(&[0i16; SAMPLES]), SILENT_DBFS);
        assert_eq!(frame_level_dbfs(&[1200i16; SAMPLES]), SILENT_DBFS);
        assert!(frame_level_dbfs(&tone(i16::MAX)) > -0.5);
    }

    #[test]
    fn stays_closed_on_a_muted_input() {
        let mut squelch = Squelch::new(config());
        for _ in 0..100 {
            let decision = squelch.push(&[7i16; SAMPLES]);
            assert!(!decision.pass && !decision.opened && !decision.closed);
        }
    }

    #[test]
    fn opens_on_speech_and_replays_preroll() {
        let mut squelch = Squelch::new(config());
        for _ in 0..10 {
            assert!(!squelch.push(&[0i16; SAMPLES]).pass);
        }
        let decision = squelch.push(&tone(8_000));
        assert!(decision.pass && decision.opened);
        assert_eq!(squelch.take_preroll().len(), 2, "only the last pre-roll period is kept");
    }

    #[test]
    fn holds_through_hangover_then_closes_once() {
        let mut squelch = Squelch::new(config());
        assert!(squelch.push(&tone(8_000)).opened);
        for _ in 0..5 {
            let decision = squelch.push(&[0i16; SAMPLES]);
            assert!(decision.pass && !decision.closed, "hangover keeps the gate open");
        }
        let decision = squelch.push(&[0i16; SAMPLES]);
        assert!(decision.closed && !decision.pass);
        let decision = squelch.push(&[0i16; SAMPLES]);
        assert!(!decision.closed && !decision.pass, "closing is reported once");
    }

    #[test]
    fn raising_the_threshold_shuts_out_room_noise() {
        let mut squelch = Squelch::new(config());
        let room = tone(260);
        assert!(frame_level_dbfs(&room) > -45.0);
        assert!(squelch.push(&room).opened, "room noise keys the radio");
        squelch.configure(SquelchConfig { open_dbfs: -30.0, ..config() });
        let closed = (0..=5).any(|_| squelch.push(&room).closed);
        assert!(closed, "the raised threshold closes the gate");
        let decision = squelch.push(&room);
        assert!(!decision.pass && !decision.opened, "and the same noise can no longer key it");
    }

    #[test]
    fn hysteresis_keeps_marginal_audio_from_chattering() {
        let mut squelch = Squelch::new(SquelchConfig { hangover_ms: 0, ..config() });
        let marginal = tone(130);
        let level = frame_level_dbfs(&marginal);
        assert!(level > -51.0 && level < -45.0, "inside the hysteresis band: {level}");
        assert!(!squelch.push(&marginal).pass, "must not open on its own");
        assert!(squelch.push(&tone(8_000)).opened);
        assert!(squelch.push(&marginal).pass, "stays open once speech started");
    }

    /// The armed microphone of a node whose floor is `floor`, fed `frame` at `now`: whether
    /// it keyed. As the hub does it.
    fn armed_frame(squelch: &mut Squelch, armed: &mut ArmedKey, floor: &mut crate::Floor, frame: &[i16], now: std::time::Instant) -> bool {
        let decision = squelch.push(frame);
        if !armed.wants_floor(&decision, config().open_dbfs, true) {
            return false;
        }
        let keyed = floor.request(now, false).is_ok();
        if keyed {
            armed.granted();
        }
        keyed
    }

    #[test]
    fn an_over_begun_while_someone_talks_is_sent_once_the_floor_is_free() {
        use crate::packet::{Packet, codec, flags};
        use std::time::{Duration, Instant};
        let packet = |flags: u8, seq: u16| Packet { flags, ttl: 4, epoch: 1, talker: [1; 4], burst: 5, seq, counter: 1, codec: codec::OPUS16, frames: vec![vec![1]], signature: None };
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let (mut squelch, mut armed, mut floor) = (Squelch::new(config()), ArmedKey::default(), crate::Floor::new([9; 4]));
        // Talker 1 talks from 0 to 1 s, a packet every 100 ms; its END arrives at 1000 ms.
        for ms in (0..600).step_by(100) {
            floor.on_packet(&packet(if ms == 0 { flags::START } else { 0 }, ms as u16 / 20), false, at(ms));
        }
        // We answer from 600 ms on, and keep talking: while talker 1 has the floor, and for
        // the 300 ms after its END, we are refused.
        let mut keyed_at = None;
        for ms in (600..2000).step_by(20) {
            if ms == 1000 {
                floor.on_packet(&packet(flags::END, 50), false, at(ms));
            } else if ms < 1000 && ms % 100 == 0 {
                floor.on_packet(&packet(0, ms as u16 / 20), false, at(ms));
            }
            floor.tick(at(ms));
            if armed_frame(&mut squelch, &mut armed, &mut floor, &tone(8_000), at(ms)) {
                keyed_at = Some(ms);
                break;
            }
            assert!(armed.is_waiting(), "at {ms} ms the over waits for the floor");
        }
        // The over is not lost: it goes out as soon as the floor is free.
        assert_eq!(keyed_at, Some(1300), "keyed 300 ms after the END");
        assert_eq!(floor.state(), crate::FloorState::Talking);
        assert!(!armed.is_waiting());
    }

    #[test]
    fn a_waiting_over_keys_on_speech_only_and_ends_with_the_gate() {
        let loud = |armed: &mut ArmedKey, squelch: &mut Squelch, quiet_speaker: bool| {
            let decision = squelch.push(&tone(8_000));
            armed.wants_floor(&decision, config().open_dbfs, quiet_speaker)
        };
        let (mut squelch, mut armed) = (Squelch::new(config()), ArmedKey::default());
        // The gate opens while the speaker plays the group: no key, the over waits.
        assert!(!loud(&mut armed, &mut squelch, false));
        assert!(armed.is_waiting());
        // The speaker is quiet, but so are we (the hangover holds the gate open): no key on
        // what is not speech.
        let decision = squelch.push(&[0i16; SAMPLES]);
        assert!(decision.pass && !armed.wants_floor(&decision, config().open_dbfs, true));
        // Speech again: ask.
        assert!(loud(&mut armed, &mut squelch, true));
        // Refused (nobody called `granted`): asked again on the next frame of speech.
        assert!(loud(&mut armed, &mut squelch, true));
        // The gate closes: the over is finished, and the hangover after it asks for nothing.
        let closed = (0..=5).map(|_| squelch.push(&[0i16; SAMPLES])).find(|decision| decision.closed).expect("closes after the hangover");
        assert!(!armed.wants_floor(&closed, config().open_dbfs, true));
        assert!(!armed.is_waiting());
        // Once given the floor it asks no more; a reset forgets a waiting over.
        assert!(loud(&mut armed, &mut squelch, true));
        armed.granted();
        let decision = squelch.push(&tone(8_000));
        assert!(!armed.wants_floor(&decision, config().open_dbfs, true));
        squelch.reset();
        assert!(!loud(&mut armed, &mut squelch, false) && armed.is_waiting());
        armed.reset();
        assert!(!armed.is_waiting());
    }

    /// Steady hiss of `amplitude` with a little variation, like an unmuted USB sound card.
    fn hiss(amplitude: i16, frame: usize) -> Vec<i16> {
        tone(amplitude + (frame % 7) as i16 * amplitude / 40)
    }

    #[test]
    fn steady_hiss_above_the_threshold_does_not_hold_the_gate_open() {
        let mut squelch = Squelch::new(SquelchConfig { hangover_ms: 600, ..config() });
        assert!(frame_level_dbfs(&hiss(1_000, 0)) > -32.0, "well above the -45 dBFS threshold");
        assert!(squelch.push(&hiss(1_000, 0)).opened, "it keys the radio at first");
        // 30 s of it: the gate learns it is noise and closes, once.
        let closed_at = (1..1_500).find(|frame| squelch.push(&hiss(1_000, *frame)).closed).expect("the gate closes on steady hiss");
        assert!(closed_at < 20 * 50, "closed after {} s", closed_at / 50);
        for frame in 1_500..3_000 {
            let decision = squelch.push(&hiss(1_000, frame));
            assert!(!decision.pass && !decision.opened, "the hiss keys nothing more");
        }
        // Talk over the hiss still opens it.
        assert!(squelch.push(&tone(12_000)).opened, "speech above the hiss opens the gate");
    }

    #[test]
    fn speech_with_pauses_keeps_the_gate_open_for_a_long_over() {
        let mut squelch = Squelch::new(SquelchConfig { hangover_ms: 600, ..config() });
        let room = tone(20);
        for _ in 0..50 {
            squelch.push(&room);
        }
        let word = tone(4_000);
        // A minute of words (400 ms) and gaps (100 ms at room level).
        for frame in 0..3_000 {
            let decision = squelch.push(if frame % 25 < 20 { &word } else { &room });
            assert!(decision.pass && !decision.closed, "frame {frame}: the over is cut");
        }
    }

    #[test]
    fn a_locked_out_gate_waits_for_quiet() {
        let mut squelch = Squelch::new(config());
        assert!(squelch.push(&tone(8_000)).opened);
        squelch.lock_out();
        for _ in 0..50 {
            assert!(!squelch.push(&tone(8_000)).pass, "stays shut while the input stays loud");
        }
        // Quiet long enough for the floor to come down, then speech opens it again.
        for _ in 0..100 {
            squelch.push(&[0i16; SAMPLES]);
        }
        assert!(squelch.push(&tone(8_000)).opened);
    }

    #[test]
    fn reset_forgets_the_preroll() {
        let mut squelch = Squelch::new(config());
        squelch.push(&[0i16; SAMPLES]);
        squelch.reset();
        assert!(squelch.take_preroll().is_empty() && !squelch.is_open());
    }
}
