//! The level gate in front of the encoder, ported from the kaonic-audio-ptt plugin
//! (`squelch.rs`) with its behaviour and tests.
//!
//! On Kaonic hardware the PTT button mutes the microphone, so between overs the capture
//! stream carries a steady near-silent signal rather than speech. The gate holds
//! transmission until the level rises; frames captured while closed are kept as pre-roll
//! and sent when it opens, so the start of a word is not clipped; it stays open for the
//! hangover after the level drops, so pauses mid-sentence do not chop the tail off.

use std::collections::VecDeque;

use crate::FRAME_MS;

/// Level reported for a frame that is digitally silent.
pub const SILENT_DBFS: f32 = -120.0;

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

    pub fn push(&mut self, frame: &[i16]) -> SquelchDecision {
        let level_dbfs = frame_level_dbfs(frame);
        if self.open {
            if level_dbfs < self.close_threshold_dbfs {
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
        if level_dbfs >= self.open_threshold_dbfs {
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

    #[test]
    fn reset_forgets_the_preroll() {
        let mut squelch = Squelch::new(config());
        squelch.push(&[0i16; SAMPLES]);
        squelch.reset();
        assert!(squelch.take_preroll().is_empty() && !squelch.is_open());
    }
}
