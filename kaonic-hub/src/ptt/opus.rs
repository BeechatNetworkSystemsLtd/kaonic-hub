//! Opus through the system libopus, loaded at run time:
//! 16 kHz mono, 20 ms frames, VoIP, 12 kbit/s, DTX and in-band FEC.

use std::ffi::{c_int, c_void};
use std::sync::{Arc, OnceLock};

use super::dl::Library;

pub const SAMPLE_RATE: i32 = 16_000;
/// One 20 ms frame.
pub const FRAME_SAMPLES: usize = 320;
/// Worst-case bytes libopus emits for one mono frame.
const MAX_PACKET: usize = 1275;

const APPLICATION_VOIP: c_int = 2048;
const SET_BITRATE: c_int = 4002;
const SET_VBR: c_int = 4006;
const SET_MAX_BANDWIDTH: c_int = 4004;
const SET_VBR_CONSTRAINT: c_int = 4020;
const SET_COMPLEXITY: c_int = 4010;
const SET_INBAND_FEC: c_int = 4012;
const SET_PACKET_LOSS_PERC: c_int = 4014;
const SET_DTX: c_int = 4016;
const SET_SIGNAL: c_int = 4024;
const SET_LSB_DEPTH: c_int = 4036;
const BANDWIDTH_WIDEBAND: c_int = 1103;
const SIGNAL_VOICE: c_int = 3001;

type EncoderCreate = unsafe extern "C" fn(c_int, c_int, c_int, *mut c_int) -> *mut c_void;
type Encode = unsafe extern "C" fn(*mut c_void, *const i16, c_int, *mut u8, c_int) -> c_int;
type EncoderCtl = unsafe extern "C" fn(*mut c_void, c_int, ...) -> c_int;
type Destroy = unsafe extern "C" fn(*mut c_void);
type DecoderCreate = unsafe extern "C" fn(c_int, c_int, *mut c_int) -> *mut c_void;
type Decode = unsafe extern "C" fn(*mut c_void, *const u8, c_int, *mut i16, c_int, c_int) -> c_int;

struct Api {
    _library: Library,
    encoder_create: EncoderCreate,
    encode: Encode,
    encoder_ctl: EncoderCtl,
    encoder_destroy: Destroy,
    decoder_create: DecoderCreate,
    decode: Decode,
    decoder_destroy: Destroy,
}

fn api() -> Option<Arc<Api>> {
    static API: OnceLock<Option<Arc<Api>>> = OnceLock::new();
    API.get_or_init(|| {
        let library = Library::open(&["libopus.so.0", "libopus.so", "libopus.0.dylib", "/opt/homebrew/lib/libopus.0.dylib", "/usr/local/lib/libopus.0.dylib"])?;
        // SAFETY: the types are libopus 1.x's documented signatures.
        unsafe {
            Some(Arc::new(Api {
                encoder_create: library.get("opus_encoder_create")?,
                encode: library.get("opus_encode")?,
                encoder_ctl: library.get("opus_encoder_ctl")?,
                encoder_destroy: library.get("opus_encoder_destroy")?,
                decoder_create: library.get("opus_decoder_create")?,
                decode: library.get("opus_decode")?,
                decoder_destroy: library.get("opus_decoder_destroy")?,
                _library: library,
            }))
        }
    })
    .clone()
}

/// Whether libopus is on this device.
pub fn available() -> bool {
    api().is_some()
}

/// The encoder options the kaonic-audio-ptt plugin offered (its defaults).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderConfig {
    pub bitrate_bps: u32,
    pub complexity: u8,
    pub dtx: bool,
    pub fec: bool,
    pub packet_loss_pct: u8,
    pub cbr: bool,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { bitrate_bps: 20_000, complexity: 5, dtx: true, fec: false, packet_loss_pct: 0, cbr: false }
    }
}

pub struct Encoder {
    api: Arc<Api>,
    state: *mut c_void,
}

// SAFETY: an OpusEncoder is plain memory, used by one thread at a time (`&mut self`).
unsafe impl Send for Encoder {}

impl Encoder {
    pub fn new() -> Result<Self, String> {
        Self::with(EncoderConfig::default())
    }

    pub fn with(config: EncoderConfig) -> Result<Self, String> {
        let api = api().ok_or("libopus is not installed")?;
        let mut error = 0;
        // SAFETY: valid arguments; the error out-pointer lives for the call.
        let state = unsafe { (api.encoder_create)(SAMPLE_RATE, 1, APPLICATION_VOIP, &mut error) };
        if state.is_null() || error != 0 {
            return Err(format!("opus encoder: error {error}"));
        }
        let encoder = Self { api, state };
        for (request, value) in [
            (SET_BITRATE, config.bitrate_bps.clamp(6_000, 64_000) as c_int),
            (SET_SIGNAL, SIGNAL_VOICE),
            (SET_MAX_BANDWIDTH, BANDWIDTH_WIDEBAND),
            (SET_COMPLEXITY, c_int::from(config.complexity.min(10))),
            (SET_LSB_DEPTH, 16),
            // Constrained VBR: quiet frames cost less, loud ones not much more.
            (SET_VBR, c_int::from(!config.cbr)),
            (SET_VBR_CONSTRAINT, 1),
            (SET_INBAND_FEC, c_int::from(config.fec)),
            (SET_PACKET_LOSS_PERC, c_int::from(config.packet_loss_pct.min(100))),
            (SET_DTX, c_int::from(config.dtx)),
        ] {
            // SAFETY: each of these requests takes one opus_int32 argument.
            let result = unsafe { (encoder.api.encoder_ctl)(encoder.state, request, value) };
            if result != 0 {
                return Err(format!("opus encoder setting {request}: error {result}"));
            }
        }
        Ok(encoder)
    }

    /// One 20 ms frame of PCM to an Opus frame (1-2 bytes in silence, with DTX).
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, String> {
        if pcm.len() != FRAME_SAMPLES {
            return Err(format!("a frame is {FRAME_SAMPLES} samples, not {}", pcm.len()));
        }
        let mut out = vec![0u8; MAX_PACKET];
        // SAFETY: the input holds one frame and the output has the documented maximum room.
        let length = unsafe { (self.api.encode)(self.state, pcm.as_ptr(), FRAME_SAMPLES as c_int, out.as_mut_ptr(), out.len() as c_int) };
        if length < 0 {
            return Err(format!("opus encode: error {length}"));
        }
        out.truncate(length as usize);
        Ok(out)
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: created by opus_encoder_create, destroyed once.
        unsafe { (self.api.encoder_destroy)(self.state) };
    }
}

pub struct Decoder {
    api: Arc<Api>,
    state: *mut c_void,
}

// SAFETY: as for the encoder.
unsafe impl Send for Decoder {}

impl Decoder {
    pub fn new() -> Result<Self, String> {
        let api = api().ok_or("libopus is not installed")?;
        let mut error = 0;
        // SAFETY: valid arguments; the error out-pointer lives for the call.
        let state = unsafe { (api.decoder_create)(SAMPLE_RATE, 1, &mut error) };
        if state.is_null() || error != 0 {
            return Err(format!("opus decoder: error {error}"));
        }
        Ok(Self { api, state })
    }

    fn run(&mut self, data: Option<&[u8]>, fec: bool) -> Vec<i16> {
        let mut pcm = vec![0i16; FRAME_SAMPLES];
        let (pointer, length) = data.map_or((std::ptr::null(), 0), |data| (data.as_ptr(), data.len() as c_int));
        // SAFETY: the output has room for one frame; a null input asks for concealment.
        let decoded = unsafe { (self.api.decode)(self.state, pointer, length, pcm.as_mut_ptr(), FRAME_SAMPLES as c_int, c_int::from(fec)) };
        if decoded < 0 {
            pcm.fill(0);
        }
        pcm
    }

    /// One received frame to PCM (silence if it is corrupt).
    pub fn decode(&mut self, frame: &[u8]) -> Vec<i16> {
        self.run(Some(frame), false)
    }

    /// A frame that never arrived: rebuilt from the next one's in-band FEC when it is here,
    /// else concealed (PLC).
    pub fn conceal(&mut self, next: Option<&[u8]>) -> Vec<i16> {
        match next {
            Some(next) => self.run(Some(next), true),
            None => self.run(None, false),
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: created by opus_decoder_create, destroyed once.
        unsafe { (self.api.decoder_destroy)(self.state) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(frame: usize) -> Vec<i16> {
        (0..FRAME_SAMPLES).map(|i| (((frame * FRAME_SAMPLES + i) as f32 * 2.0 * std::f32::consts::PI * 1000.0 / 16000.0).sin() * 8000.0) as i16).collect()
    }

    fn energy(pcm: &[i16]) -> f64 {
        pcm.iter().map(|sample| f64::from(*sample).powi(2)).sum::<f64>() / pcm.len() as f64
    }

    #[test]
    fn a_tone_survives_the_round_trip_and_losses_are_concealed() {
        if !available() {
            eprintln!("libopus is not installed: skipped");
            return;
        }
        let mut encoder = Encoder::new().unwrap();
        let mut decoder = Decoder::new().unwrap();
        let frames: Vec<Vec<u8>> = (0..20).map(|frame| encoder.encode(&tone(frame)).unwrap()).collect();
        assert!(frames.iter().all(|frame| !frame.is_empty() && frame.len() < 100), "about 50 B a frame at 20 kbit/s");
        let mut last = Vec::new();
        for frame in &frames[..10] {
            last = decoder.decode(frame);
        }
        assert_eq!(last.len(), FRAME_SAMPLES);
        let original = energy(&tone(9));
        assert!(energy(&last) > original * 0.3, "the tone comes back");
        // Frame 10 is lost: rebuilt from frame 11's FEC, then frame 11 itself.
        assert_eq!(decoder.conceal(Some(&frames[11])).len(), FRAME_SAMPLES);
        assert_eq!(decoder.decode(&frames[11]).len(), FRAME_SAMPLES);
        assert_eq!(decoder.conceal(None).len(), FRAME_SAMPLES);
        assert!(encoder.encode(&[0; 10]).is_err());
        // Silence is nearly free with DTX.
        let quiet: usize = (0..20).map(|_| encoder.encode(&[0; FRAME_SAMPLES]).unwrap().len()).sum();
        assert!(quiet < 20 * 10, "{quiet} B for 20 silent frames");
    }

    #[test]
    fn the_plugins_encoder_options_are_applied() {
        if !available() {
            eprintln!("libopus is not installed: skipped");
            return;
        }
        let size = |config: EncoderConfig| -> usize {
            let mut encoder = Encoder::with(config).unwrap();
            (0..25).map(|frame| encoder.encode(&tone(frame)).unwrap().len()).sum()
        };
        let low = size(EncoderConfig { bitrate_bps: 8_000, ..EncoderConfig::default() });
        let high = size(EncoderConfig { bitrate_bps: 40_000, ..EncoderConfig::default() });
        assert!(high > low * 2, "{low} B at 8 kbit/s, {high} B at 40 kbit/s");
        // Constant bitrate: every frame the same size.
        let mut cbr = Encoder::with(EncoderConfig { cbr: true, dtx: false, ..EncoderConfig::default() }).unwrap();
        let sizes: Vec<usize> = (0..10).map(|frame| cbr.encode(&tone(frame)).unwrap().len()).collect();
        assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]), "{sizes:?}");
        assert!(Encoder::with(EncoderConfig { fec: true, packet_loss_pct: 20, complexity: 10, ..EncoderConfig::default() }).is_ok());
    }
}
