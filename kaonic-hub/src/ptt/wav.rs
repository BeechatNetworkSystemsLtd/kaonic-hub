//! The test recording for test transmissions, ported from the kaonic-audio-ptt plugin
//! (`wav.rs`): a WAV reader (RIFF/WAVE, PCM 8/16/24/32-bit or 32-bit float, any channels,
//! any rate), a resampler, and the built-in test signal. The recording is kept in the state
//! directory as raw 16 kHz mono PCM (`ptt-test.pcm`).

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::opus::SAMPLE_RATE;

/// The largest upload, as in the plugin.
pub const MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WavInfo {
    pub sample_rate_hz: u32,
    pub channels: u16,
    pub bits_per_sample: u16,
    /// Sample frames (per channel).
    pub frames: usize,
}

const FORMAT_PCM: u16 = 1;
const FORMAT_FLOAT: u16 = 3;
const FORMAT_EXTENSIBLE: u16 = 0xFFFE;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A WAV file as mono 16-bit samples at its own rate.
pub fn parse(bytes: &[u8]) -> Result<(WavInfo, Vec<i16>), String> {
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err("not a RIFF/WAVE file".into());
    }
    let mut pos = 12;
    let mut format: Option<(u16, u16, u32, u16)> = None;
    let mut data: Option<&[u8]> = None;
    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let size = u32_at(bytes, pos + 4).ok_or("truncated chunk header")? as usize;
        let body_start = pos + 8;
        let body = &bytes[body_start..body_start.saturating_add(size).min(bytes.len())];
        match id {
            b"fmt " => {
                let mut tag = u16_at(body, 0).ok_or("short fmt chunk")?;
                let channels = u16_at(body, 2).ok_or("short fmt chunk")?;
                let rate = u32_at(body, 4).ok_or("short fmt chunk")?;
                let bits = u16_at(body, 14).ok_or("short fmt chunk")?;
                if tag == FORMAT_EXTENSIBLE {
                    // The real format is the first two bytes of the sub-format GUID.
                    tag = u16_at(body, 24).ok_or("short extensible fmt chunk")?;
                }
                format = Some((tag, channels, rate, bits));
            }
            b"data" => data = Some(body),
            _ => {}
        }
        // Chunks are word aligned.
        pos = body_start.saturating_add(size).saturating_add(size & 1);
        if format.is_some() && data.is_some() {
            break;
        }
    }
    let (tag, channels, rate, bits) = format.ok_or("no fmt chunk")?;
    let data = data.ok_or("no data chunk")?;
    if channels == 0 || rate == 0 {
        return Err("the fmt chunk has zero channels or sample rate".into());
    }
    if !(8_000..=192_000).contains(&rate) {
        return Err(format!("unsupported sample rate {rate} Hz"));
    }
    let bytes_per_sample = match (tag, bits) {
        (FORMAT_PCM, 8) => 1,
        (FORMAT_PCM, 16) => 2,
        (FORMAT_PCM, 24) => 3,
        (FORMAT_PCM, 32) | (FORMAT_FLOAT, 32) => 4,
        _ => return Err(format!("unsupported format tag {tag} with {bits} bits")),
    };
    let frame_bytes = bytes_per_sample * usize::from(channels);
    let frames = data.len() / frame_bytes;
    if frames == 0 {
        return Err("the data chunk holds no audio".into());
    }
    let mut mono = Vec::with_capacity(frames);
    let scale = 1.0 / f32::from(channels);
    for frame in 0..frames {
        let mut sum = 0f32;
        for channel in 0..usize::from(channels) {
            let at = (frame * usize::from(channels) + channel) * bytes_per_sample;
            let s = &data[at..at + bytes_per_sample];
            sum += match (tag, bits) {
                (FORMAT_PCM, 8) => (f32::from(s[0]) - 128.0) / 128.0,
                (FORMAT_PCM, 16) => f32::from(i16::from_le_bytes([s[0], s[1]])) / 32768.0,
                (FORMAT_PCM, 24) => (i32::from_le_bytes([0, s[0], s[1], s[2]]) >> 8) as f32 / 8_388_608.0,
                (FORMAT_PCM, 32) => i32::from_le_bytes([s[0], s[1], s[2], s[3]]) as f32 / 2_147_483_648.0,
                _ => f32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            };
        }
        mono.push(((sum * scale).clamp(-1.0, 1.0) * 32767.0).round() as i16);
    }
    Ok((WavInfo { sample_rate_hz: rate, channels, bits_per_sample: bits, frames }, mono))
}

/// Linear resampling: good enough for a test signal.
pub fn resample(input: &[i16], from_hz: u32, to_hz: u32) -> Vec<i16> {
    if from_hz == to_hz || input.is_empty() {
        return input.to_vec();
    }
    let out_len = ((input.len() as u64 * u64::from(to_hz)) / u64::from(from_hz)).max(1) as usize;
    let step = f64::from(from_hz) / f64::from(to_hz);
    let last = input.len() - 1;
    (0..out_len)
        .map(|i| {
            let pos = i as f64 * step;
            let base = pos as usize;
            if base >= last {
                return input[last];
            }
            let frac = (pos - base as f64) as f32;
            let (a, b) = (f32::from(input[base]), f32::from(input[base + 1]));
            (a + (b - a) * frac).round() as i16
        })
        .collect()
}

/// The built-in test signal (the plugin's): 1 s of 440 Hz, 1 s of 880 Hz and 1 s of silence
/// at -12 dBFS, so both the codec's DTX and the far end's playback can be checked.
pub fn tone_signal() -> Vec<i16> {
    let rate = SAMPLE_RATE as usize;
    let amplitude = 32767.0 * 10f32.powf(-12.0 / 20.0);
    let mut out = Vec::with_capacity(rate * 3);
    for frequency in [440.0f32, 880.0, 0.0] {
        out.extend((0..rate).map(|n| if frequency > 0.0 { ((2.0 * std::f32::consts::PI * frequency * n as f32 / rate as f32).sin() * amplitude) as i16 } else { 0 }));
    }
    out
}

/// Where the recording is kept.
pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join("ptt-test.pcm")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stored {
    pub duration_ms: u64,
    pub size_bytes: u64,
    pub uploaded_ts: i64,
}

/// Decodes an upload and stores it as 16 kHz mono.
pub fn store(state_dir: &Path, bytes: &[u8]) -> Result<Stored, String> {
    let (info, mono) = parse(bytes)?;
    let pcm = resample(&mono, info.sample_rate_hz, SAMPLE_RATE as u32);
    let raw: Vec<u8> = pcm.iter().flat_map(|sample| sample.to_le_bytes()).collect();
    let path = path(state_dir);
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, &raw).and_then(|()| std::fs::rename(&temporary, &path)).map_err(|error| format!("cannot store it: {error}"))?;
    stored(state_dir).ok_or_else(|| "cannot read it back".into())
}

/// What is stored, if anything.
pub fn stored(state_dir: &Path) -> Option<Stored> {
    let metadata = std::fs::metadata(path(state_dir)).ok()?;
    let uploaded_ts = metadata.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    let samples = metadata.len() / 2;
    Some(Stored { duration_ms: samples * 1000 / SAMPLE_RATE as u64, size_bytes: metadata.len(), uploaded_ts })
}

/// The stored recording, 16 kHz mono.
pub fn load(state_dir: &Path) -> Option<Vec<i16>> {
    let raw = std::fs::read(path(state_dir)).ok()?;
    Some(raw.as_chunks::<2>().0.iter().map(|pair| i16::from_le_bytes(*pair)).collect())
}

pub fn remove(state_dir: &Path) {
    let _ = std::fs::remove_file(path(state_dir));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wav16(rate: u32, channels: u16, samples: &[i16]) -> Vec<u8> {
        let data_len = (samples.len() * 2) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVEfmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&channels.to_le_bytes());
        out.extend_from_slice(&rate.to_le_bytes());
        out.extend_from_slice(&(rate * u32::from(channels) * 2).to_le_bytes());
        out.extend_from_slice(&(channels * 2).to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        for sample in samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        out
    }

    #[test]
    fn parses_stereo_16_bit_to_mono() {
        let (info, mono) = parse(&wav16(8_000, 2, &[1000, 3000, -2000, -2000])).unwrap();
        assert_eq!((info.channels, info.frames), (2, 2));
        assert_eq!(mono, vec![2000, -2000]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not a wav at all").is_err());
        assert!(parse(&wav16(8_000, 1, &[])).is_err());
        let mut bad_rate = wav16(8_000, 1, &[1, 2]);
        bad_rate[24..28].copy_from_slice(&4_000u32.to_le_bytes());
        assert!(parse(&bad_rate).is_err());
    }

    #[test]
    fn resamples_to_the_codec_rate() {
        let input: Vec<i16> = (0..8_000).map(|i| (i % 100) as i16).collect();
        assert_eq!(resample(&input, 8_000, 16_000).len(), 16_000);
        assert_eq!(resample(&input, 48_000, 16_000).len(), 2_666);
        assert_eq!(resample(&input, 8_000, 8_000), input);
    }

    #[test]
    fn the_tone_is_three_seconds_with_a_silent_tail() {
        let tone = tone_signal();
        assert_eq!(tone.len(), 48_000);
        assert!(tone[..16_000].iter().any(|&sample| sample != 0));
        assert!(tone[32_000..].iter().all(|&sample| sample == 0));
    }

    #[test]
    fn an_upload_is_stored_at_16_khz_and_read_back() {
        let dir = std::env::temp_dir().join(format!("kaonic-ptt-wav-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let samples: Vec<i16> = (0..8_000).map(|i| ((i % 50) * 100) as i16).collect();
        let stored = store(&dir, &wav16(8_000, 1, &samples)).unwrap();
        assert_eq!((stored.duration_ms, stored.size_bytes), (1000, 32_000));
        assert_eq!(load(&dir).unwrap().len(), 16_000);
        remove(&dir);
        assert!(super::stored(&dir).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
