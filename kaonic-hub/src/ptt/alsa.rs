//! The device's microphone and speaker through the system libasound, loaded at run time.
//! Capture and playback each run on their own thread (ALSA blocks), exchanging 20 ms frames
//! of 16 kHz mono PCM with the async side over channels.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc;

use super::dl::Library;
use super::opus::{FRAME_SAMPLES, SAMPLE_RATE};

const STREAM_PLAYBACK: c_int = 0;
const STREAM_CAPTURE: c_int = 1;
const FORMAT_S16_LE: c_int = 2;
const ACCESS_RW_INTERLEAVED: c_int = 3;
/// Device buffer: two frames each way keeps latency low and survives a busy CPU.
const LATENCY_US: c_uint = 60_000;

type Open = unsafe extern "C" fn(*mut *mut c_void, *const c_char, c_int, c_int) -> c_int;
type SetParams = unsafe extern "C" fn(*mut c_void, c_int, c_int, c_uint, c_uint, c_int, c_uint) -> c_int;
type ReadI = unsafe extern "C" fn(*mut c_void, *mut c_void, c_ulong) -> c_long;
type WriteI = unsafe extern "C" fn(*mut c_void, *const c_void, c_ulong) -> c_long;
type Recover = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type StrError = unsafe extern "C" fn(c_int) -> *const c_char;

struct Api {
    _library: Library,
    open: Open,
    set_params: SetParams,
    readi: ReadI,
    writei: WriteI,
    recover: Recover,
    close: Close,
    strerror: StrError,
}

fn api() -> Option<Arc<Api>> {
    static API: OnceLock<Option<Arc<Api>>> = OnceLock::new();
    API.get_or_init(|| {
        let library = Library::open(&["libasound.so.2", "libasound.so"])?;
        // SAFETY: the types are alsa-lib's documented signatures.
        unsafe {
            Some(Arc::new(Api {
                open: library.get("snd_pcm_open")?,
                set_params: library.get("snd_pcm_set_params")?,
                readi: library.get("snd_pcm_readi")?,
                writei: library.get("snd_pcm_writei")?,
                recover: library.get("snd_pcm_recover")?,
                close: library.get("snd_pcm_close")?,
                strerror: library.get("snd_strerror")?,
                _library: library,
            }))
        }
    })
    .clone()
}

/// An open PCM, closed on drop.
struct Pcm {
    api: Arc<Api>,
    handle: *mut c_void,
}

// SAFETY: a PCM handle is used by one thread at a time (the thread that owns it).
unsafe impl Send for Pcm {}

impl Pcm {
    fn open(device: &str, stream: c_int) -> Result<Self, String> {
        let api = api().ok_or("libasound is not installed")?;
        let name = CString::new(device).map_err(|_| "bad device name")?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: the out-pointer and name live for the call.
        let result = unsafe { (api.open)(&mut handle, name.as_ptr(), stream, 0) };
        if result < 0 {
            return Err(format!("{device}: {}", error(&api, result)));
        }
        let pcm = Self { api, handle };
        // SAFETY: an open PCM; 16-bit interleaved mono at 16 kHz, resampled by ALSA if needed.
        let result = unsafe { (pcm.api.set_params)(pcm.handle, FORMAT_S16_LE, ACCESS_RW_INTERLEAVED, 1, SAMPLE_RATE as c_uint, 1, LATENCY_US) };
        if result < 0 {
            return Err(format!("{device}: {}", error(&pcm.api, result)));
        }
        Ok(pcm)
    }
}

impl Drop for Pcm {
    fn drop(&mut self) {
        // SAFETY: opened by snd_pcm_open, closed once.
        unsafe { (self.api.close)(self.handle) };
    }
}

fn error(api: &Api, code: c_int) -> String {
    // SAFETY: snd_strerror returns a static string.
    unsafe { CStr::from_ptr((api.strerror)(code)) }.to_string_lossy().into_owned()
}

/// Whether libasound is on this device (a sound card is another matter: see `probe`).
pub fn available() -> bool {
    api().is_some()
}

/// Whether `device` opens for both capture and playback.
pub fn probe(device: &str) -> bool {
    Pcm::open(device, STREAM_CAPTURE).is_ok() && Pcm::open(device, STREAM_PLAYBACK).is_ok()
}

/// Stops its thread when dropped.
pub struct Running(Arc<AtomicBool>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Captures 20 ms frames from `device` until the handle is dropped.
pub fn capture(device: &str) -> Result<(Running, mpsc::Receiver<Vec<i16>>), String> {
    let pcm = Pcm::open(device, STREAM_CAPTURE)?;
    let running = Arc::new(AtomicBool::new(true));
    let (sender, receiver) = mpsc::channel(16);
    let flag = running.clone();
    let device = device.to_owned();
    std::thread::Builder::new()
        .name("ptt-capture".into())
        .spawn(move || {
            let mut frame = vec![0i16; FRAME_SAMPLES];
            while flag.load(Ordering::Relaxed) {
                // SAFETY: the buffer holds one frame of mono samples.
                let read = unsafe { (pcm.api.readi)(pcm.handle, frame.as_mut_ptr().cast(), FRAME_SAMPLES as c_ulong) };
                if read < 0 {
                    // SAFETY: an open PCM and the error it returned.
                    if unsafe { (pcm.api.recover)(pcm.handle, read as c_int, 1) } < 0 {
                        static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
                        if NOTED.due() {
                            log::warn!("ptt: capture on {device}: {}", error(&pcm.api, read as c_int));
                        } else {
                            log::debug!("ptt: capture on {device}: {}", error(&pcm.api, read as c_int));
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    continue;
                }
                if read as usize == FRAME_SAMPLES && sender.blocking_send(frame.clone()).is_err() {
                    return;
                }
            }
        })
        .map_err(|error| error.to_string())?;
    Ok((Running(running), receiver))
}

/// Plays frames sent to the returned channel on `device`; silence fills gaps.
pub fn playback(device: &str) -> Result<(Running, std::sync::mpsc::SyncSender<Vec<i16>>), String> {
    let pcm = Pcm::open(device, STREAM_PLAYBACK)?;
    let running = Arc::new(AtomicBool::new(true));
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<i16>>(8);
    let flag = running.clone();
    let device = device.to_owned();
    std::thread::Builder::new()
        .name("ptt-playback".into())
        .spawn(move || {
            let silence = vec![0i16; FRAME_SAMPLES];
            while flag.load(Ordering::Relaxed) {
                let frame = receiver.recv_timeout(Duration::from_millis(20));
                let frame = match &frame {
                    Ok(frame) => frame,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => &silence,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                };
                // SAFETY: the buffer holds the frame's samples.
                let written = unsafe { (pcm.api.writei)(pcm.handle, frame.as_ptr().cast(), frame.len() as c_ulong) };
                // SAFETY: an open PCM and the error it returned.
                if written < 0 && unsafe { (pcm.api.recover)(pcm.handle, written as c_int, 1) } < 0 {
                    static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
                    if NOTED.due() {
                        log::warn!("ptt: playback on {device}: {}", error(&pcm.api, written as c_int));
                    } else {
                        log::debug!("ptt: playback on {device}: {}", error(&pcm.api, written as c_int));
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        })
        .map_err(|error| error.to_string())?;
    Ok((Running(running), sender))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_library_or_card_is_reported_not_fatal() {
        // On a Mac there is no libasound; in a container there is no card.
        if !available() {
            assert!(capture("default").is_err());
            assert!(!probe("default"));
        }
        assert!(Pcm::open("no-such-device-\0", STREAM_PLAYBACK).is_err());
    }
}
