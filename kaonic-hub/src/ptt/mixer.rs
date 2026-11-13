//! The sound card's mixer and its devices, through the system libasound loaded at run
//! time: what the kaonic-audio-ptt plugin did with `amixer` (microphone gain on the
//! `Capture` control, volume on `Speaker` and, best effort, `Headphone`) and `arecord -L` /
//! `aplay -L` (the device list).

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_void};
use std::sync::{Arc, OnceLock};

use serde::Serialize;

use super::dl::Library;

type MixerOpen = unsafe extern "C" fn(*mut *mut c_void, c_int) -> c_int;
type MixerAttach = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type MixerRegister = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> c_int;
type MixerHandle = unsafe extern "C" fn(*mut c_void) -> c_int;
type IdMalloc = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
type IdFree = unsafe extern "C" fn(*mut c_void);
type IdSetName = unsafe extern "C" fn(*mut c_void, *const c_char);
type IdSetIndex = unsafe extern "C" fn(*mut c_void, c_uint);
type FindElem = unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void;
type GetRange = unsafe extern "C" fn(*mut c_void, *mut c_long, *mut c_long) -> c_int;
type SetAll = unsafe extern "C" fn(*mut c_void, c_long) -> c_int;
type SetSwitch = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type GetVolume = unsafe extern "C" fn(*mut c_void, c_int, *mut c_long) -> c_int;
type NameHint = unsafe extern "C" fn(c_int, *const c_char, *mut *mut *mut c_void) -> c_int;
type NameGetHint = unsafe extern "C" fn(*const c_void, *const c_char) -> *mut c_char;
type NameFreeHint = unsafe extern "C" fn(*mut *mut c_void) -> c_int;

/// `SND_MIXER_SCHN_FRONT_LEFT`: the channel read back.
const FRONT_LEFT: c_int = 0;

struct Api {
    _library: Library,
    open: MixerOpen,
    attach: MixerAttach,
    register: MixerRegister,
    load: MixerHandle,
    close: MixerHandle,
    id_malloc: IdMalloc,
    id_free: IdFree,
    id_set_name: IdSetName,
    id_set_index: IdSetIndex,
    find: FindElem,
    capture_range: GetRange,
    set_capture: SetAll,
    set_capture_switch: SetSwitch,
    get_capture: GetVolume,
    playback_range: GetRange,
    set_playback: SetAll,
    set_playback_switch: SetSwitch,
    get_playback: GetVolume,
    name_hint: NameHint,
    name_get_hint: NameGetHint,
    name_free_hint: NameFreeHint,
}

fn api() -> Option<Arc<Api>> {
    static API: OnceLock<Option<Arc<Api>>> = OnceLock::new();
    API.get_or_init(|| {
        let library = Library::open(&["libasound.so.2", "libasound.so"])?;
        // SAFETY: the types are alsa-lib's documented signatures.
        unsafe {
            Some(Arc::new(Api {
                open: library.get("snd_mixer_open")?,
                attach: library.get("snd_mixer_attach")?,
                register: library.get("snd_mixer_selem_register")?,
                load: library.get("snd_mixer_load")?,
                close: library.get("snd_mixer_close")?,
                id_malloc: library.get("snd_mixer_selem_id_malloc")?,
                id_free: library.get("snd_mixer_selem_id_free")?,
                id_set_name: library.get("snd_mixer_selem_id_set_name")?,
                id_set_index: library.get("snd_mixer_selem_id_set_index")?,
                find: library.get("snd_mixer_find_selem")?,
                capture_range: library.get("snd_mixer_selem_get_capture_volume_range")?,
                set_capture: library.get("snd_mixer_selem_set_capture_volume_all")?,
                set_capture_switch: library.get("snd_mixer_selem_set_capture_switch_all")?,
                get_capture: library.get("snd_mixer_selem_get_capture_volume")?,
                playback_range: library.get("snd_mixer_selem_get_playback_volume_range")?,
                set_playback: library.get("snd_mixer_selem_set_playback_volume_all")?,
                set_playback_switch: library.get("snd_mixer_selem_set_playback_switch_all")?,
                get_playback: library.get("snd_mixer_selem_get_playback_volume")?,
                name_hint: library.get("snd_device_name_hint")?,
                name_get_hint: library.get("snd_device_name_get_hint")?,
                name_free_hint: library.get("snd_device_name_free_hint")?,
                _library: library,
            }))
        }
    })
    .clone()
}

/// The card behind a configured device, for the mixer (the plugin's `alsa_card_of`):
/// `hw:1,0` and `plughw:CARD=x` name it; `default` and anything else mean card 0, the
/// on-board codec on Kaonic hardware.
pub fn card_of(device: &str) -> String {
    let device = device.trim();
    if let Some(rest) = device.strip_prefix("plughw:").or_else(|| device.strip_prefix("hw:")) {
        let card = rest.split(',').next().unwrap_or("0").trim();
        let card = card.strip_prefix("CARD=").unwrap_or(card);
        if !card.is_empty() {
            return card.to_owned();
        }
    }
    if let Some(index) = device.find("CARD=") {
        let card = device[index + "CARD=".len()..].split(',').next().unwrap_or("").trim();
        if !card.is_empty() {
            return card.to_owned();
        }
    }
    "0".to_owned()
}

/// Percent of a control's range, and back. `c_long` is 32 bits on the boards and 64 here, so
/// the conversions are not useless everywhere.
#[allow(clippy::useless_conversion)]
fn to_raw(pct: u8, min: c_long, max: c_long) -> c_long {
    let (min, max) = (i64::from(min), i64::from(max));
    c_long::try_from(min + ((max - min) * i64::from(pct.min(100)) + 50).div_euclid(100)).unwrap_or_default()
}

#[allow(clippy::useless_conversion)]
fn to_pct(raw: c_long, min: c_long, max: c_long) -> u8 {
    if max <= min {
        return 0;
    }
    let (raw, min, max) = (i64::from(raw), i64::from(min), i64::from(max));
    (((raw - min) * 100 + (max - min) / 2) / (max - min)).clamp(0, 100) as u8
}

/// An open mixer on one card, closed on drop.
struct Mixer {
    api: Arc<Api>,
    handle: *mut c_void,
}

impl Mixer {
    fn open(card: &str) -> Result<Self, String> {
        let api = api().ok_or("libasound is not installed")?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: the out-pointer lives for the call.
        if unsafe { (api.open)(&mut handle, 0) } < 0 || handle.is_null() {
            return Err("cannot open the mixer".into());
        }
        let mixer = Self { api, handle };
        let name = CString::new(format!("hw:{card}")).map_err(|_| "bad card name")?;
        // SAFETY: an open mixer, a valid name, and no options or class wanted back.
        let ready = unsafe {
            (mixer.api.attach)(mixer.handle, name.as_ptr()) >= 0
                && (mixer.api.register)(mixer.handle, std::ptr::null_mut(), std::ptr::null_mut()) >= 0
                && (mixer.api.load)(mixer.handle) >= 0
        };
        if !ready {
            return Err(format!("no mixer on card {card}"));
        }
        Ok(mixer)
    }

    /// The simple element `name`, or null.
    fn element(&self, name: &str) -> *mut c_void {
        let Ok(name) = CString::new(name) else { return std::ptr::null_mut() };
        let mut id = std::ptr::null_mut();
        // SAFETY: the out-pointer lives for the call.
        if unsafe { (self.api.id_malloc)(&mut id) } < 0 || id.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: an allocated id, a valid name; the element pointer lives as long as the mixer.
        unsafe {
            (self.api.id_set_index)(id, 0);
            (self.api.id_set_name)(id, name.as_ptr());
            let element = (self.api.find)(self.handle, id);
            (self.api.id_free)(id);
            element
        }
    }
}

impl Drop for Mixer {
    fn drop(&mut self) {
        // SAFETY: opened by snd_mixer_open, closed once.
        unsafe { (self.api.close)(self.handle) };
    }
}

#[derive(Clone, Copy)]
pub enum Control {
    /// The input gain (`Capture`), switched on.
    Capture,
    /// The speaker (`Speaker`, and `Headphone` when there is one), unmuted.
    Playback,
}

/// Sets a control to `pct` % of its range. Err when the card has no such control: the caller
/// then scales in software.
pub fn set(device: &str, control: Control, pct: u8) -> Result<(), String> {
    let mixer = Mixer::open(&card_of(device))?;
    let names: &[&str] = match control {
        Control::Capture => &["Capture"],
        Control::Playback => &["Speaker", "Headphone"],
    };
    let mut done = false;
    for name in names {
        let element = mixer.element(name);
        if element.is_null() {
            continue;
        }
        let (mut min, mut max): (c_long, c_long) = (0, 0);
        // SAFETY: a live element of the open mixer; out-pointers live for the calls.
        let set = unsafe {
            match control {
                Control::Capture => {
                    (mixer.api.capture_range)(element, &mut min, &mut max) >= 0 && (mixer.api.set_capture)(element, to_raw(pct, min, max)) >= 0 && {
                        // Not every card has a switch on the control.
                        (mixer.api.set_capture_switch)(element, 1);
                        true
                    }
                }
                Control::Playback => {
                    (mixer.api.playback_range)(element, &mut min, &mut max) >= 0 && (mixer.api.set_playback)(element, to_raw(pct, min, max)) >= 0 && {
                        (mixer.api.set_playback_switch)(element, 1);
                        true
                    }
                }
            }
        };
        done |= set;
    }
    if done { Ok(()) } else { Err(format!("no {} control on card {}", names[0], card_of(device))) }
}

/// What a control is set to, in % of its range.
pub fn get(device: &str, control: Control) -> Result<u8, String> {
    let mixer = Mixer::open(&card_of(device))?;
    let name = match control {
        Control::Capture => "Capture",
        Control::Playback => "Speaker",
    };
    let element = mixer.element(name);
    if element.is_null() {
        return Err(format!("no {name} control"));
    }
    let (mut min, mut max, mut raw): (c_long, c_long, c_long) = (0, 0, 0);
    // SAFETY: a live element; out-pointers live for the calls.
    let read = unsafe {
        match control {
            Control::Capture => (mixer.api.capture_range)(element, &mut min, &mut max) >= 0 && (mixer.api.get_capture)(element, FRONT_LEFT, &mut raw) >= 0,
            Control::Playback => (mixer.api.playback_range)(element, &mut min, &mut max) >= 0 && (mixer.api.get_playback)(element, FRONT_LEFT, &mut raw) >= 0,
        }
    };
    if read { Ok(to_pct(raw, min, max)) } else { Err(format!("cannot read {name}")) }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Device {
    pub name: String,
    pub description: String,
}

/// The PCM devices, as `arecord -L` (capture) and `aplay -L` (playback) list them. Empty
/// without libasound or a sound card.
pub fn devices() -> (Vec<Device>, Vec<Device>) {
    let Some(api) = api() else { return (Vec::new(), Vec::new()) };
    let mut hints: *mut *mut c_void = std::ptr::null_mut();
    // SAFETY: all cards (-1), the "pcm" interface, and an out-pointer that lives for the call.
    if unsafe { (api.name_hint)(-1, c"pcm".as_ptr(), &mut hints) } < 0 || hints.is_null() {
        return (Vec::new(), Vec::new());
    }
    let take = |hint: *const c_void, key: &CStr| -> Option<String> {
        // SAFETY: a hint of the list; the returned string is malloc'd and ours to free.
        let value = unsafe { (api.name_get_hint)(hint, key.as_ptr()) };
        if value.is_null() {
            return None;
        }
        // SAFETY: a valid C string from alsa-lib, freed once after copying.
        let text = unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned();
        // SAFETY: as above.
        unsafe { libc::free(value.cast()) };
        Some(text)
    };
    let (mut capture, mut playback) = (Vec::new(), Vec::new());
    let mut index = 0;
    loop {
        // SAFETY: the list is null-terminated.
        let hint = unsafe { *hints.add(index) };
        if hint.is_null() {
            break;
        }
        index += 1;
        let Some(name) = take(hint, c"NAME") else { continue };
        let description = take(hint, c"DESC").unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ");
        let direction = take(hint, c"IOID");
        let device = Device { name, description };
        if direction.as_deref() != Some("Output") {
            capture.push(device.clone());
        }
        if direction.as_deref() != Some("Input") {
            playback.push(device);
        }
    }
    // SAFETY: the list from snd_device_name_hint, freed once.
    unsafe { (api.name_free_hint)(hints) };
    (capture, playback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_card_of_a_device() {
        assert_eq!(card_of("default"), "0");
        assert_eq!(card_of("hw:1,0"), "1");
        assert_eq!(card_of("plughw:CARD=wm8960audio,DEV=0"), "wm8960audio");
        assert_eq!(card_of("sysdefault:CARD=Audio"), "Audio");
        assert_eq!(card_of(""), "0");
    }

    #[test]
    fn percent_maps_over_the_controls_range() {
        assert_eq!(to_raw(0, 0, 63), 0);
        assert_eq!(to_raw(100, 0, 63), 63);
        assert_eq!(to_raw(50, 0, 63), 32);
        assert_eq!(to_raw(50, -10, 10), 0);
        assert_eq!(to_pct(32, 0, 63), 51);
        assert_eq!(to_pct(63, 0, 63), 100);
        assert_eq!(to_pct(5, 5, 5), 0);
        for pct in [0u8, 17, 50, 83, 100] {
            assert_eq!(to_pct(to_raw(pct, 0, 255), 0, 255), pct);
        }
    }

    #[test]
    fn without_a_card_there_is_nothing_and_no_crash() {
        if api().is_none() {
            assert_eq!(devices(), (Vec::new(), Vec::new()));
            assert!(set("default", Control::Capture, 50).is_err());
            assert!(get("default", Control::Playback).is_err());
        }
    }
}
