//! Push-to-talk, native in the hub: one talker at a time speaks to
//! every node of the network at once over the GROUP channel (`kaonic_mesh::group`), and every
//! node relays what it hears so voice reaches nodes several hops away.
//!
//! One engine task owns the floor, the relay, the jitter buffer, the packer and the codecs.
//! Talk comes in from browsers (`/ptt/audio`), UDP sessions of phone and ATAK clients
//! (`udp`, the old plugin's `KU` protocol), the device microphone (keyed with `/ptt/key`, or
//! armed and keyed by the squelch: the Kaonic hardware PTT button only unmutes the
//! microphone) and test transmissions; what is played goes out every 20 ms to the device
//! speaker and every listener. The settings are the kaonic-audio-ptt plugin's, with its
//! defaults.

pub mod alsa;
mod dl;
pub mod mixer;
pub mod opus;
pub mod udp;
pub mod wav;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use kaonic_mesh::announce::Announced;
use kaonic_mesh::group::{GroupChannel, GroupMessage};
use kaonic_ptt::{Floor, FloorEvent, FloorState, Heard, Jitter, Packer, Packet, Playout, Relay, RelayConfig, Gate, Squelch, Verdict, SquelchConfig, codec};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::app::App;

/// 20 ms of 16 kHz mono PCM.
pub type Pcm = Arc<Vec<i16>>;

/// A keyed client that sends nothing for this long is unkeyed.
const UNKEY_SILENCE: Duration = Duration::from_millis(500);
/// The device microphone keyed with `/ptt/key` stays keyed this long after the last call.
const KEY_HOLD: Duration = Duration::from_secs(2);
/// Bursts kept for `GET /ptt`.
const RECENT: usize = 20;
/// The ttl the design starts bursts with: hops = this minus the ttl a packet arrives with.
const DEFAULT_TTL: u8 = 4;
/// The system restores the card's mixer state at boot, possibly after the hub started: the
/// gain and volume are applied again this long after start (as the plugin did).
const MIXER_REAPPLY: Duration = Duration::from_secs(15);

/// Where talk comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Browser(u64),
    Udp(u32),
    /// The device microphone, keyed with `/ptt/key`.
    Device,
    /// The armed device microphone, keyed by the squelch (the hardware PTT button).
    Squelch,
    /// A test transmission of the recording or the test signal.
    Test,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Browser(_) => "browser",
            Source::Udp(_) => "udp",
            Source::Device => "device",
            Source::Squelch => "squelch",
            Source::Test => "test",
        }
    }

    /// Talk the engine feeds itself, not a client that can go quiet.
    fn is_local(self) -> bool {
        matches!(self, Source::Device | Source::Squelch | Source::Test)
    }
}

/// Who talks, as the API shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TalkerView {
    pub id: String,
    pub codename: String,
    pub is_admin: bool,
    pub local: bool,
    pub source: Option<&'static str>,
}

/// What sources are told.
#[derive(Clone, Debug)]
pub enum Control {
    /// This source no longer holds the floor: `released`, `preempted` or `timeout`.
    Unkeyed { source: Source, reason: &'static str },
    /// The talker changed.
    Talker(Option<TalkerView>),
}

/// Why keying failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// No group key, codec or device yet.
    Unavailable(&'static str),
    /// The floor is taken (by this talker, when known).
    Busy(Option<TalkerView>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TalkInput {
    Device,
    Browser,
}

/// The kaonic-audio-ptt plugin's settings, with its defaults (see `PttSettings` in the API).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// % of the card's playback control; None leaves the card as the system set it.
    pub volume: Option<u8>,
    /// % of the card's Capture control, like `volume`.
    pub mic_gain: Option<u8>,
    pub capture_device: String,
    pub playback_device: String,
    pub talk_input: TalkInput,
    pub play_on_device: bool,
    pub rx_while_tx: bool,
    pub auto_arm: bool,
    pub squelch_enabled: bool,
    pub squelch_open_dbfs: f32,
    pub squelch_hysteresis_db: f32,
    pub squelch_hangover_ms: u32,
    pub squelch_preroll_ms: u32,
    pub jitter_target_ms: u32,
    pub jitter_max_ms: u32,
    pub opus_bitrate_bps: u32,
    pub opus_complexity: u8,
    pub opus_dtx: bool,
    pub opus_fec: bool,
    pub opus_packet_loss_pct: u8,
    pub opus_cbr: bool,
    pub packet_frames: u8,
    pub packet_frames_max: u8,
    pub packet_align_ldpc: bool,
    pub relay: bool,
    pub ttl: u8,
    pub spectrum_enabled: bool,
    pub spectrum_bands: u8,
    /// Earlier versions' voice activation: read once, turned into the squelch settings.
    #[serde(skip_serializing)]
    vox_enabled: Option<bool>,
    #[serde(skip_serializing)]
    vox_threshold_db: Option<f32>,
}

impl Default for Settings {
    fn default() -> Self {
        let squelch = SquelchConfig::default();
        let opus = opus::EncoderConfig::default();
        Self {
            volume: None,
            mic_gain: None,
            capture_device: "default".into(),
            playback_device: "default".into(),
            talk_input: TalkInput::Device,
            play_on_device: true,
            rx_while_tx: false,
            auto_arm: true,
            squelch_enabled: true,
            squelch_open_dbfs: squelch.open_dbfs,
            squelch_hysteresis_db: squelch.hysteresis_db,
            squelch_hangover_ms: squelch.hangover_ms,
            squelch_preroll_ms: squelch.preroll_ms,
            jitter_target_ms: 120,
            jitter_max_ms: 320,
            opus_bitrate_bps: opus.bitrate_bps,
            opus_complexity: opus.complexity,
            opus_dtx: opus.dtx,
            opus_fec: opus.fec,
            opus_packet_loss_pct: opus.packet_loss_pct,
            opus_cbr: opus.cbr,
            packet_frames: 4,
            packet_frames_max: 8,
            packet_align_ldpc: true,
            relay: true,
            ttl: DEFAULT_TTL,
            spectrum_enabled: true,
            spectrum_bands: 14,
            vox_enabled: None,
            vox_threshold_db: None,
        }
    }
}

impl Settings {
    /// Stored settings, including an earlier version's `vox_*` fields.
    pub fn load(text: &str) -> Self {
        let mut settings: Settings = serde_json::from_str(text).unwrap_or_default();
        if let Some(enabled) = settings.vox_enabled.take() {
            settings.squelch_enabled = enabled;
        }
        if let Some(threshold) = settings.vox_threshold_db.take() {
            settings.squelch_open_dbfs = threshold.clamp(-90.0, 0.0);
        }
        settings
    }

    fn squelch(&self) -> SquelchConfig {
        SquelchConfig { open_dbfs: self.squelch_open_dbfs, hysteresis_db: self.squelch_hysteresis_db, hangover_ms: self.squelch_hangover_ms, preroll_ms: self.squelch_preroll_ms }
    }

    fn encoder(&self) -> opus::EncoderConfig {
        opus::EncoderConfig { bitrate_bps: self.opus_bitrate_bps, complexity: self.opus_complexity, dtx: self.opus_dtx, fec: self.opus_fec, packet_loss_pct: self.opus_packet_loss_pct, cbr: self.opus_cbr }
    }

    /// The device microphone is armed for the squelch to key it.
    fn armed(&self) -> bool {
        self.auto_arm && self.squelch_enabled
    }
}

/// A patch field that may be set to null: absent = None, null = Some(None).
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

/// `PATCH /ptt/settings`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    #[serde(default, deserialize_with = "nullable")]
    pub volume: Option<Option<u8>>,
    #[serde(default, deserialize_with = "nullable")]
    pub mic_gain: Option<Option<u8>>,
    pub capture_device: Option<String>,
    pub playback_device: Option<String>,
    pub talk_input: Option<TalkInput>,
    pub play_on_device: Option<bool>,
    pub rx_while_tx: Option<bool>,
    pub auto_arm: Option<bool>,
    pub squelch_enabled: Option<bool>,
    pub squelch_open_dbfs: Option<f32>,
    pub squelch_hysteresis_db: Option<f32>,
    pub squelch_hangover_ms: Option<u32>,
    pub squelch_preroll_ms: Option<u32>,
    pub jitter_target_ms: Option<u32>,
    pub jitter_max_ms: Option<u32>,
    pub opus_bitrate_bps: Option<u32>,
    pub opus_complexity: Option<u8>,
    pub opus_dtx: Option<bool>,
    pub opus_fec: Option<bool>,
    pub opus_packet_loss_pct: Option<u8>,
    pub opus_cbr: Option<bool>,
    pub packet_frames: Option<u8>,
    pub packet_frames_max: Option<u8>,
    pub packet_align_ldpc: Option<bool>,
    pub relay: Option<bool>,
    pub ttl: Option<u8>,
    pub spectrum_enabled: Option<bool>,
    pub spectrum_bands: Option<u8>,
}

type Invalid = (&'static str, &'static str);

fn within<T: PartialOrd + Copy>(value: Option<T>, low: T, high: T, field: &'static str, message: &'static str) -> Result<Option<T>, Invalid> {
    match value {
        Some(value) if value < low || value > high => Err((field, message)),
        other => Ok(other),
    }
}

fn device_name(value: &Option<String>, field: &'static str) -> Result<(), Invalid> {
    match value {
        Some(name) if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) => Err((field, "Use an ALSA device name of up to 64 characters.")),
        _ => Ok(()),
    }
}

impl SettingsPatch {
    /// The patched settings, or which field is out of range.
    pub fn apply(&self, mut settings: Settings) -> Result<Settings, Invalid> {
        let percent = "Use 0 to 100, or null to leave the card as it is.";
        if let Some(volume) = self.volume {
            settings.volume = within(volume, 0, 100, "volume", percent)?;
        }
        if let Some(gain) = self.mic_gain {
            settings.mic_gain = within(gain, 0, 100, "mic_gain", percent)?;
        }
        device_name(&self.capture_device, "capture_device")?;
        device_name(&self.playback_device, "playback_device")?;
        for (value, field, low, high, message) in [
            (self.squelch_open_dbfs, "squelch_open_dbfs", -90.0, 0.0, "Use -90 to 0 dBFS."),
            (self.squelch_hysteresis_db, "squelch_hysteresis_db", 0.0, 30.0, "Use 0 to 30 dB."),
        ] {
            if value.is_some_and(|value: f32| !value.is_finite() || value < low || value > high) {
                return Err((field, message));
            }
        }
        within(self.squelch_hangover_ms, 0, 5000, "squelch_hangover_ms", "Use 0 to 5000 ms.")?;
        within(self.squelch_preroll_ms, 0, 1000, "squelch_preroll_ms", "Use 0 to 1000 ms.")?;
        within(self.jitter_target_ms, 20, 1000, "jitter_target_ms", "Use 20 to 1000 ms.")?;
        within(self.jitter_max_ms, 20, 2000, "jitter_max_ms", "Use 20 to 2000 ms.")?;
        within(self.opus_bitrate_bps, 6000, 64000, "opus_bitrate_bps", "Use 6000 to 64000 bit/s.")?;
        within(self.opus_complexity, 0, 10, "opus_complexity", "Use 0 to 10.")?;
        within(self.opus_packet_loss_pct, 0, 100, "opus_packet_loss_pct", "Use 0 to 100.")?;
        within(self.packet_frames, 1, 8, "packet_frames", "Use 1 to 8.")?;
        within(self.packet_frames_max, 1, 16, "packet_frames_max", "Use 1 to 16.")?;
        within(self.ttl, 1, 8, "ttl", "Use 1 to 8.")?;
        within(self.spectrum_bands, 4, 64, "spectrum_bands", "Use 4 to 64.")?;
        macro_rules! set {
            ($($field:ident),*) => { $( if let Some(value) = self.$field.clone() { settings.$field = value; } )* };
        }
        set!(
            capture_device, playback_device, talk_input, play_on_device, rx_while_tx, auto_arm, squelch_enabled, squelch_open_dbfs, squelch_hysteresis_db, squelch_hangover_ms,
            squelch_preroll_ms, jitter_target_ms, jitter_max_ms, opus_bitrate_bps, opus_complexity, opus_dtx, opus_fec, opus_packet_loss_pct, opus_cbr, packet_frames,
            packet_frames_max, packet_align_ldpc, relay, ttl, spectrum_enabled, spectrum_bands
        );
        if settings.jitter_max_ms < settings.jitter_target_ms {
            return Err(("jitter_max_ms", "Use at least jitter_target_ms."));
        }
        if settings.packet_frames_max < settings.packet_frames {
            return Err(("packet_frames_max", "Use at least packet_frames."));
        }
        Ok(settings)
    }
}

#[derive(Clone, Debug, Serialize)]
struct BurstView {
    talker: TalkerView,
    started_ts_ms: i64,
    duration_ms: u64,
    frames: u64,
    lost_frames: u64,
    hops: Option<u8>,
    /// `released`, `preempted` or `timeout`.
    ended: &'static str,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Stats {
    tx_packets: u64,
    rx_packets: u64,
    relayed: u64,
    suppressed: u64,
    duplicates: u64,
    /// Packets refused: a bad admin signature, unsigned in an admin burst, or a replay.
    refused: u64,
}

/// What `GET /ptt` shows, kept up to date by the engine.
#[derive(Default)]
struct Snapshot {
    floor: &'static str,
    talker: Option<TalkerView>,
    since_ms: Option<i64>,
    level: f32,
    epoch: Option<u8>,
    /// This device is the Kaonic Admin.
    admin: bool,
    recent: VecDeque<BurstView>,
    stats: Stats,
}

enum Command {
    Key { source: Source, reply: oneshot::Sender<Result<(), KeyError>> },
    Unkey { source: Source },
    Audio { source: Source, pcm: Vec<i16> },
    TestTone,
    /// Transmit `signal` (16 kHz mono) as a burst, optionally looped.
    TestTx { signal: Vec<i16>, looped: bool, reply: oneshot::Sender<Result<(), KeyError>> },
    /// The settings changed: devices, mixer, squelch, jitter.
    Settings,
}

pub struct Ptt {
    app: App,
    commands: mpsc::Sender<Command>,
    pcm: broadcast::Sender<Pcm>,
    control: broadcast::Sender<Control>,
    snapshot: Mutex<Snapshot>,
    settings: Mutex<Settings>,
    /// The configured devices open: a microphone, a speaker.
    microphone: AtomicBool,
    speaker: AtomicBool,
    pub udp: udp::Sessions,
}

fn roll() -> f64 {
    let bytes = crate::random::bytes::<4>().unwrap_or([0; 4]);
    f64::from(u32::from_be_bytes(bytes)) / f64::from(u32::MAX).max(1.0)
}

fn now_ms() -> i64 {
    crate::clock::now_ms()
}

/// Loudness of a frame, 0 to 1 (-60 dBFS to 0).
fn level(pcm: &[i16]) -> f32 {
    let db = kaonic_ptt::frame_level_dbfs(pcm);
    ((db + 60.0) / 60.0).clamp(0.0, 1.0)
}

fn scale(pcm: &mut [i16], factor: f32) {
    if (factor - 1.0).abs() < f32::EPSILON {
        return;
    }
    for sample in pcm.iter_mut() {
        *sample = (f32::from(*sample) * factor).clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16;
    }
}

const SETTINGS_KEY: &str = "ptt.settings";
/// Our burst counter (see `kaonic_ptt::Packet::counter`): the next value not yet handed out.
/// Stored a block ahead, so a restart skips the unused rest and the counter still only grows.
const COUNTER_KEY: &str = "ptt.counter";
const COUNTER_BLOCK: u32 = 1000;
/// The highest burst counter taken from the admin, kept across our restarts so a burst
/// recorded before one is not played after it.
const ADMIN_COUNTER_KEY: &str = "ptt.admin_counter";
/// The admin's counter is written at most this often (the latest wins), not once per burst.
const ADMIN_COUNTER_WRITE: Duration = Duration::from_secs(10);

/// A value to store at most once per `every`: the first at once, later ones coalesced.
struct Coalesce {
    every: Duration,
    written: Option<Instant>,
    pending: Option<String>,
}

impl Coalesce {
    fn new(every: Duration) -> Self {
        Self { every, written: None, pending: None }
    }

    /// Takes a new value; returns what to write now, if anything.
    fn offer(&mut self, value: String, now: Instant) -> Option<String> {
        self.pending = Some(value);
        self.due(now)
    }

    /// The pending value, once `every` has passed since the last write.
    fn due(&mut self, now: Instant) -> Option<String> {
        if self.written.is_some_and(|at| now.saturating_duration_since(at) < self.every) {
            return None;
        }
        let value = self.pending.take()?;
        self.written = Some(now);
        Some(value)
    }
}

impl Ptt {
    /// Starts push-to-talk: the engine waits for the group channel (the node may not be
    /// provisioned yet) and the UDP sessions listen on `udp_port`.
    pub async fn start(app: &App, udp_port: u16) -> Arc<Self> {
        let stored = app.store.call(|c| kaonic_store::settings::get(c, SETTINGS_KEY)).await.ok().flatten();
        let settings = stored.as_deref().map(Settings::load).unwrap_or_default();
        let (commands, receiver) = mpsc::channel(256);
        let ptt = Arc::new(Self {
            app: app.clone(),
            commands,
            pcm: broadcast::channel(64).0,
            control: broadcast::channel(64).0,
            snapshot: Mutex::new(Snapshot { floor: "idle", ..Snapshot::default() }),
            settings: Mutex::new(settings),
            microphone: AtomicBool::new(false),
            speaker: AtomicBool::new(false),
            udp: udp::Sessions::default(),
        });
        let engine = Engine::new(ptt.clone()).await;
        log::info!(
            "ptt: codec {}, microphone {}, speaker {}",
            if opus::available() { "opus" } else { "missing (install libopus)" },
            if ptt.microphone() { "yes" } else { "no" },
            if ptt.speaker() { "yes" } else { "no" }
        );
        tokio::spawn(async move { engine.run(receiver).await });
        udp::serve(ptt.clone(), udp_port);
        ptt
    }

    pub fn settings(&self) -> Settings {
        self.settings.lock().expect("ptt settings lock").clone()
    }

    pub async fn set_settings(&self, settings: Settings) {
        *self.settings.lock().expect("ptt settings lock") = settings.clone();
        if let Ok(text) = serde_json::to_string(&settings) {
            let _ = self.app.store.call(move |c| kaonic_store::settings::set(c, SETTINGS_KEY, &text)).await;
        }
        let _ = self.commands.send(Command::Settings).await;
        self.publish_state();
    }

    pub fn microphone(&self) -> bool {
        self.microphone.load(Ordering::Relaxed)
    }

    pub fn speaker(&self) -> bool {
        self.speaker.load(Ordering::Relaxed)
    }

    /// The device has a microphone and speaker the hub can use.
    pub fn device(&self) -> bool {
        self.microphone() && self.speaker()
    }

    async fn ask(&self, source: Source) -> Result<(), KeyError> {
        let (reply, answer) = oneshot::channel();
        if self.commands.send(Command::Key { source, reply }).await.is_err() {
            return Err(KeyError::Unavailable("Push-to-talk is not running."));
        }
        answer.await.unwrap_or(Err(KeyError::Unavailable("Push-to-talk is not running.")))
    }

    /// Asks for the floor for a client `source`: Err(talker) when it is taken.
    pub async fn key(&self, source: Source) -> Result<(), Option<TalkerView>> {
        // Two members keying together rarely collide if each waits a random 0-100 ms first.
        tokio::time::sleep(kaonic_ptt::recheck_delay(roll())).await;
        self.ask(source).await.map_err(|error| match error {
            KeyError::Busy(talker) => talker,
            KeyError::Unavailable(_) => None,
        })
    }

    /// `POST /ptt/key`: talk from the device microphone. Repeated while held; 2 s after the
    /// last call it unkeys by itself.
    pub async fn key_device(&self) -> Result<(), KeyError> {
        if !self.microphone() {
            return Err(KeyError::Unavailable("This device has no microphone the hub can use."));
        }
        self.ask(Source::Device).await
    }

    pub async fn unkey(&self, source: Source) {
        let _ = self.commands.send(Command::Unkey { source }).await;
    }

    /// `POST /ptt/test/tx`: `signal` as a burst to every node.
    pub async fn test_tx(&self, signal: Vec<i16>, looped: bool) -> Result<(), KeyError> {
        let (reply, answer) = oneshot::channel();
        if self.commands.send(Command::TestTx { signal, looped, reply }).await.is_err() {
            return Err(KeyError::Unavailable("Push-to-talk is not running."));
        }
        answer.await.unwrap_or(Err(KeyError::Unavailable("Push-to-talk is not running.")))
    }

    /// One 20 ms frame of talk from `source` (dropped unless it holds the floor).
    pub fn audio(&self, source: Source, pcm: Vec<i16>) {
        let _ = self.commands.try_send(Command::Audio { source, pcm });
    }

    pub async fn test_tone(&self) -> bool {
        self.speaker() && self.commands.send(Command::TestTone).await.is_ok()
    }

    /// What is played, 20 ms at a time.
    pub fn listen(&self) -> broadcast::Receiver<Pcm> {
        self.pcm.subscribe()
    }

    pub fn control(&self) -> broadcast::Receiver<Control> {
        self.control.subscribe()
    }

    pub fn talker(&self) -> Option<TalkerView> {
        self.snapshot.lock().expect("ptt snapshot lock").talker.clone()
    }

    /// `GET /ptt` and the `ptt.state` event.
    pub fn state(&self) -> Value {
        let settings = self.settings();
        let snapshot = self.snapshot.lock().expect("ptt snapshot lock");
        let group = self.app.ptt_group.get();
        let (status, detail) = match (group, opus::available()) {
            (None, _) => ("unprovisioned", Some("This device has no group key yet: it gets one when it is provisioned.")),
            (Some(_), false) => ("error", Some("The Opus codec library (libopus) is not installed.")),
            (Some(_), true) => ("running", None),
        };
        let members = self.app.links.get().map_or(0, |links| links.established().len());
        let id = self.app.mesh.as_ref().map(|mesh| mesh.identity_hash().to_owned()).unwrap_or_default();
        json!({
            "status": status,
            "self": { "id": id, "is_admin": snapshot.admin },
            "detail": detail,
            "group": { "name": "all", "epoch": group.map(|group| group.epoch()).or(snapshot.epoch), "members": members },
            "floor": { "state": snapshot.floor, "talker": snapshot.talker, "since_ts_ms": snapshot.since_ms, "level": snapshot.level },
            "settings": settings,
            "audio": { "device": self.device(), "codec": opus::available().then_some("opus") },
            "recent": snapshot.recent,
            "stats": snapshot.stats,
        })
    }

    fn publish_state(&self) {
        if self.app.bus.receivers() > 1 {
            self.app.bus.publish("ptt", "ptt.state", self.state());
        }
    }
}

/// A burst being played or sent, for the log.
struct BurstRecord {
    talker: TalkerView,
    key: ([u8; 4], u16),
    started_ms: i64,
    started: Instant,
    frames: u64,
    lost: u64,
    hops: Option<u8>,
    /// Its END packet arrived (a received burst).
    end_seen: bool,
}

/// A test transmission in progress.
struct TestTx {
    signal: Vec<i16>,
    position: usize,
    looped: bool,
}

type Capture = (alsa::Running, mpsc::Receiver<Vec<i16>>);
type Playback = (alsa::Running, std::sync::mpsc::SyncSender<Vec<i16>>);

struct Engine {
    ptt: Arc<Ptt>,
    me: [u8; 4],
    floor: Floor,
    relay: Relay,
    jitter: Jitter,
    packer: Packer,
    encoder: Option<opus::Encoder>,
    decoder: Option<opus::Decoder>,
    group: Option<Arc<GroupChannel>>,
    messages: Option<broadcast::Receiver<GroupMessage>>,
    /// This device is the Kaonic Admin: its bursts are signed and take the floor.
    signing: Option<SigningKey>,
    /// Checks every packet heard: admin signatures, admin bursts, replays.
    gate: Gate,
    /// Our next burst counter, and how far the stored block reaches.
    counter: (u32, u32),
    /// The admin's talker id (its identity hash's first 4 bytes), once known.
    admin_talker: Option<[u8; 4]>,
    admin_counter: Coalesce,
    keyed: Option<(Source, Instant)>,
    /// When `/ptt/key` stops holding the device microphone keyed.
    hold_until: Option<Instant>,
    rx: Option<BurstRecord>,
    tx: Option<BurstRecord>,
    /// The devices open, and their names.
    playback: Option<Playback>,
    capture: Option<Capture>,
    devices: (String, String),
    squelch: Squelch,
    /// The squelch opened while the floor was taken: drop its talk until it closes.
    squelch_blocked: bool,
    /// The card has the gain / volume control (else they are applied in software).
    hardware_gain: bool,
    hardware_volume: bool,
    mixer_reapply_at: Option<Instant>,
    test: Option<TestTx>,
    level: f32,
    /// The armed microphone's last frame, 0-1 and dBFS, for setting the squelch threshold.
    mic_level: (f32, f32),
    tone: Option<u32>,
}

impl Engine {
    async fn new(ptt: Arc<Ptt>) -> Self {
        let me_hex = ptt.app.mesh.as_ref().map(|mesh| mesh.identity_hash().to_owned()).unwrap_or_default();
        let me = u32::from_str_radix(me_hex.get(..8).unwrap_or("0"), 16).unwrap_or(0).to_be_bytes();
        let mut floor = Floor::new(me);
        floor.set_next_burst(u16::from_be_bytes(crate::random::bytes::<2>().unwrap_or([0; 2])));
        let settings = ptt.settings();
        let mut relay = Relay::new(RelayConfig::default(), me);
        relay.set_enabled(settings.relay);
        let mut jitter = Jitter::new(Duration::from_millis(u64::from(settings.jitter_target_ms)));
        jitter.set_limits(Duration::from_millis(u64::from(settings.jitter_target_ms)), Duration::from_millis(u64::from(settings.jitter_max_ms)));
        let mut engine = Self {
            me,
            floor,
            relay,
            jitter,
            packer: Packer::new(me, 0, codec::OPUS16, settings.ttl, usize::from(settings.packet_frames)),
            encoder: None,
            decoder: opus::Decoder::new().ok(),
            group: None,
            messages: None,
            signing: None,
            gate: Gate::new(),
            keyed: None,
            hold_until: None,
            rx: None,
            tx: None,
            playback: None,
            capture: None,
            devices: (String::new(), String::new()),
            squelch: Squelch::new(settings.squelch()),
            squelch_blocked: false,
            hardware_gain: false,
            hardware_volume: false,
            mixer_reapply_at: Some(Instant::now() + MIXER_REAPPLY),
            test: None,
            level: 0.0,
            mic_level: (0.0, kaonic_ptt::squelch::SILENT_DBFS),
            tone: None,
            counter: (0, 0),
            admin_talker: None,
            admin_counter: Coalesce::new(ADMIN_COUNTER_WRITE),
            ptt,
        };
        engine.load_counter().await;
        engine.open_devices();
        engine.apply_mixer().await;
        engine
    }

    async fn load_counter(&mut self) {
        let store = &self.ptt.app.store;
        let stored = store.call(|c| kaonic_store::settings::get(c, COUNTER_KEY)).await.ok().flatten();
        let next = stored.and_then(|text| text.parse::<u32>().ok()).unwrap_or(1).max(1);
        self.counter = (next, next);
        self.reserve_counters().await;
    }

    async fn reserve_counters(&mut self) {
        let reserved = self.counter.0.saturating_add(COUNTER_BLOCK);
        let text = reserved.to_string();
        if self.ptt.app.store.call(move |c| kaonic_store::settings::set(c, COUNTER_KEY, &text)).await.is_ok() {
            self.counter.1 = reserved;
        }
    }

    /// The counter for a new burst of ours: higher than any before, also across restarts.
    /// The stored value stays at least half a block ahead of what is handed out, so a crash
    /// before a write lands cannot make the counter go back (listeners would refuse our talk
    /// as replays until it caught up).
    fn next_counter(&mut self) -> u32 {
        let counter = self.counter.0;
        self.counter.0 = self.counter.0.saturating_add(1);
        if self.counter.1.saturating_sub(self.counter.0) < COUNTER_BLOCK / 2 {
            let reserved = self.counter.1.saturating_add(COUNTER_BLOCK);
            self.counter.1 = reserved;
            let app = self.ptt.app.clone();
            tokio::spawn(async move {
                let text = reserved.to_string();
                if app.store.call(move |c| kaonic_store::settings::set(c, COUNTER_KEY, &text)).await.is_err() {
                    log::error!("ptt: cannot store the burst counter");
                }
            });
        }
        counter
    }

    /// Opens the configured capture and playback devices (again, when they changed).
    fn open_devices(&mut self) {
        let settings = self.ptt.settings();
        if !alsa::available() {
            return;
        }
        if self.devices.0 != settings.capture_device || self.capture.is_none() {
            self.capture = alsa::capture(&settings.capture_device).inspect_err(|error| log::debug!("ptt: microphone: {error}")).ok();
            self.devices.0 = settings.capture_device.clone();
        }
        if self.devices.1 != settings.playback_device || self.playback.is_none() {
            self.playback = alsa::playback(&settings.playback_device).inspect_err(|error| log::debug!("ptt: speaker: {error}")).ok();
            self.devices.1 = settings.playback_device.clone();
        }
        self.ptt.microphone.store(self.capture.is_some(), Ordering::Relaxed);
        self.ptt.speaker.store(self.playback.is_some(), Ordering::Relaxed);
    }

    /// Microphone gain and speaker volume on the card's mixer, as the plugin did; a card
    /// without the control gets them in software.
    async fn apply_mixer(&mut self) {
        let settings = self.ptt.settings();
        let (capture, playback) = (settings.capture_device.clone(), settings.playback_device.clone());
        let (gain, volume) = (settings.mic_gain, settings.volume);
        let applied = tokio::task::spawn_blocking(move || {
            let gain = gain.map(|pct| mixer::set(&capture, mixer::Control::Capture, pct).inspect_err(|error| log::debug!("ptt: mic gain in software: {error}")).is_ok());
            let volume = volume.map(|pct| mixer::set(&playback, mixer::Control::Playback, pct).inspect_err(|error| log::debug!("ptt: volume in software: {error}")).is_ok());
            (gain, volume)
        })
        .await
        .unwrap_or((None, None));
        // Unset: the card is left as the system set it, nothing to scale.
        self.hardware_gain = applied.0.unwrap_or(true);
        self.hardware_volume = applied.1.unwrap_or(true);
    }

    /// Who may sign and whose signature counts; checked again as trust changes.
    async fn refresh_trust(&mut self) {
        let app = &self.ptt.app;
        let trust = crate::provision::trust(app).await;
        self.gate.set_admin_key(trust.as_ref().map(|trust| *trust.root().public_key()));
        self.signing = match trust.filter(|trust| trust.own() == trust.root()) {
            Some(_) => crate::provision::own_identity(app).await.map(|identity| identity.signing_key().clone()),
            None => None,
        };
        self.ptt.snapshot.lock().expect("ptt snapshot lock").admin = self.signing.is_some();
        let admin_talker = crate::api::our_admin(app)
            .await
            .ok()
            .flatten()
            .and_then(|hex| u32::from_str_radix(hex.get(..8)?, 16).ok())
            .map(u32::to_be_bytes);
        self.gate.set_admin_talker(admin_talker);
        if admin_talker.is_some() && admin_talker != self.admin_talker {
            self.admin_talker = admin_talker;
            let stored = app.store.call(|c| kaonic_store::settings::get(c, ADMIN_COUNTER_KEY)).await.ok().flatten();
            if let (Some(talker), Some(highest)) = (admin_talker, stored.and_then(|text| text.parse::<u32>().ok())) {
                self.gate.replay().restore(talker, highest);
            }
        }
        if self.group.is_none()
            && let Some(group) = app.ptt_group.get()
        {
            self.messages = Some(group.subscribe());
            self.group = Some(group.clone());
            log::info!("ptt: group channel open");
        }
    }

    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        self.refresh_trust().await;
        let mut tick = tokio::time::interval(Duration::from_millis(kaonic_ptt::FRAME_MS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut trust_check = tokio::time::interval(Duration::from_secs(5));
        let mut level_tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.on_command(command).await,
                    None => return,
                },
                message = recv_group(&mut self.messages) => match message {
                    Ok(message) => self.on_group(message),
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
                        if NOTED.due() {
                            log::warn!("ptt: missed {missed} group packets");
                        } else {
                            log::debug!("ptt: missed {missed} group packets");
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => self.messages = None,
                },
                frame = recv_capture(&mut self.capture) => match frame {
                    Some(frame) => self.on_device_frame(frame).await,
                    None => {
                        self.capture = None;
                        self.ptt.microphone.store(false, Ordering::Relaxed);
                    }
                },
                _ = tick.tick() => self.on_tick().await,
                _ = trust_check.tick() => {
                    if let Some(text) = self.admin_counter.due(Instant::now()) {
                        self.write_admin_counter(text);
                    }
                    self.refresh_trust().await;
                    if self.mixer_reapply_at.is_some_and(|at| Instant::now() >= at) {
                        self.mixer_reapply_at = None;
                        self.apply_mixer().await;
                    }
                }
                _ = level_tick.tick() => self.publish_level(),
            }
        }
    }

    fn talker_view(&self, talker: [u8; 4], admin: bool, local: Option<Source>) -> TalkerView {
        let prefix: String = talker.iter().map(|byte| format!("{byte:02x}")).collect();
        let peer = self.ptt.app.mesh.as_ref().and_then(|mesh| {
            if mesh.identity_hash().starts_with(&prefix) {
                return Some((mesh.identity_hash().to_owned(), mesh.info().codename));
            }
            mesh.peers().into_iter().find(|peer| peer.id.starts_with(&prefix)).map(|peer| {
                let codename = match peer.announced {
                    Announced::Hub(info) => info.codename,
                    _ => String::new(),
                };
                (peer.id, codename)
            })
        });
        let (id, codename) = peer.unwrap_or_else(|| (format!("{prefix:0<32}"), String::new()));
        TalkerView { id, codename, is_admin: admin, local: local.is_some(), source: local.map(Source::name) }
    }

    fn set_floor(&self, talker: Option<TalkerView>) {
        {
            let mut snapshot = self.ptt.snapshot.lock().expect("ptt snapshot lock");
            snapshot.floor = match self.floor.state() {
                FloorState::Idle => "idle",
                FloorState::Talking => "talking",
                FloorState::Receiving => "receiving",
            };
            snapshot.since_ms = talker.as_ref().map(|_| now_ms());
            if talker.is_none() {
                snapshot.level = 0.0;
            }
            snapshot.talker = talker.clone();
        }
        let _ = self.ptt.control.send(Control::Talker(talker));
        self.ptt.publish_state();
    }

    /// A received burst that is over: released if its END came, else it timed out.
    fn finish_rx(&mut self) {
        if let Some(record) = self.rx.take() {
            let ended = if record.end_seen { "released" } else { "timeout" };
            self.finish_burst(record, ended);
        }
    }

    fn finish_burst(&self, record: BurstRecord, ended: &'static str) {
        let view = BurstView {
            talker: record.talker,
            started_ts_ms: record.started_ms,
            duration_ms: record.started.elapsed().as_millis() as u64,
            frames: record.frames,
            lost_frames: record.lost,
            hops: record.hops,
            ended,
        };
        let mut snapshot = self.ptt.snapshot.lock().expect("ptt snapshot lock");
        if snapshot.recent.len() == RECENT {
            snapshot.recent.pop_back();
        }
        snapshot.recent.push_front(view);
    }

    async fn send(&mut self, mut packet: Packet) {
        // Every packet of an admin burst is signed: a member holding the group key could
        // otherwise add its own packets to it.
        if packet.is_admin()
            && let Some(key) = &self.signing
        {
            kaonic_ptt::sign_admin(&mut packet, key);
        }
        self.relay.on_sent(&packet, Instant::now());
        let Some(group) = &self.group else { return };
        if group.send(&packet.encode()).await {
            self.ptt.snapshot.lock().expect("ptt snapshot lock").stats.tx_packets += 1;
        }
    }

    async fn on_command(&mut self, command: Command) {
        let now = Instant::now();
        match command {
            Command::Key { source, reply } => {
                let result = if source == Source::Device && self.keyed.is_some_and(|(keyed, _)| keyed == Source::Device) {
                    Ok(())
                } else {
                    self.key(source, now)
                };
                if result.is_ok() && source == Source::Device {
                    self.hold_until = Some(now + KEY_HOLD);
                }
                let _ = reply.send(result);
            }
            Command::Unkey { source } => {
                if self.keyed.is_some_and(|(keyed, _)| keyed == source) {
                    self.unkey("released").await;
                }
            }
            Command::Audio { source, pcm } => self.talk(source, pcm, now).await,
            Command::TestTone => self.tone = Some(0),
            Command::TestTx { signal, looped, reply } => {
                if signal.len() < opus::FRAME_SAMPLES {
                    let _ = reply.send(Err(KeyError::Unavailable("The test recording is too short.")));
                    return;
                }
                let result = self.key(Source::Test, now);
                if result.is_ok() {
                    self.test = Some(TestTx { signal, position: 0, looped });
                }
                let _ = reply.send(result);
            }
            Command::Settings => {
                let settings = self.ptt.settings();
                self.relay.set_enabled(settings.relay);
                self.squelch.configure(settings.squelch());
                self.jitter.set_limits(Duration::from_millis(u64::from(settings.jitter_target_ms)), Duration::from_millis(u64::from(settings.jitter_max_ms)));
                if !settings.armed() && self.keyed.is_some_and(|(source, _)| source == Source::Squelch) {
                    self.unkey("released").await;
                }
                self.open_devices();
                self.apply_mixer().await;
            }
        }
    }

    fn key(&mut self, source: Source, now: Instant) -> Result<(), KeyError> {
        if let Some((keyed, _)) = self.keyed {
            if keyed == source {
                return Ok(());
            }
            return Err(KeyError::Busy(self.ptt.talker()));
        }
        if self.group.is_none() {
            return Err(KeyError::Unavailable("This device has no group key yet: it gets one when it is provisioned."));
        }
        if !opus::available() {
            return Err(KeyError::Unavailable("The Opus codec library (libopus) is not installed."));
        }
        let admin = self.signing.is_some();
        match self.floor.request(now, admin) {
            Ok(burst) => {
                if let Some(record) = self.rx.take() {
                    self.finish_burst(record, "preempted");
                }
                let settings = self.ptt.settings();
                let cap = self.group.as_ref().map_or(814, |group| group.max_payload());
                self.packer.set_ttl(settings.ttl);
                self.packer.set_epoch(self.group.as_ref().map_or(0, |group| group.epoch()));
                self.packer.set_packing(usize::from(settings.packet_frames), usize::from(settings.packet_frames_max), settings.packet_align_ldpc, cap);
                let counter = self.next_counter();
                self.packer.start(burst.burst, admin, counter);
                self.encoder = opus::Encoder::with(settings.encoder()).inspect_err(|error| log::warn!("ptt: encoder: {error}")).ok();
                self.keyed = Some((source, now));
                let view = self.talker_view(self.me, admin, Some(source));
                self.tx = Some(BurstRecord { talker: view.clone(), key: (self.me, burst.burst), started_ms: now_ms(), started: Instant::now(), frames: 0, lost: 0, hops: None, end_seen: false });
                self.set_floor(Some(view));
                Ok(())
            }
            Err(busy) => Err(KeyError::Busy(busy.talker.map(|talker| self.talker_view(talker.talker, talker.admin, None)))),
        }
    }

    async fn unkey(&mut self, reason: &'static str) {
        let Some((source, _)) = self.keyed.take() else { return };
        self.hold_until = None;
        self.test = None;
        if source == Source::Squelch {
            self.squelch.reset();
        }
        if let Some(packet) = self.packer.finish() {
            // The END closes the burst for listeners: a lost one leaves them waiting 500 ms and
            // logging a timeout. Copies are duplicates to whoever already has it.
            for copy in 0..3 {
                if copy > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                }
                self.send(packet.clone()).await;
            }
        }
        self.floor.release(Instant::now());
        self.encoder = None;
        if let Some(record) = self.tx.take() {
            self.finish_burst(record, reason);
        }
        let _ = self.ptt.control.send(Control::Unkeyed { source, reason });
        self.set_floor(None);
    }

    async fn talk(&mut self, source: Source, pcm: Vec<i16>, now: Instant) {
        if !self.keyed.is_some_and(|(keyed, _)| keyed == source) || pcm.len() != opus::FRAME_SAMPLES {
            return;
        }
        if let Some((_, last)) = &mut self.keyed {
            *last = now;
        }
        self.level = level(&pcm);
        let Some(encoder) = &mut self.encoder else { return };
        let Ok(frame) = encoder.encode(&pcm) else { return };
        if let Some(record) = &mut self.tx {
            record.frames += 1;
        }
        for packet in self.packer.push(frame) {
            self.send(packet).await;
        }
    }

    /// Remembers the admin's newest burst counter across our restarts.
    fn keep_admin_counter(&mut self, packet: &Packet) {
        if packet.is_start()
            && Some(packet.talker) == self.admin_talker
            && let Some(text) = self.admin_counter.offer(packet.counter.to_string(), Instant::now())
        {
            self.write_admin_counter(text);
        }
    }

    fn write_admin_counter(&self, text: String) {
        let app = self.ptt.app.clone();
        tokio::spawn(async move {
            let _ = app.store.call(move |c| kaonic_store::settings::set(c, ADMIN_COUNTER_KEY, &text)).await;
        });
    }

    fn on_group(&mut self, message: GroupMessage) {
        let Some(packet) = Packet::decode(&message.payload) else { return };
        let now = Instant::now();
        self.ptt.snapshot.lock().expect("ptt snapshot lock").stats.rx_packets += 1;
        // Copies relayed by several nodes are dropped first, before any signature check.
        match self.relay.on_heard(&packet, now, roll()) {
            Heard::New => {}
            Heard::Duplicate | Heard::Own => return,
        }
        let key = (packet.talker, packet.burst);
        let verdict = self.gate.check(&packet, now);
        if verdict == Verdict::Refused {
            // Neither played nor relayed, and forgotten, so the genuine packet still counts.
            self.relay.forget(&packet);
            self.ptt.snapshot.lock().expect("ptt snapshot lock").stats.refused += 1;
            return;
        }
        if packet.codec != codec::OPUS16 {
            return;
        }
        let admin = verdict == Verdict::Admin;
        if admin {
            self.keep_admin_counter(&packet);
        }
        let event = self.floor.on_packet(&packet, admin, now);
        if event == FloorEvent::Preempted {
            // Our talk stops at once; the admin is played.
            if let Some((source, _)) = self.keyed.take() {
                self.encoder = None;
                self.hold_until = None;
                self.test = None;
                if source == Source::Squelch {
                    self.squelch.reset();
                }
                if let Some(record) = self.tx.take() {
                    self.finish_burst(record, "preempted");
                }
                let _ = self.ptt.control.send(Control::Unkeyed { source, reason: "preempted" });
            }
        }
        if !matches!(event, FloorEvent::Play | FloorEvent::Preempted) {
            return;
        }
        let hops = DEFAULT_TTL.saturating_sub(packet.ttl);
        let fresh = self.rx.as_ref().is_none_or(|record| record.key != key);
        if fresh {
            // Only an admin burst replaces one being played.
            if let Some(record) = self.rx.take() {
                self.finish_burst(record, "preempted");
            }
            let view = self.talker_view(packet.talker, admin, None);
            self.rx = Some(BurstRecord { talker: view.clone(), key, started_ms: now_ms(), started: now, frames: 0, lost: 0, hops: Some(hops), end_seen: false });
            self.set_floor(Some(view));
        } else if let Some(record) = &mut self.rx {
            record.hops = Some(record.hops.map_or(hops, |known| known.min(hops)));
            if admin && !record.talker.is_admin {
                record.talker.is_admin = true;
                let view = record.talker.clone();
                self.set_floor(Some(view));
            }
        }
        for (index, frame) in packet.frames.iter().enumerate() {
            self.jitter.push(packet.burst, packet.seq.wrapping_add(index as u16), frame.clone(), now);
        }
        if packet.is_end() {
            if let Some(record) = &mut self.rx {
                record.end_seen = true;
            }
            self.jitter.end(packet.burst, packet.seq.wrapping_add(packet.frames.len() as u16));
        }
    }

    /// A 20 ms frame from the device microphone. Keyed with `/ptt/key`, it is sent as it is;
    /// armed, the squelch keys the floor when it opens (with its pre-roll) and releases it
    /// when it closes, which is how the hardware PTT button, that only unmutes the microphone,
    /// keys the radio.
    async fn on_device_frame(&mut self, mut frame: Vec<i16>) {
        let settings = self.ptt.settings();
        let now = Instant::now();
        if !self.hardware_gain
            && let Some(gain) = settings.mic_gain
        {
            // 50 % is unity, like a mixer control at mid range.
            scale(&mut frame, f32::from(gain) / 50.0);
        }
        let dbfs = kaonic_ptt::frame_level_dbfs(&frame);
        self.mic_level = (((dbfs + 60.0) / 60.0).clamp(0.0, 1.0), dbfs);
        match self.keyed.map(|(source, _)| source) {
            Some(Source::Device) => self.talk(Source::Device, frame, now).await,
            Some(Source::Squelch) => {
                let decision = self.squelch.push(&frame);
                if decision.closed {
                    self.unkey("released").await;
                } else if decision.pass {
                    self.talk(Source::Squelch, frame, now).await;
                }
            }
            // Someone else here holds the floor: the microphone waits.
            Some(_) => self.squelch.reset(),
            None if settings.armed() => {
                let decision = self.squelch.push(&frame);
                if decision.closed {
                    self.squelch_blocked = false;
                } else if decision.opened && !self.squelch_blocked {
                    match self.key(Source::Squelch, now) {
                        Ok(()) => {
                            for preroll in self.squelch.take_preroll() {
                                self.talk(Source::Squelch, preroll, now).await;
                            }
                            self.talk(Source::Squelch, frame, now).await;
                        }
                        // The floor is taken: this over is not sent.
                        Err(_) => self.squelch_blocked = true,
                    }
                }
            }
            None => {}
        }
    }

    fn play(&mut self, pcm: Vec<i16>) {
        let settings = self.ptt.settings();
        // The device's own speaker and microphone have no echo canceller between them.
        let quiet_while_talking = self.keyed.is_some() && !settings.rx_while_tx;
        if settings.play_on_device
            && !quiet_while_talking
            && let Some((_, speaker)) = &self.playback
        {
            let mut local = pcm.clone();
            if !self.hardware_volume
                && let Some(volume) = settings.volume
            {
                scale(&mut local, f32::from(volume) / 100.0);
            }
            let _ = speaker.try_send(local);
        }
        let _ = self.ptt.pcm.send(Arc::new(pcm));
    }

    async fn on_tick(&mut self) {
        let now = Instant::now();
        // Relays that are due.
        for packet in self.relay.due(now) {
            if let Some(group) = &self.group {
                group.send(&packet.encode()).await;
            }
        }
        match self.keyed {
            // A keyed client that went quiet.
            Some((source, last)) if !source.is_local() && now.duration_since(last) >= UNKEY_SILENCE => self.unkey("timeout").await,
            // `/ptt/key` not repeated.
            Some((Source::Device, _)) if self.hold_until.is_some_and(|until| now >= until) => self.unkey("timeout").await,
            // The next frame of a test transmission.
            Some((Source::Test, _)) => self.test_frame(now).await,
            _ => {}
        }
        // Playout.
        while let Some(playout) = self.jitter.pop(now) {
            match playout {
                Playout::Frame(frame) => {
                    if let Some(record) = &mut self.rx {
                        record.frames += 1;
                    }
                    let pcm = self.decoder.as_mut().map(|decoder| decoder.decode(&frame)).unwrap_or_default();
                    self.level = level(&pcm);
                    if !pcm.is_empty() {
                        self.play(pcm);
                    }
                }
                Playout::Lost => {
                    if let Some(record) = &mut self.rx {
                        record.lost += 1;
                    }
                    if let Some(pcm) = self.decoder.as_mut().map(|decoder| decoder.conceal(None)) {
                        self.play(pcm);
                    }
                }
                Playout::End => self.finish_rx(),
            }
        }
        if let Some(FloorEvent::Ended(_)) = self.floor.tick(now)
            && self.keyed.is_none()
        {
            self.finish_rx();
            self.level = 0.0;
            self.set_floor(None);
        }
        // The test tone: 1 s of 1 kHz on the speaker only.
        if let Some(frame) = self.tone {
            let tone: Vec<i16> = (0..opus::FRAME_SAMPLES)
                .map(|i| (((frame as usize * opus::FRAME_SAMPLES + i) as f32 * 2.0 * std::f32::consts::PI * 1000.0 / 16000.0).sin() * 6000.0) as i16)
                .collect();
            if let Some((_, speaker)) = &self.playback {
                let _ = speaker.try_send(tone);
            }
            self.tone = (frame < 49).then_some(frame + 1);
        }
    }

    async fn test_frame(&mut self, now: Instant) {
        let Some(test) = &mut self.test else {
            self.unkey("released").await;
            return;
        };
        if test.position + opus::FRAME_SAMPLES > test.signal.len() {
            if !test.looped {
                self.unkey("released").await;
                return;
            }
            test.position = 0;
        }
        let frame = test.signal[test.position..test.position + opus::FRAME_SAMPLES].to_vec();
        test.position += opus::FRAME_SAMPLES;
        self.talk(Source::Test, frame, now).await;
    }

    fn publish_level(&mut self) {
        let talking = self.floor.state() != FloorState::Idle;
        {
            let mut snapshot = self.ptt.snapshot.lock().expect("ptt snapshot lock");
            snapshot.level = if talking { self.level } else { 0.0 };
            snapshot.epoch = self.group.as_ref().map(|group| group.epoch());
            let relay = self.relay.stats();
            snapshot.stats.relayed = relay.relayed;
            snapshot.stats.suppressed = relay.suppressed;
            snapshot.stats.duplicates = relay.duplicates;
        }
        if self.ptt.app.bus.receivers() <= 1 {
            return;
        }
        // What is on the air (sent or played), and the armed microphone even between overs,
        // so the squelch threshold can be set before talking (the plugin's level meter).
        if talking {
            self.ptt.app.bus.publish("ptt", "ptt.level", json!({ "level": self.level, "source": "air" }));
        }
        if self.ptt.settings().auto_arm && self.capture.is_some() {
            let (level, dbfs) = self.mic_level;
            self.ptt.app.bus.publish("ptt", "ptt.level", json!({ "level": level, "source": "mic", "dbfs": dbfs }));
        }
    }
}

async fn recv_group(messages: &mut Option<broadcast::Receiver<GroupMessage>>) -> Result<GroupMessage, broadcast::error::RecvError> {
    match messages {
        Some(messages) => messages.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_capture(capture: &mut Option<Capture>) -> Option<Vec<i16>> {
    match capture {
        Some((_, frames)) => frames.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_counter_writes_are_coalesced_latest_wins() {
        let start = Instant::now();
        let mut counter = Coalesce::new(Duration::from_secs(10));
        assert_eq!(counter.offer("1".into(), start).as_deref(), Some("1"), "the first is written at once");
        for value in 2..50 {
            assert_eq!(counter.offer(value.to_string(), start + Duration::from_secs(1)), None);
        }
        assert_eq!(counter.due(start + Duration::from_secs(5)), None);
        assert_eq!(counter.due(start + Duration::from_secs(10)).as_deref(), Some("49"));
        assert_eq!(counter.due(start + Duration::from_secs(30)), None, "nothing new");
    }

    #[test]
    fn levels_and_gain() {
        assert_eq!(level(&[0; 320]), 0.0);
        let loud: Vec<i16> = (0..320).map(|i| if i % 2 == 0 { i16::MAX } else { -i16::MAX }).collect();
        assert!((level(&loud) - 1.0).abs() < 0.01);
        let mut pcm = vec![1000i16, -1000];
        scale(&mut pcm, 2.0);
        assert_eq!(pcm, vec![2000, -2000]);
        let mut clip = vec![30000i16];
        scale(&mut clip, 2.0);
        assert_eq!(clip, vec![i16::MAX]);
    }

    #[test]
    fn the_defaults_are_the_plugins() {
        let settings = Settings::default();
        assert_eq!((settings.volume, settings.mic_gain, settings.talk_input), (None, None, TalkInput::Device));
        assert!(settings.auto_arm && settings.squelch_enabled && settings.armed());
        assert_eq!((settings.squelch_open_dbfs, settings.squelch_hysteresis_db, settings.squelch_hangover_ms, settings.squelch_preroll_ms), (-45.0, 6.0, 600, 120));
        assert_eq!((settings.jitter_target_ms, settings.jitter_max_ms), (120, 320));
        assert_eq!((settings.opus_bitrate_bps, settings.opus_complexity, settings.opus_dtx, settings.opus_fec, settings.opus_cbr), (20_000, 5, true, false, false));
        assert_eq!((settings.packet_frames, settings.packet_frames_max, settings.packet_align_ldpc), (4, 8, true));
        assert_eq!((settings.spectrum_enabled, settings.spectrum_bands, settings.rx_while_tx), (true, 14, false));
        // 28 fields in the API; the old vox fields are never shown.
        let shown = serde_json::to_value(&settings).unwrap();
        assert_eq!(shown.as_object().unwrap().len(), 28);
        assert!(shown.get("vox_enabled").is_none());
    }

    #[test]
    fn settings_patches_are_checked() {
        let base = Settings::default();
        let patch = |json: &str| serde_json::from_str::<SettingsPatch>(json).unwrap().apply(base.clone());
        let patched = patch(r#"{"volume":30,"relay":false,"squelch_open_dbfs":-50,"talk_input":"browser"}"#).unwrap();
        assert_eq!((patched.volume, patched.relay, patched.squelch_open_dbfs, patched.talk_input), (Some(30), false, -50.0, TalkInput::Browser));
        assert_eq!(patch(r#"{"volume":null}"#).unwrap().volume, None);
        assert_eq!(patch(r#"{"volume":101}"#).unwrap_err().0, "volume");
        assert_eq!(patch(r#"{"ttl":0}"#).unwrap_err().0, "ttl");
        assert_eq!(patch(r#"{"squelch_open_dbfs":3}"#).unwrap_err().0, "squelch_open_dbfs");
        assert_eq!(patch(r#"{"jitter_target_ms":400}"#).unwrap_err().0, "jitter_max_ms");
        assert_eq!(patch(r#"{"packet_frames":8,"packet_frames_max":4}"#).unwrap_err().0, "packet_frames_max");
        assert_eq!(patch(r#"{"capture_device":""}"#).unwrap_err().0, "capture_device");
        assert_eq!(patch(r#"{"opus_bitrate_bps":100}"#).unwrap_err().0, "opus_bitrate_bps");
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"vox_enabled":true}"#).is_err(), "the old fields are not accepted any more");
    }

    #[test]
    fn earlier_settings_still_load() {
        let old = Settings::load(r#"{"volume":80,"mic_gain":50,"play_on_device":true,"vox_enabled":false,"vox_threshold_db":-30.0,"relay":true,"ttl":4}"#);
        assert_eq!((old.volume, old.mic_gain), (Some(80), Some(50)));
        assert!(!old.squelch_enabled, "the stored voice activation choice is kept");
        assert_eq!(old.squelch_open_dbfs, -30.0);
        assert!(old.auto_arm && old.packet_align_ldpc, "new settings take their defaults");
        assert!(serde_json::to_value(&old).unwrap().get("vox_threshold_db").is_none());
        assert_eq!(Settings::load("not json"), Settings::default());
    }
}
