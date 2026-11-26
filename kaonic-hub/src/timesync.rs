//! The date across the network. Kaonic boards have no battery clock, so each boot starts
//! from whatever the system has; nodes keep and share UTC (local time is the web UI's job).
//!
//! - At start the clock is moved forward to the best time known: the last one saved here
//!   (every ten minutes and whenever the clock is set), or [`FLOOR`]. That is a guess, not a
//!   valid time.
//! - A clock is *valid* once it was set this boot (from a browser, the admin or a peer), or
//!   when the kernel says NTP keeps it.
//! - Whenever an authenticated link comes up, both sides send their time. A node without a
//!   valid clock takes a valid one from any peer. A node that has just gained a valid clock
//!   sends it on all its links, so the date spreads beyond the first node to know it.
//! - The admin sends its time on every link each [`ADMIN_EVERY`]; a node steps its clock to it
//!   when it is off by more than [`STEP_OVER_MS`] (not when NTP keeps the node's clock).
//! - The web UI sets the clock from the browser (`PUT /api/v1/system/time`). On a node, the
//!   admin's next time wins over it.
//!
//! On the links it travels as a mux control message on stream [`STREAM`]:
//! `"KTM1" | unix ms i64 BE | flags u8` (bit 0: the sender's clock is valid). Only links that
//! passed the certificate handshake carry it; a member could still lie to a node that has no
//! valid clock, which is the trade for getting a date without the admin in reach.
//!
//! Stepping the clock moves stored browser sessions by as much, so a jump does not sign
//! anyone out (or keep a session past its limits).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use kaonic_mux::{Kind, Message};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::app::App;
use crate::clock;

/// The mux stream carrying time on the links.
pub const STREAM: u8 = 6;
const MAGIC: &[u8; 4] = b"KTM1";
const FLAG_VALID: u8 = 0x01;
/// No clock is earlier than this (2026-01-01T00:00:00Z): anything before is unset.
pub const FLOOR_MS: i64 = 1_767_225_600_000;
/// Nor later than this (2100-01-01T00:00:00Z).
pub const CEILING_MS: i64 = 4_102_444_800_000;
/// How often the admin sends its time.
pub const ADMIN_EVERY: Duration = Duration::from_secs(60);
/// A node follows the admin only when off by more than this, so the clock is not stepped
/// back and forth by the links' delay.
pub const STEP_OVER_MS: i64 = 2_000;
/// How often the time is saved, as the best guess for the next boot (the flash is spared).
const SAVE_EVERY: Duration = Duration::from_secs(600);
/// The settings key holding the last time saved, unix seconds.
const LAST_KNOWN: &str = "time.last_known";

/// Where this boot's valid clock came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Browser,
    Admin,
    /// A peer, by identity hash.
    Peer(String),
}

impl Source {
    fn name(&self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Admin => "admin",
            Self::Peer(_) => "peer",
        }
    }
}

struct Synced {
    source: Source,
    /// Unix ms when it was last set or confirmed.
    at_ms: i64,
}

static SYNCED: Mutex<Option<Synced>> = Mutex::new(None);

/// The clock as `GET /system/time` shows it.
#[derive(Clone, Debug, Serialize)]
pub struct TimeView {
    /// UTC, unix milliseconds.
    pub now_ms: i64,
    /// The clock is valid: set this boot, or kept by NTP.
    pub valid: bool,
    /// `browser`, `admin`, `peer` or `ntp`; None while not valid.
    pub source: Option<&'static str>,
    /// The peer it came from, for `peer`.
    pub peer: Option<String>,
    /// When it was last set or confirmed (unix ms).
    pub synced_ms: Option<i64>,
}

pub fn view() -> TimeView {
    let synced = SYNCED.lock().expect("time lock");
    let ntp = synced.is_none() && ntp_synced();
    TimeView {
        now_ms: clock::now_ms(),
        valid: synced.is_some() || ntp,
        source: synced.as_ref().map(|synced| synced.source.name()).or(ntp.then_some("ntp")),
        peer: synced.as_ref().and_then(|synced| match &synced.source {
            Source::Peer(peer) => Some(peer.clone()),
            _ => None,
        }),
        synced_ms: synced.as_ref().map(|synced| synced.at_ms),
    }
}

/// The clock is valid (set this boot, or kept by NTP).
pub fn is_valid() -> bool {
    SYNCED.lock().expect("time lock").is_some() || ntp_synced()
}

pub fn encode(now_ms: i64, valid: bool) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&now_ms.to_be_bytes());
    out.push(if valid { FLAG_VALID } else { 0 });
    out
}

/// `(unix ms, valid)`; None for anything else, or a time out of range.
pub fn decode(bytes: &[u8]) -> Option<(i64, bool)> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let (time, flags) = rest.split_first_chunk::<8>()?;
    let [flags] = flags else { return None };
    let now_ms = i64::from_be_bytes(*time);
    in_range(now_ms).then_some((now_ms, flags & FLAG_VALID != 0))
}

pub fn in_range(now_ms: i64) -> bool {
    (FLOOR_MS..CEILING_MS).contains(&now_ms)
}

/// What to do with a time a peer sent.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Ignore,
    /// Take it (step the clock if it is off by more than the margin) and mark the clock valid.
    Take,
}

/// `from_admin`: it came on the admin's link. `ours_valid`: set this boot. `ntp`: the kernel's
/// NTP keeps our clock.
fn decide(theirs_valid: bool, from_admin: bool, ours_valid: bool, ntp: bool) -> Decision {
    if !theirs_valid || ntp {
        return Decision::Ignore;
    }
    if from_admin || !ours_valid {
        Decision::Take
    } else {
        Decision::Ignore
    }
}

/// At start, before anything is stored with a time: moves the clock forward to the best time
/// known (the last saved, or [`FLOOR_MS`]) if it is behind it.
pub async fn restore(app: &App) {
    if app.config.dev {
        return;
    }
    let saved = app
        .store
        .call(|c| kaonic_store::settings::get(c, LAST_KNOWN))
        .await
        .ok()
        .flatten()
        .and_then(|text| text.parse::<i64>().ok())
        .and_then(|secs| secs.checked_mul(1000))
        .filter(|&ms| in_range(ms));
    let best = saved.unwrap_or(FLOOR_MS).max(FLOOR_MS);
    let now = clock::now_ms();
    if now >= best || ntp_synced() {
        return;
    }
    match set_system_clock(best) {
        Ok(()) => log::info!("time: the clock was unset, moved to the last known time {} (not valid until synced)", best / 1000),
        Err(error) => log::warn!("time: cannot move the clock to the last known time: {error}"),
    }
}

/// Sets the clock to `now_ms` (UTC) and marks it valid, from `source`. Moves sessions by the
/// step, saves the time and tells the web UI. `Err` when the system refuses.
pub async fn set(app: &App, now_ms: i64, source: Source) -> Result<(), String> {
    if !in_range(now_ms) {
        return Err("time out of range".into());
    }
    let before = clock::now_ms();
    let step = now_ms - before;
    let was_valid = is_valid();
    let from_browser = source == Source::Browser;
    if step.abs() > STEP_OVER_MS || !was_valid {
        if app.config.dev {
            return Err("the clock is not set in development mode".into());
        }
        set_system_clock(now_ms)?;
        let secs = step.div_euclid(1000);
        if secs != 0 {
            let _ = app.store.call(move |c| kaonic_store::sessions::shift(c, secs)).await;
        }
        log::info!("time: clock set from the {} ({:+} ms)", source.name(), step);
    }
    let changed_source = {
        let mut synced = SYNCED.lock().expect("time lock");
        let changed = synced.as_ref().map(|synced| &synced.source) != Some(&source);
        *synced = Some(Synced { source, at_ms: clock::now_ms() });
        changed
    };
    if step.abs() > STEP_OVER_MS || changed_source {
        save(app).await;
        app.bus.publish("system", "time.changed", view());
    }
    if !was_valid || from_browser {
        // Others that came up while we had no date get it now; a time set by hand goes out at
        // once (nodes take it from the admin, or when they have none).
        send_all(app).await;
    }
    Ok(())
}

async fn save(app: &App) {
    let secs = clock::now();
    if !in_range(secs.saturating_mul(1000)) {
        return;
    }
    let _ = app.store.call(move |c| kaonic_store::settings::set(c, LAST_KNOWN, &secs.to_string())).await;
}

fn message() -> Vec<u8> {
    let now = clock::now_ms();
    encode(now, is_valid() && in_range(now))
}

async fn send(app: &App, peer: &str) -> bool {
    let Some(links) = app.links.get() else { return false };
    let mut queue: VecDeque<Message> = [Message { kind: Kind::Control, stream: STREAM, payload: message() }].into();
    let Some(packet) = kaonic_mux::pack(&mut queue, 799).0 else { return false };
    links.send(peer, &packet).await
}

async fn send_all(app: &App) {
    let Some(links) = app.links.get().cloned() else { return };
    for peer in links.established() {
        send(app, &peer).await;
    }
}

/// Half the link's round trip, the best guess of how old a time from `peer` is.
async fn delay_ms(app: &App, peer: &str) -> i64 {
    let Some(links) = app.links.get() else { return 0 };
    links.view().await.into_iter().find(|view| view.peer == peer && view.state == "up").and_then(|view| view.rtt_ms).map_or(0, |rtt| (rtt / 2) as i64)
}

/// Saves the time now and then; on the links, sends it when a link comes up, takes it from
/// peers, and on the admin device sends it each [`ADMIN_EVERY`]. Call after `start_links`.
pub fn spawn(app: &App) {
    let save_app = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SAVE_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            if is_valid() {
                save(&save_app).await;
            }
        }
    });

    let Some(links) = app.links.get().cloned() else { return };

    let mut changes = links.changes();
    let up_app = app.clone();
    let up_links = links.clone();
    tokio::spawn(async move {
        loop {
            let peer = match changes.recv().await {
                Ok(peer) => peer,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            if up_links.established().contains(&peer) {
                send(&up_app, &peer).await;
            }
        }
    });

    let admin_app = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ADMIN_EVERY);
        loop {
            tick.tick().await;
            if is_valid() && crate::provision::is_admin_device(&admin_app).await {
                send_all(&admin_app).await;
            }
        }
    });

    let mut received = links.subscribe();
    let node_app = app.clone();
    tokio::spawn(async move {
        loop {
            let message = match received.recv().await {
                Ok(message) => message,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Ok(frames) = kaonic_mux::parse(&message.packet) else { continue };
            for frame in frames {
                if frame.kind != Kind::Control || frame.stream != STREAM {
                    continue;
                }
                let Some((theirs, theirs_valid)) = decode(frame.payload) else { continue };
                let admin = crate::api::our_admin(&node_app).await.ok().flatten();
                let from_admin = admin.as_deref() == Some(message.peer.as_str());
                let ours_valid = SYNCED.lock().expect("time lock").is_some();
                if decide(theirs_valid, from_admin, ours_valid, ntp_synced()) == Decision::Ignore {
                    continue;
                }
                let now_ms = theirs.saturating_add(delay_ms(&node_app, &message.peer).await);
                let source = if from_admin { Source::Admin } else { Source::Peer(message.peer.clone()) };
                if let Err(error) = set(&node_app, now_ms, source).await {
                    static NOTED: clock::Every = clock::Every::secs(clock::LOG_EVERY);
                    if NOTED.due() {
                        log::warn!("time: cannot take the time from {}: {error}", message.peer);
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn set_system_clock(now_ms: i64) -> Result<(), String> {
    let time = libc::timespec { tv_sec: now_ms.div_euclid(1000) as libc::time_t, tv_nsec: (now_ms.rem_euclid(1000) * 1_000_000) as libc::c_long };
    // SAFETY: a valid timespec, read only.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_system_clock(_now_ms: i64) -> Result<(), String> {
    Err("setting the clock is only supported on Linux".into())
}

/// The kernel says NTP keeps the clock (`adjtimex` does not report `TIME_ERROR`).
#[cfg(target_os = "linux")]
fn ntp_synced() -> bool {
    // SAFETY: a zeroed timex with modes 0 only reads the kernel's state.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::adjtimex(&mut timex) };
    state >= 0 && state != libc::TIME_ERROR
}

#[cfg(not(target_os = "linux"))]
fn ntp_synced() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_round_trips_on_the_wire() {
        let now = FLOOR_MS + 123_456;
        assert_eq!(decode(&encode(now, true)), Some((now, true)));
        assert_eq!(decode(&encode(now, false)), Some((now, false)));
    }

    #[test]
    fn bad_or_out_of_range_times_are_refused() {
        assert_eq!(decode(&encode(0, true)), None, "before the floor");
        assert_eq!(decode(&encode(CEILING_MS, true)), None, "past the ceiling");
        let mut long = encode(FLOOR_MS, true);
        long.push(0);
        assert_eq!(decode(&long), None);
        assert_eq!(decode(&encode(FLOOR_MS, true)[..12]), None);
        assert_eq!(decode(b"KGK1\0\0\0\0\0\0\0\0\x01"), None, "another message");
    }

    #[test]
    fn who_is_followed() {
        // A node without a valid clock takes one from anyone.
        assert_eq!(decide(true, false, false, false), Decision::Take);
        // Once valid, it follows only the admin.
        assert_eq!(decide(true, false, true, false), Decision::Ignore);
        assert_eq!(decide(true, true, true, false), Decision::Take);
        // Never a time its sender does not trust, nor over NTP.
        assert_eq!(decide(false, true, false, false), Decision::Ignore);
        assert_eq!(decide(true, true, false, true), Decision::Ignore);
    }
}
