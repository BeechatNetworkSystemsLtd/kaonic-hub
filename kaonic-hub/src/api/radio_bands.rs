//! `/radio/bands`: the four bands (two radio modules × sub-GHz and 2.4 GHz) with every
//! setting the `kaonic_rf215` driver offers, written through sysfs and saved so they come
//! back after a reboot (`kaonic_mesh::radio_config`).
//!
//! Changing the mesh band on one node cuts it off from the others, so the admin device can
//! change it on every node at once (`?scope=network`): the new configuration goes to every
//! authenticated node over its link (mux control stream 4, `KRC1`), all switch at the same
//! moment, and a node that hears nobody within a minute of switching goes back.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kaonic_mesh::radio_config::{self, BandConfig, Cca, Frontend, Modulation, Switch, SwitchStep, G24_RANGES, SUB_GHZ_RANGES};
use kaonic_mux::{Kind, Message};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};

/// The mux stream that carries network-wide radio changes.
pub const STREAM_RADIO: u8 = 4;
/// How long a network-wide change waits so every node has it before anyone switches.
const SWITCH_IN: u16 = 10;

struct Band {
    id: &'static str,
    interface: &'static str,
    module: u8,
    sub_ghz: bool,
}

const BANDS: [Band; 4] = [
    Band { id: "a_sub", interface: "rf09_a", module: 0, sub_ghz: true },
    Band { id: "a_24", interface: "rf24_a", module: 0, sub_ghz: false },
    Band { id: "b_sub", interface: "rf09_b", module: 1, sub_ghz: true },
    Band { id: "b_24", interface: "rf24_b", module: 1, sub_ghz: false },
];

fn band(id: &str) -> ApiResult<&'static Band> {
    BANDS.iter().find(|band| band.id == id).ok_or_else(|| ApiError::not_found("There is no such band."))
}

fn ranges(band: &Band) -> &'static [(u64, u64)] {
    if band.sub_ghz { &SUB_GHZ_RANGES } else { &G24_RANGES }
}

/// The band the mesh runs on (on the emulator, the band its radio stands for).
fn mesh_band(app: &App) -> Option<&'static Band> {
    let mesh = app.mesh.as_ref()?;
    let id = super::radio::band_of(mesh.radio());
    BANDS.iter().find(|band| band.id == id)
}

/// No driver behind this node's radios: the emulator. Settings are then only stored.
fn emulated(app: &App) -> bool {
    app.mesh.as_ref().is_some_and(|mesh| kaonic_mesh::radio::is_emulated(mesh.radio()))
}

fn sysfs(band: &Band) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/sys/class/net/{}/rf215", band.interface))
}

fn is_up(band: &Band) -> bool {
    let flags = std::fs::read_to_string(format!("/sys/class/net/{}/flags", band.interface)).unwrap_or_default();
    u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).is_ok_and(|flags| flags & 1 != 0)
}

fn store_key(band: &Band) -> String {
    format!("radio.band.{}", band.interface)
}

async fn stored(app: &App, band: &Band) -> Option<BandConfig> {
    let key = store_key(band);
    let text = app.store.call(move |c| kaonic_store::settings::get(c, &key)).await.ok().flatten()?;
    BandConfig::decode(&text)
}

/// What the band runs now: the driver's view, or (emulator) what was stored.
async fn current(app: &App, band: &Band) -> BandConfig {
    if !emulated(app)
        && let Ok(config) = radio_config::read(&sysfs(band), is_up(band))
    {
        return config;
    }
    stored(app, band).await.unwrap_or_else(|| BandConfig::default_for(band.sub_ghz))
}

fn ip_link(interface: &str, up: bool) -> std::io::Result<()> {
    let status = std::process::Command::new("ip").args(["link", "set", "dev", interface, if up { "up" } else { "down" }]).status()?;
    if status.success() { Ok(()) } else { Err(std::io::Error::other(format!("ip link set {interface} failed"))) }
}

/// Validates, applies to the driver (unless emulated), saves, and tells the mesh.
async fn apply(app: &App, band: &'static Band, config: BandConfig) -> ApiResult<()> {
    let problems = config.validate(ranges(band));
    if !problems.is_empty() {
        return Err(ApiError::invalid(problems));
    }
    let is_mesh = mesh_band(app).is_some_and(|mesh| std::ptr::eq(mesh, band));
    if is_mesh && config.modulation == Modulation::Off {
        return Err(ApiError::field("modulation", "The mesh runs on this band: it cannot be switched off."));
    }
    if !emulated(app) {
        let written = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<&'static str>> {
            if config.modulation == Modulation::Off {
                ip_link(band.interface, false)?;
                return Ok(Vec::new());
            }
            let written = radio_config::apply(&sysfs(band), &config)?;
            if !is_up(band) {
                ip_link(band.interface, true)?;
            }
            Ok(written)
        })
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|error| ApiError::new(StatusCode::BAD_GATEWAY, "radio_rejected", format!("The radio refused the setting: {error}.")))?;
        if !written.is_empty() {
            log::info!("radio {}: set {}", band.interface, written.join(", "));
        }
    }
    let key = store_key(band);
    let text = config.encode();
    app.store.call(move |c| kaonic_store::settings::set(c, &key, &text)).await?;
    if is_mesh && let Some(mesh) = &app.mesh {
        mesh.set_radio_settings(config.to_settings());
    }
    Ok(())
}

/// At start, before the mesh: the mesh band's saved record, applied, as the mesh sees it.
pub async fn restore_mesh_band(app: &App, interface: &str) -> Option<kaonic_mesh::settings::RadioSettings> {
    let band = BANDS.iter().find(|band| band.interface == interface)?;
    let config = stored(app, band).await?;
    if !kaonic_mesh::radio::is_emulated(interface) {
        let applied = tokio::task::spawn_blocking(move || radio_config::apply(&sysfs(band), &config)).await.ok()?;
        if let Err(error) = applied {
            log::warn!("radio {interface}: saved settings not applied: {error}");
            return None;
        }
    }
    config.to_settings()
}

/// At start: the other bands' saved records.
pub async fn restore_other_bands(app: &App) {
    for band in &BANDS {
        if mesh_band(app).is_some_and(|mesh| std::ptr::eq(mesh, band)) {
            continue;
        }
        if let Some(config) = stored(app, band).await
            && let Err(error) = apply(app, band, config).await
        {
            log::warn!("radio {}: saved settings not applied: {}", band.interface, error.message);
        }
    }
}

/* ── the API's view ── */

const CHIP_RATES_KHZ: [u32; 4] = [100, 200, 1000, 2000];
const FSK_SYMBOL_RATES_KHZ: [u32; 6] = [50, 100, 150, 200, 300, 400];
const FSK_MODULATION_INDEX: [f64; 8] = [0.375, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0];
const FSK_BT: [f64; 4] = [0.5, 1.0, 1.5, 2.0];

fn modulation_view(modulation: Modulation) -> Value {
    match modulation {
        Modulation::Off => json!({ "kind": "off" }),
        Modulation::Ofdm { mcs, opt } => json!({ "kind": "ofdm", "mcs": mcs, "option": opt + 1 }),
        Modulation::Qpsk { fchip, mode } => json!({ "kind": "qpsk", "chip_rate_khz": CHIP_RATES_KHZ.get(fchip as usize), "rate_mode": mode }),
        Modulation::Fsk { srate, midx, mord, bt, fec, dw, preamble } => json!({
            "kind": "fsk",
            "symbol_rate_khz": FSK_SYMBOL_RATES_KHZ.get(srate as usize),
            "modulation_index": FSK_MODULATION_INDEX.get(midx as usize),
            "order": if mord == 1 { 4 } else { 2 },
            "bt": FSK_BT.get(bt as usize),
            "fec": fec,
            "whitening": dw,
            "preamble": preamble,
        }),
    }
}

fn config_view(config: &BandConfig) -> Value {
    json!({
        "frequency_hz": config.frequency_hz,
        "channel_spacing_hz": config.channel_spacing_hz,
        "channel": config.channel,
        "modulation": modulation_view(config.modulation),
        "tx_power": config.tx_power,
        "fcs": config.fcs,
        "cca": {
            "enabled": config.cca.enabled,
            "threshold_dbm": config.cca.threshold_dbm,
            "listen_us": config.cca.listen_us,
            "retries": config.cca.retries,
            "backoff_us": config.cca.backoff_us,
        },
        "frontend": { "agc_map": config.frontend.agc_map, "agc_target": config.frontend.agc_target, "lna_bypass": config.frontend.lna_bypass },
    })
}

/// A network-wide change waiting or in its confirmation minute.
struct Pending {
    band: &'static Band,
    switch: Switch,
    at_ts_ms: i64,
    switched_unix: Option<i64>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

async fn band_view(app: &App, band: &'static Band) -> Value {
    let config = current(app, band).await;
    let is_mesh = mesh_band(app).is_some_and(|mesh| std::ptr::eq(mesh, band));
    let mut used_by = Vec::new();
    if is_mesh {
        used_by.push("mesh");
        if app.vpn.get().is_some() {
            used_by.push("vpn");
        }
        if app.ptt_group.get().is_some() {
            used_by.push("ptt");
        }
    }
    let ranges = ranges(band);
    let state = std::fs::read_to_string(sysfs(band).join("state")).map(|state| state.trim().to_owned()).ok();
    let pending = PENDING.lock().expect("radio pending lock").as_ref().filter(|pending| std::ptr::eq(pending.band, band)).map(|pending| {
        json!({ "at_ts_ms": pending.at_ts_ms, "switched": pending.switched_unix.is_some(), "config": config_view(&pending.switch.next) })
    });
    json!({
        "id": band.id,
        "module": band.module,
        "range": if band.sub_ghz { "sub_ghz" } else { "2g4" },
        "min_hz": ranges.first().map(|range| range.0),
        "max_hz": ranges.last().map(|range| range.1),
        "ranges_hz": ranges.iter().map(|(low, high)| [low, high]).collect::<Vec<_>>(),
        "interface": band.interface,
        "state": if emulated(app) { Some("emulated".to_owned()) } else { state },
        "config": config_view(&config),
        "used_by": used_by,
        "last_rssi": if is_mesh { app.mesh.as_ref().and_then(|mesh| mesh.counters().last_rssi) } else { None },
        "capabilities": ["fcs", "cca", "frontend", "fsk", "qpsk", "off"],
        "pending_switch": pending,
    })
}

/// `GET /radio/bands`
pub async fn list(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let mut views = Vec::new();
    for band in &BANDS {
        views.push(band_view(&app, band).await);
    }
    Ok(no_store(axum::Json(views)))
}

/// `GET /radio/bands/{band}`
pub async fn get(State(app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    Ok(no_store(axum::Json(band_view(&app, band(&id)?).await)))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModulationInput {
    Off,
    Ofdm { mcs: u8, option: u8 },
    Qpsk { chip_rate_khz: u32, rate_mode: u8 },
    Fsk {
        symbol_rate_khz: Option<u32>,
        modulation_index: Option<f64>,
        order: Option<u8>,
        bt: Option<f64>,
        fec: Option<bool>,
        whitening: Option<bool>,
        preamble: Option<u16>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CcaInput {
    enabled: bool,
    threshold_dbm: i8,
    listen_us: u32,
    retries: u8,
    backoff_us: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendInput {
    agc_map: u8,
    agc_target: u8,
    lna_bypass: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigInput {
    frequency_hz: u64,
    channel_spacing_hz: u32,
    channel: u16,
    modulation: ModulationInput,
    tx_power: u8,
    fcs: Option<bool>,
    cca: Option<CcaInput>,
    frontend: Option<FrontendInput>,
}

fn index_of<T: PartialEq + Copy>(table: &[T], value: Option<T>, current: u8, field: &'static str) -> ApiResult<u8> {
    match value {
        None => Ok(current),
        Some(value) => table.iter().position(|entry| *entry == value).map(|index| index as u8).ok_or_else(|| ApiError::field(field, "Not a value this radio supports.")),
    }
}

/// The input over what the band runs now (fields left out keep their value).
fn merge(input: ConfigInput, now: &BandConfig) -> ApiResult<BandConfig> {
    let modulation = match input.modulation {
        ModulationInput::Off => Modulation::Off,
        ModulationInput::Ofdm { mcs, option } => {
            if !(1..=4).contains(&option) {
                return Err(ApiError::field("modulation.option", "Use option 1 to 4."));
            }
            Modulation::Ofdm { mcs, opt: option - 1 }
        }
        ModulationInput::Qpsk { chip_rate_khz, rate_mode } => {
            Modulation::Qpsk { fchip: index_of(&CHIP_RATES_KHZ, Some(chip_rate_khz), 0, "modulation.chip_rate_khz")?, mode: rate_mode }
        }
        ModulationInput::Fsk { symbol_rate_khz, modulation_index, order, bt, fec, whitening, preamble } => {
            let base = match now.modulation {
                Modulation::Fsk { srate, midx, mord, bt, fec, dw, preamble } => (srate, midx, mord, bt, fec, dw, preamble),
                _ => (3, 3, 0, 0, false, true, 8),
            };
            Modulation::Fsk {
                srate: index_of(&FSK_SYMBOL_RATES_KHZ, symbol_rate_khz, base.0, "modulation.symbol_rate_khz")?,
                midx: index_of(&FSK_MODULATION_INDEX, modulation_index, base.1, "modulation.modulation_index")?,
                mord: match order {
                    None => base.2,
                    Some(2) => 0,
                    Some(4) => 1,
                    Some(_) => return Err(ApiError::field("modulation.order", "Use 2 or 4.")),
                },
                bt: index_of(&FSK_BT, bt, base.3, "modulation.bt")?,
                fec: fec.unwrap_or(base.4),
                dw: whitening.unwrap_or(base.5),
                preamble: preamble.unwrap_or(base.6),
            }
        }
    };
    Ok(BandConfig {
        frequency_hz: input.frequency_hz,
        channel: input.channel,
        channel_spacing_hz: input.channel_spacing_hz,
        modulation,
        tx_power: input.tx_power,
        fcs: input.fcs.unwrap_or(now.fcs),
        cca: input.cca.map_or(now.cca, |cca| Cca { enabled: cca.enabled, threshold_dbm: cca.threshold_dbm, listen_us: cca.listen_us, retries: cca.retries, backoff_us: cca.backoff_us }),
        frontend: input.frontend.map_or(now.frontend, |frontend| Frontend { agc_map: frontend.agc_map, agc_target: frontend.agc_target, lna_bypass: frontend.lna_bypass }),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeQuery {
    scope: Option<String>,
}

#[derive(Serialize)]
struct SwitchView {
    switch_at_ts_ms: i64,
    nodes: usize,
}

/// `PUT /radio/bands/{band}[?scope=network]`
pub async fn put(State(app): State<App>, Admin(_): Admin, Path(id): Path<String>, Query(query): Query<ScopeQuery>, Json(input): Json<ConfigInput>) -> ApiResult<Response> {
    let band = band(&id)?;
    let now = current(&app, band).await;
    let config = merge(input, &now)?;
    match query.scope.as_deref() {
        None | Some("node") => Ok(no_store(axum::Json(apply_here(&app, band, now, config).await?))),
        Some("network") => {
            if !mesh_band(&app).is_some_and(|mesh| std::ptr::eq(mesh, band)) {
                return Err(ApiError::field("scope", "Only the mesh band is changed on every node; set other bands per node."));
            }
            if !crate::provision::is_admin_device(&app).await {
                return Err(ApiError::forbidden("not_admin_device", "Only the Kaonic Admin device can change the radio of every node."));
            }
            let problems = config.validate(ranges(band));
            if !problems.is_empty() {
                return Err(ApiError::invalid(problems));
            }
            if config.modulation == Modulation::Off {
                return Err(ApiError::field("modulation", "The mesh band cannot be switched off."));
            }
            let message = radio_config::encode_switch(SWITCH_IN, &config);
            let mut queue = std::collections::VecDeque::from([Message { kind: Kind::Control, stream: STREAM_RADIO, payload: message }]);
            let (Some(packet), _) = kaonic_mux::pack(&mut queue, 799) else { return Err(ApiError::internal()) };
            let mut nodes = 0;
            if let Some(links) = app.links.get() {
                for peer in links.established() {
                    if links.send(&peer, &packet).await {
                        nodes += 1;
                    }
                }
            }
            let at_ts_ms = schedule(band, now, config);
            log::info!("radio: the mesh band changes on {nodes} node(s) and here in {SWITCH_IN} s");
            let audit_detail = format!("{} on {nodes} node(s)", band.interface);
            let stamp = crate::clock::now();
            let _ = app.store.call(move |c| kaonic_store::audit::record(c, stamp, "admin", "radio.switch", &audit_detail)).await;
            Ok((StatusCode::ACCEPTED, no_store(axum::Json(SwitchView { switch_at_ts_ms: at_ts_ms, nodes }))).into_response())
        }
        Some(_) => Err(ApiError::field("scope", "Use node or network.")),
    }
}

/// Applies a configuration on this node only and returns the band as the API shows it.
async fn apply_here(app: &App, band: &'static Band, now: BandConfig, config: BandConfig) -> ApiResult<Value> {
    // Moving only this node off the mesh band cuts it off from nodes it could hear: like a
    // network switch, it goes back if no node is heard on the new band within a minute.
    let is_mesh = mesh_band(app).is_some_and(|mesh| std::ptr::eq(mesh, band));
    let had_peers = app.mesh.as_ref().is_some_and(|mesh| mesh.peers().iter().any(|peer| mesh.is_online(peer)));
    apply(app, band, config).await?;
    if is_mesh && had_peers && config != now {
        let switch = Switch::applied(now, config, Instant::now());
        *PENDING.lock().expect("radio pending lock") = Some(Pending { band, switch, at_ts_ms: crate::clock::now_ms(), switched_unix: Some(crate::clock::now()) });
        log::info!("radio: mesh band changed on this node only; going back in a minute unless a node is heard");
    }
    Ok(band_view(app, band).await)
}

/// A band change ordered by the admin over the mesh (`remote`): same rules as `PUT` on this node.
pub(crate) async fn apply_remote(app: &App, band_id: &str, input: serde_json::Value) -> ApiResult<Value> {
    let band = band(band_id)?;
    let input: ConfigInput = serde_json::from_value(input).map_err(|error| ApiError::bad_request(format!("The radio settings are not valid: {error}.")))?;
    let now = current(app, band).await;
    let config = merge(input, &now)?;
    apply_here(app, band, now, config).await
}

/// Every band as the API shows it (for the admin's view of a remote node).
pub(crate) async fn all_bands(app: &App) -> Vec<Value> {
    let mut bands = Vec::new();
    for band in &BANDS {
        bands.push(band_view(app, band).await);
    }
    bands
}

fn schedule(band: &'static Band, previous: BandConfig, next: BandConfig) -> i64 {
    let at = Instant::now() + Duration::from_secs(u64::from(SWITCH_IN));
    let at_ts_ms = crate::clock::now_ms() + i64::from(SWITCH_IN) * 1000;
    *PENDING.lock().expect("radio pending lock") = Some(Pending { band, switch: Switch::new(previous, next, at), at_ts_ms, switched_unix: None });
    at_ts_ms
}

/// Network-wide changes arriving from the admin, and the pending change's clock.
pub fn spawn(app: App) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut received = app.links.get().map(|links| links.subscribe());
        loop {
            tokio::select! {
                message = async {
                    match &mut received {
                        Some(received) => received.recv().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(message) = message {
                        on_message(&app, &message.peer, &message.packet).await;
                    }
                }
                _ = tick.tick() => {
                    if received.is_none() {
                        received = app.links.get().map(|links| links.subscribe());
                    }
                    step(&app).await;
                }
            }
        }
    });
}

async fn on_message(app: &App, peer: &str, packet: &[u8]) {
    let Ok(frames) = kaonic_mux::parse(packet) else { return };
    for frame in frames {
        if frame.kind != Kind::Control || frame.stream != STREAM_RADIO {
            continue;
        }
        // Only our admin may change the radio of this node.
        if crate::api::our_admin(app).await.ok().flatten().as_deref() != Some(peer) {
            static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
            if NOTED.due() {
                log::warn!("radio: ignored a radio change from {peer}, which is not our admin");
            } else {
                log::debug!("radio: ignored a radio change from {peer}, which is not our admin");
            }
            continue;
        }
        let Some((in_secs, config)) = radio_config::decode_switch(frame.payload) else { continue };
        let Some(band) = mesh_band(app) else { continue };
        if !config.validate(ranges(band)).is_empty() || config.modulation == Modulation::Off {
            log::warn!("radio: ignored an invalid radio change from the admin");
            continue;
        }
        let previous = current(app, band).await;
        let at = Instant::now() + Duration::from_secs(u64::from(in_secs.min(60)));
        let at_ts_ms = crate::clock::now_ms() + i64::from(in_secs.min(60)) * 1000;
        *PENDING.lock().expect("radio pending lock") = Some(Pending { band, switch: Switch::new(previous, config, at), at_ts_ms, switched_unix: None });
        log::info!("radio: the admin changes the mesh band in {in_secs} s");
    }
}

async fn step(app: &App) {
    let action = {
        let mut pending = PENDING.lock().expect("radio pending lock");
        let Some(current) = pending.as_mut() else { return };
        // Heard: any node announced after we switched.
        let heard = current.switched_unix.is_some_and(|switched| app.mesh.as_ref().is_some_and(|mesh| mesh.peers().iter().any(|peer| peer.last_seen > switched)));
        let step = current.switch.tick(Instant::now(), heard.then(Instant::now));
        if matches!(step, SwitchStep::Apply(_)) {
            current.switched_unix = Some(crate::clock::now());
        }
        if matches!(step, SwitchStep::Keep | SwitchStep::Revert(_)) {
            let band = current.band;
            *pending = None;
            Some((band, step))
        } else {
            Some((current.band, step))
        }
    };
    let Some((band, step)) = action else { return };
    match step {
        SwitchStep::Wait | SwitchStep::Keep => {
            if step == SwitchStep::Keep {
                log::info!("radio: the new mesh band works, keeping it");
            }
        }
        SwitchStep::Apply(config) => {
            log::info!("radio: switching the mesh band now");
            if let Err(error) = apply(app, band, config).await {
                log::warn!("radio: switching failed: {}", error.message);
            }
        }
        SwitchStep::Revert(config) => {
            log::warn!("radio: nobody heard on the new mesh band within a minute, going back");
            if let Err(error) = apply(app, band, config).await {
                log::warn!("radio: going back failed: {}", error.message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(json: &str) -> ConfigInput {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn input_maps_onto_driver_indices_and_keeps_what_it_leaves_out() {
        let now = BandConfig::default_for(true);
        let ofdm = merge(input(r#"{"frequency_hz":868000000,"channel_spacing_hz":200000,"channel":0,"modulation":{"kind":"ofdm","mcs":3,"option":2},"tx_power":12}"#), &now).unwrap();
        assert_eq!(ofdm.modulation, Modulation::Ofdm { mcs: 3, opt: 1 });
        assert_eq!(ofdm.cca, now.cca);
        let qpsk = merge(input(r#"{"frequency_hz":868000000,"channel_spacing_hz":200000,"channel":0,"modulation":{"kind":"qpsk","chip_rate_khz":1000,"rate_mode":2},"tx_power":12,"fcs":true}"#), &now).unwrap();
        assert_eq!(qpsk.modulation, Modulation::Qpsk { fchip: 2, mode: 2 });
        assert!(qpsk.fcs);
        let fsk = merge(input(r#"{"frequency_hz":868000000,"channel_spacing_hz":200000,"channel":0,"modulation":{"kind":"fsk","symbol_rate_khz":100,"modulation_index":1.0,"order":4,"bt":2.0,"whitening":false},"tx_power":12,"cca":{"enabled":false,"threshold_dbm":-90,"listen_us":0,"retries":10,"backoff_us":300}}"#), &now).unwrap();
        assert_eq!(fsk.modulation, Modulation::Fsk { srate: 1, midx: 3, mord: 1, bt: 3, fec: false, dw: false, preamble: 8 });
        assert_eq!(fsk.cca.threshold_dbm, -90);
        assert!(merge(input(r#"{"frequency_hz":1,"channel_spacing_hz":1,"channel":0,"modulation":{"kind":"qpsk","chip_rate_khz":300,"rate_mode":0},"tx_power":1}"#), &now).is_err());
        assert!(merge(input(r#"{"frequency_hz":1,"channel_spacing_hz":1,"channel":0,"modulation":{"kind":"ofdm","mcs":1,"option":5},"tx_power":1}"#), &now).is_err());
        assert!(serde_json::from_str::<ConfigInput>(r#"{"frequency_hz":1,"channel_spacing_hz":1,"channel":0,"modulation":{"kind":"off"},"tx_power":1,"bogus":1}"#).is_err());
    }

    #[test]
    fn views_name_the_radio_values() {
        let view = modulation_view(Modulation::Fsk { srate: 1, midx: 3, mord: 1, bt: 3, fec: true, dw: false, preamble: 8 });
        assert_eq!(view["symbol_rate_khz"], 100);
        assert_eq!(view["order"], 4);
        assert_eq!(view["bt"], 2.0);
        assert_eq!(modulation_view(Modulation::Ofdm { mcs: 6, opt: 0 })["option"], 1);
        assert_eq!(modulation_view(Modulation::Qpsk { fchip: 3, mode: 1 })["chip_rate_khz"], 2000);
    }
}
