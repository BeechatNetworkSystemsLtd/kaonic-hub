//! `/vpn` and `/vpn/packets`: the mesh VPN (`kaonic_vpn`) as the contract shows it. Rates are
//! per second over the last 2 s sample, taken with the radio's (`radio::spawn_producers`).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{Query, State};
use axum::response::Response;
use kaonic_mesh::announce::Announced;
use kaonic_vpn::capture::Verdict;
use kaonic_vpn::service::{Counters, Direction};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};

/// Bits per second (rx, tx), in total and per peer, from the last two samples.
#[derive(Default)]
struct Rates {
    last: Option<(Instant, Counters, HashMap<String, Counters>)>,
    total: (u64, u64),
    peers: HashMap<String, (u64, u64)>,
}

static RATES: Mutex<Option<Rates>> = Mutex::new(None);

fn per_second(now: &Counters, before: &Counters, elapsed_ms: u64) -> (u64, u64) {
    let rate = |now: u64, before: u64| now.saturating_sub(before) * 8 * 1000 / elapsed_ms.max(1);
    (rate(now.rx_bytes, before.rx_bytes), rate(now.tx_bytes, before.tx_bytes))
}

/// Takes a sample; returns the total (rx, tx) bits per second.
pub fn sample(app: &App) -> (u64, u64) {
    let Some(vpn) = app.vpn.get() else { return (0, 0) };
    let status = vpn.status();
    let peers: HashMap<String, Counters> = status.peers.iter().map(|peer| (peer.peer.clone(), peer.counters)).collect();
    let now = Instant::now();
    let mut rates = RATES.lock().expect("vpn rates lock");
    let rates = rates.get_or_insert_with(Rates::default);
    if let Some((then, total, before)) = &rates.last {
        let elapsed_ms = now.duration_since(*then).as_millis() as u64;
        rates.total = per_second(&status.counters, total, elapsed_ms);
        rates.peers = peers.iter().map(|(peer, counters)| (peer.clone(), per_second(counters, before.get(peer).unwrap_or(&Counters::default()), elapsed_ms))).collect();
    }
    rates.last = Some((now, status.counters, peers));
    rates.total
}

fn counters(counters: &Counters, (rx_bps, tx_bps): (u64, u64)) -> Value {
    json!({
        "tx_packets": counters.tx_packets,
        "tx_bytes": counters.tx_bytes,
        "tx_bps": tx_bps,
        "rx_packets": counters.rx_packets,
        "rx_bytes": counters.rx_bytes,
        "rx_bps": rx_bps,
        "dropped": counters.dropped,
        "last_tx_ts": counters.last_tx_ms.map(|ms| ms / 1000),
        "last_rx_ts": counters.last_rx_ms.map(|ms| ms / 1000),
    })
}

/// The VPN as `GET /vpn` and the `vpn` topic show it.
pub fn state(app: &App) -> Value {
    let enabled = app.vpn_config.is_some();
    let off = json!({ "enabled": false, "active": false, "peer_id": null, "routes": [], "default_route": false, "detail": null });
    let gateway = json!({ "enabled": false, "active": false, "egress_interface": null, "routes": [], "available_interfaces": [], "detail": null });
    let Some(vpn) = app.vpn.get() else {
        return json!({
            "enabled": enabled,
            "status": if enabled { "error" } else { "stopped" },
            "interface": null,
            "network": app.vpn_config.as_ref().map(|config| config.network.to_string()),
            "tunnel_ip": null,
            "routes": { "advertised": [], "local_mappings": [], "remote": [] },
            "access": { "allow_all_peers": true, "peers": [] },
            "uplink": off,
            "gateway": gateway,
            "counters": counters(&Counters::default(), (0, 0)),
            "peers": [],
            "last_error": app.vpn_error.get().cloned().or_else(|| enabled.then(|| "The VPN needs the radio and a provisioned device.".to_owned())),
        });
    };
    let status = vpn.status();
    let rates = RATES.lock().expect("vpn rates lock");
    let rates = rates.as_ref();
    let codenames: HashMap<String, String> = app
        .mesh
        .as_ref()
        .map(|mesh| mesh.peers().into_iter().filter_map(|peer| match peer.announced { Announced::Hub(info) => Some((peer.id, info.codename)), _ => None }).collect())
        .unwrap_or_default();
    let last_seen: HashMap<String, i64> = app.mesh.as_ref().map(|mesh| mesh.peers().into_iter().map(|peer| (peer.id, peer.last_seen)).collect()).unwrap_or_default();
    let remote: Vec<Value> = status
        .remote
        .iter()
        .map(|route| {
            json!({
                "network": route.prefix.to_string(),
                "peer_id": route.peer,
                // Refused: a prefix this node will never route (too short, the tunnel network, ours…).
                // Conflict: two nodes advertise overlapping prefixes, so neither is routed.
                "status": match (route.conflict, route.reason) {
                    (false, _) => "active",
                    (true, None | Some("overlaps a prefix of another node")) => "conflict",
                    (true, Some(_)) => "refused",
                },
                "reason": route.reason,
                "installed": status.installed.contains(&route.prefix),
                "last_seen_ts": last_seen.get(&route.peer).copied().unwrap_or(0),
            })
        })
        .collect();
    let peers: Vec<Value> = status
        .peers
        .iter()
        .map(|peer| {
            json!({
                "peer_id": peer.peer,
                "codename": codenames.get(&peer.peer).cloned().unwrap_or_default(),
                "tag": "",
                "tunnel_ip": peer.tunnel.map(|address| address.to_string()),
                "state": peer.state,
                "is_gateway": status.gateways.iter().any(|(gateway, _)| gateway == &peer.peer),
                "routes": peer.advertised.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "counters": counters(&peer.counters, rates.and_then(|rates| rates.peers.get(&peer.peer).copied()).unwrap_or((0, 0))),
                "last_error": null,
            })
        })
        .collect();
    json!({
        "enabled": true,
        "status": "running",
        "interface": status.interface,
        "network": status.network.to_string(),
        "tunnel_ip": status.tunnel.to_string(),
        "routes": {
            "advertised": status.advertised.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "local_mappings": status.lans.iter().map(|lan| json!({ "subnet": lan.subnet.to_string(), "mapped_subnet": lan.mapped.to_string(), "interface": lan.interface, "address": lan.address.map(|address| address.to_string()), "setup_subnet": lan.base.map(|base| base.to_string()) })).collect::<Vec<_>>(),
            "remote": remote,
        },
        "access": { "allow_all_peers": true, "peers": [] },
        "uplink": {
            "enabled": status.uplink.settings.enabled,
            "active": status.uplink.active,
            "peer_id": status.uplink.peer.clone().or(status.uplink.settings.peer.clone()),
            "routes": cidrs(if status.uplink.active { &status.uplink.routes } else { &status.uplink.settings.routes }),
            "default_route": status.uplink.settings.default_route,
            "detail": status.uplink.detail,
            "gateways": status.gateways.iter().map(|(peer, routes)| json!({ "peer_id": peer, "codename": codenames.get(peer).cloned().unwrap_or_default(), "routes": cidrs(routes) })).collect::<Vec<_>>(),
        },
        "gateway": {
            "enabled": status.gateway.settings.enabled,
            "active": status.gateway.active,
            "egress_interface": status.gateway.egress.clone().or(status.gateway.settings.egress_interface.clone()),
            "routes": cidrs(&status.gateway.settings.routes),
            "available_interfaces": status.gateway.available_interfaces,
            "detail": status.gateway.detail,
        },
        "settings": share_json(&status.share),
        "forward": super::forward::view(&vpn.forward_status(), true, app.vpn_config.as_ref().map(|config| (config.limits.flood_rate, config.limits.flood_burst))),
        "counters": counters(&status.counters, rates.map_or((0, 0), |rates| rates.total)),
        "peers": peers,
        "last_error": status.last_error,
    })
}

/// `GET /vpn`
pub async fn get(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(state(&app))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketsQuery {
    limit: Option<usize>,
}

/// `GET /vpn/packets`: the last tunnel packets, newest first. Headers only.
pub async fn packets(State(app): State<App>, _: Viewer, Query(query): Query<PacketsQuery>) -> ApiResult<Response> {
    let limit = query.limit.unwrap_or(64);
    if !(1..=256).contains(&limit) {
        return Err(ApiError::field("limit", "Use 1 to 256."));
    }
    let packets: Vec<Value> = app
        .vpn
        .get()
        .map(|vpn| {
            vpn.packets(limit)
                .into_iter()
                .map(|packet| {
                    json!({
                        "ts_ms": packet.ts_ms,
                        "dir": match packet.direction { Direction::Tx => "tx", Direction::Rx => "rx" },
                        "src": packet.summary.src.to_string(),
                        "dst": packet.summary.dst.to_string(),
                        "proto": packet.summary.proto_name(),
                        "sport": packet.summary.ports.map(|(source, _)| source),
                        "dport": packet.summary.ports.map(|(_, destination)| destination),
                        "len": packet.summary.len,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(no_store(axum::Json(packets)))
}

/* ── packet capture (the VPN page's Wireshark view) ── */

fn vpn_of(app: &App) -> ApiResult<&std::sync::Arc<kaonic_vpn::Vpn>> {
    app.vpn.get().ok_or_else(|| ApiError::unavailable("vpn_unavailable", "The VPN is not running on this device."))
}

fn capture_view(state: &kaonic_vpn::capture::CaptureState) -> Value {
    json!({
        "running": state.running,
        "started_ts_ms": state.started_ts_ms,
        "stopped_ts_ms": state.stopped_ts_ms,
        "snaplen": state.config.snaplen,
        "max_packets": state.config.max_packets,
        "max_secs": state.config.max_secs,
        "ring": state.config.ring,
        "packets": state.packets,
        "dropped": state.dropped,
        "bytes": state.bytes,
        "first_seq": state.first_seq,
        "last_seq": state.last_seq,
    })
}

async fn audit(app: &App, action: &'static str, detail: String) {
    let now = crate::clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail)).await;
}

/// `GET /vpn/capture`
pub async fn capture_state(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    Ok(no_store(axum::Json(capture_view(&vpn_of(&app)?.capture.state()))))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureBody {
    snaplen: Option<usize>,
    max_packets: Option<usize>,
    max_secs: Option<u64>,
    ring: Option<bool>,
}

/// `POST /vpn/capture`: starts a new capture with the settings clamped to the memory cap.
pub async fn capture_start(State(app): State<App>, _: Admin, Json(body): Json<CaptureBody>) -> ApiResult<Response> {
    let vpn = vpn_of(&app)?;
    let defaults = kaonic_vpn::capture::CaptureConfig::default();
    if body.snaplen.is_some_and(|snaplen| !(64..=1500).contains(&snaplen)) {
        return Err(ApiError::field("snaplen", "Use 64 to 1500."));
    }
    if body.max_packets.is_some_and(|max| !(100..=20_000).contains(&max)) {
        return Err(ApiError::field("max_packets", "Use 100 to 20000."));
    }
    if body.max_secs.is_some_and(|secs| !(10..=3600).contains(&secs)) {
        return Err(ApiError::field("max_secs", "Use 10 to 3600."));
    }
    let config = kaonic_vpn::capture::CaptureConfig {
        snaplen: body.snaplen.unwrap_or(defaults.snaplen),
        max_packets: body.max_packets.unwrap_or(defaults.max_packets),
        max_secs: body.max_secs.unwrap_or(defaults.max_secs),
        ring: body.ring.unwrap_or(defaults.ring),
    };
    let state = vpn.capture.start(config);
    audit(&app, "vpn.capture.start", format!("snaplen {} max_packets {} max_secs {}", state.config.snaplen, state.config.max_packets, state.config.max_secs)).await;
    Ok(no_store(axum::Json(capture_view(&state))))
}

/// `POST /vpn/capture/stop`
pub async fn capture_stop(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    let state = vpn_of(&app)?.capture.stop();
    audit(&app, "vpn.capture.stop", format!("{} packets", state.packets)).await;
    Ok(no_store(axum::Json(capture_view(&state))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePacketsQuery {
    after: Option<u64>,
    limit: Option<usize>,
}

/// `GET /vpn/capture/packets?after&limit`: oldest first, bytes as base64.
pub async fn capture_packets(State(app): State<App>, _: Admin, Query(query): Query<CapturePacketsQuery>) -> ApiResult<Response> {
    let vpn = vpn_of(&app)?;
    let limit = query.limit.unwrap_or(500);
    if !(1..=1000).contains(&limit) {
        return Err(ApiError::field("limit", "Use 1 to 1000."));
    }
    let codenames: HashMap<String, String> = app
        .mesh
        .as_ref()
        .map(|mesh| mesh.peers().into_iter().filter_map(|peer| match peer.announced { Announced::Hub(info) => Some((peer.id, info.codename)), _ => None }).collect())
        .unwrap_or_default();
    let packets: Vec<Value> = vpn
        .capture
        .packets(query.after.unwrap_or(0), limit)
        .into_iter()
        .map(|packet| {
            json!({
                "seq": packet.seq,
                "ts_us": packet.ts_us,
                "dir": match packet.direction { Direction::Tx => "tx", Direction::Rx => "rx" },
                "peer_codename": packet.peer.as_ref().and_then(|peer| codenames.get(peer).cloned()),
                "peer_id": packet.peer,
                "flood": packet.flood,
                "len": packet.len,
                "data": kaonic_hub_common::base64::encode(&packet.data),
                "verdict": match packet.verdict { Verdict::Sent => "sent", Verdict::Delivered => "delivered", Verdict::Dropped => "dropped" },
                "reason": packet.reason,
            })
        })
        .collect();
    Ok(no_store(axum::Json(packets)))
}

/// `GET /vpn/capture.pcap`: the capture as a file Wireshark opens.
pub async fn capture_pcap(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    let vpn = vpn_of(&app)?;
    let mut file = Vec::new();
    vpn.capture.write_pcap(&mut file).map_err(|_| ApiError::internal())?;
    let codename = crate::api::node_info(&app).await.map(|info| info.codename).unwrap_or_default();
    let codename: String = codename.chars().filter(char::is_ascii_alphanumeric).collect();
    let disposition = format!("attachment; filename=\"kaonic-{}-{}.pcap\"", if codename.is_empty() { "node" } else { &codename }, crate::clock::now());
    let mut response = no_store((
        [(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/vnd.tcpdump.pcap"))],
        file,
    ));
    if let Ok(value) = axum::http::HeaderValue::from_str(&disposition) {
        response.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

/* ── sharing with end clients: settings, routes, uplink, gateway ── */

use kaonic_vpn::ip::Cidr;
use kaonic_vpn::share::{LanRouter, ShareSettings};

const SHARE_KEY: &str = "vpn.share";

fn cidrs(prefixes: &[Cidr]) -> Vec<String> {
    prefixes.iter().map(ToString::to_string).collect()
}

/// The sharing settings as stored and as `/vpn` shows them.
pub fn share_json(share: &ShareSettings) -> Value {
    json!({
        "share_lans": share.share_lans,
        "lan_interfaces": share.lan_interfaces,
        "map_lans": share.map_lans,
        "route_lans": share.route_lans,
        "mapping_pool": share.mapping_pool.to_string(),
        "push_routes": share.push_routes,
        "lan_router": share.lan_router.as_str(),
        "dns_servers": share.dns_servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "advertise": cidrs(&share.advertise),
        "gateway": { "enabled": share.gateway.enabled, "egress_interface": share.gateway.egress_interface, "routes": cidrs(&share.gateway.routes) },
        "uplink": { "enabled": share.uplink.enabled, "peer_id": share.uplink.peer, "default_route": share.uplink.default_route, "routes": cidrs(&share.uplink.routes) },
    })
}

fn parse_cidrs(value: Option<&Value>) -> Option<Vec<Cidr>> {
    value?.as_array()?.iter().map(|item| item.as_str()?.parse().ok()).collect()
}

/// Settings stored earlier, laid over `share` (fields that do not parse keep their default).
fn share_from_json(mut share: ShareSettings, value: &Value) -> ShareSettings {
    if let Some(on) = value["share_lans"].as_bool() {
        share.share_lans = on;
    }
    if let Some(names) = value["lan_interfaces"].as_array() {
        share.lan_interfaces = names.iter().filter_map(|name| name.as_str().map(str::to_owned)).collect();
    }
    if let Some(on) = value["map_lans"].as_bool() {
        share.map_lans = on;
    }
    if let Some(on) = value["route_lans"].as_bool() {
        share.route_lans = on;
    }
    if let Some(pool) = value["mapping_pool"].as_str().and_then(|text| text.parse().ok()) {
        share.mapping_pool = pool;
    }
    if let Some(on) = value["push_routes"].as_bool() {
        share.push_routes = on;
    }
    if let Some(router) = value["lan_router"].as_str().and_then(LanRouter::parse) {
        share.lan_router = router;
    }
    if let Some(dns) = value["dns_servers"].as_array() {
        share.dns_servers = dns.iter().filter_map(|server| server.as_str()?.parse().ok()).collect();
    }
    if let Some(advertise) = parse_cidrs(value.get("advertise")) {
        share.advertise = advertise;
    }
    let gateway = &value["gateway"];
    if let Some(on) = gateway["enabled"].as_bool() {
        share.gateway.enabled = on;
    }
    share.gateway.egress_interface = gateway["egress_interface"].as_str().map(str::to_owned).or(share.gateway.egress_interface);
    if let Some(routes) = parse_cidrs(gateway.get("routes")) {
        share.gateway.routes = routes;
    }
    let uplink = &value["uplink"];
    if let Some(on) = uplink["enabled"].as_bool() {
        share.uplink.enabled = on;
    }
    share.uplink.peer = uplink["peer_id"].as_str().map(str::to_owned).or(share.uplink.peer);
    if let Some(on) = uplink["default_route"].as_bool() {
        share.uplink.default_route = on;
    }
    if let Some(routes) = parse_cidrs(uplink.get("routes")) {
        share.uplink.routes = routes;
    }
    share
}

/// The VPN's start-up config with the sharing settings and forwarding rules saved by the API.
pub async fn with_stored_share(app: &App, mut config: kaonic_vpn::VpnConfig) -> kaonic_vpn::VpnConfig {
    let stored = app.store.call(|c| kaonic_store::settings::get(c, SHARE_KEY)).await.ok().flatten();
    if let Some(value) = stored.as_deref().and_then(|text| serde_json::from_str::<Value>(text).ok()) {
        config.share = share_from_json(config.share, &value);
    }
    config.forward = super::forward::stored(app).await;
    config
}

async fn save_and_apply(app: &App, share: ShareSettings) -> ApiResult<()> {
    let text = share_json(&share).to_string();
    app.store.call(move |c| kaonic_store::settings::set(c, SHARE_KEY, &text)).await?;
    vpn_of(app)?.set_share(share).await;
    Ok(())
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// A prefix this node may advertise or route through a gateway.
fn check_prefix(app: &App, field: &'static str, prefix: &Cidr, allow_default: bool) -> ApiResult<()> {
    let network = app.vpn_config.as_ref().map(|config| config.network);
    if prefix.prefix_len() == 0 && allow_default {
        return Ok(());
    }
    if prefix.prefix_len() < 8 {
        return Err(ApiError::field(field, format!("{prefix} is too wide (at least /8).")));
    }
    if network.is_some_and(|network| network.overlaps(prefix)) {
        return Err(ApiError::field(field, format!("{prefix} overlaps the tunnel network.")));
    }
    Ok(())
}

fn parse_list(field: &'static str, items: &[String], max: usize) -> ApiResult<Vec<Cidr>> {
    if items.len() > max {
        return Err(ApiError::field(field, format!("At most {max}.")));
    }
    items.iter().map(|item| item.parse::<Cidr>().map_err(|_| ApiError::field(field, format!("{item} is not a prefix like 192.168.10.0/24.")))).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsBody {
    network: Option<String>,
    share_lans: Option<bool>,
    lan_interfaces: Option<Vec<String>>,
    map_lans: Option<bool>,
    route_lans: Option<bool>,
    mapping_pool: Option<String>,
    push_routes: Option<bool>,
    lan_router: Option<String>,
    dns_servers: Option<Vec<String>>,
}

/// `PATCH /vpn/settings`
pub async fn patch_settings(State(app): State<App>, _: Admin, Json(body): Json<SettingsBody>) -> ApiResult<Response> {
    let vpn = vpn_of(&app)?;
    let mut share = vpn.share_settings();
    if let Some(network) = body.network {
        let current = app.vpn_config.as_ref().map(|config| config.network.to_string());
        if Some(&network) != current.as_ref() {
            return Err(ApiError::field("network", "The tunnel network is set with --vpn-network and applies to every node: change it on all of them, then restart."));
        }
    }
    if let Some(on) = body.share_lans {
        share.share_lans = on;
    }
    if let Some(names) = body.lan_interfaces {
        if names.len() > 8 || !names.iter().all(|name| valid_interface(name)) {
            return Err(ApiError::field("lan_interfaces", "Up to 8 interface names (letters, digits, _ . -)."));
        }
        share.lan_interfaces = names;
    }
    if let Some(on) = body.map_lans {
        share.map_lans = on;
    }
    if let Some(on) = body.route_lans {
        share.route_lans = on;
    }
    if let Some(pool) = body.mapping_pool {
        let pool: Cidr = pool.parse().map_err(|_| ApiError::field("mapping_pool", "A prefix like 10.78.0.0/16."))?;
        if !(8..=24).contains(&pool.prefix_len()) {
            return Err(ApiError::field("mapping_pool", "Use a /8 to /24."));
        }
        check_prefix(&app, "mapping_pool", &pool, false)?;
        share.mapping_pool = pool;
    }
    if let Some(on) = body.push_routes {
        share.push_routes = on;
    }
    if let Some(router) = body.lan_router {
        share.lan_router = LanRouter::parse(&router).ok_or_else(|| ApiError::field("lan_router", "Use auto, always or never."))?;
    }
    if let Some(dns) = body.dns_servers {
        if dns.len() > 4 {
            return Err(ApiError::field("dns_servers", "At most 4."));
        }
        share.dns_servers = dns.iter().map(|server| server.parse().map_err(|_| ApiError::field("dns_servers", format!("{server} is not an IPv4 address.")))).collect::<ApiResult<_>>()?;
    }
    save_and_apply(&app, share).await?;
    Ok(no_store(axum::Json(state(&app))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesBody {
    advertised: Vec<String>,
}

/// `PUT /vpn/routes`: extra prefixes advertised as they are (client networks are automatic).
pub async fn put_routes(State(app): State<App>, _: Admin, Json(body): Json<RoutesBody>) -> ApiResult<Response> {
    let vpn = vpn_of(&app)?;
    let advertise = parse_list("advertised", &body.advertised, 32)?;
    for prefix in &advertise {
        check_prefix(&app, "advertised", prefix, false)?;
    }
    let mut share = vpn.share_settings();
    share.advertise = advertise;
    save_and_apply(&app, share).await?;
    Ok(no_store(axum::Json(state(&app)["routes"].clone())))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UplinkBody {
    enabled: bool,
    peer_id: Option<String>,
    default_route: Option<bool>,
    routes: Option<Vec<String>>,
}

/// `PUT /vpn/uplink`
pub async fn put_uplink(State(app): State<App>, _: Admin, Json(body): Json<UplinkBody>) -> ApiResult<Response> {
    Ok(no_store(axum::Json(apply_uplink(&app, body).await?)))
}

/// Applies an uplink change, here or for the admin over the mesh; the new uplink state.
pub(crate) async fn apply_uplink(app: &App, body: UplinkBody) -> ApiResult<Value> {
    let vpn = vpn_of(app)?;
    let mut share = vpn.share_settings();
    if let Some(peer) = &body.peer_id
        && !(peer.len() == 32 && peer.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(ApiError::field("peer_id", "A node's identity hash (32 hex digits)."));
    }
    if body.enabled && share.gateway.enabled {
        return Err(ApiError::field("enabled", "This node is a gateway: it cannot use another one's uplink at the same time."));
    }
    let routes = match body.routes {
        Some(routes) => {
            let routes = parse_list("routes", &routes, 32)?;
            for route in &routes {
                check_prefix(app, "routes", route, true)?;
            }
            routes
        }
        None => share.uplink.routes.clone(),
    };
    let default_route = body.default_route.unwrap_or(share.uplink.default_route);
    if body.enabled && !default_route && routes.is_empty() {
        return Err(ApiError::field("routes", "Name the destinations to send to the gateway, or turn on the default route."));
    }
    share.uplink = kaonic_vpn::share::UplinkSettings { enabled: body.enabled, peer: body.peer_id.map(|peer| peer.to_lowercase()), default_route, routes };
    save_and_apply(app, share).await?;
    Ok(state(app)["uplink"].clone())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayBody {
    enabled: bool,
    egress_interface: Option<String>,
    routes: Option<Vec<String>>,
}

/// `PUT /vpn/gateway`
pub async fn put_gateway(State(app): State<App>, _: Admin, Json(body): Json<GatewayBody>) -> ApiResult<Response> {
    Ok(no_store(axum::Json(apply_gateway(&app, body).await?)))
}

/// Applies a gateway change, here or for the admin over the mesh; the new gateway state.
pub(crate) async fn apply_gateway(app: &App, body: GatewayBody) -> ApiResult<Value> {
    let vpn = vpn_of(app)?;
    let mut share = vpn.share_settings();
    if let Some(name) = &body.egress_interface
        && (!valid_interface(name) || name == &vpn.status().interface)
    {
        return Err(ApiError::field("egress_interface", "An interface of this node other than the tunnel."));
    }
    if body.enabled && share.uplink.enabled {
        return Err(ApiError::field("enabled", "This node uses another node's uplink: turn that off first."));
    }
    let routes = match body.routes {
        Some(routes) => {
            let routes = parse_list("routes", &routes, 32)?;
            for route in &routes {
                check_prefix(app, "routes", route, true)?;
            }
            routes
        }
        None => share.gateway.routes.clone(),
    };
    if body.enabled && routes.is_empty() {
        return Err(ApiError::field("routes", "Name the destinations to forward (0.0.0.0/0 for everything)."));
    }
    share.gateway = kaonic_vpn::share::GatewaySettings { enabled: body.enabled, egress_interface: body.egress_interface, routes };
    save_and_apply(app, share).await?;
    Ok(state(app)["gateway"].clone())
}

/// This node's part in internet sharing, for the admin's overview: its uplink, its gateway,
/// and whether it has internet of its own (a default route not through the tunnel).
pub(crate) fn sharing(app: &App) -> Value {
    let state = state(app);
    let tunnel = state["interface"].as_str().unwrap_or("kaonic0").to_owned();
    let internet = kaonic_vpn::kernel::all_routes().iter().any(|route| route.prefix.prefix_len() == 0 && route.interface != tunnel);
    json!({ "uplink": state["uplink"], "gateway": state["gateway"], "internet": internet })
}

#[cfg(test)]
mod share_tests {
    use super::*;

    #[test]
    fn stored_settings_round_trip_and_bad_fields_keep_defaults() {
        let mut share = ShareSettings { lan_router: LanRouter::Always, ..Default::default() };
        share.gateway.enabled = true;
        share.push_routes = false;
        share.uplink.peer = Some("ab".repeat(16));
        share.advertise = vec!["192.168.50.0/24".parse().unwrap()];
        let back = share_from_json(ShareSettings::default(), &share_json(&share));
        assert_eq!(back, share);
        let partial = share_from_json(ShareSettings::default(), &json!({ "lan_router": "sideways", "mapping_pool": "nope", "map_lans": false }));
        assert_eq!(partial.lan_router, LanRouter::Auto);
        assert_eq!(partial.mapping_pool, ShareSettings::default().mapping_pool);
        assert!(!partial.map_lans);
    }
}
