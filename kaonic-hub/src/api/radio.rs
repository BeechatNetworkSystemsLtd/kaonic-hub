//! `/radio/stats` and `/radio/frames`, and their live topics (`radio`, `traffic`, `frames`):
//! what the mesh radio sends and hears, for the statistics page and the traffic analyser.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::response::Response;
use kaonic_mesh::announce::Announced;
use kaonic_mesh::iface::Counters;
use kaonic_mesh::reticulum::packet::DestinationType;
use kaonic_mesh::traffic::{Direction, FrameKind, FrameRecord};
use kaonic_mesh::Mesh;
use serde::{Deserialize, Serialize};

use super::no_store;
use crate::app::App;
use crate::auth::Viewer;
use crate::error::{ApiError, ApiResult};

/// Seconds between stats samples (and `traffic`/`radio` events).
const SAMPLE_SECS: u64 = 2;
/// The `frames` topic sends at most this often.
const FRAMES_EVERY: Duration = Duration::from_millis(250);

/// The API's name for a radio interface: module (a, b) and transceiver.
pub fn band_of(interface: &str) -> &'static str {
    match interface {
        "rf09_a" => "a_sub",
        "rf24_a" => "a_24",
        "rf24_b" => "b_24",
        _ => "b_sub",
    }
}

#[derive(Clone, Serialize)]
pub struct Airtime {
    rx_pct: f64,
    tx_pct: f64,
}

#[derive(Clone, Default, Serialize)]
pub struct DriverCounters {
    rx_errors: u64,
    rx_dropped: u64,
    tx_errors: u64,
    tx_dropped: u64,
}

#[derive(Clone, Serialize)]
pub struct BandStats {
    band: &'static str,
    interface: String,
    rx_frames: u64,
    rx_packets: u64,
    rx_bytes: u64,
    rx_bps: u64,
    rx_decode_errors: u64,
    tx_frames: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_bps: u64,
    tx_errors: u64,
    airtime: Airtime,
    last_rssi: Option<i8>,
    noise_dbm: Option<i32>,
    driver: DriverCounters,
}

/// The last sample, and the counters it was taken from (for the next one's rates).
#[derive(Default)]
pub struct RadioStats {
    state: Mutex<Option<(Instant, Counters, BandStats)>>,
}

fn read_number<T: std::str::FromStr>(path: &str) -> Option<T> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn driver_counters(interface: &str) -> DriverCounters {
    let read = |name: &str| read_number(&format!("/sys/class/net/{interface}/statistics/{name}")).unwrap_or(0);
    DriverCounters { rx_errors: read("rx_errors"), rx_dropped: read("rx_dropped"), tx_errors: read("tx_errors"), tx_dropped: read("tx_dropped") }
}

/// Per second over `elapsed`, from two readings of a counter.
fn rate(now: u64, before: u64, elapsed: Duration, scale: u64) -> u64 {
    let elapsed_ms = elapsed.as_millis().max(1) as u64;
    now.saturating_sub(before) * scale * 1000 / elapsed_ms
}

fn percent(now_us: u64, before_us: u64, elapsed: Duration) -> f64 {
    let elapsed_us = elapsed.as_micros().max(1) as f64;
    (now_us.saturating_sub(before_us) as f64 / elapsed_us * 100.0).min(100.0)
}

impl RadioStats {
    /// Takes a new sample: rates since the last one.
    pub fn sample(&self, mesh: &Mesh) -> BandStats {
        let now = Instant::now();
        let counters = mesh.counters();
        let interface = mesh.radio().to_owned();
        let mut state = self.state.lock().expect("radio stats lock");
        let (rx_bps, tx_bps, airtime) = match state.as_ref() {
            Some((then, before, _)) => {
                let elapsed = now.duration_since(*then);
                (
                    rate(counters.rx_bytes, before.rx_bytes, elapsed, 8),
                    rate(counters.tx_bytes, before.tx_bytes, elapsed, 8),
                    Airtime { rx_pct: percent(counters.rx_airtime_us, before.rx_airtime_us, elapsed), tx_pct: percent(counters.tx_airtime_us, before.tx_airtime_us, elapsed) },
                )
            }
            None => (0, 0, Airtime { rx_pct: 0.0, tx_pct: 0.0 }),
        };
        let stats = BandStats {
            band: band_of(&interface),
            noise_dbm: read_number(&format!("/sys/class/net/{interface}/rf215/ed")),
            driver: driver_counters(&interface),
            interface,
            rx_frames: counters.rx_frames,
            rx_packets: counters.rx_packets,
            rx_bytes: counters.rx_bytes,
            rx_bps,
            rx_decode_errors: counters.rx_decode_errors,
            tx_frames: counters.tx_frames,
            tx_packets: counters.tx_packets,
            tx_bytes: counters.tx_bytes,
            tx_bps,
            tx_errors: counters.tx_errors,
            airtime,
            last_rssi: counters.last_rssi,
        };
        *state = Some((now, counters, stats.clone()));
        stats
    }

    /// The last sample, or a first one.
    pub fn latest(&self, mesh: &Mesh) -> BandStats {
        if let Some((_, _, stats)) = self.state.lock().expect("radio stats lock").as_ref() {
            return stats.clone();
        }
        self.sample(mesh)
    }
}

#[derive(Clone, Copy, Serialize)]
pub struct Rate {
    rx_bps: u64,
    tx_bps: u64,
}

#[derive(Serialize)]
struct TrafficSample {
    ts_ms: i64,
    channels: HashMap<&'static str, Rate>,
}

fn traffic_sample(stats: &BandStats, (vpn_rx_bps, vpn_tx_bps): (u64, u64)) -> TrafficSample {
    let idle = Rate { rx_bps: 0, tx_bps: 0 };
    let mut channels: HashMap<&'static str, Rate> = ["a_sub", "a_24", "b_sub", "b_24", "vpn"].into_iter().map(|channel| (channel, idle)).collect();
    channels.insert(stats.band, Rate { rx_bps: stats.rx_bps, tx_bps: stats.tx_bps });
    channels.insert("vpn", Rate { rx_bps: vpn_rx_bps, tx_bps: vpn_tx_bps });
    TrafficSample { ts_ms: crate::clock::now_ms(), channels }
}

#[derive(Serialize)]
pub struct FrameView {
    seq: u64,
    ts_ms: i64,
    band: &'static str,
    direction: &'static str,
    rssi: Option<i8>,
    len: usize,
    frequency_hz: u64,
    bandwidth_hz: u64,
    duration_ms: f64,
    kind: &'static str,
    hops: Option<u8>,
    destination: Option<String>,
    destination_type: Option<&'static str>,
    packet_len: Option<usize>,
    peer_id: Option<String>,
    peer_codename: Option<String>,
}

/// Turns frames into what the API shows, naming the peers they belong to.
struct FrameNamer<'a> {
    mesh: &'a Mesh,
    band: &'static str,
    frequency_hz: u64,
    bandwidth_hz: u64,
    codenames: HashMap<String, String>,
}

impl<'a> FrameNamer<'a> {
    fn new(mesh: &'a Mesh) -> Self {
        let mut codenames: HashMap<String, String> = mesh
            .peers()
            .into_iter()
            .filter_map(|peer| match peer.announced {
                Announced::Hub(info) => Some((peer.id, info.codename)),
                _ => None,
            })
            .collect();
        codenames.insert(mesh.identity_hash().to_owned(), mesh.info().codename);
        let settings = mesh.radio_settings();
        Self {
            mesh,
            band: band_of(mesh.radio()),
            frequency_hz: settings.map_or(0, |settings| settings.centre_hz()),
            bandwidth_hz: settings.map_or(0, |settings| settings.bandwidth_hz()),
            codenames,
        }
    }

    fn view(&self, frame: &FrameRecord) -> FrameView {
        let packet = frame.packet.as_ref();
        let peer_id = packet.and_then(|packet| self.mesh.owner_of(&packet.destination));
        FrameView {
            seq: frame.seq,
            ts_ms: frame.ts_ms,
            band: self.band,
            direction: match frame.direction {
                Direction::Rx => "rx",
                Direction::Tx => "tx",
            },
            rssi: frame.rssi,
            len: frame.len,
            frequency_hz: self.frequency_hz,
            bandwidth_hz: self.bandwidth_hz,
            duration_ms: frame.airtime_us as f64 / 1000.0,
            kind: match frame.kind {
                FrameKind::Announce => "announce",
                FrameKind::Data => "data",
                FrameKind::LinkRequest => "link_request",
                FrameKind::Proof => "proof",
                FrameKind::Segment => "segment",
                FrameKind::Corrupt => "corrupt",
            },
            hops: packet.map(|packet| packet.hops),
            destination: packet.map(|packet| kaonic_mesh::node::hex(&packet.destination)),
            destination_type: packet.map(|packet| match packet.destination_type {
                DestinationType::Single => "single",
                DestinationType::Group => "group",
                DestinationType::Plain => "plain",
                DestinationType::Link => "link",
            }),
            packet_len: packet.map(|packet| packet.len),
            peer_codename: peer_id.as_ref().and_then(|id| self.codenames.get(id).cloned()),
            peer_id,
        }
    }
}

/// One Reticulum packet for the Mesh page's traffic animation (`mesh.packets`).
#[derive(Debug, PartialEq, Serialize)]
pub struct MeshPacketView {
    ts_ms: i64,
    kind: &'static str,
    from_id: Option<String>,
    to_id: Option<String>,
    bytes: usize,
}

/// At most this many packets per `mesh.packets` event; the newest are kept.
const PACKETS_PER_EVENT: usize = 30;

/// A complete packet's frame as the Mesh page draws it. `me` is this node's identity hash,
/// `owner` the node a destination belongs to (link ids belong to nobody we can name cheaply).
fn packet_view(frame: &FrameRecord, me: &str, owner: impl Fn(&kaonic_mesh::reticulum::hash::AddressHash) -> Option<String>) -> Option<MeshPacketView> {
    let packet = frame.packet.as_ref()?;
    let announce = packet.kind == FrameKind::Announce;
    let dest_owner = owner(&packet.destination);
    let (from_id, to_id) = match frame.direction {
        Direction::Tx => (Some(me.to_owned()), if announce { None } else { dest_owner.clone() }),
        Direction::Rx => (if announce { dest_owner.clone() } else { None }, Some(me.to_owned())),
    };
    // Through a relay, and not ours to end: an announce passed on, a packet for someone else.
    let relayed = packet.hops > 0 && dest_owner.as_deref() != Some(me);
    let kind = if relayed { "relayed" } else if announce { "announce" } else { "data" };
    Some(MeshPacketView { ts_ms: frame.ts_ms, kind, from_id, to_id, bytes: packet.len })
}

fn mesh(app: &App) -> ApiResult<&Mesh> {
    app.mesh.as_deref().ok_or_else(|| ApiError::unavailable("radio_unavailable", "The radio is not running on this device."))
}

/// `GET /radio/stats`: one entry per band in use.
pub async fn stats(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let mesh = mesh(&app)?;
    Ok(no_store(axum::Json(vec![app.radio_stats.latest(mesh)])))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FramesQuery {
    band: Option<String>,
    limit: Option<usize>,
}

/// `GET /radio/frames`: the most recent frames, oldest first.
pub async fn frames(State(app): State<App>, _: Viewer, Query(query): Query<FramesQuery>) -> ApiResult<Response> {
    let mesh = mesh(&app)?;
    let limit = query.limit.unwrap_or(100);
    if !(1..=500).contains(&limit) {
        return Err(ApiError::field("limit", "Use 1 to 500."));
    }
    let namer = FrameNamer::new(mesh);
    if query.band.as_deref().is_some_and(|band| band != namer.band) {
        return Ok(no_store(axum::Json(Vec::<FrameView>::new())));
    }
    let recent = mesh.traffic().recent();
    let views: Vec<FrameView> = recent[recent.len().saturating_sub(limit)..].iter().map(|frame| namer.view(frame)).collect();
    Ok(no_store(axum::Json(views)))
}

/// The live topics: a stats sample every 2 s (`radio`, `traffic`), new frames at most 4 times a second (`frames`).
pub fn spawn_producers(app: App) {
    let Some(mesh) = app.mesh.clone() else { return };
    let stats_app = app.clone();
    let stats_mesh = mesh.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(SAMPLE_SECS));
        loop {
            tick.tick().await;
            // Sampled even when nobody watches, so the first `GET /radio/stats` has rates.
            let stats = stats_app.radio_stats.sample(&stats_mesh);
            let vpn_rates = super::vpn::sample(&stats_app);
            if stats_app.bus.receivers() > 1 {
                stats_app.bus.publish("traffic", "traffic.sample", traffic_sample(&stats, vpn_rates));
                stats_app.bus.publish("radio", "radio.stats", [stats]);
                if stats_app.vpn.get().is_some() {
                    stats_app.bus.publish("vpn", "vpn.state", super::vpn::state(&stats_app));
                }
            }
        }
    });

    tokio::spawn(async move {
        let mut feed = mesh.traffic().subscribe();
        let mut batch: Vec<FrameRecord> = Vec::new();
        let mut tick = tokio::time::interval(FRAMES_EVERY);
        loop {
            tokio::select! {
                received = feed.recv() => match received {
                    Ok(frame) => batch.push(frame),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
                _ = tick.tick() => {
                    if batch.is_empty() {
                        continue;
                    }
                    let frames = std::mem::take(&mut batch);
                    if app.bus.receivers() > 1 {
                        let namer = FrameNamer::new(&mesh);
                        let views: Vec<FrameView> = frames.iter().map(|frame| namer.view(frame)).collect();
                        app.bus.publish("frames", "radio.frames", views);
                        let me = mesh.identity_hash();
                        let mut packets: Vec<MeshPacketView> = frames.iter().filter_map(|frame| packet_view(frame, me, |destination| mesh.owner_of(destination))).collect();
                        if packets.len() > PACKETS_PER_EVENT {
                            packets.drain(..packets.len() - PACKETS_PER_EVENT);
                        }
                        if !packets.is_empty() {
                            app.bus.publish("packets", "mesh.packets", packets);
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_become_mesh_packets() {
        use kaonic_mesh::reticulum::hash::AddressHash;
        use kaonic_mesh::reticulum::packet::DestinationType;
        use kaonic_mesh::traffic::PacketInfo;
        let peer_dest = AddressHash::new_from_slice(&[1; 16]);
        let link = AddressHash::new_from_slice(&[2; 16]);
        let owner = |destination: &AddressHash| (*destination == peer_dest).then(|| "peer".to_owned());
        let frame = |direction, kind, destination, hops| FrameRecord {
            seq: 1,
            ts_ms: 5,
            direction,
            len: 300,
            rssi: None,
            airtime_us: 0,
            kind,
            packet: Some(PacketInfo { kind, hops, destination, destination_type: DestinationType::Single, len: 120 }),
        };
        let view = |frame: FrameRecord| packet_view(&frame, "me", owner).unwrap();
        // Our announce: broadcast.
        let ours = view(frame(Direction::Tx, FrameKind::Announce, AddressHash::new_from_slice(&[9; 16]), 0));
        assert_eq!((ours.kind, ours.from_id.as_deref(), ours.to_id.as_deref(), ours.bytes), ("announce", Some("me"), None, 120));
        // A neighbour's announce names its sender; one passed on by a relay is relayed.
        let heard = view(frame(Direction::Rx, FrameKind::Announce, peer_dest, 0));
        assert_eq!((heard.kind, heard.from_id.as_deref(), heard.to_id.as_deref()), ("announce", Some("peer"), Some("me")));
        assert_eq!(view(frame(Direction::Rx, FrameKind::Announce, peer_dest, 2)).kind, "relayed");
        // Link data: the link id belongs to nobody we can name.
        let data = view(frame(Direction::Rx, FrameKind::Data, link, 0));
        assert_eq!((data.kind, data.from_id, data.to_id.as_deref()), ("data", None, Some("me")));
        let sent = view(frame(Direction::Tx, FrameKind::Data, peer_dest, 0));
        assert_eq!(sent.to_id.as_deref(), Some("peer"));
        assert_eq!(view(frame(Direction::Tx, FrameKind::Data, link, 1)).kind, "relayed");
        // Segments and corrupt frames are not packets.
        let mut segment = frame(Direction::Rx, FrameKind::Segment, link, 0);
        segment.packet = None;
        assert_eq!(packet_view(&segment, "me", owner), None);
    }

    #[test]
    fn rates_are_per_second() {
        assert_eq!(rate(3000, 1000, Duration::from_secs(2), 8), 8000);
        assert_eq!(rate(1000, 3000, Duration::from_secs(2), 8), 0);
        assert!((percent(500_000, 0, Duration::from_secs(2)) - 25.0).abs() < 1e-9);
        assert_eq!(percent(5_000_000, 0, Duration::from_secs(2)), 100.0);
    }

    #[test]
    fn bands_are_named_by_module_and_transceiver() {
        assert_eq!(band_of("rf09_a"), "a_sub");
        assert_eq!(band_of("rf09_b"), "b_sub");
        assert_eq!(band_of("rf24_a"), "a_24");
        assert_eq!(band_of("rf24_b"), "b_24");
    }
}
