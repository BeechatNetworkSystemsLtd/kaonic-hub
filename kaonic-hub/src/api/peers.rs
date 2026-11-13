//! `/peers` and `/bearers`: the nodes heard on the mesh, and the radio under it.

use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::response::Response;
use kaonic_mesh::announce::Announced;
use kaonic_mesh::{Mesh, Peer};
use serde::{Deserialize, Serialize};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::provision;

#[derive(Serialize)]
pub struct PeerView {
    id: String,
    codename: String,
    tag: String,
    version: String,
    online: bool,
    first_seen_ts: i64,
    last_seen_ts: i64,
    hops: Option<u8>,
    via_id: Option<String>,
    rssi: Option<i8>,
    bearer: &'static str,
    list: &'static str,
    trust: TrustView,
    link: LinkView,
    tunnel_ip: Option<String>,
}

#[derive(Serialize)]
struct TrustView {
    network: &'static str,
    is_admin: bool,
    provisioning: Option<ProvisioningView>,
}

#[derive(Serialize)]
struct ProvisioningView {
    state: &'static str,
    detail: String,
    updated_ts: i64,
}

/// What this node knows about trust, to show each peer against.
pub struct Context {
    admin: Option<String>,
    /// The admin's signed list: allowed and blocked identities.
    allowlist: HashSet<String>,
    blocked: HashSet<String>,
    /// Each peer's link, and its tunnel address on the VPN.
    links: std::collections::HashMap<String, kaonic_mesh::links::LinkView>,
    tunnels: std::collections::HashMap<String, String>,
}

pub async fn context(app: &App) -> Context {
    let links = match app.links.get() {
        Some(links) => links.view().await.into_iter().map(|view| (view.peer.clone(), view)).collect(),
        None => Default::default(),
    };
    let tunnels = app
        .vpn
        .get()
        .map(|vpn| vpn.status().peers.into_iter().filter_map(|peer| Some((peer.peer, peer.tunnel?.to_string()))).collect())
        .unwrap_or_default();
    let (allowlist, blocked) = provision::lists(app).await;
    Context { admin: super::account::our_admin(app).await.ok().flatten(), allowlist, blocked, links, tunnels }
}

#[derive(Serialize)]
struct LinkView {
    state: &'static str,
    rtt_ms: Option<u32>,
    detail: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A peer as the API shows it, against this node's trust.
pub fn view(app: &App, mesh: &Mesh, peer: &Peer, context: &Context) -> PeerView {
    let our_admin = context.admin.as_deref();
    let (codename, version, network, is_admin) = match &peer.announced {
        Announced::Hub(info) => {
            let admin = info.admin_id.map(|id| hex(&id));
            let network = match (&admin, our_admin) {
                (None, _) => "unprovisioned",
                (Some(theirs), Some(ours)) if theirs == ours => "ours",
                (Some(_), _) => "other",
            };
            (
                info.codename.clone(),
                info.version.clone(),
                network,
                info.is_admin && admin.as_deref() == our_admin,
            )
        }
        Announced::Unknown => (String::new(), String::new(), "unknown", false),
    };
    PeerView {
        id: peer.id.clone(),
        codename,
        tag: String::new(),
        version,
        online: mesh.is_online(peer),
        first_seen_ts: peer.first_seen,
        last_seen_ts: peer.last_seen,
        // Reticulum counts a neighbour's announce as 0 hops travelled; one hop away, as people count.
        hops: Some(peer.hops.saturating_add(1)),
        via_id: peer.via.clone().filter(|_| peer.hops > 0),
        rssi: peer.rssi,
        bearer: "radio",
        // From the admin's signed list, the same on every node. The admin is trusted without
        // being listed.
        list: if is_admin || context.admin.as_deref() == Some(peer.id.as_str()) || context.allowlist.contains(&peer.id) {
            "whitelist"
        } else if context.blocked.contains(&peer.id) {
            "blacklist"
        } else {
            "none"
        },
        trust: TrustView {
            network,
            is_admin,
            provisioning: app.provisioning.get(&peer.id).map(|(running, detail)| {
                ProvisioningView {
                    state: if running { "running" } else { "failed" },
                    detail,
                    updated_ts: crate::clock::now(),
                }
            }),
        },
        link: match context.links.get(&peer.id) {
            Some(link) => LinkView {
                state: match link.state {
                    "up" => "active",
                    "failed" => "refused",
                    _ => "pending",
                },
                rtt_ms: link.rtt_ms.map(|ms| u32::try_from(ms).unwrap_or(u32::MAX)),
                detail: link.detail.clone(),
            },
            None => LinkView { state: "none", rtt_ms: None, detail: None },
        },
        tunnel_ip: context.tunnels.get(&peer.id).cloned(),
    }
}

fn mesh(app: &App) -> ApiResult<&Mesh> {
    app.mesh.as_deref().ok_or_else(|| {
        ApiError::unavailable(
            "radio_unavailable",
            "The radio is not running on this device.",
        )
    })
}

pub async fn list(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let mesh = mesh(&app)?;
    let context = context(&app).await;
    let peers: Vec<PeerView> = mesh
        .peers()
        .iter()
        .filter(|peer| peer.id != mesh.identity_hash())
        .map(|peer| view(&app, mesh, peer, &context))
        .collect();
    Ok(no_store(axum::Json(peers)))
}

/// Tells live subscribers how the peer `id` looks now.
pub async fn publish(app: &App, id: &str) {
    let Some(mesh) = app.mesh.as_deref() else {
        return;
    };
    let Some(peer) = mesh.peers().into_iter().find(|peer| peer.id == id) else {
        return;
    };
    let context = context(app).await;
    app.bus
        .publish("peers", "peer.updated", view(app, mesh, &peer, &context));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListBody {
    list: String,
}

/// `PUT /peers/{id}/list`: only on the admin device, whose signed list every node follows.
/// Whitelisting a node that waits for an admin provisions it (unblocking it first); `blacklist`
/// takes it off the allowlist and blocks it everywhere; `none` takes it off both.
pub async fn set_list(
    State(app): State<App>,
    Admin(_): Admin,
    Path(id): Path<String>,
    Json(body): Json<ListBody>,
) -> ApiResult<Response> {
    let mesh = mesh(&app)?;
    if !provision::is_admin_device(&app).await {
        return Err(ApiError::forbidden(
            "not_admin_device",
            "Only the Kaonic Admin device can change the whitelist and the blacklist.",
        ));
    }
    let peer = mesh
        .peers()
        .into_iter()
        .find(|peer| peer.id == id)
        .ok_or_else(|| ApiError::not_found("This device has not been heard."))?;
    let context = context(&app).await;
    // Our admin is trusted by definition: it is never removed or blacklisted.
    let is_our_admin = context.admin.as_deref() == Some(id.as_str());
    if body.list != "whitelist" && is_our_admin {
        return Err(ApiError::new(axum::http::StatusCode::CONFLICT, "is_admin", "The Kaonic Admin of this network can't be removed or blacklisted."));
    }
    match body.list.as_str() {
        "whitelist" if is_our_admin || context.allowlist.contains(&id) => {}
        "whitelist" => match &peer.announced {
            // Unprovisioned, or ours but not on the allowlist (taken off it, or a run whose
            // answer was lost): provisioning it (again) puts it on.
            Announced::Hub(info)
                if info.admin_id.is_none() || info.admin_id.map(|id| hex(&id)) == context.admin =>
            {
                if context.blocked.contains(&id) {
                    set_listing(&app, &id, provision::Listing::None).await?;
                }
                if app
                    .provisioning
                    .get(&id)
                    .is_none_or(|(running, _)| !running)
                {
                    provision::start(&app, id.clone());
                }
            }
            Announced::Hub(_) => {
                return Err(ApiError::new(
                    axum::http::StatusCode::CONFLICT,
                    "foreign_node",
                    "This device belongs to another Kaonic Admin. Factory reset it first.",
                ));
            }
            _ => {
                return Err(ApiError::conflict(
                    "This device does not run the hub and cannot be provisioned.",
                ));
            }
        },
        "none" => {
            set_listing(&app, &id, provision::Listing::None).await?;
        }
        "blacklist" => {
            set_listing(&app, &id, provision::Listing::Blocked).await?;
        }
        _ => return Err(ApiError::field("list", "Use whitelist, blacklist or none.")),
    }
    let context = super::peers::context(&app).await;
    Ok(no_store(axum::Json(view(&app, mesh, &peer, &context))))
}

async fn set_listing(app: &App, id: &str, listing: provision::Listing) -> ApiResult<bool> {
    provision::set_listing(app, id, listing)
        .await
        .map_err(|why| ApiError::new(axum::http::StatusCode::CONFLICT, "conflict", why))
}

#[derive(Serialize)]
struct BearerView {
    id: &'static str,
    enabled: bool,
    state: &'static str,
    detail: Option<String>,
    cost: u8,
    counters: CountersView,
}

#[derive(Serialize)]
struct CountersView {
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    errors: u64,
    tx_frames: u64,
    rx_frames: u64,
    rx_decode_errors: u64,
    last_rssi: Option<i8>,
}

pub async fn bearers(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let Some(mesh) = app.mesh.as_deref() else {
        return Ok(no_store(axum::Json(Vec::<BearerView>::new())));
    };
    let counters = mesh.counters();
    Ok(no_store(axum::Json(vec![BearerView {
        id: "radio",
        enabled: true,
        state: "up",
        detail: Some(format!("Reticulum on {}", app.config.radio)),
        cost: 0,
        counters: CountersView {
            tx_packets: counters.tx_packets,
            rx_packets: counters.rx_packets,
            tx_bytes: counters.tx_bytes,
            rx_bytes: counters.rx_bytes,
            errors: counters.tx_errors + counters.rx_decode_errors,
            tx_frames: counters.tx_frames,
            rx_frames: counters.rx_frames,
            rx_decode_errors: counters.rx_decode_errors,
            last_rssi: counters.last_rssi,
        },
    }])))
}
