//! `/peers/{id}/remote/*` and `/remote/jobs`: the Kaonic Admin manages the nodes of its network
//! over their secure links (`crate::remote`).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Json, Peer, client, jobs, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::remote::admin;

/// How long a shell ticket can wait to be used.
const TICKET_LIFE: Duration = Duration::from_secs(30);

async fn audit(app: &App, action: &'static str, detail: String) {
    let now = crate::clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail)).await;
}

/// `GET /peers/{id}/remote/device`: what the node says about itself.
pub async fn device(State(app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    let info = admin::request(&app, &id, json!({ "op": "info" })).await?;
    Ok(no_store(axum::Json(remote_device(&id, info))))
}

/// The node's answer in the shape of `RemoteDevice`.
fn remote_device(id: &str, info: Value) -> Value {
    let device = &info["device"];
    json!({
        "id": id,
        "codename": device["codename"],
        "serial": device["serial"],
        "version": device["versions"]["hub"],
        "os_version": device["versions"]["os"],
        "uptime_secs": device["uptime_secs"],
        "battery": info["metrics"]["battery"],
        "bands": info["bands"],
        "metrics": info["metrics"],
        "ptt": info["ptt"],
        "sharing": info["sharing"],
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodenameBody {
    codename: String,
}

/// `PUT /peers/{id}/remote/codename`
pub async fn codename(State(app): State<App>, _: Admin, Path(id): Path<String>, Json(body): Json<CodenameBody>) -> ApiResult<Response> {
    let device = admin::request(&app, &id, json!({ "op": "codename", "codename": body.codename })).await?;
    audit(&app, "remote.codename", format!("{id}: {}", body.codename)).await;
    Ok(no_store(axum::Json(device)))
}

/// `PUT /peers/{id}/remote/radio/bands/{band}`
pub async fn radio_band(State(app): State<App>, _: Admin, Path((id, band)): Path<(String, String)>, Json(config): Json<Value>) -> ApiResult<Response> {
    let view = admin::request(&app, &id, json!({ "op": "radio", "band": band, "config": config })).await?;
    audit(&app, "remote.radio", format!("{id}: {band}")).await;
    Ok(no_store(axum::Json(view)))
}

/// `PATCH /peers/{id}/remote/ptt`
pub async fn ptt(State(app): State<App>, _: Admin, Path(id): Path<String>, Json(settings): Json<Value>) -> ApiResult<Response> {
    let settings = admin::request(&app, &id, json!({ "op": "ptt", "settings": settings })).await?;
    audit(&app, "remote.ptt", id).await;
    Ok(no_store(axum::Json(settings)))
}

/// `PUT /peers/{id}/remote/vpn/uplink`: the node takes internet from a gateway node, or stops.
pub async fn uplink(State(app): State<App>, _: Admin, Path(id): Path<String>, Json(uplink): Json<Value>) -> ApiResult<Response> {
    let view = admin::request(&app, &id, json!({ "op": "uplink", "uplink": uplink })).await?;
    audit(&app, "remote.uplink", format!("{id}: {}", if view["enabled"] == true { "on" } else { "off" })).await;
    Ok(no_store(axum::Json(view)))
}

/// `PUT /peers/{id}/remote/vpn/gateway`: the node shares its internet with the mesh, or stops.
pub async fn gateway(State(app): State<App>, _: Admin, Path(id): Path<String>, Json(gateway): Json<Value>) -> ApiResult<Response> {
    let view = admin::request(&app, &id, json!({ "op": "gateway", "gateway": gateway })).await?;
    audit(&app, "remote.gateway", format!("{id}: {}", if view["enabled"] == true { "on" } else { "off" })).await;
    Ok(no_store(axum::Json(view)))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::enum_variant_names)]
pub enum JobsInput {
    NodeUpdate { node_ids: Vec<String> },
    NodeRestart { node_ids: Vec<String> },
    NodeRadio { node_ids: Vec<String>, band: String, config: Value },
    NodePtt { node_ids: Vec<String>, settings: Value },
}

/// `POST /remote/jobs`: one job per node, run one node at a time (the radio is shared and slow).
pub async fn start_jobs(State(app): State<App>, _: Admin, Json(input): Json<JobsInput>) -> ApiResult<Response> {
    let (kind, node_ids, op) = match input {
        JobsInput::NodeUpdate { node_ids } => ("node_update", node_ids, json!({ "op": "update" })),
        JobsInput::NodeRestart { node_ids } => ("node_restart", node_ids, json!({ "op": "restart" })),
        JobsInput::NodeRadio { node_ids, band, config } => ("node_radio", node_ids, json!({ "op": "radio", "band": band, "config": config })),
        JobsInput::NodePtt { node_ids, settings } => ("node_ptt", node_ids, json!({ "op": "ptt", "settings": settings })),
    };
    if node_ids.is_empty() || node_ids.len() > 256 {
        return Err(ApiError::field("node_ids", "Pick 1 to 256 nodes."));
    }
    let mut unique = node_ids.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != node_ids.len() {
        return Err(ApiError::field("node_ids", "A node is listed twice."));
    }
    if !crate::provision::is_admin_device(&app).await {
        return Err(ApiError::forbidden("not_admin_device", "Only the Kaonic Admin device can manage other nodes."));
    }
    let allowlist = crate::provision::allowlisted(&app).await;
    if let Some(stranger) = node_ids.iter().find(|id| !allowlist.contains(*id)) {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "not_whitelisted", format!("{stranger} is not in this network.")));
    }
    let queued = node_ids.iter().map(|id| jobs::queue(&app, kind, id)).collect::<ApiResult<Vec<_>>>()?;
    audit(&app, "remote.jobs", format!("{kind} on {} node(s)", queued.len())).await;
    let runner = (app.clone(), queued.clone());
    tokio::spawn(async move {
        let (app, queued) = runner;
        for job in queued {
            let node = job.node_id.clone().unwrap_or_default();
            let job = jobs::progress(&app, &job, 0.1, "Asking the node");
            match admin::request(&app, &node, op.clone()).await {
                Ok(result) => {
                    jobs::finish(&app, &job, result);
                }
                Err(error) => {
                    jobs::fail(&app, &job, error.code, &error.message);
                }
            }
        }
    });
    Ok((StatusCode::ACCEPTED, no_store(axum::Json(json!({ "jobs": queued })))).into_response())
}

/* ── the shell ── */

struct Ticket {
    peer: String,
    /// The session that asked for it: only that session may use it.
    token_hash: Vec<u8>,
    expires: Instant,
}

static TICKETS: LazyLock<Mutex<HashMap<String, Ticket>>> = LazyLock::new(Default::default);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketBody {
    password: String,
}

/// `POST /peers/{id}/remote/shell/ticket`: the password again, for a one-time ticket that opens
/// the shell's socket (a WebSocket carries no CSRF header, so the ticket stands in for it).
pub async fn shell_ticket(State(app): State<App>, peer: Option<Extension<Peer>>, Admin(caller): Admin, Path(id): Path<String>, Json(body): Json<TicketBody>) -> ApiResult<Response> {
    auth::reconfirm(&app, client(peer), &body.password, "password").await?;
    admin::reachable(&app, &id).await?;
    let ticket = crate::random::hex(&crate::random::bytes::<16>()?);
    {
        let mut tickets = TICKETS.lock().expect("tickets lock");
        tickets.retain(|_, ticket| ticket.expires > Instant::now());
        if tickets.len() >= 16 {
            return Err(ApiError::rate_limited(TICKET_LIFE.as_secs()));
        }
        tickets.insert(ticket.clone(), Ticket { peer: id.clone(), token_hash: caller.token_hash, expires: Instant::now() + TICKET_LIFE });
    }
    Ok(no_store(axum::Json(json!({ "ticket": ticket, "expires_in_secs": TICKET_LIFE.as_secs() }))))
}

#[derive(Deserialize)]
pub struct ShellQuery {
    ticket: String,
    cols: Option<u16>,
    rows: Option<u16>,
}

/// `GET /peers/{id}/remote/shell?ticket=…`: the shell's WebSocket.
pub async fn shell(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>, Query(query): Query<ShellQuery>, upgrade: WebSocketUpgrade) -> ApiResult<Response> {
    // Browsers do not apply CORS to WebSockets: this check is what stops another site.
    auth::check_origin(&headers)?;
    if headers.get(axum::http::header::ORIGIN).is_none() && !app.config.dev {
        return Err(ApiError::forbidden("forbidden", "Open the shell from the device's own page."));
    }
    let caller = auth::current(&app, &headers).await?.ok_or_else(|| ApiError::unauthenticated("Sign in to continue."))?;
    if caller.role != auth::Role::Admin {
        return Err(ApiError::forbidden("forbidden", "Only the admin can open a shell."));
    }
    let ticket = TICKETS.lock().expect("tickets lock").remove(&query.ticket);
    let valid = ticket.is_some_and(|ticket| ticket.peer == id && ticket.token_hash == caller.token_hash && ticket.expires > Instant::now());
    if !valid {
        return Err(ApiError::forbidden("ticket_invalid", "Confirm your password to open a shell."));
    }
    admin::reachable(&app, &id).await?;
    let (cols, rows) = (query.cols.unwrap_or(80).clamp(10, 500), query.rows.unwrap_or(24).clamp(2, 500));
    Ok(upgrade.max_message_size(4096).on_upgrade(move |socket| admin::shell(app, id, caller, socket, cols, rows)))
}
