//! The plugin API (`docs/api/plugin-api.yaml`): what a plugin may use on its node and across
//! the mesh, served on one Unix socket per plugin ([`socket`]).
//!
//! A socket answers only its plugin's user. Every request also carries the plugin's token,
//! `kpt1.<claims>.<signature>`, issued by the installer. The hub checks the signature with
//! the installer's public key, that the token's SHA-256 is the one in the plugin's record (so
//! a removed or reissued token stops working), and that it names the socket's plugin.
//! Everything a plugin reaches here is its own.

pub mod bridge;
pub mod socket;
pub mod wire;

use std::collections::{BTreeSet, HashMap};

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use kaonic_hub_installer::manifest::Permission;
use kaonic_store::plugin_store::{self, Put};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use self::bridge::{Reason, Target};
use crate::api::Json;
use crate::app::App;
use crate::error::{ApiError, ApiResult};

pub const BASE: &str = "/api/plugin/v1";
/// How often an open event socket checks that its token still holds.
const RECHECK: std::time::Duration = std::time::Duration::from_secs(60);

/// Which plugin's socket a request came in on.
#[derive(Clone, Debug)]
struct SocketOf(String);

/// The API as served on `plugin`'s socket: only that plugin's token is taken.
pub fn router(app: App, plugin: &str) -> Router {
    let api = Router::new()
        .route("/self", get(about))
        .route("/nodes", get(nodes))
        .route("/nodes/{node}", get(node))
        .route("/nodes/{node}/messages", post(send_to_node))
        .route("/messages", post(send_to_all))
        .route("/broadcast", post(broadcast))
        .route("/events", get(events))
        .route("/stats", get(stats))
        .route("/store", get(keys))
        .route("/store/{key}", get(get_value).put(put_value).delete(delete_value))
        .fallback(|| async { ApiError::not_found("No such endpoint.") })
        .layer(axum::extract::DefaultBodyLimit::max(plugin_store::MAX_VALUE + 4096));
    Router::new().nest(BASE, api).layer(axum::Extension(SocketOf(plugin.to_owned()))).with_state(app)
}

/// The plugin calling, from its token.
#[derive(Clone, Debug)]
pub struct Caller {
    pub id: String,
    pub version: String,
    pub permissions: Vec<Permission>,
    token_sha256: String,
}

impl Caller {
    fn may(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    fn require_mesh(&self) -> ApiResult<()> {
        if self.may(Permission::Mesh) {
            Ok(())
        } else {
            Err(ApiError::forbidden("missing_permission", "This needs the mesh permission in the plugin's manifest."))
        }
    }
}

fn unauthenticated() -> ApiError {
    ApiError::unauthenticated("Send this plugin's token: Authorization: Bearer <token>.")
}

/// Checks a token: the installer's signature, then that it is the plugin's current one and
/// names `socket`'s plugin.
pub async fn authenticate(app: &App, socket: &str, token: &str) -> ApiResult<Caller> {
    use kaonic_hub_installer::token;
    let plugins = app.plugins();
    let key = plugins
        .token_key(false)
        .await
        .ok_or_else(|| ApiError::unavailable("installer_unavailable", "The plugin installer is not running. Try again in a moment."))?;
    let claims = match token::verify(&key, token) {
        Some(claims) => claims,
        // The installer may have a new key (its state was reset): ask once more.
        None => plugins.token_key(true).await.filter(|again| *again != key).and_then(|again| token::verify(&again, token)).ok_or_else(unauthenticated)?,
    };
    if claims.id != socket {
        return Err(unauthenticated());
    }
    let sha = kaonic_hub_installer::sha256_hex(token.as_bytes());
    let plugin = plugins
        .find_since(&claims.id, |plugin| crate::auth::same(&plugin.record.token_sha256, &sha), claims.issued)
        .await
        .ok_or_else(unauthenticated)?;
    let permissions = claims.permissions.into_iter().filter(|permission| plugin.record.manifest.has(*permission)).collect();
    Ok(Caller { id: claims.id, version: plugin.record.manifest.version.clone(), permissions, token_sha256: sha })
}

impl FromRequestParts<App> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &App) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or_else(unauthenticated)?;
        // Served without a socket's plugin, nothing is let in.
        let socket = parts.extensions.get::<SocketOf>().ok_or_else(unauthenticated)?;
        authenticate(app, &socket.0, token).await
    }
}

fn no_store(response: impl IntoResponse) -> Response {
    crate::api::no_store(response)
}

/* ── self, nodes, stats ── */

/// `GET /self`
async fn about(State(app): State<App>, caller: Caller) -> ApiResult<Response> {
    let codename = crate::api::node_info(&app).await.map(|info| info.codename).unwrap_or_default();
    let node = app.mesh.as_ref().map(|mesh| mesh.identity_hash().to_owned());
    let share = app.plugins().bridge.share();
    Ok(no_store(axum::Json(serde_json::json!({
        "plugin": caller.id,
        "version": caller.version,
        "permissions": caller.permissions,
        "node": node,
        "codename": codename,
        "hub_version": env!("CARGO_PKG_VERSION"),
        "limits": {
            "max_message": bridge::max_message(),
            "max_broadcast": bridge::max_broadcast(),
            "airtime_share": share,
            "queue": bridge::QUEUE,
            "store": {
                "max_value": plugin_store::MAX_VALUE,
                "max_bytes": plugin_store::MAX_BYTES,
                "max_keys": plugin_store::MAX_KEYS,
            },
        },
    }))))
}

#[derive(Serialize)]
struct NodeView {
    id: String,
    codename: String,
    admin: bool,
    link: &'static str,
    runs_plugin: bool,
    rssi: Option<i8>,
    rtt_ms: Option<u64>,
    last_heard: Option<i64>,
}

/// The nodes this one trusts: on the admin's list, the admin itself, or linked.
async fn trusted_nodes(app: &App, plugin: &str) -> Vec<NodeView> {
    let links: HashMap<String, kaonic_mesh::links::LinkView> = match app.links.get() {
        Some(links) => links.view().await.into_iter().map(|view| (view.peer.clone(), view)).collect(),
        None => HashMap::new(),
    };
    let peers: HashMap<String, kaonic_mesh::Peer> = app.mesh.as_ref().map(|mesh| mesh.peers().into_iter().map(|peer| (peer.id.clone(), peer)).collect()).unwrap_or_default();
    let (allowed, blocked) = crate::provision::lists(app).await;
    let admin = crate::api::our_admin(app).await.ok().flatten();
    let me = app.mesh.as_ref().map(|mesh| mesh.identity_hash().to_owned());
    let ids: BTreeSet<String> = allowed.into_iter().chain(admin.clone()).chain(links.keys().cloned()).filter(|id| !blocked.contains(id) && Some(id) != me.as_ref()).collect();
    let bridge = &app.plugins().bridge;
    ids.into_iter()
        .map(|id| {
            let link = links.get(&id);
            let peer = peers.get(&id);
            NodeView {
                codename: match peer.map(|peer| &peer.announced) {
                    Some(kaonic_mesh::announce::Announced::Hub(info)) => info.codename.clone(),
                    _ => String::new(),
                },
                admin: admin.as_ref() == Some(&id),
                link: match link.map(|link| link.state) {
                    Some("up") => "up",
                    Some("opening" | "authenticating") => "connecting",
                    _ => "down",
                },
                runs_plugin: bridge.runs(&id, plugin),
                rssi: peer.and_then(|peer| peer.rssi),
                rtt_ms: link.and_then(|link| link.rtt_ms),
                last_heard: peer.map(|peer| peer.last_seen),
                id,
            }
        })
        .collect()
}

/// `GET /nodes`
async fn nodes(State(app): State<App>, caller: Caller) -> ApiResult<Response> {
    Ok(no_store(axum::Json(trusted_nodes(&app, &caller.id).await)))
}

/// `GET /nodes/{node}`
async fn node(State(app): State<App>, caller: Caller, Path(node): Path<String>) -> ApiResult<Response> {
    let found = trusted_nodes(&app, &caller.id).await.into_iter().find(|view| view.id == node).ok_or_else(|| ApiError::not_found("No trusted node with that id."))?;
    Ok(no_store(axum::Json(found)))
}

/// `GET /stats`
async fn stats(State(app): State<App>, caller: Caller) -> ApiResult<Response> {
    Ok(no_store(axum::Json(app.plugins().bridge.stats(&caller.id))))
}

/* ── messages ── */

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outgoing {
    channel: u8,
    data: String,
    /// Not yet: every message is best effort.
    #[serde(default)]
    #[allow(dead_code)]
    reliable: bool,
}

enum To {
    Node(String),
    All,
    Broadcast,
}

/// Queues a message; its id and how many nodes it goes to.
async fn queue(app: &App, caller: &Caller, to: To, channel: u8, data: &str) -> ApiResult<(u64, usize)> {
    caller.require_mesh()?;
    let data = kaonic_hub_common::base64::decode_canonical(data).ok_or_else(|| ApiError::field("data", "Send the data as base64."))?;
    let bridge = &app.plugins().bridge;
    let targets = match to {
        To::Node(node) => {
            if !trusted_nodes(app, &caller.id).await.iter().any(|view| view.id == node) {
                return Err(ApiError::not_found("No trusted node with that id."));
            }
            vec![Target::Node(node)]
        }
        To::All => bridge.linked().into_iter().filter(|node| bridge.runs(node, &caller.id)).map(Target::Node).collect(),
        To::Broadcast => {
            if app.ptt_group.get().is_none() {
                return Err(ApiError::conflict("This node has no group key yet: it gets one when it is provisioned."));
            }
            vec![Target::Broadcast]
        }
    };
    let count = targets.len();
    match bridge.send(&caller.id, targets, channel, data) {
        Ok(id) => Ok((id, count)),
        Err(Reason::TooLarge) => Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "The message is larger than limits.max_message.")),
        Err(Reason::Ambiguous) => Err(ApiError::new(StatusCode::CONFLICT, "ambiguous_name", "Another plugin here has the same mesh name; the mesh is off for both.")),
        Err(_) => Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "busy", "The message could not be queued.")),
    }
}

fn queued(id: u64, nodes: usize) -> Response {
    (StatusCode::ACCEPTED, axum::Json(serde_json::json!({ "id": id, "nodes": nodes }))).into_response()
}

/// `POST /nodes/{node}/messages`
async fn send_to_node(State(app): State<App>, caller: Caller, Path(node): Path<String>, Json(message): Json<Outgoing>) -> ApiResult<Response> {
    let (id, nodes) = queue(&app, &caller, To::Node(node), message.channel, &message.data).await?;
    Ok(queued(id, nodes))
}

/// `POST /messages`
async fn send_to_all(State(app): State<App>, caller: Caller, Json(message): Json<Outgoing>) -> ApiResult<Response> {
    let (id, nodes) = queue(&app, &caller, To::All, message.channel, &message.data).await?;
    Ok(queued(id, nodes))
}

/// `POST /broadcast`
async fn broadcast(State(app): State<App>, caller: Caller, Json(message): Json<Outgoing>) -> ApiResult<Response> {
    let (id, nodes) = queue(&app, &caller, To::Broadcast, message.channel, &message.data).await?;
    Ok(queued(id, nodes))
}

/// A message sent on the event socket.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocketOutgoing {
    /// A node id, `*` for every node running the plugin, or `broadcast`.
    to: String,
    channel: u8,
    data: String,
    #[serde(default)]
    #[allow(dead_code)]
    reliable: bool,
    /// The plugin's own reference, echoed in the answer.
    #[serde(default, rename = "ref")]
    reference: Option<serde_json::Value>,
}

/// One event socket's place in the bridge; given back when dropped, upgraded or not.
struct Attached {
    bridge: std::sync::Arc<bridge::Bridge>,
    plugin: String,
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.bridge.detach(&self.plugin);
    }
}

/// `GET /events`: a WebSocket of events; messages may be sent on it too. At most
/// [`bridge::MAX_EVENT_SOCKETS`] at once.
async fn events(State(app): State<App>, caller: Caller, upgrade: WebSocketUpgrade) -> ApiResult<Response> {
    caller.require_mesh()?;
    let bridge = app.plugins().bridge.clone();
    let events = bridge.attach(&caller.id, caller.may(Permission::Mesh)).ok_or_else(|| {
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too_many_sockets", "This plugin has 4 event sockets open already.")
    })?;
    let attached = Attached { bridge, plugin: caller.id.clone() };
    Ok(upgrade.max_message_size(64 * 1024).on_upgrade(move |socket| run_events(app, caller, socket, events, attached)))
}

async fn run_events(app: App, caller: Caller, mut socket: WebSocket, mut events: broadcast::Receiver<bridge::Event>, attached: Attached) {
    let plugins = app.plugins();
    let mut recheck = tokio::time::interval(RECHECK);
    recheck.tick().await;
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(event) => {
                    let text = serde_json::to_string(&event).expect("events serialise");
                    if !crate::server::ws_send(&mut socket, Message::Text(text.into())).await {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => log::debug!("plugins: {} missed {missed} events", caller.id),
                Err(broadcast::error::RecvError::Closed) => break,
            },
            message = socket.recv() => match message {
                Some(Ok(Message::Text(text))) => {
                    let answer = from_socket(&app, &caller, &text).await;
                    if !crate::server::ws_send(&mut socket, Message::Text(answer.to_string().into())).await {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => {
                // Removed, or given a new token: the socket ends with the old one.
                let sha = caller.token_sha256.clone();
                if plugins.find(&caller.id, |plugin| plugin.record.token_sha256 == sha).await.is_none() {
                    break;
                }
            }
        }
    }
    drop(attached);
}

async fn from_socket(app: &App, caller: &Caller, text: &str) -> serde_json::Value {
    let message: SocketOutgoing = match serde_json::from_str(text) {
        Ok(message) => message,
        Err(error) => return serde_json::json!({ "type": "refused", "ref": null, "code": "bad_request", "message": error.to_string() }),
    };
    let to = match message.to.as_str() {
        "*" => To::All,
        "broadcast" => To::Broadcast,
        node => To::Node(node.to_owned()),
    };
    match queue(app, caller, to, message.channel, &message.data).await {
        Ok((id, nodes)) => serde_json::json!({ "type": "queued", "ref": message.reference, "id": id, "nodes": nodes }),
        Err(error) => serde_json::json!({ "type": "refused", "ref": message.reference, "code": error.code, "message": error.message }),
    }
}

/* ── store ── */

fn key_of(key: &str) -> ApiResult<&str> {
    let ok = (1..=128).contains(&key.len()) && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if ok { Ok(key) } else { Err(ApiError::field("key", "Use 1-128 letters, digits, '.', '_' and '-'.")) }
}

/// `GET /store`
async fn keys(State(app): State<App>, caller: Caller) -> ApiResult<Response> {
    let keys = app.store.call(move |c| plugin_store::keys(c, &caller.id)).await?;
    Ok(no_store(axum::Json(keys)))
}

/// `GET /store/{key}`
async fn get_value(State(app): State<App>, caller: Caller, Path(key): Path<String>) -> ApiResult<Response> {
    key_of(&key)?;
    let value = app.store.call(move |c| plugin_store::get(c, &caller.id, &key)).await?.ok_or_else(|| ApiError::not_found("No such key."))?;
    Ok(no_store(([(header::CONTENT_TYPE, "application/json")], value)))
}

/// `PUT /store/{key}`: any JSON value.
async fn put_value(State(app): State<App>, caller: Caller, Path(key): Path<String>, body: Bytes) -> ApiResult<Response> {
    key_of(&key)?;
    if body.len() > plugin_store::MAX_VALUE {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "A value is at most 64 KiB."));
    }
    if serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_err() {
        return Err(ApiError::field("value", "Send a JSON value."));
    }
    match app.store.call(move |c| plugin_store::put(c, &caller.id, &key, &body)).await? {
        Put::Stored => Ok(StatusCode::NO_CONTENT.into_response()),
        Put::TooLarge => Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "A value is at most 64 KiB.")),
        Put::Full => Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "store_full", "This plugin's store is full: at most 1 MiB and 256 keys.")),
    }
}

/// `DELETE /store/{key}`
async fn delete_value(State(app): State<App>, caller: Caller, Path(key): Path<String>) -> ApiResult<Response> {
    key_of(&key)?;
    app.store.call(move |c| plugin_store::delete(c, &caller.id, &key)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
