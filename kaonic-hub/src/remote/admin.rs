//! The admin's side: asks nodes and carries the admin's shells to them.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message as WsMessage, WebSocket};
use axum::http::StatusCode;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use super::node::KEEPALIVE;
use super::proto::{self, Message, Reassembly};
use super::stream::ByteStream;
use crate::app::App;
use crate::error::{ApiError, ApiResult};
use crate::server::ws_send;

/// A request is sent again after this long without an answer...
const RETRY: Duration = Duration::from_secs(3);
/// ...until this long has passed. Two hops on a busy radio can take seconds.
pub const TIMEOUT: Duration = Duration::from_secs(24);
const OPEN_TIMEOUT: Duration = Duration::from_secs(20);
const SILENCE: Duration = Duration::from_secs(60);
const BATCH: Duration = Duration::from_millis(30);
const SESSION_CHECK: Duration = Duration::from_secs(30);
/// The browser is pinged this often and dropped after `BROWSER_SILENCE` without a frame:
/// the node's keepalives must not hold a shell open for a browser that vanished.
const BROWSER_PING: Duration = Duration::from_secs(20);
const BROWSER_SILENCE: Duration = Duration::from_secs(60);

enum ShellEvent {
    Opened { ok: bool, message: String },
    Data { offset: u32, ack: u32, bytes: Vec<u8> },
    Closed { reason: String },
}

type Answer = (bool, Vec<u8>);
type Pending = (Reassembly, Option<oneshot::Sender<Answer>>);

#[derive(Default)]
struct State {
    pending: HashMap<(String, u32), Pending>,
    shells: HashMap<(String, u32), mpsc::Sender<ShellEvent>>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(Default::default);

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().expect("remote admin lock")
}

/// An answer or shell traffic for something this admin started. True if taken.
pub(super) fn on_message(peer: &str, message: &Message) -> bool {
    let mut state = state();
    match message {
        Message::Response { req, part, parts, ok, body } => {
            let Some((whole, answer)) = state.pending.get_mut(&(peer.to_owned(), *req)) else { return false };
            // A response's parts together are bounded by `parts` × PART: at most 255 × 584 bytes.
            if let Some(done) = whole.add(*part, *parts, *ok, body.clone())
                && let Some(answer) = answer.take()
            {
                let _ = answer.send(done);
            }
            true
        }
        Message::Opened { session, ok, message } => forward(&state, peer, *session, ShellEvent::Opened { ok: *ok, message: message.clone() }),
        Message::Data { session, offset, ack, bytes } => forward(&state, peer, *session, ShellEvent::Data { offset: *offset, ack: *ack, bytes: bytes.clone() }),
        Message::Close { session, reason } => forward(&state, peer, *session, ShellEvent::Closed { reason: reason.clone() }),
        _ => false,
    }
}

fn forward(state: &State, peer: &str, session: u32, event: ShellEvent) -> bool {
    match state.shells.get(&(peer.to_owned(), session)) {
        Some(sender) => {
            let _ = sender.try_send(event);
            true
        }
        None => false,
    }
}

/// A waiting request's `pending` entry, removed however the wait ends: answered, timed
/// out, or dropped because the browser went away.
struct PendingEntry((String, u32));

impl PendingEntry {
    fn insert(key: (String, u32), sender: oneshot::Sender<Answer>) -> Self {
        state().pending.insert(key.clone(), (Reassembly::default(), Some(sender)));
        Self(key)
    }
}

impl Drop for PendingEntry {
    fn drop(&mut self) {
        state().pending.remove(&self.0);
    }
}

fn random_id() -> ApiResult<u32> {
    Ok(u32::from_be_bytes(crate::random::bytes::<4>()?))
}

/// The node must be on our allowlist and have its link up.
pub async fn reachable(app: &App, peer: &str) -> ApiResult<()> {
    if !crate::provision::is_admin_device(app).await {
        return Err(ApiError::forbidden("not_admin_device", "Only the Kaonic Admin device can manage other nodes."));
    }
    if !crate::provision::allowlisted(app).await.contains(peer) {
        return Err(ApiError::new(StatusCode::CONFLICT, "not_whitelisted", "Add this node to the network first."));
    }
    if !app.links.get().is_some_and(|links| links.established().iter().any(|up| up == peer)) {
        return Err(ApiError::unavailable("peer_unreachable", "This node has no secure link to this device right now. Try again in a minute."));
    }
    Ok(())
}

/// Asks `peer` to run `op` and waits for its answer: the node's result, or its error.
pub async fn request(app: &App, peer: &str, op: Value) -> ApiResult<Value> {
    reachable(app, peer).await?;
    let op = serde_json::to_vec(&op)?;
    if op.len() > proto::MAX_BODY - 8 {
        return Err(ApiError::bad_request("This request is too large to send over the radio."));
    }
    let req = random_id()?;
    let (sender, mut answer) = oneshot::channel();
    let entry = PendingEntry::insert((peer.to_owned(), req), sender);
    let started = Instant::now();
    let outcome = loop {
        super::send(app, peer, &Message::Request { req, op: op.clone() }).await;
        match tokio::time::timeout(RETRY, &mut answer).await {
            Ok(Ok(answer)) => break Some(answer),
            Ok(Err(_)) => break None,
            Err(_) if started.elapsed() + RETRY > TIMEOUT => break None,
            Err(_) => log::debug!("remote: no answer from {peer} yet; asking again"),
        }
    };
    drop(entry);
    let Some((ok, body)) = outcome else {
        return Err(ApiError::new(StatusCode::GATEWAY_TIMEOUT, "peer_timeout", "The node did not answer in time. It may be out of range."));
    };
    let body: Value = serde_json::from_slice(&body).map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "upstream", "The node sent an answer this device cannot read."))?;
    if ok {
        return Ok(body);
    }
    Err(remote_error(&body))
}

/// The node's error, as this API's: its field errors stay field errors.
fn remote_error(body: &Value) -> ApiError {
    let message = body["message"].as_str().unwrap_or("The node refused.").chars().take(300).collect::<String>();
    let fields: std::collections::BTreeMap<String, String> = body["fields"]
        .as_object()
        .map(|fields| fields.iter().filter_map(|(field, message)| Some((field.chars().take(64).collect(), message.as_str()?.chars().take(300).collect()))).take(16).collect())
        .unwrap_or_default();
    if !fields.is_empty() {
        return ApiError { fields, ..ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed", "Check the highlighted fields.") };
    }
    let code = match body["code"].as_str() {
        Some("not_available") => "not_available",
        Some("ptt_unavailable") => "ptt_unavailable",
        Some("bad_request") => "bad_request",
        _ => "remote_failed",
    };
    ApiError::new(StatusCode::BAD_GATEWAY, code, message)
}

/* ── the shell ── */

/// Carries one shell between the browser's socket and the node until either side ends.
/// Binary frames are terminal bytes both ways; text frames are JSON: from the browser
/// `{"type":"resize","cols":80,"rows":24}`, to it `{"type":"opened"}` and
/// `{"type":"closed","reason":"…"}`.
pub async fn shell(app: App, peer: String, caller: crate::auth::Caller, mut socket: WebSocket, cols: u16, rows: u16) {
    let reason = match shell_session(&app, &peer, &caller, &mut socket, cols, rows).await {
        Ok(reason) | Err(reason) => reason,
    };
    let text = json!({ "type": "closed", "reason": reason }).to_string();
    let _ = ws_send(&mut socket, WsMessage::Text(text.into())).await;
    let _ = ws_send(&mut socket, WsMessage::Close(None)).await;
    let (now, detail) = (crate::clock::now(), format!("{peer}: {reason}"));
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", "remote.shell.close", &detail)).await;
}

async fn shell_session(app: &App, peer: &str, caller: &crate::auth::Caller, socket: &mut WebSocket, cols: u16, rows: u16) -> Result<String, String> {
    let session = random_id().map_err(|_| "Could not start a shell.".to_owned())?;
    let key = (peer.to_owned(), session);
    let (sender, mut events) = mpsc::channel(128);
    state().shells.insert(key.clone(), sender);
    let outcome = bridge(app, peer, session, caller, socket, &mut events, cols, rows).await;
    state().shells.remove(&key);
    if !matches!(outcome, Err(ref reason) if reason.starts_with("node:")) {
        // Twice: a lost CLOSE leaves the shell to the node's silence timeout.
        for _ in 0..2 {
            super::send(app, peer, &Message::Close { session, reason: "Closed by the admin.".into() }).await;
        }
    }
    outcome.map_err(|reason| reason.trim_start_matches("node:").to_owned())
}

#[allow(clippy::too_many_arguments)]
async fn bridge(app: &App, peer: &str, session: u32, caller: &crate::auth::Caller, socket: &mut WebSocket, events: &mut mpsc::Receiver<ShellEvent>, cols: u16, rows: u16) -> Result<String, String> {
    // Open: asked again until the node answers.
    let started = Instant::now();
    loop {
        super::send(app, peer, &Message::Open { session, cols, rows }).await;
        match tokio::time::timeout(Duration::from_secs(3), events.recv()).await {
            Ok(Some(ShellEvent::Opened { ok: true, .. })) => break,
            Ok(Some(ShellEvent::Opened { ok: false, message })) => return Err(format!("node:{message}")),
            Ok(Some(ShellEvent::Closed { reason })) => return Err(format!("node:{reason}")),
            Ok(Some(ShellEvent::Data { .. })) => break,
            Ok(None) => return Err("Closed.".into()),
            Err(_) if started.elapsed() >= OPEN_TIMEOUT => return Err("The node did not answer in time. It may be out of range.".into()),
            Err(_) => {}
        }
    }
    {
        let (now, detail) = (crate::clock::now(), peer.to_owned());
        let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", "remote.shell.open", &detail)).await;
    }
    log::warn!("remote: shell opened on {peer}");
    if !ws_send(socket, WsMessage::Text(json!({ "type": "opened" }).to_string().into())).await {
        return Err("Closed.".into());
    }

    let mut stream = ByteStream::default();
    let mut tick = tokio::time::interval(BATCH);
    let mut session_check = tokio::time::interval(SESSION_CHECK);
    let mut ping = tokio::time::interval(BROWSER_PING);
    let (mut heard, mut sent, mut browser_heard) = (Instant::now(), Instant::now(), Instant::now());
    loop {
        tokio::select! {
            message = socket.recv() => {
                let Some(Ok(message)) = message else { return Ok("Closed.".into()) };
                browser_heard = Instant::now();
                match message {
                    WsMessage::Binary(bytes) => {
                        if !stream.push(&bytes) {
                            log::debug!("remote: shell input dropped, the node is behind");
                        }
                    }
                    WsMessage::Text(text) => {
                        let control: Value = serde_json::from_str(&text).unwrap_or_default();
                        if control["type"] == "resize" {
                            let size = |name: &str| control[name].as_u64().and_then(|value| u16::try_from(value).ok());
                            if let (Some(cols), Some(rows)) = (size("cols"), size("rows")) {
                                super::send(app, peer, &Message::Resize { session, cols, rows }).await;
                            }
                        }
                    }
                    WsMessage::Close(_) => return Ok("Closed.".into()),
                    _ => {}
                }
            }
            event = events.recv() => match event {
                Some(ShellEvent::Data { offset, ack, bytes }) => {
                    heard = Instant::now();
                    stream.on_ack(ack, Instant::now());
                    let fresh = stream.on_data(offset, &bytes);
                    if !fresh.is_empty() && !ws_send(socket, WsMessage::Binary(fresh.into())).await {
                        return Ok("Closed.".into());
                    }
                }
                Some(ShellEvent::Closed { reason }) => return Err(format!("node:{reason}")),
                Some(ShellEvent::Opened { .. }) => heard = Instant::now(),
                None => return Ok("Closed.".into()),
            },
            _ = tick.tick() => {
                for (offset, bytes) in stream.poll(Instant::now()) {
                    super::send(app, peer, &Message::Data { session, offset, ack: stream.ack(), bytes }).await;
                    sent = Instant::now();
                }
                if sent.elapsed() >= KEEPALIVE {
                    super::send(app, peer, &Message::Data { session, offset: 0, ack: stream.ack(), bytes: Vec::new() }).await;
                    sent = Instant::now();
                }
                if heard.elapsed() >= SILENCE {
                    return Err("The node was not heard for a minute.".into());
                }
            }
            _ = ping.tick() => {
                if browser_heard.elapsed() > BROWSER_SILENCE || !ws_send(socket, WsMessage::Ping(Vec::new().into())).await {
                    return Ok("Closed.".into());
                }
            }
            _ = session_check.tick() => {
                // The admin's session may have ended (logout, expiry): then so does the shell.
                let hash = caller.token_hash.clone();
                let now = crate::clock::now();
                let alive = app.store.call(move |c| kaonic_store::sessions::find_and_touch(c, &hash, now)).await.ok().flatten().is_some();
                if !alive {
                    return Ok("The session ended.".into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_request_dropped_while_waiting_leaves_no_pending_entry() {
        let key = ("dropped-request-peer".to_owned(), 7);
        let (sender, answer) = oneshot::channel::<Answer>();
        // A request waiting for its answer, as `request` does, then abandoned by its caller.
        let waiting = tokio::spawn({
            let key = key.clone();
            async move {
                let _entry = PendingEntry::insert(key, sender);
                let _ = answer.await;
            }
        });
        while !state().pending.contains_key(&key) {
            tokio::task::yield_now().await;
        }
        waiting.abort();
        let _ = waiting.await;
        assert!(!state().pending.contains_key(&key));
    }
}
