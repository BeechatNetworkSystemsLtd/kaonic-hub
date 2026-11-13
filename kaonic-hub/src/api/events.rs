//! `/events`: the WebSocket of live changes.

use std::collections::HashSet;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use crate::app::App;
use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::server::ws_send;

const PING_EVERY: Duration = Duration::from_secs(20);
const SILENCE_LIMIT: Duration = Duration::from_secs(60);
const SESSION_CHECK: Duration = Duration::from_secs(30);
const MAX_MESSAGE: usize = 4096;
const TOPICS: &[&str] = &[
    "metrics", "traffic", "frames", "packets", "peers", "jobs", "network", "trust", "links",
    "radio", "vpn", "ptt", "plugins", "system",
];

#[derive(Deserialize)]
pub struct TopicsQuery {
    topics: Option<String>,
}

#[derive(Deserialize)]
struct Op {
    op: String,
    topics: Vec<String>,
}

fn known(topics: impl IntoIterator<Item = String>) -> HashSet<String> {
    topics
        .into_iter()
        .filter(|topic| TOPICS.contains(&topic.as_str()))
        .collect()
}

pub async fn socket(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<TopicsQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    // Browsers do not apply CORS to WebSockets: this check is what stops another site.
    auth::check_origin(&headers)?;
    if headers.get(axum::http::header::ORIGIN).is_none() && !app.config.dev {
        return Err(ApiError::forbidden(
            "forbidden",
            "Open the events socket from the device's own page.",
        ));
    }
    let caller = auth::current(&app, &headers)
        .await?
        .ok_or_else(|| ApiError::unauthenticated("Sign in to continue."))?;
    let topics = known(
        query
            .topics
            .unwrap_or_default()
            .split(',')
            .filter(|topic| !topic.is_empty())
            .map(str::to_owned),
    );
    Ok(upgrade
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| serve(app, caller, socket, topics)))
}

async fn serve(app: App, caller: auth::Caller, mut socket: WebSocket, mut topics: HashSet<String>) {
    let mut events = app.bus.subscribe();
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut session = tokio::time::interval(SESSION_CHECK);
    let mut last_heard = tokio::time::Instant::now();
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(event) if topics.contains(event.topic) => {
                    let Ok(text) = serde_json::to_string(&event) else { continue };
                    if !ws_send(&mut socket, Message::Text(text.into())).await {
                        return;
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => {
                    // This client fell behind and missed events: it must re-read.
                    let resync = r#"{"topic":"system","type":"resync","ts_ms":0,"data":null}"#;
                    if !ws_send(&mut socket, Message::Text(resync.into())).await {
                        return;
                    }
                }
                Err(RecvError::Closed) => return,
            },
            message = socket.recv() => {
                let Some(Ok(message)) = message else { return };
                last_heard = tokio::time::Instant::now();
                match message {
                    Message::Text(text) => {
                        let Ok(op) = serde_json::from_str::<Op>(&text) else {
                            let _ = ws_send(&mut socket, Message::Close(Some(CloseFrame { code: 1008, reason: "invalid op".into() }))).await;
                            return;
                        };
                        match op.op.as_str() {
                            "subscribe" => topics.extend(known(op.topics)),
                            "unsubscribe" => {
                                for topic in op.topics {
                                    topics.remove(&topic);
                                }
                            }
                            _ => {
                                let _ = ws_send(&mut socket, Message::Close(Some(CloseFrame { code: 1008, reason: "invalid op".into() }))).await;
                                return;
                            }
                        }
                    }
                    Message::Close(_) => return,
                    _ => {}
                }
            }
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT || !ws_send(&mut socket, Message::Ping(Vec::new().into())).await {
                    return;
                }
            }
            _ = session.tick() => {
                // The session may have ended (logout, expiry, password change): then so does the socket.
                let hash = caller.token_hash.clone();
                let now = crate::clock::now();
                let alive = app.store.call(move |c| kaonic_store::sessions::find_and_touch(c, &hash, now)).await.ok().flatten().is_some();
                if !alive {
                    let _ = ws_send(&mut socket, Message::Close(Some(CloseFrame { code: 4401, reason: "session ended".into() }))).await;
                    return;
                }
            }
        }
    }
}
