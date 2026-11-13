//! `GET /links`: the authenticated mesh links, at most one per peer.

use axum::extract::State;
use axum::response::Response;
use serde::Serialize;

use super::no_store;
use crate::app::App;
use crate::auth::Viewer;
use crate::error::ApiResult;

#[derive(Serialize)]
struct LinkView {
    peer_id: String,
    link_id: String,
    initiator: &'static str,
    state: &'static str,
    peer_role: Option<&'static str>,
    bearer: &'static str,
    rtt_ms: Option<u64>,
    mdu: usize,
    established_ts: i64,
    streams: Vec<()>,
    counters: serde_json::Value,
}

pub async fn list(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let mdu = app.vpn_config.as_ref().map_or(799, |config| kaonic_mux::max_payload(config.max_packet));
    let now = std::time::Instant::now();
    let views = match app.links.get() {
        Some(links) => links.view().await,
        None => Vec::new(),
    };
    let links: Vec<LinkView> = views
        .into_iter()
        .filter(|view| !view.link_id.is_empty())
        .map(|view| LinkView {
            peer_id: view.peer,
            link_id: view.link_id,
            initiator: if view.initiator { "local" } else { "remote" },
            state: match view.state {
                "up" => "active",
                "authenticating" => "authenticating",
                _ => "pending",
            },
            peer_role: view.role,
            bearer: "radio",
            rtt_ms: view.rtt_ms,
            mdu,
            established_ts: crate::clock::now() - now.duration_since(view.since).as_secs() as i64,
            streams: Vec::new(),
            counters: serde_json::json!({}),
        })
        .collect();
    Ok(no_store(axum::Json(links)))
}
