//! `/api/v1`: the routes of the API that this release serves.

mod account;
pub mod boot;
pub(crate) mod device;
mod events;
mod forward;
mod jobs;
mod links;
mod network;
mod peers;
mod core_icons;
mod report;
mod plugins;
pub mod software;
mod ptt;
pub mod radio;
pub mod radio_bands;
mod remote;
pub mod vpn;
mod wifi;

use std::net::SocketAddr;

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Router};
use serde::de::DeserializeOwned;

pub use account::{BOOT_IDENTITY, NODE_IDENTITY, TRUST_ALLOWLIST, TRUST_OWN, TRUST_ROOT};
pub use account::{node_info, our_admin};
pub use jobs::Jobs;
pub use network::state as network_state;
pub use peers::publish as publish_peer;

use crate::app::App;
use crate::error::ApiError;

/// The address of the client and the address it reached us on, set per connection.
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub remote: SocketAddr,
    pub local: SocketAddr,
}

pub fn router(app: App) -> Router {
    Router::new()
        // setup and auth
        .route("/setup/identity", get(account::setup_identity))
        .route("/setup/derive-identity", post(account::derive_identity))
        .route("/setup", post(account::setup))
        .route("/auth/state", get(account::state))
        .route("/auth/login", post(account::login))
        .route("/auth/logout", post(account::logout))
        .route("/auth/forgot", get(account::forgot_methods))
        .route("/auth/forgot/factory-reset", post(account::forgot_reset))
        .route("/auth/password", put(account::change_password))
        // device and system
        .route("/device", get(device::get_device))
        .route("/device/codename", put(device::set_codename))
        .route("/device/rootca", get(device::root_ca))
        .route("/device/reboot", post(device::reboot))
        .route("/device/factory-reset", post(device::factory_reset))
        .route("/system/metrics", get(device::metrics))
        .route("/system/services", get(device::services))
        .route("/system/report", get(report::get))
        // A/B boot slots and kernel install
        .route("/system/boot", get(boot::get))
        .route("/system/boot/next", put(boot::set_next))
        .route(
            "/system/boot/kernel/upload",
            post(boot::upload).layer(axum::extract::DefaultBodyLimit::max(crate::boot::KERNEL_MAX + 1024)),
        )
        .route("/system/boot/kernel/staged", get(boot::staged).delete(boot::discard))
        .route("/system/boot/kernel/install", post(boot::install))
        // network and Wi-Fi
        .route(
            "/network",
            get(network::get_network).patch(network::patch_network),
        )
        .route("/network/wifi", get(wifi::get_wifi))
        .route(
            "/network/wifi/scan",
            get(wifi::scan_results).post(wifi::scan),
        )
        .route("/network/wifi/networks", post(wifi::join))
        .route(
            "/network/wifi/networks/{ssid}",
            patch(wifi::patch_network).delete(wifi::forget),
        )
        .route("/network/wifi/networks/{ssid}/connect", post(wifi::connect))
        .route("/network/wifi/order", put(wifi::order))
        .route("/network/wifi/pin", delete(wifi::unpin))
        .route("/network/wifi/hotspot", put(wifi::set_hotspot))
        .route("/network/wifi/antenna", put(wifi::set_antenna))
        // mesh
        .route("/peers", get(peers::list))
        .route("/peers/{peer_id}/list", put(peers::set_list))
        .route("/peers/{peer_id}/remote/device", get(remote::device))
        .route("/peers/{peer_id}/remote/codename", put(remote::codename))
        .route("/peers/{peer_id}/remote/radio/bands/{band}", put(remote::radio_band))
        .route("/peers/{peer_id}/remote/ptt", patch(remote::ptt))
        .route("/peers/{peer_id}/remote/shell", get(remote::shell))
        .route("/peers/{peer_id}/remote/shell/ticket", post(remote::shell_ticket))
        .route("/remote/jobs", post(remote::start_jobs))
        .route("/bearers", get(peers::bearers))
        .route("/radio/bands", get(radio_bands::list))
        .route("/radio/bands/{band}", get(radio_bands::get).put(radio_bands::put))
        .route("/radio/bands/{band}/filter", put(radio_bands::put_filter))
        .route("/radio/stats", get(radio::stats))
        .route("/radio/frames", get(radio::frames))
        .route("/links", get(links::list))
        .route("/ptt", get(ptt::get))
        .route("/ptt/settings", patch(ptt::patch_settings))
        .route("/ptt/test-tone", post(ptt::test_tone))
        .route("/ptt/devices", get(ptt::devices))
        .route("/ptt/key", post(ptt::key))
        .route("/ptt/unkey", post(ptt::unkey))
        .route(
            "/ptt/test/wav",
            get(ptt::test_wav)
                .put(ptt::put_test_wav)
                .delete(ptt::delete_test_wav)
                // The one route with a large body: a test recording.
                .layer(axum::extract::DefaultBodyLimit::max(crate::ptt::wav::MAX_BYTES + 1024)),
        )
        .route("/ptt/test/tx", post(ptt::test_tx))
        .route("/ptt/test/tx/stop", post(ptt::stop_test_tx))
        .route("/ptt/sessions", post(ptt::create_session))
        .route("/ptt/audio", get(ptt::audio))
        .route("/vpn", get(vpn::get))
        .route("/vpn/settings", patch(vpn::patch_settings))
        .route("/vpn/routes", put(vpn::put_routes))
        .route("/vpn/uplink", put(vpn::put_uplink))
        .route("/vpn/gateway", put(vpn::put_gateway))
        .route("/vpn/forward", get(forward::get).put(forward::put))
        .route("/vpn/packets", get(vpn::packets))
        .route("/vpn/capture", get(vpn::capture_state).post(vpn::capture_start))
        .route("/vpn/capture/stop", post(vpn::capture_stop))
        .route("/vpn/capture/packets", get(vpn::capture_packets))
        .route("/vpn/capture.pcap", get(vpn::capture_pcap))
        // plugins (crate::plugins, through the installer); a package upload is streamed to a
        // file within its own limit (crate::plugins::upload)
        .route("/plugins", get(plugins::list).post(plugins::install))
        .route("/plugin-check", post(plugins::check))
        .route("/plugins/{plugin_id}", get(plugins::get).delete(plugins::remove))
        .route("/plugins/{plugin_id}/package", put(plugins::update))
        .route("/plugins/{plugin_id}/icon", get(plugins::icon))
        .route("/plugins/{plugin_id}/open", post(plugins::open))
        .route("/plugins/{plugin_id}/{action}", post(plugins::action))
        .route("/plugin-policy", get(plugins::policy).put(plugins::set_policy))
        // the hub's and the installer's own updates
        .route("/software", get(software::get))
        .route("/software/hub", post(software::update_hub))
        .route("/software/installer", post(software::update_installer))
        .route("/software/history", get(software::history))
        .route("/software/{id}/icon", get(core_icons::icon))
        // jobs and events
        .route("/jobs", get(jobs::list))
        .route("/jobs/{id}", get(jobs::get_job))
        .route("/events", get(events::socket))
        .fallback(not_here)
        .with_state(app)
}

/// Everything else under `/api/v1`: either not in v1, or not in this release yet.
async fn not_here() -> ApiError {
    ApiError::not_found("This device does not offer that yet.")
}

/// JSON request bodies: unknown fields, wrong types and bad syntax become the API's error shape.
pub struct Json<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let status = rejection.status();
                let message = rejection.body_text();
                Err(if status == StatusCode::UNPROCESSABLE_ENTITY {
                    // serde: "unknown field `x`", "invalid type…": say which, without echoing values.
                    ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "validation_failed",
                        short_serde(&message),
                    )
                } else if status == StatusCode::PAYLOAD_TOO_LARGE {
                    ApiError::new(status, "payload_too_large", "The request is too large.")
                } else {
                    ApiError::bad_request("Send a JSON body with Content-Type: application/json.")
                })
            }
        }
    }
}

fn short_serde(message: &str) -> String {
    let detail = message.rsplit(": ").next().unwrap_or(message);
    let detail = detail.split(" at line").next().unwrap_or(detail);
    format!("The request is not valid: {detail}.")
}

/// A response with `Cache-Control: no-store`, as every API answer must be.
pub fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// The client address of a request (set by the server per connection; loopback in tests).
pub fn client(peer: Option<Extension<Peer>>) -> std::net::IpAddr {
    peer.map_or(std::net::IpAddr::from([127, 0, 0, 1]), |Extension(peer)| {
        peer.remote.ip()
    })
}
