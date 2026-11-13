//! kaonic-hub: the service behind a Kaonic device's web UI.

pub mod api;
pub mod app;
pub mod auth;
pub mod boot;
pub mod clock;
pub mod error;
pub mod events;
pub mod group_key;
pub mod identity;
pub mod plugin_api;
pub mod plugins;
pub mod provision;
pub mod ptt;
pub mod secure;
pub mod random;
pub mod remote;
pub mod server;
pub mod system;
pub mod tls;
pub mod web;
pub mod wifi;


use axum::Router;
use axum::extract::DefaultBodyLimit;

/// The whole app: `/api/v1`, plugin pages (`/apps/`) and the web UI, with the security headers and a 64 KiB body limit.
pub fn router(app: app::App) -> Router {
    let webui = app.config.webui.clone();
    Router::new()
        .nest("/api/v1", api::router(app.clone()))
        .merge(plugins::proxy::router(app))
        .fallback_service(axum::routing::get(web::files).with_state(webui))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn(web::security_headers))
}
