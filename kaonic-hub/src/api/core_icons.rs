//! The icons of the hub and the installer, for the plugins and System pages.

use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use super::plugins::read_icon;
use crate::app::App;
use crate::auth::Viewer;
use crate::error::{ApiError, ApiResult};

/// Built in, for when no updated copy brings its own.
const HUB: &[u8] = include_bytes!("../../files/icon.png");
const INSTALLER: &[u8] = include_bytes!("../../../kaonic-hub-installer/files/icon.png");

/// `GET /software/{id}/icon`: the updated copy's icon if it has one, else the built-in one.
pub async fn icon(State(app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    let built_in = match id.as_str() {
        "kaonic-hub" => HUB,
        "kaonic-hub-installer" => INSTALLER,
        _ => return Err(ApiError::not_found("Only kaonic-hub and kaonic-hub-installer have icons here.")),
    };
    let path = app.plugins().settings.core_dir.join(&id).join("current/files/icon.png");
    let updated = tokio::task::spawn_blocking(move || read_icon(&path)).await.map_err(|_| ApiError::internal())?;
    let bytes = updated.unwrap_or_else(|| built_in.to_vec());
    let mut response = ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "no-cache")], bytes).into_response();
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'"));
    Ok(response)
}
