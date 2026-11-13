//! The icons of the core programs, for the plugins and System pages. The hub and the installer
//! have theirs built in; any other core program brings its own (its update, or the system image's
//! copy in `kaonic_hub_installer::core::IMAGE_FILES`).

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

/// `GET /software/{id}/icon`: the icon the program brings (its update's, else the image's), else
/// the built-in one of the hub or the installer.
pub async fn icon(State(app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    if !kaonic_hub_installer::names::is_core(&id) {
        return Err(ApiError::not_found("Only the core programs have icons here."));
    }
    let built_in = match id.as_str() {
        "kaonic-hub" => Some(HUB),
        "kaonic-hub-installer" => Some(INSTALLER),
        _ => None,
    };
    let core_dir = app.plugins().settings.core_dir.clone();
    let brought = tokio::task::spawn_blocking(move || {
        let (manifest, dir) = kaonic_hub_installer::core::describe(&core_dir, std::path::Path::new(kaonic_hub_installer::core::IMAGE_FILES), &id)?;
        read_icon(&dir.join(manifest.icon?))
    })
    .await
    .map_err(|_| ApiError::internal())?;
    let bytes = brought.or_else(|| built_in.map(<[u8]>::to_vec)).ok_or_else(|| ApiError::not_found("This program has no icon."))?;
    let mut response = ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "no-cache")], bytes).into_response();
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'"));
    Ok(response)
}
