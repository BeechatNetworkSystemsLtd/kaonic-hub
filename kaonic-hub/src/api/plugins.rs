//! `/plugins`: installed plugins, through `kaonic-hub-installer` (`crate::plugins`).
//!
//! Anyone signed in may look and open a plugin's page; installing, updating, removing,
//! starting, stopping, rolling back and the install policy need the admin, and installing,
//! updating and the policy the password again. The installer checks packages; the hub
//! decides who may ask. Packages are streamed to a file (`crate::plugins::upload`) and from
//! it to the installer.

use std::io::Read;
use std::net::IpAddr;

use axum::Extension;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use kaonic_hub_installer::manifest::Permission;
use kaonic_hub_installer::records::Policy;
use serde::{Deserialize, Serialize};

use super::{Json, Peer, client, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::plugin_api::wire;
use crate::plugins::{Failure, Installed, upload};

/// The largest icon shown.
const MAX_ICON: u64 = 512 * 1024;
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

#[derive(Serialize)]
pub struct PluginView {
    id: String,
    name: String,
    version: String,
    description: String,
    developer: String,
    /// Signed by a Beechat release key, as the installer checked.
    official: bool,
    running: bool,
    /// Started when the device starts.
    enabled: bool,
    removable: bool,
    has_icon: bool,
    /// Its page under the hub, if it has one.
    app_url: Option<String>,
    channel: Option<String>,
    url: Option<String>,
    permissions: Vec<Permission>,
    service: String,
    installed_ts: u64,
    highest_version: String,
    /// The version a rollback goes back to.
    previous_version: Option<String>,
}

fn view(plugin: &Installed) -> PluginView {
    let record = &plugin.record;
    let manifest = &record.manifest;
    PluginView {
        id: manifest.id.clone(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        description: manifest.description.clone(),
        developer: manifest.developer.clone(),
        official: record.signed,
        running: plugin.running,
        enabled: record.enabled,
        removable: true,
        has_icon: manifest.icon.is_some(),
        app_url: manifest.page.then(|| format!("/apps/{}/", manifest.id)),
        channel: manifest.channel.clone(),
        url: manifest.url.clone(),
        permissions: manifest.permissions.clone(),
        service: kaonic_hub_installer::unit::name(&manifest.id),
        installed_ts: record.installed_at,
        highest_version: record.highest_version.clone(),
        previous_version: record.previous.as_ref().map(|previous| previous.manifest.version.clone()),
    }
}

/// The installer's errors as the API's.
pub fn error(failure: Failure) -> ApiError {
    match failure.status {
        404 => ApiError::not_found(failure.message),
        // An older version than one installed before: the UI offers "allow a downgrade".
        409 if failure.code == "downgrade" => ApiError::new(StatusCode::CONFLICT, "downgrade", failure.message),
        409 => ApiError::conflict(failure.message),
        403 => ApiError::forbidden("refused", failure.message),
        422 | 400 => {
            let mut api = ApiError::field("file", failure.message.clone());
            api.message = failure.message;
            api
        }
        0 | 401 => {
            log::warn!("plugins: {failure}");
            ApiError::unavailable("installer_unavailable", "The plugin installer is not running. Try again in a moment.")
        }
        _ => ApiError::new(StatusCode::BAD_GATEWAY, "plugin_failed", failure.message),
    }
}

/// How the installer's history names who asked: the hub has one admin account, so its
/// address tells requests apart.
pub fn actor(client: IpAddr) -> String {
    format!("admin ({client})")
}

pub(crate) async fn audit(app: &App, action: &'static str, detail: String) {
    let now = crate::clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail)).await;
}

/// `GET /plugins`
pub async fn list(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let list = app.plugins().list().await.map_err(error)?;
    Ok(no_store(axum::Json(list.iter().map(view).collect::<Vec<_>>())))
}

/// `GET /plugins/{id}`
pub async fn get(State(app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    let plugin = app.plugins().installer.get(&id).await.map_err(error)?;
    Ok(no_store(axum::Json(view(&plugin))))
}

/// `GET /plugins/{id}/icon`: the PNG from the installed package, never a file the plugin can write.
pub async fn icon(State(app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    let no_icon = || ApiError::not_found("This plugin has no icon.");
    let plugin = app.plugins().find(&id, |_| true).await.ok_or_else(|| ApiError::not_found("No plugin with that id is installed."))?;
    let icon = plugin.record.manifest.icon.clone().ok_or_else(no_icon)?;
    if !icon.starts_with("files/") || kaonic_hub_installer::names::relative_path(&icon).is_err() {
        return Err(no_icon());
    }
    let path = app.plugins().settings.dir.join(plugin.id()).join("current").join(&icon);
    let bytes = tokio::task::spawn_blocking(move || read_icon(&path)).await.map_err(|_| ApiError::internal())?.ok_or_else(no_icon)?;
    let mut response = ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "no-cache")], bytes).into_response();
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'"));
    Ok(response)
}

/// A regular file, not through a symlink, small, and a PNG.
pub(crate) fn read_icon(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_ICON {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_ICON).read_to_end(&mut bytes).ok()?;
    bytes.starts_with(PNG).then_some(bytes)
}

/// `POST /plugins`: multipart `file` (the package), `password` and optionally `allow_downgrade`.
pub async fn install(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    _: Admin,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let plugin = install_package(&app, client(peer), &headers, body, None).await?;
    let action = if plugin.record.previous.is_some() { "updated" } else { "installed" };
    Ok(no_store(axum::Json(serde_json::json!({ "action": action, "plugin": view(&plugin) }))))
}

/// `PUT /plugins/{id}/package`: an update of that plugin only.
pub async fn update(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    _: Admin,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    app.plugins().installer.get(&id).await.map_err(error)?;
    let plugin = install_package(&app, client(peer), &headers, body, Some(id)).await?;
    Ok(no_store(axum::Json(view(&plugin))))
}

async fn install_package(app: &App, client: IpAddr, headers: &HeaderMap, body: Body, expected: Option<String>) -> ApiResult<Installed> {
    let form = upload::read(&app.config.state_dir, headers, body).await?;
    let file = form.file.ok_or_else(|| ApiError::field("file", "Choose a plugin package to install."))?;
    auth::reconfirm(app, client, form.password.as_deref().unwrap_or_default(), "password").await?;
    let plugins = app.plugins();
    let checked = plugins.installer.check(file.path()).await.map_err(error)?;
    let id = &checked.manifest.id;
    if let Some(expected) = expected
        && *id != expected
    {
        return Err(ApiError::field("file", format!("This package is the plugin {id}, not {expected}.")));
    }
    // The installer refuses this too: a plugin whose mesh name is another's would get its messages.
    let installed = plugins.refresh().await.map_err(error)?;
    if let Some(other) = installed.iter().find(|other| other.id() != id && wire::id_hash(other.id()) == wire::id_hash(id)) {
        return Err(ApiError::conflict(format!("The plugin {id} has the same mesh name as {}, which is installed.", other.id())));
    }
    let result = plugins.installer.install(file.path(), form.allow_downgrade, Some(&actor(client))).await;
    plugins.changed();
    let plugin = result.map_err(error)?;
    let what = if plugin.record.previous.is_some() { "plugin.update" } else { "plugin.install" };
    let signed = if plugin.record.signed { "signed" } else { "unsigned" };
    audit(app, what, format!("{} {} ({signed}, sha256 {})", plugin.id(), plugin.record.manifest.version, file.sha256())).await;
    Ok(plugin)
}

#[derive(Deserialize)]
pub struct RemoveQuery {
    #[serde(default)]
    keep_data: bool,
}

/// `DELETE /plugins/{id}[?keep_data=true]`
pub async fn remove(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, Path(id): Path<String>, Query(query): Query<RemoveQuery>) -> ApiResult<Response> {
    let plugins = app.plugins();
    let result = plugins.installer.remove(&id, query.keep_data, Some(&actor(client(peer)))).await;
    plugins.changed();
    result.map_err(error)?;
    plugins.bridge.forget(&id);
    if !query.keep_data {
        let plugin = id.clone();
        let _ = app.store.call(move |c| kaonic_store::plugin_store::delete_all(c, &plugin)).await;
    }
    let kept = if query.keep_data { ", data kept" } else { "" };
    audit(&app, "plugin.remove", format!("{id}{kept}")).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /plugins/{id}/{start|stop|restart|rollback}`
pub async fn action(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, Path((id, action)): Path<(String, String)>) -> ApiResult<Response> {
    if !matches!(action.as_str(), "start" | "stop" | "restart" | "rollback") {
        return Err(ApiError::not_found("Use start, stop, restart or rollback."));
    }
    let plugins = app.plugins();
    let result = plugins.installer.act(&id, &action, Some(&actor(client(peer)))).await;
    plugins.changed();
    let plugin = result.map_err(error)?;
    let what = if action == "rollback" { "plugin.rollback" } else { "plugin.control" };
    audit(&app, what, format!("{id} {action} ({})", plugin.record.manifest.version)).await;
    Ok(no_store(axum::Json(view(&plugin))))
}

/// `POST /plugins/{id}/open`: a ticket to the plugin's page, as a URL to load in the frame.
pub async fn open(State(app): State<App>, Viewer(caller): Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    let plugin = app.plugins().find(&id, |_| true).await.ok_or_else(|| ApiError::not_found("No plugin with that id is installed."))?;
    if !plugin.record.manifest.page {
        return Err(ApiError::not_found("This plugin has no page."));
    }
    let ticket = app.plugins().tickets.mint(plugin.id(), &caller.token_hash)?;
    let url = format!("/apps/{}/{}{ticket}/", plugin.id(), crate::plugins::tickets::MARK);
    let expires_in = crate::plugins::tickets::LIFETIME.as_secs();
    Ok(no_store(axum::Json(serde_json::json!({ "url": url, "expires_in_secs": expires_in }))))
}

/// `GET /plugin-policy`: `require_signed`, and `release_key` (false on a development device).
pub async fn policy(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let policy = app.plugins().installer.policy_view().await.map_err(error)?;
    Ok(no_store(axum::Json(policy)))
}

/// `POST /plugin-check`: multipart `file`. What the package is and asks for (its
/// permissions), and whether it is signed, without installing it; the UI shows this before
/// asking for the password.
pub async fn check(State(app): State<App>, _: Admin, headers: HeaderMap, body: Body) -> ApiResult<Response> {
    let form = upload::read(&app.config.state_dir, &headers, body).await?;
    let file = form.file.ok_or_else(|| ApiError::field("file", "Choose a plugin package."))?;
    let checked = app.plugins().installer.check(file.path()).await.map_err(error)?;
    let manifest = &checked.manifest;
    Ok(no_store(axum::Json(serde_json::json!({
        "id": manifest.id,
        "name": manifest.name,
        "version": manifest.version,
        "developer": manifest.developer,
        "description": manifest.description,
        "permissions": manifest.permissions,
        "page": manifest.page,
        "signed": checked.signed,
        "installed": app.plugins().find(&manifest.id, |_| true).await.map(|plugin| plugin.record.manifest.version.clone()),
    }))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChange {
    require_signed: bool,
    password: String,
}

/// `PUT /plugin-policy`: the password again, as it decides what may be installed.
pub async fn set_policy(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, Json(change): Json<PolicyChange>) -> ApiResult<Response> {
    auth::reconfirm(&app, client(peer), &change.password, "password").await?;
    let policy = app.plugins().installer.set_policy(&Policy { require_signed: change.require_signed }).await.map_err(error)?;
    audit(&app, "plugin.policy", format!("require_signed {}", policy.require_signed)).await;
    // The same shape as GET, with release_key.
    let view = app.plugins().installer.policy_view().await.map_err(error)?;
    Ok(no_store(axum::Json(view)))
}
