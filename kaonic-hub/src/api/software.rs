//! The hub's and the installer's own updates, and the history of plugins and updates.
//!
//! The two update each other: the installer updates the hub (it restarts us and puts the
//! old hub back if the new one does not come up), the hub updates the installer (here: it
//! restarts the installer and puts the old one back if it does not answer). Each update
//! needs the admin's password again.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::body::Body;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::Mutex;

use super::plugins::{actor, audit, error};
use super::{Peer, client, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::plugins::upload;

const HUB: &str = "kaonic-hub";
const INSTALLER: &str = "kaonic-hub-installer";

/// One installer update at a time.
static UPDATING: Mutex<()> = Mutex::const_new(());

/// `GET /software`: what runs, the updated copies, and the last hub update.
pub async fn get(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let installer = &app.plugins().installer;
    let installer_version = installer.health().await.ok();
    let core = installer.core().await.ok();
    let hub_job = installer.hub_job().await.ok().flatten();
    let release_key = installer.policy_view().await.ok().and_then(|policy| policy.get("release_key").and_then(serde_json::Value::as_bool));
    let from_update = std::env::var("KAONIC_CORE_EXEC").is_ok_and(|value| value == HUB);
    Ok(no_store(axum::Json(serde_json::json!({
        "hub": { "version": env!("CARGO_PKG_VERSION"), "from_update": from_update },
        "installer": { "version": installer_version, "reachable": installer_version.is_some() },
        "core": core,
        "programs": programs(&app).await,
        "hub_update": hub_job,
        "release_key": release_key,
    }))))
}

/// commd and the factory server: whether they run, their version, and whether it is the update.
async fn programs(app: &App) -> Vec<serde_json::Value> {
    let core_dir = app.plugins().settings.core_dir.clone();
    tokio::task::spawn_blocking(move || {
        use kaonic_hub_installer::host::Host;
        let host = kaonic_hub_installer::host::System;
        kaonic_hub_installer::names::LAUNCHED
            .iter()
            .map(|id| {
                let running = host.main_process(&format!("{id}.service")).is_some();
                let from_update = kaonic_hub_installer::core::runs_update(&core_dir, &host, id, std::time::Duration::ZERO);
                let record = kaonic_hub_installer::core::Core::record_in(&core_dir, id);
                let version = if from_update { record.map(|record| record.version) } else { image_version(id) };
                let about = kaonic_hub_installer::core::describe(&core_dir, std::path::Path::new(kaonic_hub_installer::core::IMAGE_FILES), id).map(|(manifest, _)| manifest);
                serde_json::json!({
                    "id": id,
                    "name": about.as_ref().map_or_else(|| (*id).to_owned(), |manifest| manifest.name.clone()),
                    "description": about.map(|manifest| manifest.description).unwrap_or_default(),
                    "running": running,
                    "version": version,
                    "from_update": from_update,
                })
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// The version the system image's copy of `id` says it is, in `/etc/kaonic/<id>.version`
/// (`<id>-version=...`, written by its Yocto recipe).
fn image_version(id: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/etc/kaonic/{id}.version")).ok()?;
    text.lines().find_map(|line| line.strip_prefix(&format!("{id}-version=")).map(|version| version.trim().to_owned()))
}

/// `POST /software/hub`: multipart `file`, `password`, `allow_downgrade`. Answers 202: the
/// installer restarts the hub with it, so the outcome is read from `GET /software` after.
pub async fn update_hub(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, headers: HeaderMap, body: Body) -> ApiResult<Response> {
    let client = client(peer);
    let form = upload::read(&app.config.state_dir, &headers, body).await?;
    let file = form.file.ok_or_else(|| ApiError::field("file", "Choose a hub package."))?;
    auth::reconfirm(&app, client, form.password.as_deref().unwrap_or_default(), "password").await?;
    // On its own task: the audit row is written even if this request is cut short.
    let task = tokio::spawn(async move {
        let job = app.plugins().installer.update_hub(file.path(), form.allow_downgrade, Some(&actor(client))).await;
        if let Ok(job) = &job {
            audit(&app, "software.hub", format!("update to {} started", job.version)).await;
        }
        job
    });
    let job = task.await.map_err(|_| ApiError::internal())?.map_err(error)?;
    Ok((StatusCode::ACCEPTED, no_store(axum::Json(job))).into_response())
}

/// The release keys core updates must be signed with. No key file is a development device,
/// which takes unsigned updates; a key that cannot be read refuses the update.
fn release_keys(path: &Path) -> ApiResult<Vec<Vec<u8>>> {
    kaonic_hub_installer::core::read_release_keys(&[path.to_owned()]).map_err(|error| {
        log::error!("software: {}", error.message);
        ApiError::unavailable("release_key_unreadable", "The device's release key cannot be read, so no update is taken.")
    })
}

/// `POST /software/installer`: multipart `file`, `password`, `allow_downgrade`. The hub
/// swaps the installer, restarts it and waits for it (up to two minutes); if it does not
/// answer at the new version, the previous installer goes back.
pub async fn update_installer(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, headers: HeaderMap, body: Body) -> ApiResult<Response> {
    let client = client(peer);
    let form = upload::read(&app.config.state_dir, &headers, body).await?;
    let file = form.file.ok_or_else(|| ApiError::field("file", "Choose an installer package."))?;
    auth::reconfirm(&app, client, form.password.as_deref().unwrap_or_default(), "password").await?;
    let one = UPDATING.try_lock().map_err(|_| ApiError::conflict("An installer update is already running."))?;

    let settings = app.plugins().settings.clone();
    let release_keys = release_keys(&settings.release_key)?;
    let actor = actor(client);
    let allow_downgrade = form.allow_downgrade;
    // The update, the lock and the audit row live on their own task: cutting this request
    // short neither frees the lock early nor loses the row.
    let task = tokio::spawn(async move {
        let _one = one;
        let plugins = app.plugins().clone();
        let runtime = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            use kaonic_hub_installer::{Error, Kind};
            let mut package = std::fs::File::open(file.path()).map_err(|why| Error::new(Kind::Failed, format!("reading the upload: {why}")))?;
            let host: Arc<dyn kaonic_hub_installer::host::Host> = Arc::new(kaonic_hub_installer::host::System);
            let core = kaonic_hub_installer::core::Core::new(&settings.core_dir, &settings.installer_state, release_keys, host)?;
            let healthy = |version: &str| runtime.block_on(async { plugins.installer.health().await.is_ok_and(|running| running == version) });
            core.update(INSTALLER, &mut package, allow_downgrade, Some(&actor), &healthy, kaonic_hub_installer::core::START_TIMEOUT)
        })
        .await;
        app.plugins().changed();
        match &result {
            Ok(Ok(record)) => audit(&app, "software.installer", format!("updated to {}", record.version)).await,
            Ok(Err(failure)) => audit(&app, "software.installer", format!("update failed: {}", failure.message)).await,
            Err(_) => audit(&app, "software.installer", "update failed: it stopped".into()).await,
        }
        result
    });
    let result = task.await.map_err(|_| ApiError::internal())?.map_err(|_| ApiError::internal())?;
    result.map(|record| no_store(axum::Json(record))).map_err(core_failure)
}

fn core_failure(failure: kaonic_hub_installer::Error) -> ApiError {
    match failure.kind {
        kaonic_hub_installer::Kind::Invalid => ApiError::field("file", failure.message),
        kaonic_hub_installer::Kind::Conflict => ApiError::conflict(failure.message),
        kaonic_hub_installer::Kind::Downgrade => ApiError::new(StatusCode::CONFLICT, "downgrade", failure.message),
        kaonic_hub_installer::Kind::Forbidden => ApiError::forbidden("refused", failure.message),
        kaonic_hub_installer::Kind::NotFound => ApiError::not_found(failure.message),
        kaonic_hub_installer::Kind::Failed => ApiError::new(StatusCode::BAD_GATEWAY, "update_failed", failure.message),
    }
}

/// `POST /software/core/{id}`: multipart `file`, `password`, `allow_downgrade`, for
/// `kaonic-commd` or `kaonic-factory`. The hub swaps the program, restarts its service and
/// waits until the service runs the update and stays up; if it does not within two minutes,
/// the previous version goes back.
pub async fn update_launched(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, UrlPath(id): UrlPath<String>, headers: HeaderMap, body: Body) -> ApiResult<Response> {
    if !kaonic_hub_installer::names::is_launched(&id) {
        return Err(ApiError::not_found("Only kaonic-commd and kaonic-factory are updated here."));
    }
    let client = client(peer);
    let form = upload::read(&app.config.state_dir, &headers, body).await?;
    let file = form.file.ok_or_else(|| ApiError::field("file", "Choose a package."))?;
    auth::reconfirm(&app, client, form.password.as_deref().unwrap_or_default(), "password").await?;
    let one = UPDATING.try_lock().map_err(|_| ApiError::conflict("Another update is already running."))?;

    let settings = app.plugins().settings.clone();
    let release_keys = release_keys(&settings.release_key)?;
    let actor = actor(client);
    let allow_downgrade = form.allow_downgrade;
    // On its own task, as for the installer: a cut request frees neither the lock nor loses the row.
    let task = tokio::spawn(async move {
        let _one = one;
        let program = id.clone();
        let result = tokio::task::spawn_blocking(move || {
            use kaonic_hub_installer::{Error, Kind};
            let mut package = std::fs::File::open(file.path()).map_err(|why| Error::new(Kind::Failed, format!("reading the upload: {why}")))?;
            let host: Arc<dyn kaonic_hub_installer::host::Host> = Arc::new(kaonic_hub_installer::host::System);
            let core = kaonic_hub_installer::core::Core::new(&settings.core_dir, &settings.installer_state, release_keys, host.clone())?;
            let healthy = |_: &str| kaonic_hub_installer::core::runs_update(&settings.core_dir, host.as_ref(), &program, kaonic_hub_installer::core::LAUNCHED_SETTLE);
            core.update(&program, &mut package, allow_downgrade, Some(&actor), &healthy, kaonic_hub_installer::core::START_TIMEOUT)
        })
        .await;
        app.plugins().changed();
        match &result {
            Ok(Ok(record)) => audit(&app, "software.core", format!("{id} updated to {}", record.version)).await,
            Ok(Err(failure)) => audit(&app, "software.core", format!("{id} update failed: {}", failure.message)).await,
            Err(_) => audit(&app, "software.core", format!("{id} update failed: it stopped")).await,
        }
        result
    });
    let result = task.await.map_err(|_| ApiError::internal())?.map_err(|_| ApiError::internal())?;
    result.map(|record| no_store(axum::Json(record))).map_err(core_failure)
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    id: Option<String>,
    limit: Option<usize>,
}

/// `GET /software/history[?id=&limit=]`: plugin and update events, newest first.
pub async fn history(State(app): State<App>, _: Admin, Query(query): Query<HistoryQuery>) -> ApiResult<Response> {
    let limit = query.limit.unwrap_or(100).min(kaonic_hub_installer::history::KEEP);
    let events = app.plugins().installer.history(query.id.as_deref(), limit).await.map_err(error)?;
    Ok(no_store(axum::Json(events)))
}

/// After start: clears our failed-start count and tells the installer we are up (a hub
/// update waits for this). Retried while the installer is starting too.
pub fn report_ready(app: &App) {
    kaonic_hub_installer::core::healthy(&app.plugins().settings.core_dir, HUB);
    let plugins = app.plugins().clone();
    tokio::spawn(async move {
        for _ in 0..40 {
            match plugins.installer.hub_ready(env!("CARGO_PKG_VERSION")).await {
                Ok(()) => return,
                Err(_) => tokio::time::sleep(Duration::from_secs(3)).await,
            }
        }
        log::warn!("software: could not tell the installer this hub is up");
    });
}
