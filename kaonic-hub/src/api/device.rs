//! `/device*` and `/system/*`.

use std::time::Duration;

use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kaonic_store::settings;
use serde::{Deserialize, Serialize};

use super::account::{CODENAME, NODE_IDENTITY, PasswordBody};
use super::{Json, Peer, client, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::identity::NodeIdentity;
use crate::{clock, random};

/// The API version this hub serves.
pub const API_VERSION: &str = "1.0";

#[derive(Serialize)]
struct Versions {
    hub: &'static str,
    os: String,
    webui: Option<String>,
}

#[derive(Serialize)]
struct DeviceView {
    serial: String,
    codename: String,
    hostname: String,
    model: String,
    identity_hash: String,
    api_version: &'static str,
    versions: Versions,
    uptime_secs: u64,
    radio_modules: u8,
    /// This device is the Kaonic Admin of its network.
    is_admin: bool,
}

/// This device as `GET /device` shows it, for the admin's view of a remote node.
pub(crate) async fn device_json(app: &App) -> ApiResult<serde_json::Value> {
    Ok(serde_json::to_value(device_view(app).await?)?)
}

async fn device_view(app: &App) -> ApiResult<DeviceView> {
    let codename = app
        .store
        .call(|c| settings::get(c, CODENAME))
        .await?
        .unwrap_or_default();
    let identity = app
        .secrets(|keys| {
            Ok(keys
                .get(NODE_IDENTITY)
                .map(|secret| secret.expose().to_vec()))
        })
        .await?;
    let identity_hash = match identity.and_then(|bytes| <[u8; 64]>::try_from(bytes).ok()) {
        Some(bytes) => NodeIdentity::from_bytes(&bytes).public().hash().to_hex(),
        None => String::new(),
    };
    Ok(DeviceView {
        serial: app.device.serial(),
        codename,
        hostname: app.device.hostname(),
        model: app.device.model(),
        identity_hash,
        api_version: API_VERSION,
        versions: Versions {
            hub: env!("CARGO_PKG_VERSION"),
            os: app.device.os_version(),
            webui: app.config.webui.version(),
        },
        uptime_secs: app.device.uptime_secs(),
        radio_modules: 2,
        is_admin: crate::provision::is_admin_device(app).await,
    })
}

pub async fn get_device(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(device_view(&app).await?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodenameBody {
    codename: String,
}

pub async fn set_codename(
    State(app): State<App>,
    _: Admin,
    Json(body): Json<CodenameBody>,
) -> ApiResult<Response> {
    set_codename_here(&app, body.codename, "admin").await?;
    Ok(no_store(axum::Json(device_view(&app).await?)))
}

/// Renames this device (from its own API, or from the admin over the mesh) and says so in the next announces.
pub(crate) async fn set_codename_here(app: &App, codename: String, actor: &'static str) -> ApiResult<()> {
    if codename.len() != 8
        || !codename
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ApiError::field(
            "codename",
            "Use exactly 8 lowercase letters or digits.",
        ));
    }
    let now = clock::now();
    app.store
        .call(move |c| {
            settings::set(c, CODENAME, &codename)?;
            kaonic_store::audit::record(c, now, actor, "device.codename", &codename)
        })
        .await?;
    if let (Some(mesh), Ok(info)) = (&app.mesh, super::node_info(app).await) {
        mesh.set_info(info);
    }
    Ok(())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RebootBody {
    #[serde(default)]
    mode: Option<String>,
}

/// The body is optional: none means a normal reboot.
pub async fn reboot(
    State(app): State<App>,
    _: Admin,
    body: axum::body::Bytes,
) -> ApiResult<Response> {
    let body: RebootBody = if body.is_empty() {
        RebootBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| ApiError::bad_request("Send {\"mode\":\"normal\"} or no body."))?
    };
    let mode = body.mode.unwrap_or_else(|| "normal".into());
    if mode != "normal" {
        // USB download mode needs the boot-mode switch from the BSP; not in this release.
        return Err(ApiError::field(
            "mode",
            "Only a normal reboot is available in this release.",
        ));
    }
    let now = clock::now();
    app.store
        .call(move |c| kaonic_store::audit::record(c, now, "admin", "device.reboot", ""))
        .await?;
    if !app.config.dev {
        // Answer first; the browser shows "restarting" rather than a dropped request.
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = tokio::process::Command::new("systemctl")
                .arg("reboot")
                .status()
                .await;
        });
    }
    Ok(no_store(StatusCode::ACCEPTED))
}

/// Erases everything the hub keeps and restarts it: the device comes back in setup with a new identity.
pub async fn factory_reset(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    _: Admin,
    Json(body): Json<PasswordBody>,
) -> ApiResult<Response> {
    auth::reconfirm(&app, client(peer), &body.password, "password").await?;
    schedule_factory_reset(&app, "the signed-in admin");
    Ok(no_store(StatusCode::ACCEPTED))
}

/// Erases everything the hub keeps and exits half a second later (after the answer is sent);
/// systemd (Restart=always) starts a fresh hub in setup. Logged to the journal first: the
/// audit log is erased with the rest. A dev hub (a laptop, the tests) only logs it.
pub(crate) fn schedule_factory_reset(app: &App, by: &str) {
    log::warn!("factory reset requested by {by}");
    if app.config.dev {
        log::warn!("dev mode: nothing is erased");
        return;
    }
    let state_dir = app.config.state_dir.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        erase_state(&state_dir);
        std::process::exit(0);
    });
}

/// Removes the database and the keystore, overwriting the keystore first so its key material is not left in free blocks.
fn erase_state(state_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(state_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("hub.db") || name.starts_with("keystore") {
            overwrite_and_remove(&entry.path());
        }
    }
}

/// Overwrites a file with noise, then removes it, so its contents are not left in free blocks.
fn overwrite_and_remove(path: &std::path::Path) {
    let Ok(length) = std::fs::metadata(path).map(|metadata| metadata.len()) else {
        return;
    };
    if let Ok(noise) = random::bytes::<4096>() {
        let mut data = Vec::with_capacity(length as usize);
        while (data.len() as u64) < length {
            data.extend_from_slice(&noise);
        }
        data.truncate(length as usize);
        let _ = std::fs::write(path, &data);
    }
    let _ = std::fs::remove_file(path);
}

pub async fn metrics(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(
        app.metrics.read(&app.device, &app.config.state_dir),
    )))
}

#[derive(Serialize)]
struct Service {
    unit: &'static str,
    name: &'static str,
    state: &'static str,
    version: Option<String>,
}

#[derive(Serialize)]
struct Services {
    services: Vec<Service>,
    ports: Vec<()>,
}

const CORE: &[(&str, &str)] = &[
    ("kaonic-hub.service", "Hub"),
    ("kaonic-commd.service", "Radio control"),
];

pub async fn services(State(_app): State<App>, _: Viewer) -> ApiResult<Response> {
    let mut services = Vec::new();
    for (unit, name) in CORE {
        let output = tokio::process::Command::new("systemctl")
            .args(["show", "-p", "ActiveState", "--value", unit])
            .output()
            .await;
        let state = match output
            .as_ref()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .as_deref()
        {
            Ok("active" | "activating" | "reloading") => "active",
            Ok("failed") => "failed",
            _ => "inactive",
        };
        let version = (*unit == "kaonic-hub.service").then(|| env!("CARGO_PKG_VERSION").to_owned());
        services.push(Service {
            unit,
            name,
            state,
            version,
        });
    }
    Ok(no_store(axum::Json(Services {
        services,
        ports: Vec::new(),
    })))
}

/// The HTTPS CA, so a browser can trust this device. Public: it is a certificate, not a key.
pub async fn root_ca(State(app): State<App>) -> ApiResult<Response> {
    let pem = app
        .ca_pem
        .get()
        .cloned()
        .ok_or_else(|| ApiError::not_found("This device serves no HTTPS certificate."))?;
    let mut response = (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-x509-ca-cert",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"kaonic-rootca.crt\"",
            ),
        ],
        pem,
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
