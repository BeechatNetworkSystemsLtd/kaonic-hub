//! `/network/wifi*`: the Wi-Fi client manager and the hotspot.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Deserializer};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Caller, Role, Viewer};
use crate::clock;
use crate::error::{ApiError, ApiResult};
use crate::wifi::{WifiError, WifiView};

pub fn wifi_error(error: WifiError) -> ApiError {
    match error {
        WifiError::NotSaved => ApiError::not_found("This network is not saved."),
        WifiError::BadOrder => ApiError::field("ssids", "List every saved network exactly once."),
        WifiError::Invalid(field, message) => ApiError::field(field, message),
        WifiError::Unavailable(message) => ApiError::unavailable("not_running", message),
    }
}

/// The view for this caller: viewers never see the hotspot password.
fn shown(view: WifiView, caller: &Caller) -> Response {
    no_store(axum::Json(if caller.role == Role::Admin {
        view
    } else {
        view.for_viewer()
    }))
}

async fn audit(app: &App, action: &'static str, detail: String) {
    let now = clock::now();
    if let Err(error) = app
        .store
        .call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail))
        .await
    {
        log::error!("audit: {error}");
    }
}

pub async fn get_wifi(State(app): State<App>, Viewer(caller): Viewer) -> ApiResult<Response> {
    Ok(shown(app.wifi.get().await.map_err(wifi_error)?, &caller))
}

pub async fn scan_results(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(
        app.wifi.get().await.map_err(wifi_error)?.scan_results(),
    )))
}

pub async fn scan(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    let job = super::jobs::start_scan(&app).await?;
    let location = format!("/api/v1/jobs/{}", job.id);
    let mut response = no_store((StatusCode::ACCEPTED, axum::Json(job)));
    if let Ok(value) = axum::http::HeaderValue::from_str(&location) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, value);
    }
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinBody {
    ssid: String,
    password: Option<String>,
    #[serde(default)]
    hidden: bool,
}

pub async fn join(
    State(app): State<App>,
    Admin(caller): Admin,
    Json(body): Json<JoinBody>,
) -> ApiResult<Response> {
    let ssid = body.ssid.clone();
    let view = app
        .wifi
        .save(body.ssid, body.password, body.hidden)
        .await
        .map_err(wifi_error)?;
    audit(&app, "wifi.join", ssid).await;
    Ok(shown(view, &caller))
}

/// `null` and absent are different in a PATCH: absent keeps, null clears.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPatch {
    #[serde(default, deserialize_with = "present")]
    password: Option<Option<String>>,
    auto_connect: Option<bool>,
}

pub async fn patch_network(
    State(app): State<App>,
    Admin(caller): Admin,
    Path(ssid): Path<String>,
    Json(body): Json<NetworkPatch>,
) -> ApiResult<Response> {
    if body.password.is_none() && body.auto_connect.is_none() {
        return Err(ApiError::bad_request("Send at least one field to change."));
    }
    let view = app
        .wifi
        .patch(ssid.clone(), body.password, body.auto_connect)
        .await
        .map_err(wifi_error)?;
    audit(&app, "wifi.change", ssid).await;
    Ok(shown(view, &caller))
}

pub async fn forget(
    State(app): State<App>,
    Admin(caller): Admin,
    Path(ssid): Path<String>,
) -> ApiResult<Response> {
    let view = app.wifi.forget(ssid.clone()).await.map_err(wifi_error)?;
    audit(&app, "wifi.forget", ssid).await;
    Ok(shown(view, &caller))
}

pub async fn connect(
    State(app): State<App>,
    Admin(caller): Admin,
    Path(ssid): Path<String>,
) -> ApiResult<Response> {
    let view = app.wifi.connect(ssid.clone()).await.map_err(wifi_error)?;
    audit(&app, "wifi.connect", ssid).await;
    Ok(shown(view, &caller))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBody {
    ssids: Vec<String>,
}

pub async fn order(
    State(app): State<App>,
    Admin(caller): Admin,
    Json(body): Json<OrderBody>,
) -> ApiResult<Response> {
    let view = app.wifi.order(body.ssids).await.map_err(wifi_error)?;
    audit(&app, "wifi.order", String::new()).await;
    Ok(shown(view, &caller))
}

pub async fn unpin(State(app): State<App>, Admin(caller): Admin) -> ApiResult<Response> {
    Ok(shown(app.wifi.unpin().await.map_err(wifi_error)?, &caller))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotBody {
    ssid: String,
    password: Option<String>,
}

pub async fn set_hotspot(
    State(app): State<App>,
    Admin(caller): Admin,
    Json(body): Json<HotspotBody>,
) -> ApiResult<Response> {
    let ssid = body.ssid.clone();
    let view = app
        .wifi
        .set_hotspot(body.ssid, body.password)
        .await
        .map_err(wifi_error)?;
    audit(&app, "wifi.hotspot", ssid).await;
    Ok(shown(view, &caller))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntennaBody {
    antenna: String,
}

pub async fn set_antenna(
    State(app): State<App>,
    Admin(caller): Admin,
    Json(body): Json<AntennaBody>,
) -> ApiResult<Response> {
    let external = match body.antenna.as_str() {
        "internal" => false,
        "external" => true,
        _ => return Err(ApiError::field("antenna", "Use internal or external.")),
    };
    let view = app
        .wifi
        .set_antenna(external)
        .await
        .map_err(|error| match error {
            WifiError::Unavailable(message) => ApiError::conflict(message),
            other => wifi_error(other),
        })?;
    audit(&app, "wifi.antenna", body.antenna).await;
    Ok(shown(view, &caller))
}
