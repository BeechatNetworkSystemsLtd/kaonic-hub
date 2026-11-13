//! `/network`: the sources and consumers this release manages (the Wi-Fi client and the hotspot).

use axum::extract::State;
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::{Json, no_store, wifi::wifi_error};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::wifi::WifiView;

#[derive(Serialize)]
pub struct Port {
    id: &'static str,
    enabled: bool,
    status: &'static str,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    clients: Option<u32>,
}

#[derive(Serialize)]
pub struct NetworkState {
    active_source: Option<&'static str>,
    sources: Vec<Port>,
    consumers: Vec<Port>,
    lan: Lan,
}

#[derive(Serialize)]
struct Lan {
    address: String,
    subnet: String,
}

/// Not managed by this release yet: shown as off, and refused when switched on.
fn not_yet(id: &'static str, clients: Option<u32>) -> Port {
    Port {
        id,
        enabled: false,
        status: "off",
        detail: "Not available in this release yet".into(),
        clients,
    }
}

pub fn state(wifi: &WifiView) -> NetworkState {
    let client = &wifi.client;
    let (status, detail) = match client.state {
        "connected" => (
            "active",
            format!(
                "\"{}\"{}",
                client.ssid.clone().unwrap_or_default(),
                client
                    .signal_dbm
                    .map(|dbm| format!(" at {dbm} dBm"))
                    .unwrap_or_default()
            ),
        ),
        "connecting" => (
            "waiting",
            format!("Joining \"{}\"", client.ssid.clone().unwrap_or_default()),
        ),
        "searching" if wifi.saved.is_empty() => ("waiting", "No network chosen yet".into()),
        "searching" => (
            "waiting",
            match &client.attempt {
                Some(attempt) if attempt.reason == "wrong_password" => {
                    format!("Wrong password for \"{}\"", attempt.ssid)
                }
                _ => "No saved network in range".into(),
            },
        ),
        _ => ("off", "Off".into()),
    };
    let (status, detail) = match &client.fault {
        Some(fault) => ("waiting", fault.clone()),
        None => (status, detail),
    };
    let wifi_client = Port {
        id: "wifi_client",
        enabled: client.state != "off" || client.fault.is_some(),
        status,
        detail,
        clients: None,
    };
    let hotspot = Port {
        id: "hotspot",
        enabled: wifi.hotspot.enabled,
        status: if wifi.hotspot.enabled {
            "active"
        } else {
            "off"
        },
        detail: if wifi.hotspot.enabled {
            format!(
                "{}{}",
                wifi.hotspot.ssid,
                if wifi.hotspot.open {
                    " (open, no password)"
                } else {
                    ""
                }
            )
        } else {
            "Off".into()
        },
        clients: Some(0),
    };
    let lan_address = crate::system::interface_addresses("br0")
        .first()
        .map_or_else(|| "192.168.10.1".to_owned(), ToString::to_string);
    NetworkState {
        active_source: (client.state == "connected").then_some("wifi_client"),
        sources: vec![
            wifi_client,
            not_yet("usb_phone", None),
            not_yet("mesh_gateway", None),
        ],
        consumers: vec![
            hotspot,
            not_yet("usb_computer", Some(0)),
            not_yet("mesh_peers", Some(0)),
        ],
        lan: Lan {
            subnet: format!(
                "{}.0/24",
                lan_address
                    .rsplit_once('.')
                    .map_or("192.168.10", |(prefix, _)| prefix)
            ),
            address: lan_address,
        },
    }
}

pub async fn get_network(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let wifi = app.wifi.get().await.map_err(wifi_error)?;
    Ok(no_store(axum::Json(state(&wifi))))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Switches {
    wifi_client: Option<bool>,
    usb_phone: Option<bool>,
    mesh_gateway: Option<bool>,
    hotspot: Option<bool>,
    usb_computer: Option<bool>,
    mesh_peers: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPatch {
    #[serde(default)]
    sources: Switches,
    #[serde(default)]
    consumers: Switches,
}

pub async fn patch_network(
    State(app): State<App>,
    _: Admin,
    Json(patch): Json<NetworkPatch>,
) -> ApiResult<Response> {
    let unsupported = [
        patch.sources.usb_phone,
        patch.sources.mesh_gateway,
        patch.consumers.usb_computer,
        patch.consumers.mesh_peers,
        patch.sources.hotspot,
        patch.consumers.wifi_client,
    ];
    if unsupported.contains(&Some(true)) {
        return Err(ApiError::conflict(
            "That switch is not available in this release yet.",
        ));
    }
    if let Some(on) = patch.sources.wifi_client {
        app.wifi.set_client(on).await.map_err(wifi_error)?;
    }
    if let Some(on) = patch.consumers.hotspot {
        app.wifi.set_hotspot_on(on).await.map_err(wifi_error)?;
    }
    let wifi = app.wifi.get().await.map_err(wifi_error)?;
    Ok(no_store(axum::Json(state(&wifi))))
}
