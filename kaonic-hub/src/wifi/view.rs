//! What the API returns: `WifiConfig` and `WifiScanResults`.

use kaonic_wifi::policy::{Problem, Security, State};
use serde::Serialize;

use super::Service;

#[derive(Clone, Debug, Serialize)]
pub struct WifiView {
    pub client: ClientView,
    pub saved: Vec<SavedView>,
    pub hotspot: HotspotView,
    pub antenna: &'static str,
    pub antenna_supported: bool,
    #[serde(skip)]
    scan: ScanResultsView,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientView {
    pub state: &'static str,
    pub ssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub address: Option<String>,
    pub pinned: Option<String>,
    pub attempt: Option<AttemptView>,
    pub scanned_ts: Option<i64>,
    /// Switched on but not running, and why.
    pub fault: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttemptView {
    pub ssid: String,
    pub reason: &'static str,
    pub ts: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SavedView {
    pub ssid: String,
    pub secured: bool,
    pub auto_connect: bool,
    pub in_range: bool,
    pub signal_dbm: Option<i32>,
    pub last_connected_ts: Option<i64>,
    pub problem: Option<&'static str>,
    pub retry_ts: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HotspotView {
    pub enabled: bool,
    pub ssid: String,
    /// Null for viewers (see [`WifiView::for_viewer`]) and for an open hotspot.
    pub password: Option<String>,
    pub open: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanResultsView {
    pub scanned_ts: Option<i64>,
    pub networks: Vec<ScanEntryView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanEntryView {
    pub ssid: String,
    pub signal_dbm: i32,
    pub security: &'static str,
    pub frequency_mhz: u32,
    pub saved: bool,
}

pub fn problem_name(problem: Problem) -> &'static str {
    match problem {
        Problem::WrongPassword => "wrong_password",
        Problem::NotFound => "not_found",
        Problem::Rejected => "rejected",
        Problem::Timeout => "timeout",
        Problem::NoAddress => "no_address",
    }
}

fn security_name(security: Security) -> &'static str {
    match security {
        Security::Open => "open",
        Security::Wpa2 => "wpa2",
        Security::Wpa3 => "wpa3",
    }
}

impl WifiView {
    pub(super) fn build(service: &Service) -> Self {
        let policy = &service.policy;
        let wall = |mono: u64| mono as i64 + service.wall_offset;
        let (state, ssid) = match policy.state() {
            State::Off => ("off", None),
            State::Searching { .. } => ("searching", None),
            State::Connecting { ssid, .. } => ("connecting", Some(ssid.clone())),
            State::Connected { ssid, .. } => ("connected", Some(ssid.clone())),
        };
        let connected = state == "connected";
        let client = ClientView {
            state,
            ssid,
            signal_dbm: if connected { service.signal } else { None },
            address: if connected {
                service.address.clone()
            } else {
                None
            },
            pinned: policy.pinned().map(str::to_owned),
            attempt: policy.attempt().map(|attempt| AttemptView {
                ssid: attempt.ssid.clone(),
                reason: problem_name(attempt.problem),
                ts: wall(attempt.at),
            }),
            scanned_ts: policy.scanned_at().map(wall),
            fault: if service.client_on {
                service.fault.clone()
            } else {
                None
            },
        };
        let saved = policy
            .saved()
            .iter()
            .map(|saved| {
                let seen = policy.in_range(&saved.ssid);
                SavedView {
                    ssid: saved.ssid.clone(),
                    secured: saved.secured,
                    auto_connect: saved.auto_connect,
                    in_range: seen.is_some(),
                    signal_dbm: seen.map(|seen| seen.signal_dbm),
                    last_connected_ts: saved.last_connected.map(wall),
                    problem: saved.problem.map(problem_name),
                    retry_ts: saved.retry_at.map(wall),
                }
            })
            .collect();
        let scan = ScanResultsView {
            scanned_ts: policy.scanned_at().map(wall),
            networks: policy
                .scan()
                .iter()
                .map(|seen| ScanEntryView {
                    ssid: seen.ssid.clone(),
                    signal_dbm: seen.signal_dbm,
                    security: security_name(seen.security),
                    frequency_mhz: seen.frequency_mhz,
                    saved: policy.saved().iter().any(|saved| saved.ssid == seen.ssid),
                })
                .collect(),
        };
        Self {
            client,
            saved,
            hotspot: HotspotView {
                enabled: service.hotspot_on,
                ssid: service.hotspot.ssid.clone(),
                password: service.hotspot.password.clone(),
                open: service.hotspot.password.is_none(),
            },
            antenna: if service.antenna_external {
                "external"
            } else {
                "internal"
            },
            antenna_supported: service.radio.antenna_supported(),
            scan,
        }
    }

    pub fn scan_results(&self) -> ScanResultsView {
        self.scan.clone()
    }

    /// What a viewer may see: no hotspot password.
    pub fn for_viewer(mut self) -> Self {
        self.hotspot.password = None;
        self
    }
}
