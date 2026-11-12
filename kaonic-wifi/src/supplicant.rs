//! Drives wpa_supplicant on behalf of the [`Policy`](crate::policy::Policy).
//!
//! The hub owns the network list. wpa_supplicant runs with a config file that
//! holds only `ctrl_interface` and `update_config=0`; every network is added
//! over the control socket at start, kept disabled, and enabled one at a time
//! with `SELECT_NETWORK`. Passwords therefore never reach a file: they go from
//! the keystore to wpa_supplicant's memory.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use crate::ctrl::Ctrl;
use crate::policy::{Event, Seen};
use crate::wpa::{self, Notice, Status};

pub struct Supplicant {
    ctrl: Ctrl,
    /// wpa_supplicant's network id for each SSID it holds.
    ids: HashMap<String, u32>,
    /// The network last selected: failures that name no network are about it.
    selected: Option<String>,
    /// "Not found" reports since that selection. The first can come from a scan started
    /// before it, so only a second one is believed.
    not_found: std::cell::Cell<u8>,
}

impl Supplicant {
    /// Connects to `daemon` and adopts the networks it already holds: after a hub
    /// restart they are the hub's own, and the current connection must not drop.
    /// [`Supplicant::retain`] then removes any the hub no longer knows.
    pub fn open(daemon: &Path, local_dir: &Path) -> io::Result<Self> {
        let ctrl = Ctrl::open(daemon, local_dir)?;
        let ids = wpa::parse_list_networks(&ctrl.request("LIST_NETWORKS")?).into_iter().map(|listed| (listed.ssid, listed.id)).collect();
        let status = wpa::parse_status(&ctrl.request("STATUS")?);
        let selected = (status.wpa_state == "COMPLETED").then_some(status.ssid).flatten();
        Ok(Self { ctrl, ids, selected, not_found: std::cell::Cell::new(0) })
    }

    /// The network wpa_supplicant is connected to now, if any.
    pub fn current(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Removes every network not in `ssids` (left from an earlier run).
    pub fn retain(&mut self, ssids: &[&str]) -> io::Result<()> {
        let stale: Vec<String> = self.ids.keys().filter(|ssid| !ssids.contains(&ssid.as_str())).cloned().collect();
        for ssid in stale {
            self.remove(&ssid)?;
        }
        Ok(())
    }

    /// Adds a network, or updates it in place (a new password). A new one stays
    /// disabled until selected; the one in use stays in use.
    pub fn configure(&mut self, ssid: &str, password: Option<&str>, hidden: bool) -> io::Result<()> {
        if !wpa::valid_ssid(ssid) || password.is_some_and(|password| !wpa::valid_passphrase(password)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "network name or password out of range"));
        }
        let id = match self.ids.get(ssid) {
            Some(id) => *id,
            None => {
                let id = self.ctrl.request("ADD_NETWORK")?.trim().parse().map_err(|_| io::Error::other("ADD_NETWORK: no id"))?;
                self.ids.insert(ssid.to_owned(), id);
                id
            }
        };
        let in_use = self.selected.as_deref() == Some(ssid);
        for command in wpa::network_commands(id, ssid, password, hidden) {
            if in_use && command.starts_with("DISABLE_NETWORK") {
                continue;
            }
            self.ctrl.ok(&command)?;
        }
        Ok(())
    }

    pub fn remove(&mut self, ssid: &str) -> io::Result<()> {
        if let Some(id) = self.ids.remove(ssid) {
            self.ctrl.ok(&format!("REMOVE_NETWORK {id}"))?;
        }
        if self.selected.as_deref() == Some(ssid) {
            self.selected = None;
        }
        Ok(())
    }

    /// Joins `ssid` and disables every other network.
    pub fn select(&mut self, ssid: &str) -> io::Result<()> {
        let id = *self.ids.get(ssid).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "network not configured"))?;
        self.ctrl.ok(&format!("SELECT_NETWORK {id}"))?;
        self.selected = Some(ssid.to_owned());
        self.not_found.set(0);
        Ok(())
    }

    /// Leaves the current network and stops trying.
    pub fn disconnect(&mut self) -> io::Result<()> {
        self.selected = None;
        self.ctrl.ok("DISABLE_NETWORK all")?;
        self.ctrl.ok("DISCONNECT")
    }

    /// Starts a scan. False when one is already running; its results will come.
    pub fn scan(&self) -> io::Result<bool> {
        match self.ctrl.request("SCAN")?.trim_end() {
            "OK" => Ok(true),
            "FAIL-BUSY" => Ok(false),
            other => Err(io::Error::other(format!("SCAN: {other}"))),
        }
    }

    pub fn scan_results(&self) -> io::Result<Vec<Seen>> {
        Ok(wpa::parse_scan_results(&self.ctrl.request("SCAN_RESULTS")?))
    }

    pub fn status(&self) -> io::Result<Status> {
        Ok(wpa::parse_status(&self.ctrl.request("STATUS")?))
    }

    /// The signal of the current connection, in dBm.
    pub fn signal(&self) -> Option<i32> {
        wpa::parse_signal(&self.ctrl.request("SIGNAL_POLL").ok()?)
    }

    /// What a notice means to the policy. `ScanResults` is not translated here:
    /// the caller reads the results with [`Supplicant::scan_results`].
    pub fn translate(&self, notice: &Notice) -> Option<Event> {
        let name_of = |id: Option<u32>| id.and_then(|id| self.ids.iter().find(|(_, known)| **known == id).map(|(ssid, _)| ssid.clone()));
        match notice {
            Notice::Connected { id } => name_of(*id).or_else(|| self.selected.clone()).map(Event::Associated),
            // We asked for it (DISCONNECT, SELECT_NETWORK of another): not news.
            Notice::Disconnected { locally_generated: true, .. } => None,
            Notice::Disconnected { .. } => Some(Event::Disconnected),
            Notice::TempDisabled { id, ssid, .. } => {
                let ssid = name_of(*id).unwrap_or_else(|| ssid.clone());
                notice.problem().map(|problem| Event::Failed(ssid, problem))
            }
            Notice::NetworkNotFound => {
                let selected = self.selected.clone()?;
                let count = self.not_found.get().saturating_add(1);
                self.not_found.set(count);
                if count < 2 {
                    return None;
                }
                notice.problem().map(|problem| Event::Failed(selected, problem))
            }
            _ => None,
        }
    }
}
