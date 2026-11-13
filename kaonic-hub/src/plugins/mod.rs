//! Plugins, as the hub sees them (`docs/plugins.md`).
//!
//! `kaonic-hub-installer` owns packages, units and users; the hub asks it over its Unix
//! socket ([`installer`]) and decides who may ask. The hub keeps a short-lived copy of the
//! installer's list: for plugin pages (`/apps/<id>/`, [`proxy`]), to check plugin tokens on
//! the plugin API (`crate::plugin_api`) and to keep one plugin API socket per plugin.

pub mod installer;
pub mod proxy;
pub mod tickets;
pub mod upload;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use installer::{Failure, Installed};

use crate::plugin_api::bridge::{Bridge, DEFAULT_SHARE};
use crate::plugin_api::socket::Sockets;

/// The largest package upload.
pub const MAX_PACKAGE: usize = kaonic_hub_installer::api::MAX_PACKAGE;
/// The list is asked for again after this long.
const FRESH: Duration = Duration::from_secs(30);
/// A plugin not in the list (or a token that does not match) asks again at most this often.
const RECHECK: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct Settings {
    /// The installer's socket.
    pub installer: PathBuf,
    /// The user the installer runs as (root): its socket must be served by that user.
    pub installer_uid: u32,
    /// Where the plugin API's sockets go, `<id>.sock` for each plugin.
    pub api_dir: PathBuf,
    /// Every plugin taken to run as this user, not its record's: for tests, which cannot
    /// run plugins as other users. Never set on a device (no flag sets it).
    pub plugins_uid: Option<u32>,
    /// Where the installer puts plugins (icons are read from there).
    pub dir: PathBuf,
    /// Each plugin's share of the channel, 0-1.
    pub airtime_share: f64,
    /// Updated copies of the hub and the installer (`kaonic_hub_installer::core`).
    pub core_dir: PathBuf,
    /// The installer's state directory: its history, and staging for installer updates.
    pub installer_state: PathBuf,
    /// Release keys that sign core updates; none on a development device.
    pub release_key: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            installer: "/run/kaonic-hub-installer/api.sock".into(),
            installer_uid: 0,
            api_dir: "/run/kaonic-hub/plugins".into(),
            plugins_uid: None,
            dir: "/usr/local/kaonic-plugins".into(),
            airtime_share: DEFAULT_SHARE,
            core_dir: "/usr/local/kaonic-core".into(),
            installer_state: "/usr/local/kaonic-hub-installer".into(),
            release_key: "/etc/kaonic/beechat-ota.pub.pem".into(),
        }
    }
}

#[derive(Default)]
struct Cache {
    list: Arc<Vec<Installed>>,
    fetched: Option<Instant>,
    asked: Option<Instant>,
    /// When it was last asked for, in Unix seconds.
    asked_unix: u64,
    key: Option<[u8; 32]>,
    key_asked: Option<Instant>,
}

pub struct Plugins {
    pub settings: Settings,
    pub installer: installer::Client,
    pub tickets: tickets::Tickets,
    pub bridge: Arc<Bridge>,
    /// The plugin API's sockets.
    pub sockets: Sockets,
    /// The list changed through the hub: the sockets are brought up to date.
    changes: tokio::sync::Notify,
    cache: Mutex<Cache>,
}

impl Plugins {
    pub fn new(settings: Settings) -> Self {
        Self {
            installer: installer::Client::new(settings.installer.clone(), settings.installer_uid),
            tickets: tickets::Tickets::default(),
            bridge: Arc::new(Bridge::new(settings.airtime_share)),
            sockets: Sockets::default(),
            changes: tokio::sync::Notify::new(),
            settings,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// The user `plugin` runs as: its sockets must be that user's.
    pub fn uid_of(&self, plugin: &Installed) -> u32 {
        self.settings.plugins_uid.unwrap_or(plugin.record.uid)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().expect("plugins cache lock")
    }

    /// The installer's list, asked again if it is older than [`FRESH`].
    pub async fn list(&self) -> Result<Arc<Vec<Installed>>, Failure> {
        {
            let cache = self.cache();
            if cache.fetched.is_some_and(|at| at.elapsed() < FRESH) {
                return Ok(cache.list.clone());
            }
        }
        self.refresh().await
    }

    /// Asks the installer for the list now.
    pub async fn refresh(&self) -> Result<Arc<Vec<Installed>>, Failure> {
        {
            let mut cache = self.cache();
            cache.asked = Some(Instant::now());
            cache.asked_unix = crate::clock::now().max(0) as u64;
        }
        let list = Arc::new(self.installer.list().await?);
        let mut cache = self.cache();
        cache.list = list.clone();
        cache.fetched = Some(Instant::now());
        Ok(list)
    }

    /// A plugin from the list; asks again (at most every [`RECHECK`]) when `accept` refuses
    /// what the list says, for a plugin just installed or a token just issued.
    pub async fn find(&self, id: &str, accept: impl Fn(&Installed) -> bool) -> Option<Installed> {
        self.find_since(id, accept, 0).await
    }

    /// As [`Plugins::find`], and asks again at once if the list is older than `since` (Unix
    /// seconds): a token issued after the list was asked for is not in it yet.
    pub async fn find_since(&self, id: &str, accept: impl Fn(&Installed) -> bool, since: u64) -> Option<Installed> {
        let list = self.list().await.ok()?;
        if let Some(found) = list.iter().find(|plugin| plugin.id() == id).filter(|plugin| accept(plugin)) {
            return Some(found.clone());
        }
        let wait = {
            let cache = self.cache();
            cache.asked_unix > since && cache.asked.is_some_and(|at| at.elapsed() < RECHECK)
        };
        if wait {
            return None;
        }
        self.refresh().await.ok()?.iter().find(|plugin| plugin.id() == id).filter(|plugin| accept(plugin)).cloned()
    }

    /// The list changed through the hub (an install, a start): forget the copy, and bring
    /// the sockets up to date.
    pub fn changed(&self) {
        self.cache().fetched = None;
        self.changes.notify_one();
    }

    /// Asks for the list and opens or closes plugin API sockets to match it; the bridge
    /// forgets plugins no longer installed.
    pub async fn reconcile(&self, app: &crate::app::App) {
        let Ok(list) = self.refresh().await else { return };
        let owned: Vec<(&str, u32)> = list.iter().map(|plugin| (plugin.id(), self.uid_of(plugin))).collect();
        self.sockets.reconcile(app, &self.settings.api_dir, &owned);
        self.bridge.set_installed(list.iter().map(Installed::id));
    }

    /// The key plugin tokens are signed with; `again` asks the installer even if known (at
    /// most every [`RECHECK`]).
    pub async fn token_key(&self, again: bool) -> Option<[u8; 32]> {
        {
            let mut cache = self.cache();
            let recent = cache.key_asked.is_some_and(|at| at.elapsed() < RECHECK);
            if let Some(key) = cache.key
                && (!again || recent)
            {
                return Some(key);
            }
            cache.key_asked = Some(Instant::now());
        }
        match self.installer.token_key().await {
            Ok(key) => {
                self.cache().key = Some(key);
                Some(key)
            }
            Err(error) => {
                log::warn!("plugins: {error}");
                self.cache().key
            }
        }
    }
}

/// Starts the plugin API's sockets and the mesh bridge. Call once the links run (if any).
pub async fn start(app: &crate::app::App) {
    let plugins = app.plugins();
    crate::plugin_api::bridge::spawn(app, plugins.bridge.clone());
    upload::clear(&app.config.state_dir);
    log::info!("plugins: plugin API on {}/<id>.sock", plugins.settings.api_dir.display());
    // A plugin installed, removed, stopped or crashed shows in the list within a while.
    let watcher = app.clone();
    tokio::spawn(async move {
        let plugins = watcher.plugins().clone();
        let mut tick = tokio::time::interval(FRESH);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = plugins.changes.notified() => {}
            }
            plugins.reconcile(&watcher).await;
        }
    });
}
