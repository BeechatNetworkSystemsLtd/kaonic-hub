//! The hub's shared state, handed to every handler.

use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kaonic_keystore::Keystore;
use tokio::sync::Semaphore;

use crate::api::Jobs;
use crate::auth::Limiter;
use crate::error::{ApiError, ApiResult};
use crate::events::Bus;
use crate::system::{Device, Metrics};
use crate::wifi::WifiHandle;

#[derive(Clone, Debug)]
pub struct Config {
    /// Persistent state on userfs: `hub.db`, the keystore.
    pub state_dir: PathBuf,
    /// Where the web UI comes from.
    pub webui: crate::web::Webui,
    /// Runtime files (tmpfs): sockets, rendered daemon configs.
    pub run_dir: PathBuf,
    /// Development: plain HTTP, setup allowed from any address. Never on a device.
    pub dev: bool,
    /// The radio interface Reticulum runs on (`rf09_a`).
    pub radio: String,
    /// Setup is answered only on these interfaces' addresses (the device's own networks).
    pub setup_interfaces: Vec<String>,
    /// The plugin installer and the plugin API.
    pub plugins: crate::plugins::Settings,
}

pub struct Inner {
    pub config: Config,
    pub store: kaonic_store::Store,
    pub keystore: Arc<Mutex<Keystore>>,
    pub bus: Bus,
    pub limiter: Limiter,
    /// One Argon2 hash at a time.
    pub argon: Semaphore,
    pub device: Device,
    pub metrics: Metrics,
    pub wifi: WifiHandle,
    pub jobs: Jobs,
    /// The HTTPS CA certificate (PEM), once TLS is set up.
    pub ca_pem: std::sync::OnceLock<String>,
    /// Reticulum over the radio; None where there is no radio (a laptop) or it failed to start.
    pub mesh: Option<std::sync::Arc<kaonic_mesh::Mesh>>,
    /// Provisioning this admin device is doing, by peer.
    pub provisioning: crate::provision::Provisioning,
    /// The radio's last statistics sample.
    pub radio_stats: crate::api::radio::RadioStats,
    /// One authenticated link per trusted peer, once the mesh runs.
    pub links: std::sync::OnceLock<Arc<kaonic_mesh::links::Links>>,
    /// The push-to-talk GROUP channel, once this node holds the group key.
    pub ptt_group: std::sync::OnceLock<Arc<kaonic_mesh::group::GroupChannel>>,
    /// Push-to-talk, once started.
    pub ptt: std::sync::OnceLock<Arc<crate::ptt::Ptt>>,
    /// The mesh VPN, when turned on and running; or why it could not start.
    pub vpn: std::sync::OnceLock<Arc<kaonic_vpn::Vpn>>,
    pub vpn_error: std::sync::OnceLock<String>,
    /// The VPN's settings from the command line, when it is turned on.
    pub vpn_config: Option<kaonic_vpn::VpnConfig>,
    /// Plugins, made from `config.plugins` when first used ([`App::plugins`]).
    pub plugins: std::sync::OnceLock<Arc<crate::plugins::Plugins>>,
}

#[derive(Clone)]
pub struct App(Arc<Inner>);

impl Deref for App {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl App {
    pub fn new(inner: Inner) -> Self {
        Self(Arc::new(inner))
    }

    /// The same app with the mesh running. Only at start-up, before the app is shared.
    pub fn with_mesh(self, mesh: Arc<kaonic_mesh::Mesh>) -> Self {
        let mut inner = Arc::try_unwrap(self.0)
            .unwrap_or_else(|_| panic!("the app is shared before the mesh starts"));
        inner.mesh = Some(mesh);
        Self(Arc::new(inner))
    }

    /// Plugins: the installer's client, plugin page tickets and the mesh bridge.
    pub fn plugins(&self) -> &Arc<crate::plugins::Plugins> {
        self.plugins.get_or_init(|| Arc::new(crate::plugins::Plugins::new(self.config.plugins.clone())))
    }

    /// Runs `work` on the keystore off the async runtime (it does file I/O and fsync).
    pub async fn secrets<T, F>(&self, work: F) -> ApiResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Keystore) -> kaonic_keystore::Result<T> + Send + 'static,
    {
        let keystore = self.keystore.clone();
        tokio::task::spawn_blocking(move || {
            let mut keystore = keystore.lock().map_err(|_| ApiError::internal())?;
            work(&mut keystore).map_err(|error| {
                log::error!("keystore: {error}");
                ApiError::internal()
            })
        })
        .await
        .map_err(|_| ApiError::internal())?
    }
}
