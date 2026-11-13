//! The Wi-Fi service: one thread that owns the client policy, wpa_supplicant and
//! the hotspot, and answers the API through [`WifiHandle`].
//!
//! - The saved list (order, flags) is in `hub.db`; passwords are in the keystore
//!   under `wifi/net/<hex ssid>` and `wifi/hotspot`.
//! - wpa_supplicant gets networks over its control socket; hostapd's config is
//!   rendered to tmpfs. Neither ever writes a password to the SD card.
//! - Daemons and interfaces are behind [`Radio`], so this module is tested with
//!   a fake; `linux.rs` is the real one.

pub mod linux;
pub mod view;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kaonic_store::{Store, settings, wifi as saved_db};
use kaonic_keystore::Keystore;
use kaonic_wifi::policy::{self, Action, Event, Policy, PolicyError, Saved};
use kaonic_wifi::wpa::{self, Notice};
use tokio::sync::oneshot;

use crate::clock;
use crate::events::Bus;
pub use view::{HotspotView, WifiView};

/// Reads the next wpa_supplicant notice, waiting at most the given time.
pub type NoticeReader = Box<dyn FnMut(Duration) -> std::io::Result<Option<String>> + Send>;

/// How long the notice reader waits per read: also how soon a stopped reader exits.
const NOTICE_POLL: Duration = Duration::from_secs(5);

/// What the service needs from the device. Blocking; called on the Wi-Fi thread only.
pub trait Radio: Send {
    /// Starts wpa_supplicant (if needed) and returns a fresh driver for it.
    fn supplicant(&mut self) -> std::io::Result<Box<dyn Supplicant>>;
    /// A blocking source of wpa_supplicant notices, read on its own thread.
    fn notices(&mut self) -> std::io::Result<NoticeReader>;
    fn stop_supplicant(&mut self) -> std::io::Result<()>;
    /// Runs the hotspot with this config, or stops it with None. `client_frequency`
    /// is set when the client is connected: the radio has one channel, so the
    /// hotspot must use it (repeater).
    fn hotspot(
        &mut self,
        config: Option<&HotspotConfig>,
        client_frequency: Option<u32>,
    ) -> std::io::Result<()>;
    /// The client interface's IPv4 address with prefix, once DHCP has given one.
    fn client_address(&mut self) -> Option<String>;
    /// DHCP on the client interface on or off.
    fn client_dhcp(&mut self, on: bool) -> std::io::Result<()>;
    fn antenna_supported(&self) -> bool;
    fn set_antenna(&mut self, external: bool) -> std::io::Result<()>;
    /// Whether the hotspot that should be running really is: its interface in AP mode and
    /// hostapd up. Something else (a supplicant, networkd reconfiguring the bridge, the driver)
    /// can take the interface over while hostapd keeps running with the AP disabled.
    fn hotspot_healthy(&mut self) -> bool {
        true
    }
    /// Starts the running hotspot again as it is.
    fn restart_hotspot(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How often the running hotspot is checked.
const HOTSPOT_CHECK: Duration = if cfg!(test) { Duration::from_millis(300) } else { Duration::from_secs(10) };

/// The parts of [`kaonic_wifi::supplicant::Supplicant`] the service uses, so tests can fake it.
pub trait Supplicant: Send {
    fn configure(
        &mut self,
        ssid: &str,
        password: Option<&str>,
        hidden: bool,
    ) -> std::io::Result<()>;
    fn remove(&mut self, ssid: &str) -> std::io::Result<()>;
    fn select(&mut self, ssid: &str) -> std::io::Result<()>;
    fn disconnect(&mut self) -> std::io::Result<()>;
    fn scan(&mut self) -> std::io::Result<bool>;
    fn scan_results(&mut self) -> std::io::Result<Vec<policy::Seen>>;
    fn signal(&mut self) -> Option<i32>;
    fn frequency(&mut self) -> Option<u32>;
    fn translate(&self, notice: &Notice) -> Option<Event>;
    /// The network it is connected to now (adopted after a hub restart).
    fn current(&self) -> Option<String>;
    /// Drops every network not in `ssids`.
    fn retain(&mut self, ssids: &[&str]) -> std::io::Result<()>;
}

impl Supplicant for kaonic_wifi::supplicant::Supplicant {
    fn configure(
        &mut self,
        ssid: &str,
        password: Option<&str>,
        hidden: bool,
    ) -> std::io::Result<()> {
        kaonic_wifi::supplicant::Supplicant::configure(self, ssid, password, hidden)
    }
    fn remove(&mut self, ssid: &str) -> std::io::Result<()> {
        kaonic_wifi::supplicant::Supplicant::remove(self, ssid)
    }
    fn select(&mut self, ssid: &str) -> std::io::Result<()> {
        kaonic_wifi::supplicant::Supplicant::select(self, ssid)
    }
    fn disconnect(&mut self) -> std::io::Result<()> {
        kaonic_wifi::supplicant::Supplicant::disconnect(self)
    }
    fn scan(&mut self) -> std::io::Result<bool> {
        kaonic_wifi::supplicant::Supplicant::scan(self)
    }
    fn scan_results(&mut self) -> std::io::Result<Vec<policy::Seen>> {
        kaonic_wifi::supplicant::Supplicant::scan_results(self)
    }
    fn signal(&mut self) -> Option<i32> {
        kaonic_wifi::supplicant::Supplicant::signal(self)
    }
    fn frequency(&mut self) -> Option<u32> {
        self.status().ok()?.frequency_mhz
    }
    fn translate(&self, notice: &Notice) -> Option<Event> {
        kaonic_wifi::supplicant::Supplicant::translate(self, notice)
    }
    fn current(&self) -> Option<String> {
        kaonic_wifi::supplicant::Supplicant::current(self).map(str::to_owned)
    }
    fn retain(&mut self, ssids: &[&str]) -> std::io::Result<()> {
        kaonic_wifi::supplicant::Supplicant::retain(self, ssids)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotspotConfig {
    pub ssid: String,
    /// None: an open network.
    pub password: Option<String>,
    /// ISO 3166 country for regulatory limits; None leaves the driver's world default.
    pub country: Option<String>,
    /// The channel while no Wi-Fi client sets it; None: channel 6.
    pub channel: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WifiError {
    NotSaved,
    BadOrder,
    Invalid(&'static str, &'static str),
    Unavailable(String),
}

type Reply<T> = oneshot::Sender<Result<T, WifiError>>;

enum Message {
    Get(Reply<WifiView>),
    Scan(Reply<bool>),
    Save {
        ssid: String,
        password: Option<String>,
        hidden: bool,
        reply: Reply<WifiView>,
    },
    Patch {
        ssid: String,
        password: Option<Option<String>>,
        auto_connect: Option<bool>,
        reply: Reply<WifiView>,
    },
    Forget {
        ssid: String,
        reply: Reply<WifiView>,
    },
    Connect {
        ssid: String,
        reply: Reply<WifiView>,
    },
    Order {
        ssids: Vec<String>,
        reply: Reply<WifiView>,
    },
    Unpin(Reply<WifiView>),
    SetClient {
        on: bool,
        reply: Reply<WifiView>,
    },
    SetHotspotOn {
        on: bool,
        reply: Reply<WifiView>,
    },
    SetHotspot {
        ssid: String,
        password: Option<String>,
        reply: Reply<WifiView>,
    },
    SetAntenna {
        external: bool,
        reply: Reply<WifiView>,
    },
    Notice(String),
    /// The notice reader lost wpa_supplicant (it restarted, or died).
    SupplicantLost,
}

/// The API's way in. Cheap to clone.
#[derive(Clone)]
pub struct WifiHandle {
    sender: mpsc::Sender<Message>,
}

impl WifiHandle {
    async fn ask<T>(&self, make: impl FnOnce(Reply<T>) -> Message) -> Result<T, WifiError> {
        let (reply, answer) = oneshot::channel();
        self.sender
            .send(make(reply))
            .map_err(|_| WifiError::Unavailable("The Wi-Fi service is not running.".into()))?;
        answer
            .await
            .map_err(|_| WifiError::Unavailable("The Wi-Fi service stopped.".into()))?
    }

    pub async fn get(&self) -> Result<WifiView, WifiError> {
        self.ask(Message::Get).await
    }
    pub async fn scan(&self) -> Result<bool, WifiError> {
        self.ask(Message::Scan).await
    }
    pub async fn save(
        &self,
        ssid: String,
        password: Option<String>,
        hidden: bool,
    ) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::Save {
            ssid,
            password,
            hidden,
            reply,
        })
        .await
    }
    pub async fn patch(
        &self,
        ssid: String,
        password: Option<Option<String>>,
        auto_connect: Option<bool>,
    ) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::Patch {
            ssid,
            password,
            auto_connect,
            reply,
        })
        .await
    }
    pub async fn forget(&self, ssid: String) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::Forget { ssid, reply }).await
    }
    pub async fn connect(&self, ssid: String) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::Connect { ssid, reply }).await
    }
    pub async fn order(&self, ssids: Vec<String>) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::Order { ssids, reply }).await
    }
    pub async fn unpin(&self) -> Result<WifiView, WifiError> {
        self.ask(Message::Unpin).await
    }
    pub async fn set_client(&self, on: bool) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::SetClient { on, reply }).await
    }
    pub async fn set_hotspot_on(&self, on: bool) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::SetHotspotOn { on, reply }).await
    }
    pub async fn set_hotspot(
        &self,
        ssid: String,
        password: Option<String>,
    ) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::SetHotspot {
            ssid,
            password,
            reply,
        })
        .await
    }
    pub async fn set_antenna(&self, external: bool) -> Result<WifiView, WifiError> {
        self.ask(|reply| Message::SetAntenna { external, reply })
            .await
    }
}

/// Keystore names.
fn password_key(ssid: &str) -> String {
    format!("wifi/net/{}", wpa::hex(ssid))
}
const HOTSPOT_PASSWORD_KEY: &str = "wifi/hotspot";

/// Settings keys.
const CLIENT_ON: &str = "wifi.client_on";
const HOTSPOT_ON: &str = "wifi.hotspot_on";
const HOTSPOT_SSID: &str = "wifi.hotspot_ssid";
const ANTENNA_EXTERNAL: &str = "wifi.antenna_external";
const COUNTRY: &str = "wifi.country";
const HOTSPOT_CHANNEL: &str = "wifi.hotspot_channel";

struct Service {
    policy: Policy,
    radio: Box<dyn Radio>,
    supplicant: Option<Box<dyn Supplicant>>,
    store: Store,
    keystore: Arc<Mutex<Keystore>>,
    runtime: tokio::runtime::Handle,
    bus: Bus,
    sender: mpsc::Sender<Message>,
    /// Bumped whenever wpa_supplicant goes away: a notice reader of an older value exits,
    /// closing its socket. A gone daemon gives a connected datagram socket no error.
    readers: Arc<AtomicU64>,
    client_on: bool,
    hotspot_on: bool,
    hotspot: HotspotConfig,
    /// The channel the hotspot was last started on, to follow the client.
    hotspot_frequency: Option<u32>,
    /// When the running hotspot was last checked.
    hotspot_checked: std::time::Instant,
    antenna_external: bool,
    address: Option<String>,
    signal: Option<i32>,
    /// Why the client is switched on but not running (wpa_supplicant would not start).
    fault: Option<String>,
    /// Unix time = mono + offset, for showing times the policy keeps in monotonic seconds.
    wall_offset: i64,
}

/// Starts the service thread. `default_hotspot_ssid` is used until an admin names it.
pub fn start(
    radio: Box<dyn Radio>,
    store: Store,
    keystore: Arc<Mutex<Keystore>>,
    bus: Bus,
    default_hotspot_ssid: String,
) -> std::io::Result<WifiHandle> {
    let (sender, inbox) = mpsc::channel();
    let runtime = tokio::runtime::Handle::current();
    let handle = WifiHandle {
        sender: sender.clone(),
    };
    thread::Builder::new()
        .name("hub-wifi".into())
        .spawn(move || {
            let mut service = Service::load(
                radio,
                store,
                keystore,
                runtime,
                bus,
                sender,
                default_hotspot_ssid,
            );
            service.bring_up();
            service.run(inbox);
        })?;
    Ok(handle)
}

impl Service {
    // Everything the thread owns arrives here once; a struct for it would only be unpacked again.
    #[allow(clippy::too_many_arguments)]
    fn load(
        radio: Box<dyn Radio>,
        store: Store,
        keystore: Arc<Mutex<Keystore>>,
        runtime: tokio::runtime::Handle,
        bus: Bus,
        sender: mpsc::Sender<Message>,
        default_hotspot_ssid: String,
    ) -> Self {
        let (saved, client_on, hotspot_on, ssid, antenna_external, country, channel) = runtime
            .block_on(store.call(|c| {
                Ok((
                    saved_db::list(c)?,
                    settings::get_bool(c, CLIENT_ON, false)?,
                    settings::get_bool(c, HOTSPOT_ON, true)?,
                    settings::get(c, HOTSPOT_SSID)?,
                    settings::get_bool(c, ANTENNA_EXTERNAL, false)?,
                    settings::get(c, COUNTRY)?,
                    settings::get(c, HOTSPOT_CHANNEL)?.and_then(|value| value.parse().ok()),
                ))
            }))
            .unwrap_or_else(|error| {
                log::error!("wifi: cannot read settings, starting with defaults: {error}");
                (Vec::new(), false, true, None, false, None, None)
            });
        let hotspot_password = keystore.lock().ok().and_then(|keys| {
            keys.get(HOTSPOT_PASSWORD_KEY)
                .and_then(|secret| secret.expose_str().map(str::to_owned))
        });
        let wall_offset = clock::now() - clock::mono() as i64;
        let policy = Policy::new(
            saved
                .iter()
                .map(|network| {
                    let mut entry = Saved::new(network.ssid.clone(), network.secured);
                    entry.hidden = network.hidden;
                    entry.auto_connect = network.auto_connect;
                    // Stored as Unix time; the policy counts monotonic seconds. Earlier than this boot is fine as 0.
                    entry.last_connected = network
                        .last_connected_ts
                        .map(|ts| (ts - wall_offset).max(0) as u64);
                    entry
                })
                .collect(),
        );
        Self {
            policy,
            radio,
            supplicant: None,
            store,
            keystore,
            runtime,
            bus,
            sender,
            readers: Arc::default(),
            client_on,
            hotspot_on,
            hotspot: HotspotConfig {
                ssid: ssid.unwrap_or(default_hotspot_ssid),
                password: hotspot_password,
                country,
                channel,
            },
            hotspot_frequency: None,
            hotspot_checked: std::time::Instant::now(),
            antenna_external,
            address: None,
            signal: None,
            fault: None,
            wall_offset,
        }
    }

    /// Applies the saved state at start.
    fn bring_up(&mut self) {
        if self.radio.antenna_supported()
            && let Err(error) = self.radio.set_antenna(self.antenna_external)
        {
            log::warn!("wifi: antenna: {error}");
        }
        if self.client_on {
            if let Err(error) = self.radio.client_dhcp(true) {
                log::warn!("wifi: DHCP on: {error}");
            }
            // A hub restart finds wpa_supplicant still connected: keep that connection.
            let current = if self.ensure_supplicant() {
                self.supplicant
                    .as_ref()
                    .and_then(|supplicant| supplicant.current())
            } else {
                None
            };
            let resumed = current
                .as_deref()
                .is_some_and(|ssid| self.policy.resume(ssid, clock::mono()).is_ok());
            if resumed {
                log::info!("wifi: kept the connection wpa_supplicant already had");
            } else if self.supplicant.is_some() {
                let actions = self.policy.set_enabled(true, clock::mono());
                self.perform(actions);
            }
        }
        self.apply_hotspot();
    }

    fn run(&mut self, inbox: mpsc::Receiver<Message>) {
        loop {
            let wait = self
                .policy
                .next_deadline()
                .map_or(Duration::from_secs(2), |deadline| {
                    Duration::from_secs(deadline.saturating_sub(clock::mono()).clamp(0, 2))
                });
            match inbox.recv_timeout(wait.max(Duration::from_millis(200))) {
                Ok(message) => self.handle(message),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            let actions = self.policy.tick(clock::mono());
            self.perform(actions);
            self.check_address();
            self.check_hotspot();
        }
    }

    /// Brings a hotspot that should be running back when its access point went away under it.
    fn check_hotspot(&mut self) {
        if self.hotspot_frequency.is_none() || self.hotspot_checked.elapsed() < HOTSPOT_CHECK {
            return;
        }
        self.hotspot_checked = std::time::Instant::now();
        if !self.radio.hotspot_healthy() {
            log::warn!("wifi: the hotspot's access point is down; restarting it");
            if let Err(error) = self.radio.restart_hotspot() {
                log::error!("wifi: restarting the hotspot: {error}");
            }
        }
    }

    fn handle(&mut self, message: Message) {
        let now = clock::mono();
        match message {
            Message::Get(reply) => {
                let _ = reply.send(Ok(self.view()));
            }
            Message::Scan(reply) => {
                let result = if self.policy.state() == &policy::State::Off {
                    // The radio may be busy as the hotspot's access point, which cannot scan.
                    Err(WifiError::Unavailable(
                        "Switch on the Wi-Fi network to scan.".into(),
                    ))
                } else {
                    let actions = self.policy.request_scan(now);
                    let started = !actions.is_empty();
                    self.perform(actions);
                    Ok(started)
                };
                let _ = reply.send(result);
            }
            Message::Save {
                ssid,
                password,
                hidden,
                reply,
            } => {
                let result = self.save(&ssid, password, hidden, now);
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::Patch {
                ssid,
                password,
                auto_connect,
                reply,
            } => {
                let result = self.patch(&ssid, password, auto_connect, now);
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::Forget { ssid, reply } => {
                let result = self.policy.forget(&ssid, now).map_err(policy_error);
                let result = result.map(|actions| {
                    self.forget_secret(&ssid);
                    if let Some(supplicant) = &mut self.supplicant {
                        let _ = supplicant.remove(&ssid);
                    }
                    self.perform(actions);
                    self.persist();
                });
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::Connect { ssid, reply } => {
                let result = self
                    .policy
                    .connect(&ssid, now)
                    .map_err(policy_error)
                    .map(|actions| self.perform(actions));
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::Order { ssids, reply } => {
                let result =
                    self.policy
                        .reorder(&ssids, now)
                        .map_err(policy_error)
                        .map(|actions| {
                            self.perform(actions);
                            self.persist();
                        });
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::Unpin(reply) => {
                let actions = self.policy.unpin(now);
                self.perform(actions);
                let _ = reply.send(Ok(self.view()));
                self.changed();
            }
            Message::SetClient { on, reply } => {
                if on != self.client_on {
                    self.client_on = on;
                    self.save_setting(CLIENT_ON, on);
                    // The hotspot moves between wlan0 (alone) and uap0 (next to the client): stop it first.
                    if self.hotspot_frequency.is_some() {
                        self.start_hotspot(None);
                    }
                    if on {
                        self.client_up()
                    } else {
                        self.client_down()
                    }
                    self.apply_hotspot_now();
                }
                let _ = reply.send(Ok(self.view()));
                self.changed();
            }
            Message::SetHotspotOn { on, reply } => {
                if on != self.hotspot_on {
                    self.hotspot_on = on;
                    self.save_setting(HOTSPOT_ON, on);
                    self.apply_hotspot();
                }
                let _ = reply.send(Ok(self.view()));
                self.changed();
            }
            Message::SetHotspot {
                ssid,
                password,
                reply,
            } => {
                let result = self.set_hotspot(ssid, password);
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::SetAntenna { external, reply } => {
                let result = if !self.radio.antenna_supported() {
                    Err(WifiError::Unavailable(
                        "This board has no antenna switch.".into(),
                    ))
                } else {
                    self.radio
                        .set_antenna(external)
                        .map_err(|error| WifiError::Unavailable(error.to_string()))
                        .map(|()| {
                            self.antenna_external = external;
                            self.save_setting(ANTENNA_EXTERNAL, external);
                        })
                };
                let _ = reply.send(result.map(|()| self.view()));
                self.changed();
            }
            Message::Notice(text) => self.notice(&text, now),
            Message::SupplicantLost => {
                log::warn!("wifi: lost wpa_supplicant; starting it again");
                self.stop_notice_reader();
                self.supplicant = None;
                if self.client_on {
                    self.client_down();
                    self.client_up();
                }
            }
        }
    }

    /* ── the client ── */

    fn ensure_supplicant(&mut self) -> bool {
        if self.supplicant.is_some() {
            return true;
        }
        let supplicant = match self.radio.supplicant() {
            Ok(supplicant) => supplicant,
            Err(error) => {
                log::error!("wifi: cannot start wpa_supplicant: {error}");
                self.fault = Some(format!("The Wi-Fi client did not start: {error}"));
                return false;
            }
        };
        self.fault = None;
        self.supplicant = Some(supplicant);
        // Every saved network, with its password from the keystore.
        let networks: Vec<(String, bool, bool)> = self
            .policy
            .saved()
            .iter()
            .map(|saved| (saved.ssid.clone(), saved.secured, saved.hidden))
            .collect();
        let names: Vec<String> = networks.iter().map(|(ssid, _, _)| ssid.clone()).collect();
        if let Some(supplicant) = &mut self.supplicant
            && let Err(error) =
                supplicant.retain(&names.iter().map(String::as_str).collect::<Vec<_>>())
        {
            log::warn!("wifi: cannot drop old networks: {error}");
        }
        for (ssid, secured, hidden) in networks {
            let password = if secured {
                self.secret(&password_key(&ssid))
            } else {
                None
            };
            if secured && password.is_none() {
                log::warn!("wifi: no password stored for a saved network; it cannot be joined");
                continue;
            }
            if let Some(supplicant) = &mut self.supplicant
                && let Err(error) = supplicant.configure(&ssid, password.as_deref(), hidden)
            {
                log::warn!("wifi: cannot configure a saved network: {error}");
            }
        }
        self.start_notice_reader();
        true
    }

    fn start_notice_reader(&mut self) {
        // At most one reader: any earlier one stops.
        self.stop_notice_reader();
        let next = match self.radio.notices() {
            Ok(next) => next,
            Err(error) => {
                log::error!("wifi: cannot listen to wpa_supplicant: {error}");
                return;
            }
        };
        let _ = spawn_notice_reader(next, self.sender.clone(), self.readers.clone(), NOTICE_POLL);
    }

    /// The running notice reader exits within [`NOTICE_POLL`] and drops its socket.
    fn stop_notice_reader(&mut self) {
        self.readers.fetch_add(1, Ordering::SeqCst);
    }

    fn client_up(&mut self) {
        if let Err(error) = self.radio.client_dhcp(true) {
            log::warn!("wifi: DHCP on: {error}");
        }
        if self.ensure_supplicant() {
            let actions = self.policy.set_enabled(true, clock::mono());
            self.perform(actions);
        }
    }

    fn client_down(&mut self) {
        let actions = self.policy.set_enabled(false, clock::mono());
        self.perform(actions);
        self.stop_notice_reader();
        if let Err(error) = self.radio.stop_supplicant() {
            log::warn!("wifi: stop wpa_supplicant: {error}");
        }
        if let Err(error) = self.radio.client_dhcp(false) {
            log::warn!("wifi: DHCP off: {error}");
        }
        self.supplicant = None;
        self.address = None;
        self.signal = None;
        self.fault = None;
    }

    fn perform(&mut self, actions: Vec<Action>) {
        if actions.is_empty() {
            return;
        }
        for action in actions {
            let result = match (&action, &mut self.supplicant) {
                (_, None) => Ok(()),
                (Action::Join(ssid), Some(supplicant)) => supplicant.select(ssid),
                (Action::Disconnect, Some(supplicant)) => supplicant.disconnect(),
                (Action::Scan, Some(supplicant)) => supplicant.scan().map(|_| ()),
            };
            if let Err(error) = result {
                log::warn!("wifi: {action:?}: {error}");
            }
            if matches!(action, Action::Join(_) | Action::Disconnect) {
                self.address = None;
                self.signal = None;
            }
        }
        self.changed();
    }

    fn notice(&mut self, text: &str, now: u64) {
        let notice = wpa::parse_notice(text);
        let event = match &notice {
            Notice::ScanResults => {
                let Some(supplicant) = &mut self.supplicant else {
                    return;
                };
                match supplicant.scan_results() {
                    Ok(seen) => Some(Event::ScanResults(seen)),
                    Err(error) => {
                        log::warn!("wifi: scan results: {error}");
                        None
                    }
                }
            }
            Notice::Terminating => {
                self.handle(Message::SupplicantLost);
                return;
            }
            _ => self
                .supplicant
                .as_ref()
                .and_then(|supplicant| supplicant.translate(&notice)),
        };
        let Some(event) = event else { return };
        let was_scan = matches!(event, Event::ScanResults(_));
        let actions = self.policy.handle(event, now);
        self.perform(actions);
        if was_scan {
            self.bus
                .publish("network", "wifi.scan", self.view().scan_results());
        }
        // The client's channel may have changed: the hotspot follows it.
        self.apply_hotspot();
    }

    /// Polls for the DHCP address while joining, and the signal while connected.
    fn check_address(&mut self) {
        match self.policy.state().clone() {
            policy::State::Connecting {
                associated: true, ..
            } => {
                if let Some(address) = self.radio.client_address() {
                    self.address = Some(address);
                    let actions = self.policy.handle(Event::AddressAcquired, clock::mono());
                    self.perform(actions);
                    self.persist();
                    self.apply_hotspot();
                }
            }
            policy::State::Connected { .. } => {
                let signal = self
                    .supplicant
                    .as_mut()
                    .and_then(|supplicant| supplicant.signal());
                if signal.map(|dbm| dbm / 3) != self.signal.map(|dbm| dbm / 3) {
                    // Only a real change is news: a few dB of jitter is not.
                    self.signal = signal;
                    self.changed();
                }
            }
            _ => {}
        }
    }

    fn save(
        &mut self,
        ssid: &str,
        password: Option<String>,
        hidden: bool,
        now: u64,
    ) -> Result<(), WifiError> {
        let ssid = ssid.trim();
        if !wpa::valid_ssid(ssid) {
            return Err(WifiError::Invalid("ssid", "Use 1 to 32 characters."));
        }
        if password
            .as_deref()
            .is_some_and(|password| !wpa::valid_passphrase(password))
        {
            return Err(WifiError::Invalid(
                "password",
                "Use 8 to 63 letters, digits or symbols.",
            ));
        }
        let secured = password.is_some();
        match &password {
            Some(password) => self.store_secret(&password_key(ssid), password)?,
            None => self.forget_secret(ssid),
        }
        if let Some(supplicant) = &mut self.supplicant {
            supplicant
                .configure(ssid, password.as_deref(), hidden)
                .map_err(|error| WifiError::Unavailable(error.to_string()))?;
        }
        let mut network = Saved::new(ssid, secured);
        network.hidden = hidden;
        let actions = self.policy.save(network, now);
        self.persist();
        self.perform(actions);
        Ok(())
    }

    fn patch(
        &mut self,
        ssid: &str,
        password: Option<Option<String>>,
        auto_connect: Option<bool>,
        now: u64,
    ) -> Result<(), WifiError> {
        let saved = self
            .policy
            .saved()
            .iter()
            .find(|saved| saved.ssid == ssid)
            .cloned()
            .ok_or(WifiError::NotSaved)?;
        if let Some(password) = password {
            if password
                .as_deref()
                .is_some_and(|password| !wpa::valid_passphrase(password))
            {
                return Err(WifiError::Invalid(
                    "password",
                    "Use 8 to 63 letters, digits or symbols.",
                ));
            }
            match &password {
                Some(password) => self.store_secret(&password_key(ssid), password)?,
                None => self.forget_secret(ssid),
            }
            if let Some(supplicant) = &mut self.supplicant {
                supplicant
                    .configure(ssid, password.as_deref(), saved.hidden)
                    .map_err(|error| WifiError::Unavailable(error.to_string()))?;
            }
            let actions = self
                .policy
                .password_changed(ssid, password.is_some(), now)
                .map_err(policy_error)?;
            self.perform(actions);
        }
        if let Some(auto_connect) = auto_connect {
            let actions = self
                .policy
                .set_auto_connect(ssid, auto_connect, now)
                .map_err(policy_error)?;
            self.perform(actions);
        }
        self.persist();
        Ok(())
    }

    /* ── the hotspot ── */

    fn set_hotspot(&mut self, ssid: String, password: Option<String>) -> Result<(), WifiError> {
        let ssid = ssid.trim().to_owned();
        if !wpa::valid_ssid(&ssid) {
            return Err(WifiError::Invalid("ssid", "Use 1 to 32 characters."));
        }
        if password
            .as_deref()
            .is_some_and(|password| !wpa::valid_passphrase(password))
        {
            return Err(WifiError::Invalid(
                "password",
                "Use 8 to 63 letters, digits or symbols.",
            ));
        }
        match &password {
            Some(password) => self.store_secret(HOTSPOT_PASSWORD_KEY, password)?,
            None => {
                if let Ok(mut keys) = self.keystore.lock() {
                    let _ = keys.remove(HOTSPOT_PASSWORD_KEY);
                }
            }
        }
        let stored = ssid.clone();
        let _ = self.runtime.block_on(
            self.store
                .call(move |c| settings::set(c, HOTSPOT_SSID, &stored)),
        );
        self.hotspot.ssid = ssid;
        self.hotspot.password = password;
        // A new name or password needs a restart of the access point.
        self.hotspot_frequency = None;
        self.apply_hotspot_now();
        Ok(())
    }

    /// Starts, stops or moves the hotspot to match the switches and the client's channel.
    ///
    /// The radio has one channel, so while the client is connected the hotspot
    /// uses the client's. When the client drops, the hotspot stays where it is:
    /// a restart would drop every device on it. `Some(0)` means "its own channel".
    fn apply_hotspot(&mut self) {
        let wanted = match (
            self.hotspot_on,
            self.client_frequency(),
            self.hotspot_frequency,
        ) {
            (false, _, _) => None,
            (true, Some(frequency), _) => Some(frequency),
            (true, None, Some(running)) => Some(running),
            (true, None, None) => Some(0),
        };
        if wanted != self.hotspot_frequency {
            self.start_hotspot(wanted);
        }
    }

    /// Restarts the hotspot on its current channel (new name or password).
    fn apply_hotspot_now(&mut self) {
        let channel = if self.hotspot_on {
            Some(
                self.client_frequency()
                    .or(self.hotspot_frequency)
                    .unwrap_or(0),
            )
        } else {
            None
        };
        self.start_hotspot(channel);
    }

    fn start_hotspot(&mut self, frequency: Option<u32>) {
        let config = frequency.map(|_| &self.hotspot);
        match self
            .radio
            .hotspot(config, frequency.filter(|frequency| *frequency != 0))
        {
            Ok(()) => self.hotspot_frequency = frequency,
            Err(error) => log::error!("wifi: hotspot: {error}"),
        }
    }

    fn client_frequency(&mut self) -> Option<u32> {
        if !matches!(self.policy.state(), policy::State::Connected { .. }) {
            return None;
        }
        self.supplicant
            .as_mut()
            .and_then(|supplicant| supplicant.frequency())
    }

    /* ── persistence ── */

    fn persist(&self) {
        let networks: Vec<saved_db::SavedNetwork> = self
            .policy
            .saved()
            .iter()
            .map(|saved| saved_db::SavedNetwork {
                ssid: saved.ssid.clone(),
                secured: saved.secured,
                hidden: saved.hidden,
                auto_connect: saved.auto_connect,
                last_connected_ts: saved
                    .last_connected
                    .map(|mono| mono as i64 + self.wall_offset),
            })
            .collect();
        if let Err(error) = self.runtime.block_on(
            self.store
                .call(move |c| saved_db::replace_all(c, &networks)),
        ) {
            log::error!("wifi: cannot save the network list: {error}");
        }
    }

    fn save_setting(&self, key: &'static str, value: bool) {
        if let Err(error) = self
            .runtime
            .block_on(self.store.call(move |c| settings::set_bool(c, key, value)))
        {
            log::error!("wifi: cannot save {key}: {error}");
        }
    }

    fn secret(&self, name: &str) -> Option<String> {
        self.keystore
            .lock()
            .ok()?
            .get(name)?
            .expose_str()
            .map(str::to_owned)
    }

    fn store_secret(&self, name: &str, value: &str) -> Result<(), WifiError> {
        let mut keys = self
            .keystore
            .lock()
            .map_err(|_| WifiError::Unavailable("Keystore unavailable.".into()))?;
        keys.set(name, value).map_err(|error| {
            log::error!("wifi: keystore: {error}");
            WifiError::Unavailable("Could not store the password.".into())
        })
    }

    fn forget_secret(&self, ssid: &str) {
        if let Ok(mut keys) = self.keystore.lock() {
            let _ = keys.remove(&password_key(ssid));
        }
    }

    /// Tells subscribers. Events go to viewers too, so never with the hotspot password.
    fn changed(&self) {
        self.bus
            .publish("network", "wifi.changed", self.view().for_viewer());
    }

    fn view(&self) -> WifiView {
        WifiView::build(self)
    }
}

/// Reads notices on its own thread until `readers` moves past the value it started at,
/// the service is gone, or the socket fails (then reports the daemon lost).
fn spawn_notice_reader(mut next: NoticeReader, sender: mpsc::Sender<Message>, readers: Arc<AtomicU64>, poll: Duration) -> std::io::Result<thread::JoinHandle<()>> {
    let mine = readers.load(Ordering::SeqCst);
    let current = move || readers.load(Ordering::SeqCst) == mine;
    thread::Builder::new()
        .name("hub-wifi-events".into())
        .spawn(move || {
            while current() {
                match next(poll) {
                    Ok(Some(text)) => {
                        if !current() || sender.send(Message::Notice(text)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        if current() {
                            let _ = sender.send(Message::SupplicantLost);
                        }
                        return;
                    }
                }
            }
        })
}

fn policy_error(error: PolicyError) -> WifiError {
    match error {
        PolicyError::NotSaved => WifiError::NotSaved,
        PolicyError::BadOrder => WifiError::BadOrder,
    }
}

#[cfg(test)]
mod tests;

/// A device without Wi-Fi (development on a laptop): every daemon operation fails, politely.
pub struct NullRadio;

impl Radio for NullRadio {
    fn supplicant(&mut self) -> std::io::Result<Box<dyn Supplicant>> {
        Err(std::io::Error::other("no Wi-Fi on this machine"))
    }
    fn notices(&mut self) -> std::io::Result<NoticeReader> {
        Err(std::io::Error::other("no Wi-Fi on this machine"))
    }
    fn stop_supplicant(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn hotspot(&mut self, _: Option<&HotspotConfig>, _: Option<u32>) -> std::io::Result<()> {
        Ok(())
    }
    fn client_address(&mut self) -> Option<String> {
        None
    }
    fn client_dhcp(&mut self, _: bool) -> std::io::Result<()> {
        Ok(())
    }
    fn antenna_supported(&self) -> bool {
        false
    }
    fn set_antenna(&mut self, _: bool) -> std::io::Result<()> {
        Err(std::io::Error::other("no antenna switch"))
    }
}
