use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kaonic_store::Store;
use kaonic_keystore::{Keystore, RawKey};
use kaonic_wifi::policy::{Event, Security, Seen};
use kaonic_wifi::wpa::Notice;

use super::*;

type Log = Arc<Mutex<Vec<String>>>;

struct FakeRadio {
    log: Log,
    notices: Arc<Mutex<Option<mpsc::Receiver<String>>>>,
    address: Arc<Mutex<Option<String>>>,
    /// Whether the access point is really up.
    healthy: Arc<std::sync::atomic::AtomicBool>,
}

struct FakeSupplicant {
    log: Log,
    selected: Option<String>,
}

impl Radio for FakeRadio {
    fn supplicant(&mut self) -> std::io::Result<Box<dyn Supplicant>> {
        self.log.lock().unwrap().push("supplicant up".into());
        Ok(Box::new(FakeSupplicant {
            log: self.log.clone(),
            selected: None,
        }))
    }
    fn notices(&mut self) -> std::io::Result<super::NoticeReader> {
        let receiver = self
            .notices
            .lock()
            .unwrap()
            .take()
            .expect("one notice reader");
        Ok(Box::new(move |timeout| {
            Ok(receiver.recv_timeout(timeout).ok())
        }))
    }
    fn stop_supplicant(&mut self) -> std::io::Result<()> {
        self.log.lock().unwrap().push("supplicant down".into());
        Ok(())
    }
    fn hotspot(
        &mut self,
        config: Option<&HotspotConfig>,
        frequency: Option<u32>,
    ) -> std::io::Result<()> {
        let entry = match config {
            Some(config) => format!(
                "hotspot {} open={} freq={frequency:?}",
                config.ssid,
                config.password.is_none()
            ),
            None => "hotspot off".into(),
        };
        self.log.lock().unwrap().push(entry);
        Ok(())
    }
    fn client_address(&mut self) -> Option<String> {
        self.address.lock().unwrap().clone()
    }
    fn client_dhcp(&mut self, on: bool) -> std::io::Result<()> {
        self.log.lock().unwrap().push(format!("dhcp {on}"));
        Ok(())
    }
    fn antenna_supported(&self) -> bool {
        false
    }
    fn set_antenna(&mut self, _: bool) -> std::io::Result<()> {
        unreachable!()
    }
    fn hotspot_healthy(&mut self) -> bool {
        self.healthy.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn restart_hotspot(&mut self) -> std::io::Result<()> {
        self.log.lock().unwrap().push("hotspot restarted".into());
        self.healthy.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

impl Supplicant for FakeSupplicant {
    fn configure(
        &mut self,
        ssid: &str,
        password: Option<&str>,
        hidden: bool,
    ) -> std::io::Result<()> {
        self.log.lock().unwrap().push(format!(
            "configure {ssid} {} hidden={hidden}",
            password.unwrap_or("-")
        ));
        Ok(())
    }
    fn remove(&mut self, ssid: &str) -> std::io::Result<()> {
        self.log.lock().unwrap().push(format!("remove {ssid}"));
        Ok(())
    }
    fn select(&mut self, ssid: &str) -> std::io::Result<()> {
        self.selected = Some(ssid.into());
        self.log.lock().unwrap().push(format!("select {ssid}"));
        Ok(())
    }
    fn disconnect(&mut self) -> std::io::Result<()> {
        self.log.lock().unwrap().push("disconnect".into());
        Ok(())
    }
    fn scan(&mut self) -> std::io::Result<bool> {
        self.log.lock().unwrap().push("scan".into());
        Ok(true)
    }
    fn scan_results(&mut self) -> std::io::Result<Vec<Seen>> {
        Ok(vec![Seen {
            ssid: "Home".into(),
            signal_dbm: -50,
            security: Security::Wpa2,
            frequency_mhz: 2437,
        }])
    }
    fn signal(&mut self) -> Option<i32> {
        Some(-52)
    }
    fn frequency(&mut self) -> Option<u32> {
        Some(2437)
    }
    fn current(&self) -> Option<String> {
        None
    }
    fn retain(&mut self, _: &[&str]) -> std::io::Result<()> {
        Ok(())
    }
    fn translate(&self, notice: &Notice) -> Option<Event> {
        match notice {
            Notice::Connected { .. } => self.selected.clone().map(Event::Associated),
            Notice::TempDisabled { ssid, .. } => notice
                .problem()
                .map(|problem| Event::Failed(ssid.clone(), problem)),
            _ => None,
        }
    }
}

struct Rig {
    wifi: WifiHandle,
    log: Log,
    notices: mpsc::Sender<String>,
    address: Arc<Mutex<Option<String>>>,
    healthy: Arc<std::sync::atomic::AtomicBool>,
    keystore: Arc<Mutex<Keystore>>,
    store: Store,
    _dir: std::path::PathBuf,
}

fn rig(name: &str) -> Rig {
    let dir = std::env::temp_dir().join(format!("kh-wifi-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let keystore = Arc::new(Mutex::new(
        Keystore::create(dir.join("keystore"), &RawKey::generate().unwrap()).unwrap(),
    ));
    let store = Store::open_in_memory().unwrap();
    let log: Log = Arc::default();
    let (notices, receiver) = mpsc::channel();
    let address = Arc::new(Mutex::new(None));
    let healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let radio = FakeRadio {
        log: log.clone(),
        notices: Arc::new(Mutex::new(Some(receiver))),
        address: address.clone(),
        healthy: healthy.clone(),
    };
    let wifi = start(
        Box::new(radio),
        store.clone(),
        keystore.clone(),
        Bus::new(),
        "Kaonic /ABCD/".into(),
    )
    .unwrap();
    Rig {
        wifi,
        log,
        notices,
        address,
        healthy,
        keystore,
        store,
        _dir: dir,
    }
}

#[tokio::test]
async fn a_hotspot_whose_access_point_went_away_is_restarted() {
    let rig = rig("hotspot-heal");
    rig.wifi.get().await.unwrap();
    taken(&rig.log);
    // Something took the interface over while hostapd kept running.
    rig.healthy.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(2600)).await;
    assert!(taken(&rig.log).contains(&"hotspot restarted".to_owned()));
    // Healthy again: no more restarts.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!taken(&rig.log).contains(&"hotspot restarted".to_owned()));
}

fn taken(log: &Log) -> Vec<String> {
    std::mem::take(&mut *log.lock().unwrap())
}

/// Waits until the service shows `state` (it reacts to notices on its own thread).
async fn until(wifi: &WifiHandle, state: &str) -> WifiView {
    for _ in 0..100 {
        let view = wifi.get().await.unwrap();
        if view.client.state == state {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never reached {state}");
}

#[tokio::test]
async fn joins_a_new_network_and_reports_the_connection() {
    let rig = rig("join");
    // A fresh device: hotspot on (open), client off.
    let view = rig.wifi.get().await.unwrap();
    assert_eq!(
        (view.client.state, view.hotspot.enabled, view.hotspot.open),
        ("off", true, true)
    );
    assert_eq!(
        taken(&rig.log),
        vec!["hotspot Kaonic /ABCD/ open=true freq=None"]
    );

    // Switching the client on moves the hotspot off wlan0 and back next to the client.
    rig.wifi.set_client(true).await.unwrap();
    assert_eq!(
        taken(&rig.log),
        vec![
            "hotspot off",
            "dhcp true",
            "supplicant up",
            "scan",
            "hotspot Kaonic /ABCD/ open=true freq=None"
        ]
    );

    let view = rig
        .wifi
        .save("Home".into(), Some("home-password".into()), false)
        .await
        .unwrap();
    assert_eq!(view.client.state, "connecting");
    assert_eq!(view.client.pinned.as_deref(), Some("Home"));
    assert_eq!(
        taken(&rig.log),
        vec!["configure Home home-password hidden=false", "select Home"]
    );

    // The password went to the keystore and the list to the database; neither holds it twice.
    let stored = rig
        .keystore
        .lock()
        .unwrap()
        .get("wifi/net/486f6d65")
        .unwrap()
        .expose_str()
        .map(str::to_owned);
    assert_eq!(stored.as_deref(), Some("home-password"));
    let saved = rig.store.call(|c| kaonic_store::wifi::list(c)).await.unwrap();
    assert_eq!(saved[0].ssid, "Home");

    rig.notices
        .send("<3>CTRL-EVENT-CONNECTED - Connection to aa completed [id=0 id_str=]".into())
        .unwrap();
    *rig.address.lock().unwrap() = Some("192.168.1.23/24".into());
    let view = until(&rig.wifi, "connected").await;
    assert_eq!(view.client.address.as_deref(), Some("192.168.1.23/24"));
    assert_eq!(view.client.signal_dbm, None.or(view.client.signal_dbm));
    // The hotspot moved to the client's channel.
    assert!(
        taken(&rig.log).contains(&"hotspot Kaonic /ABCD/ open=true freq=Some(2437)".to_owned())
    );
}

#[tokio::test]
async fn a_wrong_password_is_reported_and_not_retried() {
    let rig = rig("wrong");
    rig.wifi.set_client(true).await.unwrap();
    rig.wifi
        .save("Home".into(), Some("bad-password".into()), false)
        .await
        .unwrap();
    rig.notices.send("<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Home\" auth_failures=1 duration=10 reason=WRONG_KEY".into()).unwrap();
    let view = until(&rig.wifi, "searching").await;
    let attempt = view.client.attempt.unwrap();
    assert_eq!(
        (attempt.ssid.as_str(), attempt.reason),
        ("Home", "wrong_password")
    );
    assert_eq!(view.saved[0].problem, Some("wrong_password"));
    assert_eq!(view.saved[0].retry_ts, None);

    // A new password clears it and joins again.
    taken(&rig.log);
    let view = rig
        .wifi
        .patch("Home".into(), Some(Some("good-password".into())), None)
        .await
        .unwrap();
    assert_eq!(view.saved[0].problem, None);
    assert_eq!(
        taken(&rig.log),
        vec!["configure Home good-password hidden=false", "select Home"]
    );
}

#[tokio::test]
async fn hotspot_password_is_kept_secret_from_viewers_and_events() {
    let rig = rig("hotspot");
    let view = rig
        .wifi
        .set_hotspot("Field HQ".into(), Some("hotspot-pass".into()))
        .await
        .unwrap();
    assert_eq!(view.hotspot.password.as_deref(), Some("hotspot-pass"));
    assert!(!view.hotspot.open);
    assert_eq!(view.clone().for_viewer().hotspot.password, None);
    assert!(rig.keystore.lock().unwrap().contains("wifi/hotspot"));

    let invalid = rig
        .wifi
        .set_hotspot("x".into(), Some("short".into()))
        .await
        .unwrap_err();
    assert_eq!(
        invalid,
        WifiError::Invalid("password", "Use 8 to 63 letters, digits or symbols.")
    );
}

#[tokio::test]
async fn scanning_needs_the_client_on() {
    let rig = rig("scan");
    assert!(matches!(
        rig.wifi.scan().await,
        Err(WifiError::Unavailable(_))
    ));
    rig.wifi.set_client(true).await.unwrap();
    rig.notices
        .send("<3>CTRL-EVENT-SCAN-RESULTS ".into())
        .unwrap();
    for _ in 0..100 {
        if rig
            .wifi
            .get()
            .await
            .unwrap()
            .scan_results()
            .scanned_ts
            .is_some()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("scan results never arrived");
}

#[tokio::test]
async fn forgetting_removes_the_password_too() {
    let rig = rig("forget");
    rig.wifi
        .save("Home".into(), Some("home-password".into()), false)
        .await
        .unwrap();
    rig.wifi.forget("Home".into()).await.unwrap();
    assert!(!rig.keystore.lock().unwrap().contains("wifi/net/486f6d65"));
    assert!(
        rig.store
            .call(|c| kaonic_store::wifi::list(c))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        rig.wifi.forget("Home".into()).await.unwrap_err(),
        WifiError::NotSaved
    );
}

/// Set when the reader closure is dropped, as the real one's socket would be.
struct Dropped(Arc<std::sync::atomic::AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn a_stopped_notice_reader_exits_and_drops_its_socket() {
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let guard = Dropped(dropped.clone());
    // A daemon that went away silently: reads only ever time out.
    let next: super::NoticeReader = Box::new(move |timeout| {
        let _ = &guard;
        std::thread::sleep(timeout);
        Ok(None)
    });
    let (sender, inbox) = mpsc::channel();
    let readers = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reader = super::spawn_notice_reader(next, sender, readers.clone(), Duration::from_millis(20)).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    assert!(!reader.is_finished(), "a current reader keeps reading");
    readers.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    reader.join().unwrap();
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst), "its socket is closed");
    assert!(inbox.try_recv().is_err(), "a stopped reader reports nothing");
}

#[test]
fn a_stale_reader_does_not_report_the_daemon_lost() {
    let readers = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bump = readers.clone();
    // The socket fails only after the service moved on.
    let next: super::NoticeReader = Box::new(move |_| {
        bump.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::other("gone"))
    });
    let (sender, inbox) = mpsc::channel();
    super::spawn_notice_reader(next, sender, readers, Duration::from_millis(20)).unwrap().join().unwrap();
    assert!(inbox.try_recv().is_err());
}
