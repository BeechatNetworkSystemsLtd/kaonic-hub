use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use kaonic_wifi::policy::{Event, Problem};
use kaonic_wifi::supplicant::Supplicant;
use kaonic_wifi::wpa::parse_notice;

/// A fake wpa_supplicant: numbers networks on ADD_NETWORK, answers SCAN with
/// FAIL-BUSY the second time, OK to everything else, and logs what it was told.
fn fake(name: &str) -> (std::path::PathBuf, std::path::PathBuf, std::thread::JoinHandle<Vec<String>>) {
    let dir = std::env::temp_dir().join(format!("ks-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wlan0");
    let socket = UnixDatagram::bind(&path).unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let server = std::thread::spawn(move || {
        let mut log = Vec::new();
        let (mut next_id, mut scans) = (0, 0);
        let mut buffer = [0u8; 4096];
        while let Ok((length, from)) = socket.recv_from(&mut buffer) {
            let command = String::from_utf8_lossy(&buffer[..length]).into_owned();
            let reply = match command.as_str() {
                "ADD_NETWORK" => {
                    next_id += 1;
                    format!("{}\n", next_id - 1)
                }
                "SCAN" => {
                    scans += 1;
                    if scans == 1 { "OK\n".into() } else { "FAIL-BUSY\n".into() }
                }
                "SCAN_RESULTS" => "bssid / frequency / signal level / flags / ssid\naa\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tHome\n".into(),
                // An earlier run left one network, and is connected to it.
                "LIST_NETWORKS" => "network id / ssid / bssid / flags\n7\tOld\tany\t[CURRENT]\n".into(),
                "STATUS" => "wpa_state=COMPLETED\nssid=Old\nid=7\n".into(),
                "DETACH" => break,
                _ => "OK\n".into(),
            };
            log.push(command);
            let _ = socket.send_to_addr(reply.as_bytes(), &from);
        }
        log
    });
    (path, dir, server)
}

#[test]
fn owns_the_network_list_and_enables_one_network_at_a_time() {
    let (path, dir, server) = fake("own");
    let mut wpa = Supplicant::open(&path, &dir).unwrap();
    // It adopted what was there, including the connection.
    assert_eq!(wpa.current(), Some("Old"));
    wpa.configure("Home", Some("home-password"), false).unwrap();
    wpa.configure("Cafe", None, true).unwrap();
    // A new password replaces the network rather than adding a second one.
    wpa.configure("Home", Some("new-password"), false).unwrap();
    wpa.select("Home").unwrap();
    assert!(wpa.scan().unwrap());
    assert!(!wpa.scan().unwrap());
    assert_eq!(wpa.scan_results().unwrap()[0].ssid, "Home");
    wpa.disconnect().unwrap();
    assert!(wpa.select("Nowhere").is_err());
    drop(wpa);

    let log = server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let expected = [
        "LIST_NETWORKS",
        "STATUS",
        "ADD_NETWORK",
        "SET_NETWORK 0 ssid 486f6d65",
        "SET_NETWORK 0 key_mgmt WPA-PSK WPA-PSK-SHA256 SAE",
        "SET_NETWORK 0 psk \"home-password\"",
        "SET_NETWORK 0 ieee80211w 1",
        "DISABLE_NETWORK 0",
        "ADD_NETWORK",
        "SET_NETWORK 1 ssid 43616665",
        "SET_NETWORK 1 key_mgmt NONE",
        "SET_NETWORK 1 scan_ssid 1",
        "DISABLE_NETWORK 1",
        // A new password updates the network in place.
        "SET_NETWORK 0 ssid 486f6d65",
        "SET_NETWORK 0 key_mgmt WPA-PSK WPA-PSK-SHA256 SAE",
        "SET_NETWORK 0 psk \"new-password\"",
        "SET_NETWORK 0 ieee80211w 1",
        "DISABLE_NETWORK 0",
        "SELECT_NETWORK 0",
        "SCAN",
        "SCAN",
        "SCAN_RESULTS",
        "DISABLE_NETWORK all",
        "DISCONNECT",
    ];
    assert_eq!(log, expected);
}

#[test]
fn notices_become_policy_events() {
    let (path, dir, server) = fake("events");
    let mut wpa = Supplicant::open(&path, &dir).unwrap();
    wpa.configure("Home", Some("home-password"), false).unwrap();
    wpa.select("Home").unwrap();

    let event = |text: &str| wpa.translate(&parse_notice(text));
    assert_eq!(event("<3>CTRL-EVENT-CONNECTED - Connection to aa completed [id=0 id_str=]"), Some(Event::Associated("Home".into())));
    assert_eq!(
        event("<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Home\" auth_failures=1 duration=10 reason=WRONG_KEY"),
        Some(Event::Failed("Home".into(), Problem::WrongPassword))
    );
    // The first report can come from a scan started before the selection: only a second is believed.
    assert_eq!(event("<3>CTRL-EVENT-NETWORK-NOT-FOUND"), None);
    assert_eq!(event("<3>CTRL-EVENT-NETWORK-NOT-FOUND"), Some(Event::Failed("Home".into(), Problem::NotFound)));
    assert_eq!(event("<3>CTRL-EVENT-DISCONNECTED bssid=aa reason=3 locally_generated=1"), None);
    assert_eq!(event("<3>CTRL-EVENT-DISCONNECTED bssid=aa reason=4"), Some(Event::Disconnected));
    assert_eq!(event("<3>CTRL-EVENT-ASSOC-REJECT bssid=aa status_code=17"), None);

    drop(wpa);
    server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn refuses_values_wpa_supplicant_would_reject_before_sending_anything() {
    let (path, dir, server) = fake("refuse");
    let mut wpa = Supplicant::open(&path, &dir).unwrap();
    assert!(wpa.configure("", None, false).is_err());
    assert!(wpa.configure(&"x".repeat(33), None, false).is_err());
    assert!(wpa.configure("Home", Some("short"), false).is_err());
    drop(wpa);
    assert_eq!(server.join().unwrap(), vec!["LIST_NETWORKS", "STATUS"]);
    std::fs::remove_dir_all(dir).unwrap();
}
