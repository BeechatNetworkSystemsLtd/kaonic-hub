use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

use kaonic_wifi::ctrl::Ctrl;

/// A fake daemon socket in a fresh directory, answering one script of replies.
fn daemon(name: &str) -> (UnixDatagram, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("kw-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wlan0");
    (UnixDatagram::bind(&path).unwrap(), path, dir)
}

/// Answers each expected request; the socket is handed back so it stays open until the test is done with it.
fn serve(socket: UnixDatagram, replies: Vec<(&'static str, Vec<&'static str>)>) -> std::thread::JoinHandle<(Vec<String>, UnixDatagram)> {
    std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        for (expect, answers) in replies {
            let (length, from) = socket.recv_from(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..length]).into_owned();
            assert!(request.starts_with(expect), "expected {expect}, got {request}");
            seen.push(request);
            for answer in answers {
                socket.send_to_addr(answer.as_bytes(), &from).unwrap();
            }
        }
        (seen, socket)
    })
}

#[test]
fn requests_get_their_replies_and_events_in_between_are_skipped() {
    let (socket, path, dir) = daemon("req");
    let server = serve(socket, vec![("PING", vec!["PONG\n"]), ("STATUS", vec!["<3>CTRL-EVENT-SCAN-STARTED ", "wpa_state=SCANNING\n"]), ("SCAN", vec!["FAIL-BUSY\n"])]);

    let ctrl = Ctrl::open(&path, &dir).unwrap();
    assert_eq!(ctrl.request("PING").unwrap(), "PONG\n");
    assert_eq!(ctrl.request("STATUS").unwrap(), "wpa_state=SCANNING\n");
    let error = ctrl.ok("SCAN").unwrap_err();
    assert_eq!(error.to_string(), "SCAN: FAIL-BUSY");
    drop(ctrl);
    server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_attached_socket_receives_events_and_times_out_quietly() {
    let (socket, path, dir) = daemon("ev");
    let server = serve(socket, vec![("ATTACH", vec!["OK\n", "<3>CTRL-EVENT-SCAN-RESULTS "])]);

    let events = Ctrl::open(&path, &dir).unwrap();
    events.attach().unwrap();
    assert_eq!(events.next_event(Duration::from_secs(2)).unwrap().as_deref(), Some("<3>CTRL-EVENT-SCAN-RESULTS "));
    let _daemon = server.join().unwrap();
    assert_eq!(events.next_event(Duration::from_millis(50)).unwrap(), None);
    drop(events);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn errors_never_echo_a_password() {
    let (socket, path, dir) = daemon("pw");
    let server = serve(socket, vec![("SET_NETWORK", vec!["FAIL\n"])]);
    let ctrl = Ctrl::open(&path, &dir).unwrap();
    let error = ctrl.ok("SET_NETWORK 0 psk \"secret-password\"").unwrap_err().to_string();
    assert!(!error.contains("secret"), "{error}");
    server.join().unwrap();
    drop(ctrl);
    std::fs::remove_dir_all(dir).unwrap();
}
