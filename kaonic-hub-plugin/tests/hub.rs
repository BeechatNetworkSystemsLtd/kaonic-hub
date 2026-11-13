//! The SDK against the hub's real plugin API, on each plugin's own Unix socket as the hub
//! serves it in this process, with a real installer (in-process, on its socket, with a
//! systemd that only remembers) issuing the tokens.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kaonic_hub::api::{BOOT_IDENTITY, Jobs};
use kaonic_hub::app::{App, Config, Inner};
use kaonic_hub::auth::Limiter;
use kaonic_hub::events::Bus;
use kaonic_hub::plugin_api::wire;
use kaonic_hub::system::{Device, Metrics};
use kaonic_hub::wifi;
use kaonic_hub_installer::host::Fake;
use kaonic_hub_installer::{Installer, Paths};
use kaonic_hub_plugin::page::{self, Response};
use kaonic_hub_plugin::{DropReason, Error, Event, Hub, Link, Target};
use kaonic_keystore::{Keystore, RawKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\nnot really an image";
const NODE: &str = "00112233445566778899aabbccddeeff";
const MESH: &str = "[service]\npermissions = \"mesh\"\n";
const PASSWORD: &str = "correct-horse-1";
/// The tests that set the installer's environment take turns.
static ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn tempdir(name: &str) -> PathBuf {
    // Short: a socket path is at most 104 bytes on macOS.
    let dir = Path::new("/tmp").join(format!("khs-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    dir
}

/// This test's user: the owner of what it makes.
fn own_uid(made: &Path) -> u32 {
    std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(made).unwrap())
}

/// A package as `tar` and `sha256sum` would make it.
fn package(id: &str, extra: &str) -> Vec<u8> {
    let manifest = format!("[kaonic-plugin]\nformat = 2\nid = \"{id}\"\nname = \"{id}\"\nversion = \"1.0.0\"\ndeveloper = \"Test\"\nicon = \"files/icon.png\"\n{extra}");
    let program = format!("bin/{id}");
    let files: Vec<(&str, &[u8])> = vec![("kaonic-plugin.toml", manifest.as_bytes()), (&program, b"#!/bin/sh\nsleep 1000\n"), ("files/icon.png", PNG)];
    let sums: String = files.iter().map(|(path, data)| format!("{}  {path}\n", kaonic_hub_installer::sha256_hex(data))).collect();
    let mut all = files.clone();
    all.push(("SHA256SUMS", sums.as_bytes()));
    kaonic_hub_installer::tar::write(&all)
}

/// An installer on its socket and a hub serving each plugin's API on its own socket.
struct Bench {
    installer: Arc<Installer>,
    app: App,
}

async fn bench(name: &str, plugins: &[(&str, &str)]) -> Bench {
    let bench = bench_without_sockets(name, plugins).await;
    bench.open_sockets().await;
    bench
}

/// As [`bench`], before the hub has made the plugins' sockets.
async fn bench_without_sockets(name: &str, plugins: &[(&str, &str)]) -> Bench {
    let root = tempdir(name);
    let uid = own_uid(&root);
    let paths = Paths::under(&root.join("d"));
    let installer = Arc::new(Installer::new(paths.clone(), vec![b"a release key".to_vec()], Arc::new(Fake::default()), Duration::ZERO).unwrap());
    for (id, extra) in plugins {
        let (installer, package) = (installer.clone(), package(id, extra));
        tokio::task::spawn_blocking(move || installer.install(&mut package.as_slice(), false)).await.unwrap().unwrap();
    }
    let listener = kaonic_hub_installer::api::bind(&paths.socket).unwrap();
    tokio::spawn(kaonic_hub_installer::api::serve(listener, vec![uid], installer.clone(), std::future::pending()));

    let settings = kaonic_hub::plugins::Settings {
        installer: paths.socket.clone(),
        installer_uid: uid,
        api_dir: paths.plugin_api_dir.clone(),
        // The plugins "run" as this test's user.
        plugins_uid: Some(uid),
        dir: paths.plugins.clone(),
        airtime_share: 0.1,
        core_dir: paths.core.clone(),
        installer_state: paths.state.clone(),
        release_key: root.join("no-release-key"),
    };
    let dir = root.join("hub");
    std::fs::create_dir_all(dir.join("webui")).unwrap();
    std::fs::write(dir.join("webui/index.html"), "<!doctype html>").unwrap();
    let store = kaonic_store::Store::open_in_memory().unwrap();
    let mut keystore = Keystore::create(dir.join("keystore"), &RawKey::generate().unwrap()).unwrap();
    keystore.get_or_generate(BOOT_IDENTITY, 64).unwrap();
    let keystore = Arc::new(Mutex::new(keystore));
    let bus = Bus::new();
    let wifi = wifi::start(Box::new(wifi::NullRadio), store.clone(), keystore.clone(), bus.clone(), "Kaonic /TEST/".into()).unwrap();
    let app = App::new(Inner {
        config: Config {
            state_dir: dir.clone(),
            webui: kaonic_hub::web::Webui::Dir(dir.join("webui")),
            run_dir: dir.join("run"),
            dev: true,
            radio: "rf09_a".into(),
            setup_interfaces: vec!["br0".into()],
            plugins: settings,
        },
        store,
        keystore,
        bus,
        limiter: Limiter::default(),
        argon: Semaphore::new(1),
        device: Device::new(&dir),
        metrics: Metrics::default(),
        wifi,
        jobs: Jobs::default(),
        ca_pem: std::sync::OnceLock::new(),
        mesh: None,
        provisioning: Default::default(),
        radio_stats: Default::default(),
        links: Default::default(),
        ptt_group: Default::default(),
        ptt: Default::default(),
        vpn: Default::default(),
        vpn_error: Default::default(),
        vpn_config: None,
        plugins: Default::default(),
    });
    Bench { installer, app }
}

impl Bench {
    /// What the hub does when it sees the installer's list: a socket per plugin.
    async fn open_sockets(&self) {
        self.app.plugins().reconcile(&self.app).await;
    }

    fn token_file(&self, id: &str) -> PathBuf {
        self.installer.paths().plugin(id).join("token")
    }

    /// `KAONIC_HUB_API` as the installer sets it for `id`.
    fn api(&self, id: &str) -> String {
        format!("unix:{}", self.installer.paths().plugin_api_socket(id).display())
    }

    fn hub(&self, id: &str) -> Hub {
        Hub::connect_to(&self.api(id), &std::fs::read_to_string(self.token_file(id)).unwrap()).unwrap()
    }

    /// Sets what the installer would for `id`; the caller holds [`ENV`].
    fn set_env(&self, id: &str) {
        // SAFETY: only the tests holding ENV touch these variables.
        unsafe {
            std::env::set_var(kaonic_hub_plugin::ENV_API, self.api(id));
            std::env::set_var(kaonic_hub_plugin::ENV_TOKEN, self.token_file(id));
        }
    }
}

/// The next event, within a second.
async fn next(events: &mut kaonic_hub_plugin::Events) -> Event {
    tokio::time::timeout(Duration::from_secs(5), events.next()).await.expect("an event in time").expect("the socket is open")
}

#[tokio::test]
async fn who_we_are_and_the_nodes() {
    let bench = bench("self", &[("echo", MESH)]).await;
    let hub = bench.hub("echo");
    let me = hub.me().await.unwrap();
    assert_eq!((me.plugin.as_str(), me.version.as_str(), me.node.as_deref()), ("echo", "1.0.0", None));
    assert!(me.has("mesh"));
    assert!(me.limits.max_message > 700 && me.limits.max_broadcast > 700, "{:?}", me.limits);
    assert_eq!((me.limits.queue, me.limits.store.max_value, me.limits.airtime_share), (64, 64 * 1024, 0.1));
    assert!(!me.hub_version.is_empty());

    // No mesh here: no trusted nodes.
    assert!(hub.nodes().await.unwrap().is_empty());
    assert!(matches!(hub.node(NODE).await, Err(Error::NotFound)));
    assert!(matches!(hub.node("../self").await, Err(Error::NotFound)));
    let stats = hub.stats().await.unwrap();
    assert_eq!((stats.sent, stats.airtime_share), (0, 0.1));
    assert_eq!(kaonic_hub_plugin::Node::default().link, Link::Down);
}

#[tokio::test]
async fn the_store_round_trips_and_is_each_plugins_own() {
    let bench = bench("store", &[("alpha", ""), ("beta", "")]).await;
    let (alpha, beta) = (bench.hub("alpha"), bench.hub("beta"));
    let store = alpha.store();
    assert_eq!(store.get::<u64>("count").await.unwrap(), None);
    store.set("count", &41u64).await.unwrap();
    store.set("favourites", &["b4o0cvts", "kaon7qjt"]).await.unwrap();
    assert_eq!(store.get::<u64>("count").await.unwrap(), Some(41));
    assert_eq!(store.get::<Vec<String>>("favourites").await.unwrap().unwrap(), ["b4o0cvts", "kaon7qjt"]);
    assert_eq!(store.keys().await.unwrap(), ["count", "favourites"]);
    // Asked as the wrong type.
    assert!(matches!(store.get::<String>("count").await, Err(Error::Invalid(_))));

    // Beta has its own store: none of alpha's keys, and removing there touches nothing here.
    assert_eq!(beta.store().get::<u64>("count").await.unwrap(), None);
    assert!(beta.store().keys().await.unwrap().is_empty());
    beta.store().remove("count").await.unwrap();
    assert_eq!(store.get::<u64>("count").await.unwrap(), Some(41));

    store.remove("count").await.unwrap();
    assert_eq!(store.keys().await.unwrap(), ["favourites"]);
    // Bad keys never leave the plugin; too large values are the hub's to refuse.
    assert!(matches!(store.set("a/b", &1).await, Err(Error::Invalid(_))));
    let big = "x".repeat(64 * 1024);
    let refused = store.set("big", &big).await.unwrap_err();
    assert!(matches!(&refused, Error::TooLarge { code } if code == "too_large"), "{refused:?}");
}

#[tokio::test]
async fn tokens_and_permissions() {
    let bench = bench("tokens", &[("echo", MESH), ("quiet", "")]).await;
    let wrong = Hub::connect_to(&bench.api("echo"), "kpt1.e30.AAAA").unwrap();
    assert!(matches!(wrong.me().await, Err(Error::Unauthorized)));
    assert!(matches!(wrong.events().await, Err(Error::Unauthorized)));
    // Another plugin's token, valid as it is, is not taken on echo's socket.
    let token = std::fs::read_to_string(bench.token_file("quiet")).unwrap();
    assert!(matches!(Hub::connect_to(&bench.api("echo"), &token).unwrap().me().await, Err(Error::Unauthorized)));

    // Without the mesh permission: the store works, messages and events do not.
    let quiet = bench.hub("quiet");
    assert!(!quiet.me().await.unwrap().has("mesh"));
    for refused in [quiet.send_all(1, b"hi").await.unwrap_err(), quiet.broadcast(1, b"hi").await.unwrap_err(), quiet.events().await.err().unwrap()] {
        assert!(matches!(&refused, Error::Forbidden { code, .. } if code == "missing_permission"), "{refused:?}");
    }

    // Under the installer: the token from its file, and a clear error without one.
    let echo = bench.hub("echo");
    assert_eq!(echo.me().await.unwrap().plugin, "echo");
    let _env = ENV.lock().await;
    // SAFETY: only the tests holding ENV touch these variables.
    unsafe {
        std::env::remove_var(kaonic_hub_plugin::ENV_API);
    }
    assert!(matches!(Hub::connect().await, Err(Error::Config(message)) if message.contains("KAONIC_HUB_API")));
    bench.set_env("echo");
    assert_eq!(Hub::connect().await.unwrap().me().await.unwrap().plugin, "echo");
}

#[tokio::test]
async fn messages_go_only_where_they_may() {
    let bench = bench("messages", &[("echo", MESH)]).await;
    let hub = bench.hub("echo");
    // Not a trusted node.
    assert!(matches!(hub.send(NODE, 1, b"hi").await, Err(Error::NotFound)));
    // Nobody runs it yet.
    assert_eq!(hub.send_all(1, b"hi").await.unwrap().nodes, 0);
    // No group key on this node.
    assert!(matches!(hub.broadcast(1, b"hi").await, Err(Error::Hub { status: 409, .. })));
    let max = hub.me().await.unwrap().limits.max_message;
    assert!(matches!(hub.send_all(1, &vec![0; max + 1]).await, Err(Error::TooLarge { .. })));
    assert!(hub.send_all(1, &vec![0; max]).await.is_ok());
}

#[tokio::test]
async fn the_event_socket_carries_events_and_messages() {
    let bench = bench("events", &[("echo", MESH)]).await;
    let hub = bench.hub("echo");
    let mut events = hub.events().await.unwrap();
    let bridge = bench.app.plugins().bridge.clone();
    // The socket is attached once the upgrade has run: until then, nothing is running.
    for _ in 0..100 {
        if bridge.running().contains(&wire::id_hash("echo")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(bridge.running().contains(&wire::id_hash("echo")), "the open socket counts as running");

    // Congestion, a node coming up and running echo, a message from it.
    bridge.set_congestion(0.95);
    assert_eq!(next(&mut events).await, Event::Congestion { level: 0.95 });
    bridge.link_changed(NODE, true);
    assert_eq!(next(&mut events).await, Event::NodeUp { node: NODE.into() });
    bridge.on_frame(NODE, kaonic_mux::Kind::Control, &wire::encode_running(&[wire::id_hash("echo")]), None);
    assert_eq!(next(&mut events).await, Event::PluginUp { node: NODE.into() });
    let data: Vec<u8> = (0..=255).collect();
    bridge.on_frame(NODE, kaonic_mux::Kind::Data, &wire::encode_data(wire::id_hash("echo"), 1, &data), Some(-71));
    let Event::Received { from, channel, data: got, broadcast, rssi } = next(&mut events).await else { panic!("a message") };
    assert_eq!((from.as_str(), channel, &got, broadcast, rssi), (NODE, 1, &data, false, Some(-71)));

    // Sent back on the socket: to all (the node runs echo), and to a node that is not trusted.
    let to_all = events.send(Target::All, 1, &got).await.unwrap();
    let Event::Queued { reference, nodes, .. } = next(&mut events).await else { panic!("queued") };
    assert_eq!((reference, nodes), (Some(to_all), 1));
    let to_node = events.sender().send(Target::Node(NODE.into()), 1, b"hi").await.unwrap();
    assert_ne!(to_all, to_node);
    let Event::Refused { reference, code, .. } = next(&mut events).await else { panic!("refused") };
    assert_eq!((reference, code.as_str()), (Some(to_node), "not_found"));
    let broadcast = events.send(Target::Broadcast, 1, b"all").await.unwrap();
    assert!(matches!(next(&mut events).await, Event::Refused { reference: Some(r), code, .. } if r == broadcast && code == "conflict"));
    // A full queue drops the oldest (no links run here, so nothing goes out).
    for _ in 0..64 {
        hub.send_all(1, b"x").await.unwrap();
    }
    let Event::Dropped { id, reason, node } = next(&mut events).await else { panic!("dropped") };
    assert_eq!((reason, node.as_deref()), (DropReason::QueueFull, Some(NODE)));
    assert!(id > 0);
    assert_eq!(hub.stats().await.unwrap().per_node[NODE].dropped, 1);

    // A node going down; closing the socket stops echo running here.
    bridge.link_changed(NODE, false);
    assert_eq!(next(&mut events).await, Event::PluginDown { node: NODE.into() });
    assert_eq!(next(&mut events).await, Event::NodeDown { node: NODE.into() });
    events.close().await.unwrap();
    for _ in 0..100 {
        if !bridge.running().contains(&wire::id_hash("echo")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!bridge.running().contains(&wire::id_hash("echo")));
}

#[tokio::test]
async fn a_new_token_is_read_again_from_its_file() {
    let bench = bench("reread", &[("echo", MESH)]).await;
    let _env = ENV.lock().await;
    bench.set_env("echo");
    let hub = Hub::connect().await.unwrap();
    assert_eq!(hub.me().await.unwrap().version, "1.0.0");
    // Reinstalled: a new token in the same file. The old one is refused, the new one read.
    let installer = bench.installer.clone();
    let package = package("echo", &format!("{MESH}args = \"again\"\n"));
    tokio::task::spawn_blocking(move || installer.install(&mut package.as_slice(), true)).await.unwrap().unwrap();
    bench.app.plugins().changed();
    assert_eq!(hub.me().await.unwrap().plugin, "echo");
    assert!(hub.events().await.is_ok());
}

#[tokio::test]
async fn connecting_waits_for_a_socket_that_comes_late() {
    let bench = bench_without_sockets("late", &[("echo", MESH)]).await;
    // Without waiting, no socket is an error at once.
    let early = bench.hub("echo");
    let refused = early.me().await.unwrap_err();
    assert!(matches!(&refused, Error::Io(error) if error.kind() == std::io::ErrorKind::NotFound), "{refused:?}");
    let waited = early.wait(Duration::from_millis(300)).await.unwrap_err();
    assert!(matches!(&waited, Error::Io(error) if error.kind() == std::io::ErrorKind::NotFound), "{waited:?}");

    let _env = ENV.lock().await;
    bench.set_env("echo");
    let connecting = tokio::spawn(Hub::connect());
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!connecting.is_finished(), "waits for the socket");
    bench.open_sockets().await;
    let hub = tokio::time::timeout(Duration::from_secs(10), connecting).await.expect("connected in time").unwrap().unwrap();
    assert_eq!(hub.me().await.unwrap().plugin, "echo");
    // The early handle works now too.
    assert_eq!(early.me().await.unwrap().plugin, "echo");
}

#[tokio::test]
async fn four_event_sockets_and_many_requests_at_once() {
    let bench = bench("caps", &[("echo", MESH)]).await;
    let hub = bench.hub("echo");
    let mut open = Vec::new();
    for _ in 0..4 {
        open.push(hub.events().await.unwrap());
    }
    let refused = hub.events().await.err().unwrap();
    assert!(matches!(refused, Error::TooManySockets), "{refused:?}");
    assert_eq!(refused.code(), Some("too_many_sockets"));

    // With the four open, more requests at once than the hub's 16 connections: they take
    // turns, none is closed unanswered.
    let calls: Vec<_> = (0..40)
        .map(|_| {
            let hub = hub.clone();
            tokio::spawn(async move { hub.me().await })
        })
        .collect();
    for call in calls {
        assert_eq!(call.await.unwrap().unwrap().plugin, "echo");
    }

    // A closed one frees its place.
    open.pop().unwrap().close().await.unwrap();
    let mut again = None;
    for _ in 0..100 {
        match hub.events().await {
            Ok(events) => {
                again = Some(events);
                break;
            }
            Err(Error::TooManySockets) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(error) => panic!("{error:?}"),
        }
    }
    assert!(again.is_some(), "a fifth after one closed");
}

/// The hub's own HTTP API and pages, served on loopback TCP for this test.
async fn serve_hub(bench: &Bench) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, kaonic_hub::router(bench.app.clone())).into_future());
    address
}

/// One request to the hub; the status, headers (in lower case) and body.
async fn ask(hub: std::net::SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, Vec<(String, String)>, String) {
    let mut stream = tokio::net::TcpStream::connect(hub).await.unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nhost: 192.168.10.1\r\nconnection: close\r\ncontent-length: {}\r\n", body.len());
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await.unwrap().unwrap();
    let answer = String::from_utf8(answer).unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers: Vec<(String, String)> = lines.filter_map(|line| line.split_once(':')).map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned())).collect();
    assert!(!headers.iter().any(|(name, value)| name == "transfer-encoding" && value.contains("chunked")), "answered with a length");
    (status, headers, body.to_owned())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

/// A tiny status page, as `examples/page.rs` serves it.
async fn status_page(request: page::Request) -> Response {
    match request.path.as_str() {
        "/" => Response::html(format!("<!doctype html><p>prefix {}</p><a href=\"files/\">files</a>", request.prefix())).header("set-cookie", "plugin=1"),
        "/go" => Response::redirect("files/done"),
        "/away" => Response::text(302, "").header("location", "/api/v1/auth/logout"),
        "/echo" => Response::text(200, format!("{} {} bytes", request.method, request.body.len())),
        path => match path.strip_prefix("/files/") {
            // Split first, then decode each piece.
            Some(rest) => {
                let pieces: Vec<String> = rest.split('/').map(|piece| page::decode(piece).unwrap_or_default()).collect();
                let query = request.query.as_deref().and_then(page::decode).unwrap_or_default();
                Response::text(200, format!("{pieces:?} {query}"))
            }
            None => Response::text(404, "no such page"),
        },
    }
}

#[tokio::test]
async fn a_page_is_served_through_the_hub() {
    let bench = bench("page", &[("status", "page = true\n")]).await;
    let socket = bench.installer.paths().page_socket("status");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    // A socket left by an earlier run is replaced.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    let listener = page::bind(&socket).unwrap();
    tokio::spawn(page::serve_on(listener, status_page));
    // Anything else there is not removed.
    let not_a_socket = socket.with_file_name("file");
    std::fs::write(&not_a_socket, "keep").unwrap();
    assert!(matches!(page::bind(&not_a_socket), Err(Error::Config(_))));
    assert_eq!(std::fs::read_to_string(&not_a_socket).unwrap(), "keep");

    let hub = serve_hub(&bench).await;
    let json = [("content-type", "application/json")];
    let (status, headers, body) = ask(hub, "POST", "/api/v1/setup", &json, &format!("{{\"mode\":\"member\",\"password\":\"{PASSWORD}\",\"codename\":\"kaon7qjt\"}}")).await;
    assert_eq!(status, 200, "{body}");
    let cookie = header(&headers, "set-cookie").unwrap().split(';').next().unwrap().to_owned();
    let csrf = serde_json::from_str::<serde_json::Value>(&body).unwrap()["csrf_token"].as_str().unwrap().to_owned();
    let (status, _, body) = ask(hub, "POST", "/api/v1/plugins/status/open", &[("cookie", &cookie), ("x-kaonic-csrf", &csrf)], "").await;
    assert_eq!(status, 200, "{body}");
    let url = serde_json::from_str::<serde_json::Value>(&body).unwrap()["url"].as_str().unwrap().to_owned();
    let prefix = url.trim_end_matches('/');

    // The page, with the prefix it was told; its cookie stays out.
    let (status, headers, body) = ask(hub, "GET", &url, &[], "").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, format!("<!doctype html><p>prefix {prefix}</p><a href=\"files/\">files</a>"));
    assert_eq!(header(&headers, "content-type"), Some("text/html; charset=utf-8"));
    assert!(header(&headers, "set-cookie").is_none());
    // The path as sent, decoded piece by piece by the page.
    let (_, _, body) = ask(hub, "GET", &format!("{url}files/a%20b/%2e%2e%2fadmin?q=x%20y"), &[], "").await;
    assert_eq!(body, r#"["a b", "../admin"] q=x y"#);
    // A body, and HEAD.
    assert_eq!(ask(hub, "POST", &format!("{url}echo"), &[], "hello").await.2, "POST 5 bytes");
    let (status, headers, body) = ask(hub, "HEAD", &format!("{url}echo"), &[], "").await;
    assert_eq!((status, header(&headers, "content-length"), body.as_str()), (200, Some("12"), ""));
    // A redirect on the page comes through; one off it does not.
    let (status, headers, _) = ask(hub, "GET", &format!("{url}go"), &[], "").await;
    assert_eq!((status, header(&headers, "location")), (303, Some("files/done")));
    let (status, headers, _) = ask(hub, "GET", &format!("{url}away"), &[], "").await;
    assert_eq!((status, header(&headers, "location")), (302, None));
    assert_eq!(ask(hub, "GET", &format!("{url}nothing"), &[], "").await.0, 404);
}

#[tokio::test]
async fn the_page_socket_comes_from_the_environment() {
    let _env = ENV.lock().await;
    // SAFETY: only the tests holding ENV touch these variables.
    unsafe {
        std::env::remove_var(kaonic_hub_plugin::ENV_PAGE_SOCKET);
    }
    assert!(matches!(page::serve(status_page).await, Err(Error::Config(message)) if message.contains("page = true")));
}
