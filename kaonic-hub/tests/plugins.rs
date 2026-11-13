//! Plugins through the hub, against a real installer (its HTTP API on a Unix socket in this
//! process, with a systemd that only remembers what it was told).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use kaonic_hub::api::{BOOT_IDENTITY, Jobs};
use kaonic_hub::app::{App, Config, Inner};
use kaonic_hub::auth::{Limiter, Role};
use kaonic_hub::events::Bus;
use kaonic_hub::plugins::installer::Client;
use kaonic_hub::system::{Device, Metrics};
use kaonic_hub::wifi;
use kaonic_hub_installer::host::Fake;
use kaonic_hub_installer::manifest::Permission;
use kaonic_hub_installer::{Installer, Paths};
use kaonic_keystore::{Keystore, RawKey};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tower::ServiceExt;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\nnot really an image";
const PASSWORD: &str = "correct-horse-1";

fn own_uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

fn tempdir(name: &str) -> PathBuf {
    // Short: a socket path is at most 104 bytes on macOS.
    let dir = Path::new("/tmp").join(format!("khp-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    dir
}

/// A package as `tar` and `sha256sum` would make it: a manifest, the program and an icon.
fn package(id: &str, version: &str, extra: &str) -> Vec<u8> {
    let manifest = format!(
        "[kaonic-plugin]\nformat = 2\nid = \"{id}\"\nname = \"{id}\"\nversion = \"{version}\"\ndeveloper = \"Test\"\nicon = \"files/icon.png\"\n{extra}"
    );
    let program = format!("bin/{id}");
    let files: Vec<(&str, &[u8])> = vec![("kaonic-plugin.toml", manifest.as_bytes()), (&program, b"#!/bin/sh\nsleep 1000\n"), ("files/icon.png", PNG)];
    let sums: String = files.iter().map(|(path, data)| format!("{}  {path}\n", kaonic_hub_installer::sha256_hex(data))).collect();
    let mut all = files.clone();
    all.push(("SHA256SUMS", sums.as_bytes()));
    kaonic_hub_installer::tar::write(&all)
}

/// The installer, serving on its socket to this test's user.
struct Bench {
    root: PathBuf,
    installer: Arc<Installer>,
    settings: kaonic_hub::plugins::Settings,
}

async fn bench(name: &str) -> Bench {
    bench_with(name, vec![b"a release key".to_vec()]).await
}

async fn bench_with(name: &str, release_keys: Vec<Vec<u8>>) -> Bench {
    let root = tempdir(name);
    let paths = Paths::under(&root.join("d"));
    let installer = Arc::new(Installer::new(paths.clone(), release_keys, Arc::new(Fake::default()), Duration::ZERO).unwrap());
    let listener = kaonic_hub_installer::api::bind(&paths.socket).unwrap();
    tokio::spawn(kaonic_hub_installer::api::serve(listener, vec![own_uid()], installer.clone(), std::future::pending()));
    let settings = kaonic_hub::plugins::Settings {
        installer: paths.socket.clone(),
        installer_uid: own_uid(),
        api_dir: paths.plugin_api_dir.clone(),
        plugins_uid: Some(own_uid()),
        dir: paths.plugins.clone(),
        airtime_share: 0.1,
        core_dir: paths.core.clone(),
        installer_state: paths.state.clone(),
        release_key: root.join("no-release-key"),
    };
    Bench { root, installer, settings }
}

impl Bench {
    fn token(&self, id: &str) -> String {
        std::fs::read_to_string(self.installer.paths().plugin(id).join("token")).unwrap().trim().to_owned()
    }

    async fn install(&self, package: Vec<u8>) {
        let installer = self.installer.clone();
        tokio::task::spawn_blocking(move || installer.install(&mut package.as_slice(), false)).await.unwrap().unwrap();
    }

    /// A package as a file, as the hub has it after an upload.
    fn file(&self, package: &[u8]) -> PathBuf {
        let path = self.root.join(format!("upload-{}.tar", kaonic_hub_installer::sha256_hex(package)));
        std::fs::write(&path, package).unwrap();
        path
    }
}

struct Hub {
    app: App,
    router: axum::Router,
    cookie: Option<String>,
    csrf: Option<String>,
}

fn hub(bench: &Bench) -> Hub {
    let dir = bench.root.join("hub");
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
            plugins: bench.settings.clone(),
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
    Hub { router: kaonic_hub::router(app.clone()), app, cookie: None, csrf: None }
}

struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    bytes: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }
}

async fn call(router: &axum::Router, request: Request<Body>) -> Answer {
    let response = router.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    Answer { status: parts.status, headers: parts.headers, bytes: body.collect().await.unwrap().to_bytes().to_vec() }
}

impl Hub {
    fn request(&self, method: &str, path: &str, csrf: bool) -> axum::http::request::Builder {
        let mut request = Request::builder().method(method).uri(path).header(header::HOST, "192.168.10.1");
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if csrf && let Some(token) = &self.csrf {
            request = request.header("x-kaonic-csrf", token);
        }
        request
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<Value>, csrf: bool) -> Answer {
        let request = self.request(method, path, csrf);
        let request = match body {
            Some(body) => request.header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let answer = call(&self.router, request).await;
        if let Some(set) = answer.headers.get(header::SET_COOKIE) {
            let pair = set.to_str().unwrap().split(';').next().unwrap().to_owned();
            self.cookie = if pair.ends_with('=') { None } else { Some(pair) };
        }
        if let Some(token) = answer.json().get("csrf_token").and_then(Value::as_str) {
            self.csrf = Some(token.to_owned());
        }
        answer
    }

    async fn set_up(&mut self) {
        let answer = self.send("POST", "/api/v1/setup", Some(json!({ "mode": "member", "password": PASSWORD, "codename": "kaon7qjt" })), true).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.json());
    }

    /// A package upload as the UI sends it.
    async fn upload(&mut self, method: &str, path: &str, package: &[u8], password: &str, csrf: bool) -> Answer {
        let boundary = "kaonicboundary";
        let mut form = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"p.tar\"\r\nContent-Type: application/x-tar\r\n\r\n").into_bytes();
        form.extend_from_slice(package);
        form.extend_from_slice(format!("\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{password}\r\n--{boundary}--\r\n").as_bytes());
        let request = self.request(method, path, csrf).header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}")).body(Body::from(form)).unwrap();
        call(&self.router, request).await
    }

    /// A call to the plugin API, as served on `socket`'s socket, with this token.
    async fn plugin(&self, socket: &str, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> Answer {
        let mut request = Request::builder().method(method).uri(format!("{}{path}", kaonic_hub::plugin_api::BASE));
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request.header(header::CONTENT_TYPE, "application/json").body(Body::from(body)),
            None => request.body(Body::empty()),
        }
        .unwrap();
        call(&kaonic_hub::plugin_api::router(self.app.clone(), socket), request).await
    }
}

#[tokio::test]
async fn the_installer_client_drives_a_real_installer() {
    let bench = bench("client").await;
    // A socket served by another user than the installer's is sent nothing.
    let impostor = Client::new(bench.settings.installer.clone(), own_uid().wrapping_add(1));
    let refused = impostor.list().await.unwrap_err();
    assert_eq!(refused.status, 0, "{refused}");
    let client = Client::new(bench.settings.installer.clone(), own_uid());
    assert!(client.list().await.unwrap().is_empty());

    let installed = client.install(&bench.file(&package("echo", "1.0.0", "")), false, Some("tester")).await.unwrap();
    assert_eq!((installed.id(), installed.running, installed.record.signed), ("echo", true, false));
    assert!(installed.record.uid >= 61000, "a plugin's own user");
    assert_eq!(client.check(&bench.file(&package("echo", "2.0.0", ""))).await.unwrap().manifest.version, "2.0.0");
    let stopped = client.act("echo", "stop", Some("tester")).await.unwrap();
    assert!(!stopped.running && !stopped.record.enabled);
    assert!(client.act("echo", "start", Some("tester")).await.unwrap().running);
    assert_eq!(client.act("echo", "explode", Some("tester")).await.unwrap_err().status, 404);

    let upgraded = client.install(&bench.file(&package("echo", "1.1.0", "")), false, Some("tester")).await.unwrap();
    assert_eq!(upgraded.record.previous.as_ref().unwrap().manifest.version, "1.0.0");
    assert_eq!(client.act("echo", "rollback", Some("tester")).await.unwrap().record.manifest.version, "1.0.0");
    let older = client.install(&bench.file(&package("echo", "0.9.0", "")), false, Some("tester")).await.unwrap_err();
    assert_eq!((older.status, older.code.as_str()), (409, "downgrade"));
    assert_eq!(client.install(&bench.file(&package("echo", "0.9.0", "")), true, Some("tester")).await.unwrap().record.manifest.version, "0.9.0");
    assert_eq!(client.install(&bench.file(b"not a tar"), false, Some("tester")).await.unwrap_err().status, 422);

    assert_eq!(client.token_key().await.unwrap(), bench.installer.token_public_key());
    client.set_policy(&kaonic_hub_installer::records::Policy { require_signed: true }).await.unwrap();
    assert!(client.policy().await.unwrap().require_signed);
    assert_eq!(client.install(&bench.file(&package("other", "1.0.0", "")), false, Some("tester")).await.unwrap_err().status, 403);

    client.remove("echo", false, Some("tester")).await.unwrap();
    assert_eq!(client.get("echo").await.unwrap_err().status, 404);
    assert_eq!(client.get("../policy").await.unwrap_err().status, 404);
}

#[tokio::test]
async fn the_installer_updates_the_hub_and_keeps_the_history() {
    // A development device: no release key, so unsigned core packages are taken.
    let bench = bench_with("core", vec![]).await;
    let client = Client::new(bench.settings.installer.clone(), own_uid());
    assert!(client.hub_job().await.unwrap().is_none());
    let job = client.update_hub(&bench.file(&package("kaonic-hub", "9.0.0", "")), false, Some("admin (10.0.0.2)")).await.unwrap();
    assert_eq!(job.version, "9.0.0");
    client.hub_ready("9.0.0").await.unwrap();
    for _ in 0..100 {
        if client.hub_job().await.unwrap().is_some_and(|job| job.state == kaonic_hub_installer::installer::HubJobState::Done) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(client.hub_job().await.unwrap().unwrap().state, kaonic_hub_installer::installer::HubJobState::Done);
    let core = client.core().await.unwrap();
    assert_eq!(core[0]["updated"]["version"], "9.0.0");
    let history = client.history(Some("kaonic-hub"), 10).await.unwrap();
    assert_eq!(history[0].actor.as_deref(), Some("admin (10.0.0.2)"));
    assert!(!client.health().await.unwrap().is_empty());
    // Plugin actions carry who asked too.
    client.install(&bench.file(&package("echo", "1.0.0", "")), false, Some("admin (10.0.0.3)")).await.unwrap();
    assert_eq!(client.history(Some("echo"), 1).await.unwrap()[0].actor.as_deref(), Some("admin (10.0.0.3)"));
}

#[tokio::test]
async fn installing_needs_the_admin_the_csrf_token_and_the_password() {
    let bench = bench("admin").await;
    let mut hub = hub(&bench);
    assert_eq!(hub.send("GET", "/api/v1/plugins", None, false).await.status, StatusCode::UNAUTHORIZED);
    hub.set_up().await;
    let admin = (hub.cookie.clone(), hub.csrf.clone());

    // A viewer may look, not install.
    let (cookie, csrf) = kaonic_hub::auth::start_session(&hub.app, Role::Viewer).await.unwrap();
    hub.cookie = Some(cookie.to_str().unwrap().split(';').next().unwrap().to_owned());
    hub.csrf = Some(csrf);
    let list = hub.send("GET", "/api/v1/plugins", None, false).await;
    assert_eq!((list.status, list.json()), (StatusCode::OK, json!([])));
    let refused = hub.upload("POST", "/api/v1/plugins", &package("echo", "1.0.0", ""), PASSWORD, true).await;
    assert_eq!((refused.status, refused.json()["code"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")));

    (hub.cookie, hub.csrf) = admin;
    let no_csrf = hub.upload("POST", "/api/v1/plugins", &package("echo", "1.0.0", ""), PASSWORD, false).await;
    assert_eq!((no_csrf.status, no_csrf.json()["code"].as_str()), (StatusCode::FORBIDDEN, Some("csrf_failed")));
    let wrong = hub.upload("POST", "/api/v1/plugins", &package("echo", "1.0.0", ""), "wrong-password", true).await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(wrong.json()["details"]["fields"]["password"].is_string());
    assert!(bench.installer.list().is_empty(), "nothing reached the installer");

    let installed = hub.upload("POST", "/api/v1/plugins", &package("echo", "1.0.0", "page = true\n"), PASSWORD, true).await;
    assert_eq!(installed.status, StatusCode::OK, "{}", installed.json());
    let body = installed.json();
    assert_eq!(body["action"], "installed");
    assert_eq!((body["plugin"]["id"].as_str(), body["plugin"]["running"].as_bool()), (Some("echo"), Some(true)));
    assert_eq!(body["plugin"]["app_url"], "/apps/echo/");
    assert!(!body.to_string().contains("token"), "the token's hash stays between the installer and the hub");
    let invalid = hub.upload("POST", "/api/v1/plugins", b"not a package", PASSWORD, true).await;
    assert_eq!((invalid.status, invalid.json()["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("validation_failed")));

    // An update of a named plugin takes only that plugin's package.
    let mismatch = hub.upload("PUT", "/api/v1/plugins/echo/package", &package("other", "1.0.0", ""), PASSWORD, true).await;
    assert_eq!(mismatch.status, StatusCode::UNPROCESSABLE_ENTITY);
    let updated = hub.upload("PUT", "/api/v1/plugins/echo/package", &package("echo", "1.1.0", ""), PASSWORD, true).await;
    assert_eq!((updated.status, updated.json()["previous_version"].as_str()), (StatusCode::OK, Some("1.0.0")));

    // The icon comes from the installed package, as a PNG that cannot run anything.
    let icon = hub.send("GET", "/api/v1/plugins/echo/icon", None, false).await;
    assert_eq!((icon.status, icon.bytes.as_slice()), (StatusCode::OK, PNG));
    assert_eq!(icon.headers.get(header::CONTENT_TYPE).unwrap(), "image/png");
    assert_eq!(icon.headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(icon.headers.get_all("content-security-policy").iter().next().unwrap(), "default-src 'none'");
    let file = bench.installer.paths().plugin("echo").join("current/files/icon.png");
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", &file).unwrap();
    assert_eq!(hub.send("GET", "/api/v1/plugins/echo/icon", None, false).await.status, StatusCode::NOT_FOUND, "never through a link");

    let stopped = hub.send("POST", "/api/v1/plugins/echo/stop", None, true).await;
    assert_eq!((stopped.status, stopped.json()["running"].as_bool()), (StatusCode::OK, Some(false)));
    let rolled = hub.send("POST", "/api/v1/plugins/echo/rollback", None, true).await;
    assert_eq!(rolled.json()["version"], "1.0.0");
    let policy = hub.send("PUT", "/api/v1/plugin-policy", Some(json!({ "require_signed": true, "password": PASSWORD })), true).await;
    assert_eq!((policy.status, policy.json()["require_signed"].as_bool()), (StatusCode::OK, Some(true)));
    let unsigned = hub.upload("POST", "/api/v1/plugins", &package("other", "1.0.0", ""), PASSWORD, true).await;
    assert_eq!(unsigned.status, StatusCode::FORBIDDEN);

    assert_eq!(hub.send("DELETE", "/api/v1/plugins/echo", None, true).await.status, StatusCode::NO_CONTENT);
    assert_eq!(hub.send("GET", "/api/v1/plugins/echo", None, false).await.status, StatusCode::NOT_FOUND);
    let audit = hub.app.store.call(|c| kaonic_store::audit::recent(c, 20)).await.unwrap();
    let actions: Vec<&str> = audit.iter().map(|entry| entry.action.as_str()).collect();
    for action in ["plugin.install", "plugin.update", "plugin.control", "plugin.rollback", "plugin.policy", "plugin.remove"] {
        assert!(actions.contains(&action), "{action} in {actions:?}");
    }
}

#[tokio::test]
async fn the_plugin_api_knows_plugins_only_by_their_current_token() {
    let bench = bench("tokens").await;
    bench.install(package("echo", "1.0.0", "[service]\npermissions = \"mesh\"\n")).await;
    bench.install(package("quiet", "1.0.0", "")).await;
    let hub = hub(&bench);
    let echo = bench.token("echo");
    let quiet = bench.token("quiet");

    let me = hub.plugin("echo", "GET", "/self", Some(&echo), None).await;
    assert_eq!(me.status, StatusCode::OK);
    let me = me.json();
    assert_eq!((me["plugin"].as_str(), me["permissions"].clone()), (Some("echo"), json!(["mesh"])));
    assert!(me["limits"]["max_message"].as_u64().unwrap() > 700);

    assert_eq!(hub.plugin("echo", "GET", "/self", None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(hub.plugin("echo", "GET", "/self", Some("kpt1.e30.AAAA"), None).await.status, StatusCode::UNAUTHORIZED);
    // Another plugin's id with this token's signature.
    let (_, signature) = echo.rsplit_once('.').unwrap();
    let claims = json!({ "id": "quiet", "permissions": ["mesh"], "issued": 1, "serial": "00" }).to_string();
    let forged = format!("kpt1.{}.{signature}", kaonic_hub_common::base64::encode_url(claims.as_bytes()));
    assert_eq!(hub.plugin("quiet", "GET", "/self", Some(&forged), None).await.status, StatusCode::UNAUTHORIZED);
    // Signed by another installer's key.
    let other = kaonic_hub_installer::token::TokenKey::load_or_create(&bench.root.join("other.key")).unwrap();
    let foreign = other.issue("echo", &[Permission::Mesh], 1).unwrap();
    assert_eq!(hub.plugin("echo", "GET", "/self", Some(&foreign), None).await.status, StatusCode::UNAUTHORIZED);
    // A plugin's own token on another plugin's socket.
    assert_eq!(hub.plugin("quiet", "GET", "/self", Some(&echo), None).await.status, StatusCode::UNAUTHORIZED);

    // The mesh needs the mesh permission.
    let message = || Some(json!({ "channel": 1, "data": "aGk=" }).to_string().into_bytes());
    let refused = hub.plugin("quiet", "POST", "/messages", Some(&quiet), message()).await;
    assert_eq!((refused.status, refused.json()["code"].as_str()), (StatusCode::FORBIDDEN, Some("missing_permission")));
    assert_eq!(hub.plugin("quiet", "POST", "/broadcast", Some(&quiet), message()).await.status, StatusCode::FORBIDDEN);
    let queued = hub.plugin("echo", "POST", "/messages", Some(&echo), message()).await;
    assert_eq!((queued.status, queued.json()["nodes"].as_u64()), (StatusCode::ACCEPTED, Some(0)), "no node runs it yet");
    let node = "00112233445566778899aabbccddeeff";
    assert_eq!(hub.plugin("echo", "POST", &format!("/nodes/{node}/messages"), Some(&echo), message()).await.status, StatusCode::NOT_FOUND);
    assert_eq!(hub.plugin("echo", "POST", "/broadcast", Some(&echo), message()).await.status, StatusCode::CONFLICT, "no group key on this node");
    let max = kaonic_hub::plugin_api::bridge::max_message();
    let large = json!({ "channel": 1, "data": kaonic_hub_common::base64::encode(&vec![0; max + 1]) }).to_string().into_bytes();
    assert_eq!(hub.plugin("echo", "POST", "/messages", Some(&echo), Some(large)).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(hub.plugin("echo", "GET", "/stats", Some(&echo), None).await.json()["airtime_share"], 0.1);

    // A new install issues a new token: the old one stops working, the new one works at once.
    // (The hub forgets its copy of the list whenever it asks the installer for a change.)
    bench.install(package("echo", "1.0.1", "[service]\npermissions = \"mesh\"\n")).await;
    hub.app.plugins().changed();
    assert_eq!(hub.plugin("echo", "GET", "/self", Some(&echo), None).await.status, StatusCode::UNAUTHORIZED);
    let renewed = bench.token("echo");
    assert_eq!(hub.plugin("echo", "GET", "/self", Some(&renewed), None).await.json()["version"], "1.0.1");
    // Removed: nothing works.
    let installer = bench.installer.clone();
    tokio::task::spawn_blocking(move || installer.remove("quiet", false)).await.unwrap().unwrap();
    hub.app.plugins().changed();
    assert_eq!(hub.plugin("quiet", "GET", "/self", Some(&quiet), None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn each_plugin_has_its_own_limited_store() {
    let bench = bench("store").await;
    bench.install(package("alpha", "1.0.0", "")).await;
    bench.install(package("beta", "1.0.0", "")).await;
    let hub = hub(&bench);
    let (alpha, beta) = (bench.token("alpha"), bench.token("beta"));

    let put = hub.plugin("alpha", "PUT", "/store/favourites", Some(&alpha), Some(br#"["b4o0cvts"]"#.to_vec())).await;
    assert_eq!(put.status, StatusCode::NO_CONTENT);
    let got = hub.plugin("alpha", "GET", "/store/favourites", Some(&alpha), None).await;
    assert_eq!((got.status, got.json()), (StatusCode::OK, json!(["b4o0cvts"])));
    assert_eq!(hub.plugin("alpha", "GET", "/store", Some(&alpha), None).await.json(), json!(["favourites"]));
    // Beta asks for the same key: its own store has none.
    assert_eq!(hub.plugin("beta", "GET", "/store/favourites", Some(&beta), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(hub.plugin("beta", "GET", "/store", Some(&beta), None).await.json(), json!([]));
    assert_eq!(hub.plugin("beta", "DELETE", "/store/favourites", Some(&beta), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(hub.plugin("alpha", "GET", "/store/favourites", Some(&alpha), None).await.status, StatusCode::OK);

    let big = format!("\"{}\"", "x".repeat(64 * 1024));
    assert_eq!(hub.plugin("alpha", "PUT", "/store/big", Some(&alpha), Some(big.into_bytes())).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(hub.plugin("alpha", "PUT", "/store/bad", Some(&alpha), Some(b"{not json".to_vec())).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(hub.plugin("alpha", "PUT", "/store/a%2Fb", Some(&alpha), Some(b"1".to_vec())).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    // Full at 1 MiB.
    let value = format!("\"{}\"", "y".repeat(60 * 1024));
    let mut full = None;
    for n in 0..20 {
        let answer = hub.plugin("alpha", "PUT", &format!("/store/k{n}"), Some(&alpha), Some(value.clone().into_bytes())).await;
        if answer.status != StatusCode::NO_CONTENT {
            full = Some((n, answer.status, answer.json()["code"].clone()));
            break;
        }
    }
    assert_eq!(full, Some((17, StatusCode::PAYLOAD_TOO_LARGE, json!("store_full"))));
}

const HELLO: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: plugin=1\r\n\r\nhello";

/// Plugin `id`'s page on its page socket: answers every request with `answer` and remembers
/// what it was asked in `seen`. (The hub takes plugins to run as this test's user.)
fn page_server(bench: &Bench, id: &str, answer: &'static [u8], seen: Arc<Mutex<Vec<String>>>) {
    let path = bench.installer.paths().page_socket(id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let mut request = vec![0u8; 8192];
            let read = stream.read(&mut request).await.unwrap_or(0);
            seen.lock().unwrap().push(String::from_utf8_lossy(&request[..read]).into_owned());
            let _ = stream.write_all(answer).await;
        }
    });
}

#[tokio::test]
async fn plugin_pages_are_for_the_signed_in_only() {
    let bench = bench("pages").await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    bench.install(package("echo", "1.0.0", "page = true\n")).await;
    bench.install(package("other", "1.0.0", "page = true\n")).await;
    bench.install(package("plain", "1.0.0", "")).await;
    page_server(&bench, "echo", HELLO, seen.clone());
    page_server(&bench, "other", HELLO, seen.clone());
    let mut hub = hub(&bench);
    hub.set_up().await;
    let cookie = hub.cookie.take();

    // Signed out: nothing, and nothing reaches the plugin.
    let answer = hub.send("GET", "/apps/echo/", None, false).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert!(answer.headers.get_all("content-security-policy").iter().any(|value| value.to_str().unwrap().starts_with("sandbox ")));
    assert_eq!(hub.send("GET", &format!("/apps/echo/~{}/", "0".repeat(64)), None, false).await.status, StatusCode::UNAUTHORIZED);
    assert!(seen.lock().unwrap().is_empty());

    // Signed in: sent on with a ticket in the path, which the page's own requests keep.
    hub.cookie = cookie.clone();
    let answer = hub.send("GET", "/apps/echo/index.html?x=1", None, false).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER);
    let location = answer.headers.get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    assert!(location.starts_with("/apps/echo/~") && location.ends_with("/index.html?x=1"), "{location}");
    let base = location.trim_end_matches("index.html?x=1").to_owned();
    hub.cookie = None;
    let page = hub.send("GET", &location, None, false).await;
    assert_eq!((page.status, page.bytes.as_slice()), (StatusCode::OK, &b"hello"[..]));
    assert!(page.headers.get(header::SET_COOKIE).is_none(), "a plugin sets no cookie on the hub");
    let asked = seen.lock().unwrap().last().cloned().unwrap();
    assert!(asked.starts_with("GET /index.html?x=1 HTTP/1.0\r\n"), "{asked}");
    assert!(!asked.to_ascii_lowercase().contains("cookie"), "{asked}");
    assert!(asked.contains(&format!("x-forwarded-prefix: {}", base.trim_end_matches('/'))), "{asked}");
    assert_eq!(hub.send("GET", &format!("{base}assets/app.js"), None, false).await.status, StatusCode::OK);
    // The ticket opens this plugin only.
    assert_eq!(hub.send("GET", &base.replace("/apps/echo/", "/apps/other/"), None, false).await.status, StatusCode::UNAUTHORIZED);
    // Bodies are limited.
    let request = hub.request("POST", &format!("{base}upload"), false).header(header::CONTENT_LENGTH, 2 * 1024 * 1024).body(Body::from(vec![0u8; 2 * 1024 * 1024])).unwrap();
    assert_eq!(call(&hub.router, request).await.status, StatusCode::PAYLOAD_TOO_LARGE);

    // No ticket for a plugin without a page, or one not installed.
    hub.cookie = cookie.clone();
    assert_eq!(hub.send("GET", "/apps/plain/", None, false).await.status, StatusCode::NOT_FOUND);
    assert_eq!(hub.send("GET", "/apps/nobody/", None, false).await.status, StatusCode::NOT_FOUND);
    assert_eq!(hub.send("POST", "/api/v1/plugins/plain/open", None, true).await.status, StatusCode::NOT_FOUND);

    // Or asked for by the UI, for its frame.
    hub.cookie = cookie;
    let opened = hub.send("POST", "/api/v1/plugins/echo/open", None, true).await;
    assert_eq!(opened.status, StatusCode::OK);
    let url = opened.json()["url"].as_str().unwrap().to_owned();
    assert!(url.starts_with("/apps/echo/~") && url.ends_with('/'));
    // Without the slash, relative URLs would miss the ticket.
    let bare = hub.send("GET", url.trim_end_matches('/'), None, false).await;
    assert_eq!((bare.status, bare.headers.get(header::LOCATION).unwrap().to_str().unwrap()), (StatusCode::SEE_OTHER, url.as_str()));

    // Signing out ends every ticket of the session.
    assert_eq!(hub.send("POST", "/api/v1/auth/logout", Some(json!({})), true).await.status, StatusCode::NO_CONTENT);
    assert_eq!(hub.send("GET", &url, None, false).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(hub.send("GET", &location, None, false).await.status, StatusCode::UNAUTHORIZED);
}

/// A page that answers with headers a plugin must not set on the hub's origin.
const HOSTILE: &[u8] = b"HTTP/1.1 302 Found\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\
NEL: {\"report_to\":\"x\",\"max_age\":31536000,\"success_fraction\":1.0}\r\n\
Report-To: {\"group\":\"x\",\"max_age\":31536000,\"endpoints\":[{\"url\":\"https://collector.example/r\"}]}\r\n\
Reporting-Endpoints: x=\"https://collector.example/r\"\r\n\
Alt-Svc: h2=\"evil.example:443\"; ma=31536000\r\n\
Refresh: 0; url=https://evil.example/\r\n\
Service-Worker-Allowed: /\r\n\
Location: https://evil.example/\r\n\
Referrer-Policy: unsafe-url\r\n\r\nok";

#[tokio::test]
async fn a_page_cannot_set_origin_wide_headers_and_gets_the_path_as_sent() {
    let bench = bench("hostile").await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    bench.install(package("evil", "1.0.0", "page = true\n")).await;
    page_server(&bench, "evil", HOSTILE, seen.clone());
    let mut hub = hub(&bench);
    hub.set_up().await;
    let opened = hub.send("POST", "/api/v1/plugins/evil/open", None, true).await;
    let url = opened.json()["url"].as_str().unwrap().to_owned();
    hub.cookie = None;

    let page = hub.send("GET", &url, None, false).await;
    assert_eq!((page.status, page.bytes.as_slice()), (StatusCode::FOUND, &b"ok"[..]));
    for name in ["nel", "report-to", "reporting-endpoints", "alt-svc", "refresh", "service-worker-allowed", "location"] {
        assert!(page.headers.get(name).is_none(), "{name} came through");
    }
    assert_eq!(page.headers.get(header::CONTENT_TYPE).unwrap(), "text/plain");
    // The hub's own policy, not the plugin's.
    assert_eq!(page.headers.get("referrer-policy").unwrap(), "no-referrer");

    // An encoded '?', '#' and '../' stay encoded: the plugin gets the request the browser made.
    hub.send("GET", &format!("{url}files/%2e%2e%2fadmin%3Fas=root%23x?q=%20"), None, false).await;
    let asked = seen.lock().unwrap().last().cloned().unwrap();
    assert!(asked.starts_with("GET /files/%2e%2e%2fadmin%3Fas=root%23x?q=%20 HTTP/1.0\r\n"), "{asked}");
}

#[tokio::test]
async fn a_page_socket_of_another_user_is_never_asked() {
    let bench = bench("stranger").await;
    bench.install(package("echo", "1.0.0", "page = true\n")).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    page_server(&bench, "echo", HELLO, seen.clone());
    // The plugin runs as another user: the socket here is not its.
    let mut bench = bench;
    bench.settings.plugins_uid = Some(own_uid().wrapping_add(1));
    let mut hub = hub(&bench);
    hub.set_up().await;
    let url = hub.send("POST", "/api/v1/plugins/echo/open", None, true).await.json()["url"].as_str().unwrap().to_owned();
    assert_eq!(hub.send("GET", &url, None, false).await.status, StatusCode::BAD_GATEWAY);
    assert!(seen.lock().unwrap().is_empty());
}

/// One request on a Unix socket; the status and the whole answer, or None if the hub
/// closed without answering.
async fn ask(socket: &Path, request: &str) -> Option<(u16, String)> {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await.unwrap();
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let status = answer.split(' ').nth(1)?.parse().ok()?;
    Some((status, answer))
}

fn get(path: &str, token: &str) -> String {
    format!("GET /api/plugin/v1{path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n")
}

/// An event socket: the answer's head, and the connection, held open.
async fn upgrade(socket: &Path, token: &str) -> (String, tokio::net::UnixStream) {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let request = format!(
        "GET /api/plugin/v1/events HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    (String::from_utf8(head).unwrap(), stream)
}

#[tokio::test]
async fn each_plugin_has_its_own_api_socket_with_caps() {
    use std::os::unix::fs::PermissionsExt;
    let bench = bench("sockets").await;
    bench.install(package("echo", "1.0.0", "[service]\npermissions = \"mesh\"\n")).await;
    bench.install(package("quiet", "1.0.0", "")).await;
    let hub = hub(&bench);
    let plugins = hub.app.plugins().clone();
    plugins.reconcile(&hub.app).await;
    assert_eq!(plugins.sockets.ids(), ["echo", "quiet"]);
    let dir = &bench.settings.api_dir;
    let echo_socket = dir.join("echo.sock");
    assert_eq!(std::fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o711);
    assert_eq!(std::fs::metadata(&echo_socket).unwrap().permissions().mode() & 0o777, 0o600);
    let (echo, quiet) = (bench.token("echo"), bench.token("quiet"));

    let (status, answer) = ask(&echo_socket, &get("/self", &echo)).await.unwrap();
    assert_eq!(status, 200, "{answer}");
    assert!(answer.contains("\"plugin\":\"echo\""), "{answer}");
    // Another plugin's token, valid as it is, is not taken on this socket.
    assert_eq!(ask(&echo_socket, &get("/self", &quiet)).await.unwrap().0, 401);

    // At most four event sockets.
    let mut open = Vec::new();
    for _ in 0..kaonic_hub::plugin_api::bridge::MAX_EVENT_SOCKETS {
        let (head, stream) = upgrade(&echo_socket, &echo).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        open.push(stream);
    }
    let (head, _) = upgrade(&echo_socket, &echo).await;
    assert!(head.starts_with("HTTP/1.1 429"), "{head}");

    // At most sixteen connections, the event sockets among them; the next is closed unanswered.
    let cap = kaonic_hub::plugin_api::socket::MAX_CONNECTIONS;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in open.len()..cap {
        open.push(tokio::net::UnixStream::connect(&echo_socket).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(ask(&echo_socket, &get("/self", &echo)).await.is_none(), "over the cap");
    // Quiet's socket is its own.
    assert_eq!(ask(&dir.join("quiet.sock"), &get("/self", &quiet)).await.unwrap().0, 200);
    open.truncate(cap - 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(ask(&echo_socket, &get("/self", &echo)).await.unwrap().0, 200, "a closed connection frees its place");
    drop(open);

    // Removed: its socket goes, and the mesh bridge forgets it.
    let installer = bench.installer.clone();
    tokio::task::spawn_blocking(move || installer.remove("quiet", false)).await.unwrap().unwrap();
    plugins.reconcile(&hub.app).await;
    assert_eq!(plugins.sockets.ids(), ["echo"]);
    assert!(!dir.join("quiet.sock").exists());
}

#[tokio::test]
async fn a_plugin_api_socket_answers_only_its_plugins_user() {
    let bench = bench("peer").await;
    bench.install(package("echo", "1.0.0", "")).await;
    let hub = hub(&bench);
    let path = bench.root.join("echo.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(kaonic_hub::plugin_api::socket::serve(listener, hub.app.clone(), "echo".into(), own_uid().wrapping_add(1)));
    assert!(ask(&path, &get("/self", &bench.token("echo"))).await.is_none());
}

#[tokio::test]
async fn an_unreadable_release_key_refuses_an_installer_update() {
    let mut bench = bench("release-key").await;
    // A directory: there is something, but it cannot be read as a key.
    bench.settings.release_key = bench.root.clone();
    let mut hub = hub(&bench);
    hub.set_up().await;
    let answer = hub.upload("POST", "/api/v1/software/installer", &package("kaonic-hub-installer", "9.0.0", ""), PASSWORD, true).await;
    assert_eq!((answer.status, answer.json()["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("release_key_unreadable")), "{}", answer.json());
    // Nothing of the upload is left behind.
    assert_eq!(std::fs::read_dir(hub.app.config.state_dir.join("uploads")).unwrap().count(), 0);
}
