//! The HTTP API through the real router, on an in-memory store and no Wi-Fi hardware.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use kaonic_hub::api::{BOOT_IDENTITY, Jobs};
use kaonic_hub::app::{App, Config, Inner};
use kaonic_hub::auth::Limiter;
use kaonic_hub::events::Bus;
use kaonic_hub::system::{Device, Metrics};
use kaonic_hub::wifi;
use kaonic_keystore::{Keystore, RawKey};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tower::ServiceExt;

struct Hub {
    router: axum::Router,
    cookie: Option<String>,
    csrf: Option<String>,
    _dir: std::path::PathBuf,
}

fn hub(name: &str) -> Hub {
    hub_with(name, None)
}

fn hub_with(name: &str, commd: Option<Arc<kaonic_mesh::commd::Commd>>) -> Hub {
    let dir = std::env::temp_dir().join(format!("kh-api-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("webui/assets")).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    std::fs::write(
        dir.join("webui/index.html"),
        "<!doctype html><title>Kaonic</title>",
    )
    .unwrap();
    std::fs::write(dir.join("webui/assets/app-1234.js"), "console.log(1)").unwrap();

    let store = kaonic_store::Store::open_in_memory().unwrap();
    let mut keystore =
        Keystore::create(dir.join("keystore"), &RawKey::generate().unwrap()).unwrap();
    keystore.get_or_generate(BOOT_IDENTITY, 64).unwrap();
    let keystore = Arc::new(Mutex::new(keystore));
    let bus = Bus::new();
    let wifi = wifi::start(
        Box::new(wifi::NullRadio),
        store.clone(),
        keystore.clone(),
        bus.clone(),
        "Kaonic /TEST/".into(),
    )
    .unwrap();
    let app = App::new(Inner {
        config: Config {
            state_dir: dir.clone(),
            webui: kaonic_hub::web::Webui::Dir(dir.join("webui")),
            run_dir: dir.join("run"),
            dev: true,
            radio: "rf09_a".into(),
            setup_interfaces: vec!["br0".into(), "usb0".into()],
            plugins: Default::default(),
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
        commd,
    });
    Hub {
        router: kaonic_hub::router(app),
        cookie: None,
        csrf: None,
        _dir: dir,
    }
}

impl Hub {
    async fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        csrf: bool,
    ) -> (StatusCode, Value, axum::http::HeaderMap) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "192.168.10.1");
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if csrf && let Some(token) = &self.csrf {
            request = request.header("x-kaonic-csrf", token);
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        if let Some(set) = parts.headers.get(header::SET_COOKIE) {
            let pair = set.to_str().unwrap().split(';').next().unwrap().to_owned();
            self.cookie = if pair.ends_with('=') {
                None
            } else {
                Some(pair)
            };
        }
        let bytes = body.collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if let Some(token) = value.get("csrf_token").and_then(Value::as_str) {
            self.csrf = Some(token.to_owned());
        }
        (parts.status, value, parts.headers)
    }

    async fn get(&mut self, path: &str) -> (StatusCode, Value) {
        let (status, value, _) = self.send("GET", path, None, false).await;
        (status, value)
    }

    async fn write(&mut self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let (status, value, _) = self.send(method, path, Some(body), true).await;
        (status, value)
    }

    async fn set_up(&mut self) {
        let (status, body) = self
            .write(
                "POST",
                "/api/v1/setup",
                json!({ "mode": "member", "password": "correct-horse-1", "codename": "kaon7qjt" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn setup_signs_in_once_and_only_once() {
    let mut hub = hub("setup");
    let (status, state) = hub.get("/api/v1/auth/state").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        state,
        json!({ "setup_required": true, "authenticated": false, "role": null, "csrf_token": null })
    );

    let (_, identity) = hub.get("/api/v1/setup/identity").await;
    assert_eq!(identity["identity_hash"].as_str().unwrap().len(), 32);
    assert_eq!(identity["public_identity"].as_str().unwrap().len(), 128);

    // Field errors come back per field, in the hub's field names.
    let (status, error) = hub.write("POST", "/api/v1/setup", json!({ "mode": "admin", "password": "password", "codename": "BAD", "seed_password": "short" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error["code"], "validation_failed");
    let fields = error["details"]["fields"].as_object().unwrap();
    assert!(
        fields.contains_key("password")
            && fields.contains_key("codename")
            && fields.contains_key("seed_password")
    );

    // Unknown fields are refused, not ignored.
    let (status, _) = hub.write("POST", "/api/v1/setup", json!({ "mode": "member", "password": "correct-horse-1", "codename": "kaon7qjt", "admin": true })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    hub.set_up().await;
    let (_, state) = hub.get("/api/v1/auth/state").await;
    assert_eq!(
        (state["authenticated"].as_bool(), state["role"].as_str()),
        (Some(true), Some("admin"))
    );

    let (_, device) = hub.get("/api/v1/device").await;
    assert_eq!(device["codename"], "kaon7qjt");
    // A member keeps its boot identity.
    assert_eq!(device["identity_hash"], identity["identity_hash"]);

    let (status, _) = hub
        .write(
            "POST",
            "/api/v1/setup",
            json!({ "mode": "member", "password": "another-pass", "codename": "kaon7qjt" }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        hub.get("/api/v1/setup/identity").await.0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn writes_need_the_csrf_token_and_a_same_origin() {
    let mut hub = hub("csrf");
    hub.set_up().await;

    let (status, error, _) = hub
        .send(
            "PUT",
            "/api/v1/device/codename",
            Some(json!({ "codename": "abcd1234" })),
            false,
        )
        .await;
    assert_eq!(
        (status, error["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("csrf_failed"))
    );

    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/device/codename")
        .header(header::HOST, "192.168.10.1")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::COOKIE, hub.cookie.clone().unwrap())
        .header("x-kaonic-csrf", hub.csrf.clone().unwrap())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "codename": "abcd1234" }).to_string()))
        .unwrap();
    assert_eq!(
        hub.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let (status, device) = hub
        .write(
            "PUT",
            "/api/v1/device/codename",
            json!({ "codename": "abcd1234" }),
        )
        .await;
    assert_eq!(
        (status, device["codename"].as_str()),
        (StatusCode::OK, Some("abcd1234"))
    );
}

#[tokio::test]
async fn logout_ends_the_session_and_login_is_throttled() {
    let mut hub = hub("login");
    hub.set_up().await;
    let (status, _) = hub.write("POST", "/api/v1/auth/logout", json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(hub.get("/api/v1/device").await.0, StatusCode::UNAUTHORIZED);

    for _ in 0..5 {
        let (status, error) = hub
            .write(
                "POST",
                "/api/v1/auth/login",
                json!({ "password": "wrong-password" }),
            )
            .await;
        assert_eq!(
            (status, error["code"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("unauthenticated"))
        );
    }
    // The sixth wrong one still counts; then even the right password must wait.
    hub.write(
        "POST",
        "/api/v1/auth/login",
        json!({ "password": "wrong-password" }),
    )
    .await;
    let (status, error, headers) = hub
        .send(
            "POST",
            "/api/v1/auth/login",
            Some(json!({ "password": "correct-horse-1" })),
            true,
        )
        .await;
    assert_eq!(
        (status, error["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
    assert!(headers.contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn a_wrong_password_for_a_dangerous_action_is_a_field_error() {
    let mut hub = hub("reset");
    hub.set_up().await;
    let (status, error) = hub
        .write(
            "POST",
            "/api/v1/device/factory-reset",
            json!({ "password": "not-it" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error["details"]["fields"]["password"], "Wrong password.");
    // Still signed in.
    assert_eq!(hub.get("/api/v1/device").await.0, StatusCode::OK);
}

#[tokio::test]
async fn wifi_networks_are_saved_without_ever_returning_their_password() {
    let mut hub = hub("wifi");
    hub.set_up().await;
    let (status, wifi) = hub
        .write(
            "POST",
            "/api/v1/network/wifi/networks",
            json!({ "ssid": "Office", "password": "office-password" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{wifi}");
    assert_eq!(wifi["saved"][0]["ssid"], "Office");
    assert!(!wifi.to_string().contains("office-password"));

    let (status, error) = hub
        .write(
            "POST",
            "/api/v1/network/wifi/networks",
            json!({ "ssid": "Short", "password": "short" }),
        )
        .await;
    assert_eq!(
        (status, error["details"]["fields"]["password"].is_string()),
        (StatusCode::UNPROCESSABLE_ENTITY, true)
    );

    let (status, wifi) = hub
        .write(
            "PATCH",
            "/api/v1/network/wifi/networks/Office",
            json!({ "auto_connect": false }),
        )
        .await;
    assert_eq!(
        (status, wifi["saved"][0]["auto_connect"].as_bool()),
        (StatusCode::OK, Some(false))
    );

    // The hotspot password is shown to the admin who set it.
    let (_, wifi) = hub
        .write(
            "PUT",
            "/api/v1/network/wifi/hotspot",
            json!({ "ssid": "Field HQ", "password": "hotspot-pass" }),
        )
        .await;
    assert_eq!(
        (
            wifi["hotspot"]["password"].as_str(),
            wifi["hotspot"]["open"].as_bool()
        ),
        (Some("hotspot-pass"), Some(false))
    );

    let (status, _) = hub
        .write("DELETE", "/api/v1/network/wifi/networks/Office", json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hub.write("DELETE", "/api/v1/network/wifi/networks/Office", json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // No client: scanning is refused with a reason, and the network shows the client off.
    let (status, error) = hub
        .write("POST", "/api/v1/network/wifi/scan", json!({}))
        .await;
    assert_eq!(
        (status, error["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("not_running"))
    );
    let (_, network) = hub.get("/api/v1/network").await;
    assert_eq!(network["sources"][0]["id"], "wifi_client");
}

#[tokio::test]
async fn the_ui_is_served_with_its_headers_and_unknown_api_paths_answer_in_json() {
    let mut hub = hub("web");
    let (status, _, headers) = hub.send("GET", "/nodes/abc", None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );

    let (_, _, headers) = hub.send("GET", "/assets/app-1234.js", None, false).await;
    assert!(
        headers[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
    assert_eq!(
        hub.send("GET", "/assets/missing.js", None, false).await.0,
        StatusCode::NOT_FOUND
    );

    let (status, error) = hub.get("/api/v1/no-such-thing").await;
    assert_eq!(
        (status, error["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    // A plugin page opened directly still runs in an opaque origin, never as the hub.
    let (_, _, headers) = hub.send("GET", "/apps/evil/", None, false).await;
    assert!(
        headers
            .get_all("content-security-policy")
            .iter()
            .any(|value| value.to_str().unwrap().starts_with("sandbox "))
    );
}

#[tokio::test]
async fn the_vpn_capture_needs_the_vpn_and_forwarding_rules_are_kept_without_it() {
    let mut hub = hub("vpn-capture");
    hub.set_up().await;
    let routes = ["/api/v1/vpn/capture", "/api/v1/vpn/capture/packets", "/api/v1/vpn/capture.pcap"];
    // This test hub has no VPN: an admin is told so.
    for path in routes {
        assert_eq!(hub.get(path).await.0, StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    assert_eq!(hub.write("POST", "/api/v1/vpn/capture", json!({})).await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(hub.write("POST", "/api/v1/vpn/capture/stop", json!({})).await.0, StatusCode::SERVICE_UNAVAILABLE);

    // Out of the box every multicast group and broadcast is forwarded; ATAK alone is there to
    // be picked instead, and no rules at all turns it off.
    let (status, state) = hub.get("/api/v1/vpn/forward").await;
    assert_eq!(status, StatusCode::OK, "{state}");
    assert_eq!((&state["active"], state["presets"][0]["id"].as_str(), state["presets"][1]["id"].as_str()), (&json!(false), Some("default"), Some("atak")));
    assert_eq!((state["rules"][0]["name"].as_str(), state["rules"][0]["address"].as_str(), state["rules"][1]["address"].as_str(), state["rules"].as_array().map(Vec::len)), (Some("multicast"), Some("224.0.0.0/4"), Some("255.255.255.255"), Some(2)));
    let (status, off) = hub.write("PUT", "/api/v1/vpn/forward", json!({ "rules": [] })).await;
    assert_eq!((status, &off["rules"]), (StatusCode::OK, &json!([])), "{off}");
    assert_eq!(hub.get("/api/v1/vpn/forward").await.1["rules"], json!([]), "turned off stays off");
    // The preset's rules are taken as they are, and kept (this test hub runs no VPN).
    let (status, state) = hub.write("PUT", "/api/v1/vpn/forward", json!({ "rules": state["presets"][1]["rules"] })).await;
    assert_eq!(status, StatusCode::OK, "{state}");
    let (_, state) = hub.get("/api/v1/vpn/forward").await;
    assert_eq!(state["rules"].as_array().map(Vec::len), Some(2));
    assert_eq!((state["rules"][0]["name"].as_str(), state["rules"][0]["address"].as_str(), &state["rules"][0]["port"]), (Some("atak-sa"), Some("239.2.3.1"), &json!(6969)));
    assert_eq!(state["rules"][1]["counters"]["to_mesh_packets"], json!(0));
    // A rule that is not multicast or broadcast is refused, and the stored rules stay.
    let (status, error) = hub.write("PUT", "/api/v1/vpn/forward", json!({ "rules": [{ "name": "dns", "address": "8.8.8.8", "port": 53 }] })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{error}");
    assert!(error["details"]["fields"]["address"].as_str().is_some_and(|message| message.starts_with("Rule 1 (dns)")), "{error}");
    assert_eq!(hub.get("/api/v1/vpn/forward").await.1["rules"].as_array().map(Vec::len), Some(2));

    // Signed out, nothing.
    hub.cookie = None;
    for path in routes.into_iter().chain(["/api/v1/vpn/forward"]) {
        assert_eq!(hub.get(path).await.0, StatusCode::UNAUTHORIZED, "{path}");
    }
    assert_eq!(hub.write("PUT", "/api/v1/vpn/forward", json!({ "rules": [] })).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn remote_management_is_for_the_admin_device_and_the_shell_needs_the_password_again() {
    let mut hub = hub("remote");
    hub.set_up().await;
    let node = "ab".repeat(16);
    // A member device manages no other node.
    let (status, error) = hub.write("POST", "/api/v1/remote/jobs", json!({ "kind": "node_restart", "node_ids": [node] })).await;
    assert_eq!((status, error["code"].as_str()), (StatusCode::FORBIDDEN, Some("not_admin_device")), "{error}");
    let (status, error) = hub.get(&format!("/api/v1/peers/{node}/remote/device")).await;
    assert_eq!((status, error["code"].as_str()), (StatusCode::FORBIDDEN, Some("not_admin_device")), "{error}");
    let (status, _) = hub.write("PUT", &format!("/api/v1/peers/{node}/remote/codename"), json!({ "codename": "abcd1234" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Only known operations, with their exact fields.
    let (status, _) = hub.write("POST", "/api/v1/remote/jobs", json!({ "kind": "node_shell", "node_ids": [node], "command": "id" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = hub.write("POST", "/api/v1/remote/jobs", json!({ "kind": "node_restart", "node_ids": [] })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // The shell ticket needs the password; a wrong one is a field error.
    let ticket = format!("/api/v1/peers/{node}/remote/shell/ticket");
    let (status, error) = hub.write("POST", &ticket, json!({ "password": "wrong-password" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{error}");
    // The right password still finds no node to open a shell on: this device is no admin.
    let (status, error) = hub.write("POST", &ticket, json!({ "password": "correct-horse-1" })).await;
    assert_eq!((status, error["code"].as_str()), (StatusCode::FORBIDDEN, Some("not_admin_device")), "{error}");
    // The socket itself needs a ticket (the request is no upgrade here, so only the checks before it run).
    let (status, _) = hub.get(&format!("/api/v1/peers/{node}/remote/shell?ticket=00")).await;
    assert!(status.is_client_error(), "{status}");
    hub.cookie = None;
    let (status, _) = hub.write("POST", "/api/v1/remote/jobs", json!({ "kind": "node_restart", "node_ids": [node] })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A valid uImage header around `payload`, as `mkimage` writes for an ARM Linux kernel.
fn uimage(name: &str, payload: &[u8]) -> Vec<u8> {
    use kaonic_hub::boot::crc32;
    let mut header = vec![0u8; 64];
    header[0..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    header[24..28].copy_from_slice(&crc32(payload).to_be_bytes());
    header[28] = 5;
    header[29] = 2;
    header[30] = 2;
    header[32..32 + name.len()].copy_from_slice(name.as_bytes());
    let crc = crc32(&header);
    header[4..8].copy_from_slice(&crc.to_be_bytes());
    [header, payload.to_vec()].concat()
}

#[tokio::test]
async fn kernel_uploads_are_checked_and_boot_changes_need_the_password_and_a_bootable_slot() {
    let mut hub = hub("boot");
    hub.set_up().await;
    // Off the board (dry run) the slots are unknown, but the state answers.
    let (status, state) = hub.get("/api/v1/system/boot").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["dry_run"], json!(true));

    let upload = |hub: &Hub, bytes: Vec<u8>, kind: &str| {
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/system/boot/kernel/upload?kind={kind}"))
            .header(header::HOST, "192.168.10.1")
            .header(header::COOKIE, hub.cookie.clone().unwrap())
            .header("x-kaonic-csrf", hub.csrf.clone().unwrap())
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(bytes))
            .unwrap()
    };
    let garbage = hub.router.clone().oneshot(upload(&hub, b"definitely not a kernel image, just text padding it past 64 bytes".to_vec(), "kernel")).await.unwrap();
    assert_eq!(garbage.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let good = hub.router.clone().oneshot(upload(&hub, uimage("Linux-6.6.129-test", b"zImage"), "kernel")).await.unwrap();
    assert_eq!(good.status(), StatusCode::OK);
    let info: Value = serde_json::from_slice(&good.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(info["version"], json!("6.6.129-test"));
    let (_, staged) = hub.get("/api/v1/system/boot/kernel/staged").await;
    assert_eq!(staged["kernel"]["info"]["format"], json!("uimage"));

    // The password again, then a slot with a system.
    let (status, _) = hub.write("PUT", "/api/v1/system/boot/next", json!({ "slot": "b", "mode": "once", "password": "wrong-password-1" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, body) = hub.write("PUT", "/api/v1/system/boot/next", json!({ "slot": "b", "mode": "once", "password": "correct-horse-1" })).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("slot_not_bootable")));
    assert_eq!(hub.write("PUT", "/api/v1/system/boot/next", json!({ "slot": "c", "mode": "once", "password": "x" })).await.0, StatusCode::UNPROCESSABLE_ENTITY);

    // Discarding clears what was uploaded; signed out, nothing.
    assert_eq!(hub.send("DELETE", "/api/v1/system/boot/kernel/staged", None, true).await.0, StatusCode::NO_CONTENT);
    let (_, staged) = hub.get("/api/v1/system/boot/kernel/staged").await;
    assert_eq!(staged["kernel"], Value::Null);
    hub.cookie = None;
    assert_eq!(hub.get("/api/v1/system/boot").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_forgotten_password_reset_needs_the_serial_over_usb_and_wrong_guesses_are_throttled() {
    let mut hub = hub("forgot");
    assert_eq!(hub.get("/api/v1/auth/forgot").await.1["set_up"], false);
    hub.set_up().await;
    std::fs::create_dir_all(hub._dir.join("etc/kaonic")).unwrap();
    std::fs::write(hub._dir.join("etc/kaonic/kaonic_serial"), "K1S-30-004217\n").unwrap();
    // Signed out, as someone who forgot the password.
    hub.cookie = None;
    hub.csrf = None;
    let (status, methods) = hub.get("/api/v1/auth/forgot").await;
    assert_eq!(status, StatusCode::OK);
    // The test hub runs in dev mode, where every connection counts as USB; a member has no seed.
    assert_eq!((methods["usb"].clone(), methods["seed"].clone()), (json!(true), json!(false)));

    let reset = |method: &str, serial: &str, confirm: &str| json!({ "method": method, "serial": serial, "confirm": confirm });
    let (status, error) = hub.write("POST", "/api/v1/auth/forgot/factory-reset", json!({ "method": "seed", "seed_password": "a long admin seed", "confirm": "ERASE" })).await;
    assert_eq!((status, error["code"].clone()), (StatusCode::FORBIDDEN, json!("seed_unavailable")));
    let (status, error) = hub.write("POST", "/api/v1/auth/forgot/factory-reset", reset("usb", "K1S-30-004217", "erase")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(error["details"]["fields"]["confirm"].is_string());

    // Wrong serials count like wrong passwords.
    let mut throttled = false;
    for _ in 0..8 {
        let (status, _) = hub.write("POST", "/api/v1/auth/forgot/factory-reset", reset("usb", "K1S-00-000000", "ERASE")).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(throttled, "wrong serials are never throttled");

    // Once throttled, even the right serial waits.
    let (status, _) = hub.write("POST", "/api/v1/auth/forgot/factory-reset", reset("usb", "K1S-30-004217", "ERASE")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // On another device, the right serial erases (in dev mode the hub only logs it).
    let mut other = crate::hub("forgot-ok");
    other.set_up().await;
    std::fs::create_dir_all(other._dir.join("etc/kaonic")).unwrap();
    std::fs::write(other._dir.join("etc/kaonic/kaonic_serial"), "K1S-30-004217\n").unwrap();
    other.cookie = None;
    other.csrf = None;
    let (status, body) = other.write("POST", "/api/v1/auth/forgot/factory-reset", reset("usb", " K1S-30-004217 ", "ERASE")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
async fn the_system_report_is_plain_text_for_the_admin() {
    let mut hub = hub("report");
    let request = |cookie: Option<&String>| {
        let mut request = Request::builder().uri("/api/v1/system/report").header(header::HOST, "192.168.10.1");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request.body(Body::empty()).unwrap()
    };
    assert_eq!(hub.router.clone().oneshot(request(None)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    hub.set_up().await;
    let response = hub.router.clone().oneshot(request(hub.cookie.as_ref())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/plain"));
    let text = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    println!("{text}");
    for section in ["Kaonic system report", "Device", "Kaonic software", "OS", "Services", "Mesh", "Plugins"] {
        assert!(text.contains(section), "{section} missing");
    }
    assert!(text.contains(env!("CARGO_PKG_VERSION")));
    assert!(!text.contains("correct-horse-1"), "never the password");
}

/// The kaonic1s r30's filters, as commd reports them.
fn r30_filters() -> Vec<kaonic_mesh::commd::Filter> {
    [("Wide 730–960 MHz", 730_000, 960_000), ("868 MHz", 862_000, 876_000), ("915 MHz", 902_000, 928_000)]
        .into_iter()
        .map(|(label, min_khz, max_khz)| kaonic_mesh::commd::Filter { label: label.into(), min_khz, max_khz })
        .collect()
}

fn band<'a>(bands: &'a Value, id: &str) -> &'a Value {
    bands.as_array().unwrap().iter().find(|band| band["id"] == id).unwrap()
}

#[tokio::test]
async fn the_sub_ghz_filter_is_chosen_per_band_saved_and_handed_to_commd() {
    let fake = kaonic_mesh::commd::FakeCommd::spawn("127.0.0.1:0".parse().unwrap(), 2, r30_filters(), (863_000, 928_000))
        .await
        .unwrap();
    let commd = Arc::new(kaonic_mesh::commd::Commd::new(fake.addr));
    let mut hub = hub_with("filter", Some(commd));

    // Changing it is for the signed-in admin.
    let (status, _) = hub.write("PUT", "/api/v1/radio/bands/a_sub/filter", json!({ "filter": 1 })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    hub.set_up().await;

    let (status, bands) = hub.get("/api/v1/radio/bands").await;
    assert_eq!(status, StatusCode::OK);
    let a_sub = band(&bands, "a_sub");
    assert_eq!(a_sub["filter"], "auto");
    assert_eq!(a_sub["filter_state"], "ok");
    assert_eq!(a_sub["active_filter"], 0);
    assert_eq!(a_sub["filters"][1], json!({ "index": 1, "label": "868 MHz", "min_mhz": 862.0, "max_mhz": 876.0 }));
    assert_eq!(a_sub["filters"].as_array().unwrap().len(), 3);
    assert_eq!((a_sub["min_mhz"].as_f64(), a_sub["max_mhz"].as_f64()), (Some(863.0), Some(928.0)));
    // The 2.4 GHz bands have no filter, only their range.
    let a_24 = band(&bands, "a_24");
    assert_eq!((a_24["filter_state"].as_str(), a_24["filters"].as_array().unwrap().len()), (Some("none"), 0));
    assert_eq!((a_24["min_mhz"].as_f64(), a_24["max_mhz"].as_f64()), (Some(2400.0), Some(2483.5)));

    // Any filter the board has may be chosen, whatever the frequency; it is saved and handed on.
    let (status, view) = hub.write("PUT", "/api/v1/radio/bands/b_sub/filter", json!({ "filter": 2 })).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!((view["filter"].as_u64(), view["active_filter"].as_u64()), (Some(2), Some(2)));
    assert_eq!(*fake.selected.lock().unwrap(), vec![None, Some(2)]);

    // A filter the board does not have, a name, or a filter on a 2.4 GHz band is refused.
    for (path, filter) in [("b_sub", json!(3)), ("b_sub", json!("wide")), ("b_24", json!(1))] {
        let (status, error) = hub.write("PUT", &format!("/api/v1/radio/bands/{path}/filter"), json!({ "filter": filter })).await;
        assert!(status.is_client_error(), "{path} {filter}: {status}");
        if let Some(fields) = error["details"]["fields"].as_object() {
            assert!(fields.contains_key("filter"), "{error}");
        }
    }
    assert_eq!(fake.selected.lock().unwrap()[1], Some(2));

    // commd restarted (back on auto): the saved choice goes back to it.
    fake.selected.lock().unwrap()[1] = None;
    let (_, bands) = hub.get("/api/v1/radio/bands").await;
    assert_eq!(band(&bands, "b_sub")["filter"], 2);
    assert_eq!(fake.selected.lock().unwrap()[1], Some(2));

    // Back to auto.
    let (status, view) = hub.write("PUT", "/api/v1/radio/bands/b_sub/filter", json!({ "filter": "auto" })).await;
    assert_eq!((status, view["filter"].as_str()), (StatusCode::OK, Some("auto")));
    assert_eq!(fake.selected.lock().unwrap()[1], None);
}

#[tokio::test]
async fn without_commd_the_filter_choice_is_kept_and_shown_unavailable() {
    // A port nobody answers on.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let commd = Arc::new(kaonic_mesh::commd::Commd::new(silent.local_addr().unwrap()));
    let mut hub = hub_with("filter-down", Some(commd));
    hub.set_up().await;

    let (status, view) = hub.write("PUT", "/api/v1/radio/bands/a_sub/filter", json!({ "filter": 1 })).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!((view["filter"].as_u64(), view["filter_state"].as_str()), (Some(1), Some("unavailable")));
    assert_eq!(view["filters"], json!([]));
    assert_eq!(view["min_mhz"], Value::Null);

    // No commd at all (a laptop): the same.
    let mut laptop = self::hub("filter-none");
    laptop.set_up().await;
    let (_, bands) = laptop.get("/api/v1/radio/bands").await;
    assert_eq!(band(&bands, "a_sub")["filter_state"], "unavailable");
    assert_eq!(band(&bands, "a_sub")["filter"], "auto");
}
