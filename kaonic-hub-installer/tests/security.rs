//! Regression tests for the security review of the installer: the API socket and its peer
//! check, ids from requests, records read back, uids, tokens, floors and units.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kaonic_hub_installer::host::Fake;
use kaonic_hub_installer::installer::HubJobState;
use kaonic_hub_installer::records::Record;
use kaonic_hub_installer::{Installer, Kind, Paths, api, sha256_hex, tar, unit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A short root under /tmp: socket paths have a length limit.
fn root() -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/khi-{}-{}", std::process::id(), kaonic_hub_installer::hex(&kaonic_hub_installer::random::<6>().unwrap())));
    fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

/// An unsigned package; `extra` is "<[kaonic-plugin] lines>|<[service] lines>".
fn package(id: &str, version: &str, extra: &str) -> Vec<u8> {
    let (plugin_extra, service) = extra.split_once('|').unwrap_or((extra, ""));
    let manifest = format!("[kaonic-plugin]\nformat = 2\nid = \"{id}\"\nname = \"N\"\nversion = \"{version}\"\ndeveloper = \"D\"\n{plugin_extra}\n[service]\n{service}\n");
    let program = format!("bin/{id}");
    let files: Vec<(&str, &[u8])> = vec![("kaonic-plugin.toml", manifest.as_bytes()), (&program, b"#!/bin/sh\n")];
    let sums: String = files.iter().map(|(path, data)| format!("{}  {path}\n", sha256_hex(data))).collect();
    let mut all = files.clone();
    all.push(("SHA256SUMS", sums.as_bytes()));
    tar::write(&all)
}

/// A device with a release key (any key file makes it one).
fn bench(root: &Path) -> (Arc<Installer>, Arc<Fake>) {
    let host = Arc::new(Fake::default());
    let key = b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".to_vec();
    (Arc::new(Installer::new(Paths::under(root), vec![key], host.clone(), Duration::ZERO).unwrap()), host)
}

/// A development device: no release key.
fn development(root: &Path) -> Arc<Installer> {
    Arc::new(Installer::new(Paths::under(root), vec![], Arc::new(Fake::default()), Duration::ZERO).unwrap())
}

fn my_uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

async fn call(router: axum::Router, method: &str, uri: &str) -> (u16, String) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let request = axum::http::Request::builder().method(method).uri(uri).body(axum::body::Body::empty()).unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes()).into_owned())
}

/// Serves `installer` on its socket for peers `allowed`.
fn serve(installer: &Arc<Installer>, allowed: Vec<u32>) -> PathBuf {
    let socket = installer.paths().socket.clone();
    let listener = api::bind(&socket).unwrap();
    tokio::spawn(api::serve(listener, allowed, installer.clone(), std::future::pending()));
    socket
}

/// One raw HTTP/1.1 request over the socket; the whole answer, empty if the server hung up.
async fn raw(socket: &Path, head: &str, body: &[u8]) -> String {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;
    String::from_utf8_lossy(&answer).into_owned()
}

#[tokio::test]
async fn a_peer_with_another_uid_is_refused_on_every_route() {
    let root = root();
    let installer = development(&root);
    let socket = serve(&installer, vec![my_uid().wrapping_add(1)]);
    assert_eq!(fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(socket.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    for (method, path) in [("GET", "/v1/health"), ("GET", "/v1/token-key"), ("POST", "/v1/core/kaonic-hub/ready")] {
        let body = br#"{"version":"1"}"#;
        let head = format!("{method} {path} HTTP/1.1\r\nHost: i\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        assert_eq!(raw(&socket, &head, body).await, "", "{path} answered a refused peer");
    }
    // The allowed uid is served.
    let root = self::root();
    let installer = development(&root);
    let socket = serve(&installer, vec![my_uid()]);
    let answer = raw(&socket, "GET /v1/health HTTP/1.1\r\nHost: i\r\nConnection: close\r\n\r\n", b"").await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

#[tokio::test]
async fn a_stale_socket_is_replaced_but_nothing_else() {
    let root = root();
    let installer = development(&root);
    let socket = installer.paths().socket.clone();
    drop(api::bind(&socket).unwrap());
    drop(api::bind(&socket).unwrap());
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, b"a file").unwrap();
    assert!(api::bind(&socket).is_err());
    assert_eq!(fs::read(&socket).unwrap(), b"a file");
}

#[tokio::test]
async fn a_package_is_streamed_in_and_its_upload_removed() {
    let root = root();
    let installer = development(&root);
    let socket = serve(&installer, vec![my_uid()]);
    let body = package("sample", "1", "");
    let head = format!("POST /v1/plugins HTTP/1.1\r\nHost: i\r\nContent-Type: application/x-tar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let answer = raw(&socket, &head, &body).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("\"uid\":61000"), "{answer}");
    let staging = root.join("state/staging");
    assert!(fs::read_dir(&staging).unwrap().next().is_none(), "the upload is gone");

    // Too large, by its length or by what is sent.
    let head = format!("POST /v1/packages/check HTTP/1.1\r\nHost: i\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", api::MAX_PACKAGE + 1);
    assert!(raw(&socket, &head, b"").await.starts_with("HTTP/1.1 413"));
    let chunk = vec![0u8; 1 << 20];
    let mut chunked = Vec::new();
    for _ in 0..(api::MAX_PACKAGE >> 20) + 1 {
        chunked.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        chunked.extend_from_slice(&chunk);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let head = "POST /v1/packages/check HTTP/1.1\r\nHost: i\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    let answer = raw(&socket, head, &chunked).await;
    assert!(answer.starts_with("HTTP/1.1 413"), "{answer}");
    assert!(fs::read_dir(&staging).unwrap().next().is_none(), "the partial upload is gone");
}

/// The PoC: a forged record in the plugin's own data/, reached through a path id.
#[tokio::test]
async fn an_id_from_a_request_never_names_a_path() {
    let root = root();
    let (installer, _) = bench(&root);
    let record = installer.install(&mut package("evil", "1", "").as_slice(), false).unwrap();
    let data = root.join("plugins/evil/data");
    let fake_dir = data.join("x");
    fs::create_dir_all(fake_dir.join("current")).unwrap();
    fs::create_dir_all(fake_dir.join("previous")).unwrap();
    let mut previous = serde_json::to_value(&record).unwrap();
    previous["manifest"]["permissions"] = serde_json::json!(["root"]);
    let mut forged = serde_json::to_value(&record).unwrap();
    forged["previous"] = previous;
    fs::write(data.join("x.json"), serde_json::to_vec(&forged).unwrap()).unwrap();

    let id = fake_dir.to_string_lossy().replace('/', "%2F");
    let router = api::router(installer.clone());
    for (method, path) in [("GET", format!("/v1/plugins/{id}")), ("POST", format!("/v1/plugins/{id}/rollback")), ("DELETE", format!("/v1/plugins/{id}")), ("POST", "/v1/plugins/..%2Fx/start".into())] {
        let (status, body) = call(router.clone(), method, &path).await;
        assert_eq!(status, 422, "{method} {path}: {body}");
    }
    for id in ["../x", "a/b", ""] {
        assert_eq!(installer.get(id).unwrap_err().kind, Kind::Invalid);
        assert_eq!(installer.rollback(id).unwrap_err().kind, Kind::Invalid);
        assert_eq!(installer.remove(id, false).unwrap_err().kind, Kind::Invalid);
        assert_eq!(installer.control(id, kaonic_hub_installer::installer::Action::Start).unwrap_err().kind, Kind::Invalid);
    }
    let unit = fs::read_to_string(root.join("systemd/kaonic-plugin-evil.service")).unwrap();
    assert!(!unit.contains("User=root"), "{unit}");
}

/// A record read back is checked like a new manifest, its previous version too.
#[test]
fn a_record_that_would_not_install_is_refused() {
    let root = root();
    let (installer, _) = bench(&root);
    installer.install(&mut package("sample", "1", "").as_slice(), false).unwrap();
    installer.install(&mut package("sample", "2", "").as_slice(), false).unwrap();
    let path = root.join("state/records/sample.json");
    let good: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    type Forge<'a> = (&'a str, &'a dyn Fn(&mut serde_json::Value));
    let forgeries: [Forge; 5] = [
        ("previous runs as root under a plugin uid", &|record| record["previous"]["manifest"]["permissions"] = serde_json::json!(["root"])),
        ("previous sets LD_PRELOAD", &|record| record["previous"]["manifest"]["environment"] = serde_json::json!([["LD_PRELOAD", "/x.so"]])),
        ("previous is another plugin", &|record| record["previous"]["manifest"]["id"] = serde_json::json!("other")),
        ("root as a plugin uid", &|record| record["manifest"]["permissions"] = serde_json::json!(["root"])),
        ("a uid outside the plugin range", &|record| record["uid"] = serde_json::json!(1000)),
    ];
    for (why, forge) in forgeries {
        let mut record = good.clone();
        forge(&mut record);
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(installer.get("sample").unwrap_err().kind, Kind::NotFound, "{why}");
        assert!(installer.rollback("sample").is_err(), "{why}");
        assert!(installer.list().is_empty(), "{why}");
    }
    let unit = fs::read_to_string(root.join("systemd/kaonic-plugin-sample.service")).unwrap();
    assert!(!unit.contains("User=root") && !unit.contains("LD_PRELOAD"), "{unit}");
    fs::write(&path, serde_json::to_vec(&good).unwrap()).unwrap();
    assert!(serde_json::from_value::<Record>(good).unwrap().check("sample").is_ok());
    assert!(installer.rollback("sample").is_ok());
}

/// Long ids no longer share a user: each plugin gets its own uid, never one a record or a
/// kept data/ still owns.
#[test]
fn every_plugin_gets_its_own_uid() {
    let root = root();
    let (installer, _) = bench(&root);
    let a = installer.install(&mut package("aaaaaaaaaaaaaaaaaaaa-victim", "1", "").as_slice(), false).unwrap();
    let b = installer.install(&mut package("aaaaaaaaaaaaaaaaaaaa-1", "1", "").as_slice(), false).unwrap();
    assert_ne!(a.uid, b.uid);
    assert!(kaonic_hub_installer::records::UIDS.contains(&a.uid) && kaonic_hub_installer::records::UIDS.contains(&b.uid));

    installer.remove(&a.manifest.id, true).unwrap();
    let c = installer.install(&mut package("third", "1", "").as_slice(), false).unwrap();
    assert!(c.uid != a.uid && c.uid != b.uid, "a kept data/ keeps its uid reserved");
    let again = installer.install(&mut package(&a.manifest.id, "1", "").as_slice(), false).unwrap();
    assert_eq!(again.uid, a.uid, "and gets it back");

    installer.remove(&a.manifest.id, false).unwrap();
    let d = installer.install(&mut package("fourth", "1", "").as_slice(), false).unwrap();
    assert_eq!(d.uid, a.uid, "a uid is free once nothing owns it");
    // A root plugin runs as 0 (development device, so unsigned is allowed).
    let root2 = self::root();
    let dev = development(&root2);
    assert_eq!(dev.install(&mut package("rooted", "1", "|permissions = \"root\"").as_slice(), false).unwrap().uid, 0);
}

#[test]
fn command_links_take_kaonic_names_only() {
    let root = root();
    let (installer, _) = bench(&root);
    assert_eq!(installer.install(&mut package("ip", "1", "command = true").as_slice(), false).unwrap_err().kind, Kind::Invalid);
    assert!(fs::symlink_metadata(root.join("bin/ip")).is_err());
    installer.install(&mut package("kaonic-ip", "1", "command = true").as_slice(), false).unwrap();
    assert!(fs::symlink_metadata(root.join("bin/kaonic-ip")).unwrap().file_type().is_symlink());
}

#[test]
fn a_failed_upgrade_leaves_a_token_that_matches_the_record() {
    let root = root();
    let (installer, host) = bench(&root);
    installer.install(&mut package("sample", "1", "|permissions = \"mesh\"").as_slice(), false).unwrap();
    host.state.lock().unwrap().crashing.insert("kaonic-plugin-sample.service".into());
    assert!(installer.install(&mut package("sample", "2", "").as_slice(), false).is_err());
    let token = fs::read_to_string(root.join("plugins/sample/token")).unwrap();
    let record = installer.get("sample").unwrap();
    assert_eq!(record.manifest.version, "1");
    assert_eq!(record.token_sha256, sha256_hex(token.as_bytes()));
    let claims = kaonic_hub_installer::token::verify(&installer.token_public_key(), &token).unwrap();
    assert_eq!(claims.permissions, record.manifest.permissions, "the token is the restored version's");
}

#[test]
fn an_interrupted_hub_update_does_not_block_the_next() {
    let root = root();
    fs::create_dir_all(root.join("state")).unwrap();
    fs::write(root.join("state/hub-job.json"), r#"{"id":1,"version":"1.0.0","state":"running","message":"","started":1,"finished":null}"#).unwrap();
    let installer = development(&root);
    let job = installer.hub_job().unwrap();
    assert_eq!(job.state, HubJobState::Failed);
    assert!(job.message.contains("interrupted"), "{}", job.message);
    let next = installer.update_hub_with(&mut package("kaonic-hub", "2", "").as_slice(), false, None, Duration::from_millis(50)).unwrap();
    assert_eq!((next.id, next.state), (2, HubJobState::Running));
}

#[test]
fn removing_a_plugin_keeps_its_downgrade_floor() {
    for keep_data in [true, false] {
        let root = root();
        let (installer, _) = bench(&root);
        installer.install(&mut package("sample", "2", "").as_slice(), false).unwrap();
        installer.remove("sample", keep_data).unwrap();
        assert_eq!(installer.install(&mut package("sample", "1", "").as_slice(), false).unwrap_err().kind, Kind::Downgrade, "keep_data {keep_data}");
        let record = installer.install(&mut package("sample", "1", "").as_slice(), true).unwrap();
        assert_eq!(record.highest_version, "2");
        assert_eq!(fs::metadata(root.join("state/removed.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn a_name_ending_in_a_backslash_stays_on_its_line() {
    let manifest = kaonic_hub_installer::manifest::parse("[kaonic-plugin]\nformat = 2\nid = \"sample\"\nname = 'N \\'\nversion = \"1\"\ndeveloper = \"D\"\n").unwrap();
    let unit = unit::render(&manifest, 61_000, &Paths::under(Path::new("/t")));
    assert!(!unit.lines().any(|line| line.ends_with('\\')), "{unit}");
    assert!(unit.contains("\nDescription=N /\nAfter="), "{unit}");
}

#[tokio::test]
async fn a_development_device_says_so_and_still_takes_root_plugins() {
    let root = root();
    let installer = development(&root);
    let (status, body) = call(api::router(installer.clone()), "GET", "/v1/policy").await;
    assert_eq!(status, 200);
    assert!(body.contains("\"release_key\":false"), "{body}");
    let record = installer.install(&mut package("rooted", "1", "|permissions = \"root\"").as_slice(), false).unwrap();
    assert!(!record.signed && record.uid == 0);
}
