//! The hub's client of `kaonic-hub-installer` (`docs/api/installer-api.yaml`).
//!
//! Plain HTTP/1.1 on the installer's Unix socket, one request per connection. Nothing is
//! sent until the socket's peer is the installer's user (root on a device). Packages are
//! sent from their file, in pieces.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kaonic_hub_common::http;
use kaonic_hub_installer::records::{Policy, Record};
use serde::Deserialize;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// An install waits for the plugin to stay up; everything else is quick.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(180);
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// A request body.
#[derive(Clone, Copy)]
enum Body<'a> {
    Json(&'a [u8]),
    /// A package (a tar), read from this file as it is sent.
    Package(&'a Path),
}
const NONE: Body<'static> = Body::Json(&[]);

/// A plugin as the installer reports it.
#[derive(Clone, Debug, Deserialize)]
pub struct Installed {
    #[serde(flatten)]
    pub record: Record,
    pub running: bool,
}

impl Installed {
    pub fn id(&self) -> &str {
        &self.record.manifest.id
    }
}

/// A package as checked.
#[derive(Clone, Debug, Deserialize)]
pub struct Checked {
    pub manifest: kaonic_hub_installer::manifest::Manifest,
    pub signed: bool,
}

/// What went wrong: the installer's answer, or `status` 0 when it could not be reached.
#[derive(Clone, Debug)]
pub struct Failure {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl Failure {
    fn unreachable(why: impl std::fmt::Display) -> Self {
        Self { status: 0, code: "unreachable".into(), message: format!("the plugin installer does not answer: {why}") }
    }
    fn bad(why: &str) -> Self {
        Self { status: 0, code: "bad_answer".into(), message: format!("the plugin installer answered wrongly: {why}") }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub struct Client {
    socket: PathBuf,
    /// The user the installer runs as.
    uid: u32,
}

/// Who asked, for the installer's history (`X-Kaonic-Actor`).
pub type Actor<'a> = Option<&'a str>;

impl Client {
    /// The installer on `socket`, served by `uid`.
    pub fn new(socket: PathBuf, uid: u32) -> Self {
        Self { socket, uid }
    }

    pub async fn list(&self) -> Result<Vec<Installed>, Failure> {
        self.json("GET", "/v1/plugins", NONE, TIMEOUT).await
    }

    pub async fn get(&self, id: &str) -> Result<Installed, Failure> {
        self.json("GET", &format!("/v1/plugins/{}", checked(id)?), NONE, TIMEOUT).await
    }

    /// Installs or upgrades from a package (a tar file).
    pub async fn install(&self, package: &Path, allow_downgrade: bool, actor: Actor<'_>) -> Result<Installed, Failure> {
        let path = if allow_downgrade { "/v1/plugins?allow_downgrade=1" } else { "/v1/plugins" };
        self.json_as("POST", path, Body::Package(package), INSTALL_TIMEOUT, actor).await
    }

    /// Checks a package without installing it: its manifest, and whether it is signed.
    pub async fn check(&self, package: &Path) -> Result<Checked, Failure> {
        self.json("POST", "/v1/packages/check", Body::Package(package), INSTALL_TIMEOUT).await
    }

    /// `start`, `stop`, `restart` or `rollback`.
    pub async fn act(&self, id: &str, action: &str, actor: Actor<'_>) -> Result<Installed, Failure> {
        if !matches!(action, "start" | "stop" | "restart" | "rollback") {
            return Err(Failure { status: 404, code: "not_found".into(), message: format!("no action {action}") });
        }
        let timeout = if action == "rollback" { INSTALL_TIMEOUT } else { TIMEOUT };
        self.json_as("POST", &format!("/v1/plugins/{}/{action}", checked(id)?), NONE, timeout, actor).await
    }

    pub async fn remove(&self, id: &str, keep_data: bool, actor: Actor<'_>) -> Result<(), Failure> {
        let query = if keep_data { "?keep_data=1" } else { "" };
        self.call("DELETE", &format!("/v1/plugins/{}{query}", checked(id)?), NONE, TIMEOUT, actor).await.map(|_| ())
    }

    /// The installer's version.
    pub async fn health(&self) -> Result<String, Failure> {
        #[derive(Deserialize)]
        struct Health {
            version: String,
        }
        self.json::<Health>("GET", "/v1/health", NONE, TIMEOUT).await.map(|health| health.version)
    }

    /// What happened to plugins and the core programs, newest first.
    pub async fn history(&self, id: Option<&str>, limit: usize) -> Result<Vec<kaonic_hub_installer::history::Event>, Failure> {
        let path = match id {
            Some(id) => format!("/v1/history?id={}&limit={limit}", checked(id)?),
            None => format!("/v1/history?limit={limit}"),
        };
        self.json("GET", &path, NONE, TIMEOUT).await
    }

    /// The hub and the installer: their updated copies, if any.
    pub async fn core(&self) -> Result<serde_json::Value, Failure> {
        self.json("GET", "/v1/core", NONE, TIMEOUT).await
    }

    /// Starts an update of the hub: the installer restarts us with it.
    pub async fn update_hub(&self, package: &Path, allow_downgrade: bool, actor: Actor<'_>) -> Result<kaonic_hub_installer::installer::HubJob, Failure> {
        let path = if allow_downgrade { "/v1/core/kaonic-hub?allow_downgrade=1" } else { "/v1/core/kaonic-hub" };
        self.json_as("POST", path, Body::Package(package), INSTALL_TIMEOUT, actor).await
    }

    /// The last hub update, if any.
    pub async fn hub_job(&self) -> Result<Option<kaonic_hub_installer::installer::HubJob>, Failure> {
        match self.json("GET", "/v1/core/kaonic-hub/job", NONE, TIMEOUT).await {
            Ok(job) => Ok(Some(job)),
            Err(failure) if failure.status == 404 => Ok(None),
            Err(failure) => Err(failure),
        }
    }

    /// Tells the installer this hub is fully up.
    pub async fn hub_ready(&self, version: &str) -> Result<(), Failure> {
        let body = serde_json::to_vec(&serde_json::json!({ "version": version })).expect("serialises");
        self.call("POST", "/v1/core/kaonic-hub/ready", Body::Json(&body), TIMEOUT, None).await.map(|_| ())
    }

    /// The policy as the installer gives it, with `release_key` (false on a development device).
    pub async fn policy_view(&self) -> Result<serde_json::Value, Failure> {
        self.json("GET", "/v1/policy", NONE, TIMEOUT).await
    }

    pub async fn policy(&self) -> Result<Policy, Failure> {
        self.json("GET", "/v1/policy", NONE, TIMEOUT).await
    }

    pub async fn set_policy(&self, policy: &Policy) -> Result<Policy, Failure> {
        let body = serde_json::to_vec(policy).expect("a policy serialises");
        self.json("PUT", "/v1/policy", Body::Json(&body), TIMEOUT).await
    }

    /// The Ed25519 key plugin tokens are signed with.
    pub async fn token_key(&self) -> Result<[u8; 32], Failure> {
        #[derive(Deserialize)]
        struct Key {
            public: String,
        }
        let key: Key = self.json("GET", "/v1/token-key", NONE, TIMEOUT).await?;
        unhex(&key.public).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()).ok_or_else(|| Failure::bad("token key"))
    }

    async fn json<T: serde::de::DeserializeOwned>(&self, method: &str, path: &str, body: Body<'_>, timeout: Duration) -> Result<T, Failure> {
        self.json_as(method, path, body, timeout, None).await
    }

    async fn json_as<T: serde::de::DeserializeOwned>(&self, method: &str, path: &str, body: Body<'_>, timeout: Duration, actor: Actor<'_>) -> Result<T, Failure> {
        let answer = self.call(method, path, body, timeout, actor).await?;
        serde_json::from_slice(&answer).map_err(|error| Failure::bad(&error.to_string()))
    }

    /// One request; the body of a 2xx answer, or the installer's error.
    async fn call(&self, method: &str, path: &str, body: Body<'_>, timeout: Duration, actor: Actor<'_>) -> Result<Vec<u8>, Failure> {
        let (status, answer) = tokio::time::timeout(timeout, exchange(&self.socket, self.uid, method, path, body, actor))
            .await
            .map_err(|_| Failure::unreachable("timed out"))?
            .map_err(Failure::unreachable)?;
        if (200..300).contains(&status) {
            return Ok(answer);
        }
        #[derive(Deserialize)]
        struct Error {
            code: String,
            message: String,
        }
        let error: Option<Error> = serde_json::from_slice(&answer).ok();
        Err(match error {
            Some(error) => Failure { status, code: error.code, message: error.message },
            None => Failure { status, code: "failed".into(), message: format!("the plugin installer answered {status}") },
        })
    }
}

/// An id safe to put in a path; anything else is no plugin.
fn checked(id: &str) -> Result<&str, Failure> {
    let ok = !id.is_empty() && id.len() <= 64 && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if ok { Ok(id) } else { Err(Failure { status: 404, code: "not_found".into(), message: format!("no plugin {id}") }) }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok()).collect()
}

async fn exchange(socket: &Path, uid: u32, method: &str, path: &str, body: Body<'_>, actor: Actor<'_>) -> std::io::Result<(u16, Vec<u8>)> {
    let mut stream = http::connect_unix_as(socket, uid, CONNECT_TIMEOUT).await?;
    // Printable ASCII only: it goes into a header line.
    let actor: String = actor.unwrap_or_default().chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(64).collect();
    let (content_type, bytes, file) = match body {
        Body::Json(bytes) => ("application/json", bytes, None),
        Body::Package(package) => {
            let file = tokio::fs::File::open(package).await?;
            let length = file.metadata().await?.len();
            ("application/x-tar", &[][..], Some((file, length)))
        }
    };
    let length = file.as_ref().map_or(bytes.len() as u64, |(_, length)| *length).to_string();
    let mut headers = vec![("host", "localhost")];
    if !actor.is_empty() {
        headers.push(("x-kaonic-actor", actor.as_str()));
    }
    headers.extend_from_slice(&[("content-type", content_type), ("content-length", length.as_str()), ("connection", "close")]);
    http::write_request(&mut stream, &http::request_head(method, path, &headers), bytes).await?;
    if let Some((mut file, length)) = file {
        http::write_body(&mut stream, &mut file, length).await?;
    }
    let answer = http::read_answer(&mut stream, MAX_ANSWER).await?;
    Ok(http::parse(&answer)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_checked_before_they_reach_a_path() {
        assert!(checked("audio-ptt").is_ok());
        for bad in ["", "../policy", "a/b", "A", "a?b=1", "a b"] {
            assert_eq!(checked(bad).unwrap_err().status, 404, "{bad}");
        }
    }
}
