//! `kaonic-hub-plugin`: the SDK for Kaonic plugins.
//!
//! A small client for the hub's plugin API (`docs/api/plugin-api.yaml`), on the plugin's
//! own Unix socket: who this plugin is, the trusted nodes, messages to this plugin on other
//! nodes, events, and a key/value store of its own. The hub owns the radio and the links; a
//! plugin only ever talks to its own copies on nodes the admin trusts. [`page`] serves the
//! plugin's web page, if it has one.
//!
//! ```no_run
//! use kaonic_hub_plugin::{Event, Hub, Target};
//!
//! # async fn run() -> Result<(), kaonic_hub_plugin::Error> {
//! let hub = Hub::connect().await?;
//! let me = hub.me().await?;
//! println!("I am {} on {:?}", me.plugin, me.node);
//! let mut events = hub.events().await?;
//! while let Some(event) = events.next().await {
//!     if let Event::Received { from, channel, data, .. } = event {
//!         events.send(Target::Node(from), channel, &data).await?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Messages need the `mesh` permission in the plugin's manifest; without it they and the
//! event socket answer [`Error::Forbidden`] with code `missing_permission`.
//!
//! **Limits** (the hub's, per plugin): at most 16 connections at once (this SDK makes at
//! most [`MAX_REQUESTS`] requests at once, one connection each; the rest wait their turn),
//! a request within 30 s, at most 4 event sockets ([`Error::TooManySockets`]). Message
//! sizes and the queue are in [`Me::limits`]: read them, do not assume them.

mod error;
mod events;
mod http;
pub mod page;
mod store;
mod types;
mod ws;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kaonic_hub_common::base64;
use serde::de::DeserializeOwned;

pub use error::{Error, Result};
pub use events::{DropReason, Event, Events, Sender, Target};
pub use http::MAX_REQUESTS;
pub use store::Store;
pub use types::{Counts, Limits, Link, Me, Node, Queued, Stats, StoreLimits};

/// The plugin API's address, set by the installer: `unix:/run/kaonic-hub/plugins/<id>.sock`.
pub const ENV_API: &str = "KAONIC_HUB_API";
/// The file holding the plugin's token, set by the installer.
pub const ENV_TOKEN: &str = "KAONIC_PLUGIN_TOKEN";
/// The plugin's id, set by the installer.
pub const ENV_ID: &str = "KAONIC_PLUGIN_ID";
/// The plugin's directory, set by the installer; `data/` in it is writable.
pub const ENV_DIR: &str = "KAONIC_PLUGIN_DIR";
/// The socket the plugin's page is served on, set by the installer with `page = true`.
pub const ENV_PAGE_SOCKET: &str = "KAONIC_PLUGIN_PAGE_SOCKET";
/// How long [`Hub::connect`] waits for the hub's socket.
pub const CONNECT_WAIT: Duration = Duration::from_secs(60);

/// The plugin API. Cheap to clone; every call is one request on its own connection.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<Inner>,
}

struct Inner {
    endpoint: http::Endpoint,
    token: Mutex<String>,
    /// Read again after a 401: a rollback or reinstall writes a new token.
    token_file: Option<PathBuf>,
}

impl Hub {
    /// From what the installer sets: [`ENV_API`] and the token in the file [`ENV_TOKEN`].
    ///
    /// Waits for the hub's socket, for at most [`CONNECT_WAIT`] (60 s): a plugin may start
    /// before the hub has made it (at once after an install through the hub, otherwise
    /// within 30 s), or while the hub restarts. A missing socket or a refused connection is
    /// tried again, with a pause growing from 0.1 s to 2 s; anything else, and still no
    /// socket after 60 s, is [`Error::Io`].
    pub async fn connect() -> Result<Hub> {
        let missing = |name: &str| {
            Error::Config(format!("{name} is not set: run this plugin under kaonic-hub-installer, or use Hub::connect_to(api, token) for development"))
        };
        let api = std::env::var(ENV_API).map_err(|_| missing(ENV_API))?;
        let file = PathBuf::from(std::env::var_os(ENV_TOKEN).ok_or_else(|| missing(ENV_TOKEN))?);
        let token = read_token(&file).await?;
        let hub = Hub { inner: Arc::new(Inner { endpoint: http::Endpoint::parse(&api)?, token: Mutex::new(token), token_file: Some(file) }) };
        hub.wait(CONNECT_WAIT).await?;
        Ok(hub)
    }

    /// With a given address and token (`kpt1.…`), for tests and development. The address is
    /// as in [`ENV_API`], `unix:<path>`, or `http://host:port` for a hub serving the API on
    /// TCP. Does not contact the hub yet (see [`Hub::wait`]).
    pub fn connect_to(api: &str, token: &str) -> Result<Hub> {
        let token = checked_token(token.trim())?;
        Ok(Hub { inner: Arc::new(Inner { endpoint: http::Endpoint::parse(api)?, token: Mutex::new(token), token_file: None }) })
    }

    /// Waits until the hub accepts a connection, for at most `within`, as [`Hub::connect`]
    /// does: for after the hub restarted (its socket goes and comes back).
    pub async fn wait(&self, within: Duration) -> Result<()> {
        self.inner.endpoint.wait(within).await
    }

    /// The plugin's id as the installer set it ([`ENV_ID`]); [`Hub::me`] asks the hub.
    pub fn id() -> Option<String> {
        std::env::var(ENV_ID).ok()
    }

    /// The plugin's directory ([`ENV_DIR`]); its `data/` is the only place it may write.
    pub fn dir() -> Option<PathBuf> {
        std::env::var_os(ENV_DIR).map(PathBuf::from)
    }

    /// This plugin, its permissions, the node and the limits.
    pub async fn me(&self) -> Result<Me> {
        self.json("/self").await
    }

    /// The trusted nodes, sorted by id.
    pub async fn nodes(&self) -> Result<Vec<Node>> {
        self.json("/nodes").await
    }

    /// One trusted node; [`Error::NotFound`] if it is not one.
    pub async fn node(&self, id: &str) -> Result<Node> {
        self.json(&format!("/nodes/{}", node_id(id)?)).await
    }

    /// A message to this plugin on one trusted node, best effort, of at most
    /// `limits.max_message` bytes. [`Error::NotFound`] if it is not trusted,
    /// [`Error::TooLarge`], [`Error::QueueFull`], or [`Error::AmbiguousName`]; `sent` or
    /// `dropped` (`no_link`, `over_budget`, …) follow as events.
    pub async fn send(&self, node: &str, channel: u8, data: &[u8]) -> Result<Queued> {
        self.post(&format!("/nodes/{}/messages", node_id(node)?), channel, data).await
    }

    /// A message to this plugin on every linked node that runs it (`nodes` may be 0).
    pub async fn send_all(&self, channel: u8, data: &[u8]) -> Result<Queued> {
        self.post("/messages", channel, data).await
    }

    /// One transmission heard by every neighbour (one hop), encrypted with the group key.
    /// [`Error::Hub`] with status 409 while this node has no group key.
    pub async fn broadcast(&self, channel: u8, data: &[u8]) -> Result<Queued> {
        self.post("/broadcast", channel, data).await
    }

    /// This plugin's use of the mesh.
    pub async fn stats(&self) -> Result<Stats> {
        self.json("/stats").await
    }

    /// This plugin's key/value store.
    pub fn store(&self) -> Store {
        Store::new(self.clone())
    }

    /// Opens the event socket. See [`Events`] for when it ends and reconnecting. At most 4
    /// per plugin: a fifth is [`Error::TooManySockets`].
    pub async fn events(&self) -> Result<Events> {
        let mut retried = false;
        loop {
            let token = self.token();
            match ws::connect(&self.inner.endpoint, "/events", &token).await {
                Err(Error::Unauthorized) if !retried && self.reread_token(&token).await => retried = true,
                Ok((reader, writer)) => return Ok(Events::new(reader, writer)),
                Err(error) => return Err(error),
            }
        }
    }

    async fn post(&self, path: &str, channel: u8, data: &[u8]) -> Result<Queued> {
        let body = serde_json::json!({ "channel": channel, "data": base64::encode(data) }).to_string();
        let answer = self.call("POST", path, Some(body.as_bytes())).await?;
        parse_json(&answer)
    }

    pub(crate) async fn json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        parse_json(&self.call("GET", path, None).await?)
    }

    /// One request; the body of a 2xx answer, or the error.
    pub(crate) async fn call(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut retried = false;
        loop {
            let token = self.token();
            let (status, answer) = http::exchange(&self.inner.endpoint, method, path, &token, body).await?;
            if (200..300).contains(&status) {
                return Ok(answer);
            }
            if status == 401 && !retried && self.reread_token(&token).await {
                retried = true;
                continue;
            }
            return Err(Error::from_answer(status, &answer));
        }
    }

    fn token(&self) -> String {
        self.inner.token.lock().expect("token lock").clone()
    }

    /// Reads the token file again; true if it holds another token than `used`.
    async fn reread_token(&self, used: &str) -> bool {
        let Some(file) = &self.inner.token_file else { return false };
        match read_token(file).await {
            Ok(token) if token != used => {
                *self.inner.token.lock().expect("token lock") = token;
                true
            }
            _ => false,
        }
    }
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|error| Error::Protocol(error.to_string()))
}

async fn read_token(file: &std::path::Path) -> Result<String> {
    let text = tokio::fs::read_to_string(file).await.map_err(|error| Error::Config(format!("reading the token {}: {error}", file.display())))?;
    checked_token(text.trim())
}

/// A token goes into a header line: printable ASCII only.
fn checked_token(token: &str) -> Result<String> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(Error::Config("the plugin token is empty or not one line of text".into()));
    }
    Ok(token.to_owned())
}

/// A node id safe to put in a path; anything else is no trusted node.
fn node_id(id: &str) -> Result<&str> {
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) { Ok(id) } else { Err(Error::NotFound) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_node_ids_are_checked() {
        assert!(Hub::connect_to("http://127.0.0.1:8783", "kpt1.abc.def\n").is_ok());
        assert!(Hub::connect_to("unix:/run/kaonic-hub/plugins/echo.sock", "kpt1.abc.def").is_ok());
        for bad in ["", "kpt1 abc", "kpt1.a\r\nx: y"] {
            assert!(matches!(Hub::connect_to("http://127.0.0.1:8783", bad), Err(Error::Config(_))), "{bad:?}");
        }
        assert!(node_id("00112233445566778899aabbccddeeff").is_ok());
        for bad in ["", "../self", "ab/cd", "zz"] {
            assert!(matches!(node_id(bad), Err(Error::NotFound)), "{bad}");
        }
    }

    /// Plugins may spawn the calls on a multi-threaded runtime.
    #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
    fn futures_are_send(hub: Hub, mut events: Events) {
        fn send<T: Send>(_: T) {}
        send(hub.me());
        send(hub.send("ab", 1, b""));
        send(hub.store().get::<u64>("k"));
        send(hub.events());
        send(hub.wait(Duration::ZERO));
        send(page::serve_at(std::path::Path::new("p"), |_| async { page::Response::text(200, "") }));
        send(events.sender().send(Target::All, 1, b""));
        send(events.next());
    }
}
