//! A minimal HTTP/1.1 client: one request per connection, on the plugin's Unix socket (or
//! loopback TCP, for development).

use std::time::Duration;

pub use kaonic_hub_common::http::{Address, Io};
use kaonic_hub_common::http::{self as common, request_head};
use tokio::sync::Semaphore;

use crate::error::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The hub's own deadline for a whole request.
const TIMEOUT: Duration = Duration::from_secs(30);
/// More than any answer of the plugin API (a store value is at most 64 KiB).
const MAX_ANSWER: usize = 4 * 1024 * 1024;
/// The path of the plugin API under the hub's address.
pub const BASE: &str = "/api/plugin/v1";
/// Requests at once from this process. The hub holds at most 16 connections per plugin
/// (the event sockets among them, at most 4) and closes more unanswered; the rest is room
/// for connections still closing.
pub const MAX_REQUESTS: usize = 8;
static REQUESTS: Semaphore = Semaphore::const_new(MAX_REQUESTS);
/// A request the hub closed unanswered (it was over its connection cap) is sent again
/// this many times, after a short pause: the hub did not read it.
const UNANSWERED_RETRIES: u32 = 3;

/// Where the plugin API is: `unix:<path>`, or `http://host:port[/prefix]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: Address,
    /// For the `Host` header.
    pub authority: String,
    /// The API's path, without a trailing slash.
    pub base: String,
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Self> {
        let bad = |why: &str| Error::Config(format!("hub API {url:?}: {why}"));
        let url = url.trim();
        if let Some(path) = url.strip_prefix("unix:") {
            if path.is_empty() || path.bytes().any(|byte| byte == 0) {
                return Err(bad("no socket path after unix:"));
            }
            return Ok(Self { address: Address::Unix(path.into()), authority: "localhost".into(), base: BASE.into() });
        }
        let rest = url.strip_prefix("http://").ok_or_else(|| bad("use unix:<path> (as the installer sets it), or http://host:port for development"))?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6.split_once(']').ok_or_else(|| bad("unclosed ["))?;
                (host, after.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        if host.is_empty() {
            return Err(bad("no host"));
        }
        let port = match port {
            Some(port) => port.parse::<u16>().map_err(|_| bad("bad port"))?,
            None => 80,
        };
        let base = if path.ends_with(BASE) { path.to_owned() } else { format!("{path}{BASE}") };
        Ok(Self { address: Address::Tcp(host.to_owned(), port), authority: authority.to_owned(), base })
    }

    pub async fn connect(&self) -> Result<Box<dyn Io>> {
        let connected = tokio::time::timeout(CONNECT_TIMEOUT, self.address.connect())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connecting to the hub timed out"))?;
        match (&self.address, connected) {
            (Address::Unix(path), Err(error)) => Err(std::io::Error::new(error.kind(), format!("the plugin API socket {}: {error}", path.display())).into()),
            (_, connected) => Ok(connected?),
        }
    }

    /// Waits until the hub accepts a connection, for at most `within`: the socket may not
    /// be there yet (the hub makes it after an install, within 30 s). Only a missing socket
    /// or a refused connection is waited out; any other error is returned at once.
    pub async fn wait(&self, within: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        let mut pause = Duration::from_millis(100);
        loop {
            let error = match self.connect().await {
                Ok(_) => return Ok(()),
                Err(Error::Io(error)) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => error,
                Err(error) => return Err(error),
            };
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(Error::Io(std::io::Error::new(error.kind(), format!("{error} (waited {} s for the hub)", within.as_secs()))));
            }
            tokio::time::sleep(pause.min(deadline - now)).await;
            pause = (pause * 2).min(Duration::from_secs(2));
        }
    }
}

/// One request; the status and body of the answer.
pub async fn exchange(endpoint: &Endpoint, method: &str, path: &str, token: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>)> {
    let _turn = REQUESTS.acquire().await.expect("never closed");
    let mut tries = 0;
    loop {
        let answer = tokio::time::timeout(TIMEOUT, exchange_now(endpoint, method, path, token, body))
            .await
            .map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "the hub did not answer in time")))?;
        match answer {
            Err(Unanswered) if tries < UNANSWERED_RETRIES => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50 << tries)).await;
            }
            Err(Unanswered) => return Err(unanswered()),
            Ok(answer) => return answer,
        }
    }
}

/// The hub closed before a byte of the answer.
struct Unanswered;

fn unanswered() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "the hub closed the connection unanswered (over its 16 connections per plugin, or not this plugin's user)",
    ))
}

async fn exchange_now(endpoint: &Endpoint, method: &str, path: &str, token: &str, body: Option<&[u8]>) -> std::result::Result<Result<(u16, Vec<u8>)>, Unanswered> {
    let mut stream = match endpoint.connect().await {
        Ok(stream) => stream,
        Err(error) => return Ok(Err(error)),
    };
    let target = format!("{}{path}", endpoint.base);
    let bearer = format!("Bearer {token}");
    let length = body.map(|body| body.len().to_string());
    let mut headers = vec![("host", endpoint.authority.as_str()), ("authorization", bearer.as_str()), ("connection", "close")];
    if let Some(length) = &length {
        headers.extend_from_slice(&[("content-type", "application/json"), ("content-length", length.as_str())]);
    } else if method != "GET" {
        headers.push(("content-length", "0"));
    }
    // Closed at once by the hub, the request may not go out whole: what was read says.
    let _ = common::write_request(&mut stream, &request_head(method, &target, &headers), body.unwrap_or_default()).await;
    match common::read_answer(&mut stream, MAX_ANSWER).await {
        Ok(answer) => Ok(common::parse(&answer).map_err(Error::from)),
        Err(common::Error::Unanswered(_)) => Err(Unanswered),
        Err(error) => Ok(Err(error.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_urls() {
        let socket = Endpoint::parse("unix:/run/kaonic-hub/plugins/echo.sock").unwrap();
        assert_eq!((&socket.address, socket.authority.as_str(), socket.base.as_str()), (&Address::Unix("/run/kaonic-hub/plugins/echo.sock".into()), "localhost", BASE));
        let local = Endpoint::parse("http://127.0.0.1:8783").unwrap();
        assert_eq!((&local.address, local.authority.as_str(), local.base.as_str()), (&Address::Tcp("127.0.0.1".into(), 8783), "127.0.0.1:8783", BASE));
        assert_eq!(Endpoint::parse("http://127.0.0.1:8783/api/plugin/v1/").unwrap().base, BASE);
        assert_eq!(Endpoint::parse("http://hub/prefix").unwrap().base, format!("/prefix{BASE}"));
        assert_eq!(Endpoint::parse("http://hub").unwrap().address, Address::Tcp("hub".into(), 80));
        let v6 = Endpoint::parse("http://[::1]:8783").unwrap();
        assert_eq!((&v6.address, v6.authority.as_str()), (&Address::Tcp("::1".into(), 8783), "[::1]:8783"));
        for bad in ["https://127.0.0.1:8783", "127.0.0.1:8783", "http://:80", "http://hub:x", "http://[::1:80", "unix:", "/run/x.sock"] {
            assert!(matches!(Endpoint::parse(bad), Err(Error::Config(_))), "{bad}");
        }
    }
}
