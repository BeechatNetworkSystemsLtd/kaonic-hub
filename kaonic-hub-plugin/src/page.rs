//! The plugin's own web page (`page = true` in its manifest), served on its page socket
//! ([`crate::ENV_PAGE_SOCKET`], `<plugins>/<id>/run/page.sock`). The hub shows it at
//! `/apps/<id>/` to signed-in users only, and proxies each request to this socket.
//!
//! ```no_run
//! use kaonic_hub_plugin::page::{self, Response};
//!
//! # async fn run() -> Result<(), kaonic_hub_plugin::Error> {
//! page::serve(|request| async move {
//!     match request.path.as_str() {
//!         "/" => Response::html("<!doctype html><title>Echo</title><a href=\"stats\">stats</a>"),
//!         "/stats" => Response::new(200, "application/json", "{\"echoed\":3}"),
//!         _ => Response::text(404, "no such page"),
//!     }
//! })
//! .await
//! # }
//! ```
//!
//! What the hub does, and so what a page must:
//!
//! - **Relative URLs.** The browser sees the page under `/apps/<id>/~<ticket>/`; the
//!   request arrives without that prefix (`/stats`), which is in `X-Forwarded-Prefix`
//!   ([`Request::prefix`]). A link to `/stats` would leave the page: write `stats` (or
//!   `./stats`), or the prefix and the path.
//! - **The path as the browser sent it**, still percent-encoded: split it at `/` first,
//!   then [`decode`] each piece. An encoded `%2F` or `..` is data, not structure.
//! - **One request per connection**, as HTTP/1.0 with `Connection: close` and a
//!   `Content-Length`; bodies are at most 1 MiB. This helper answers with a
//!   `Content-Length`, never in chunks, and closes.
//! - **Only some answer headers reach the browser**: `content-type`, `content-length`,
//!   `content-encoding`, `content-language`, `content-disposition`, `cache-control`,
//!   `etag`, `last-modified`, `expires`, `vary`, `accept-ranges`, `content-range` and
//!   `content-security-policy` (added to the hub's sandbox). Cookies and everything else
//!   are dropped. A `Location` stays only if it is relative without `..`, or under the
//!   page's own prefix: [`Response::redirect`] makes one that does.
//! - **The answer's head within 25 s**, or the hub gives up.
//! - **WebSockets** come as HTTP/1.1 upgrades; this helper does not take them (it answers
//!   501). A page that needs one serves the socket itself (see [`bind`]).
//!
//! The socket's directory is the plugin's own (0700); the helper also answers only root
//! (the hub) and the plugin's own user.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::error::{Error, Result};

/// The largest request head taken.
pub const MAX_HEAD: usize = 64 * 1024;
/// The largest request body taken (the hub passes on no more).
pub const MAX_BODY: usize = 1024 * 1024;
/// Requests served at once; more wait to be accepted.
pub const MAX_CONNECTIONS: usize = 32;
/// A connection's whole time: reading, the handler and answering.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// A request, as the hub passed it on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// `GET`, `POST`, … as sent.
    pub method: String,
    /// The path, still percent-encoded, without the page's prefix: `/`, `/stats`.
    pub path: String,
    /// What came after `?`, still encoded.
    pub query: Option<String>,
    /// Names in lower case, in the order sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header of that name (in lower case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// Where the browser sees the page, `/apps/<id>/~<ticket>` (no trailing slash), from
    /// `X-Forwarded-Prefix`; empty if the hub did not say. For absolute URLs.
    pub fn prefix(&self) -> &str {
        self.header("x-forwarded-prefix").unwrap_or_default()
    }
}

/// An answer: a status, a `Content-Type`, a body, and any more headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Besides `Content-Length` and `Connection`, which the helper sets.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers: vec![("content-type".into(), content_type.into())], body: body.into() }
    }

    /// 200, `text/html; charset=utf-8`.
    pub fn html(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, "text/html; charset=utf-8", body)
    }

    /// `text/plain; charset=utf-8`.
    pub fn text(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(status, "text/plain; charset=utf-8", body)
    }

    /// 303 to `location`, relative to the page (`stats`, `./?done=1`); the hub drops a
    /// `Location` that leaves the page, so this takes none with `..`, a scheme or a
    /// leading `/` (500 instead).
    pub fn redirect(location: &str) -> Self {
        let first = location.split(['/', '?', '#']).next().unwrap_or_default();
        let path = &location[..location.find(['?', '#']).unwrap_or(location.len())];
        let leaves = location.starts_with('/')
            || first.contains(':')
            || path.split('/').any(|segment| segment == "..")
            || location.to_ascii_lowercase().contains("%2e")
            || location.bytes().any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\');
        if leaves {
            return Self::text(500, "a redirect out of the page");
        }
        Self::text(303, "").header("location", location)
    }

    /// One more header; one with a bad name or value is left out when answering.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }
}

/// Percent-decodes a piece of a path or query (`%20` → ` `); `+` stays `+`. None for a bad
/// escape or text that is not UTF-8.
pub fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Serves the page on the socket the installer set ([`crate::ENV_PAGE_SOCKET`]) until an
/// error stops it; see [`serve_on`].
pub async fn serve<H, F>(handler: H) -> Result<()>
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let path = std::env::var_os(crate::ENV_PAGE_SOCKET)
        .ok_or_else(|| Error::Config(format!("{} is not set: add page = true to [kaonic-plugin] in kaonic-plugin.toml", crate::ENV_PAGE_SOCKET)))?;
    serve_at(Path::new(&path), handler).await
}

/// Serves the page on the socket at `path`; see [`bind`] and [`serve_on`].
pub async fn serve_at<H, F>(path: &Path, handler: H) -> Result<()>
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    serve_on(bind(path)?, handler).await
}

/// Binds the page socket at `path`, removing one left by an earlier run first (only a
/// socket: anything else there is an error).
pub fn bind(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    let config = |why: String| Error::Config(format!("the page socket {}: {why}", path.display()));
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => std::fs::remove_file(path).map_err(|error| config(error.to_string()))?,
        Ok(_) => return Err(config("something other than a socket is there".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(config(error.to_string())),
    }
    UnixListener::bind(path).map_err(|error| config(error.to_string()))
}

/// Serves requests on `listener` with `handler`, each on its own task, at most
/// [`MAX_CONNECTIONS`] at once. Returns only if the socket's owner cannot be read.
pub async fn serve_on<H, F>(listener: UnixListener, handler: H) -> Result<()>
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let owner = owner(&listener)?;
    let handler = Arc::new(handler);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let slot = slots.clone().acquire_owned().await.expect("never closed");
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                // Out of descriptors: wait instead of spinning.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !stream.peer_cred().is_ok_and(|peer| peer.uid() == 0 || peer.uid() == owner) {
            continue;
        }
        let handler = handler.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(TIMEOUT, connection(stream, &*handler)).await;
            drop(slot);
        });
    }
}

/// The user the socket file belongs to: this process's.
fn owner(listener: &UnixListener) -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let address = listener.local_addr()?;
    let path = address.as_pathname().ok_or_else(|| Error::Config("the page socket has no path".into()))?;
    Ok(std::fs::metadata(path)?.uid())
}

async fn connection<H, F>(mut stream: UnixStream, handler: &H)
where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    let response = match read_request(&mut stream).await {
        Ok(Some(request)) if is_websocket(&request) => (Response::text(501, "this page takes no WebSockets"), false),
        Ok(Some(request)) => {
            let head = request.method == "HEAD";
            (handler(request).await, head)
        }
        Ok(None) => return,
        Err(response) => (response, false),
    };
    let _ = stream.write_all(&encode(&response.0, response.1)).await;
    let _ = stream.shutdown().await;
}

fn is_websocket(request: &Request) -> bool {
    request.header("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// A whole request; None if the connection closed first, or the answer to a bad one.
async fn read_request(stream: &mut UnixStream) -> std::result::Result<Option<Request>, Response> {
    let mut buffer = Vec::with_capacity(4096);
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        if buffer.len() > MAX_HEAD {
            return Err(Response::text(431, "request head too large"));
        }
        match stream.read_buf(&mut buffer).await {
            Ok(1..) => {}
            _ => return Ok(None),
        }
    };
    let mut request = parse_head(&buffer[..end]).ok_or_else(|| Response::text(400, "bad request"))?;
    if request.header("transfer-encoding").is_some() {
        return Err(Response::text(501, "chunked requests are not taken"));
    }
    let length = match request.header("content-length") {
        Some(value) => value.parse::<usize>().map_err(|_| Response::text(400, "bad content-length"))?,
        None => 0,
    };
    if length > MAX_BODY {
        return Err(Response::text(413, "request body too large"));
    }
    let mut body = buffer.split_off(end + 4);
    while body.len() < length {
        match stream.read_buf(&mut body).await {
            Ok(1..) => {}
            _ => return Ok(None),
        }
    }
    body.truncate(length);
    request.body = body;
    Ok(Some(request))
}

fn parse_head(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut words = lines.next()?.split(' ');
    let (method, target, version) = (words.next()?, words.next()?, words.next()?);
    if words.next().is_some() || method.is_empty() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_owned())),
        None => (target, None),
    };
    let headers = lines.map(|line| line.split_once(':').map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))).collect::<Option<Vec<_>>>()?;
    Some(Request { method: method.to_owned(), path: path.to_owned(), query, headers, body: Vec::new() })
}

/// The answer, with its length; the body left out for `HEAD`.
fn encode(response: &Response, head_only: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status)).into_bytes();
    let token = |name: &str| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    for (name, value) in &response.headers {
        let set_here = matches!(name.as_str(), "content-length" | "connection" | "transfer-encoding");
        if set_here || !token(name) || value.bytes().any(|byte| byte.is_ascii_control() && byte != b'\t') {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\nconnection: close\r\n\r\n", response.body.len()).as_bytes());
    if !head_only {
        out.extend_from_slice(&response.body);
    }
    out
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        303 => "See Other",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_decode_piece_by_piece() {
        assert_eq!(decode("a%20b+c").as_deref(), Some("a b+c"));
        assert_eq!(decode("%2e%2e%2Fadmin").as_deref(), Some("../admin"));
        assert_eq!(decode("caf%C3%A9").as_deref(), Some("café"));
        for bad in ["%", "%2", "%zz", "%ff"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn requests_parse_as_the_hub_sends_them() {
        let request = parse_head(b"GET /files/%2e%2e%2fadmin?q=%20 HTTP/1.0\r\nhost: localhost\r\nX-Forwarded-Prefix: /apps/echo/~t").unwrap();
        assert_eq!((request.method.as_str(), request.path.as_str(), request.query.as_deref()), ("GET", "/files/%2e%2e%2fadmin", Some("q=%20")));
        assert_eq!((request.header("host"), request.prefix()), (Some("localhost"), "/apps/echo/~t"));
        for bad in [&b"GET /a"[..], b"GET a HTTP/1.0", b"GET /a HTTP/2", b"GET /a HTTP/1.0 x", b"GET /a HTTP/1.0\r\nno colon"] {
            assert!(parse_head(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn answers_have_a_length_and_no_bad_headers() {
        let response = Response::html("<p>hi</p>").header("Cache-Control", "no-store").header("x-bad", "a\r\nset-cookie: b").header("content-length", "99").header("bad name", "x");
        let text = String::from_utf8(encode(&response, false)).unwrap();
        assert_eq!(text, "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\ncontent-length: 9\r\nconnection: close\r\n\r\n<p>hi</p>");
        assert!(String::from_utf8(encode(&response, true)).unwrap().ends_with("content-length: 9\r\nconnection: close\r\n\r\n"));
    }

    #[test]
    fn redirects_stay_on_the_page() {
        assert_eq!(Response::redirect("stats?x=1").status, 303);
        assert_eq!(Response::redirect("./").headers.last().unwrap(), &("location".to_owned(), "./".to_owned()));
        for out in ["/admin", "../x", "a/../../x", "https://evil.example/", "//evil.example", "%2e%2e/x", "a b"] {
            assert_eq!(Response::redirect(out).status, 500, "{out}");
        }
    }
}
