//! `/apps/<id>/…`: a plugin's own web page, proxied to the HTTP server it runs on its page
//! socket, `<plugins>/<id>/run/page.sock` (the manifest's `page = true`). Nothing is sent
//! until the socket's peer is the plugin's own user.
//!
//! Only for the signed-in. The page runs sandboxed in an opaque origin, so the session
//! cookie (`SameSite=Strict`) does not come with what it loads: a signed-in request without
//! a ticket is redirected to `/apps/<id>/~<ticket>/…` ([`super::tickets`]), and requests
//! with a ticket are let through while its session lives. Pages must use relative URLs.
//!
//! The page is served from the hub's origin, so `web::security_headers` sandboxes it, and the
//! hub's credentials (session cookie, CSRF token, authorization) are never passed on. Of the
//! plugin's answer only the headers in [`KEEP_RESPONSE`] come through, and a `Location` only
//! within the page's own prefix. The plugin gets the path as the browser sent it, still
//! percent-encoded, after the prefix. Request bodies are at most [`MAX_REQUEST_BODY`],
//! streamed; WebSockets are passed through, closed when idle for [`WEBSOCKET_IDLE`] and
//! when their ticket or session ends (checked every [`WEBSOCKET_RECHECK`]).

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::any;
use hyper_util::rt::TokioIo;
use kaonic_hub_common::http::{self, Io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::tickets;
use crate::app::App;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Until the plugin has sent its status line and headers.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_HEAD: usize = 64 * 1024;
/// The largest request body passed to a plugin.
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// A proxied WebSocket with nothing sent either way for this long is closed.
pub const WEBSOCKET_IDLE: Duration = Duration::from_secs(300);
/// How often a proxied WebSocket checks that its ticket and session still hold.
pub const WEBSOCKET_RECHECK: Duration = Duration::from_secs(30);

/// Request headers that carry the hub's credentials or belong to one hop only.
const DROP_REQUEST: &[&str] = &[
    "cookie",
    "authorization",
    "proxy-authorization",
    crate::auth::CSRF_HEADER,
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "expect",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-prefix",
];

/// The only response headers a plugin may send through the hub (and `Location`, checked).
/// Its `content-security-policy` adds to the hub's own.
pub const KEEP_RESPONSE: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "content-disposition",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "vary",
    "content-security-policy",
    "accept-ranges",
    "content-range",
];

/// A WebSocket handshake's answer headers, kept on a 101.
const KEEP_UPGRADE: &[&str] = &["sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions"];

pub fn router(app: App) -> Router {
    Router::new()
        .route("/apps/{id}", any(|request: Request| async move { bare(request.uri().path()) }))
        .route("/apps/{id}/", any(|State(app): State<App>, request: Request| forward(app, request)))
        .route("/apps/{id}/{*rest}", any(|State(app): State<App>, request: Request| forward(app, request)))
        .with_state(app)
}

fn not_here() -> Response {
    (StatusCode::NOT_FOUND, "This plugin has no page here.").into_response()
}

fn sign_in() -> Response {
    (StatusCode::UNAUTHORIZED, "Sign in to the hub to open this page.").into_response()
}

/// A plugin id as it may stand in a path: no encoding, nothing else.
fn plugin_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// `/apps/<id>`: the same with the slash.
fn bare(path: &str) -> Response {
    match path.strip_prefix("/apps/").filter(|id| plugin_id(id)) {
        Some(id) => Redirect::permanent(&format!("/apps/{id}/")).into_response(),
        None => not_here(),
    }
}

/// The plugin's id and the path after `/apps/<id>/`, as sent (still percent-encoded).
fn split_path(path: &str) -> Option<(&str, &str)> {
    let (id, rest) = path.strip_prefix("/apps/")?.split_once('/')?;
    plugin_id(id).then_some((id, rest))
}

/// Let in: the page's prefix (`/apps/<id>/~<ticket>`), its ticket, and the path after it.
struct Admitted<'a> {
    prefix: String,
    ticket: String,
    after: &'a str,
}

/// Whether `id` is installed and has a page.
async fn has_page(app: &App, id: &str) -> bool {
    app.plugins().find(id, |plugin| plugin.record.manifest.page).await.is_some()
}

/// Whether a ticket and the session it came from still hold.
async fn still_admitted(app: &App, id: &str, ticket: &str) -> bool {
    let Some(session) = app.plugins().tickets.check(id, ticket) else { return false };
    let now = crate::clock::now();
    app.store.call(move |c| kaonic_store::sessions::is_live(c, &session, now)).await.unwrap_or(false)
}

/// The ticket and the path after it, or the answer to give instead (sign in, a redirect).
async fn admit<'a>(app: &App, id: &str, rest: &'a str, method: &Method, uri: &axum::http::Uri, headers: &HeaderMap) -> Result<Admitted<'a>, Box<Response>> {
    let query = uri.query().map(|query| format!("?{query}")).unwrap_or_default();
    let Some((ticket, after)) = tickets::split(rest) else {
        // Signed in (a navigation from the UI, or a new tab): a ticket, then the same page.
        let caller = crate::auth::current(app, headers).await.ok().flatten();
        let Some(caller) = caller.filter(|_| matches!(*method, Method::GET | Method::HEAD)) else { return Err(Box::new(sign_in())) };
        if !has_page(app, id).await {
            return Err(Box::new(not_here()));
        }
        let ticket = app.plugins().tickets.mint(id, &caller.token_hash).map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
        return Err(Box::new(Redirect::to(&format!("/apps/{id}/{}{ticket}/{rest}{query}", tickets::MARK)).into_response()));
    };
    if !still_admitted(app, id, ticket).await {
        return Err(Box::new(sign_in()));
    }
    // `/apps/<id>/~<ticket>` without the slash: relative URLs need it.
    if after.is_empty() && !uri.path().ends_with('/') {
        return Err(Box::new(Redirect::to(&format!("/apps/{id}/{}{ticket}/{query}", tickets::MARK)).into_response()));
    }
    Ok(Admitted { prefix: format!("/apps/{id}/{}{ticket}", tickets::MARK), ticket: ticket.to_owned(), after })
}

async fn forward(app: App, mut request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let Some((id, rest)) = split_path(&path) else { return not_here() };
    let admitted = admit(&app, id, rest, request.method(), request.uri(), request.headers()).await;
    let Admitted { prefix, ticket, after } = match admitted {
        Ok(admitted) => admitted,
        Err(answer) => return *answer,
    };
    let Some(plugin) = app.plugins().find(id, |_| true).await else { return not_here() };
    if !plugin.record.manifest.page {
        return not_here();
    }
    let name = plugin.record.manifest.name.clone();
    if !plugin.running {
        return (StatusCode::SERVICE_UNAVAILABLE, format!("{name} is not running.")).into_response();
    }
    let socket = page_socket(&app.plugins().settings.dir, id);
    let uid = app.plugins().uid_of(&plugin);

    let query = request.uri().query().map(|query| format!("?{query}")).unwrap_or_default();
    let target = format!("/{after}{query}");
    if target.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let websocket = is_websocket(request.headers());
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let too_large = || (StatusCode::PAYLOAD_TOO_LARGE, "The request is too large.").into_response();
    // A body of a stated length is streamed; one without (chunked) is read first, within the limit.
    let declared = parts.headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.trim().parse::<usize>().ok());
    let (body, length) = match (websocket, declared) {
        (true, _) => (Outgoing::Read(Bytes::new()), 0),
        (false, Some(length)) if length > MAX_REQUEST_BODY => return too_large(),
        (false, Some(length)) => (Outgoing::Stream(body), length),
        (false, None) => match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
            Ok(bytes) => {
                let length = bytes.len();
                (Outgoing::Read(bytes), length)
            }
            Err(_) => return too_large(),
        },
    };
    let headers = outgoing_headers(&parts.headers, &prefix, websocket);
    let head = request_head(parts.method.as_str(), &target, &headers, websocket, length);

    let answer = async {
        let mut stream = connect(&socket, uid).await?;
        stream.write_all(&head).await?;
        body.send(&mut stream, length).await?;
        stream.flush().await?;
        let (status, headers, leftover) = read_head(&mut stream).await?;
        Ok::<_, std::io::Error>((stream, status, headers, leftover))
    };
    let (stream, status, headers, leftover) = match tokio::time::timeout(ANSWER_TIMEOUT, answer).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => {
            log::debug!("plugins: proxy to {id}: {error}");
            return (StatusCode::BAD_GATEWAY, format!("{name} does not answer on its page socket.")).into_response();
        }
        Err(_) => return (StatusCode::GATEWAY_TIMEOUT, format!("{name} did not answer in time.")).into_response(),
    };

    if status == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let upgrade = headers.get(header::UPGRADE).cloned();
        let (app, id) = (app.clone(), id.to_owned());
        tokio::spawn(async move {
            match client_upgrade.await {
                Ok(client) => {
                    let mut client = TokioIo::new(client);
                    if client.write_all(&leftover).await.is_ok() {
                        relay(client, stream, WEBSOCKET_IDLE, WEBSOCKET_RECHECK, || still_admitted(&app, &id, &ticket)).await;
                    }
                }
                Err(error) => log::debug!("plugins: websocket upgrade: {error}"),
            }
        });
        let mut headers = response_headers(&headers, true, &prefix);
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(upgrade) = upgrade {
            headers.insert(header::UPGRADE, upgrade);
        }
        let mut response = Response::new(Body::empty());
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return response;
    }

    // Asked as HTTP/1.0, a server delimits the body by its length or by closing; never by chunks.
    if headers.get(header::TRANSFER_ENCODING).is_some() {
        return (StatusCode::BAD_GATEWAY, "The plugin answered in a form the hub does not pass on.").into_response();
    }
    let length = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.trim().parse::<u64>().ok());
    let headers = response_headers(&headers, false, &prefix);
    let no_body = parts.method == Method::HEAD || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED;
    let body = if no_body { Body::empty() } else { Body::new(Upstream::new(stream, leftover, length)) };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// Where plugin `id` serves its page.
pub fn page_socket(plugins: &Path, id: &str) -> std::path::PathBuf {
    plugins.join(id).join("run").join("page.sock")
}

/// A request body on its way to the plugin.
enum Outgoing {
    Read(Bytes),
    Stream(Body),
}

impl Outgoing {
    /// Writes exactly `length` bytes; a body longer or shorter than it said is an error.
    async fn send(self, stream: &mut Box<dyn Io>, length: usize) -> std::io::Result<()> {
        let mut body = match self {
            Outgoing::Read(bytes) => return stream.write_all(&bytes).await,
            Outgoing::Stream(body) => body,
        };
        let bad = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_owned());
        let mut sent = 0;
        loop {
            let frame = std::future::poll_fn(|cx| http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)).await;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|error| bad(&error.to_string()))?;
            if let Ok(data) = frame.into_data() {
                sent += data.len();
                if sent > length {
                    return Err(bad("the body is longer than it said"));
                }
                stream.write_all(&data).await?;
            }
        }
        if sent != length {
            return Err(bad("the body is shorter than it said"));
        }
        Ok(())
    }
}

/// Copies both ways until either side closes, nothing moves for `idle`, or `admitted`
/// (asked every `recheck`) says no.
async fn relay<F, A>(client: impl AsyncRead + AsyncWrite + Unpin, upstream: impl AsyncRead + AsyncWrite + Unpin, idle: Duration, recheck: Duration, admitted: F)
where
    F: Fn() -> A,
    A: Future<Output = bool>,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut from_client = vec![0u8; 16 * 1024];
    let mut from_upstream = vec![0u8; 16 * 1024];
    let mut checks = tokio::time::interval(recheck);
    checks.tick().await;
    loop {
        tokio::select! {
            read = client_read.read(&mut from_client) => match read {
                Ok(0) | Err(_) => return,
                Ok(read) => if upstream_write.write_all(&from_client[..read]).await.is_err() { return },
            },
            read = upstream_read.read(&mut from_upstream) => match read {
                Ok(0) | Err(_) => return,
                Ok(read) => if client_write.write_all(&from_upstream[..read]).await.is_err() { return },
            },
            _ = tokio::time::sleep(idle) => return,
            _ = checks.tick() => if !admitted().await { return },
        }
    }
}

/// The request line and headers. HTTP/1.0 with `Connection: close` (one request per
/// connection, and the answer cannot come in chunks); a WebSocket handshake needs HTTP/1.1.
fn request_head(method: &str, target: &str, headers: &HeaderMap, websocket: bool, length: usize) -> Vec<u8> {
    let mut head = format!("{method} {target} HTTP/1.{}\r\n", u8::from(websocket)).into_bytes();
    for (name, value) in headers {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if !websocket {
        head.extend_from_slice(format!("content-length: {length}\r\nconnection: close\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// Reads the status line and headers; returns what was read past them too.
async fn read_head(stream: &mut Box<dyn Io>) -> std::io::Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(4096);
    let head = http::read_head(stream, &mut buffer, MAX_HEAD).await?;
    let status = StatusCode::from_u16(head.status).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad status"))?;
    let mut headers = HeaderMap::new();
    for (name, value) in &head.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            headers.append(name, value);
        }
    }
    Ok((status, headers, buffer.split_off(head.length)))
}

/// A plugin's answer body, streamed from its connection.
struct Upstream {
    stream: Box<dyn Io>,
    first: Option<Bytes>,
    /// Bytes still to come, if the answer said how many.
    left: Option<u64>,
    buffer: Box<[u8]>,
}

impl Upstream {
    fn new(stream: Box<dyn Io>, leftover: Vec<u8>, length: Option<u64>) -> Self {
        Self { stream, first: Some(Bytes::from(leftover)), left: length, buffer: vec![0; 16 * 1024].into_boxed_slice() }
    }

    fn take(&mut self, mut data: Bytes) -> Bytes {
        if let Some(left) = &mut self.left {
            data.truncate((*left).min(data.len() as u64) as usize);
            *left -= data.len() as u64;
        }
        data
    }
}

impl http_body::Body for Upstream {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
        use std::task::Poll;
        let this = &mut *self;
        if let Some(first) = this.first.take() {
            let first = this.take(first);
            if !first.is_empty() {
                return Poll::Ready(Some(Ok(http_body::Frame::data(first))));
            }
        }
        if this.left == Some(0) {
            return Poll::Ready(None);
        }
        let mut read = tokio::io::ReadBuf::new(&mut this.buffer);
        match std::pin::Pin::new(&mut this.stream).poll_read(cx, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                if this.left.is_some_and(|left| left > 0) {
                    Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the plugin closed early"))))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Ok(())) => {
                let data = Bytes::copy_from_slice(read.filled());
                let data = this.take(data);
                Poll::Ready(Some(Ok(http_body::Frame::data(data))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.left == Some(0)
    }
}

fn is_websocket(headers: &HeaderMap) -> bool {
    headers.get(header::UPGRADE).and_then(|value| value.to_str().ok()).is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// The request's headers as the plugin gets them: without the hub's credentials.
pub fn outgoing_headers(incoming: &HeaderMap, prefix: &str, websocket: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in incoming {
        if !DROP_REQUEST.contains(&name.as_str()) {
            headers.append(name.clone(), value.clone());
        }
    }
    headers.insert(header::HOST, HeaderValue::from_static("localhost"));
    if let Ok(prefix) = HeaderValue::from_str(prefix) {
        headers.insert(HeaderName::from_static("x-forwarded-prefix"), prefix);
    }
    headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    if websocket {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    }
    headers
}

/// The plugin's answer headers as the browser gets them: [`KEEP_RESPONSE`] (and the
/// handshake's on a WebSocket), and `Location` only if it stays within `prefix`.
pub fn response_headers(answer: &HeaderMap, websocket: bool, prefix: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in answer {
        if KEEP_RESPONSE.contains(&name.as_str()) || (websocket && KEEP_UPGRADE.contains(&name.as_str())) {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Some(location) = answer.get(header::LOCATION)
        && location.to_str().is_ok_and(|location| within(location, prefix))
    {
        headers.insert(header::LOCATION, location.clone());
    }
    headers
}

/// Whether a `Location` stays within the page's prefix: a path under it, or a relative
/// reference that cannot climb out of it.
fn within(location: &str, prefix: &str) -> bool {
    if location.bytes().any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\') || location.to_ascii_lowercase().contains("%2e") {
        return false;
    }
    let path = &location[..location.find(['?', '#']).unwrap_or(location.len())];
    if path.split('/').any(|segment| segment == "..") {
        return false;
    }
    match path.strip_prefix(prefix) {
        Some(under) => under.starts_with('/'),
        // Relative: no scheme, not from the root or another host.
        None => !path.starts_with('/') && !path.split('/').next().unwrap_or_default().contains(':'),
    }
}

/// Connects to a page socket served by `uid`.
async fn connect(socket: &Path, uid: u32) -> std::io::Result<Box<dyn Io>> {
    Ok(Box::new(http::connect_unix_as(socket, uid, CONNECT_TIMEOUT).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_uid() -> u32 {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }
    }

    fn socket_path(name: &str) -> std::path::PathBuf {
        // Short: a socket path is at most 104 bytes on macOS.
        let dir = std::path::Path::new("/tmp").join(format!("khx-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("page.sock")
    }

    #[test]
    fn the_hubs_credentials_never_reach_a_plugin() {
        let mut incoming = HeaderMap::new();
        incoming.insert(header::COOKIE, HeaderValue::from_static("__Host-kaonic_session=secret"));
        incoming.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        incoming.insert(crate::auth::CSRF_HEADER, HeaderValue::from_static("secret"));
        incoming.insert(header::HOST, HeaderValue::from_static("192.168.10.1"));
        incoming.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        incoming.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        let out = outgoing_headers(&incoming, "/apps/kaonic-sample", false);
        assert!(out.get(header::COOKIE).is_none() && out.get(header::AUTHORIZATION).is_none());
        assert!(out.get(crate::auth::CSRF_HEADER).is_none() && out.get("x-forwarded-for").is_none());
        assert!(!out.values().any(|value| value.as_bytes().windows(6).any(|window| window == b"secret")));
        assert_eq!(out.get(header::HOST).unwrap(), "localhost");
        assert_eq!(out.get(header::ACCEPT).unwrap(), "text/html");
        assert_eq!(out.get("x-forwarded-prefix").unwrap(), "/apps/kaonic-sample");
    }

    /// Only what a page needs comes through; anything that would reach past the page (the
    /// origin's reports, service workers, other hosts, redirects out of the prefix) does not.
    #[test]
    fn only_allowed_answer_headers_come_through() {
        let mut answer = HeaderMap::new();
        for (name, value) in [
            ("set-cookie", "__Host-kaonic_session=evil; Path=/"),
            ("content-type", "text/html"),
            ("content-security-policy", "default-src 'self'"),
            ("etag", "\"1\""),
            ("access-control-allow-origin", "*"),
            ("nel", "{\"report_to\":\"x\"}"),
            ("report-to", "{\"group\":\"x\"}"),
            ("reporting-endpoints", "x=\"https://collector.example/r\""),
            ("alt-svc", "h2=\"evil.example:443\""),
            ("refresh", "0; url=https://evil.example/"),
            ("service-worker-allowed", "/"),
            ("strict-transport-security", "max-age=0"),
            ("sec-websocket-accept", "abc"),
            ("x-anything", "1"),
        ] {
            answer.append(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        let headers = response_headers(&answer, false, "/apps/p/~t");
        let names: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["content-type", "content-security-policy", "etag"]);
        assert!(response_headers(&answer, true, "/apps/p/~t").get("sec-websocket-accept").is_some());

        let prefix = "/apps/p/~t";
        for kept in ["/apps/p/~t/next", "/apps/p/~t/a/b?x=1#y", "next.html", "sub/page?return=1", "?page=2"] {
            assert!(within(kept, prefix), "{kept}");
        }
        for dropped in [
            "/apps/p/~t",
            "/apps/p/~tx/next",
            "/apps/other/~t/",
            "/api/v1/auth/logout",
            "https://evil.example/",
            "//evil.example/",
            "javascript:alert(1)",
            "../../../api/v1/",
            "/apps/p/~t/../../x",
            "/apps/p/~t/%2e%2e/%2E%2E/x",
            "a\\b",
        ] {
            assert!(!within(dropped, prefix), "{dropped}");
        }
        let mut redirect = HeaderMap::new();
        redirect.insert(header::LOCATION, HeaderValue::from_static("https://evil.example/"));
        assert!(response_headers(&redirect, false, prefix).get(header::LOCATION).is_none());
        redirect.insert(header::LOCATION, HeaderValue::from_static("/apps/p/~t/in"));
        assert_eq!(response_headers(&redirect, false, prefix).get(header::LOCATION).unwrap(), "/apps/p/~t/in");
    }

    #[test]
    fn websockets_keep_their_upgrade() {
        let mut incoming = HeaderMap::new();
        incoming.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        incoming.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        incoming.insert("sec-websocket-key", HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(is_websocket(&incoming));
        let out = outgoing_headers(&incoming, "/apps/x", true);
        assert_eq!(out.get(header::UPGRADE).unwrap(), "websocket");
        assert_eq!(out.get("sec-websocket-key").unwrap(), "dGhlIHNhbXBsZSBub25jZQ==");
    }

    #[test]
    fn paths_are_split_as_sent() {
        assert_eq!(split_path("/apps/echo/~t/files/%2e%2e%2fadmin%3Fas=root"), Some(("echo", "~t/files/%2e%2e%2fadmin%3Fas=root")));
        assert_eq!(split_path("/apps/echo/"), Some(("echo", "")));
        assert_eq!(split_path("/apps/%65cho/x"), None, "an encoded id is no plugin");
        assert_eq!(split_path("/apps/echo"), None);
        assert_eq!(bare("/apps/echo").status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(bare("/apps/%2F%2Fevil").status(), StatusCode::NOT_FOUND);
    }

    /// A plugin answering with a length, and one that closes to end its answer.
    #[tokio::test]
    async fn passes_answers_through_by_length_and_by_close() {
        for (index, (answer, expected)) in [
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: a=b\r\n\r\nhelloEXTRA"[..], &b"hello"[..]),
            (&b"HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\nno such page, closed at the end"[..], &b"no such page, closed at the end"[..]),
        ]
        .into_iter()
        .enumerate()
        {
            let path = socket_path(&format!("answers-{index}"));
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let read = stream.read(&mut request).await.unwrap();
                stream.write_all(answer).await.unwrap();
                String::from_utf8_lossy(&request[..read]).into_owned()
            });
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, HeaderValue::from_static("__Host-kaonic_session=secret"));
            let head = request_head("POST", "/api/x?y=1", &outgoing_headers(&headers, "/apps/p", false), false, 3);
            let mut stream = connect(&path, own_uid()).await.unwrap();
            stream.write_all(&head).await.unwrap();
            Outgoing::Stream(Body::from("abc")).send(&mut stream, 3).await.unwrap();
            let (status, headers, leftover) = read_head(&mut stream).await.unwrap();
            let length = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.parse().ok());
            assert!(response_headers(&headers, false, "/apps/p").get(header::SET_COOKIE).is_none());
            let body = axum::body::to_bytes(Body::new(Upstream::new(stream, leftover, length)), 1 << 20).await.unwrap();
            assert_eq!(&body[..], expected, "{status}");
            let request = server.await.unwrap();
            assert!(request.starts_with("POST /api/x?y=1 HTTP/1.0\r\n"), "{request}");
            assert!(request.contains("content-length: 3\r\nconnection: close\r\n\r\n") && !request.contains("secret"), "{request}");
        }
    }

    /// Another user's socket at the plugin's path is never sent anything.
    #[tokio::test]
    async fn a_page_socket_must_be_the_plugins_own() {
        let path = socket_path("owner");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let heard = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink).await;
            sink
        });
        let error = connect(&path, own_uid().wrapping_add(1)).await.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(heard.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_body_must_be_as_long_as_it_says() {
        let path = socket_path("length");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let mut sink = Vec::new();
                let _ = stream.read_to_end(&mut sink).await;
            }
        });
        let mut stream = connect(&path, own_uid()).await.unwrap();
        assert!(Outgoing::Stream(Body::from("abcd")).send(&mut stream, 3).await.is_err());
        let mut stream = connect(&path, own_uid()).await.unwrap();
        assert!(Outgoing::Stream(Body::from("ab")).send(&mut stream, 3).await.is_err());
    }

    #[tokio::test]
    async fn an_idle_websocket_is_closed() {
        let (client, _client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);
        let started = std::time::Instant::now();
        relay(client, upstream, Duration::from_millis(50), Duration::from_secs(30), || async { true }).await;
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// Signed out or out of time, a busy socket is closed at the next check.
    #[tokio::test]
    async fn a_websocket_ends_with_its_ticket() {
        let (client, mut client_far) = tokio::io::duplex(64);
        let (upstream, _upstream_far) = tokio::io::duplex(64);
        let busy = tokio::spawn(async move {
            while client_far.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let started = std::time::Instant::now();
        relay(client, upstream, Duration::from_secs(30), Duration::from_millis(50), || async { false }).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        busy.abort();
    }
}
