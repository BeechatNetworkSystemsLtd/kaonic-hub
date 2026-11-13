//! Accepting connections: HTTPS for the app, and plain HTTP that only redirects.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::extract::ws::{Message, WebSocket};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::api::Peer;
use crate::app::App;
use crate::error::ApiError;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Headers must arrive promptly; a slow sender cannot hold a connection forever.
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
/// A request, body included, must be read and answered within this (an upload, longer):
/// a body sent one byte at a time cannot hold a connection.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// Connections held at once, in total and from one address. Every connection is a task and
/// a file descriptor; past the process limit nothing else in the hub can open a file.
const MAX_CONNECTIONS: usize = 256;
const MAX_PER_CLIENT: usize = 32;
/// After a failed accept (out of descriptors), wait instead of spinning on the one core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// A WebSocket frame must be taken by the client within this: a stalled reader is dropped.
pub const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Who may hold a connection: caps in total and per client address, and a refusal rule.
pub struct Gate {
    clients: Mutex<(usize, HashMap<IpAddr, usize>)>,
    refuse: Box<dyn Fn(IpAddr, IpAddr) -> bool + Send + Sync>,
}

/// A connection let in; it leaves the count when dropped.
pub struct Admission {
    gate: Arc<Gate>,
    client: IpAddr,
}

impl Drop for Admission {
    fn drop(&mut self) {
        let mut clients = self.gate.clients.lock().expect("gate lock");
        clients.0 = clients.0.saturating_sub(1);
        if let Some(count) = clients.1.get_mut(&self.client) {
            *count -= 1;
            if *count == 0 {
                clients.1.remove(&self.client);
            }
        }
    }
}

/// A connection's stream that holds its admission: an upgraded WebSocket keeps the stream,
/// so it stays counted until the socket closes, not only until the HTTP exchange ends.
pub struct Admitted<I, A = Admission> {
    io: I,
    _admission: A,
}

impl<I, A> Admitted<I, A> {
    pub fn new(io: I, admission: A) -> Self {
        Self { io, _admission: admission }
    }
}

impl<I: AsyncRead + Unpin, A: Unpin> AsyncRead for Admitted<I, A> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin, A: Unpin> AsyncWrite for Admitted<I, A> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// Sends one WebSocket message; false if the socket failed or the client did not take it
/// within [`WS_SEND_TIMEOUT`] (then the socket should be dropped).
pub async fn ws_send(socket: &mut WebSocket, message: Message) -> bool {
    send_within(socket, message, WS_SEND_TIMEOUT).await
}

async fn send_within(socket: &mut WebSocket, message: Message, limit: Duration) -> bool {
    matches!(tokio::time::timeout(limit, socket.send(message)).await, Ok(Ok(())))
}

impl Gate {
    /// `refuse(remote, local)`: connections not to answer at all.
    pub fn new(refuse: impl Fn(IpAddr, IpAddr) -> bool + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self { clients: Mutex::new((0, HashMap::new())), refuse: Box::new(refuse) })
    }

    /// Lets everyone in, within the caps.
    pub fn open() -> Arc<Self> {
        Self::new(|_, _| false)
    }

    pub fn admit(self: &Arc<Self>, remote: IpAddr, local: IpAddr) -> Option<Admission> {
        if (self.refuse)(remote, local) {
            return None;
        }
        let mut clients = self.clients.lock().expect("gate lock");
        let (total, per_client) = &mut *clients;
        let count = per_client.entry(remote).or_insert(0);
        if *total >= MAX_CONNECTIONS || *count >= MAX_PER_CLIENT {
            if *count == 0 {
                per_client.remove(&remote);
            }
            return None;
        }
        *count += 1;
        *total += 1;
        Some(Admission { gate: self.clone(), client: remote })
    }
}

/// Whether `address` is reached through the mesh VPN: the tunnel network, or a prefix another
/// node advertised. The API and the PTT audio port answer only the device's own networks.
pub fn via_tunnel(app: &App, address: IpAddr) -> bool {
    let IpAddr::V4(address) = address else { return false };
    let Some(config) = &app.vpn_config else { return false };
    if config.network.contains(address) {
        return true;
    }
    app.vpn.get().is_some_and(|vpn| vpn.status().installed.iter().any(|prefix| prefix.contains(address)))
}

/// The user at the other end of a Unix socket (`SO_PEERCRED` on Linux, `getpeereid`
/// elsewhere).
pub fn peer_uid(stream: &tokio::net::UnixStream) -> Option<u32> {
    kaonic_hub_common::peer_uid(stream).ok()
}

/// Ends a request that takes too long, reading its body included.
async fn deadline(request: Request, next: axum::middleware::Next) -> Response {
    let (method, path) = (request.method(), request.uri().path());
    let upload = (method == axum::http::Method::PUT && path.ends_with("/ptt/test/wav"))
        || (method == axum::http::Method::POST && path.ends_with("/system/boot/kernel/upload"))
        // A package: upload, unpack, install, and wait for it to start.
        || (method == axum::http::Method::POST && path.ends_with("/api/v1/plugins"))
        || (method == axum::http::Method::PUT && path.ends_with("/package"))
        || (method == axum::http::Method::POST
            && ["/api/v1/plugin-check", "/api/v1/software/hub", "/api/v1/software/installer"].iter().any(|upload| path.ends_with(upload)));
    let limit = if upload { UPLOAD_TIMEOUT } else { REQUEST_TIMEOUT };
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(StatusCode::REQUEST_TIMEOUT, "timeout", "The request took too long.").into_response(),
    }
}

/// `router` with the request deadline, for connections without a client address.
pub fn with_deadline(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(deadline))
}

fn per_connection(router: &Router, remote: SocketAddr, local: SocketAddr) -> Router {
    router
        .clone()
        .layer(axum::Extension(Peer { remote, local }))
        .layer(axum::middleware::from_fn(deadline))
}

/// The next connection the gate lets in.
async fn next_connection(listener: &TcpListener, gate: &Arc<Gate>) -> (Admitted<tokio::net::TcpStream>, SocketAddr, SocketAddr) {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                log::debug!("accept: {error}");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Ok(local) = stream.local_addr() else {
            continue;
        };
        // Dropping the stream closes it: no task, no handshake.
        if let Some(admission) = gate.admit(remote.ip(), local.ip()) {
            return (Admitted::new(stream, admission), remote, local);
        }
    }
}

/// HTTP/1.1 on one connection, with the header timeout; WebSockets may upgrade it.
pub async fn serve_connection<I>(io: I, router: Router)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(router);
    let connection = http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades();
    if let Err(error) = connection.await {
        log::debug!("connection: {error}");
    }
}

/// Serves `router` over TLS on `listener` until the process ends.
pub async fn https(listener: TcpListener, router: Router, tls: Arc<rustls::ServerConfig>, gate: Arc<Gate>) {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (stream, remote, local) = next_connection(&listener, &gate).await;
        let acceptor = acceptor.clone();
        let router = per_connection(&router, remote, local);
        tokio::spawn(async move {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => serve_connection(tls, router).await,
                _ => log::debug!("TLS handshake with {remote} failed"),
            }
        });
    }
}

/// Serves `router` over plain HTTP. Development only.
pub async fn http(listener: TcpListener, router: Router, gate: Arc<Gate>) {
    loop {
        let (stream, remote, local) = next_connection(&listener, &gate).await;
        let router = per_connection(&router, remote, local);
        tokio::spawn(serve_connection(stream, router));
    }
}

/// Port 80: every request is sent to the same path over HTTPS.
pub fn redirect_router() -> Router {
    Router::new().fallback(|request: Request| async move {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("192.168.10.1");
        // Only a plain host name or address: never let a header steer the redirect elsewhere.
        let host = host.split(':').next().unwrap_or_default();
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str());
        let response: Response =
            Redirect::permanent(&format!("https://{host}{path}")).into_response();
        response
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_caps_each_client_and_the_total_and_refuses_what_it_is_told() {
        let refused: IpAddr = "10.77.1.2".parse().unwrap();
        let gate = Gate::new(move |remote, _| remote == refused);
        let local: IpAddr = "192.168.10.1".parse().unwrap();
        assert!(gate.admit(refused, local).is_none());
        let client: IpAddr = "192.168.10.20".parse().unwrap();
        let held: Vec<Admission> = (0..MAX_PER_CLIENT).map(|_| gate.admit(client, local).unwrap()).collect();
        assert!(gate.admit(client, local).is_none(), "one address may hold only so many");
        assert!(gate.admit("192.168.10.21".parse().unwrap(), local).is_some(), "others still get in");
        drop(held);
        assert!(gate.admit(client, local).is_some(), "closed connections leave the count");
        let mut many = Vec::new();
        for index in 0..MAX_CONNECTIONS + 10 {
            if let Some(admission) = gate.admit(IpAddr::from([10, 0, (index / 250) as u8, (index % 250) as u8]), local) {
                many.push(admission);
            }
        }
        assert_eq!(many.len(), MAX_CONNECTIONS, "the total is capped");
        drop(many);
        assert_eq!(gate.clients.lock().unwrap().0, 0);
        assert!(gate.clients.lock().unwrap().1.is_empty());
    }

    fn held(gate: &Gate) -> usize {
        gate.clients.lock().unwrap().0
    }

    /// Serves `router` on one admitted in-memory connection and upgrades `/ws`; returns the client end.
    async fn upgraded(gate: &Arc<Gate>, router: Router) -> tokio::io::DuplexStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let local: IpAddr = "192.168.10.1".parse().unwrap();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let admission = gate.admit("192.168.10.20".parse().unwrap(), local).unwrap();
        let connection = tokio::spawn(serve_connection(Admitted::new(server, admission), router));
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: hub\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
        // The HTTP side is over once the socket is upgraded.
        tokio::time::timeout(Duration::from_secs(5), connection).await.unwrap().unwrap();
        client
    }

    #[tokio::test]
    async fn an_upgraded_socket_stays_counted_until_it_closes() {
        let gate = Gate::open();
        let router = Router::new().route(
            "/ws",
            axum::routing::get(|upgrade: axum::extract::WebSocketUpgrade| async move {
                upgrade.on_upgrade(|mut socket| async move { while let Some(Ok(_)) = socket.recv().await {} })
            }),
        );
        let client = upgraded(&gate, router).await;
        assert_eq!(held(&gate), 1, "the open socket still holds its admission");
        drop(client);
        for _ in 0..200 {
            if held(&gate) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("a closed socket must leave the count");
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_fails_the_send() {
        let gate = Gate::open();
        let (stalled, mut told) = tokio::sync::mpsc::channel(1);
        let router = Router::new().route(
            "/ws",
            axum::routing::get(move |upgrade: axum::extract::WebSocketUpgrade| async move {
                upgrade.on_upgrade(move |mut socket| async move {
                    for _ in 0..1000 {
                        if !send_within(&mut socket, Message::Binary(vec![0; 8192].into()), Duration::from_millis(200)).await {
                            let _ = stalled.send(()).await;
                            return;
                        }
                    }
                })
            }),
        );
        // The client never reads past the upgrade.
        let _client = upgraded(&gate, router).await;
        tokio::time::timeout(Duration::from_secs(5), told.recv()).await.expect("the send gave up").unwrap();
        for _ in 0..200 {
            if held(&gate) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the dropped socket must leave the count");
    }
}

