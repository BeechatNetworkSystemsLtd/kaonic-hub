//! An emulated radio channel for kaonic-hub nodes without boards: each node's
//! radio is a UDP socket (`air://HOST:PORT/NAME` in kaonic-mesh), and the air delivers
//! every frame a node sends to the nodes in range after its time on air, with
//! per-link loss and RSSI, collisions, half duplex and carrier sense
//! ([`medium`]).
//!
//! Datagrams from a node: `0x00 | frame` or `0x01 | name` (register, repeated now and
//! then). To a node: `rssi i8 | frame`.

pub mod medium;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

pub use medium::{Fate, LinkParams, Medium, MediumConfig, NodeStats, Transmission};

const FRAME: u8 = 0x00;
const HELLO: u8 = 0x01;
/// The largest frame accepted (the radio transceiver's).
const MAX_FRAME: usize = 2048;

/// A small, seedable generator for loss and backoff (xorshift64*). Not for anything secret.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct State {
    medium: Medium,
    rng: Rng,
    by_address: HashMap<SocketAddr, String>,
    by_name: HashMap<String, SocketAddr>,
}

/// A running air. Dropping it does not stop it; it lives as long as the runtime.
#[derive(Clone)]
pub struct Air {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl Air {
    /// Starts an air on `listen` (port 0 for any). Must run inside a tokio runtime.
    pub async fn start(listen: SocketAddr, config: MediumConfig, seed: u64) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(listen).await?);
        let address = socket.local_addr()?;
        let state = Arc::new(Mutex::new(State { medium: Medium::new(config), rng: Rng::new(seed), by_address: HashMap::new(), by_name: HashMap::new() }));
        let air = Self { address, state };
        tokio::spawn(air.clone().serve(socket));
        Ok(air)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().expect("air lock"))
    }

    pub fn set_link(&self, a: &str, b: &str, params: LinkParams) {
        self.with(|state| state.medium.set_link(a, b, params));
    }

    pub fn block(&self, a: &str, b: &str) {
        self.with(|state| state.medium.block(a, b));
    }

    pub fn unblock(&self, a: &str, b: &str) {
        self.with(|state| state.medium.unblock(a, b));
    }

    /// Counters per node, by name.
    pub fn stats(&self) -> Vec<(String, NodeStats)> {
        self.with(|state| state.medium.stats())
    }

    /// The nodes that have said hello.
    pub fn nodes(&self) -> Vec<String> {
        self.with(|state| {
            let mut names: Vec<String> = state.by_name.keys().cloned().collect();
            names.sort();
            names
        })
    }

    async fn serve(self, socket: Arc<UdpSocket>) {
        let origin = Instant::now();
        let mut buffer = vec![0u8; MAX_FRAME + 1];
        loop {
            let (length, from) = match socket.recv_from(&mut buffer).await {
                Ok(received) => received,
                // A node that went away (ICMP unreachable on some systems): keep serving the rest.
                Err(_) => continue,
            };
            let Some((&kind, body)) = buffer[..length].split_first() else { continue };
            match kind {
                HELLO => {
                    let Ok(name) = std::str::from_utf8(body) else { continue };
                    if name.is_empty() || name.len() > 64 {
                        continue;
                    }
                    self.with(|state| {
                        if let Some(old) = state.by_name.insert(name.to_owned(), from)
                            && old != from
                        {
                            state.by_address.remove(&old);
                        }
                        state.by_address.insert(from, name.to_owned());
                        state.medium.add_node(name);
                    });
                }
                FRAME if !body.is_empty() && body.len() <= MAX_FRAME => {
                    let now = origin.elapsed().as_micros() as u64;
                    let frame: Arc<[u8]> = Arc::from(body);
                    let deliveries = self.with(|state| {
                        let name = state.by_address.get(&from)?.clone();
                        let State { medium, rng, by_name, .. } = state;
                        match medium.transmit(&name, now, frame.len(), &mut || rng.next()) {
                            Transmission::Dropped => None,
                            Transmission::OnAir { receptions, .. } => Some(
                                receptions.into_iter().filter_map(|(id, to, end)| by_name.get(&to).map(|address| (id, *address, end))).collect::<Vec<_>>(),
                            ),
                        }
                    });
                    for (id, address, end) in deliveries.into_iter().flatten() {
                        let air = self.clone();
                        let socket = socket.clone();
                        let frame = frame.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep_until((origin + Duration::from_micros(end)).into()).await;
                            let Some((Fate::Received, rssi)) = air.with(|state| state.medium.finish(id)) else { return };
                            let mut datagram = Vec::with_capacity(frame.len() + 1);
                            datagram.push(rssi as u8);
                            datagram.extend_from_slice(&frame);
                            let _ = socket.send_to(&datagram, address).await;
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn node(air: SocketAddr, name: &str) -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(air).await.unwrap();
        let mut hello = vec![HELLO];
        hello.extend_from_slice(name.as_bytes());
        socket.send(&hello).await.unwrap();
        socket
    }

    #[tokio::test]
    async fn frames_travel_after_their_airtime_and_only_in_range() {
        let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 7).await.unwrap();
        air.set_link("a", "b", LinkParams { loss: 0.0, rssi: -71 });
        air.block("a", "c");
        let a = node(air.local_addr(), "a").await;
        let b = node(air.local_addr(), "b").await;
        let c = node(air.local_addr(), "c").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(air.nodes(), vec!["a", "b", "c"]);

        let sent = Instant::now();
        a.send(&[FRAME, 1, 2, 3]).await.unwrap();
        let mut buffer = [0u8; 16];
        let length = tokio::time::timeout(Duration::from_secs(1), b.recv(&mut buffer)).await.unwrap().unwrap();
        assert!(sent.elapsed() >= Duration::from_micros(1080));
        assert_eq!(&buffer[..length], &[(-71i8) as u8, 1, 2, 3]);
        assert!(tokio::time::timeout(Duration::from_millis(100), c.recv(&mut buffer)).await.is_err());
        let stats = air.stats();
        assert_eq!(stats.iter().find(|(name, _)| name == "a").unwrap().1.sent, 1);
        assert_eq!(stats.iter().find(|(name, _)| name == "b").unwrap().1.received, 1);
    }

    #[test]
    fn the_generator_is_uniform_enough() {
        let mut rng = Rng::new(42);
        let mean = (0..10_000).map(|_| rng.next()).sum::<f64>() / 10_000.0;
        assert!((mean - 0.5).abs() < 0.02, "{mean}");
    }
}
