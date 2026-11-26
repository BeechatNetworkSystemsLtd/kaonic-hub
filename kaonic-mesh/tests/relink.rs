//! Secure links come back after the radio loses them, without restarting a hub: radio
//! outages on one side and on both, one-way loss, flapping, hub restarts (same identity),
//! relays that go away, both ends relinking at once and many peers at once. Each test
//! asserts that mux traffic (a request and its response) flows again within a bound, on
//! the emulated channel (`kaonic-sim-air`) with the timers the hub runs in the field.
//!
//! `KAONIC_TEST_LOG=debug` shows what the links do. The 2- and 10-minute outages are
//! `#[ignore]`d (they run for minutes): `cargo test -p kaonic-mesh --test relink -- --ignored`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use kaonic_handshake::Credentials;
use kaonic_mesh::announce::NodeInfo;
use kaonic_mesh::links::{Auth, Links};
use kaonic_mesh::{Mesh, MeshConfig};
use kaonic_pki::{CertRequest, Certificate, Identity};
use kaonic_sim_air::{Air, MediumConfig};
use kaonic_trust::{Allowlist, Trust};
use reticulum::identity::PrivateIdentity;
use x25519_dalek::{PublicKey, StaticSecret};

const ISSUED_AT: u64 = 1_792_000_000;
/// The hub's announce interval in the field, and its offline time (four intervals).
const ANNOUNCE_SECS: u64 = 120;
const OFFLINE_SECS: u64 = ANNOUNCE_SECS * 4;
/// After the radio is back (or a restarted hub is up), traffic flows again within this.
const RECOVER_WITHIN: Duration = Duration::from_secs(10);
/// After an outage longer than the offline time (8 min without an announce), the peer is
/// tried only about every 30 s (to keep the channel free): traffic flows again within this.
const RECOVER_WITHIN_OFFLINE: Duration = Duration::from_secs(40);
/// How long a test waits before it gives up measuring.
const GIVE_UP: Duration = Duration::from_secs(300);

/// `KAONIC_TEST_LOG=debug` shows what the links do.
struct Logger(log::LevelFilter);

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.0
    }
    fn log(&self, record: &log::Record) {
        let ours = record.target().starts_with("kaonic_mesh") || (RETICULUM_LOG.get().copied().unwrap_or(false) && record.target().starts_with("reticulum"));
        if self.enabled(record.metadata()) && (ours || record.level() <= log::Level::Warn) {
            eprintln!("{:?} {:<5} {} {}", std::time::Instant::now(), record.level(), record.target(), record.args());
        }
    }
    fn flush(&self) {}
}

/// `KAONIC_TEST_LOG_RETICULUM=1` adds Reticulum's own lines.
static RETICULUM_LOG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn init_log() {
    let _ = RETICULUM_LOG.set(std::env::var_os("KAONIC_TEST_LOG_RETICULUM").is_some());
    if let Ok(level) = std::env::var("KAONIC_TEST_LOG")
        && let Ok(filter) = level.parse()
    {
        let _ = log::set_logger(Box::leak(Box::new(Logger(filter))));
        log::set_max_level(filter);
    }
}

struct Keys {
    x25519: StaticSecret,
    ed25519: SigningKey,
}

impl Keys {
    fn new(seed: u8) -> Self {
        Self { x25519: StaticSecret::from([seed.wrapping_add(100); 32]), ed25519: SigningKey::from_bytes(&[seed; 32]) }
    }

    fn identity(&self) -> Identity {
        Identity { x25519: PublicKey::from(&self.x25519).to_bytes(), ed25519: self.ed25519.verifying_key().to_bytes() }
    }
}

/// An admin (not on the air) and the nodes it certified, all on its allowlist.
struct Network {
    air: Air,
    admin: Keys,
    root: Certificate,
    nodes: Vec<Keys>,
}

impl Network {
    async fn new(seed: u64, nodes: usize) -> Self {
        init_log();
        let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), seed).await.unwrap();
        let admin = Keys::new(1);
        let root = Certificate::new_root(&admin.identity(), &admin.ed25519, ISSUED_AT).unwrap();
        Self { air, admin, root, nodes: (0..nodes).map(|n| Keys::new(10 + n as u8)).collect() }
    }

    fn auth(&self, keys: &Keys) -> Auth {
        let identity = keys.identity();
        let request = CertRequest::create(&identity, &keys.ed25519, b"link").unwrap();
        let cert = self.root.issue(&self.admin.ed25519, &request, &identity, ISSUED_AT).unwrap();
        let allowlist = Allowlist::sign(&self.admin.ed25519, 1, self.nodes.iter().map(|keys| keys.identity().hash())).unwrap();
        let trust = Trust::from_der(self.root.der(), cert.der(), allowlist.as_bytes()).unwrap();
        Auth { credentials: Credentials { identity, key: keys.ed25519.clone(), cert }, trust }
    }

    /// Starts (or restarts, with the same identity) node `n`, called `name` on the air.
    async fn start(&self, n: usize, name: &str) -> Node {
        let keys = &self.nodes[n];
        let info = NodeInfo { codename: name.to_owned(), version: "test".into(), is_admin: false, admin_id: Some(self.admin.identity().hash().0) };
        let config = MeshConfig { radio: format!("air://{}/{name}", self.air.local_addr()), announce_secs: ANNOUNCE_SECS, offline_secs: OFFLINE_SECS, settings: None, ..MeshConfig::default() };
        let identity = PrivateIdentity::new(keys.x25519.clone(), keys.ed25519.clone());
        let mesh = Mesh::start(identity, info, config).await.expect("mesh starts");
        let links = Links::start(mesh.clone(), Some(self.auth(keys)), Box::new(|_| {})).await;
        echo(&links);
        Node { name: name.to_owned(), id: keys.identity().hash().to_hex(), mesh, links }
    }

    /// The radios of `a` and `b` stop hearing each other (both ways).
    fn cut(&self, a: &Node, b: &Node) {
        self.air.block(&a.name, &b.name);
    }

    fn mend(&self, a: &Node, b: &Node) {
        self.air.unblock(&a.name, &b.name);
    }

    /// Frames sent on the air so far, by every node.
    fn frames_sent(&self) -> u64 {
        self.air.stats().iter().map(|(_, stats)| stats.sent).sum()
    }
}

struct Node {
    name: String,
    id: String,
    mesh: Arc<Mesh>,
    links: Arc<Links>,
}

impl Node {
    /// Ends this node's process: it neither sends nor hears any more.
    async fn kill(&self) {
        self.mesh.stop().await;
    }
}

const PING: u8 = b'P';
const PONG: u8 = b'Q';

/// Answers every ping with a pong carrying the same nonce.
fn echo(links: &Arc<Links>) {
    let mut received = links.subscribe();
    let links = links.clone();
    tokio::spawn(async move {
        loop {
            match received.recv().await {
                Ok(message) if message.packet.get(1) == Some(&PING) => {
                    let mut pong = message.packet.as_slice().to_vec();
                    pong[1] = PONG;
                    links.send(&message.peer, &pong).await;
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
}

/// Sends pings from `from` to `to` until a pong comes back; how long that took, or None by `give_up`.
async fn ping(from: &Node, to: &Node, give_up: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut received = from.links.subscribe();
    let mut nonce: u64 = rand_nonce();
    while start.elapsed() < give_up {
        nonce = nonce.wrapping_add(1);
        let mut packet = vec![kaonic_mux::MUX, PING];
        packet.extend_from_slice(&nonce.to_be_bytes());
        if !from.links.send(&to.id, &packet).await {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        let wait = tokio::time::Instant::now() + Duration::from_millis(1500);
        loop {
            match tokio::time::timeout_at(wait, received.recv()).await {
                Ok(Ok(message)) if message.peer == to.id && message.packet.get(1) == Some(&PONG) && message.packet[2..] == nonce.to_be_bytes() => {
                    return Some(start.elapsed());
                }
                Ok(Ok(_)) | Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
    }
    None
}

fn rand_nonce() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

/// Waits until every pair of `nodes` exchanges a ping, so tests start from a linked network.
async fn all_linked(nodes: &[&Node]) {
    for (i, a) in nodes.iter().enumerate() {
        for b in &nodes[i + 1..] {
            let took = ping(a, b, Duration::from_secs(120)).await;
            assert!(took.is_some(), "{} and {} never linked: {:?}", a.name, b.name, a.links.view().await);
        }
    }
}

/// After the radio came back: measures until traffic flows, reports it, and checks the bound.
async fn recovers(what: &str, from: &Node, to: &Node, within: Duration) -> Duration {
    let took = ping(from, to, GIVE_UP).await;
    eprintln!("RECOVERY {what}: {}", took.map_or("never (gave up)".to_owned(), |took| format!("{:.1} s", took.as_secs_f64())));
    let Some(took) = took else {
        panic!("{what}: no traffic {} s after recovery; {}: {:?}", GIVE_UP.as_secs(), from.name, from.links.view().await);
    };
    assert!(took <= within, "{what}: traffic flowed again only after {:.1} s (bound {} s)", took.as_secs_f64(), within.as_secs());
    took
}

/// Two nodes lose each other for `outage`, then hear each other again.
async fn outage_both_ways(seed: u64, outage: Duration, within: Duration) {
    let net = Network::new(seed, 2).await;
    let a = net.start(0, "a").await;
    let b = net.start(1, "b").await;
    all_linked(&[&a, &b]).await;
    net.cut(&a, &b);
    tokio::time::sleep(outage).await;
    net.mend(&a, &b);
    let what = format!("{} s outage, both ways", outage.as_secs());
    recovers(&what, &a, &b, within).await;
    recovers(&format!("{what} (other direction)"), &b, &a, RECOVER_WITHIN).await;
}

#[tokio::test]
async fn a_5_second_outage_does_not_stop_traffic_for_long() {
    outage_both_ways(101, Duration::from_secs(5), RECOVER_WITHIN).await;
}

#[tokio::test]
async fn a_30_second_outage_recovers_within_seconds() {
    outage_both_ways(102, Duration::from_secs(30), RECOVER_WITHIN).await;
}

#[tokio::test]
#[ignore = "runs for minutes"]
async fn a_2_minute_outage_recovers_within_seconds() {
    outage_both_ways(103, Duration::from_secs(120), RECOVER_WITHIN).await;
}

#[tokio::test]
#[ignore = "runs for minutes"]
async fn a_10_minute_outage_recovers_within_seconds() {
    outage_both_ways(104, Duration::from_secs(600), RECOVER_WITHIN_OFFLINE).await;
}

/// One node's radio goes quiet (it hears nobody, nobody hears it) while the others carry on.
#[tokio::test]
async fn one_radio_off_for_30_seconds_recovers_with_every_peer() {
    let net = Network::new(105, 3).await;
    let a = net.start(0, "a").await;
    let b = net.start(1, "b").await;
    let c = net.start(2, "c").await;
    all_linked(&[&a, &b, &c]).await;
    net.cut(&c, &a);
    net.cut(&c, &b);
    tokio::time::sleep(Duration::from_secs(30)).await;
    net.mend(&c, &a);
    net.mend(&c, &b);
    recovers("c's radio off 30 s: a to c", &a, &c, RECOVER_WITHIN).await;
    recovers("c's radio off 30 s: b to c", &b, &c, RECOVER_WITHIN).await;
    assert!(ping(&a, &b, Duration::from_secs(5)).await.is_some(), "a and b kept their link");
}

/// a hears b, b does not hear a, for 30 s.
#[tokio::test]
async fn one_way_loss_recovers() {
    let net = Network::new(106, 2).await;
    let a = net.start(0, "a").await;
    let b = net.start(1, "b").await;
    all_linked(&[&a, &b]).await;
    net.air.block_one_way("a", "b");
    tokio::time::sleep(Duration::from_secs(30)).await;
    net.air.unblock_one_way("a", "b");
    recovers("one-way loss a to b, 30 s", &a, &b, RECOVER_WITHIN).await;
    recovers("one-way loss a to b, 30 s (other direction)", &b, &a, RECOVER_WITHIN).await;
}

/// The radio between a and b flaps (3 s off, 3 s on) for a minute, then stays on. Relinking
/// must not flood the channel meanwhile.
#[tokio::test]
async fn flapping_recovers_without_a_relink_storm() {
    let net = Network::new(107, 2).await;
    let a = net.start(0, "a").await;
    let b = net.start(1, "b").await;
    all_linked(&[&a, &b]).await;
    let before = net.frames_sent();
    for _ in 0..10 {
        net.cut(&a, &b);
        tokio::time::sleep(Duration::from_secs(3)).await;
        net.mend(&a, &b);
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let frames = net.frames_sent() - before;
    eprintln!("FLAPPING: {frames} frames in 60 s");
    recovers("after a minute of flapping", &a, &b, RECOVER_WITHIN).await;
    // Two nodes, one link: keepalives, announces and a few relinks are well below one frame a
    // second; a storm of link requests and AUTHs is far above.
    assert!(frames < 120, "{frames} frames in a minute of flapping");
}

/// A hub restarts (a new process with the same identity), the opener or the responder.
async fn restart(seed: u64, restart_opener: bool) {
    let net = Network::new(seed, 2).await;
    let a = net.start(0, "a").await;
    let b = net.start(1, "b").await;
    all_linked(&[&a, &b]).await;
    // The lower identity hash opens the link.
    let a_opens = a.id < b.id;
    let (stays, restarting, index, name) = if a_opens == restart_opener { (&b, &a, 0, "a") } else { (&a, &b, 1, "b") };
    restarting.kill().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let restarted = net.start(index, name).await;
    let what = format!("restart of the {}", if restart_opener { "opener" } else { "responder" });
    recovers(&what, stays, &restarted, RECOVER_WITHIN).await;
    recovers(&format!("{what} (other direction)"), &restarted, stays, RECOVER_WITHIN).await;
}

#[tokio::test]
async fn a_restarted_responder_is_linked_again_within_seconds() {
    restart(108, false).await;
}

#[tokio::test]
async fn a_restarted_opener_links_again_within_seconds() {
    restart(109, true).await;
}

/// Both ends restart at the same time: both are new, both may open.
#[tokio::test]
async fn both_ends_restarting_at_once_link_again() {
    let net = Network::new(110, 2).await;
    let a = net.start(0, "a").await;
    let b = net.start(1, "b").await;
    all_linked(&[&a, &b]).await;
    a.kill().await;
    b.kill().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (a, b) = tokio::join!(net.start(0, "a"), net.start(1, "b"));
    recovers("both ends restarted", &a, &b, RECOVER_WITHIN).await;
    recovers("both ends restarted (other direction)", &b, &a, RECOVER_WITHIN).await;
}

/// a reaches c only through the relay r. c reboots and is away for 30 s: everything it knew
/// about paths is gone when it is back.
#[tokio::test]
async fn a_peer_rebooting_behind_a_relay_is_linked_again() {
    let net = Network::new(111, 3).await;
    net.air.block("a", "c");
    let a = net.start(0, "a").await;
    let r = net.start(1, "r").await;
    let c = net.start(2, "c").await;
    all_linked(&[&a, &r, &c]).await;
    c.kill().await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let c = net.start(2, "c").await;
    recovers("c rebooted behind a relay", &a, &c, RECOVER_WITHIN).await;
    recovers("c rebooted behind a relay (other direction)", &c, &a, RECOVER_WITHIN).await;
    drop(r);
}

/// The only relay between a and c goes out of range of both for 30 s and comes back.
#[tokio::test]
async fn a_relay_that_comes_back_carries_the_link_again() {
    let net = Network::new(112, 3).await;
    net.air.block("a", "c");
    let a = net.start(0, "a").await;
    let r = net.start(1, "r").await;
    let c = net.start(2, "c").await;
    all_linked(&[&a, &r, &c]).await;
    net.cut(&r, &a);
    net.cut(&r, &c);
    tokio::time::sleep(Duration::from_secs(30)).await;
    net.mend(&r, &a);
    net.mend(&r, &c);
    recovers("the relay came back", &a, &c, RECOVER_WITHIN).await;
    recovers("the relay came back (other direction)", &c, &a, RECOVER_WITHIN).await;
}

/// a reaches c through r1 or r2 (which do not hear each other). A relay goes away for good:
/// a link it carried moves to the other relay. Each relay goes in turn (the first comes back
/// as a new process), so one of the two rounds takes the relay the link is on.
#[tokio::test]
async fn a_link_moves_to_another_relay_when_its_relay_goes() {
    let net = Network::new(113, 4).await;
    net.air.block("a", "c");
    net.air.block("r1", "r2");
    let a = net.start(0, "a").await;
    let r1 = net.start(1, "r1").await;
    let r2 = net.start(2, "r2").await;
    let c = net.start(3, "c").await;
    all_linked(&[&a, &c]).await;
    // Path switches take the link's death (20 s) and a new path: within 40 s of the relay going.
    let within = Duration::from_secs(40);
    r1.kill().await;
    let took = recovers("r1 went for good, r2 remains", &a, &c, within).await;
    eprintln!("RECOVERY relay switch (r1 gone): {:.1} s after the relay went", took.as_secs_f64());
    let r1 = net.start(1, "r1").await;
    all_linked(&[&a, &c]).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    r2.kill().await;
    let took = recovers("r2 went for good, r1 remains", &a, &c, within).await;
    eprintln!("RECOVERY relay switch (r2 gone): {:.1} s after the relay went", took.as_secs_f64());
    recovers("r2 went for good (other direction)", &c, &a, RECOVER_WITHIN).await;
    drop(r1);
}

/// Six nodes in range of each other; one is cut off for 30 s and comes back: every link to it
/// recovers, and relinking all of them does not flood the channel.
#[tokio::test]
async fn many_peers_relink_to_a_node_that_comes_back() {
    let net = Network::new(114, 6).await;
    let mut nodes = Vec::new();
    for n in 0..6 {
        nodes.push(net.start(n, &format!("n{n}")).await);
    }
    let refs: Vec<&Node> = nodes.iter().collect();
    all_linked(&refs).await;
    let (away, rest) = refs.split_last().unwrap();
    for node in rest {
        net.cut(away, node);
    }
    let before = net.frames_sent();
    tokio::time::sleep(Duration::from_secs(30)).await;
    let during = net.frames_sent() - before;
    eprintln!("air during the outage: {:?}", net.air.stats());
    for node in rest {
        net.mend(away, node);
    }
    let back = Instant::now();
    let results = futures_join(rest.iter().map(|node| ping(node, away, GIVE_UP))).await;
    for (node, took) in rest.iter().zip(&results) {
        eprintln!("RECOVERY many peers: {} to {}: {:?}", node.name, away.name, took);
    }
    let slowest = results.iter().map(|took| took.expect("every peer relinks")).max().unwrap();
    eprintln!("RECOVERY many peers: all {} links in {:.1} s; {during} frames sent during the 30 s outage", rest.len(), slowest.as_secs_f64());
    assert!(slowest <= RECOVER_WITHIN + Duration::from_secs(5), "the last link came back after {:.1} s", slowest.as_secs_f64());
    assert!(back.elapsed() < GIVE_UP);
}

/// Runs the futures together (no futures crate here).
async fn futures_join<F: std::future::Future<Output = Option<Duration>>>(futures: impl Iterator<Item = F>) -> Vec<Option<Duration>> {
    let handles: Vec<_> = futures.map(|future| Box::pin(future)).collect();
    let mut results = vec![None; handles.len()];
    let mut pending: Vec<(usize, std::pin::Pin<Box<F>>)> = handles.into_iter().enumerate().collect();
    std::future::poll_fn(|context| {
        pending.retain_mut(|(index, future)| match future.as_mut().poll(context) {
            std::task::Poll::Ready(result) => {
                results[*index] = result;
                false
            }
            std::task::Poll::Pending => true,
        });
        if pending.is_empty() { std::task::Poll::Ready(()) } else { std::task::Poll::Pending }
    })
    .await;
    results
}
