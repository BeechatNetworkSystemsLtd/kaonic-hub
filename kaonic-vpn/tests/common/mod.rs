//! Test nodes of one admin on the emulated channel, each running the VPN on an in-memory
//! TUN device ([`Vpn::start_detached`]).
#![allow(dead_code)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use kaonic_mesh::announce::NodeInfo;
use kaonic_mesh::links::{Auth, Links};
use kaonic_mesh::{Mesh, MeshConfig};
use kaonic_vpn::forward::Rule;
use kaonic_vpn::service::{Detached, VpnLimits};
use kaonic_vpn::share::ShareSettings;
use kaonic_vpn::{Vpn, VpnConfig};
use kaonic_sim_air::Air;
use kaonic_handshake::Credentials;
use kaonic_pki::{CertRequest, Certificate, Identity};
use kaonic_trust::{Allowlist, Trust};
use reticulum::identity::PrivateIdentity;
use x25519_dalek::{PublicKey, StaticSecret};

pub const ISSUED_AT: u64 = 1_792_000_000;

/// Set `KAONIC_TEST_LOG=debug` for link and VPN logs.
struct Logger(log::LevelFilter);

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.0
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) && (record.target().starts_with("hub_") || record.level() <= log::Level::Warn) {
            eprintln!("{:?} {:<5} {} {}", std::time::Instant::now(), record.level(), record.target(), record.args());
        }
    }
    fn flush(&self) {}
}

pub fn init_log() {
    if let Ok(level) = std::env::var("KAONIC_TEST_LOG")
        && let Ok(filter) = level.parse()
    {
        let _ = log::set_logger(Box::leak(Box::new(Logger(filter))));
        log::set_max_level(filter);
    }
}

pub struct Keys {
    pub x25519: StaticSecret,
    pub ed25519: SigningKey,
}

impl Keys {
    pub fn new(seed: u8) -> Self {
        Self { x25519: StaticSecret::from([seed.wrapping_add(100); 32]), ed25519: SigningKey::from_bytes(&[seed; 32]) }
    }

    pub fn identity(&self) -> Identity {
        Identity { x25519: PublicKey::from(&self.x25519).to_bytes(), ed25519: self.ed25519.verifying_key().to_bytes() }
    }
}

/// Keys and allowlist for a node of `admin`, with `listed` on the allowlist.
pub fn auth(admin: &Keys, root: &Certificate, keys: &Keys, listed: &[&Keys]) -> Auth {
    let identity = keys.identity();
    let cert = if identity == admin.identity() {
        root.clone()
    } else {
        let request = CertRequest::create(&identity, &keys.ed25519, b"link").unwrap();
        root.issue(&admin.ed25519, &request, &identity, ISSUED_AT).unwrap()
    };
    let allowlist = Allowlist::sign(&admin.ed25519, 1, listed.iter().map(|keys| keys.identity().hash())).unwrap();
    let trust = Trust::from_der(root.der(), cert.der(), allowlist.as_bytes()).unwrap();
    Auth { credentials: Credentials { identity, key: keys.ed25519.clone(), cert }, trust }
}

pub struct Node {
    pub vpn: Arc<Vpn>,
    pub ends: Detached,
    pub links: Arc<Links>,
    _mesh: Arc<Mesh>,
}

/// A node whose client interfaces are `lan`.
pub async fn node(air: &Air, name: &str, keys: &Keys, admin_id: [u8; 16], auth: Auth, lan: &str, rules: Vec<Rule>) -> Node {
    let share = ShareSettings { share_lans: false, lan_interfaces: vec![lan.to_owned()], ..ShareSettings::default() };
    node_sharing(air, name, keys, admin_id, auth, share, rules).await
}

/// A node with these sharing settings (not applied to the system).
pub async fn node_sharing(air: &Air, name: &str, keys: &Keys, admin_id: [u8; 16], auth: Auth, share: ShareSettings, rules: Vec<Rule>) -> Node {
    node_limited(air, name, keys, admin_id, auth, share, rules, VpnLimits::default()).await
}

/// A node with these sharing settings and limits.
#[allow(clippy::too_many_arguments)]
pub async fn node_limited(air: &Air, name: &str, keys: &Keys, admin_id: [u8; 16], auth: Auth, share: ShareSettings, rules: Vec<Rule>, limits: VpnLimits) -> Node {
    let info = NodeInfo { codename: name.to_owned(), version: "test".into(), is_admin: keys.identity().hash().0 == admin_id, admin_id: Some(admin_id) };
    let config = MeshConfig { radio: format!("air://{}/{name}", air.local_addr()), announce_secs: 5, offline_secs: 60, settings: None, ..MeshConfig::default() };
    let mesh = Mesh::start(PrivateIdentity::new(keys.x25519.clone(), keys.ed25519.clone()), info, config).await.expect("mesh starts");
    let links = Links::start(mesh.clone(), Some(auth), Box::new(|_| {})).await;
    let config = VpnConfig {
        network: "10.77.0.0/16".parse().unwrap(),
        interface: "kaonic0".into(),
        advertise: Vec::new(),
        max_packet: 799,
        limits,
        share,
        forward: rules,
    };
    let id = keys.identity().hash().to_hex();
    let (vpn, ends) = Vpn::start_detached(links.clone(), &id, config).expect("the VPN starts");
    Node { vpn, ends, links, _mesh: mesh }
}

/// Waits until every node has heard every other node's HELLO.
pub async fn all_up(nodes: &[&Node]) {
    let up = || nodes.iter().all(|node| node.vpn.status().peers.iter().filter(|peer| peer.state == "active").count() == nodes.len() - 1);
    for _ in 0..900 {
        if up() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the VPN is not up between all nodes: {:?}", nodes.iter().map(|node| node.vpn.status().peers.iter().map(|peer| (peer.peer[..8].to_owned(), peer.state)).collect::<Vec<_>>()).collect::<Vec<_>>());
}

pub fn counters(node: &Node, rule: &str) -> kaonic_vpn::forward::Counters {
    node.vpn.forward_status().into_iter().find(|status| status.rule.name == rule).expect("the rule").counters
}
