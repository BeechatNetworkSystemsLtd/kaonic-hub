//! Secure links on the emulated channel (`kaonic-air`): the nodes of one admin link up and
//! carry mux packets, through a relay where they are out of range; a node certified by
//! another admin is refused even when it claims our admin in its announce.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use kaonic_mesh::announce::NodeInfo;
use kaonic_mesh::links::{AllowlistSink, Auth, Links};
use kaonic_mesh::{Mesh, MeshConfig};
use kaonic_air::{Air, MediumConfig};
use kaonic_handshake::Credentials;
use kaonic_pki::{CertRequest, Certificate, Identity, IdentityHash};
use kaonic_trust::{Allowlist, Trust};
use reticulum::identity::PrivateIdentity;
use x25519_dalek::{PublicKey, StaticSecret};

const ISSUED_AT: u64 = 1_792_000_000;

/// `KAONIC_TEST_LOG=debug` shows what the links do.
struct Logger(log::LevelFilter);

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.0
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) && (record.target().starts_with("kaonic_mesh") || record.level() <= log::Level::Warn) {
            eprintln!("{:?} {:<5} {} {}", std::time::Instant::now(), record.level(), record.target(), record.args());
        }
    }
    fn flush(&self) {}
}

fn init_log() {
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

struct Admin {
    keys: Keys,
    root: Certificate,
}

impl Admin {
    fn new(seed: u8) -> Self {
        let keys = Keys::new(seed);
        let root = Certificate::new_root(&keys.identity(), &keys.ed25519, ISSUED_AT).unwrap();
        Self { keys, root }
    }

    fn id(&self) -> [u8; 16] {
        self.keys.identity().hash().0
    }

    /// What a node of this admin holds, with the allowlist listing `listed`.
    fn auth(&self, keys: &Keys, listed: &[&Keys]) -> Auth {
        self.auth_seq(keys, listed, 1)
    }

    fn auth_seq(&self, keys: &Keys, listed: &[&Keys], seq: u64) -> Auth {
        let identity = keys.identity();
        let cert = if identity == self.keys.identity() {
            self.root.clone()
        } else {
            let request = CertRequest::create(&identity, &keys.ed25519, b"link").unwrap();
            self.root.issue(&self.keys.ed25519, &request, &identity, ISSUED_AT).unwrap()
        };
        let allowlist = Allowlist::sign(&self.keys.ed25519, seq, listed.iter().map(|keys| keys.identity().hash())).unwrap();
        let trust = Trust::from_der(self.root.der(), cert.der(), allowlist.as_bytes()).unwrap();
        Auth { credentials: Credentials { identity, key: keys.ed25519.clone(), cert }, trust }
    }
}

async fn node(air: &Air, name: &str, keys: &Keys, admin_id: [u8; 16], auth: Auth) -> (Arc<Mesh>, Arc<Links>) {
    node_storing(air, name, keys, admin_id, auth, Box::new(|_| {})).await
}

/// A node that hands allowlists it receives to `store`.
async fn node_storing(air: &Air, name: &str, keys: &Keys, admin_id: [u8; 16], auth: Auth, store: AllowlistSink) -> (Arc<Mesh>, Arc<Links>) {
    let is_admin = keys.identity().hash().0 == admin_id;
    let info = NodeInfo { codename: name.to_owned(), version: "test".into(), is_admin, admin_id: Some(admin_id) };
    let config = MeshConfig { radio: format!("air://{}/{name}", air.local_addr()), announce_secs: 5, offline_secs: 60, settings: None, ..MeshConfig::default() };
    let identity = PrivateIdentity::new(keys.x25519.clone(), keys.ed25519.clone());
    let mesh = Mesh::start(identity, info, config).await.expect("mesh starts");
    let links = Links::start(mesh.clone(), Some(auth), store).await;
    (mesh, links)
}

fn hash(keys: &Keys) -> String {
    keys.identity().hash().to_hex()
}

#[tokio::test]
async fn the_admins_nodes_link_up_and_carry_traffic_and_a_foreign_node_is_refused() {
    init_log();
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 7).await.unwrap();
    // c reaches the admin only through b.
    air.block("admin", "c");
    air.block("rogue", "c");

    let admin = Admin::new(1);
    let (b_keys, c_keys) = (Keys::new(2), Keys::new(3));
    let (admin_mesh, admin_links) = node(&air, "admin", &admin.keys, admin.id(), admin.auth(&admin.keys, &[&b_keys, &c_keys])).await;
    let (_b_mesh, b_links) = node(&air, "b", &b_keys, admin.id(), admin.auth(&b_keys, &[&b_keys, &c_keys])).await;
    let (_c_mesh, c_links) = node(&air, "c", &c_keys, admin.id(), admin.auth(&c_keys, &[&b_keys, &c_keys])).await;

    // Certified by another admin, and announcing ours to be linked anyway.
    let other = Admin::new(9);
    let rogue_keys = Keys::new(4);
    let (_rogue_mesh, rogue_links) = node(&air, "rogue", &rogue_keys, admin.id(), other.auth(&rogue_keys, &[&rogue_keys])).await;

    let (admin_id, b, c, rogue) = (hash(&admin.keys), hash(&b_keys), hash(&c_keys), hash(&rogue_keys));
    let all_up = || {
        let up = |links: &Links, peers: &[&String]| peers.iter().all(|peer| links.established().contains(peer));
        up(&admin_links, &[&b, &c]) && up(&b_links, &[&admin_id, &c]) && up(&c_links, &[&admin_id, &b])
    };
    for _ in 0..600 {
        if all_up() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !all_up() {
        for (name, links) in [("admin", &admin_links), ("b", &b_links), ("c", &c_links)] {
            eprintln!("{name}: {:?}", links.view().await.iter().map(|view| (&view.peer[..8], view.state, &view.detail)).collect::<Vec<_>>());
        }
        eprintln!("ids: admin {} b {} c {} rogue {}", &admin_id[..8], &b[..8], &c[..8], &rogue[..8]);
        eprintln!("air: {:?}", air.stats());
        panic!("not every pair of the admin's nodes linked");
    }

    // A mux packet from the admin reaches c through b. Links do not retransmit (the VPN's
    // TCP does), and this channel loses frames, so send until one arrives.
    let mut received = c_links.subscribe();
    let packet = [kaonic_mux::MUX, 0x10, 0x00, 1, b'h', b'i'];
    let mut message = None;
    for _ in 0..10 {
        assert!(admin_links.send(&c, &packet).await);
        if let Ok(Ok(arrived)) = tokio::time::timeout(Duration::from_secs(2), received.recv()).await {
            message = Some(arrived);
            break;
        }
    }
    let message = message.expect("a packet reaches c within 10 tries");
    assert_eq!(message.peer, admin_id);
    assert_eq!(message.packet.as_slice(), &packet);

    // The rogue is never accepted, on either side, and is backed off.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!admin_links.established().contains(&rogue));
    assert!(!b_links.established().contains(&rogue));
    assert!(rogue_links.established().is_empty());
    assert!(!admin_links.send(&rogue, &packet).await);
    let views = admin_links.view().await;
    assert!(views.iter().any(|view| view.peer == c && view.state == "up"));

    // The admin revokes c: its own link to c closes, and the newer allowlist reaches b, which
    // closes its link to c too. c cannot link again.
    admin_links.set_auth(Some(admin.auth_seq(&admin.keys, &[&b_keys], 2))).await;
    let mut revoked = false;
    for _ in 0..300 {
        if !admin_links.established().contains(&c) && !b_links.established().contains(&c) {
            revoked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(revoked, "c is still linked: admin {:?}, b {:?}", admin_links.established(), b_links.established());
    assert!(b_links.established().contains(&admin_id), "b keeps its link to the admin");
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!admin_links.established().contains(&c) && !b_links.established().contains(&c), "c came back");
    drop(admin_mesh);
}

#[tokio::test]
async fn an_allowlist_too_big_for_one_packet_reaches_a_linked_node() {
    init_log();
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 11).await.unwrap();
    let admin = Admin::new(1);
    let b_keys = Keys::new(2);
    let (_admin_mesh, admin_links) = node(&air, "admin", &admin.keys, admin.id(), admin.auth(&admin.keys, &[&b_keys])).await;
    let stored = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink: AllowlistSink = {
        let stored = stored.clone();
        Box::new(move |bytes: Vec<u8>| stored.lock().unwrap().push(Allowlist::seq_of(&bytes).unwrap()))
    };
    let (_b_mesh, b_links) = node_storing(&air, "b", &b_keys, admin.id(), admin.auth(&b_keys, &[&b_keys]), sink).await;
    let b = hash(&b_keys);
    for _ in 0..600 {
        if admin_links.established().contains(&b) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(admin_links.established().contains(&b), "b never linked");

    // 400 more identities: about 6.5 KB, 9 parts.
    let made_up = (0..400u16).map(|n| {
        let mut hash = [0xEE; 16];
        hash[..2].copy_from_slice(&n.to_be_bytes());
        IdentityHash(hash)
    });
    let big = Allowlist::sign(&admin.keys.ed25519, 2, std::iter::once(b_keys.identity().hash()).chain(made_up)).unwrap();
    let mut auth = admin.auth(&admin.keys, &[&b_keys]);
    assert!(auth.trust.update_allowlist(big.as_bytes()).unwrap());
    admin_links.set_auth(Some(auth)).await;
    for _ in 0..600 {
        if stored.lock().unwrap().contains(&2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(*stored.lock().unwrap(), vec![2], "b did not get the list: {:?}", air.stats());
    assert!(b_links.established().contains(&admin.keys.identity().hash().to_hex()), "b stays linked");
}
