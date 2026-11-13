//! Provisioning and the PTT group key against an attacker in radio range: the certificate and
//! allowlist a node shows on every link are public, so repeating PROVISION with them must not
//! let anyone hand the node a group key, and old key epochs never come back.

use std::sync::{Arc, Mutex};

use kaonic_mesh::group::GroupKeyMaterial;
use kaonic_mesh::reticulum::hash::AddressHash;
use kaonic_hub::api::{BOOT_IDENTITY, Jobs, NODE_IDENTITY, TRUST_ALLOWLIST, TRUST_OWN, TRUST_ROOT};
use kaonic_hub::app::{App, Config, Inner};
use kaonic_hub::auth::Limiter;
use kaonic_hub::events::Bus;
use kaonic_hub::group_key;
use kaonic_hub::identity::NodeIdentity;
use kaonic_hub::provision::{Message, Offered, Status, answer};
use kaonic_hub::system::{Device, Metrics};
use kaonic_hub::wifi;
use kaonic_keystore::{Keystore, RawKey};
use kaonic_pki::{CertRequest, Certificate};
use kaonic_trust::Allowlist;
use tokio::sync::Semaphore;

const ISSUED_AT: u64 = 1_792_000_000;

fn app(name: &str) -> (App, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("kh-provision-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kaonic_store::Store::open_in_memory().unwrap();
    let mut keystore = Keystore::create(dir.join("keystore"), &RawKey::generate().unwrap()).unwrap();
    keystore.get_or_generate(BOOT_IDENTITY, 64).unwrap();
    let keystore = Arc::new(Mutex::new(keystore));
    let bus = Bus::new();
    let wifi = wifi::start(Box::new(wifi::NullRadio), store.clone(), keystore.clone(), bus.clone(), "Kaonic /TEST/".into()).unwrap();
    let app = App::new(Inner {
        config: Config {
            state_dir: dir.clone(),
            webui: kaonic_hub::web::Webui::Dir(dir.join("webui")),
            run_dir: dir.join("run"),
            dev: true,
            radio: "rf09_a".into(),
            setup_interfaces: vec!["br0".into()],
            plugins: Default::default(),
        },
        store,
        keystore,
        bus,
        limiter: Limiter::default(),
        argon: Semaphore::new(1),
        device: Device::new(&dir),
        metrics: Metrics::default(),
        wifi,
        jobs: Jobs::default(),
        ca_pem: std::sync::OnceLock::new(),
        mesh: None,
        provisioning: Default::default(),
        radio_stats: Default::default(),
        links: Default::default(),
        ptt_group: Default::default(),
        ptt: Default::default(),
        vpn: Default::default(),
        vpn_error: Default::default(),
        vpn_config: None,
        plugins: Default::default(),
    });
    (app, dir)
}

struct Admin {
    identity: NodeIdentity,
    root: Certificate,
}

impl Admin {
    fn new() -> Self {
        let identity = NodeIdentity::generate().unwrap();
        let root = Certificate::new_root(&identity.public(), identity.signing_key(), ISSUED_AT).unwrap();
        Self { identity, root }
    }

    fn allowlist(&self, seq: u64, nodes: &[&NodeIdentity]) -> Allowlist {
        Allowlist::sign(self.identity.signing_key(), seq, nodes.iter().map(|node| node.public().hash())).unwrap()
    }
}

/// The node's identity (its boot identity, as a member).
async fn node_identity(app: &App) -> NodeIdentity {
    let bytes = app.secrets(|keys| Ok(keys.get(BOOT_IDENTITY).unwrap().expose().to_vec())).await.unwrap();
    let identity = NodeIdentity::from_bytes(&bytes.try_into().unwrap());
    let stored = identity.to_bytes().to_vec();
    app.secrets(move |keys| keys.set(NODE_IDENTITY, stored)).await.unwrap();
    identity
}

/// Provisions `app` by `admin` the way the admin does: REQUEST, CSR, PROVISION with `key`.
async fn provision(app: &App, admin: &Admin, node: &NodeIdentity, link: AddressHash, offered: &mut Offered, key: Option<&GroupKeyMaterial>) -> Message {
    let csr = match answer(app, &link, Message::Request { root: admin.root.der().to_vec() }, offered).await {
        Some(Message::Csr { csr }) => csr,
        other => panic!("expected a CSR, got {other:?}"),
    };
    let request = CertRequest::from_der(&csr).unwrap();
    let cert = admin.root.issue(admin.identity.signing_key(), &request, &node.public(), ISSUED_AT).unwrap();
    let allowlist = admin.allowlist(2, &[node]);
    let message = Message::Provision { cert: cert.der().to_vec(), allowlist: allowlist.as_bytes().to_vec(), group_key: key.map(group_key::encode) };
    answer(app, &link, message, offered).await.unwrap()
}

fn ok(message: &Message) -> bool {
    matches!(message, Message::Result { status: Status::Ok, .. })
}

#[tokio::test]
async fn a_provisioned_node_takes_no_group_key_from_a_repeated_provision() {
    let (app, _dir) = app("repeat");
    let admin = Admin::new();
    let node = node_identity(&app).await;
    let mut offered = Offered::new();
    let genuine = GroupKeyMaterial::generate(1);
    assert!(ok(&provision(&app, &admin, &node, AddressHash::new([1; 16]), &mut offered, Some(&genuine)).await));
    assert_eq!(group_key::stored(&app).await.unwrap().key, genuine.key, "the first provisioning brings the key");

    // What the attacker has: the node's certificate (from its AUTH) and allowlist (ALLOWLIST).
    let (cert, allowlist) = app
        .secrets(|keys| Ok((keys.get(TRUST_OWN).unwrap().expose().to_vec(), keys.get(TRUST_ALLOWLIST).unwrap().expose().to_vec())))
        .await
        .unwrap();
    let forged = GroupKeyMaterial::generate(9);

    // 1. The repeated-PROVISION shortcut: answered, but nothing adopted.
    let replay = Message::Provision { cert: cert.clone(), allowlist: allowlist.clone(), group_key: Some(group_key::encode(&forged)) };
    assert!(ok(&answer(&app, &AddressHash::new([2; 16]), replay, &mut offered).await.unwrap()));
    assert_eq!(group_key::stored(&app).await.unwrap().key, genuine.key);

    // 2. The full REQUEST → PROVISION path with the same public parts.
    let link = AddressHash::new([3; 16]);
    let root = app.secrets(|keys| Ok(keys.get(TRUST_ROOT).unwrap().expose().to_vec())).await.unwrap();
    assert!(matches!(answer(&app, &link, Message::Request { root }, &mut offered).await, Some(Message::Csr { .. })));
    let full = Message::Provision { cert, allowlist, group_key: Some(group_key::encode(&forged)) };
    answer(&app, &link, full, &mut offered).await;
    assert_eq!(group_key::stored(&app).await.unwrap().key, genuine.key, "a provisioned node takes keys only on its admin's link");
}

#[tokio::test]
async fn old_epochs_never_replace_a_newer_key() {
    let (app, _dir) = app("epochs");
    let admin = Admin::new();
    let node = node_identity(&app).await;
    let mut offered = Offered::new();
    assert!(ok(&provision(&app, &admin, &node, AddressHash::new([1; 16]), &mut offered, Some(&GroupKeyMaterial::generate(5))).await));
    assert!(!group_key::adopt(&app, GroupKeyMaterial::generate(4)).await, "older");
    assert!(!group_key::adopt(&app, GroupKeyMaterial::generate(5)).await, "same epoch, other key");
    assert_eq!(group_key::stored(&app).await.unwrap().epoch, 5);
    assert!(group_key::adopt(&app, GroupKeyMaterial::generate(6)).await, "the next rotation");
    assert_eq!(group_key::stored(&app).await.unwrap().epoch, 6);
}

#[tokio::test]
async fn the_admin_device_is_never_provisioned_and_takes_no_key() {
    let (app, _dir) = app("admin");
    // This device is the admin: its own certificate is the root.
    let identity = node_identity(&app).await;
    let root = Certificate::new_root(&identity.public(), identity.signing_key(), ISSUED_AT).unwrap();
    let allowlist = Allowlist::sign(identity.signing_key(), 1, std::iter::empty()).unwrap();
    let (root_der, list) = (root.der().to_vec(), allowlist.as_bytes().to_vec());
    app.secrets(move |keys| {
        keys.set(TRUST_ROOT, root_der.clone())?;
        keys.set(TRUST_OWN, root_der)?;
        keys.set(TRUST_ALLOWLIST, list)
    })
    .await
    .unwrap();
    let own = group_key::admin_key(&app).await.unwrap();

    let mut offered = Offered::new();
    let reply = answer(&app, &AddressHash::new([1; 16]), Message::Request { root: root.der().to_vec() }, &mut offered).await;
    assert!(matches!(reply, Some(Message::Result { status: Status::Taken, .. })));
    let forged = Message::Provision { cert: root.der().to_vec(), allowlist: allowlist.as_bytes().to_vec(), group_key: Some(group_key::encode(&GroupKeyMaterial::generate(200))) };
    assert!(matches!(answer(&app, &AddressHash::new([1; 16]), forged, &mut offered).await, Some(Message::Result { status: Status::Taken, .. })));
    assert!(!group_key::adopt(&app, GroupKeyMaterial::generate(own.epoch.wrapping_add(1))).await);
    assert_eq!(group_key::stored(&app).await.unwrap().key, own.key);
}

#[tokio::test]
async fn offers_are_capped() {
    let (app, _dir) = app("offers");
    let admin = Admin::new();
    let mut offered = Offered::new();
    let mut refused = 0;
    for link in 0..40u8 {
        match answer(&app, &AddressHash::new([link; 16]), Message::Request { root: admin.root.der().to_vec() }, &mut offered).await {
            Some(Message::Csr { .. }) => {}
            _ => refused += 1,
        }
    }
    assert_eq!(offered.len(), 32);
    assert_eq!(refused, 8);
}

#[tokio::test]
async fn the_admin_blocks_and_unblocks_on_its_signed_list() {
    use kaonic_hub::provision::{Listing, lists, set_listing};
    let (app, _dir) = app("block");
    let identity = node_identity(&app).await;
    let root = Certificate::new_root(&identity.public(), identity.signing_key(), ISSUED_AT).unwrap();
    let member = NodeIdentity::generate().unwrap();
    let member_id = member.public().hash().to_hex();
    let stranger_id = NodeIdentity::generate().unwrap().public().hash().to_hex();
    let allowlist = Allowlist::sign(identity.signing_key(), 1, [member.public().hash()]).unwrap();
    let (root_der, list) = (root.der().to_vec(), allowlist.as_bytes().to_vec());
    app.secrets(move |keys| {
        keys.set(TRUST_ROOT, root_der.clone())?;
        keys.set(TRUST_OWN, root_der)?;
        keys.set(TRUST_ALLOWLIST, list)
    })
    .await
    .unwrap();
    let epoch = group_key::admin_key(&app).await.unwrap().epoch;

    // Blocking a member revokes it everywhere the list goes, and rotates the talk key past it.
    assert_eq!(set_listing(&app, &member_id, Listing::Blocked).await, Ok(true));
    let (allowed, blocked) = lists(&app).await;
    assert!(!allowed.contains(&member_id) && blocked.contains(&member_id));
    assert_ne!(group_key::admin_key(&app).await.unwrap().epoch, epoch);
    // A node never provisioned can be blocked too; again is no change.
    assert_eq!(set_listing(&app, &stranger_id, Listing::Blocked).await, Ok(true));
    assert_eq!(set_listing(&app, &stranger_id, Listing::Blocked).await, Ok(false));
    assert_eq!(lists(&app).await.1.len(), 2);
    // Unblocking leaves it off both lists.
    assert_eq!(set_listing(&app, &member_id, Listing::None).await, Ok(true));
    let (allowed, blocked) = lists(&app).await;
    assert!(!allowed.contains(&member_id) && !blocked.contains(&member_id) && blocked.contains(&stranger_id));
    // The admin itself never.
    assert!(set_listing(&app, &identity.public().hash().to_hex(), Listing::Blocked).await.is_err());
    let stored = app.secrets(|keys| Ok(keys.get(TRUST_ALLOWLIST).unwrap().expose().to_vec())).await.unwrap();
    assert_eq!(Allowlist::from_bytes(&stored, &identity.public().ed25519).unwrap().seq(), 4);
}
