//! Provisioning over the mesh: the Kaonic
//! Admin takes a node that waits for one, certifies it, and puts it on the
//! allowlist. The first admin wins; a node with an admin refuses any other
//! until it is factory reset. Its own admin may provision it again (to repair
//! a run that did not finish, or to whitelist it again), never with an older
//! allowlist.
//!
//! On a link the admin opens to the node (the node is the link's responder,
//! so Reticulum's link proof already shows the admin it reached that node):
//!
//! ```text
//! admin → node   REQUEST   the admin's root certificate
//! node  → admin  CSR       signed by the node, challenge = this link's id
//! admin → node   PROVISION the node's certificate, the new signed allowlist
//! node  → admin  RESULT    ok, or why not
//! ```
//! Messages: `"KPV1" | type u8 | body`. PROVISION's body is
//! `cert len u16 | cert | allowlist`; RESULT's is `status u8 | message`.
//!
//! Radio frames get lost, so the admin sends REQUEST and PROVISION again when
//! no answer comes, and the node answers a repeated PROVISION it already took
//! with OK again.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use kaonic_mesh::reticulum::destination::link::LinkId;
use kaonic_pki::{CertRequest, Certificate, Identity, IdentityHash};
use kaonic_trust::{Allowlist, Trust};

use crate::api::{BOOT_IDENTITY, NODE_IDENTITY, TRUST_ALLOWLIST, TRUST_OWN, TRUST_ROOT};
use crate::app::App;
use crate::clock;
use crate::identity::NodeIdentity;

const MAGIC: &[u8; 4] = b"KPV1";
const LINK_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for each answer, and how many times to ask.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPTS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Request { root: Vec<u8> },
    Csr { csr: Vec<u8> },
    /// `group_key`: the push-to-talk key (`group_key::encode`), after the allowlist; older
    /// admins send none.
    Provision { cert: Vec<u8>, allowlist: Vec<u8>, group_key: Option<Vec<u8>> },
    Result { status: Status, message: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    /// This node already has an admin (first admin wins).
    Taken = 1,
    Rejected = 2,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        match self {
            Message::Request { root } => {
                out.push(1);
                out.extend_from_slice(root);
            }
            Message::Csr { csr } => {
                out.push(2);
                out.extend_from_slice(csr);
            }
            Message::Provision { cert, allowlist, group_key } => {
                out.push(3);
                out.extend_from_slice(&(cert.len() as u16).to_be_bytes());
                out.extend_from_slice(cert);
                out.extend_from_slice(allowlist);
                if let Some(group_key) = group_key {
                    out.extend_from_slice(group_key);
                }
            }
            Message::Result { status, message } => {
                out.push(4);
                out.push(*status as u8);
                out.extend_from_slice(message.as_bytes());
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let rest = data.strip_prefix(MAGIC)?;
        let (&kind, body) = rest.split_first()?;
        Some(match kind {
            1 => Message::Request {
                root: body.to_vec(),
            },
            2 => Message::Csr { csr: body.to_vec() },
            3 => {
                let (length, rest) = body.split_first_chunk::<2>()?;
                let (cert, rest) =
                    rest.split_at_checked(u16::from_be_bytes(*length) as usize)?;
                // The allowlist says its own length; anything after it is the group key.
                let (allowlist, group_key) = rest.split_at(Allowlist::encoded_len(rest).unwrap_or(rest.len()));
                Message::Provision {
                    cert: cert.to_vec(),
                    allowlist: allowlist.to_vec(),
                    group_key: (!group_key.is_empty()).then(|| group_key.to_vec()),
                }
            }
            4 => {
                let (&status, message) = body.split_first()?;
                let status = match status {
                    0 => Status::Ok,
                    1 => Status::Taken,
                    _ => Status::Rejected,
                };
                Message::Result {
                    status,
                    message: String::from_utf8_lossy(message)
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(200)
                        .collect(),
                }
            }
            _ => return None,
        })
    }
}

/// At most this many peers' provisioning outcomes are kept; the oldest finished go first.
const PROVISIONING_MAX: usize = 64;

/// Provisioning on the admin device, by peer: (running, detail), with when it was last set.
#[derive(Default)]
pub struct Provisioning {
    state: Mutex<(u64, HashMap<String, (bool, String, u64)>)>,
}

impl Provisioning {
    pub fn get(&self, id: &str) -> Option<(bool, String)> {
        self.state
            .lock()
            .expect("provisioning lock")
            .1
            .get(id)
            .map(|(running, detail, _)| (*running, detail.clone()))
    }

    fn set(&self, id: &str, running: bool, detail: impl Into<String>) {
        let mut state = self.state.lock().expect("provisioning lock");
        let (next, entries) = &mut *state;
        *next += 1;
        if entries.len() >= PROVISIONING_MAX && !entries.contains_key(id) {
            // The oldest finished outcome, else the oldest of all.
            let oldest = entries
                .iter()
                .min_by_key(|(_, (running, _, at))| (*running, *at))
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(id.to_owned(), (running, detail.into(), *next));
    }

    fn clear(&self, id: &str) {
        self.state.lock().expect("provisioning lock").1.remove(id);
    }
}

/// This node's identity: the set-up one, or the boot identity before setup (the mesh uses the same).
pub(crate) async fn own_identity(app: &App) -> Option<NodeIdentity> {
    let bytes = app
        .secrets(|keys| {
            Ok(keys
                .get(NODE_IDENTITY)
                .or_else(|| keys.get(BOOT_IDENTITY))
                .map(|secret| secret.expose().to_vec()))
        })
        .await
        .ok()
        .flatten()?;
    Some(NodeIdentity::from_bytes(&<[u8; 64]>::try_from(bytes).ok()?))
}

/// The trust state this node holds, if provisioned (or the admin).
pub async fn trust(app: &App) -> Option<Trust> {
    let (root, own, allowlist) = app
        .secrets(|keys| {
            let get = |name: &str| keys.get(name).map(|secret| secret.expose().to_vec());
            Ok((get(TRUST_ROOT), get(TRUST_OWN), get(TRUST_ALLOWLIST)))
        })
        .await
        .ok()?;
    Trust::from_der(&root?, &own?, &allowlist?).ok()
}

/// The identities on this node's allowlist, as hex.
pub async fn allowlisted(app: &App) -> HashSet<String> {
    lists(app).await.0
}

/// The identities the admin's signed list allows and blocks, as hex.
pub async fn lists(app: &App) -> (HashSet<String>, HashSet<String>) {
    trust(app)
        .await
        .map(|trust| {
            let list = trust.allowlist();
            (list.entries().map(|hash| hash.to_hex()).collect(), list.blocked().map(|hash| hash.to_hex()).collect())
        })
        .unwrap_or_default()
}

/* ── the node's side ── */

/// Answers provisioning requests that arrive on links other nodes open to this one.
pub fn serve(app: App) {
    let Some(mesh) = app.mesh.clone() else { return };
    tokio::spawn(async move {
        let mut events = mesh.incoming().await;
        // The root an admin offered on each link, until its PROVISION arrives (or the link
        // closes, or OFFER_TIMEOUT passes: anyone in range can send a REQUEST).
        let mut offered: Offered = HashMap::new();
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            offered.retain(|_, (_, at)| at.elapsed() < OFFER_TIMEOUT);
            if matches!(event.event, kaonic_mesh::reticulum::destination::link::LinkEvent::Closed) {
                offered.remove(&event.id);
                continue;
            }
            let Some(incoming) = kaonic_mesh::link::message(&event) else {
                continue;
            };
            let Some(message) = Message::decode(&incoming.data) else {
                continue;
            };
            let answer = answer(&app, &incoming.link, message, &mut offered).await;
            if let Some(answer) = answer
                && let Err(error) = mesh.reply(&incoming.link, &answer.encode()).await
            {
                log::warn!("provision: cannot answer: {error}");
            }
        }
    });
}

/// Roots offered by REQUEST, by link, with when.
pub type Offered = HashMap<LinkId, (Vec<u8>, std::time::Instant)>;

/// A REQUEST's offer lasts this long without its PROVISION.
const OFFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// At most this many offers at once (one per link; links are cheap to open).
const OFFERS_MAX: usize = 32;

/// One provisioning message on `link` and our answer. Public for the tests.
pub async fn answer(
    app: &App,
    link: &LinkId,
    message: Message,
    offered: &mut Offered,
) -> Option<Message> {
    let refuse = |status, message: &str| {
        Some(Message::Result {
            status,
            message: message.to_owned(),
        })
    };
    // The admin device holds the root itself: nobody provisions it.
    if matches!(message, Message::Request { .. } | Message::Provision { .. }) && is_admin_device(app).await {
        return refuse(Status::Taken, "This is the Kaonic Admin device.");
    }
    match message {
        Message::Request { root } => {
            if trust(app)
                .await
                .is_some_and(|trust| trust.root().der() != root.as_slice())
            {
                // Anyone in range can send a REQUEST: not one log line each.
                static NOTED: clock::Every = clock::Every::secs(clock::LOG_EVERY);
                if NOTED.due() {
                    log::info!("provision: refused an admin: this device already has another");
                } else {
                    log::debug!("provision: refused an admin: this device already has another");
                }
                return refuse(
                    Status::Taken,
                    "This device already belongs to a Kaonic Admin. Factory reset it first.",
                );
            }
            match Certificate::from_der(&root) {
                Ok(root) if root.is_root() => {}
                _ => return refuse(Status::Rejected, "That is not an admin certificate."),
            }
            let identity = own_identity(app).await?;
            let csr =
                CertRequest::create(&identity.public(), identity.signing_key(), link.as_slice())
                    .ok()?;
            if offered.len() >= OFFERS_MAX && !offered.contains_key(link) {
                return refuse(Status::Rejected, "Too many provisioning requests at once. Try again.");
            }
            offered.insert(*link, (root, std::time::Instant::now()));
            Some(Message::Csr {
                csr: csr.der().to_vec(),
            })
        }
        Message::Provision { cert, allowlist, group_key } => {
            let group_key = group_key.as_deref().and_then(crate::group_key::decode);
            let current = trust(app).await;
            // The answer to this very PROVISION was lost and the admin sent it again. Only an
            // answer: the certificate and allowlist it repeats are not secret (AUTH and
            // ALLOWLIST carry them), so it proves nothing and changes nothing.
            if let Some(current) = &current
                && current.own().der() == cert.as_slice()
                && current.allowlist().as_bytes() == allowlist.as_slice()
            {
                return refuse(Status::Ok, "Provisioned.");
            }
            let Some((root, _)) = offered.remove(link) else {
                return refuse(Status::Rejected, "No request came first on this link.");
            };
            if let Some(current) = &current
                && current.root().der() != root.as_slice()
            {
                return refuse(
                    Status::Taken,
                    "This device already belongs to a Kaonic Admin.",
                );
            }
            let identity = own_identity(app).await?;
            let public = identity.public();
            let checked = Trust::from_der(&root, &cert, &allowlist)
                .map_err(|error| error.to_string())
                .and_then(|trust| {
                    trust
                        .own()
                        .check_identity(&public)
                        .map_err(|error| error.to_string())?;
                    if !trust.allowlist().contains(&public.hash()) {
                        return Err("the allowlist does not list this device".into());
                    }
                    // A recorded PROVISION must not roll the allowlist back past a revocation.
                    // The same seq is fine only as the very same allowlist: the admin signs it
                    // again when an earlier run's answer was lost.
                    if current.as_ref().is_some_and(|current| {
                        let (new, old) = (trust.allowlist(), current.allowlist());
                        new.seq() < old.seq()
                            || (new.seq() == old.seq() && new.as_bytes() != old.as_bytes())
                    }) {
                        return Err("the allowlist is older than the one this device has".into());
                    }
                    Ok(trust)
                });
            if let Err(why) = checked {
                static NOTED: clock::Every = clock::Every::secs(clock::LOG_EVERY);
                if NOTED.due() {
                    log::warn!("provision: refused: {why}");
                } else {
                    log::debug!("provision: refused: {why}");
                }
                return refuse(Status::Rejected, &format!("Refused: {why}."));
            }
            let stored = app
                .secrets(move |keys| {
                    keys.set(TRUST_ROOT, root)?;
                    keys.set(TRUST_OWN, cert)?;
                    keys.set(TRUST_ALLOWLIST, allowlist)
                })
                .await;
            if stored.is_err() {
                return refuse(
                    Status::Rejected,
                    "This device could not store its certificate.",
                );
            }
            log::info!(
                "provision: this device now belongs to admin {}",
                crate::api::our_admin(app)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default()
            );
            announce_change(app).await;
            // The group key travels with the first provisioning only (trust on first use, like
            // the root). A provisioned node gets later keys on its admin's authenticated link:
            // anyone can repeat this exchange with the node's public certificate and
            // allowlist, so a key here would be unauthenticated.
            if current.is_none()
                && let Some(key) = group_key
            {
                crate::group_key::adopt(app, key).await;
            }
            refuse(Status::Ok, "Provisioned.")
        }
        _ => None,
    }
}

/// The next announces say what changed (provisioned, codename…).
pub async fn announce_change(app: &App) {
    crate::secure::refresh(app).await;
    if let (Some(mesh), Ok(info)) = (&app.mesh, crate::api::node_info(app).await) {
        mesh.set_info(info);
    }
    app.bus.publish("trust", "trust.changed", ());
}

/* ── the admin's side ── */

/// Whether this device is the Kaonic Admin: it holds the root's key.
pub async fn is_admin_device(app: &App) -> bool {
    let Some(trust) = trust(app).await else {
        return false;
    };
    trust.own() == trust.root()
}

/// Starts provisioning the peer `id` in the background; progress shows on the peer.
pub fn start(app: &App, id: String) {
    app.provisioning.set(&id, true, "Opening a link");
    let app = app.clone();
    tokio::spawn(async move {
        let outcome = provision(&app, &id).await;
        match outcome {
            Ok(()) => {
                app.provisioning.clear(&id);
                log::info!("provision: {id} joined");
            }
            Err(why) => {
                log::warn!("provision: {id}: {why}");
                app.provisioning.set(&id, false, why);
            }
        }
        crate::api::publish_peer(&app, &id).await;
    });
}

async fn provision(app: &App, id: &str) -> Result<(), String> {
    let mesh = app.mesh.clone().ok_or("The radio is not running.")?;
    let trust = trust(app)
        .await
        .ok_or("This device is not the Kaonic Admin.")?;
    let admin = own_identity(app)
        .await
        .ok_or("This device has no identity.")?;
    let (x25519, ed25519) = mesh
        .public_keys(id)
        .ok_or("This device has not been heard announcing.")?;
    let node = Identity { x25519, ed25519 };
    if node.hash().to_hex() != id {
        return Err("The announced keys do not match the device.".into());
    }

    let step = |detail: &str| {
        app.provisioning.set(id, true, detail);
        let app = app.clone();
        let id = id.to_owned();
        tokio::spawn(async move { crate::api::publish_peer(&app, &id).await });
    };
    let mut link = mesh
        .open_link(id, LINK_TIMEOUT)
        .await
        .map_err(|error| format!("No link to the device: {error}."))?;
    step("Asking for its certificate request");
    let request = Message::Request {
        root: trust.root().der().to_vec(),
    };
    let answer = exchange(&mut link, &request, |answer| {
        matches!(answer, Message::Csr { .. } | Message::Result { .. })
    })
    .await;
    let csr = match answer {
        Ok(Message::Csr { csr }) => csr,
        Ok(Message::Result { message, .. }) => {
            link.close().await;
            return Err(message);
        }
        Ok(_) => unreachable!("exchange returns only accepted answers"),
        Err(why) => {
            link.close().await;
            return Err(why);
        }
    };
    let request = CertRequest::from_der(&csr)
        .map_err(|error| format!("Bad certificate request: {error}."))?;
    // Bound to this link: a request recorded on another link cannot be replayed here.
    if request.challenge() != link.id().as_slice() {
        return Err("The certificate request is not for this link.".into());
    }
    step("Issuing its certificate");
    let cert = trust
        .root()
        .issue(admin.signing_key(), &request, &node, clock::now() as u64)
        .map_err(|error| format!("Cannot certify it: {error}."))?;
    let hash = IdentityHash(node.hash().0);
    let entries: Vec<IdentityHash> = trust
        .allowlist()
        .entries()
        .copied()
        .filter(|entry| *entry != hash)
        .chain(std::iter::once(hash))
        .collect();
    let blocked = trust.allowlist().blocked().copied().filter(|entry| *entry != hash);
    let allowlist = Allowlist::sign_with_blocked(admin.signing_key(), trust.allowlist().seq() + 1, entries, blocked)
        .map_err(|error| format!("Cannot sign the allowlist: {error}."))?;

    step("Delivering its certificate");
    let provision = Message::Provision {
        cert: cert.der().to_vec(),
        allowlist: allowlist.as_bytes().to_vec(),
        group_key: crate::group_key::admin_key(app).await.map(|key| crate::group_key::encode(&key)),
    };
    // A late CSR from a repeated REQUEST is not the answer.
    let result = exchange(&mut link, &provision, |answer| {
        matches!(answer, Message::Result { .. })
    })
    .await;
    link.close().await;
    match result? {
        Message::Result {
            status: Status::Ok, ..
        } => {}
        Message::Result { message, .. } => return Err(message),
        _ => unreachable!("exchange returns only accepted answers"),
    }
    // Only once the node has it: the admin's allowlist now lists it.
    let bytes = allowlist.as_bytes().to_vec();
    app.secrets(move |keys| keys.set(TRUST_ALLOWLIST, bytes))
        .await
        .map_err(|_| "Cannot store the allowlist.".to_owned())?;
    let now = clock::now();
    let detail = id.to_owned();
    let _ = app
        .store
        .call(move |c| kaonic_store::audit::record(c, now, "admin", "peer.provision", &detail))
        .await;
    announce_change(app).await;
    Ok(())
}

/// Sends `message` and waits for an answer `accept` takes, sending again when none comes.
async fn exchange(
    link: &mut kaonic_mesh::OutLink,
    message: &Message,
    accept: impl Fn(&Message) -> bool,
) -> Result<Message, String> {
    let encoded = message.encode();
    for _ in 0..ATTEMPTS {
        link.send(&encoded).await;
        let deadline = tokio::time::Instant::now() + ANSWER_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match link.recv(left).await {
                Ok(data) => match Message::decode(&data) {
                    Some(answer) if accept(&answer) => return Ok(answer),
                    _ => {}
                },
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
                Err(error) => return Err(format!("The link failed: {error}.")),
            }
        }
    }
    Err("The device did not answer.".into())
}

/// Where the admin puts a node on its signed list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listing {
    /// Neither allowed nor blocked (allowing is provisioning, see [`start`]).
    None,
    Blocked,
}

/// Takes a node off the allowlist (revocation), and blocks it or unblocks it: a new list one
/// `seq` higher, which spreads to every node. Returns whether the list changed. A node taken
/// off the allowlist loses its links, and the push-to-talk key is rotated past it.
pub async fn set_listing(app: &App, id: &str, listing: Listing) -> Result<bool, String> {
    let trust = trust(app)
        .await
        .ok_or("This device is not the Kaonic Admin.")?;
    let admin = own_identity(app)
        .await
        .ok_or("This device has no identity.")?;
    let hash = IdentityHash::from_hex(id).ok_or("Not a node identity.")?;
    if hash == trust.root().identity_hash() {
        return Err("The Kaonic Admin can't be removed or blocked.".into());
    }
    let list = trust.allowlist();
    let was_member = list.contains(&hash);
    let blocked = listing == Listing::Blocked;
    if !was_member && list.is_blocked(&hash) == blocked {
        return Ok(false);
    }
    let entries: Vec<IdentityHash> = list.entries().copied().filter(|entry| *entry != hash).collect();
    let others = list.blocked().copied().filter(|entry| *entry != hash);
    let allowlist = Allowlist::sign_with_blocked(admin.signing_key(), list.seq() + 1, entries, others.chain(blocked.then_some(hash)))
        .map_err(|error| error.to_string())?;
    let bytes = allowlist.as_bytes().to_vec();
    app.secrets(move |keys| keys.set(TRUST_ALLOWLIST, bytes))
        .await
        .map_err(|_| "Cannot store the allowlist.".to_owned())?;
    let now = clock::now();
    let detail = id.to_owned();
    let action = match (was_member, listing) {
        (_, Listing::Blocked) => "peer.block",
        (true, Listing::None) => "peer.revoke",
        (false, Listing::None) => "peer.unblock",
    };
    let _ = app
        .store
        .call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail))
        .await;
    announce_change(app).await;
    if was_member {
        // The revoked node's links are closed by now: the next key reaches only the others.
        crate::group_key::rotate(app).await;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_outcomes_are_capped_oldest_finished_first() {
        let provisioning = Provisioning::default();
        provisioning.set("running", true, "Opening a link");
        for index in 0..PROVISIONING_MAX + 10 {
            provisioning.set(&format!("failed-{index}"), false, "No answer.");
        }
        let state = provisioning.state.lock().unwrap();
        assert_eq!(state.1.len(), PROVISIONING_MAX);
        drop(state);
        assert!(provisioning.get("running").is_some(), "a run in progress stays");
        assert!(provisioning.get("failed-0").is_none(), "the oldest outcome went first");
        assert!(provisioning.get(&format!("failed-{}", PROVISIONING_MAX + 9)).is_some());
    }

    #[test]
    fn provision_carries_the_group_key_after_the_allowlist() {
        // A real allowlist's layout: header, two entries, signature.
        let mut allowlist = b"KALW\x01".to_vec();
        allowlist.extend_from_slice(&5u64.to_be_bytes());
        allowlist.extend_from_slice(&2u16.to_be_bytes());
        allowlist.extend_from_slice(&[7; 32 + 64]);
        let key = crate::group_key::encode(&kaonic_mesh::group::GroupKeyMaterial::generate(2));
        let message = Message::Provision { cert: vec![5; 354], allowlist: allowlist.clone(), group_key: Some(key) };
        assert_eq!(Message::decode(&message.encode()), Some(message));
        // A list that blocks someone is longer; the key still follows it.
        let admin = kaonic_pki::SigningKey::from_bytes(&[3; 32]);
        let blocking = Allowlist::sign_with_blocked(&admin, 6, [IdentityHash([1; 16])], [IdentityHash([2; 16])]).unwrap();
        let key = crate::group_key::encode(&kaonic_mesh::group::GroupKeyMaterial::generate(3));
        let message = Message::Provision { cert: vec![5; 354], allowlist: blocking.as_bytes().to_vec(), group_key: Some(key) };
        assert_eq!(Message::decode(&message.encode()), Some(message));
        // From an admin that sends no key.
        let old = Message::Provision { cert: vec![5; 354], allowlist, group_key: None };
        assert_eq!(Message::decode(&old.encode()), Some(old));
    }

    #[test]
    fn messages_round_trip_and_garbage_is_ignored() {
        for message in [
            Message::Request {
                root: vec![1, 2, 3],
            },
            Message::Csr { csr: vec![4; 240] },
            Message::Provision {
                cert: vec![5; 354],
                allowlist: vec![6; 95],
                group_key: None,
            },
            Message::Result {
                status: Status::Taken,
                message: "taken".into(),
            },
        ] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
        assert_eq!(Message::decode(b"KPV1\x03\xff\xff"), None);
        assert_eq!(Message::decode(b"KPV2\x01"), None);
        assert_eq!(Message::decode(b"KPV1\x09"), None);
        let Some(Message::Result { message, .. }) = Message::decode(b"KPV1\x04\x02bad\x1b[2Jtext")
        else {
            panic!()
        };
        assert_eq!(message, "bad[2Jtext");
    }
}
