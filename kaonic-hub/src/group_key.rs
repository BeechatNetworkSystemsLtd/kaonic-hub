//! The network's group key for push-to-talk, and the GROUP
//! channel it opens.
//!
//! - Stored in the keystore as `ptt/group-key` = `epoch u8 | key`.
//! - The admin device makes epoch 1 (at setup, or the first time it is needed) and hands the
//!   current key to every node in `PROVISION`.
//! - Revoking a node rotates it: the admin makes the next epoch and sends it to every node it
//!   has an authenticated link to. A node that missed it gets it again whenever its link to
//!   the admin comes up. Nodes keep reading the previous epoch for ten minutes.
//! - On the links the key travels as a mux control message on stream 3:
//!   `"KGK1" | epoch u8 | key`. A node takes it only from the admin's authenticated link.

use std::collections::VecDeque;
use std::sync::Arc;

use kaonic_mesh::group::{GroupChannel, GroupKeyMaterial};
use kaonic_mux::{Kind, Message};
use tokio::sync::broadcast;

use crate::app::App;
use crate::provision;

pub const PTT_GROUP_KEY: &str = "ptt/group-key";
/// The GROUP destination push-to-talk speaks on: `kaonic.ptt.all`.
pub const ASPECT: &str = "ptt.all";
/// The mux stream carrying group keys on the links.
pub const KEY_STREAM: u8 = 3;
const KEY_MAGIC: &[u8; 4] = b"KGK1";

/// `"KGK1" | epoch | key`, as in `PROVISION` and on the links.
pub fn encode(key: &GroupKeyMaterial) -> Vec<u8> {
    let mut out = KEY_MAGIC.to_vec();
    out.extend_from_slice(&key.to_bytes());
    out
}

pub fn decode(bytes: &[u8]) -> Option<GroupKeyMaterial> {
    GroupKeyMaterial::from_bytes(bytes.strip_prefix(KEY_MAGIC)?)
}

/// A short public fingerprint of a key for logs (the first 4 bytes of its SHA-256): equal on
/// every node holding the same key, and says nothing about the key itself.
pub fn fingerprint(key: &GroupKeyMaterial) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(&key.key)[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The key this node holds.
pub async fn stored(app: &App) -> Option<GroupKeyMaterial> {
    let bytes = app.secrets(|keys| Ok(keys.get(PTT_GROUP_KEY).map(|secret| secret.expose().to_vec()))).await.ok()??;
    GroupKeyMaterial::from_bytes(&bytes)
}

async fn store(app: &App, key: &GroupKeyMaterial) -> bool {
    let bytes = key.to_bytes();
    app.secrets(move |keys| keys.set(PTT_GROUP_KEY, bytes)).await.is_ok()
}

/// On the admin device: the current key, made (epoch 1) if there is none yet.
pub async fn admin_key(app: &App) -> Option<GroupKeyMaterial> {
    if !provision::is_admin_device(app).await {
        return None;
    }
    if let Some(key) = stored(app).await {
        return Some(key);
    }
    let key = GroupKeyMaterial::generate(1);
    if !store(app, &key).await {
        return None;
    }
    log::info!("ptt: made the group key, epoch {}", key.epoch);
    Some(key)
}

/// Opens the GROUP channel with the stored key (the admin makes one if needed), and starts
/// listening for keys on the links. Does nothing without a mesh.
pub async fn start(app: &App) {
    let Some(mesh) = app.mesh.clone() else { return };
    let key = match admin_key(app).await {
        Some(key) => Some(key),
        None => stored(app).await,
    };
    if let Some(key) = key {
        open(app, &mesh, key).await;
    }
    spawn_listeners(app);
}

async fn open(app: &App, mesh: &Arc<kaonic_mesh::Mesh>, key: GroupKeyMaterial) {
    log::info!("ptt: group key epoch {} ({})", key.epoch, fingerprint(&key));
    match GroupChannel::open(mesh, ASPECT, key).await {
        Ok(channel) => {
            let _ = app.ptt_group.set(channel);
        }
        Err(error) => log::error!("ptt: cannot open the group channel: {error}"),
    }
}

/// Whether epoch `new` comes after `current` (epochs wrap at 255).
pub fn is_newer(new: u8, current: u8) -> bool {
    (new.wrapping_sub(current) as i8) > 0
}

/// A key from the admin (in a first `PROVISION`, or on its authenticated link): stored and
/// used only if its epoch is newer than ours, so a recorded old key cannot roll the group
/// back. The admin device makes its own keys and takes none.
pub async fn adopt(app: &App, key: GroupKeyMaterial) -> bool {
    if provision::is_admin_device(app).await {
        log::warn!("ptt: the admin device ignored a group key (epoch {})", key.epoch);
        return false;
    }
    if let Some(current) = stored(app).await
        && !is_newer(key.epoch, current.epoch)
    {
        if current.epoch != key.epoch || current.key != key.key {
            log::warn!("ptt: ignored a group key of epoch {} (we have {})", key.epoch, current.epoch);
        }
        return false;
    }
    if !store(app, &key).await {
        log::error!("ptt: cannot store the group key");
        return false;
    }
    log::info!("ptt: group key epoch {} ({}) from the admin", key.epoch, fingerprint(&key));
    match app.ptt_group.get() {
        Some(channel) => channel.set_key(key).await,
        None => {
            if let Some(mesh) = app.mesh.clone() {
                open(app, &mesh, key).await;
            }
        }
    }
    true
}

/// On the admin device, after a revocation: the next epoch, used at once and sent to every
/// node still linked (the revoked one's link is already closed).
pub async fn rotate(app: &App) {
    let Some(current) = admin_key(app).await else { return };
    let next = GroupKeyMaterial::generate(current.epoch.wrapping_add(1).max(1));
    if !store(app, &next).await {
        log::error!("ptt: cannot store the new group key");
        return;
    }
    log::info!("ptt: group key rotated to epoch {} ({})", next.epoch, fingerprint(&next));
    if let Some(channel) = app.ptt_group.get() {
        channel.set_key(next.clone()).await;
    }
    if let Some(links) = app.links.get() {
        for peer in links.established() {
            send(app, &peer, &next).await;
        }
    }
}

async fn send(app: &App, peer: &str, key: &GroupKeyMaterial) -> bool {
    let Some(links) = app.links.get() else { return false };
    let mut queue: VecDeque<Message> = [Message { kind: Kind::Control, stream: KEY_STREAM, payload: encode(key) }].into();
    let Some(packet) = kaonic_mux::pack(&mut queue, 799).0 else { return false };
    let sent = links.send(peer, &packet).await;
    if sent {
        log::debug!("ptt: sent group key epoch {} to {peer}", key.epoch);
    }
    sent
}

/// The admin re-sends the key whenever a link to a node comes up (it may have missed a
/// rotation); every node takes keys that arrive on the admin's link.
fn spawn_listeners(app: &App) {
    let Some(links) = app.links.get().cloned() else { return };
    let mut changes = links.changes();
    let admin_app = app.clone();
    let admin_links = links.clone();
    tokio::spawn(async move {
        loop {
            let peer = match changes.recv().await {
                Ok(peer) => peer,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            if !admin_links.established().contains(&peer) {
                continue;
            }
            if let Some(key) = admin_key(&admin_app).await {
                send(&admin_app, &peer, &key).await;
            }
        }
    });

    let mut received = links.subscribe();
    let node_app = app.clone();
    tokio::spawn(async move {
        loop {
            let message = match received.recv().await {
                Ok(message) => message,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Ok(frames) = kaonic_mux::parse(&message.packet) else { continue };
            for frame in frames {
                if frame.kind != Kind::Control || frame.stream != KEY_STREAM {
                    continue;
                }
                let admin = crate::api::our_admin(&node_app).await.ok().flatten();
                if admin.as_deref() != Some(message.peer.as_str()) {
                    static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
                    if NOTED.due() {
                        log::warn!("ptt: ignored a group key from {}, not the admin", message.peer);
                    } else {
                        log::debug!("ptt: ignored a group key from {}, not the admin", message.peer);
                    }
                    continue;
                }
                if let Some(key) = decode(frame.payload) {
                    adopt(&node_app, key).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_are_newer_across_the_wrap() {
        assert!(is_newer(2, 1) && is_newer(1, 255) && is_newer(100, 1));
        assert!(!is_newer(1, 1) && !is_newer(1, 2) && !is_newer(255, 1) && !is_newer(100, 200));
        // 57 rotations after 200, past the wrap.
        assert!(is_newer(1, 200));
    }

    #[test]
    fn keys_round_trip_on_the_wire() {
        let key = GroupKeyMaterial::generate(7);
        let decoded = decode(&encode(&key)).unwrap();
        assert_eq!((decoded.epoch, &decoded.key), (7, &key.key));
        assert!(decode(b"KGK2\x01").is_none());
        assert!(decode(&encode(&key)[..20]).is_none());
    }
}
