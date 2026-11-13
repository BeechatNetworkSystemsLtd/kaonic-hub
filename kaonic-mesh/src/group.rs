//! A Reticulum GROUP channel: one packet, encrypted with the network's group key, heard by
//! every neighbour at once. Push-to-talk speaks on it.
//!
//! Reticulum never relays GROUP packets (it drops any with hops > 0): what reaches further
//! nodes is the hubs' own job (PTT re-sends what it hears, with its own suppression).
//!
//! What goes inside the encrypted packet is `epoch u8 | payload`: the key epoch the sender
//! used, so a receiver can tell traffic of a node that has not caught up with a rotation. The
//! destination is `kaonic.<aspect>` with an identity derived from that name, so every node
//! computes the same address; the key alone decides who can read it.

use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use reticulum::crypt::group::GroupKey;
use reticulum::destination::{DestinationName, GroupInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::{GroupIdentity, PrivateIdentity};
use tokio::sync::{broadcast, Mutex};

use crate::node::Mesh;

/// Bytes of a group key (Reticulum's Fernet signing and encryption keys).
pub const KEY_LENGTH: usize = reticulum::crypt::group::GROUP_KEY_LENGTH;
/// After a rotation, packets under the previous key are read for this long.
pub const KEY_GRACE: Duration = Duration::from_secs(600);

/// Serialized Reticulum packet bytes one LDPC radio frame carries.
const FRAME_PACKET: usize = 896;
/// A GROUP data packet's header (type 1, no transport id).
const HEADER: usize = 19;
/// Fernet: IV and HMAC around the AES-CBC ciphertext, padded to 16 with at least one byte.
const FERNET_IV: usize = 16;
const FERNET_HMAC: usize = 32;

/// A group key and its epoch (which rotation it is).
#[derive(Clone)]
pub struct GroupKeyMaterial {
    pub epoch: u8,
    /// [`KEY_LENGTH`] bytes.
    pub key: Vec<u8>,
}

impl GroupKeyMaterial {
    /// A fresh random key for `epoch`.
    pub fn generate(epoch: u8) -> Self {
        Self { epoch, key: GroupKey::new_rand(OsRng).as_bytes().to_vec() }
    }

    /// As stored: `epoch u8 | key`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.key.len());
        out.push(self.epoch);
        out.extend_from_slice(&self.key);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&epoch, key) = bytes.split_first()?;
        (key.len() == KEY_LENGTH).then(|| Self { epoch, key: key.to_vec() })
    }

    fn group_key(&self) -> io::Result<GroupKey> {
        GroupKey::new_from_slice(&self.key).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("a group key is {KEY_LENGTH} bytes")))
    }
}

impl std::fmt::Debug for GroupKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key itself.
        f.debug_struct("GroupKeyMaterial").field("epoch", &self.epoch).finish_non_exhaustive()
    }
}

/// What arrived on the channel.
#[derive(Clone, Debug)]
pub struct GroupMessage {
    pub payload: Arc<Vec<u8>>,
    /// The key epoch the sender used.
    pub epoch: u8,
    /// The radio's signal for the last frame heard (the radio cannot tell per packet yet).
    pub rssi: Option<i8>,
}

pub struct GroupChannel {
    mesh: Arc<Mesh>,
    destination: Arc<Mutex<GroupInputDestination>>,
    address: AddressHash,
    epoch: AtomicU8,
    messages: broadcast::Sender<GroupMessage>,
}

impl GroupChannel {
    /// Registers the GROUP destination `kaonic.<aspect>` (e.g. aspect "ptt.all") with this key
    /// and starts delivering what arrives.
    pub async fn open(mesh: &Arc<Mesh>, aspect: &str, key: GroupKeyMaterial) -> io::Result<Arc<Self>> {
        let group_key = key.group_key()?;
        let identity = PrivateIdentity::new_from_name(&format!("kaonic.{aspect}"));
        let destination = mesh
            .transport()
            .lock()
            .await
            .add_group_destination(GroupIdentity::new(*identity.as_identity(), group_key), DestinationName::new("kaonic", aspect))
            .await;
        let address = destination.lock().await.desc.address_hash;
        let (messages, _) = broadcast::channel(256);
        let channel = Arc::new(Self { mesh: mesh.clone(), destination, address, epoch: AtomicU8::new(key.epoch), messages });

        let mut received = mesh.transport().lock().await.received_data_events();
        let delivery = Arc::downgrade(&channel);
        tokio::spawn(async move {
            loop {
                let data = match received.recv().await {
                    Ok(data) => data,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        log::warn!("group: missed {missed} packets");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                let Some(channel) = delivery.upgrade() else { return };
                if data.destination != channel.address {
                    continue;
                }
                let Some((&epoch, payload)) = data.data.as_slice().split_first() else { continue };
                let rssi = channel.mesh.counters().last_rssi;
                let _ = channel.messages.send(GroupMessage { payload: Arc::new(payload.to_vec()), epoch, rssi });
            }
        });
        log::info!("group: kaonic.{aspect} open, key epoch {}", key.epoch);
        Ok(channel)
    }

    /// Encrypts with the current epoch's key and broadcasts one GROUP packet; false if it
    /// could not be sent (too large, or the transport refused it).
    pub async fn send(&self, payload: &[u8]) -> bool {
        if payload.len() > self.max_payload() {
            return false;
        }
        let mut plain = Vec::with_capacity(1 + payload.len());
        plain.push(self.epoch());
        plain.extend_from_slice(payload);
        self.mesh.transport().lock().await.send_group(&self.destination, &plain).await.is_ok()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GroupMessage> {
        self.messages.subscribe()
    }

    /// Rotation: the new epoch becomes current for sending; the previous one is still
    /// accepted for [`KEY_GRACE`]. A key of the wrong length is ignored (and logged).
    pub async fn set_key(&self, key: GroupKeyMaterial) {
        let group_key = match key.group_key() {
            Ok(group_key) => group_key,
            Err(error) => {
                log::error!("group: {error}");
                return;
            }
        };
        if self.mesh.transport().lock().await.set_group_key(&self.address, group_key, KEY_GRACE).await {
            let previous = self.epoch.swap(key.epoch, Ordering::Relaxed);
            log::info!("group: key epoch {previous} -> {}", key.epoch);
        }
    }

    pub fn epoch(&self) -> u8 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// The largest payload that still fits one radio frame.
    pub fn max_payload(&self) -> usize {
        max_payload()
    }
}

fn max_payload() -> usize {
    let ciphertext = (FRAME_PACKET - HEADER - FERNET_IV - FERNET_HMAC) / 16 * 16;
    // PKCS7 adds at least one byte; our epoch byte comes first.
    ciphertext - 1 - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_round_trips_and_payloads_fit_a_frame() {
        let key = GroupKeyMaterial::generate(3);
        assert_eq!(key.key.len(), KEY_LENGTH);
        let again = GroupKeyMaterial::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!((again.epoch, again.key), (3, key.key.clone()));
        assert!(GroupKeyMaterial::from_bytes(&[1, 2, 3]).is_none());
        assert_eq!(format!("{key:?}"), "GroupKeyMaterial { epoch: 3, .. }");
        // 1 + 814 bytes pad to 816 of ciphertext: 19 + 16 + 816 + 32 = 883 <= 896.
        assert_eq!(max_payload(), 814);
    }
}
