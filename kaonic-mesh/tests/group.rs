//! The GROUP channel on the emulated radio (`kaonic-sim-air`): one packet reaches every neighbour
//! holding the key, nobody further (relaying is the hubs' job), and after a rotation the
//! previous epoch is still read for the grace period.

use std::sync::Arc;
use std::time::Duration;

use kaonic_mesh::announce::NodeInfo;
use kaonic_mesh::group::{GroupChannel, GroupKeyMaterial, GroupMessage};
use kaonic_mesh::{Mesh, MeshConfig};
use kaonic_sim_air::{Air, MediumConfig};
use rand::rngs::OsRng;
use reticulum::identity::PrivateIdentity;
use tokio::sync::broadcast;

async fn node(air: &Air, name: &str) -> Arc<Mesh> {
    let info = NodeInfo { codename: name.to_owned(), version: "test".into(), is_admin: false, admin_id: None };
    let config = MeshConfig { radio: format!("air://{}/{name}", air.local_addr()), announce_secs: 30, offline_secs: 60, settings: None, ..MeshConfig::default() };
    Mesh::start(PrivateIdentity::new_from_rand(OsRng), info, config).await.expect("mesh starts")
}

/// Sends until `receiver` gets it (the channel loses frames; group packets are not retried).
async fn deliver(from: &GroupChannel, receiver: &mut broadcast::Receiver<GroupMessage>, payload: &[u8]) -> Option<GroupMessage> {
    for _ in 0..10 {
        assert!(from.send(payload).await);
        if let Ok(Ok(message)) = tokio::time::timeout(Duration::from_millis(500), receiver.recv()).await {
            return Some(message);
        }
    }
    None
}

#[tokio::test]
async fn group_packets_reach_neighbours_only_and_survive_a_rotation() {
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 11).await.unwrap();
    air.block("a", "c");
    let (a, b, c) = (node(&air, "a").await, node(&air, "b").await, node(&air, "c").await);
    let key = GroupKeyMaterial::generate(1);
    let a_group = GroupChannel::open(&a, "ptt.all", key.clone()).await.unwrap();
    let b_group = GroupChannel::open(&b, "ptt.all", key.clone()).await.unwrap();
    let c_group = GroupChannel::open(&c, "ptt.all", key.clone()).await.unwrap();
    // A node with another key hears the packets but cannot read them.
    let stranger = node(&air, "d").await;
    let d_group = GroupChannel::open(&stranger, "ptt.all", GroupKeyMaterial::generate(1)).await.unwrap();

    let mut at_b = b_group.subscribe();
    let mut at_c = c_group.subscribe();
    let mut at_d = d_group.subscribe();
    let message = deliver(&a_group, &mut at_b, b"over").await.expect("b hears a");
    assert_eq!((message.payload.as_slice(), message.epoch), (&b"over"[..], 1));
    assert!(at_c.try_recv().is_err(), "c is out of range: group packets are not relayed");
    assert!(at_d.try_recv().is_err(), "d has another key");

    // a and b rotate to epoch 2; c has not caught up and still sends with epoch 1.
    let next = GroupKeyMaterial::generate(2);
    a_group.set_key(next.clone()).await;
    b_group.set_key(next).await;
    assert_eq!(a_group.epoch(), 2);
    let message = deliver(&a_group, &mut at_b, b"new").await.expect("b reads epoch 2");
    assert_eq!(message.epoch, 2);
    let message = deliver(&c_group, &mut at_b, b"old").await.expect("b still reads epoch 1");
    assert_eq!((message.payload.as_slice(), message.epoch), (&b"old"[..], 1));

    assert!(!a_group.send(&vec![0; a_group.max_payload() + 1]).await, "too large for one frame");
    assert!(a_group.send(&vec![0; a_group.max_payload()]).await);
}
