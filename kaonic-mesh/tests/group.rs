//! The GROUP channel on the emulated radio (`kaonic-sim-air`): one packet reaches every node
//! holding the key, nodes out of range through a relay, each once; and after a rotation the
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
async fn group_packets_are_relayed_once_and_survive_a_rotation() {
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
    assert_eq!((message.payload.as_slice(), message.epoch, message.hops), (&b"over"[..], 1, 0));
    // c is out of a's range: b relays it, after its random wait.
    let relayed = tokio::time::timeout(Duration::from_secs(2), at_c.recv()).await.expect("b relays to c").unwrap();
    assert_eq!((relayed.payload.as_slice(), relayed.hops), (&b"over"[..], 1));
    // Each packet reaches c at most once: ten distinct ones, each sent once (the air may lose some).
    tokio::time::sleep(Duration::from_millis(300)).await;
    while at_c.try_recv().is_ok() {}
    for n in 0..10u8 {
        assert!(a_group.send(&[b'#', n]).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut heard = Vec::new();
    while let Ok(message) = at_c.try_recv() {
        heard.push(message.payload[1]);
    }
    let mut unique = heard.clone();
    unique.dedup();
    assert_eq!(heard, unique, "a packet reached c twice");
    assert!(!heard.is_empty(), "b relayed none of them");
    assert!(at_d.try_recv().is_err(), "d has another key");
    // a's own packet relayed back by b is dropped, not delivered to a.
    let mut at_a = a_group.subscribe();
    assert!(deliver(&b_group, &mut at_a, b"back").await.is_some());
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(echo) = at_a.try_recv() {
        assert_ne!(echo.payload.as_slice(), b"over", "our own packet came back");
    }

    while at_b.try_recv().is_ok() {}

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
