//! Several meshes on one emulated channel (`kaonic-sim-air`): they hear each other's
//! announces, and a node out of range of another learns it through a relay.

use std::sync::Arc;
use std::time::Duration;

use kaonic_mesh::announce::{Announced, NodeInfo};
use kaonic_mesh::{Mesh, MeshConfig};
use kaonic_sim_air::{Air, MediumConfig};
use rand::rngs::OsRng;
use reticulum::identity::PrivateIdentity;

async fn node(air: &Air, name: &str) -> Arc<Mesh> {
    let info = NodeInfo { codename: name.to_owned(), version: "test".into(), is_admin: false, admin_id: None };
    let config = MeshConfig { radio: format!("air://{}/{name}", air.local_addr()), announce_secs: 1, offline_secs: 30, settings: None, ..MeshConfig::default() };
    Mesh::start(PrivateIdentity::new_from_rand(OsRng), info, config).await.expect("mesh starts")
}

/// The peer `codename` as `mesh` knows it: (hops, via).
fn heard(mesh: &Mesh, codename: &str) -> Option<(u8, Option<String>)> {
    mesh.peers().into_iter().find(|peer| matches!(&peer.announced, Announced::Hub(info) if info.codename == codename)).map(|peer| (peer.hops, peer.via))
}

async fn wait_for(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting until {what}");
}

#[tokio::test]
async fn neighbours_hear_each_other_and_relays_reach_further() {
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 1).await.unwrap();
    // a and c are out of range of each other; b hears both.
    air.block("a", "c");
    let a = node(&air, "a").await;
    let b = node(&air, "b").await;
    let c = node(&air, "c").await;

    wait_for("b hears a and c directly", || heard(&b, "a").is_some_and(|(hops, _)| hops == 0) && heard(&b, "c").is_some_and(|(hops, _)| hops == 0)).await;
    wait_for("c learns a through b", || heard(&c, "a").is_some_and(|(hops, _)| hops == 1)).await;
    wait_for("a learns c through b", || heard(&a, "c").is_some_and(|(hops, _)| hops == 1)).await;
    let (_, via) = heard(&c, "a").unwrap();
    assert_eq!(via.as_deref(), Some(b.identity_hash()), "the relay is b");

    // a and c are hidden from each other, so their frames can collide at b.
    let stats = air.stats();
    assert!(stats.iter().all(|(_, stats)| stats.sent > 0 && stats.received > 0));
}

#[tokio::test]
async fn the_peer_table_stays_within_its_cap() {
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 2).await.unwrap();
    let info = NodeInfo { codename: "small".to_owned(), version: "test".into(), is_admin: false, admin_id: None };
    let config = MeshConfig { radio: format!("air://{}/small", air.local_addr()), announce_secs: 1, offline_secs: 30, settings: None, max_peers: 1, ..MeshConfig::default() };
    let small = Mesh::start(PrivateIdentity::new_from_rand(OsRng), info, config).await.unwrap();
    let _b = node(&air, "b").await;
    let _c = node(&air, "c").await;
    // Both are heard (each replaces the other), but the table never holds more than one.
    let mut heard = std::collections::HashSet::new();
    // Up to 30 s: announces are every second, but a busy machine (the whole suite) is slow.
    for _ in 0..300 {
        let peers = small.peers();
        assert!(peers.len() <= 1, "{} peers", peers.len());
        heard.extend(peers.into_iter().map(|peer| peer.id));
        if heard.len() == 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("heard only {} of the two nodes", heard.len());
}
