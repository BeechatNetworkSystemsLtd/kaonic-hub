//! A peer whose link closes leaves nothing behind on this node: no routes, counters or
//! retransmission state, so peers that come and go for months do not add up.

mod common;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use common::{ISSUED_AT, Keys, all_up, auth, init_log, node_limited};
use kaonic_vpn::forward::Rule;
use kaonic_vpn::service::VpnLimits;
use kaonic_vpn::share::ShareSettings;
use kaonic_sim_air::{Air, MediumConfig};
use kaonic_pki::Certificate;

const SA: Ipv4Addr = Ipv4Addr::new(239, 2, 3, 1);
const PHONE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 10, 23), 40123);

#[tokio::test]
async fn a_closed_peer_leaves_no_state() {
    init_log();
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 5).await.unwrap();
    let (a_keys, b_keys) = (Keys::new(1), Keys::new(2));
    let root = Certificate::new_root(&a_keys.identity(), &a_keys.ed25519, ISSUED_AT).unwrap();
    let admin_id = a_keys.identity().hash().0;
    let share = || ShareSettings { share_lans: false, lan_interfaces: vec!["br0".to_owned()], ..ShareSettings::default() };
    let limits = VpnLimits { arq: true, ..VpnLimits::default() };
    let rules = vec![Rule::new("sa", SA, 6969)];
    let a = node_limited(&air, "a", &a_keys, admin_id, auth(&a_keys, &root, &a_keys, &[&b_keys]), share(), rules.clone(), limits.clone()).await;
    let b = node_limited(&air, "b", &b_keys, admin_id, auth(&a_keys, &root, &b_keys, &[&b_keys]), share(), rules, limits).await;
    all_up(&[&a, &b]).await;

    // Traffic to b: counted, and numbered for retransmission.
    a.vpn.lan_datagram("br0", PHONE, SA, 6969, b"hello b").await;
    let b_id = b_keys.identity().hash().to_hex();
    assert!(a.vpn.status().peers.iter().any(|peer| peer.peer == b_id && peer.counters.tx_packets > 0));
    assert!(a.vpn.reliable.stats().contains_key(&b_id));

    // a's links close (it was unprovisioned): b is forgotten.
    a.links.set_auth(None).await;
    let mut gone = false;
    for _ in 0..100 {
        if a.vpn.status().peers.is_empty() && a.vpn.reliable.stats().is_empty() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gone, "a still holds b: {:?}, arq {:?}", a.vpn.status().peers, a.vpn.reliable.stats().keys().collect::<Vec<_>>());
    assert!(a.vpn.status().remote.is_empty());
}
