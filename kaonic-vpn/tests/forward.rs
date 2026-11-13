//! Multicast forwarding between three nodes on the emulated channel (`kaonic-sim-air`). A
//! datagram heard on one node's LAN comes out once on the others' LANs where a rule matches,
//! via a relay when out of range, and never comes back.

mod common;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use common::{ISSUED_AT, Keys, Node, all_up, auth, counters, init_log, node};
use kaonic_vpn::forward::{Direction, Emit, Rule, presets};
use kaonic_sim_air::{Air, MediumConfig};
use kaonic_pki::Certificate;

const SA: Ipv4Addr = Ipv4Addr::new(239, 2, 3, 1);
const MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PHONE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 168, 10, 23), 40123);

/// The next datagram `node` would send on its LAN, within `wait`.
async fn emitted(node: &mut Node, wait: Duration) -> Option<Emit> {
    tokio::time::timeout(wait, node.ends.emits.recv()).await.ok().flatten()
}

/// Feeds `payload` to `from`'s LAN until `to` emits it (the channel loses frames). Each try
/// gets a number appended so it isn't a duplicate.
async fn carried(from: &Node, to: &mut Node, group: Ipv4Addr, port: u16, payload: &str) -> Option<Emit> {
    for attempt in 0..8 {
        let payload = format!("{payload} {attempt}");
        from.vpn.lan_datagram("br0", PHONE, group, port, payload.as_bytes()).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        while let Some(emit) = emitted(to, deadline.saturating_duration_since(tokio::time::Instant::now())).await {
            if emit.payload == payload.as_bytes() {
                return Some(emit);
            }
        }
    }
    None
}

#[tokio::test]
async fn multicast_crosses_the_mesh_by_rule_once_and_does_not_come_back() {
    init_log();
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 11).await.unwrap();
    // c reaches a only through b.
    air.block("a", "c");

    let (a_keys, b_keys, c_keys) = (Keys::new(1), Keys::new(2), Keys::new(3));
    let root = Certificate::new_root(&a_keys.identity(), &a_keys.ed25519, ISSUED_AT).unwrap();
    let admin_id = a_keys.identity().hash().0;
    let listed = [&b_keys, &c_keys];
    let atak = || presets().into_iter().find(|preset| preset.id == "atak").expect("the ATAK preset").rules;
    // a and c forward ATAK both ways; b has no rule at all; c also takes mDNS from the mesh.
    let mdns_out = Rule { direction: Direction::ToMesh, ..Rule::new("mdns", MDNS, 5353) };
    let mdns_in = Rule { direction: Direction::FromMesh, ..Rule::new("mdns", MDNS, 5353) };
    // Start nodes seconds apart. Otherwise a's and c's HELLOs (hidden from each other) would
    // always collide at b.
    let mut a = node(&air, "a", &a_keys, admin_id, auth(&a_keys, &root, &a_keys, &listed), "br0", [atak(), vec![mdns_out]].concat()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut b = node(&air, "b", &b_keys, admin_id, auth(&a_keys, &root, &b_keys, &listed), "br0", Vec::new()).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let mut c = node(&air, "c", &c_keys, admin_id, auth(&a_keys, &root, &c_keys, &listed), "br0", [atak(), vec![mdns_in]].concat()).await;

    all_up(&[&a, &b, &c]).await;

    // A phone behind a sends situational awareness: it comes out on c's LAN, two hops away.
    let emit = carried(&a, &mut c, SA, 6969, "<event uid='phone-a'/>").await.expect("a's datagram reaches c's LAN");
    assert_eq!((emit.rule.as_str(), emit.interfaces.clone(), emit.address, emit.port, emit.ttl), ("atak-sa", vec!["br0".to_owned()], SA, 6969, 1));
    assert!(counters(&a, "atak-sa").to_mesh_packets >= 1);
    assert_eq!(counters(&c, "atak-sa").from_mesh_packets, 1);
    // It also reached c's own stack, from a's tunnel address.
    let packet = tokio::time::timeout(Duration::from_secs(2), c.ends.tun.recv()).await.expect("c's TUN got the packet").unwrap();
    let summary = kaonic_vpn::ip::summarize(&packet).unwrap();
    assert_eq!((summary.src, summary.dst, summary.ports), (a.vpn.status().tunnel, SA, Some((40123, 6969))));
    assert_eq!(packet[8], 1, "one hop in the tunnel");

    // c's emission heard back on c's LAN is not sent to the mesh again, so a never gets its
    // own phone's datagram back.
    let before = counters(&c, "atak-sa");
    c.vpn.lan_datagram("br0", SocketAddrV4::new(Ipv4Addr::new(192, 168, 10, 1), 50000), SA, 6969, &emit.payload).await;
    let after = counters(&c, "atak-sa");
    assert_eq!((after.duplicates, after.to_mesh_packets), (before.duplicates + 1, before.to_mesh_packets));
    assert!(emitted(&mut a, Duration::from_secs(3)).await.is_none(), "a emitted something: the datagram came back");

    // b got every flooded packet too, and has no rule: nothing comes out on its LAN.
    assert!(emitted(&mut b, Duration::from_millis(200)).await.is_none());
    assert!(b.vpn.forward_status().is_empty());

    // The other way, and the other rule.
    let emit = carried(&c, &mut a, Ipv4Addr::new(224, 10, 10, 1), 17012, "chat from c").await.expect("c's chat reaches a's LAN");
    assert_eq!((emit.rule.as_str(), emit.port), ("atak-chat", 17012));

    // A group with no rule stays on the LAN. mDNS, normally never flooded, crosses one way
    // once a rule names it.
    a.vpn.lan_datagram("br0", PHONE, Ipv4Addr::new(239, 9, 9, 9), 6969, b"nobody asked").await;
    let emit = carried(&a, &mut c, MDNS, 5353, "mdns query").await.expect("mDNS crosses by rule");
    assert_eq!(emit.rule, "mdns");
    c.vpn.lan_datagram("br0", PHONE, MDNS, 5353, b"mdns from c").await;
    assert!(emitted(&mut a, Duration::from_secs(3)).await.is_none(), "c's mDNS rule is from_mesh only");

    // A chatty app: the rule's burst goes out, the rest is dropped.
    let before = counters(&a, "atak-chat");
    for n in 0..40 {
        a.vpn.lan_datagram("br0", PHONE, Ipv4Addr::new(224, 10, 10, 1), 17012, format!("flood {n}").as_bytes()).await;
    }
    let after = counters(&a, "atak-chat");
    let passed = (after.to_mesh_packets + after.not_sent) - (before.to_mesh_packets + before.not_sent);
    assert!(passed <= 11, "{passed} of 40 passed a rule of 2/s with a burst of 10");
    assert!(after.rate_limited - before.rate_limited >= 29);

    // New rules apply at once: with none, a forwards nothing.
    a.vpn.set_forward(Vec::new());
    assert!(a.vpn.forward_rules().is_empty());
    a.vpn.lan_datagram("br0", PHONE, SA, 6969, b"after the rules went").await;
    while let Some(emit) = emitted(&mut c, Duration::from_secs(3)).await {
        assert!(emit.payload.starts_with(b"flood "), "c emitted {:?} after a's rules were removed", String::from_utf8_lossy(&emit.payload));
    }
}
