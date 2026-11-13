//! The forwarding LAN sockets on real interfaces: two nodes on the emulated channel, each
//! serving a veth whose other end is a "phone" in its own network namespace. Run it with
//! `emulator/forward-test.sh` (Linux container); ignored elsewhere.
#![cfg(target_os = "linux")]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::{ISSUED_AT, Keys, Node, all_up, auth, counters, init_log, node};
use kaonic_vpn::forward::defaults;
use kaonic_sim_air::{Air, MediumConfig};
use kaonic_pki::Certificate;

/// A phone: `socat` in the namespace `netns`, killed with the test.
struct Phone(Child);

impl Drop for Phone {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Lines the phone in `netns` receives on `listen` (a socat address).
fn receiver(netns: &str, listen: &str) -> (Phone, mpsc::Receiver<String>) {
    let mut child = Command::new("ip").args(["netns", "exec", netns, "socat", "-u", listen, "STDOUT"]).stdout(Stdio::piped()).spawn().expect("socat starts");
    let stdout = child.stdout.take().expect("piped");
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines.send(line);
        }
    });
    (Phone(child), received)
}

/// The phone in `netns` sends one datagram to `to` (a socat address).
fn send(netns: &str, to: &str, text: &str) {
    let mut child = Command::new("ip").args(["netns", "exec", netns, "socat", "-u", "STDIN", to]).stdin(Stdio::piped()).spawn().expect("socat starts");
    child.stdin.take().expect("piped").write_all(format!("{text}\n").as_bytes()).unwrap();
    assert!(child.wait().unwrap().success(), "socat could not send to {to}");
}

/// Sends `text` from one phone until the other receives it (the channel loses frames). Each
/// try gets a number appended so it isn't a duplicate.
async fn carried(netns: &str, to: &str, text: &str, received: &mpsc::Receiver<String>) -> bool {
    for attempt in 0..8 {
        let text = format!("{text} {attempt}");
        send(netns, to, &text);
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if received.try_iter().any(|line| line == text) {
                return true;
            }
        }
    }
    false
}

async fn ready(node: &Node) {
    for _ in 0..100 {
        let statuses = node.vpn.forward_status();
        if statuses.iter().all(|status| !status.lan.is_empty() && status.lan.iter().all(|lan| lan.state == "ready")) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the rules are not ready on the LAN: {:?}", node.vpn.forward_status());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the interfaces and namespaces of emulator/forward-test.sh"]
async fn phones_behind_two_nodes_hear_each_others_multicast_and_broadcast() {
    init_log();
    let air = Air::start("127.0.0.1:0".parse().unwrap(), MediumConfig::default(), 5).await.unwrap();
    let (a_keys, c_keys) = (Keys::new(1), Keys::new(3));
    let root = Certificate::new_root(&a_keys.identity(), &a_keys.ed25519, ISSUED_AT).unwrap();
    let admin_id = a_keys.identity().hash().0;
    let listed = [&c_keys];
    // Default rules. a serves lana (192.168.11.1/24, phone pa at .23), c serves lanc
    // (192.168.12.1/24, phone pc). Both nodes share one network namespace, so datagrams are
    // re-sent from the node's address, not the original sender's.
    let mut a = node(&air, "a", &a_keys, admin_id, auth(&a_keys, &root, &a_keys, &listed), "lana", defaults()).await;
    let mut c = node(&air, "c", &c_keys, admin_id, auth(&a_keys, &root, &c_keys, &listed), "lanc", defaults()).await;
    for node in [&mut a, &mut c] {
        let (_, emits) = tokio::sync::mpsc::channel(1);
        tokio::spawn(kaonic_vpn::lan::run(node.vpn.clone(), std::mem::replace(&mut node.ends.emits, emits)));
    }
    all_up(&[&a, &c]).await;
    ready(&a).await;
    ready(&c).await;

    // Multicast both ways: ATAK's groups and an arbitrary one.
    let (_sa, sa) = receiver("pc", "UDP4-RECV:6969,reuseaddr,ip-add-membership=239.2.3.1:192.168.12.23");
    let (_chat, chat) = receiver("pa", "UDP4-RECV:17012,reuseaddr,ip-add-membership=224.10.10.1:192.168.11.23");
    let (_other, other) = receiver("pc", "UDP4-RECV:41000,reuseaddr,ip-add-membership=239.77.1.9:192.168.12.23");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(carried("pa", "UDP4-DATAGRAM:239.2.3.1:6969", "sa from pa", &sa).await, "pa's multicast did not reach pc: a {:?}, c {:?}", a.vpn.forward_status(), c.vpn.forward_status());
    assert!(carried("pc", "UDP4-DATAGRAM:224.10.10.1:17012", "chat from pc", &chat).await, "pc's multicast did not reach pa: a {:?}, c {:?}", a.vpn.forward_status(), c.vpn.forward_status());
    assert!(carried("pa", "UDP4-DATAGRAM:239.77.1.9:41000", "some other application", &other).await, "a group without a rule of its own did not cross");
    // A node's own emission is not sent back to the mesh.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (a_all, c_all) = (counters(&a, "multicast"), counters(&c, "multicast"));
    assert!(a_all.to_mesh_packets >= 2 && c_all.from_mesh_packets >= 2 && c_all.to_mesh_packets >= 1 && a_all.from_mesh_packets >= 1, "a {a_all:?}, c {c_all:?}");
    assert!(a_all.from_mesh_packets <= c_all.to_mesh_packets && c_all.from_mesh_packets <= a_all.to_mesh_packets, "more came out than went in: a {a_all:?}, c {c_all:?}");
    assert_eq!((a_all.looped, c_all.looped, a_all.emit_errors, c_all.emit_errors), (0, 0, 0, 0), "a {a_all:?}, c {c_all:?}");

    // Unicast to the node and LAN chatter are not forwarded.
    let before = (counters(&a, "multicast"), counters(&a, "broadcast"));
    send("pa", "UDP4-DATAGRAM:192.168.11.1:6969", "to the node itself");
    send("pa", "UDP4-DATAGRAM:224.0.0.251:5353", "mdns");
    send("pa", "UDP4-DATAGRAM:192.168.11.255:67,broadcast", "dhcp");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!((counters(&a, "multicast"), counters(&a, "broadcast")), before);

    // Subnet broadcast arrives as the far network's broadcast; limited broadcast as is.
    // A node does not hear its own emission.
    let (_found, found) = receiver("pc", "UDP4-RECV:4000,reuseaddr");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(carried("pa", "UDP4-DATAGRAM:192.168.11.255:4000,broadcast", "who is there", &found).await, "pa's broadcast did not reach pc: a {:?}, c {:?}", a.vpn.forward_status(), c.vpn.forward_status());
    assert!(carried("pa", "UDP4-DATAGRAM:255.255.255.255:4000,broadcast,so-bindtodevice=eth0", "anyone at all", &found).await, "pa's limited broadcast did not reach pc");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (a_found, c_found) = (counters(&a, "broadcast"), counters(&c, "broadcast"));
    assert_eq!((c_found.to_mesh_packets, a_found.from_mesh_packets, c_found.looped), (0, 0, 0), "a {a_found:?}, c {c_found:?}");

    // The interface is re-created with a new index: the rule waits, then works again.
    let ip = |args: &str| assert!(Command::new("sh").args(["-c", &format!("ip {args}")]).status().unwrap().success(), "ip {args}");
    ip("link del lanc");
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(c.vpn.forward_status().iter().all(|status| status.lan.iter().all(|lan| lan.state == "waiting")), "{:?}", c.vpn.forward_status());
    ip("link add lanc type veth peer name eth0 netns pc");
    ip("addr add 192.168.12.1/24 dev lanc");
    ip("link set lanc up");
    ip("-n pc addr add 192.168.12.23/24 dev eth0");
    ip("-n pc link set eth0 up");
    ip("-n pc route add 224.0.0.0/4 dev eth0");
    ready(&c).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (_again, sa) = receiver("pc", "UDP4-RECV:6969,reuseaddr,ip-add-membership=239.2.3.1:192.168.12.23");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(carried("pa", "UDP4-DATAGRAM:239.2.3.1:6969", "sa after the interface came back", &sa).await, "nothing after lanc came back: c {:?}", c.vpn.forward_status());
}
