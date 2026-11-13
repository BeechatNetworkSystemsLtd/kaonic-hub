//! LAN sockets for [`crate::forward`]: they hear multicast and broadcast on the client
//! interfaces and re-send what arrives from the mesh.
//!
//! - Listening uses a packet socket per interface with a kernel filter for UDP in multicast
//!   and broadcast frames. It hears every group and port without joining any, and skips
//!   frames this node sends.
//! - Sending uses two sockets per interface, with multicast loopback off: a raw socket that
//!   keeps the original sender's address and port, and a plain UDP socket for rules that
//!   don't keep the source (or when raw sockets are not allowed).
//! - Every few seconds, and when rules change, sockets are re-matched to rules and
//!   interfaces. Late or re-created interfaces get new sockets; failed ones are retried.
//! - A datagram is accepted only from an address on one of the interface's networks.
//!
//! Errors are logged, shown in the rule's state, and retried; nothing stops for good.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::forward::{self, Emit, LanState};
use crate::ip::Cidr;
use crate::kernel;
use crate::service::Vpn;

/// How often sockets are re-matched to the rules.
const RECHECK: Duration = Duration::from_secs(5);
/// Receive buffer size; larger than any packet a rule carries.
const BUFFER: usize = 4096;

/// This node's addresses and networks, refreshed on each check.
#[derive(Default)]
struct Known {
    /// Our addresses, on any interface.
    local: Vec<Ipv4Addr>,
    /// Connected networks per interface.
    networks: HashMap<String, Vec<Cidr>>,
}

struct Listener {
    index: u32,
    task: JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Emitter {
    index: u32,
    socket: UdpSocket,
    /// Sends whole IPv4 packets with the original source. None if raw sockets are not allowed.
    raw: Option<Socket>,
}

fn interface_index(name: &str) -> u32 {
    let Ok(name) = std::ffi::CString::new(name) else { return 0 };
    // SAFETY: a valid C string for the length of the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

fn option<T>(fd: i32, level: i32, name: i32, value: &T) -> io::Result<()> {
    // SAFETY: the option takes a `T`, which lives for the call.
    if unsafe { libc::setsockopt(fd, level, name, std::ptr::from_ref(value).cast(), size_of::<T>() as libc::socklen_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A socket that receives every incoming UDP/IPv4 packet in a multicast or broadcast frame
/// on the interface, from the IP header on. Not frames this node sends.
fn capture_socket(index: u32) -> io::Result<AsyncFd<OwnedFd>> {
    // No protocol yet, so nothing is queued before the filter is attached.
    // SAFETY: a new socket, owned from here on.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just opened, and nobody else has it.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // Filter: frame type broadcast or multicast, then IP protocol UDP.
    const PKTTYPE: u32 = (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE) as u32;
    let jump = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let mut filter = [
        jump(0x20, 0, 0, PKTTYPE),
        jump(0x15, 1, 0, libc::PACKET_BROADCAST as u32),
        jump(0x15, 0, 3, libc::PACKET_MULTICAST as u32),
        jump(0x30, 0, 0, 9),
        jump(0x15, 0, 1, u32::from(crate::ip::UDP)),
        jump(0x06, 0, 0, 0x0004_0000),
        jump(0x06, 0, 0, 0),
    ];
    let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
    option(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program)?;
    // Also receive groups nobody on this node joined.
    let request = libc::packet_mreq { mr_ifindex: index as i32, mr_type: libc::PACKET_MR_ALLMULTI as u16, mr_alen: 0, mr_address: [0; 8] };
    option(fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &request)?;
    // SAFETY: all zeroes is a valid sockaddr_ll.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    address.sll_ifindex = index as i32;
    // SAFETY: a sockaddr_ll of its own size, for the length of the call.
    if unsafe { libc::bind(fd, (&raw const address).cast(), size_of::<libc::sockaddr_ll>() as libc::socklen_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the socket is owned by the AsyncFd from here on, and closed with it.
    unsafe { AsyncFd::register(socket) }.map_err(io::Error::from)
}

fn new_socket(interface: &str, index: u32, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, kind, Some(protocol))?;
    socket.set_nonblocking(true)?;
    socket.bind_device(Some(interface.as_bytes()))?;
    socket.set_broadcast(true)?;
    socket.set_multicast_loop_v4(false)?;
    let request = libc::ip_mreqn { imr_multiaddr: libc::in_addr { s_addr: 0 }, imr_address: libc::in_addr { s_addr: 0 }, imr_ifindex: index as libc::c_int };
    option(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &request)?;
    Ok(socket)
}

/// The sending sockets for `interface`, with multicast loopback off.
fn emit_sockets(interface: &str, index: u32) -> io::Result<Emitter> {
    let socket = new_socket(interface, index, Type::DGRAM, Protocol::UDP)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    // IPPROTO_RAW: we send the whole packet, IP header included.
    let raw = match new_socket(interface, index, Type::RAW, Protocol::from(libc::IPPROTO_RAW)) {
        Ok(raw) => Some(raw),
        Err(error) => {
            log::warn!("vpn: forward: no raw socket on {interface} ({error}): datagrams are re-emitted from this node's address, not their sender's");
            None
        }
    };
    Ok(Emitter { index, socket: UdpSocket::from_std(socket.into())?, raw })
}

/// The network's broadcast address, if it has one (/30 or shorter).
fn broadcast_of(network: &Cidr) -> Option<Ipv4Addr> {
    (network.prefix_len() <= 30).then(|| network.broadcast())
}

/// The bridge `interface` belongs to, if any. Its traffic is handled on the bridge.
fn bridge_of(interface: &str) -> Option<String> {
    let master = std::fs::read_link(format!("/sys/class/net/{interface}/master")).ok()?;
    std::path::Path::new(&format!("/sys/class/net/{interface}/brport")).exists().then(|| master.file_name().map(|name| name.to_string_lossy().into_owned())).flatten()
}

fn mtu_of(interface: &str) -> usize {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/mtu")).ok().and_then(|text| text.trim().parse().ok()).unwrap_or(1500)
}

/// A warning if the bridge does IGMP snooping with no querier: it forgets listeners after a
/// few minutes and clients stop receiving.
fn snooping_warning(interface: &str) -> Option<String> {
    let read = |file: &str| std::fs::read_to_string(format!("/sys/class/net/{interface}/bridge/{file}")).ok().map(|text| text.trim().to_owned());
    (read("multicast_snooping").as_deref() == Some("1") && read("multicast_querier").as_deref() == Some("0"))
        .then(|| format!("{interface} filters multicast by IGMP snooping and has no querier: clients may stop receiving after a few minutes (set its multicast_querier to 1, or multicast_snooping to 0)."))
}

async fn listen(vpn: Arc<Vpn>, socket: AsyncFd<OwnedFd>, interface: String, known: Arc<Mutex<Known>>) {
    let mut buffer = vec![0u8; BUFFER];
    loop {
        let Ok(mut ready) = socket.readable().await else { return };
        // SAFETY: sockaddr_ll is plain data, filled by the kernel up to the length given.
        let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let read = ready.try_io(|socket| {
            let mut size = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: the buffer and the address live for the call and have the sizes given.
            let length = unsafe { libc::recvfrom(socket.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0, (&raw mut from).cast(), &raw mut size) };
            if length < 0 { Err(io::Error::last_os_error()) } else { Ok(length as usize) }
        });
        let length = match read {
            Ok(Ok(length)) => length,
            Ok(Err(error)) => {
                // The interface may be going away; the next check replaces this socket.
                log::warn!("vpn: forward: reading {interface}: {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => continue,
        };
        let (networks, local) = {
            let known = known.lock().expect("lan lock");
            (known.networks.get(&interface).cloned().unwrap_or_default(), known.local.clone())
        };
        vpn.lan_packet(&interface, from.sll_pkttype == libc::PACKET_BROADCAST as u8, &buffer[..length], &networks, &local).await;
    }
}

#[derive(Default)]
struct Lan {
    listeners: HashMap<String, Listener>,
    emitters: HashMap<String, Emitter>,
    known: Arc<Mutex<Known>>,
    /// Failures already logged, so each is logged once.
    logged: HashSet<String>,
    /// Bridge ports, mapped to their bridge.
    bridged: HashMap<String, String>,
    next_id: u16,
}

impl Lan {
    /// Matches the sockets to the current rules and interfaces.
    fn check(&mut self, vpn: &Arc<Vpn>) {
        let (served, mut listen_on, mut emit_on) = {
            let forward = vpn.forward();
            (forward.served(), forward.listen_interfaces(), forward.emit_interfaces())
        };
        // Bridge ports are served through the bridge; otherwise every datagram would be doubled.
        self.bridged = listen_on.iter().chain(&emit_on).filter_map(|interface| Some((interface.clone(), bridge_of(interface)?))).collect();
        listen_on.retain(|interface| !self.bridged.contains_key(interface));
        emit_on.retain(|interface| !self.bridged.contains_key(interface));
        let routes = kernel::all_routes();
        let mut networks: HashMap<String, Vec<Cidr>> = HashMap::new();
        for route in routes.iter().filter(|route| route.connected && route.prefix.prefix_len() > 0) {
            networks.entry(route.interface.clone()).or_default().push(route.prefix);
        }
        // Per (interface, listening): why sockets could not be opened.
        let mut errors: HashMap<(String, bool), String> = HashMap::new();

        self.emitters.retain(|interface, emitter| emit_on.contains(interface) && interface_index(interface) == emitter.index);
        for interface in &emit_on {
            let index = interface_index(interface);
            if index == 0 || self.emitters.contains_key(interface) {
                continue;
            }
            match emit_sockets(interface, index) {
                Ok(emitter) => {
                    self.emitters.insert(interface.clone(), emitter);
                }
                Err(error) => {
                    errors.insert((interface.clone(), false), format!("Cannot send on {interface}: {error}."));
                }
            }
        }
        {
            let mut known = self.known.lock().expect("lan lock");
            known.local = kernel::interface_addresses().into_iter().map(|(_, address)| address).collect();
            known.networks = networks;
        }

        self.listeners.retain(|interface, listener| listen_on.contains(interface) && interface_index(interface) == listener.index && !listener.task.is_finished());
        for interface in &listen_on {
            let index = interface_index(interface);
            if index == 0 || self.listeners.contains_key(interface) {
                continue;
            }
            match capture_socket(index) {
                Ok(socket) => {
                    let task = tokio::spawn(listen(vpn.clone(), socket, interface.clone(), self.known.clone()));
                    self.listeners.insert(interface.clone(), Listener { index, task });
                }
                Err(error) => {
                    errors.insert((interface.clone(), true), format!("Cannot listen on {interface}: {error}."));
                }
            }
        }

        let mut states = Vec::new();
        let mut failing = HashSet::new();
        for (rule, interfaces) in &served {
            if rule.direction == forward::Direction::Block {
                continue;
            }
            for interface in interfaces {
                let error = [(true, forward::Direction::FromMesh), (false, forward::Direction::ToMesh)].into_iter().filter(|(_, unused)| rule.direction != *unused).find_map(|(listens, _)| errors.get(&(interface.clone(), listens)));
                let (state, detail) = if interface_index(interface) == 0 {
                    ("waiting", Some(format!("No interface {interface} yet.")))
                } else if let Some(bridge) = self.bridged.get(interface) {
                    ("ready", Some(if interfaces.contains(bridge) { format!("A port of {bridge}: served there.") } else { format!("A port of {bridge}: add {bridge} to the rule's interfaces to serve it.") }))
                } else if let Some(error) = error {
                    if self.logged.insert(error.clone()) {
                        log::warn!("vpn: forward: {}: {error}", rule.name);
                    }
                    failing.insert(error.clone());
                    ("error", Some(error.clone()))
                } else {
                    ("ready", (!rule.is_broadcast()).then(|| snooping_warning(interface)).flatten())
                };
                states.push(LanState { rule: rule.name.clone(), interface: interface.clone(), state, detail });
            }
        }
        self.logged.retain(|error| failing.contains(error));
        vpn.forward().set_lan(states);
    }

    fn emit(&mut self, vpn: &Vpn, emit: &Emit) {
        for interface in emit.interfaces.iter().filter(|interface| !self.bridged.contains_key(*interface)) {
            let sent = match self.emitters.get(interface) {
                Some(emitter) => {
                    // A directed broadcast goes to this network's broadcast address.
                    let address = if emit.directed {
                        let served = vpn.forward().broadcast_of(interface);
                        served.or_else(|| self.known.lock().expect("lan lock").networks.get(interface).into_iter().flatten().find_map(broadcast_of)).unwrap_or(Ipv4Addr::BROADCAST)
                    } else {
                        emit.address
                    };
                    match (&emitter.raw, emit.source) {
                        (Some(raw), Some(source)) => {
                            self.next_id = self.next_id.wrapping_add(1).max(1);
                            let to = SocketAddrV4::new(address, emit.port);
                            let packets = forward::packets(source, to, &emit.payload, self.next_id, emit.ttl, mtu_of(interface));
                            packets.iter().try_for_each(|packet| raw.send_to(packet, &SocketAddrV4::new(address, 0).into()).map(|_| ()))
                        }
                        _ => {
                            let ttl = if address.is_multicast() { emitter.socket.set_multicast_ttl_v4(u32::from(emit.ttl)) } else { emitter.socket.set_ttl(u32::from(emit.ttl)) };
                            ttl.and_then(|()| emitter.socket.try_send_to(&emit.payload, SocketAddrV4::new(address, emit.port).into())).map(|_| ())
                        }
                    }
                }
                None => Err(io::Error::new(io::ErrorKind::NotConnected, "no socket on the interface yet")),
            };
            if let Err(error) = sent {
                log::debug!("vpn: forward: {} to {}:{} on {interface}: {error}", emit.rule, emit.address, emit.port);
                vpn.forward().emit_failed(&emit.rule);
            }
        }
    }
}

/// Runs the forwarding sockets for as long as the VPN runs.
pub async fn run(vpn: Arc<Vpn>, mut emits: mpsc::Receiver<Emit>) {
    let mut lan = Lan::default();
    let mut every = tokio::time::interval(RECHECK);
    loop {
        tokio::select! {
            emit = emits.recv() => match emit {
                Some(emit) => {
                    lan.emit(&vpn, &emit);
                    continue;
                }
                None => return,
            },
            _ = every.tick() => {}
            _ = vpn.forward_changed() => {}
        }
        lan.check(&vpn);
    }
}
