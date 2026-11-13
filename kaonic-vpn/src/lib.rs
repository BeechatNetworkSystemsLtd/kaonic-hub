//! kaonic-hub's mesh VPN: IPv4 over the authenticated mesh links (`kaonic_mesh::links`).
//!
//! - [`ip`]: prefixes and IPv4 headers.
//! - [`table`]: peers' tunnel addresses and advertised prefixes.
//! - [`tun`]: the TUN device and its routes (Linux).
//! - [`service`]: the running VPN.
//! - [`reliable`]: retransmission (ARQ) between hubs.
//! - [`capture`]: packet capture for the VPN page (pcap download).
//! - [`kernel`]: networks this node already reaches.
//! - [`firewall`]: keeps management ports off the tunnel.
//! - [`flood`]: limits on broadcast and multicast.
//! - [`share`]: client networks, internet gateway and uplink.
//! - [`forward`], `lan`: UDP multicast and broadcast forwarding between client networks.
//!
//! Each node gets a tunnel address from its identity hash (in `10.77.0.0/16` by default).
//! Unicast goes to the peer that owns the destination. Broadcast and multicast go to every
//! authenticated peer. IP packets travel as mux messages, several per link packet. TCP is
//! carried end to end for now.

pub mod capture;
pub mod firewall;
pub mod flood;
pub mod forward;
pub mod ip;
pub mod kernel;
#[cfg(target_os = "linux")]
pub mod lan;
pub mod reliable;
pub mod service;
pub mod share;
pub mod table;
pub mod tun;

pub use service::{Status, Vpn, VpnConfig};
