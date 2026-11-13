//! kaonic-hub's mesh: Reticulum over the Kaonic radios.
//!
//! - [`radio`]: a transceiver of the `kaonic_rf215` kernel driver, as a packet socket.
//! - [`group`]: a Reticulum GROUP channel (one packet to every neighbour), for push-to-talk.
//! - [`iface`]: the Reticulum interface on it, as LDPC-coded `kaonic-net` frames.
//! - [`announce`]: what a node says about itself when it announces.
//! - [`radio_config`]: everything the driver lets us configure on a band, and the network-wide switch.
//! - [`settings`]: the radio's frequency, channel and modulation, kept by the hub.
//! - [`traffic`]: every frame sent and heard, for the traffic analyser.
//! - [`links`]: one authenticated link per trusted peer, carrying mux packets.
//! - [`node`]: the transport, this node's destination and announces, and the peers heard.
//! - [`log_limit`]: a log line written at most once per interval.

pub mod announce;
pub mod group;
pub mod iface;
pub mod link;
pub mod links;
pub mod log_limit;
pub mod node;
pub mod radio;
pub mod radio_config;
pub mod settings;
pub mod traffic;

pub use link::{Incoming, OutLink};
pub use node::{Mesh, MeshConfig, Peer};
/// The Reticulum crate this mesh runs on, for its identity and destination types.
pub use reticulum;
