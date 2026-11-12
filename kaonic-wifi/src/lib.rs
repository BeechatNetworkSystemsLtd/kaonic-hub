//! Wi-Fi client management for kaonic-hub.
//!
//! - [`policy`]: which saved network to be on, when to scan, when to retry. Pure; no I/O.
//! - [`wpa`]: the wpa_supplicant control protocol: commands and parsers. Pure.
//! - [`ctrl`]: the control socket itself.
//! - [`supplicant`]: carries out the policy's actions on wpa_supplicant and translates its events.

pub mod ctrl;
pub mod policy;
pub mod supplicant;
pub mod wpa;
