//! `kaonic-hub-installer`: installs, runs, upgrades and removes Kaonic plugins.
//!
//! A standalone program that runs as root and serves its API on a Unix socket. It answers
//! only peers whose uid it allows (root, the hub), checked on every connection; the hub
//! decides who may ask for what. The installer decides what may be installed: it checks
//! every package itself.
//!
//! - [`package`]: the package format (a tar with a manifest, checksums and a signature).
//! - [`manifest`]: the manifest, `kaonic-plugin.toml`.
//! - [`unit`]: the systemd unit, written by the installer from the manifest.
//! - [`installer`]: install with rollback, start/stop, remove, restore at boot.
//! - [`host`]: systemd and file owners, behind a trait so tests run anywhere.
//! - [`core`]: the hub and the installer updating each other.
//! - [`history`]: what happened, one line per event.
//! - [`token`]: plugin tokens (id and permissions, signed), checked by the hub.
//! - [`api`]: the HTTP API on the Unix socket.

pub mod api;
pub mod core;
pub mod error;
pub mod history;
pub mod host;
pub mod installer;
pub mod manifest;
pub mod names;
pub mod package;
pub mod records;
pub mod tar;
pub mod token;
pub mod unit;

pub use error::{Error, Kind};
pub use installer::{Installer, Paths};

/// Random bytes from the kernel.
pub fn random<const N: usize>() -> std::io::Result<[u8; N]> {
    use std::io::Read;
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The uid of the process at the other end of a Unix socket.
pub use kaonic_hub_common::peer_uid;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(bytes))
}

/// Writes a file whole: to a temporary name, synced, then renamed over the old one.
pub fn write_atomic(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = path.with_file_name(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)
}
