//! Encrypted, crash-safe storage for Kaonic secrets: node identity, mesh key, passwords.
//!
//! ```no_run
//! use kaonic_keystore::{DeviceKey, Keystore};
//!
//! # fn main() -> kaonic_keystore::Result<()> {
//! kaonic_keystore::harden_process()?;
//! # let app_token = [0u8; 32];
//! let kek = DeviceKey::for_this_device(&app_token)?; // SoC UID + token, Argon2id
//! let mut ks = Keystore::open_or_create("/usr/local/kaonic-hub/keystore", &kek)?;
//! if let Some(recovery) = ks.recovery() {
//!     eprintln!("keystore repaired: {recovery:?}");
//! }
//! let identity = ks.get_or_generate("mesh/identity", 64)?;
//! # let _ = identity;
//! ks.set("wifi/home", "correct horse battery staple")?;
//! # Ok(())
//! # }
//! ```
//!
//! - **Encryption:** XChaCha20-Poly1305 under a random data key, which a [`KeyProvider`]
//!   wraps ([`DeviceKey`], [`RawKey`], [`Passphrase`]). Everything in the file is
//!   authenticated.
//! - **Durability:** two copies; a power cut or one damaged copy is repaired on open.
//! - **Dependencies:** RustCrypto primitives and `libc` only.
//!
//! # Files
//!
//! - `<path>` and `<path>.mirror`: two identical copies of the store.
//! - `<path>.lock`: held while a [`Keystore`] is open.
//! - `<path>.tmp`, `<path>.mirror.tmp`: staging files for atomic writes.
//!
//! Files are 0600, owned by the user, and never followed through symlinks; otherwise
//! [`Error::Insecure`]. On open, the newest good copy repairs the other one. If neither
//! copy opens, `open` fails and leaves both files alone.
//!
//! # On the device
//!
//! Keep the store on `userfs` (`/usr/local`), not the root filesystem, so updates keep it.
//! - After an upgrade the previous release may open it again (a rollback): a release must
//!   not write what the previous one cannot read until it is confirmed.
//! - The hub unit needs `RequiresMountsFor=/usr/local`; otherwise an unmounted userfs
//!   makes `open_or_create` start a fresh store with a new identity.
//!
//! # Limits
//!
//! Against a stolen card the key is only as secret as [`DeviceKey`]'s token (the UID is
//! guessable from the public serial), or a [`RawKey`] file kept off the card. Against a
//! stolen device it needs secure boot and an OP-TEE-held secret. Nothing here protects
//! against code running as the hub, or against both copies being rolled back together.
//! An open [`Keystore`] keeps all entries decrypted in memory.

#[cfg(not(unix))]
compile_error!("kaonic-keystore supports Unix targets only");

mod crypto;
mod error;
mod format;
mod fsutil;
mod provider;
mod store;

pub use crypto::DataKey;
pub use error::{Error, Result};
pub use provider::{DeviceKey, KdfParams, KeyProvider, Passphrase, RawKey};
pub use store::{CopyState, Keystore, Recovery};

use zeroize::Zeroizing;

/// A secret value: zeroized on drop, redacted in `Debug`, no `Display`, no `==`.
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Copy `bytes` into a new secret.
    pub fn new(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    /// The raw bytes. Avoid copying them into buffers that are not zeroized.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The value as UTF-8, for passwords and other text secrets.
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// The length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret([REDACTED; {} bytes])", self.0.len())
    }
}

impl From<Zeroizing<Vec<u8>>> for Secret {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

/// Takes ownership of the buffer without copying it.
impl From<Vec<u8>> for Secret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Takes ownership of the buffer without copying it.
impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self::from(s.into_bytes())
    }
}

impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

const MAX_NAME_LEN: usize = 128;

/// Names are `/`-separated `[a-z0-9._-]` segments, at most 128 bytes, e.g. `wifi/home`.
pub fn validate_name(name: &str) -> Result<()> {
    let valid_segment = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    };
    if name.len() <= MAX_NAME_LEN && name.split('/').all(valid_segment) {
        Ok(())
    } else {
        Err(Error::InvalidName(name.to_owned()))
    }
}

/// Disable core dumps and, on Linux, ptrace and `/proc/<pid>/mem` access. Call early in `main`.
///
/// Does not stop root, and cannot be undone.
pub fn harden_process() -> Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `none` is a valid rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: PR_SET_DUMPABLE takes one integer argument; the rest are ignored.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
