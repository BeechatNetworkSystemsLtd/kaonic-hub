use std::fmt;
use std::io;
use std::path::PathBuf;

/// `Result` with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Keystore errors. They never contain secret data.
#[derive(Debug)]
pub enum Error {
    /// A filesystem or OS error.
    Io(io::Error),
    /// The store or key file does not exist.
    NotFound(PathBuf),
    /// [`Keystore::create`](crate::Keystore::create) found an existing store.
    AlreadyExists(PathBuf),
    /// Another process holds the store's lock.
    Locked(PathBuf),
    /// A file or directory could be read or swapped by someone other than the owner.
    Insecure {
        /// The offending file or directory.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// A write would make the store larger than 4 MiB.
    TooLarge,
    /// Not a keystore file, or a truncated or malformed one.
    Corrupt(&'static str),
    /// The file was written by a newer format version.
    UnsupportedVersion(u8),
    /// The store was sealed by a different kind of [`KeyProvider`](crate::KeyProvider).
    ProviderMismatch {
        /// The kind of the provider passed in.
        expected: String,
        /// The kind recorded in the store.
        found: String,
    },
    /// The data key could not be unwrapped: wrong key or passphrase, or a modified header.
    WrongKey,
    /// The data key unwrapped but the body failed authentication: the file was modified.
    Tampered,
    /// A name failed [`validate_name`](crate::validate_name).
    InvalidName(String),
    /// The system random number generator failed.
    Rng(io::Error),
    /// A provider-specific failure, e.g. a hardware or TEE backend being unavailable.
    Provider(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "keystore I/O: {e}"),
            Self::NotFound(p) => write!(f, "{} not found", p.display()),
            Self::AlreadyExists(p) => write!(f, "keystore {} already exists", p.display()),
            Self::Locked(p) => write!(f, "keystore {} is locked by another process", p.display()),
            Self::Insecure { path, reason } => write!(f, "refusing {}: {reason}", path.display()),
            Self::TooLarge => f.write_str("keystore would exceed the maximum file size"),
            Self::Corrupt(why) => write!(f, "not a keystore file, or it is damaged: {why}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported keystore format version {v}"),
            Self::ProviderMismatch { expected, found } => write!(
                f,
                "keystore was sealed with the '{found}' key provider, not '{expected}'"
            ),
            Self::WrongKey => f.write_str("wrong key or passphrase"),
            Self::Tampered => f.write_str("keystore contents failed authentication"),
            Self::InvalidName(name) => write!(
                f,
                "invalid secret name {name:?}: use 1-128 bytes of [a-z0-9._-] in '/'-separated segments"
            ),
            Self::Rng(e) => write!(f, "system random number generator failed: {e}"),
            Self::Provider(e) => write!(f, "key provider: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Rng(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
