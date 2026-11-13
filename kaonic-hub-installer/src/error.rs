//! What went wrong, in words an admin can act on.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The package or request is wrong.
    Invalid,
    NotFound,
    /// It clashes with what is installed (a name in use, an update already running).
    Conflict,
    /// Older than a version installed before: needs `allow_downgrade`.
    Downgrade,
    /// Policy says no (unsigned package when only signed ones are allowed).
    Forbidden,
    /// The device could not do it (disk, systemd, the plugin did not start).
    Failed,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
}

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Kind::Invalid, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Kind::NotFound, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(Kind::Conflict, message)
    }
    pub fn downgrade(message: impl Into<String>) -> Self {
        Self::new(Kind::Downgrade, message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(Kind::Forbidden, message)
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(Kind::Failed, message)
    }
    /// A file system error, with what we were doing.
    pub fn io(context: impl fmt::Display) -> impl FnOnce(std::io::Error) -> Self {
        move |error| Self::failed(format!("{context}: {error}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
