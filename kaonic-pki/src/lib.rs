//! Admin-issued X.509 certificates bound to Kaonic Reticulum identities.
//!
//! - The admin creates a self-signed [`Certificate::new_root`] with its own identity.
//! - A node sends a [`CertRequest`] (PKCS#10) signed with its identity key.
//! - The admin [`Certificate::issue`]s a node certificate from it.
//! - Peers check each other with [`Certificate::verify_issued_by`] and
//!   [`Certificate::check_identity`].
//!
//! Everything is Ed25519. A certificate's key is the node's Reticulum Ed25519 key and its
//! subject is `CN=<identity hash>`, which also binds the X25519 half of the identity. Parsing
//! is strict: only the layout this crate writes is accepted.

mod cert;
mod csr;
mod name;

use std::fmt;

pub use cert::Certificate;
pub use csr::CertRequest;
pub use ed25519_dalek::SigningKey;

use sha2::{Digest, Sha256};

/// A Reticulum public identity: X25519 key ‖ Ed25519 key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

impl Identity {
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let (x25519, ed25519) = bytes.split_at(32);
        Self {
            x25519: x25519.try_into().unwrap(),
            ed25519: ed25519.try_into().unwrap(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519);
        out[32..].copy_from_slice(&self.ed25519);
        out
    }

    /// Reticulum's identity hash: `SHA-256(x25519 ‖ ed25519)[..16]`.
    pub fn hash(&self) -> IdentityHash {
        let digest = Sha256::digest(self.to_bytes());
        IdentityHash(digest[..16].try_into().unwrap())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.hash())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityHash(pub [u8; 16]);

impl IdentityHash {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Exactly 32 lowercase hex digits, as written into certificates.
    pub fn from_hex(hex: &str) -> Option<Self> {
        let bytes = hex.as_bytes();
        if bytes.len() != 32 || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, pair) in bytes.chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityHash({self})")
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    /// Not valid DER, or not the structure this crate writes.
    Malformed(&'static str),
    /// A signature does not verify.
    BadSignature,
    /// The certificate was not issued by the given root.
    NotIssuedBy,
    /// The certificate or request does not belong to the given identity.
    IdentityMismatch,
    /// A signing key does not belong to the identity it is used for.
    WrongSigningKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed certificate or request: {why}"),
            Self::BadSignature => f.write_str("signature does not verify"),
            Self::NotIssuedBy => f.write_str("certificate is not issued by this root"),
            Self::IdentityMismatch => f.write_str("certificate does not belong to this identity"),
            Self::WrongSigningKey => f.write_str("signing key does not match the identity"),
        }
    }
}

impl std::error::Error for Error {}

impl From<x509_cert::der::Error> for Error {
    fn from(_: x509_cert::der::Error) -> Self {
        Self::Malformed("invalid DER")
    }
}

/// Check that `key` is the Ed25519 half of `identity`.
fn check_signing_key(identity: &Identity, key: &SigningKey) -> Result<()> {
    if key.verifying_key().to_bytes() == identity.ed25519 {
        Ok(())
    } else {
        Err(Error::WrongSigningKey)
    }
}

/// Verify an Ed25519 signature, strictly (no malleable or small-order keys).
fn verify(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| Error::BadSignature)?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::BadSignature)
}
