//! Who a provisioned Kaonic node trusts: its admin root, its own certificate and the
//! admin-signed [`Allowlist`].
//!
//! A peer is trusted when it is the admin itself, or when it holds a certificate issued by
//! the root, bound to the identity it presents, and its identity is on the allowlist.
//! No I/O: the hub stores the parts in `kaonic-keystore`.

mod allowlist;

use std::fmt;

pub use allowlist::Allowlist;
pub use kaonic_pki::{Certificate, Identity, IdentityHash};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Malformed(&'static str),
    BadSignature,
    /// The certificate is not from our admin root.
    NotIssued,
    /// The certificate does not belong to the identity presented with it.
    IdentityMismatch,
    /// A valid certificate, but the identity is not on the allowlist.
    NotAllowed,
    /// The admin blocked this identity.
    Blocked,
    Pki(kaonic_pki::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed trust data: {why}"),
            Self::BadSignature => f.write_str("allowlist signature does not verify"),
            Self::NotIssued => f.write_str("certificate is not issued by our admin"),
            Self::IdentityMismatch => f.write_str("certificate does not match the identity"),
            Self::NotAllowed => f.write_str("identity is not on the allowlist"),
            Self::Blocked => f.write_str("identity is blocked by the admin"),
            Self::Pki(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<kaonic_pki::Error> for Error {
    fn from(e: kaonic_pki::Error) -> Self {
        match e {
            kaonic_pki::Error::NotIssuedBy => Self::NotIssued,
            kaonic_pki::Error::IdentityMismatch => Self::IdentityMismatch,
            other => Self::Pki(other),
        }
    }
}

/// What kind of trusted peer passed [`Trust::verify_peer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    Admin,
    Node,
}

/// The trust state of a provisioned node.
#[derive(Debug, Clone)]
pub struct Trust {
    root: Certificate,
    own: Certificate,
    allowlist: Allowlist,
}

impl Trust {
    /// Rebuild from stored parts, checking that they belong together. On the admin device
    /// `own` is the root itself.
    pub fn from_der(root: &[u8], own: &[u8], allowlist: &[u8]) -> Result<Self> {
        let root = Certificate::from_der(root)?;
        if !root.is_root() {
            return Err(Error::Malformed("trust anchor is not a root certificate"));
        }
        let own = Certificate::from_der(own)?;
        if own != root {
            own.verify_issued_by(&root)?;
        }
        let allowlist = Allowlist::from_bytes(allowlist, root.public_key())?;
        Ok(Self {
            root,
            own,
            allowlist,
        })
    }

    pub fn root(&self) -> &Certificate {
        &self.root
    }

    pub fn own(&self) -> &Certificate {
        &self.own
    }

    pub fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    /// Decide whether a peer presenting `identity` and `cert` is trusted.
    pub fn verify_peer(&self, identity: &Identity, cert: &Certificate) -> Result<Peer> {
        cert.check_identity(identity)?;
        if *cert == self.root {
            return Ok(Peer::Admin);
        }
        if self.allowlist.is_blocked(&identity.hash()) {
            return Err(Error::Blocked);
        }
        cert.verify_issued_by(&self.root)?;
        if self.allowlist.contains(&identity.hash()) {
            Ok(Peer::Node)
        } else {
            Err(Error::NotAllowed)
        }
    }

    /// Offer a list received from a peer. It replaces ours only if our admin signed it and
    /// its `seq` is higher; returns whether it did. An equal or older list is ignored.
    pub fn update_allowlist(&mut self, bytes: &[u8]) -> Result<bool> {
        let list = Allowlist::from_bytes(bytes, self.root.public_key())?;
        if list.seq() <= self.allowlist.seq() {
            return Ok(false);
        }
        self.allowlist = list;
        Ok(true)
    }
}
