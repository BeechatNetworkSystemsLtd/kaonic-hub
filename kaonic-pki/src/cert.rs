use std::time::Duration;

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use x509_cert::der::asn1::{GeneralizedTime, OctetString, UtcTime};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{DateTime, Decode, Encode};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{TbsCertificate, Version};

use crate::name::{self, ADMIN_ORG, NODE_ORG};
use crate::{CertRequest, Error, Identity, IdentityHash, Result, SigningKey, check_signing_key};

/// A parsed and structurally checked certificate: an admin root or a node certificate.
///
/// Parsing checks layout and, for a root, its self-signature. Whether a node certificate
/// is trusted is decided by [`verify_issued_by`](Self::verify_issued_by) and
/// [`check_identity`](Self::check_identity).
#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    hash: IdentityHash,
    key: [u8; 32],
    is_root: bool,
    subject: Name,
    issuer: Name,
}

impl Certificate {
    /// A self-signed admin root for `identity`, whose Ed25519 half is `key`.
    pub fn new_root(identity: &Identity, key: &SigningKey, issued_at: u64) -> Result<Self> {
        check_signing_key(identity, key)?;
        let subject = name::build(&identity.hash(), ADMIN_ORG)?;
        sign(identity, subject.clone(), subject, true, issued_at, key)
    }

    /// Issue a node certificate from `request`, which must come from `subject`: the
    /// identity the admin knows the node by (from its announce). `self` is the root and
    /// `admin_key` its key.
    pub fn issue(
        &self,
        admin_key: &SigningKey,
        request: &CertRequest,
        subject: &Identity,
        issued_at: u64,
    ) -> Result<Self> {
        if !self.is_root {
            return Err(Error::NotIssuedBy);
        }
        if admin_key.verifying_key().to_bytes() != self.key {
            return Err(Error::WrongSigningKey);
        }
        request.check_identity(subject)?;
        let name = name::build(&subject.hash(), NODE_ORG)?;
        sign(
            subject,
            name,
            self.subject.clone(),
            false,
            issued_at,
            admin_key,
        )
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let cert = x509_cert::Certificate::from_der(der)?;
        // DER is canonical; a different re-encoding means a non-DER or ambiguous input.
        if cert.to_der()? != der {
            return Err(Error::Malformed("not canonical DER"));
        }
        let tbs = &cert.tbs_certificate;
        name::check_algorithm(&cert.signature_algorithm)?;
        name::check_algorithm(&tbs.signature)?;
        if tbs.version != Version::V3
            || tbs.issuer_unique_id.is_some()
            || tbs.subject_unique_id.is_some()
        {
            return Err(Error::Malformed("not a plain v3 certificate"));
        }
        let (hash, org) = name::parse(&tbs.subject)?;
        let is_root = match org.as_str() {
            ADMIN_ORG => true,
            NODE_ORG => false,
            _ => return Err(Error::Malformed("unknown organization")),
        };
        let (issuer_hash, issuer_org) = name::parse(&tbs.issuer)?;
        if issuer_org != ADMIN_ORG || (is_root && issuer_hash != hash) {
            return Err(Error::Malformed("unexpected issuer"));
        }
        check_extensions(tbs.extensions.as_deref().unwrap_or_default(), is_root)?;

        let this = Self {
            der: der.to_vec(),
            tbs: tbs.to_der()?,
            signature: name::signature_bytes(&cert.signature)?.to_vec(),
            hash,
            key: name::spki_key(&tbs.subject_public_key_info)?,
            is_root,
            subject: tbs.subject.clone(),
            issuer: tbs.issuer.clone(),
        };
        if is_root {
            crate::verify(&this.key, &this.tbs, &this.signature)?;
        }
        Ok(this)
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn identity_hash(&self) -> IdentityHash {
        self.hash
    }

    /// The certified Ed25519 key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn is_root(&self) -> bool {
        self.is_root
    }

    /// Check that `root` issued this node certificate.
    pub fn verify_issued_by(&self, root: &Certificate) -> Result<()> {
        if !root.is_root || self.is_root || self.issuer != root.subject {
            return Err(Error::NotIssuedBy);
        }
        crate::verify(&root.key, &self.tbs, &self.signature)
    }

    /// Check that this certificate belongs to `identity`: same identity hash, same key.
    pub fn check_identity(&self, identity: &Identity) -> Result<()> {
        if identity.hash() == self.hash && identity.ed25519 == self.key {
            Ok(())
        } else {
            Err(Error::IdentityMismatch)
        }
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for Certificate {}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("identity", &self.hash)
            .field("root", &self.is_root)
            .finish()
    }
}

fn sign(
    subject_identity: &Identity,
    subject: Name,
    issuer: Name,
    is_root: bool,
    issued_at: u64,
    signer: &SigningKey,
) -> Result<Certificate> {
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&serial(&subject_identity.hash(), issued_at))?,
        signature: name::ed25519_algorithm(),
        issuer,
        validity: Validity {
            not_before: time(issued_at)?,
            // RFC 5280 §4.1.2.5: "no well-defined expiration date". Trust is withdrawn
            // through the allowlist instead, since nodes may have no reliable clock.
            not_after: Time::GeneralTime(GeneralizedTime::from_date_time(DateTime::new(
                9999, 12, 31, 23, 59, 59,
            )?)),
        },
        subject,
        subject_public_key_info: name::ed25519_spki(&subject_identity.ed25519)?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions(is_root)?),
    };
    let signature = signer.sign(&tbs.to_der()?);
    let cert = x509_cert::Certificate {
        tbs_certificate: tbs,
        signature_algorithm: name::ed25519_algorithm(),
        signature: name::signature_bits(&signature)?,
    };
    Certificate::from_der(&cert.to_der()?)
}

/// Deterministic, positive, 16 bytes with no leading zero byte: unique per subject and time.
fn serial(hash: &IdentityHash, issued_at: u64) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"kaonic-pki serial\0")
        .chain_update(hash.0)
        .chain_update(issued_at.to_be_bytes())
        .finalize();
    let mut serial: [u8; 16] = digest[..16].try_into().unwrap();
    serial[0] = (serial[0] & 0x7f) | 0x40;
    serial
}

/// UTCTime through 2049, GeneralizedTime after, as RFC 5280 requires.
fn time(unix: u64) -> Result<Time> {
    let duration = Duration::from_secs(unix);
    Ok(match UtcTime::from_unix_duration(duration) {
        Ok(utc) => Time::UtcTime(utc),
        Err(_) => Time::GeneralTime(GeneralizedTime::from_unix_duration(duration)?),
    })
}

fn expected_extensions(is_root: bool) -> (BasicConstraints, KeyUsage) {
    if is_root {
        (
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
            // The admin key also signs link authentication as a node does.
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::DigitalSignature),
        )
    } else {
        (
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            KeyUsage(KeyUsages::DigitalSignature.into()),
        )
    }
}

fn extensions(is_root: bool) -> Result<Vec<Extension>> {
    let (constraints, usage) = expected_extensions(is_root);
    Ok(vec![
        Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(constraints.to_der()?)?,
        },
        Extension {
            extn_id: KeyUsage::OID,
            critical: true,
            extn_value: OctetString::new(usage.to_der()?)?,
        },
    ])
}

/// Exactly the two critical extensions this crate writes, with the values for the role.
fn check_extensions(extensions: &[Extension], is_root: bool) -> Result<()> {
    let [constraints, usage] = extensions else {
        return Err(Error::Malformed("unexpected extensions"));
    };
    let (want_constraints, want_usage) = expected_extensions(is_root);
    let ok = constraints.extn_id == BasicConstraints::OID
        && constraints.critical
        && BasicConstraints::from_der(constraints.extn_value.as_bytes())? == want_constraints
        && usage.extn_id == KeyUsage::OID
        && usage.critical
        && KeyUsage::from_der(usage.extn_value.as_bytes())? == want_usage;
    if ok {
        Ok(())
    } else {
        Err(Error::Malformed(
            "extensions do not match the certificate role",
        ))
    }
}
