use ed25519_dalek::Signer;
use x509_cert::attr::Attribute;
use x509_cert::der::asn1::{SetOfVec, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Any, Decode, Encode};
use x509_cert::request::{CertReq, CertReqInfo, Version};

use crate::name::{self, NODE_ORG};
use crate::{Error, Identity, IdentityHash, Result, SigningKey, check_signing_key};

/// PKCS#9 challengePassword: carries the provisioning link's id, so a request captured
/// on one link cannot be replayed on another.
const CHALLENGE_PASSWORD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");
const MAX_CHALLENGE_LEN: usize = 64;

/// A PKCS#10 certificate request from a node, signed with its identity key.
#[derive(Clone)]
pub struct CertRequest {
    der: Vec<u8>,
    hash: IdentityHash,
    key: [u8; 32],
    challenge: Vec<u8>,
}

impl CertRequest {
    /// Build and sign a request for `identity`, whose Ed25519 half is `key`.
    pub fn create(identity: &Identity, key: &SigningKey, challenge: &[u8]) -> Result<Self> {
        check_signing_key(identity, key)?;
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(Error::Malformed("challenge must be 1-64 bytes"));
        }
        let hex: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
        let attribute = Attribute {
            oid: CHALLENGE_PASSWORD,
            values: SetOfVec::try_from(vec![Any::encode_from(&Utf8StringRef::new(&hex)?)?])?,
        };
        let info = CertReqInfo {
            version: Version::V1,
            subject: name::build(&identity.hash(), NODE_ORG)?,
            public_key: name::ed25519_spki(&identity.ed25519)?,
            attributes: SetOfVec::try_from(vec![attribute])?,
        };
        let signature = key.sign(&info.to_der()?);
        let request = CertReq {
            info,
            algorithm: name::ed25519_algorithm(),
            signature: name::signature_bits(&signature)?,
        };
        Self::from_der(&request.to_der()?)
    }

    /// Parse a request and check its signature (proof that the sender holds the key).
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let request = CertReq::from_der(der)?;
        if request.to_der()? != der {
            return Err(Error::Malformed("not canonical DER"));
        }
        name::check_algorithm(&request.algorithm)?;
        let info = &request.info;
        if info.version != Version::V1 {
            return Err(Error::Malformed("not a v1 request"));
        }
        let (hash, org) = name::parse(&info.subject)?;
        if org != NODE_ORG {
            return Err(Error::Malformed("request is not for a node"));
        }
        let key = name::spki_key(&info.public_key)?;
        let challenge = parse_challenge(info)?;
        crate::verify(
            &key,
            &info.to_der()?,
            name::signature_bytes(&request.signature)?,
        )?;
        Ok(Self {
            der: der.to_vec(),
            hash,
            key,
            challenge,
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn identity_hash(&self) -> IdentityHash {
        self.hash
    }

    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// Check that the request comes from `identity`: same identity hash, same key.
    pub fn check_identity(&self, identity: &Identity) -> Result<()> {
        if identity.hash() == self.hash && identity.ed25519 == self.key {
            Ok(())
        } else {
            Err(Error::IdentityMismatch)
        }
    }
}

impl std::fmt::Debug for CertRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertRequest")
            .field("identity", &self.hash)
            .finish_non_exhaustive()
    }
}

fn parse_challenge(info: &CertReqInfo) -> Result<Vec<u8>> {
    let [attribute] = info.attributes.as_slice() else {
        return Err(Error::Malformed("expected exactly one attribute"));
    };
    let [value] = attribute.values.as_slice() else {
        return Err(Error::Malformed("challenge must have one value"));
    };
    if attribute.oid != CHALLENGE_PASSWORD {
        return Err(Error::Malformed("unexpected attribute"));
    }
    let der = value.to_der()?;
    let hex = Utf8StringRef::from_der(&der)?;
    let hex = hex.as_str().as_bytes();
    if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 2 * MAX_CHALLENGE_LEN {
        return Err(Error::Malformed("bad challenge length"));
    }
    hex.chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|p| p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or(Error::Malformed("challenge is not lowercase hex"))
        })
        .collect()
}
