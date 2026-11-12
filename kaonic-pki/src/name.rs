//! Names, algorithm identifiers and keys in the exact form this crate writes and accepts.

use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::der::asn1::{BitString, SetOfVec, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Any, Decode, Encode};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::{Error, IdentityHash, Result};

pub(crate) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

pub(crate) const NODE_ORG: &str = "Kaonic";
pub(crate) const ADMIN_ORG: &str = "Kaonic Admin";

/// Ed25519 takes no parameters (RFC 8410).
pub(crate) fn ed25519_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ED25519,
        parameters: None,
    }
}

pub(crate) fn check_algorithm(alg: &AlgorithmIdentifierOwned) -> Result<()> {
    if alg.oid == ED25519 && alg.parameters.is_none() {
        Ok(())
    } else {
        Err(Error::Malformed("algorithm is not Ed25519"))
    }
}

pub(crate) fn ed25519_spki(key: &[u8; 32]) -> Result<SubjectPublicKeyInfoOwned> {
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: ed25519_algorithm(),
        subject_public_key: BitString::from_bytes(key)?,
    })
}

pub(crate) fn spki_key(spki: &SubjectPublicKeyInfoOwned) -> Result<[u8; 32]> {
    check_algorithm(&spki.algorithm)?;
    spki.subject_public_key
        .as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Malformed("public key is not 32 bytes"))
}

pub(crate) fn signature_bits(signature: &ed25519_dalek::Signature) -> Result<BitString> {
    Ok(BitString::from_bytes(&signature.to_bytes())?)
}

pub(crate) fn signature_bytes(bits: &BitString) -> Result<&[u8]> {
    bits.as_bytes()
        .ok_or(Error::Malformed("signature has unused bits"))
}

/// `CN=<identity hash>, O=<org>`, both UTF8String.
pub(crate) fn build(hash: &IdentityHash, org: &str) -> Result<Name> {
    let hex = hash.to_hex();
    let rdn = |oid, value: &str| -> Result<RelativeDistinguishedName> {
        let atv = AttributeTypeAndValue {
            oid,
            value: Any::encode_from(&Utf8StringRef::new(value)?)?,
        };
        Ok(RelativeDistinguishedName::from(SetOfVec::try_from(vec![
            atv,
        ])?))
    };
    Ok(RdnSequence(vec![
        rdn(COMMON_NAME, &hex)?,
        rdn(ORGANIZATION, org)?,
    ]))
}

/// Parse a name written by [`build`]; returns the identity hash and the organization.
pub(crate) fn parse(name: &Name) -> Result<(IdentityHash, String)> {
    let [cn, org] = name.0.as_slice() else {
        return Err(Error::Malformed("name is not CN, O"));
    };
    let value = |rdn: &RelativeDistinguishedName, oid| -> Result<String> {
        let [atv] = rdn.0.as_slice() else {
            return Err(Error::Malformed("multi-valued name component"));
        };
        if atv.oid != oid {
            return Err(Error::Malformed("unexpected name attribute"));
        }
        // Re-decode from DER so only UTF8String is accepted.
        let der = atv.value.to_der()?;
        let s = Utf8StringRef::from_der(&der)?;
        Ok(s.as_str().to_owned())
    };
    let hash = IdentityHash::from_hex(&value(cn, COMMON_NAME)?)
        .ok_or(Error::Malformed("common name is not an identity hash"))?;
    Ok((hash, value(org, ORGANIZATION)?))
}
