use std::collections::BTreeSet;

use ed25519_dalek::Signer;
use kaonic_pki::{IdentityHash, SigningKey};

use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"KALW";
/// Without a blocked section.
const V1: u8 = 1;
/// With one.
const V2: u8 = 2;
const HEADER_LEN: usize = 4 + 1 + 8 + 2;
const SIG_LEN: usize = 64;

/// The admin-signed list of identities allowed on the network, and of those blocked from it.
///
/// ```text
/// v1: "KALW" | 1 | seq u64 | count u16 | identity hash[16] * count | Ed25519 sig[64]
/// v2: "KALW" | 2 | seq u64 | count u16 | identity hash[16] * count
///            | blocked u16 | identity hash[16] * blocked | Ed25519 sig[64]
/// ```
/// Integers are big-endian; hashes are sorted and unique, so one list has one encoding. A list
/// with nobody blocked is written as v1, which nodes without blocking still read. `seq` only
/// grows: a newer list replaces an older one, and removing an identity with a higher `seq`
/// revokes it. A blocked identity is refused even with a valid certificate; it is never also
/// allowed.
#[derive(Clone, PartialEq, Eq)]
pub struct Allowlist {
    seq: u64,
    entries: BTreeSet<IdentityHash>,
    blocked: BTreeSet<IdentityHash>,
    bytes: Vec<u8>,
}

impl Allowlist {
    /// Sign a list with the admin root's key.
    pub fn sign(
        admin_key: &SigningKey,
        seq: u64,
        entries: impl IntoIterator<Item = IdentityHash>,
    ) -> Result<Self> {
        Self::sign_with_blocked(admin_key, seq, entries, [])
    }

    /// Sign a list that also blocks `blocked`. An identity in both is blocked.
    pub fn sign_with_blocked(
        admin_key: &SigningKey,
        seq: u64,
        entries: impl IntoIterator<Item = IdentityHash>,
        blocked: impl IntoIterator<Item = IdentityHash>,
    ) -> Result<Self> {
        let blocked: BTreeSet<IdentityHash> = blocked.into_iter().collect();
        let entries: BTreeSet<IdentityHash> =
            entries.into_iter().filter(|hash| !blocked.contains(hash)).collect();
        let count =
            u16::try_from(entries.len()).map_err(|_| Error::Malformed("too many entries"))?;
        let blocked_count =
            u16::try_from(blocked.len()).map_err(|_| Error::Malformed("too many entries"))?;
        let mut bytes =
            Vec::with_capacity(HEADER_LEN + 2 + (entries.len() + blocked.len()) * 16 + SIG_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.push(if blocked.is_empty() { V1 } else { V2 });
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for hash in &entries {
            bytes.extend_from_slice(&hash.0);
        }
        if !blocked.is_empty() {
            bytes.extend_from_slice(&blocked_count.to_be_bytes());
            for hash in &blocked {
                bytes.extend_from_slice(&hash.0);
            }
        }
        let signature = admin_key.sign(&bytes);
        bytes.extend_from_slice(&signature.to_bytes());
        Ok(Self {
            seq,
            entries,
            blocked,
            bytes,
        })
    }

    /// The length of the encoded list at the start of `bytes`, from its counts, if it fits.
    /// Says nothing about the signature.
    pub fn encoded_len(bytes: &[u8]) -> Option<usize> {
        let header = bytes.get(..HEADER_LEN)?;
        if &header[..4] != MAGIC {
            return None;
        }
        let count = u16::from_be_bytes([header[13], header[14]]) as usize;
        let mut len = HEADER_LEN + count * 16;
        match header[4] {
            V1 => {}
            V2 => {
                let blocked = bytes.get(len..len + 2)?;
                len += 2 + u16::from_be_bytes([blocked[0], blocked[1]]) as usize * 16;
            }
            _ => return None,
        }
        len += SIG_LEN;
        (len <= bytes.len()).then_some(len)
    }

    /// The `seq` in the header at the start of `bytes`. Says nothing about the signature.
    pub fn seq_of(bytes: &[u8]) -> Option<u64> {
        let header = bytes.get(..HEADER_LEN)?;
        (&header[..4] == MAGIC).then(|| u64::from_be_bytes(header[5..13].try_into().unwrap()))
    }

    /// Parse a list and check that `admin_key` signed it.
    pub fn from_bytes(bytes: &[u8], admin_key: &[u8; 32]) -> Result<Self> {
        let (body, signature) = bytes
            .split_last_chunk::<SIG_LEN>()
            .ok_or(Error::Malformed("allowlist is truncated"))?;
        let (header, rest) = body
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(Error::Malformed("allowlist is truncated"))?;
        if &header[..4] != MAGIC || !matches!(header[4], V1 | V2) {
            return Err(Error::Malformed("not a version 1 or 2 allowlist"));
        }
        let seq = u64::from_be_bytes(header[5..13].try_into().unwrap());
        let count = u16::from_be_bytes(header[13..15].try_into().unwrap()) as usize;
        let (hashes, blocked_hashes) = if header[4] == V1 {
            (rest, &[][..])
        } else {
            let (hashes, rest) = rest
                .split_at_checked(count * 16)
                .ok_or(Error::Malformed("allowlist length does not match its count"))?;
            let (blocked, blocked_hashes) = rest
                .split_first_chunk::<2>()
                .ok_or(Error::Malformed("allowlist is truncated"))?;
            if blocked_hashes.len() != u16::from_be_bytes(*blocked) as usize * 16
                || blocked_hashes.is_empty()
            {
                return Err(Error::Malformed(
                    "allowlist length does not match its count",
                ));
            }
            (hashes, blocked_hashes)
        };
        if hashes.len() != count * 16 {
            return Err(Error::Malformed(
                "allowlist length does not match its count",
            ));
        }
        let verifying =
            ed25519_dalek::VerifyingKey::from_bytes(admin_key).map_err(|_| Error::BadSignature)?;
        verifying
            .verify_strict(body, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| Error::BadSignature)?;

        let entries = sorted(hashes)?;
        let blocked = sorted(blocked_hashes)?;
        if entries.intersection(&blocked).next().is_some() {
            return Err(Error::Malformed("allowlist both allows and blocks an identity"));
        }
        Ok(Self {
            seq,
            entries,
            blocked,
            bytes: bytes.to_vec(),
        })
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn contains(&self, hash: &IdentityHash) -> bool {
        self.entries.contains(hash)
    }

    pub fn entries(&self) -> impl Iterator<Item = &IdentityHash> {
        self.entries.iter()
    }

    pub fn is_blocked(&self, hash: &IdentityHash) -> bool {
        self.blocked.contains(hash)
    }

    pub fn blocked(&self) -> impl Iterator<Item = &IdentityHash> {
        self.blocked.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The signed encoding, to store or send to a peer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for Allowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allowlist")
            .field("seq", &self.seq)
            .field("entries", &self.entries.len())
            .field("blocked", &self.blocked.len())
            .finish()
    }
}

/// Hashes that must be sorted and unique, so one list has one encoding.
fn sorted(hashes: &[u8]) -> Result<BTreeSet<IdentityHash>> {
    let mut set = BTreeSet::new();
    let mut previous: Option<IdentityHash> = None;
    for chunk in hashes.as_chunks::<16>().0 {
        let hash = IdentityHash(*chunk);
        if previous.is_some_and(|p| p >= hash) {
            return Err(Error::Malformed("allowlist is not sorted and unique"));
        }
        previous = Some(hash);
        set.insert(hash);
    }
    Ok(set)
}
