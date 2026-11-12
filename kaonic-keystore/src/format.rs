//! On-disk layout, version 1. All integers are little-endian.
//!
//! ```text
//! header  magic "KAONICKS" | version u8 | kind_len u8 | kind | wrapped_len u16 | wrapped
//! body    nonce[24] | XChaCha20-Poly1305(data key, entries, aad = header) incl. tag[16]
//! entries generation u64 | count u32 | { name_len u8 | name | value_len u32 | value } * count
//! ```
//!
//! The wrapped key is authenticated against the header up to `kind`, the body against the
//! whole header. `generation` grows on every write and picks the newer of two copies.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::crypto::{self, DataKey, NONCE_LEN, TAG_LEN};
use crate::{Error, Result, Secret, validate_name};

const MAGIC: &[u8; 8] = b"KAONICKS";
const VERSION: u8 = 1;
const MAX_KIND_LEN: usize = 32;

/// Upper bound for a whole store file. Secrets are small; this only stops runaway input.
pub(crate) const MAX_FILE_LEN: u64 = 4 * 1024 * 1024;

pub(crate) struct Header<'a> {
    pub kind: &'a str,
    pub wrapped: &'a [u8],
}

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty() && kind.len() <= MAX_KIND_LEN && kind.is_ascii()
}

/// The bytes the provider must authenticate the wrapped data key with.
pub(crate) fn wrap_aad(kind: &str) -> Result<Vec<u8>> {
    if !valid_kind(kind) {
        return Err(Error::Provider(format!("invalid provider kind {kind:?}")));
    }
    let mut aad = Vec::with_capacity(MAGIC.len() + 2 + kind.len());
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.push(kind.len() as u8);
    aad.extend_from_slice(kind.as_bytes());
    Ok(aad)
}

pub(crate) fn encode_header(kind: &str, wrapped: &[u8]) -> Result<Vec<u8>> {
    let wrapped_len = u16::try_from(wrapped.len())
        .map_err(|_| Error::Provider("wrapped key blob is larger than 64 KiB".into()))?;
    let mut header = wrap_aad(kind)?;
    header.extend_from_slice(&wrapped_len.to_le_bytes());
    header.extend_from_slice(wrapped);
    Ok(header)
}

/// Split a file into its parsed header, the raw header bytes and the sealed body.
pub(crate) fn decode_file(file: &[u8]) -> Result<(Header<'_>, &[u8], &[u8])> {
    let mut r = Reader(file);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(Error::Corrupt("bad magic"));
    }
    let version = r.u8()?;
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let kind_len = r.u8()? as usize;
    let kind = std::str::from_utf8(r.take(kind_len)?)
        .ok()
        .filter(|k| valid_kind(k))
        .ok_or(Error::Corrupt("bad provider kind"))?;
    let wrapped_len = r.u16()? as usize;
    let wrapped = r.take(wrapped_len)?;
    let (header_bytes, body) = file.split_at(file.len() - r.0.len());
    Ok((Header { kind, wrapped }, header_bytes, body))
}

/// Build a whole file, encoding and encrypting the entries in a single buffer.
pub(crate) fn seal_file(
    header: &[u8],
    dek: &DataKey,
    generation: u64,
    entries: &BTreeMap<String, Secret>,
) -> Result<Vec<u8>> {
    let plain_len = 8
        + 4
        + entries
            .iter()
            .map(|(name, value)| 1 + name.len() + 4 + value.len())
            .sum::<usize>();
    let len = header.len() + NONCE_LEN + plain_len + TAG_LEN;
    if len as u64 > MAX_FILE_LEN {
        return Err(Error::TooLarge);
    }
    // Zeroizing until sealed, in case sealing fails with plaintext in the buffer.
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(header);
    out.extend_from_slice(&[0u8; NONCE_LEN]);
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, value) in entries {
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.expose());
    }
    crypto::seal_in_place(dek.as_bytes(), &mut out, header.len())?;
    debug_assert_eq!(out.len(), len);
    Ok(std::mem::take(&mut *out))
}

/// The generation counter at the start of decrypted entries.
pub(crate) fn generation(plain: &[u8]) -> Result<u64> {
    Reader(plain).u64()
}

pub(crate) fn decode_entries(plain: &[u8]) -> Result<BTreeMap<String, Secret>> {
    let mut r = Reader(plain);
    r.u64()?;
    let count = r.u32()?;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let name_len = r.u8()? as usize;
        let name = std::str::from_utf8(r.take(name_len)?)
            .map_err(|_| Error::Corrupt("entry name is not UTF-8"))?;
        validate_name(name).map_err(|_| Error::Corrupt("invalid entry name"))?;
        let value_len = r.u32()? as usize;
        let value = Secret::new(r.take(value_len)?);
        if entries.insert(name.to_owned(), value).is_some() {
            return Err(Error::Corrupt("duplicate entry name"));
        }
    }
    if !r.0.is_empty() {
        return Err(Error::Corrupt("trailing bytes after entries"));
    }
    Ok(entries)
}

/// Bounds-checked little-endian reader; running out of input is [`Error::Corrupt`].
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or(Error::Corrupt("unexpected end of data"))?;
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(Error::Corrupt("unexpected end of data"))?;
        self.0 = tail;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_le_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }
}
