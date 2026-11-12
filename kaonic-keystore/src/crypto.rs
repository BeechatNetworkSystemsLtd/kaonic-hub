//! XChaCha20-Poly1305 with random nonces. ChaCha, not AES: the SoC has no AES
//! hardware, and in software ChaCha is faster and constant-time.

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

/// The 256-bit data key that encrypts the store body. Providers wrap and unwrap it.
pub struct DataKey(Zeroizing<[u8; KEY_LEN]>);

impl DataKey {
    pub(crate) fn generate() -> Result<Self> {
        Ok(Self(random_key()?))
    }

    /// Rebuild a data key from bytes a provider has just unwrapped.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// The 32 key bytes, for a provider to wrap.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}

/// Fill `buf` from the kernel CSPRNG (`getentropy`, at most 256 bytes per call).
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    for chunk in buf.chunks_mut(256) {
        // SAFETY: the pointer and length describe the writable slice `chunk`.
        if unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } != 0 {
            return Err(Error::Rng(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

pub(crate) fn random_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(key.as_mut())?;
    Ok(key)
}

/// Encrypt `plaintext` and return `nonce || ciphertext || tag`.
pub(crate) fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::TooLarge)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// [`seal`] in place: `buf` is `aad || nonce slot || plaintext`; the tag is appended.
pub(crate) fn seal_in_place(key: &[u8; KEY_LEN], buf: &mut Vec<u8>, aad_len: usize) -> Result<()> {
    let (aad, rest) = buf.split_at_mut(aad_len);
    let (nonce, msg) = rest.split_at_mut(NONCE_LEN);
    fill_random(nonce)?;
    let tag = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, msg)
        .map_err(|_| Error::TooLarge)?;
    buf.extend_from_slice(&tag);
    Ok(())
}

/// Reverse of [`seal`]. `None` if authentication fails; the caller picks the error.
pub(crate) fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}
