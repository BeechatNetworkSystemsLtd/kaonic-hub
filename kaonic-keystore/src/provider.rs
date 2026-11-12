//! Key providers wrap and unwrap the 32-byte data key, so a hardware backend never has
//! to expose its key.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::{self, DataKey, KEY_LEN};
use crate::format::Reader;
use crate::fsutil;
use crate::{Error, Result};

/// Wraps and unwraps a store's [`DataKey`] under a key-encryption key (KEK).
///
/// Implement this for a hardware or TEE backend that never releases its KEK. The wrapped
/// blob may be at most 64 KiB.
pub trait KeyProvider: Send + Sync {
    /// Stable identifier written into the store header, at most 32 ASCII bytes.
    /// A store only opens with a provider of the same kind.
    fn kind(&self) -> &str;

    /// Seal `dek` into an opaque blob, authenticating `aad` with it.
    ///
    /// Must be safe to call more than once with the same key (e.g. use a random nonce).
    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>>;

    /// Reverse of [`wrap`](Self::wrap). Returns [`Error::WrongKey`] if authentication fails.
    ///
    /// `blob` comes from the file and may be hostile.
    fn unwrap(&self, blob: &[u8], aad: &[u8]) -> Result<DataKey>;
}

fn unwrap_sealed(kek: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<DataKey> {
    let dek = crypto::open(kek, aad, sealed).ok_or(Error::WrongKey)?;
    let dek: &[u8; KEY_LEN] = dek.as_slice().try_into().map_err(|_| Error::WrongKey)?;
    Ok(DataKey::from_bytes(dek))
}

/// A raw 256-bit KEK: from a key file, or derived by the caller from a device secret.
///
/// Keep a key file off the medium that holds the store.
pub struct RawKey {
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl RawKey {
    /// The provider kind stored in the header.
    pub const KIND: &'static str = "raw";

    /// Use `key` as the KEK.
    pub fn from_bytes(key: &[u8; KEY_LEN]) -> Self {
        Self {
            key: Zeroizing::new(*key),
        }
    }

    /// A new random KEK, held only in memory.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            key: crypto::random_key()?,
        })
    }

    /// Load a key file of exactly 32 bytes, owned by us with mode 0600 or 0400.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        fsutil::check_dir(path)?;
        let bytes = fsutil::read_private(path, KEY_LEN as u64)?
            .ok_or_else(|| Error::NotFound(path.to_owned()))?;
        let key: &[u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupt("key file must be exactly 32 bytes"))?;
        Ok(Self::from_bytes(key))
    }

    /// Generate a key into a new 0600 file. Fails if it exists; never leaves a partial file.
    pub fn generate_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let this = Self::generate()?;
        fsutil::check_dir(path)?;
        fsutil::write_new(path, this.key.as_ref())?;
        Ok(this)
    }
}

impl KeyProvider for RawKey {
    fn kind(&self) -> &str {
        Self::KIND
    }

    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>> {
        crypto::seal(&self.key, aad, dek.as_bytes())
    }

    fn unwrap(&self, blob: &[u8], aad: &[u8]) -> Result<DataKey> {
        unwrap_sealed(&self.key, aad, blob)
    }
}

impl std::fmt::Debug for RawKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawKey([REDACTED])")
    }
}

/// Argon2id costs, stored in the file, so changing defaults never locks out a store.
///
/// Do not seal with more than 256 MiB, 32 passes or 4 lanes: such a store will not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Number of lanes. More lanes do not make it faster here.
    pub p_cost: u32,
}

impl KdfParams {
    // Upper bounds accepted from a file, so a crafted header cannot exhaust RAM or CPU.
    const MAX_M_COST_KIB: u32 = 256 * 1024;
    const MAX_T_COST: u32 = 32;
    const MAX_P_COST: u32 = 4;
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane (OWASP minimum; one core). About a second on the device.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// A KEK derived from a passphrase with Argon2id, for backups and operator-unlocked stores.
///
/// Slow: runs Argon2id, about a second, on every create, open and rekey.
pub struct Passphrase {
    passphrase: Zeroizing<Vec<u8>>,
    params: KdfParams,
}

impl Passphrase {
    /// The provider kind stored in the header.
    pub const KIND: &'static str = "argon2id";
    const SALT_LEN: usize = 16;

    /// A passphrase provider with the default [`KdfParams`].
    pub fn new(passphrase: impl Into<Vec<u8>>) -> Self {
        Self::with_params(passphrase, KdfParams::default())
    }

    /// `params` apply when wrapping; unwrapping uses the ones stored in the file.
    pub fn with_params(passphrase: impl Into<Vec<u8>>, params: KdfParams) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.into()),
            params,
        }
    }

    fn derive(&self, params: KdfParams, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let argon_params = Params::new(
            params.m_cost_kib,
            params.t_cost,
            params.p_cost,
            Some(KEY_LEN),
        )
        .map_err(|e| Error::Provider(format!("argon2 parameters: {e}")))?;
        let mut kek = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
            .hash_password_into(&self.passphrase, salt, kek.as_mut())
            .map_err(|e| Error::Provider(format!("argon2: {e}")))?;
        Ok(kek)
    }
}

impl KeyProvider for Passphrase {
    fn kind(&self) -> &str {
        Self::KIND
    }

    /// Blob: `m_cost | t_cost | p_cost` (u32le) `| salt[16] | sealed key`, all authenticated.
    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>> {
        let mut salt = [0u8; Self::SALT_LEN];
        crypto::fill_random(&mut salt)?;
        let kek = self.derive(self.params, &salt)?;

        let mut blob = Vec::new();
        blob.extend_from_slice(&self.params.m_cost_kib.to_le_bytes());
        blob.extend_from_slice(&self.params.t_cost.to_le_bytes());
        blob.extend_from_slice(&self.params.p_cost.to_le_bytes());
        blob.extend_from_slice(&salt);
        let sealed = crypto::seal(&kek, &[aad, &blob].concat(), dek.as_bytes())?;
        blob.extend_from_slice(&sealed);
        Ok(blob)
    }

    fn unwrap(&self, blob: &[u8], aad: &[u8]) -> Result<DataKey> {
        let mut r = Reader(blob);
        let params = KdfParams {
            m_cost_kib: r.u32()?,
            t_cost: r.u32()?,
            p_cost: r.u32()?,
        };
        let salt = r.take(Self::SALT_LEN)?;
        if params.m_cost_kib > KdfParams::MAX_M_COST_KIB
            || params.t_cost > KdfParams::MAX_T_COST
            || params.p_cost > KdfParams::MAX_P_COST
        {
            return Err(Error::Corrupt("passphrase KDF parameters out of range"));
        }
        let (prefix, sealed) = blob.split_at(blob.len() - r.0.len());
        let kek = self.derive(params, salt)?;
        unwrap_sealed(&kek, &[aad, prefix].concat(), sealed)
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passphrase")
            .field("passphrase", &"[REDACTED]")
            .field("params", &self.params)
            .finish()
    }
}

/// A KEK bound to this chip and to an application token: Argon2id over the SoC's unique
/// device ID and the token, with a random salt stored in the file.
///
/// The UID ties the store to one board, so a copied card does not open on other hardware.
/// It is not secret: the public serial and Wi-Fi SSID are hashes of it, and UIDs are
/// structured enough to enumerate. The token carries the secrecy, so it must be random
/// and must not be stored on the same card in the clear.
pub struct DeviceKey(Passphrase);

impl DeviceKey {
    /// The provider kind stored in the header.
    pub const KIND: &'static str = "device-argon2id";
    /// The shortest application token accepted, in bytes. Use at least 32 random bytes.
    pub const MIN_TOKEN_LEN: usize = 16;
    const DOMAIN: &'static [u8] = b"kaonic-keystore device-key v1\0";

    /// OTP words 13-15 hold the SoC's 96-bit unique device ID.
    const NVMEM: &'static str = "/sys/bus/nvmem/devices/stm32-romem0/nvmem";
    const UID_OFFSET: u64 = 13 * 4;
    const UID_LEN: usize = 12;

    /// Bind to this board's SoC UID. Needs read access to the OTP nvmem (root).
    pub fn for_this_device(app_token: &[u8]) -> Result<Self> {
        Self::new(&Self::read_uid(Path::new(Self::NVMEM))?, app_token)
    }

    /// Bind to a given device ID, for tests and other devices.
    ///
    /// Fails with [`Error::Provider`] for a blank ID or a token shorter than
    /// [`MIN_TOKEN_LEN`](Self::MIN_TOKEN_LEN).
    pub fn new(device_id: &[u8], app_token: &[u8]) -> Result<Self> {
        Self::with_params(device_id, app_token, KdfParams::default())
    }

    /// `params` apply when wrapping; unwrapping uses the ones stored in the file.
    pub fn with_params(device_id: &[u8], app_token: &[u8], params: KdfParams) -> Result<Self> {
        // An unprogrammed or unreadable OTP reads as all 0x00 or 0xFF; a key derived from
        // it would be the same on every board.
        if device_id.is_empty()
            || device_id.len() > usize::from(u8::MAX)
            || device_id.iter().all(|&b| b == 0x00)
            || device_id.iter().all(|&b| b == 0xFF)
        {
            return Err(Error::Provider("device ID is missing or blank".into()));
        }
        if app_token.len() < Self::MIN_TOKEN_LEN {
            return Err(Error::Provider(format!(
                "application token must be at least {} bytes",
                Self::MIN_TOKEN_LEN
            )));
        }
        // DOMAIN | uid_len u8 | uid | token: unambiguous, and never equal to a passphrase.
        let mut input = Zeroizing::new(Vec::with_capacity(
            Self::DOMAIN.len() + 1 + device_id.len() + app_token.len(),
        ));
        input.extend_from_slice(Self::DOMAIN);
        input.push(device_id.len() as u8);
        input.extend_from_slice(device_id);
        input.extend_from_slice(app_token);
        Ok(Self(Passphrase {
            passphrase: input,
            params,
        }))
    }

    fn read_uid(nvmem: &Path) -> Result<[u8; Self::UID_LEN]> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(nvmem)?;
        file.seek(SeekFrom::Start(Self::UID_OFFSET))?;
        let mut uid = [0u8; Self::UID_LEN];
        file.read_exact(&mut uid)?;
        Ok(uid)
    }
}

impl KeyProvider for DeviceKey {
    fn kind(&self) -> &str {
        Self::KIND
    }

    fn wrap(&self, dek: &DataKey, aad: &[u8]) -> Result<Vec<u8>> {
        self.0.wrap(dek, aad)
    }

    fn unwrap(&self, blob: &[u8], aad: &[u8]) -> Result<DataKey> {
        self.0.unwrap(blob, aad)
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_uid_from_otp_words_13_to_15() {
        let path = std::env::temp_dir().join(format!("kaonic-nvmem-{}", std::process::id()));
        let mut otp = vec![0u8; 96 * 4];
        otp[52..64].copy_from_slice(b"UID-96-BITS!");
        std::fs::write(&path, &otp).unwrap();
        let uid = DeviceKey::read_uid(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(&uid.unwrap(), b"UID-96-BITS!");
    }
}
