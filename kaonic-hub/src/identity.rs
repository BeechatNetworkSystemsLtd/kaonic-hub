//! This node's Reticulum identity: an X25519 key (encryption) and an Ed25519
//! key (signatures), as Reticulum lays them out (64 private bytes, x25519 first).
//!
//! A member keeps the random identity made on first boot. The Kaonic Admin's
//! identity is derived from its seed password, so the same seed always gives
//! the same admin, which is how an admin is recovered.

use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::SigningKey;
use kaonic_pki::Identity;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::random;

/// Domain-separates the admin derivation from every other use of the seed.
const ADMIN_SALT: &[u8] = b"kaonic-admin-identity v1";
/// The cost of one guess at the seed: anyone who hears the admin announce can try offline.
const ADMIN_KDF: (u32, u32, u32) = (64 * 1024, 3, 1);

pub struct NodeIdentity {
    x25519: StaticSecret,
    ed25519: SigningKey,
}

impl NodeIdentity {
    pub fn generate() -> std::io::Result<Self> {
        let bytes = Zeroizing::new(random::bytes::<64>()?);
        Ok(Self::from_bytes(&bytes))
    }

    /// The admin identity for a seed password. Slow on purpose (Argon2id, 64 MiB).
    pub fn from_seed(seed: &str) -> Self {
        let (memory, time, lanes) = ADMIN_KDF;
        let params = Params::new(memory, time, lanes, Some(64)).expect("valid Argon2 parameters");
        let mut bytes = Zeroizing::new([0u8; 64]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(seed.as_bytes(), ADMIN_SALT, bytes.as_mut())
            .expect("Argon2 accepts a 64-byte output");
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let (x25519, ed25519) = bytes.split_at(32);
        Self {
            x25519: StaticSecret::from(<[u8; 32]>::try_from(x25519).expect("32 bytes")),
            ed25519: SigningKey::from_bytes(&<[u8; 32]>::try_from(ed25519).expect("32 bytes")),
        }
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        bytes[..32].copy_from_slice(self.x25519.as_bytes());
        bytes[32..].copy_from_slice(&self.ed25519.to_bytes());
        bytes
    }

    pub fn public(&self) -> Identity {
        Identity {
            x25519: PublicKey::from(&self.x25519).to_bytes(),
            ed25519: self.ed25519.verifying_key().to_bytes(),
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.ed25519
    }

    /// The same identity, as Reticulum holds it.
    pub fn to_reticulum(&self) -> kaonic_mesh::reticulum::identity::PrivateIdentity {
        kaonic_mesh::reticulum::identity::PrivateIdentity::new(
            self.x25519.clone(),
            self.ed25519.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_the_seed_gives_the_same_admin() {
        let identity = NodeIdentity::generate().unwrap();
        let again = NodeIdentity::from_bytes(&identity.to_bytes());
        assert_eq!(identity.public().hash(), again.public().hash());

        let a = NodeIdentity::from_seed("a long enough seed phrase");
        let b = NodeIdentity::from_seed("a long enough seed phrase");
        let c = NodeIdentity::from_seed("another long seed phrase!");
        assert_eq!(a.public().hash(), b.public().hash());
        assert_ne!(a.public().hash(), c.public().hash());
    }
}
