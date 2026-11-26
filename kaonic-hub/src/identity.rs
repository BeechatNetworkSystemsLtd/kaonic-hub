//! This node's Reticulum identity: an X25519 key (encryption) and an Ed25519
//! key (signatures), as Reticulum lays them out (64 private bytes, x25519 first).
//!
//! A member keeps the random identity made on first boot. The Kaonic Admin's
//! keys are derived from its seed phrase, so the same words always give the
//! same admin, which is how an admin is recovered: the words give the standard
//! BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, no passphrase), and HKDF-SHA256
//! derives each key from that seed under its own label.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use kaonic_pki::Identity;
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::random;

const BIP39_ROUNDS: u32 = 2048;
/// One label per key, so each comes from the seed independently.
const X25519_LABEL: &[u8] = b"kaonic admin x25519 v1";
const ED25519_LABEL: &[u8] = b"kaonic admin ed25519 v1";

/// The BIP39 seed of a phrase (words in lowercase, single spaces).
fn bip39_seed(phrase: &str, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let salt = Zeroizing::new(format!("mnemonic{passphrase}"));
    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(phrase.as_bytes(), salt.as_bytes(), BIP39_ROUNDS, seed.as_mut());
    seed
}

pub struct NodeIdentity {
    x25519: StaticSecret,
    ed25519: SigningKey,
}

impl NodeIdentity {
    pub fn generate() -> std::io::Result<Self> {
        let bytes = Zeroizing::new(random::bytes::<64>()?);
        Ok(Self::from_bytes(&bytes))
    }

    /// The admin identity for a seed phrase, as `mnemonic::parse` returns it.
    pub fn from_phrase(phrase: &str) -> Self {
        let seed = bip39_seed(phrase, "");
        let hkdf = Hkdf::<Sha256>::new(None, seed.as_ref());
        let mut bytes = Zeroizing::new([0u8; 64]);
        let (x25519, ed25519) = bytes.split_at_mut(32);
        hkdf.expand(X25519_LABEL, x25519).expect("32 bytes is a valid HKDF length");
        hkdf.expand(ED25519_LABEL, ed25519).expect("32 bytes is a valid HKDF length");
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn the_seed_is_the_bip39_one() {
        // BIP39 test vectors (passphrase "TREZOR").
        let abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            hex(bip39_seed(abandon, "TREZOR").as_ref()),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        let legal = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(
            hex(bip39_seed(legal, "TREZOR").as_ref()),
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        );
    }

    #[test]
    fn round_trips_and_the_phrase_gives_the_same_admin() {
        let identity = NodeIdentity::generate().unwrap();
        let again = NodeIdentity::from_bytes(&identity.to_bytes());
        assert_eq!(identity.public().hash(), again.public().hash());

        let a = NodeIdentity::from_phrase("abandon amount liar amount expire adjust cage candy arch gather drum buyer");
        let b = NodeIdentity::from_phrase("abandon amount liar amount expire adjust cage candy arch gather drum buyer");
        let c = NodeIdentity::from_phrase("avoid mass luggage choice fabric argue gather cash brand thought elegant divide");
        assert_eq!(a.public().hash(), b.public().hash());
        assert_ne!(a.public().hash(), c.public().hash());
        // The two keys come from the seed independently.
        let bytes = a.to_bytes();
        assert_ne!(bytes[..32], bytes[32..]);
    }
}
