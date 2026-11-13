//! Plugin tokens: who a plugin is and what it may do, signed by the installer.
//!
//! ```text
//! kpt1.<base64url(claims JSON)>.<base64url(Ed25519 signature of "kpt1.<claims>")>
//! claims = {"id": "audio-ptt", "permissions": ["audio", "mesh"], "issued": 1794000000, "serial": "9f3c…"}
//! ```
//!
//! The installer writes a plugin's token to `<plugin>/token`, readable by that plugin's user
//! only, at every install and rollback. The plugin sends it as is; it does not need to know
//! its own id. The hub checks the signature with the installer's public key and reads the id
//! and permissions from the claims. A token stops working when the plugin is removed or a new
//! one is issued: the hub also compares its hash with the plugin's record.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kaonic_hub_common::base64;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::manifest::Permission;

const PREFIX: &str = "kpt1.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub id: String,
    pub permissions: Vec<Permission>,
    /// Unix seconds.
    pub issued: u64,
    /// Random, so every issued token differs.
    pub serial: String,
}

/// The installer's token key, kept in its state directory.
pub struct TokenKey {
    key: SigningKey,
}

impl TokenKey {
    /// Loads the key from `path`, or makes one there.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice())
        {
            return Ok(Self { key: SigningKey::from_bytes(&seed) });
        }
        let seed = crate::random::<32>().map_err(Error::io("random"))?;
        crate::write_atomic(path, &seed, 0o600).map_err(Error::io("writing the token key"))?;
        Ok(Self { key: SigningKey::from_bytes(&seed) })
    }

    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn issue(&self, id: &str, permissions: &[Permission], issued: u64) -> Result<String, Error> {
        let serial = crate::hex(&crate::random::<8>().map_err(Error::io("random"))?);
        let claims = Claims { id: id.to_owned(), permissions: permissions.to_vec(), issued, serial };
        let signed = format!("{PREFIX}{}", base64::encode_url(&serde_json::to_vec(&claims).expect("claims serialise")));
        let signature = self.key.sign(signed.as_bytes());
        Ok(format!("{signed}.{}", base64::encode_url(&signature.to_bytes())))
    }
}

/// Checks a token against the installer's public key and returns its claims.
pub fn verify(public: &[u8; 32], token: &str) -> Option<Claims> {
    if token.len() > 1024 {
        return None;
    }
    let (signed, signature) = token.rsplit_once('.')?;
    let claims = signed.strip_prefix(PREFIX)?;
    let key = VerifyingKey::from_bytes(public).ok()?;
    let signature = Signature::from_slice(&base64::decode_url(signature)?).ok()?;
    key.verify(signed.as_bytes(), &signature).ok()?;
    serde_json::from_slice(&base64::decode_url(claims)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TokenKey {
        TokenKey { key: SigningKey::from_bytes(&crate::random::<32>().unwrap()) }
    }

    #[test]
    fn a_token_says_who_the_plugin_is() {
        let key = key();
        let token = key.issue("audio-ptt", &[Permission::Audio, Permission::Mesh], 1_794_000_000).unwrap();
        assert!(token.starts_with("kpt1.") && !token.contains('=') && !token.contains('/'));
        let claims = verify(&key.public(), &token).unwrap();
        assert_eq!(claims.id, "audio-ptt");
        assert_eq!(claims.permissions, [Permission::Audio, Permission::Mesh]);
        assert_ne!(key.issue("audio-ptt", &[], 1).unwrap(), key.issue("audio-ptt", &[], 1).unwrap(), "serials differ");
    }

    #[test]
    fn a_changed_or_foreign_token_is_refused() {
        let key = key();
        let token = key.issue("sample", &[], 1).unwrap();
        // Claim another id with the same signature.
        let (_, signature) = token.rsplit_once('.').unwrap();
        let forged = format!("kpt1.{}.{signature}", base64::encode_url(br#"{"id":"other","permissions":["root"],"issued":1,"serial":"00"}"#));
        assert!(verify(&key.public(), &forged).is_none());
        assert!(verify(&self::key().public(), &token).is_none(), "another installer's key");
        assert!(verify(&key.public(), "kpt1.e30").is_none());
        assert!(verify(&key.public(), &token.replace("kpt1.", "kpt2.")).is_none());
    }
}
