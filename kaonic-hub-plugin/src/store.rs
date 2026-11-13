//! The plugin's own key/value store on the hub: JSON values, kept across restarts and
//! updates, seen by no other plugin.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Hub;
use crate::error::{Error, Result};

/// From [`Hub::store`]. Keys are 1-128 of `A-Z a-z 0-9 . _ -`; see `limits.store` in
/// [`Hub::me`] for the sizes.
#[derive(Clone)]
pub struct Store {
    hub: Hub,
}

/// Checks a key before it goes into a path.
fn key(key: &str) -> Result<&str> {
    let ok = (1..=128).contains(&key.len()) && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if ok { Ok(key) } else { Err(Error::Invalid(format!("store key {key:?}: use 1-128 letters, digits, '.', '_' and '-'"))) }
}

impl Store {
    pub(crate) fn new(hub: Hub) -> Self {
        Self { hub }
    }

    /// The value of `key`; None if there is none.
    pub async fn get<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = format!("/store/{}", key(name)?);
        match self.hub.call("GET", &path, None).await {
            Ok(body) => serde_json::from_slice(&body).map(Some).map_err(|error| Error::Invalid(format!("store key {name:?}: {error}"))),
            Err(Error::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Stores any value that serialises to JSON. [`Error::TooLarge`] with code `too_large`
    /// for a value over `max_value`, or `store_full`.
    pub async fn set<T: Serialize + ?Sized>(&self, name: &str, value: &T) -> Result<()> {
        let path = format!("/store/{}", key(name)?);
        let body = serde_json::to_vec(value).map_err(|error| Error::Invalid(format!("store key {name:?}: {error}")))?;
        self.hub.call("PUT", &path, Some(&body)).await.map(|_| ())
    }

    /// Deletes a value; fine if there was none.
    pub async fn remove(&self, name: &str) -> Result<()> {
        self.hub.call("DELETE", &format!("/store/{}", key(name)?), None).await.map(|_| ())
    }

    /// Every key, sorted.
    pub async fn keys(&self) -> Result<Vec<String>> {
        self.hub.json("/store").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked_before_they_reach_a_path() {
        assert!(key("favourites.v2_a-b").is_ok());
        assert!(key(&"k".repeat(128)).is_ok());
        for bad in ["", "a/b", "../x", "a b", "a?b", "é", &"k".repeat(129)] {
            assert!(matches!(key(bad), Err(Error::Invalid(_))), "{bad}");
        }
    }
}
