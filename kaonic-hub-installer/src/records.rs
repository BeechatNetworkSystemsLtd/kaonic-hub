//! What the installer remembers, in its own root-only directory: one record per plugin,
//! the policy, and what stays known of removed plugins (`removed.json`: the highest
//! version, the downgrade floor, and the uid while their `data/` is kept). Plugins cannot
//! write here, so nothing they do changes what the hub is told about them. A record read
//! back is checked like a new manifest ([`Record::check`]) before it is used.

use std::collections::BTreeMap;
use std::fs;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::manifest::{self, Manifest, Permission};
use crate::names::{self, Version};

/// The uids plugins run as, one each; `root` plugins run as 0.
pub const UIDS: RangeInclusive<u32> = 61_000..=61_999;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub manifest: Manifest,
    /// The uid (and gid) it runs as: from [`UIDS`], or 0 for a `root` plugin.
    pub uid: u32,
    /// Signed by a release key ("official").
    pub signed: bool,
    /// Unix seconds.
    pub installed_at: u64,
    /// Started at boot and kept running.
    pub enabled: bool,
    /// The highest version ever installed: going below needs the admin to say so.
    pub highest_version: String,
    /// The version kept for rollback, if any.
    pub previous: Option<Box<Record>>,
    /// SHA-256 of the plugin's API token, so the hub can tell which plugin calls it.
    pub token_sha256: String,
}

impl Record {
    /// The checks a new install passes, for a record read back from disk: a valid manifest
    /// with id `id`, a uid that fits its permissions, and the same for `previous`.
    pub fn check(&self, id: &str) -> Result<(), Error> {
        self.check_one(id)?;
        if let Some(previous) = &self.previous {
            if previous.previous.is_some() {
                return Err(Error::invalid(format!("the record of {id} nests previous versions")));
            }
            previous.check_one(id)?;
        }
        Ok(())
    }

    fn check_one(&self, id: &str) -> Result<(), Error> {
        names::id(&self.manifest.id)?;
        if self.manifest.id != id {
            return Err(Error::invalid(format!("the record of {id} is for {}", self.manifest.id)));
        }
        manifest::validate(&self.manifest)?;
        Version::parse(&self.highest_version)?;
        let uid_ok = if self.manifest.has(Permission::Root) { self.uid == 0 } else { UIDS.contains(&self.uid) };
        if !uid_ok {
            return Err(Error::invalid(format!("the record of {id} has uid {}, which does not fit its permissions", self.uid)));
        }
        if self.token_sha256.len() != 64 || !self.token_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::invalid(format!("the record of {id} has no token hash")));
        }
        Ok(())
    }
}

/// What stays known of a removed plugin.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    /// The highest version it ever had: a reinstall below it needs `allow_downgrade`.
    pub highest_version: String,
    /// Its uid while its `data/` is kept (removed with `keep_data`).
    #[serde(default)]
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Refuse packages that are not signed by a release key.
    pub require_signed: bool,
}

pub struct Records {
    dir: PathBuf,
}

impl Records {
    pub fn open(state: &Path) -> Result<Self, Error> {
        let dir = state.join("records");
        fs::create_dir_all(&dir).map_err(Error::io("making the records directory"))?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> Result<PathBuf, Error> {
        Ok(self.dir.join(format!("{}.json", names::id(id)?)))
    }

    /// The record of plugin `id`, if it is there and passes [`Record::check`].
    pub fn get(&self, id: &str) -> Option<Record> {
        let bytes = fs::read(self.path(id).ok()?).ok()?;
        let record: Record = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(error) => {
                log::warn!("installer: record of {id} is unreadable: {error}");
                return None;
            }
        };
        match record.check(id) {
            Ok(()) => Some(record),
            Err(error) => {
                log::warn!("installer: record of {id} is refused: {error}");
                None
            }
        }
    }

    pub fn all(&self) -> Vec<Record> {
        let mut ids: Vec<String> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".json").filter(|id| names::id(id).is_ok()).map(str::to_owned))
            .collect();
        ids.sort();
        ids.iter().filter_map(|id| self.get(id)).collect()
    }

    pub fn put(&self, record: &Record) -> Result<(), Error> {
        let bytes = serde_json::to_vec_pretty(record).expect("a record serialises");
        crate::write_atomic(&self.path(&record.manifest.id)?, &bytes, 0o600).map_err(Error::io("writing a record"))
    }

    pub fn remove(&self, id: &str) -> Result<(), Error> {
        match fs::remove_file(self.path(id)?) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(Error::io("removing a record")(error)),
            _ => Ok(()),
        }
    }

    fn state(&self, name: &str) -> PathBuf {
        self.dir.parent().expect("records is inside the state directory").join(name)
    }

    pub fn policy(&self) -> Policy {
        fs::read(self.state("policy.json")).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
    }

    pub fn set_policy(&self, policy: &Policy) -> Result<(), Error> {
        crate::write_atomic(&self.state("policy.json"), &serde_json::to_vec_pretty(policy).expect("serialises"), 0o600).map_err(Error::io("writing the policy"))
    }

    /// Removed plugins, by id.
    pub fn removed(&self) -> BTreeMap<String, Removed> {
        fs::read(self.state("removed.json")).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
    }

    pub fn set_removed(&self, removed: &BTreeMap<String, Removed>) -> Result<(), Error> {
        crate::write_atomic(&self.state("removed.json"), &serde_json::to_vec_pretty(removed).expect("serialises"), 0o600).map_err(Error::io("writing removed.json"))
    }
}
