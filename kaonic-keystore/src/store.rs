use std::collections::BTreeMap;
use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{self, DataKey};
use crate::provider::KeyProvider;
use crate::{Error, Result, Secret, format, fsutil, validate_name};

/// An open keystore, stored as `<path>` and an identical `<path>.mirror`.
///
/// - Every write replaces both copies atomically, primary first; the primary is the commit.
/// - On open, the newest copy that authenticates wins and the other is rewritten from it.
/// - Files are 0600, owned by us, never followed through symlinks, and locked against a
///   second process via `<path>.lock`.
/// - The provider is not kept after the call; the data key and entries are zeroized on drop.
///
/// Entries live decrypted in memory; each write rewrites the whole store.
pub struct Keystore {
    path: PathBuf,
    mirror: PathBuf,
    dek: DataKey,
    header: Vec<u8>,
    generation: u64,
    entries: BTreeMap<String, Secret>,
    recovery: Option<Recovery>,
    degraded: Option<String>,
    _lock: File,
}

/// The state of one copy of the store as found on open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyState {
    /// Good and newest.
    Current,
    /// The file did not exist.
    Missing,
    /// Valid, but older than the other copy: a write was cut short.
    Stale {
        /// The generation this copy was at.
        generation: u64,
    },
    /// Unreadable or failed authentication; the reason is the error it gave.
    Damaged(String),
}

/// What [`Keystore::open`] found when the two copies did not agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// The state of `<path>` as found.
    pub primary: CopyState,
    /// The state of `<path>.mirror` as found.
    pub mirror: CopyState,
}

/// One authenticated copy; only the winner's entries are decoded.
struct Copy {
    bytes: Zeroizing<Vec<u8>>,
    dek: DataKey,
    plain: Zeroizing<Vec<u8>>,
    generation: u64,
}

impl Keystore {
    /// Create a new, empty store. Fails with [`Error::AlreadyExists`] if either copy exists.
    ///
    /// Slow with the Argon2 providers: about a second.
    pub fn create(path: impl AsRef<Path>, provider: &dyn KeyProvider) -> Result<Self> {
        let (path, mirror, lock) = prepare(path.as_ref())?;
        if path.try_exists()? || mirror.try_exists()? {
            return Err(Error::AlreadyExists(path));
        }
        Self::init(path, mirror, provider, lock)
    }

    /// Open an existing store, repairing a missing, stale or damaged copy.
    ///
    /// Slow with the Argon2 providers: about a second. Returns [`Error::Locked`] if the store
    /// is already open.
    pub fn open(path: impl AsRef<Path>, provider: &dyn KeyProvider) -> Result<Self> {
        let (path, mirror, lock) = prepare(path.as_ref())?;
        Self::load(path, mirror, provider, lock)
    }

    /// Open the store, or create it if neither copy exists. An unreadable store is an
    /// error, never replaced.
    ///
    /// On an unmounted or wrong directory this silently creates a new store.
    pub fn open_or_create(path: impl AsRef<Path>, provider: &dyn KeyProvider) -> Result<Self> {
        let (path, mirror, lock) = prepare(path.as_ref())?;
        if path.try_exists()? || mirror.try_exists()? {
            Self::load(path, mirror, provider, lock)
        } else {
            Self::init(path, mirror, provider, lock)
        }
    }

    fn init(
        path: PathBuf,
        mirror: PathBuf,
        provider: &dyn KeyProvider,
        lock: File,
    ) -> Result<Self> {
        let dek = DataKey::generate()?;
        let header = seal_header(provider, &dek)?;
        let mut store = Self {
            path,
            mirror,
            dek,
            header,
            generation: 0,
            entries: BTreeMap::new(),
            recovery: None,
            degraded: None,
            _lock: lock,
        };
        store.save()?;
        Ok(store)
    }

    fn load(
        path: PathBuf,
        mirror: PathBuf,
        provider: &dyn KeyProvider,
        lock: File,
    ) -> Result<Self> {
        let primary_bytes = fsutil::read_private(&path, format::MAX_FILE_LEN);
        let mirror_bytes = fsutil::read_private(&mirror, format::MAX_FILE_LEN);

        // The normal case: both copies are byte-identical, so authenticate one.
        let (primary, secondary) = match (primary_bytes, mirror_bytes) {
            (Ok(Some(p)), Ok(Some(m))) if p == m => {
                let copy = open_copy(p, provider)?;
                return Self::from_copy(path, mirror, copy, None, lock);
            }
            (p, m) => (
                p.and_then(|b| b.map(|b| open_copy(b, provider)).transpose()),
                m.and_then(|b| b.map(|b| open_copy(b, provider)).transpose()),
            ),
        };

        let newest = [&primary, &secondary]
            .into_iter()
            .filter_map(|r| r.as_ref().ok()?.as_ref())
            .map(|c| c.generation)
            .max();
        let Some(newest) = newest else {
            return Err(no_usable_copy(&path, primary, secondary));
        };
        let state = |r: &Result<Option<Copy>>| match r {
            Ok(Some(c)) if c.generation == newest => CopyState::Current,
            Ok(Some(c)) => CopyState::Stale {
                generation: c.generation,
            },
            Ok(None) => CopyState::Missing,
            Err(e) => CopyState::Damaged(e.to_string()),
        };
        let recovery = Recovery {
            primary: state(&primary),
            mirror: state(&secondary),
        };
        let copy = [primary, secondary]
            .into_iter()
            .flatten()
            .flatten()
            .find(|c| c.generation == newest)
            .expect("`newest` is the generation of a readable copy");

        // Rewrite the out-of-date copies with the winner's exact bytes.
        let targets: Vec<&Path> = [(&recovery.primary, &path), (&recovery.mirror, &mirror)]
            .into_iter()
            .filter(|(state, _)| **state != CopyState::Current)
            .map(|(_, p)| p.as_path())
            .collect();
        let degraded = degraded(&targets, fsutil::replace_in_order(&targets, &copy.bytes));

        let mut store = Self::from_copy(path, mirror, copy, Some(recovery), lock)?;
        store.degraded = degraded;
        Ok(store)
    }

    fn from_copy(
        path: PathBuf,
        mirror: PathBuf,
        copy: Copy,
        recovery: Option<Recovery>,
        lock: File,
    ) -> Result<Self> {
        let (_, header, _) = format::decode_file(&copy.bytes)?;
        Ok(Self {
            path,
            mirror,
            header: header.to_vec(),
            entries: format::decode_entries(&copy.plain)?,
            dek: copy.dek,
            generation: copy.generation,
            recovery,
            degraded: None,
            _lock: lock,
        })
    }

    fn save(&mut self) -> Result<()> {
        let generation = self.generation + 1;
        let bytes = format::seal_file(&self.header, &self.dek, generation, &self.entries)?;
        self.commit(generation, &bytes)
    }

    /// Write both copies. A failed primary is an error; a failed mirror only sets `degraded`.
    fn commit(&mut self, generation: u64, bytes: &[u8]) -> Result<()> {
        let targets = [self.path.as_path(), self.mirror.as_path()];
        match fsutil::replace_in_order(&targets, bytes) {
            (0, Err(e)) => Err(e),
            outcome => {
                self.degraded = degraded(&targets, outcome);
                self.generation = generation;
                Ok(())
            }
        }
    }

    /// The primary copy's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The kind of provider the store is sealed with, e.g. `"raw"` or `"argon2id"`.
    pub fn provider_kind(&self) -> &str {
        // The header was built or validated before it was stored, so it always parses.
        format::decode_file(&self.header).map_or("", |(header, _, _)| header.kind)
    }

    /// What open repaired, if anything. Worth logging: repeated damage means failing storage.
    pub fn recovery(&self) -> Option<&Recovery> {
        self.recovery.as_ref()
    }

    /// Set while the mirror could not be written; the store works without redundancy.
    pub fn degraded(&self) -> Option<&str> {
        self.degraded.as_deref()
    }

    /// The entry called `name`, or `None`.
    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.entries.get(name)
    }

    /// Whether an entry called `name` exists.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Entry names in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Names under `prefix/`, e.g. `names_under("wifi")` yields `wifi/home`, `wifi/office`.
    pub fn names_under<'a>(&'a self, prefix: &str) -> impl Iterator<Item = &'a str> {
        let prefix = format!("{}/", prefix.trim_end_matches('/'));
        self.entries
            .range(prefix.clone()..)
            .map(|(name, _)| name.as_str())
            .take_while(move |name| name.starts_with(&prefix))
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or replace an entry. `Ok` means it is on disk; on error nothing changed.
    pub fn set(&mut self, name: &str, value: impl Into<Secret>) -> Result<()> {
        validate_name(name)?;
        let previous = self.entries.insert(name.to_owned(), value.into());
        if let Err(e) = self.save() {
            match previous {
                Some(value) => self.entries.insert(name.to_owned(), value),
                None => self.entries.remove(name),
            };
            return Err(e);
        }
        Ok(())
    }

    /// Remove an entry and write the store. Returns whether it existed.
    pub fn remove(&mut self, name: &str) -> Result<bool> {
        let Some(previous) = self.entries.remove(name) else {
            return Ok(false);
        };
        if let Err(e) = self.save() {
            self.entries.insert(name.to_owned(), previous);
            return Err(e);
        }
        Ok(true)
    }

    /// Return the entry, creating it from `len` random bytes if missing.
    pub fn get_or_generate(&mut self, name: &str, len: usize) -> Result<&Secret> {
        if !self.entries.contains_key(name) {
            let mut value = Zeroizing::new(vec![0u8; len]);
            crypto::fill_random(&mut value)?;
            self.set(name, Secret::from(value))?;
        }
        Ok(&self.entries[name])
    }

    /// Re-seal under a new provider with a fresh data key; the old one stops working.
    pub fn rekey(&mut self, provider: &dyn KeyProvider) -> Result<()> {
        let dek = DataKey::generate()?;
        let header = seal_header(provider, &dek)?;
        let generation = self.generation + 1;
        let bytes = format::seal_file(&header, &dek, generation, &self.entries)?;
        self.commit(generation, &bytes)?;
        self.header = header;
        self.dek = dek;
        Ok(())
    }
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("path", &self.path)
            .field("provider", &self.provider_kind())
            .field("generation", &self.generation)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Check the directory, take the lock and derive the mirror path.
fn prepare(path: &Path) -> Result<(PathBuf, PathBuf, File)> {
    fsutil::check_dir(path)?;
    let lock_path = fsutil::sibling(path, ".lock")?;
    let lock = fsutil::private_options().create(true).open(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(Error::Locked(path.to_owned())),
        Err(TryLockError::Error(e)) => return Err(e.into()),
    }
    Ok((path.to_owned(), fsutil::sibling(path, ".mirror")?, lock))
}

fn seal_header(provider: &dyn KeyProvider, dek: &DataKey) -> Result<Vec<u8>> {
    let kind = provider.kind();
    let wrapped = provider.wrap(dek, &format::wrap_aad(kind)?)?;
    format::encode_header(kind, &wrapped)
}

/// Open one copy: parse the header, unwrap the data key and authenticate the body.
fn open_copy(bytes: Zeroizing<Vec<u8>>, provider: &dyn KeyProvider) -> Result<Copy> {
    let (header, header_bytes, body) = format::decode_file(&bytes)?;
    if header.kind != provider.kind() {
        return Err(Error::ProviderMismatch {
            expected: provider.kind().to_owned(),
            found: header.kind.to_owned(),
        });
    }
    let dek = provider.unwrap(header.wrapped, &format::wrap_aad(header.kind)?)?;
    let plain = crypto::open(dek.as_bytes(), header_bytes, body).ok_or(Error::Tampered)?;
    let generation = format::generation(&plain)?;
    Ok(Copy {
        bytes,
        dek,
        plain,
        generation,
    })
}

/// Describe the target a [`fsutil::replace_in_order`] run stopped at, if it failed.
fn degraded(targets: &[&Path], (replaced, result): (usize, Result<()>)) -> Option<String> {
    result
        .err()
        .map(|e| format!("writing {}: {e}", targets[replaced].display()))
}

/// Neither copy is usable: prefer a key error, since a wrong key fails both copies.
fn no_usable_copy(
    path: &Path,
    primary: Result<Option<Copy>>,
    mirror: Result<Option<Copy>>,
) -> Error {
    let mut errors: Vec<Error> = [primary, mirror]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    if errors.is_empty() {
        return Error::NotFound(path.to_owned());
    }
    let key_error = errors
        .iter()
        .position(|e| matches!(e, Error::WrongKey | Error::ProviderMismatch { .. }));
    errors.swap_remove(key_error.unwrap_or(0))
}
