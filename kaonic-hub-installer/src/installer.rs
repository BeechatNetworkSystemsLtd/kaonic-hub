//! Installs, upgrades, runs and removes plugins.
//!
//! A plugin lives in `<plugins>/<id>/`:
//!
//! ```text
//! current/    the running version: manifest, bin/<id>, files/ (root-owned, read-only)
//! previous/   the version before, for rollback
//! next/       an install in progress (removed if found at start)
//! data/       the plugin's own, writable by it, kept across upgrades
//! run/        its page socket, page.sock (a plugin with `page = true`), its own
//! token       its key to the hub's plugin API, readable by it only
//! ```
//!
//! Each plugin runs as its own uid from [`crate::records::UIDS`], kept in its record; a uid
//! is never handed to another plugin while a record, or a kept `data/`, still owns it.
//!
//! An upgrade unpacks into `next/`, stops the plugin, moves `current/` to `previous/` and
//! `next/` to `current/`, starts it and watches it. If it does not stay up, the previous
//! version goes back and is started again. One operation at a time.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::core::Core;
use crate::history::{self, Event, History, Outcome};
use crate::host::Host;
use crate::manifest::{Manifest, Permission};
use crate::names::{self, Version};
use crate::package::{self, Package};
use crate::records::{Policy, Record, Records, Removed, UIDS};
use crate::token::TokenKey;
use crate::{Error, unit};

#[derive(Debug, Clone)]
pub struct Paths {
    /// The installer's own state: records, policy, staging. Root only.
    pub state: PathBuf,
    /// Where plugins live.
    pub plugins: PathBuf,
    /// Where units are written.
    pub systemd: PathBuf,
    /// Where command links go.
    pub bin: PathBuf,
    /// Updated copies of the hub and the installer ([`crate::core`]).
    pub core: PathBuf,
    /// The installer's API socket ([`crate::api`]).
    pub socket: PathBuf,
    /// Where the hub makes each plugin's API socket, `<id>.sock`, told to the plugin.
    pub plugin_api_dir: PathBuf,
}

impl Paths {
    pub fn device() -> Self {
        Self {
            state: "/usr/local/kaonic-hub-installer".into(),
            plugins: "/usr/local/kaonic-plugins".into(),
            systemd: "/etc/systemd/system".into(),
            bin: "/usr/bin".into(),
            core: "/usr/local/kaonic-core".into(),
            socket: "/run/kaonic-hub-installer/api.sock".into(),
            plugin_api_dir: "/run/kaonic-hub/plugins".into(),
        }
    }

    /// Everything under `root`, for tests and development: the socket is `<root>/run/api.sock`,
    /// plugin API sockets go in `<root>/run/plugins/`.
    pub fn under(root: &Path) -> Self {
        Self {
            state: root.join("state"),
            plugins: root.join("plugins"),
            systemd: root.join("systemd"),
            bin: root.join("bin"),
            core: root.join("core"),
            socket: root.join("run/api.sock"),
            plugin_api_dir: root.join("run/plugins"),
        }
    }

    pub fn plugin(&self, id: &str) -> PathBuf {
        self.plugins.join(id)
    }

    /// The socket the hub serves plugin `id`'s API on.
    pub fn plugin_api_socket(&self, id: &str) -> PathBuf {
        self.plugin_api_dir.join(format!("{id}.sock"))
    }

    /// The socket plugin `id` serves its page on (`page = true`).
    pub fn page_socket(&self, id: &str) -> PathBuf {
        self.plugin(id).join("run/page.sock")
    }
}

pub struct Installer {
    paths: Paths,
    release_keys: Vec<Vec<u8>>,
    host: Arc<dyn Host>,
    records: Records,
    token_key: TokenKey,
    history: History,
    core: Core,
    hub_job: Mutex<Option<HubJob>>,
    /// The hub version that last said it is up (see [`Installer::hub_ready`]).
    hub_ready: Arc<Mutex<Option<String>>>,
    /// How long a started plugin must stay up to count as working.
    settle: Duration,
    lock: Mutex<()>,
}

/// Removes a staging directory when dropped.
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The installer's update of the hub. The hub asked for it and is restarted by it, so the
/// result is kept (also on disk) for the new hub to read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HubJob {
    pub id: u64,
    pub version: String,
    pub state: HubJobState,
    pub message: String,
    /// Unix seconds.
    pub started: u64,
    pub finished: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HubJobState {
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

/// How long past [`crate::core::START_TIMEOUT`] a running hub update may go before it
/// counts as interrupted.
const HUB_JOB_MARGIN: Duration = Duration::from_secs(60);

impl Installer {
    pub fn new(paths: Paths, release_keys: Vec<Vec<u8>>, host: Arc<dyn Host>, settle: Duration) -> Result<Self, Error> {
        for dir in [&paths.state, &paths.plugins, &paths.systemd, &paths.bin] {
            fs::create_dir_all(dir).map_err(Error::io(format!("making {}", dir.display())))?;
        }
        fs::set_permissions(&paths.state, fs::Permissions::from_mode(0o700)).map_err(Error::io("securing the state directory"))?;
        let records = Records::open(&paths.state)?;
        let token_key = TokenKey::load_or_create(&paths.state.join("token.key"))?;
        let history = History::in_state(&paths.state);
        let core = Core::new(&paths.core, &paths.state, release_keys.clone(), host.clone())?;
        let job: Option<HubJob> = fs::read(paths.state.join("hub-job.json")).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let installer = Self {
            paths,
            release_keys,
            host,
            records,
            token_key,
            history,
            core,
            hub_job: Mutex::new(job),
            hub_ready: Arc::new(Mutex::new(None)),
            settle,
            lock: Mutex::new(()),
        };
        // A job still running on disk was cut off: the thread that ran it is gone.
        installer.end_interrupted_hub_job(Duration::ZERO);
        Ok(installer)
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn history(&self, id: Option<&str>, limit: usize) -> Vec<Event> {
        History::in_state(&self.paths.state).recent(id, limit)
    }

    pub fn core(&self) -> &Core {
        &self.core
    }

    /// The last hub update, if any.
    pub fn hub_job(&self) -> Option<HubJob> {
        self.end_interrupted_hub_job(crate::core::START_TIMEOUT + HUB_JOB_MARGIN);
        self.hub_job.lock().expect("hub job lock").clone()
    }

    /// Marks a running hub job started more than `older_than` ago as failed.
    fn end_interrupted_hub_job(&self, older_than: Duration) {
        let mut slot = self.hub_job.lock().expect("hub job lock");
        if let Some(job) = slot.as_mut()
            && job.state == HubJobState::Running
            && now().saturating_sub(job.started) >= older_than.as_secs()
        {
            job.state = HubJobState::Failed;
            job.finished = Some(now());
            job.message = "interrupted: the installer stopped during the update".into();
            log::warn!("installer: hub update {} to {} was interrupted", job.id, job.version);
            self.save_hub_job(job);
        }
    }

    /// The hub says it is up, at `version`. A running hub update waits for this.
    pub fn hub_ready(&self, version: &str) {
        *self.hub_ready.lock().expect("hub ready lock") = Some(version.to_owned());
    }

    /// Updates the hub from a package. Checks it and answers at once; the switch, the
    /// restart of the hub and the wait for it (up to [`crate::core::START_TIMEOUT`]) run
    /// after, with [`Installer::hub_job`] telling how it went.
    pub fn update_hub(self: &Arc<Self>, archive: &mut impl std::io::Read, allow_downgrade: bool, actor: Option<&str>) -> Result<HubJob, Error> {
        self.update_hub_with(archive, allow_downgrade, actor, crate::core::START_TIMEOUT)
    }

    pub fn update_hub_with(self: &Arc<Self>, archive: &mut impl std::io::Read, allow_downgrade: bool, actor: Option<&str>, timeout: Duration) -> Result<HubJob, Error> {
        const HUB: &str = "kaonic-hub";
        self.end_interrupted_hub_job(crate::core::START_TIMEOUT + HUB_JOB_MARGIN);
        let mut job_slot = self.hub_job.lock().expect("hub job lock");
        if job_slot.as_ref().is_some_and(|job| job.state == HubJobState::Running) {
            return Err(Error::conflict("a hub update is already running"));
        }
        let staged = self.core.stage(HUB, archive, allow_downgrade)?;
        let job = HubJob {
            id: job_slot.as_ref().map_or(1, |job| job.id + 1),
            version: staged.version.clone(),
            state: HubJobState::Running,
            message: String::new(),
            started: now(),
            finished: None,
        };
        *job_slot = Some(job.clone());
        self.save_hub_job(&job);
        drop(job_slot);
        *self.hub_ready.lock().expect("hub ready lock") = None;
        let installer = self.clone();
        let actor = actor.map(str::to_owned);
        let job_id = job.id;
        std::thread::spawn(move || {
            let ready = installer.hub_ready.clone();
            let healthy = move |version: &str| ready.lock().expect("hub ready lock").as_deref() == Some(version);
            let result = installer.core.run_switch(&staged, actor.as_deref(), &healthy, timeout);
            let mut slot = installer.hub_job.lock().expect("hub job lock");
            // Unless it was given up on as interrupted and another one started.
            if let Some(job) = slot.as_mut().filter(|slot| slot.id == job_id && slot.state == HubJobState::Running) {
                job.finished = Some(now());
                match result {
                    Ok(record) => {
                        job.state = HubJobState::Done;
                        job.message = format!("kaonic-hub {} is running", record.version);
                    }
                    Err(error) => {
                        job.state = HubJobState::Failed;
                        job.message = error.message;
                    }
                }
                installer.save_hub_job(job);
            }
        });
        Ok(job)
    }

    fn save_hub_job(&self, job: &HubJob) {
        let bytes = serde_json::to_vec(job).expect("a job serialises");
        if let Err(error) = crate::write_atomic(&self.paths.state.join("hub-job.json"), &bytes, 0o600) {
            log::warn!("installer: saving the hub job: {error}");
        }
    }

    /// The public key plugin tokens are signed with; the hub checks tokens with it.
    pub fn token_public_key(&self) -> [u8; 32] {
        self.token_key.public()
    }

    pub fn list(&self) -> Vec<Record> {
        self.records.all()
    }

    /// The record of plugin `id`. A malformed id is refused before it names a path.
    pub fn get(&self, id: &str) -> Result<Record, Error> {
        crate::names::path_id(id)?;
        self.records.get(id).ok_or_else(|| Error::not_found(format!("no plugin {id}")))
    }

    pub fn policy(&self) -> Policy {
        self.records.policy()
    }

    pub fn set_policy(&self, policy: &Policy) -> Result<(), Error> {
        let _guard = self.lock.lock().expect("installer lock");
        if policy.require_signed && !self.has_release_key() {
            return Err(Error::conflict("this device has no release key, so it cannot require signed packages"));
        }
        self.records.set_policy(policy)
    }

    /// False on a development device: no release key, so signatures are not checked.
    pub fn has_release_key(&self) -> bool {
        !self.release_keys.is_empty()
    }

    pub fn is_running(&self, id: &str) -> bool {
        crate::names::path_id(id).is_ok() && self.host.is_active(&unit::name(id))
    }

    /// Checks a package without installing it.
    pub fn check(&self, archive: &mut impl std::io::Read) -> Result<Package, Error> {
        let staging = self.staging()?;
        package::open(archive, &staging.0, &self.release_keys)
    }

    fn staging(&self) -> Result<Staging, Error> {
        let dir = self.paths.state.join("staging").join(crate::hex(&crate::random::<8>().map_err(Error::io("random"))?));
        fs::create_dir_all(&dir).map_err(Error::io("making a staging directory"))?;
        Ok(Staging(dir))
    }

    /// Installs or upgrades from a package. A lower version than ever installed (also
    /// before a removal) needs `allow_downgrade`.
    pub fn install(&self, archive: &mut impl std::io::Read, allow_downgrade: bool) -> Result<Record, Error> {
        self.install_as(archive, allow_downgrade, None)
    }

    /// [`Installer::install`], recording `actor` (who asked) in the history.
    pub fn install_as(&self, archive: &mut impl std::io::Read, allow_downgrade: bool, actor: Option<&str>) -> Result<Record, Error> {
        let _guard = self.lock.lock().expect("installer lock");
        let staging = self.staging()?;
        let package = package::open(archive, &staging.0, &self.release_keys)?;
        if self.records.policy().require_signed && !package.signed {
            return Err(Error::forbidden("this device installs signed plugins only"));
        }
        let manifest = package.manifest.clone();
        let id = manifest.id.clone();
        if crate::names::is_core(&id) {
            return Err(Error::invalid(format!("{id} is a core program; it is updated through /v1/core")));
        }
        let old = self.records.get(&id);
        if let Some(other) = mesh_clash(&id, self.records.all().iter().map(|record| record.manifest.id.as_str()), names::mesh_hash) {
            return Err(Error::conflict(format!("{id} has the same mesh name as {other}; one of them must change its id")));
        }
        let action = match old.as_ref().and_then(|old| Version::parse(&old.manifest.version).ok()) {
            None => history::Action::Install,
            Some(old) if manifest.version() > old => history::Action::Upgrade,
            Some(old) if manifest.version() < old => history::Action::Downgrade,
            Some(_) => history::Action::Install,
        };
        let (event_id, from, to, signed) = (id.clone(), old.as_ref().map(|old| old.manifest.version.clone()), manifest.version.clone(), package.signed);
        let event = move |outcome, message: &str| {
            Event::new(&event_id, action, outcome).versions(from.as_deref(), Some(&to)).signed(signed).actor(actor).message(message)
        };
        let version = manifest.version();
        let removed = self.records.removed().remove(&id);
        let floor = [old.as_ref().map(|old| old.highest_version.as_str()), removed.as_ref().map(|removed| removed.highest_version.as_str())]
            .into_iter()
            .flatten()
            .filter_map(|text| Version::parse(text).ok().map(|parsed| (parsed, text.to_owned())))
            .max_by(|a, b| a.0.cmp(&b.0));
        if let Some((floor, text)) = &floor
            && version < *floor
            && !allow_downgrade
        {
            return Err(Error::downgrade(format!("{id} {} is older than {text} installed before; allow a downgrade to install it", manifest.version)));
        }
        let highest_version = match floor {
            Some((floor, text)) if floor > version => text,
            _ => manifest.version.clone(),
        };
        let link = self.command_link(&manifest)?;
        if manifest.has(Permission::Root) && !self.has_release_key() {
            log::warn!("installer: {id} {} runs as root, unsigned: this is a development device (no release key)", manifest.version);
        }

        let dir = self.paths.plugin(&id);
        let data = dir.join("data");
        let had_data = data.exists();
        let kept_uid = removed.as_ref().and_then(|removed| removed.uid).filter(|_| had_data);
        let uid = self.uid_for(&manifest, old.as_ref().map(|old| old.uid).or(kept_uid))?;
        make_dir(&dir, 0o755)?;
        let next = dir.join("next");
        remove_tree(&next)?;
        make_dir(&next, 0o755)?;
        for path in package.files.keys() {
            let to = next.join(path);
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent).map_err(Error::io("making a directory"))?;
            }
            fs::rename(staging.0.join(path), &to).map_err(Error::io(format!("placing {path}")))?;
            let mode = if *path == manifest.program() { 0o755 } else { 0o644 };
            fs::set_permissions(&to, fs::Permissions::from_mode(mode)).map_err(Error::io("setting a file mode"))?;
        }
        set_dir_modes(&next)?;
        let data_owner = old.as_ref().map(|old| old.uid).or(kept_uid);
        self.own_dirs(&manifest, uid, had_data && data_owner != Some(uid))?;
        let token_sha256 = self.token(&manifest, uid)?;

        // Switch.
        let unit_name = unit::name(&id);
        if old.is_some() {
            let _ = self.host.systemctl(&["stop", &unit_name]);
        }
        let previous = dir.join("previous");
        let current = dir.join("current");
        let had_current = current.exists();
        if had_current {
            remove_tree(&previous)?;
            fs::rename(&current, &previous).map_err(Error::io("keeping the previous version"))?;
        }
        fs::rename(&next, &current).map_err(Error::io("switching to the new version"))?;
        self.write_unit(&manifest, uid)?;
        self.place_link(&manifest, link.as_deref())?;
        self.host.systemctl(&["daemon-reload"])?;
        self.host.systemctl(&["enable", &unit_name])?;
        self.host.systemctl(&["start", &unit_name])?;

        if !self.settles(&unit_name) {
            log::warn!("installer: {id} {} did not stay running", manifest.version);
            let _ = self.host.systemctl(&["stop", &unit_name]);
            remove_tree(&current)?;
            return match old {
                Some(old) if had_current => {
                    fs::rename(&previous, &current).map_err(Error::io("restoring the previous version"))?;
                    self.own_dirs(&old.manifest, old.uid, old.uid != uid)?;
                    // The token file now holds the failed version's token: issue one for the old.
                    let restored = Record { token_sha256: self.token(&old.manifest, old.uid)?, ..old };
                    self.write_unit(&restored.manifest, restored.uid)?;
                    if link.is_some() && !restored.manifest.command {
                        self.remove_link(&manifest);
                    }
                    let old_link = self.command_link(&restored.manifest).ok().flatten();
                    self.place_link(&restored.manifest, old_link.as_deref())?;
                    self.host.systemctl(&["daemon-reload"])?;
                    if restored.enabled {
                        self.host.systemctl(&["start", &unit_name])?;
                    } else {
                        let _ = self.host.systemctl(&["disable", &unit_name]);
                    }
                    self.records.put(&restored)?;
                    let message = format!("{id} {} did not stay running; {} is back", manifest.version, restored.manifest.version);
                    self.history.add(event(Outcome::RolledBack, &message));
                    Err(Error::failed(message))
                }
                _ => {
                    // Data kept from an earlier install stays, with its uid reserved.
                    self.forget(&manifest, had_data)?;
                    let message = format!("{id} {} did not stay running and was removed", manifest.version);
                    self.history.add(event(Outcome::Failed, &message));
                    Err(Error::failed(message))
                }
            };
        }

        let record = Record {
            manifest,
            uid,
            signed: package.signed,
            installed_at: now(),
            enabled: true,
            highest_version,
            previous: old.filter(|_| had_current).map(|mut old| {
                old.previous = None;
                Box::new(old)
            }),
            token_sha256,
        };
        self.records.put(&record)?;
        if removed.is_some_and(|removed| removed.uid.is_some()) {
            // The record owns the uid now.
            self.update_removed(&id, |entry| entry.uid = None)?;
        }
        self.history.add(event(Outcome::Done, ""));
        log::info!("installer: {id} {} installed as uid {uid}{}", record.manifest.version, if record.signed { ", signed" } else { "" });
        Ok(record)
    }

    pub fn control(&self, id: &str, action: Action) -> Result<Record, Error> {
        self.control_as(id, action, None)
    }

    pub fn control_as(&self, id: &str, action: Action, actor: Option<&str>) -> Result<Record, Error> {
        let record = self.control_inner(id, action)?;
        let action = match action {
            Action::Start => history::Action::Start,
            Action::Stop => history::Action::Stop,
            Action::Restart => history::Action::Restart,
        };
        self.history.add(Event::new(id, action, Outcome::Done).versions(None, Some(&record.manifest.version)).actor(actor));
        Ok(record)
    }

    fn control_inner(&self, id: &str, action: Action) -> Result<Record, Error> {
        let _guard = self.lock.lock().expect("installer lock");
        let mut record = self.get(id)?;
        let unit_name = unit::name(id);
        match action {
            Action::Start => {
                self.host.systemctl(&["enable", &unit_name])?;
                self.host.systemctl(&["start", &unit_name])?;
                record.enabled = true;
            }
            Action::Stop => {
                self.host.systemctl(&["disable", &unit_name])?;
                self.host.systemctl(&["stop", &unit_name])?;
                record.enabled = false;
            }
            Action::Restart => self.host.systemctl(&["restart", &unit_name])?,
        }
        self.records.put(&record)?;
        Ok(record)
    }

    /// Goes back to the version kept before the last upgrade.
    pub fn rollback(&self, id: &str) -> Result<Record, Error> {
        self.rollback_as(id, None)
    }

    pub fn rollback_as(&self, id: &str, actor: Option<&str>) -> Result<Record, Error> {
        let record = self.rollback_inner(id)?;
        let from = record.previous.as_ref().map(|previous| previous.manifest.version.clone());
        self.history.add(Event::new(id, history::Action::Rollback, Outcome::Done).versions(from.as_deref(), Some(&record.manifest.version)).actor(actor));
        Ok(record)
    }

    fn rollback_inner(&self, id: &str) -> Result<Record, Error> {
        let _guard = self.lock.lock().expect("installer lock");
        let mut record = self.get(id)?;
        let Some(mut previous) = record.previous.take() else {
            return Err(Error::conflict(format!("{id} has no previous version to go back to")));
        };
        let dir = self.paths.plugin(id);
        let (current, kept, swap) = (dir.join("current"), dir.join("previous"), dir.join("swap"));
        if !kept.exists() {
            return Err(Error::conflict(format!("the previous version of {id} is not on disk")));
        }
        let uid = self.uid_for(&previous.manifest, Some(record.uid))?;
        let unit_name = unit::name(id);
        let _ = self.host.systemctl(&["stop", &unit_name]);
        remove_tree(&swap)?;
        fs::rename(&current, &swap).map_err(Error::io("rolling back"))?;
        fs::rename(&kept, &current).map_err(Error::io("rolling back"))?;
        fs::rename(&swap, &kept).map_err(Error::io("rolling back"))?;
        self.own_dirs(&previous.manifest, uid, uid != record.uid)?;
        self.write_unit(&previous.manifest, uid)?;
        if record.manifest.command && !previous.manifest.command {
            self.remove_link(&record.manifest);
        }
        let link = self.command_link(&previous.manifest).ok().flatten();
        self.place_link(&previous.manifest, link.as_deref())?;
        self.host.systemctl(&["daemon-reload"])?;
        if record.enabled {
            self.host.systemctl(&["start", &unit_name])?;
        }
        previous.uid = uid;
        previous.enabled = record.enabled;
        previous.highest_version = record.highest_version.clone();
        previous.token_sha256 = self.token(&previous.manifest, uid)?;
        previous.previous = Some(Box::new(record));
        self.records.put(&previous)?;
        log::info!("installer: {id} rolled back to {}", previous.manifest.version);
        Ok(*previous)
    }

    /// Removes a plugin. With `keep_data` its `data/` stays for a later reinstall, and so
    /// does its uid. Its highest version is remembered either way.
    pub fn remove(&self, id: &str, keep_data: bool) -> Result<(), Error> {
        self.remove_as(id, keep_data, None)
    }

    pub fn remove_as(&self, id: &str, keep_data: bool, actor: Option<&str>) -> Result<(), Error> {
        let version = self.get(id)?.manifest.version;
        self.remove_inner(id, keep_data)?;
        let message = if keep_data { "data kept" } else { "" };
        self.history.add(Event::new(id, history::Action::Remove, Outcome::Done).versions(Some(&version), None).actor(actor).message(message));
        Ok(())
    }

    fn remove_inner(&self, id: &str, keep_data: bool) -> Result<(), Error> {
        let _guard = self.lock.lock().expect("installer lock");
        let record = self.get(id)?;
        let unit_name = unit::name(id);
        let _ = self.host.systemctl(&["disable", &unit_name]);
        let _ = self.host.systemctl(&["stop", &unit_name]);
        // The floor first: if the rest fails half way, a reinstall still cannot go lower.
        let highest = record.highest_version.clone();
        self.update_removed(id, |entry| {
            if Version::parse(&entry.highest_version).ok() < Version::parse(&highest).ok() {
                entry.highest_version = highest.clone();
            }
            entry.uid = Some(record.uid).filter(|uid| keep_data && UIDS.contains(uid));
        })?;
        self.forget(&record.manifest, keep_data)?;
        log::info!("installer: {id} removed{}", if keep_data { ", data kept" } else { "" });
        Ok(())
    }

    /// Changes what is remembered of removed plugin `id`.
    fn update_removed(&self, id: &str, change: impl FnOnce(&mut Removed)) -> Result<(), Error> {
        let mut removed = self.records.removed();
        change(removed.entry(id.to_owned()).or_default());
        self.records.set_removed(&removed)
    }

    /// Puts back what lives on the root filesystem (units, links), which a system update
    /// replaces, and starts enabled plugins. Run at every start.
    pub fn restore(&self) -> Result<(), Error> {
        let _guard = self.lock.lock().expect("installer lock");
        let _ = fs::remove_dir_all(self.paths.state.join("staging"));
        let records = self.records.all();
        for record in &records {
            let id = &record.manifest.id;
            remove_tree(&self.paths.plugin(id).join("next"))?;
            if let Err(error) = self.own_dirs(&record.manifest, record.uid, false).and_then(|_| self.write_unit(&record.manifest, record.uid)) {
                log::warn!("installer: {id}: {error}");
            }
            match self.command_link(&record.manifest) {
                Ok(link) => self.place_link(&record.manifest, link.as_deref())?,
                Err(error) => log::warn!("installer: {id}: {error}"),
            }
        }
        self.host.systemctl(&["daemon-reload"])?;
        for record in records.iter().filter(|record| record.enabled) {
            let unit_name = unit::name(&record.manifest.id);
            if let Err(error) = self.host.systemctl(&["start", &unit_name]) {
                log::warn!("installer: {error}");
            }
        }
        Ok(())
    }

    /// Removes a plugin's files, unit, link and record.
    fn forget(&self, manifest: &Manifest, keep_data: bool) -> Result<(), Error> {
        let id = &manifest.id;
        let unit_path = self.paths.systemd.join(unit::name(id));
        if is_ours(&unit_path) {
            let _ = fs::remove_file(&unit_path);
        }
        self.remove_link(manifest);
        let dir = self.paths.plugin(id);
        if keep_data {
            for part in ["current", "previous", "next", "swap", "run", "token"] {
                let path = dir.join(part);
                if path.is_dir() { remove_tree(&path)? } else { let _ = fs::remove_file(path); }
            }
        } else {
            remove_tree(&dir)?;
        }
        let _ = self.host.systemctl(&["daemon-reload"]);
        self.records.remove(id)
    }

    /// The uid for `manifest`: 0 for `root`; else `had` if it is a plugin uid; else the
    /// lowest one no record, kept `data/` or plugin directory owns.
    fn uid_for(&self, manifest: &Manifest, had: Option<u32>) -> Result<u32, Error> {
        if manifest.has(Permission::Root) {
            return Ok(0);
        }
        if let Some(uid) = had.filter(|uid| UIDS.contains(uid)) {
            return Ok(uid);
        }
        let mut used: HashSet<u32> = self.records.all().iter().flat_map(|record| [Some(record.uid), record.previous.as_ref().map(|previous| previous.uid)]).flatten().collect();
        for (id, removed) in self.records.removed() {
            if let Some(uid) = removed.uid
                && self.paths.plugin(&id).join("data").exists()
            {
                used.insert(uid);
            }
        }
        // Owners on disk too, should a record be unreadable.
        for entry in fs::read_dir(&self.paths.plugins).into_iter().flatten().flatten() {
            for part in ["data", "run", "token"] {
                if let Ok(meta) = fs::symlink_metadata(entry.path().join(part)) {
                    used.insert(meta.uid());
                }
            }
        }
        UIDS.into_iter().find(|uid| !used.contains(uid)).ok_or_else(|| Error::failed("every plugin uid is in use"))
    }

    /// Makes `data/` (and `run/` for a page) owned by `uid`; with `all`, everything inside
    /// `data/` too (its uid changed).
    fn own_dirs(&self, manifest: &Manifest, uid: u32, all: bool) -> Result<(), Error> {
        let dir = self.paths.plugin(&manifest.id);
        let data = dir.join("data");
        if !data.exists() {
            make_dir(&data, 0o700)?;
        }
        if all { self.chown_tree(&data, uid)? } else { self.host.chown(&data, uid, uid)? }
        if manifest.page {
            let run = dir.join("run");
            make_dir(&run, 0o700)?;
            self.host.chown(&run, uid, uid)?;
        }
        Ok(())
    }

    /// Chowns `path` and, if it is a real directory, everything in it; never follows a link.
    fn chown_tree(&self, path: &Path, uid: u32) -> Result<(), Error> {
        self.host.chown(path, uid, uid)?;
        if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()) {
            for entry in fs::read_dir(path).map_err(Error::io("reading a directory"))? {
                self.chown_tree(&entry.map_err(Error::io("reading a directory"))?.path(), uid)?;
            }
        }
        Ok(())
    }

    /// Issues the plugin's API token (its id and permissions, signed) into `<plugin>/token`,
    /// readable by the plugin only. Returns the token's hash for the record.
    fn token(&self, manifest: &Manifest, uid: u32) -> Result<String, Error> {
        let path = self.paths.plugin(&manifest.id).join("token");
        let token = self.token_key.issue(&manifest.id, &manifest.permissions, now())?;
        let _ = fs::remove_file(&path);
        crate::write_atomic(&path, token.as_bytes(), 0o400).map_err(Error::io("writing the plugin token"))?;
        self.host.chown(&path, uid, uid)?;
        Ok(crate::sha256_hex(token.as_bytes()))
    }

    fn write_unit(&self, manifest: &Manifest, uid: u32) -> Result<(), Error> {
        crate::manifest::validate(manifest)?;
        let path = self.paths.systemd.join(unit::name(&manifest.id));
        if path.exists() && !is_ours(&path) {
            return Err(Error::conflict(format!("{} exists and was not written by the installer", path.display())));
        }
        fs::create_dir_all(&self.paths.systemd).map_err(Error::io("making the unit directory"))?;
        crate::write_atomic(&path, unit::render(manifest, uid, &self.paths).as_bytes(), 0o644).map_err(Error::io("writing the unit"))
    }

    /// The command link the manifest asks for, if it is free or already ours. Only ids
    /// starting with `kaonic-` get one ([`crate::manifest::validate`]).
    fn command_link(&self, manifest: &Manifest) -> Result<Option<PathBuf>, Error> {
        if !manifest.command {
            return Ok(None);
        }
        if !manifest.id.starts_with("kaonic-") {
            return Err(Error::invalid(format!("{} cannot have a command link: only ids starting with kaonic- do", manifest.id)));
        }
        let link = self.paths.bin.join(&manifest.id);
        let target = self.program(&manifest.id, manifest);
        match fs::symlink_metadata(&link) {
            Err(_) => Ok(Some(link)),
            Ok(meta) if meta.file_type().is_symlink() && fs::read_link(&link).ok().as_deref() == Some(target.as_path()) => Ok(Some(link)),
            Ok(_) => Err(Error::conflict(format!("{} already exists; the plugin cannot take that command name", link.display()))),
        }
    }

    fn place_link(&self, manifest: &Manifest, link: Option<&Path>) -> Result<(), Error> {
        let Some(link) = link else { return Ok(()) };
        let target = self.program(&manifest.id, manifest);
        if fs::read_link(link).ok().as_deref() == Some(target.as_path()) {
            return Ok(());
        }
        let _ = fs::remove_file(link);
        std::os::unix::fs::symlink(&target, link).map_err(Error::io(format!("linking {}", link.display())))
    }

    /// Removes the plugin's command link if it is ours.
    fn remove_link(&self, manifest: &Manifest) {
        let link = self.paths.bin.join(&manifest.id);
        let ours = self.paths.plugin(&manifest.id).join("current");
        if fs::read_link(&link).is_ok_and(|target| target.starts_with(&ours)) {
            let _ = fs::remove_file(link);
        }
    }

    fn program(&self, id: &str, manifest: &Manifest) -> PathBuf {
        self.paths.plugin(id).join("current").join(manifest.program())
    }

    /// Watches a started unit for `settle`: it must be running throughout and at the end.
    fn settles(&self, unit_name: &str) -> bool {
        let deadline = Instant::now() + self.settle;
        loop {
            if !self.host.is_active(unit_name) {
                return false;
            }
            if Instant::now() >= deadline {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250).min(self.settle));
        }
    }
}

/// The installed plugin among `others` (not `id` itself) whose mesh name equals `id`'s.
fn mesh_clash<'a>(id: &str, others: impl Iterator<Item = &'a str>, hash: fn(&str) -> u64) -> Option<String> {
    let mine = hash(id);
    others.filter(|other| *other != id).find(|other| hash(other) == mine).map(str::to_owned)
}

fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

fn is_ours(unit: &Path) -> bool {
    fs::read_to_string(unit).is_ok_and(|text| text.starts_with(unit::MARKER))
}

fn make_dir(path: &Path, mode: u32) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(Error::failed(format!("{} is not a directory", path.display()))),
        Err(_) => fs::create_dir(path).map_err(Error::io(format!("making {}", path.display())))?,
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(Error::io("setting a directory mode"))
}

fn set_dir_modes(dir: &Path) -> Result<(), Error> {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).map_err(Error::io("setting a directory mode"))?;
    for entry in fs::read_dir(dir).map_err(Error::io("reading a directory"))? {
        let entry = entry.map_err(Error::io("reading a directory"))?;
        if entry.file_type().map_err(Error::io("reading a directory"))?.is_dir() {
            set_dir_modes(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_tree(path: &Path) -> Result<(), Error> {
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(Error::io(format!("removing {}", path.display()))(error)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Fake;
    use crate::package::testing::{Key, sample, staging};
    use crate::token;

    struct Bench {
        installer: Installer,
        host: Arc<Fake>,
        root: PathBuf,
        key: Key,
    }

    fn bench() -> Bench {
        let root = staging();
        let host = Arc::new(Fake::default());
        let key = Key::generate();
        let installer = Installer::new(Paths::under(&root), vec![key.public_pem()], host.clone(), Duration::ZERO).unwrap();
        Bench { installer, host, root, key }
    }

    impl Bench {
        fn install(&self, version: &str, extra: &str) -> Result<Record, Error> {
            self.installer.install(&mut sample(version, extra, Some(&self.key)).as_slice(), false)
        }
        fn plugin(&self, path: &str) -> PathBuf {
            self.root.join("plugins/sample").join(path)
        }
        fn unit(&self) -> String {
            fs::read_to_string(self.root.join("systemd/kaonic-plugin-sample.service")).unwrap()
        }
        fn running(&self) -> bool {
            self.host.is_active("kaonic-plugin-sample.service")
        }
    }

    #[test]
    fn installs_and_starts_a_plugin_as_its_own_uid() {
        let bench = bench();
        let record = bench.install("1.0.0", "").unwrap();
        assert!(record.signed && record.enabled && record.previous.is_none());
        assert!(bench.running());
        assert_eq!(fs::read(bench.plugin("current/bin/sample")).unwrap(), b"#!/bin/sh\nsleep 1000\n");
        assert_eq!(fs::metadata(bench.plugin("current/bin/sample")).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(bench.plugin("data")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(record.uid, 61_000);
        assert!(bench.unit().contains("\nUser=61000\nGroup=61000\n"));
        assert!(bench.host.state.lock().unwrap().chowned.contains(&(bench.plugin("data"), 61_000, 61_000)));
        assert!(!bench.root.join("state/staging").read_dir().is_ok_and(|mut dir| dir.next().is_some()), "staging cleaned");
    }

    #[test]
    fn each_plugin_gets_its_own_signed_token() {
        let bench = bench();
        let record = bench.install("1.0.0", "[service]\npermissions = \"mesh\"\n").unwrap();
        let token = fs::read_to_string(bench.plugin("token")).unwrap();
        assert_eq!(fs::metadata(bench.plugin("token")).unwrap().permissions().mode() & 0o777, 0o400);
        let claims = token::verify(&bench.installer.token_public_key(), &token).unwrap();
        assert_eq!(claims.id, "sample");
        assert_eq!(claims.permissions, [crate::manifest::Permission::Mesh]);
        assert_eq!(record.token_sha256, crate::sha256_hex(token.as_bytes()));
        // An upgrade issues a new token; the old one no longer matches the record.
        let upgraded = bench.install("1.1.0", "").unwrap();
        assert_ne!(upgraded.token_sha256, record.token_sha256);
        assert!(token::verify(&bench.installer.token_public_key(), &fs::read_to_string(bench.plugin("token")).unwrap()).unwrap().permissions.is_empty());
    }

    #[test]
    fn an_upgrade_keeps_data_and_the_previous_version() {
        let bench = bench();
        bench.install("1.0.0", "").unwrap();
        fs::write(bench.plugin("data/state.db"), b"mine").unwrap();
        let record = bench.install("1.1.0", "").unwrap();
        assert_eq!(record.manifest.version, "1.1.0");
        assert_eq!(record.previous.as_ref().unwrap().manifest.version, "1.0.0");
        assert_eq!(fs::read(bench.plugin("data/state.db")).unwrap(), b"mine");
        assert!(bench.plugin("previous/bin/sample").exists());
        let back = bench.installer.rollback("sample").unwrap();
        assert_eq!(back.manifest.version, "1.0.0");
        assert_eq!(back.previous.unwrap().manifest.version, "1.1.0");
        assert!(bench.running());
    }

    #[test]
    fn a_downgrade_needs_permission() {
        let bench = bench();
        bench.install("2.0.0", "").unwrap();
        let error = bench.install("1.0.0", "").unwrap_err();
        assert_eq!(error.kind, crate::Kind::Downgrade);
        let record = bench.installer.install(&mut sample("1.0.0", "", Some(&bench.key)).as_slice(), true).unwrap();
        assert_eq!(record.manifest.version, "1.0.0");
        assert_eq!(record.highest_version, "2.0.0", "the floor is remembered");
    }

    #[test]
    fn an_upgrade_that_does_not_stay_up_is_rolled_back() {
        let bench = bench();
        bench.install("1.0.0", "").unwrap();
        bench.host.state.lock().unwrap().crashing.insert("kaonic-plugin-sample.service".into());
        // The old version crashes too in the fake; only check the files and record.
        let error = bench.install("1.1.0", "").unwrap_err();
        assert!(error.message.contains("1.0.0 is back"), "{}", error.message);
        assert_eq!(bench.installer.get("sample").unwrap().manifest.version, "1.0.0");
        assert!(fs::read_to_string(bench.plugin("current/kaonic-plugin.toml")).unwrap().contains("1.0.0"));
    }

    #[test]
    fn a_first_install_that_does_not_stay_up_is_removed() {
        let bench = bench();
        bench.host.state.lock().unwrap().crashing.insert("kaonic-plugin-sample.service".into());
        assert!(bench.install("1.0.0", "").is_err());
        assert!(bench.installer.list().is_empty());
        assert!(!bench.plugin("").exists());
        assert!(!bench.root.join("systemd/kaonic-plugin-sample.service").exists());
    }

    #[test]
    fn a_development_device_cannot_require_signatures() {
        let root = staging();
        let installer = Installer::new(Paths::under(&root), vec![], Arc::new(Fake::default()), Duration::ZERO).unwrap();
        assert!(!installer.has_release_key());
        assert_eq!(installer.set_policy(&Policy { require_signed: true }).unwrap_err().kind, crate::Kind::Conflict);
        assert!(installer.install(&mut sample("1.0.0", "", Some(&Key::generate())).as_slice(), false).is_ok());
    }

    #[test]
    fn signed_only_refuses_unsigned_packages() {
        let bench = bench();
        bench.installer.set_policy(&Policy { require_signed: true }).unwrap();
        let error = bench.installer.install(&mut sample("1.0.0", "", None).as_slice(), false).unwrap_err();
        assert_eq!(error.kind, crate::Kind::Forbidden);
        assert!(bench.install("1.0.0", "").is_ok());
    }

    #[test]
    fn never_takes_a_name_it_does_not_own() {
        let bench = bench();
        fs::create_dir_all(bench.root.join("bin")).unwrap();
        fs::write(bench.root.join("bin/kaonic-tool"), b"someone else's").unwrap();
        assert_eq!(bench.installer.install(&mut tool("1").as_slice(), false).unwrap_err().kind, crate::Kind::Conflict);
        assert_eq!(fs::read(bench.root.join("bin/kaonic-tool")).unwrap(), b"someone else's");

        let bench = super::tests::bench();
        fs::create_dir_all(bench.root.join("systemd")).unwrap();
        fs::write(bench.root.join("systemd/kaonic-plugin-sample.service"), "[Service]\nExecStart=/bin/true\n").unwrap();
        assert!(bench.install("1.0.0", "").is_err());
        assert!(fs::read_to_string(bench.root.join("systemd/kaonic-plugin-sample.service")).unwrap().contains("/bin/true"));
    }

    #[test]
    fn command_links_are_for_kaonic_ids_only() {
        let bench = bench();
        assert_eq!(bench.install("1.0.0", "command = true\n").unwrap_err().kind, crate::Kind::Invalid);
        assert!(!bench.root.join("bin/sample").exists());
        bench.installer.install(&mut tool("1").as_slice(), false).unwrap();
        assert!(fs::symlink_metadata(bench.root.join("bin/kaonic-tool")).unwrap().file_type().is_symlink());
        bench.installer.remove("kaonic-tool", false).unwrap();
        assert!(fs::symlink_metadata(bench.root.join("bin/kaonic-tool")).is_err());
    }

    /// A plugin with a command link, id `kaonic-tool`.
    fn tool(version: &str) -> Vec<u8> {
        let manifest = format!("[kaonic-plugin]\nformat = 2\nid = \"kaonic-tool\"\nname = \"Tool\"\nversion = \"{version}\"\ndeveloper = \"B\"\ncommand = true\n");
        crate::package::testing::package(&[("kaonic-plugin.toml", manifest.as_bytes()), ("bin/kaonic-tool", b"#!/bin/sh\n")], None)
    }

    #[test]
    fn remove_can_keep_the_data() {
        let bench = bench();
        let first = bench.install("1.0.0", "page = true\n").unwrap();
        assert!(bench.plugin("run").is_dir());
        fs::write(bench.plugin("data/x"), b"1").unwrap();
        bench.installer.remove("sample", true).unwrap();
        assert!(bench.plugin("data/x").exists());
        assert!(!bench.plugin("current").exists() && !bench.plugin("token").exists() && !bench.plugin("run").exists());
        assert!(!bench.root.join("systemd/kaonic-plugin-sample.service").exists());
        assert!(!bench.running());
        assert_eq!(bench.install("1.0.0", "").unwrap().uid, first.uid, "a reinstall finds its data, and its uid");
        assert!(bench.plugin("data/x").exists());
        bench.installer.remove("sample", false).unwrap();
        assert!(!bench.plugin("").exists());
    }

    fn hub_package(version: &str) -> Vec<u8> {
        let manifest = format!("[kaonic-plugin]\nformat = 2\nid = \"kaonic-hub\"\nname = \"Hub\"\nversion = \"{version}\"\ndeveloper = \"Beechat\"\n");
        crate::package::testing::package(&[("kaonic-plugin.toml", manifest.as_bytes()), ("bin/kaonic-hub", b"hub")], None)
    }

    fn wait_for(installer: &Installer, state: HubJobState) -> HubJob {
        for _ in 0..200 {
            if let Some(job) = installer.hub_job().filter(|job| job.state == state) {
                return job;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the hub job never reached {state:?}: {:?}", installer.hub_job());
    }

    #[test]
    fn the_installer_updates_the_hub_and_waits_for_it() {
        let root = staging();
        let installer = Arc::new(Installer::new(Paths::under(&root), vec![], Arc::new(Fake::default()), Duration::ZERO).unwrap());
        let job = installer.update_hub_with(&mut hub_package("1.1").as_slice(), false, Some("admin"), Duration::from_secs(5)).unwrap();
        assert_eq!(job.state, HubJobState::Running);
        assert!(installer.update_hub_with(&mut hub_package("1.2").as_slice(), false, None, Duration::from_secs(5)).is_err(), "one at a time");
        installer.hub_ready("1.0");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(installer.hub_job().unwrap().state, HubJobState::Running, "an old hub saying ready does not count");
        installer.hub_ready("1.1");
        let job = wait_for(&installer, HubJobState::Done);
        assert_eq!(job.version, "1.1");
        assert!(installer.core().record("kaonic-hub").unwrap().confirmed);
        assert_eq!(installer.history(Some("kaonic-hub"), 1)[0].actor.as_deref(), Some("admin"));
        // A plugin package cannot use a core id.
        assert!(installer.install(&mut hub_package("9").as_slice(), false).is_err());
    }

    #[test]
    fn a_hub_that_never_says_ready_is_rolled_back() {
        let root = staging();
        let installer = Arc::new(Installer::new(Paths::under(&root), vec![], Arc::new(Fake::default()), Duration::ZERO).unwrap());
        installer.update_hub_with(&mut hub_package("1.1").as_slice(), false, None, Duration::from_millis(100)).unwrap();
        let job = wait_for(&installer, HubJobState::Failed);
        assert!(job.message.contains("did not come up"), "{}", job.message);
        assert!(installer.core().record("kaonic-hub").is_none(), "the image's hub runs");
        // The result survives an installer restart, for the new hub to read.
        let again = Installer::new(Paths::under(&root), vec![], Arc::new(Fake::default()), Duration::ZERO).unwrap();
        assert_eq!(again.hub_job().unwrap().state, HubJobState::Failed);
    }

    #[test]
    fn plugin_actions_are_in_the_history() {
        let bench = bench();
        bench.installer.install_as(&mut sample("1.0.0", "", Some(&bench.key)).as_slice(), false, Some("alice")).unwrap();
        bench.installer.control_as("sample", Action::Stop, Some("bob")).unwrap();
        bench.install("1.1.0", "").unwrap();
        bench.installer.remove("sample", false).unwrap();
        let events = bench.installer.history(Some("sample"), 10);
        let actions: Vec<_> = events.iter().map(|event| event.action).collect();
        assert_eq!(actions, [history::Action::Remove, history::Action::Upgrade, history::Action::Stop, history::Action::Install]);
        assert_eq!(events[3].actor.as_deref(), Some("alice"));
        assert!(events[3].signed);
    }

    #[test]
    fn a_mesh_name_clash_is_found() {
        let ids = ["alpha", "beta"];
        assert_eq!(mesh_clash("gamma", ids.into_iter(), |_| 7).as_deref(), Some("alpha"));
        assert_eq!(mesh_clash("alpha", ["alpha"].into_iter(), |_| 7), None, "not with itself");
        assert_eq!(mesh_clash("gamma", ids.into_iter(), names::mesh_hash), None);
    }

    #[test]
    fn a_page_gets_a_run_directory_of_its_own() {
        let bench = bench();
        let record = bench.install("1.0.0", "page = true\n").unwrap();
        assert!(record.manifest.page);
        assert_eq!(fs::metadata(bench.plugin("run")).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(bench.host.state.lock().unwrap().chowned.contains(&(bench.plugin("run"), record.uid, record.uid)));
        assert!(bench.unit().contains("KAONIC_PLUGIN_PAGE_SOCKET="));
    }

    #[test]
    fn restore_writes_units_back_after_a_system_update() {
        let bench = bench();
        bench.install("1.0.0", "").unwrap();
        bench.installer.control("sample", Action::Stop).unwrap();
        fs::remove_dir_all(bench.root.join("systemd")).unwrap();
        bench.installer.restore().unwrap();
        assert!(bench.unit().contains("ExecStart="));
        assert!(!bench.running(), "a stopped plugin stays stopped");
        bench.installer.control("sample", Action::Start).unwrap();
        bench.installer.restore().unwrap();
        assert!(bench.running());
    }
}
