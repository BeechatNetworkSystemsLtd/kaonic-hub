//! The core programs, `kaonic-hub` and `kaonic-hub-installer`, update each other: the
//! installer updates the hub, the hub updates the installer. The one doing the update stays
//! up to watch the other start, and puts the previous version back if it does not.
//!
//! ```text
//! <core>/<id>/current/   the updated program (bin/<id>, manifest, files/)
//! <core>/<id>/previous/  the version before
//! <core>/<id>/next/      an update being prepared
//! <core>/<id>/record.json
//! <core>/<id>/attempts   starts since the program last said it was healthy
//! ```
//!
//! The image keeps its own copy of both programs (`/usr/bin`) and its units start that
//! copy. At start, [`exec_newer`] switches to the copy here when it is at least as new and
//! has not failed to come up [`MAX_ATTEMPTS`] times in a row; otherwise the image's copy
//! runs. So a broken update, or a newer system image, never leaves the device without a
//! working hub or installer.
//!
//! Packages use the plugin format with a core id. They need a release signature when the
//! device has a release key; a development device (no key) takes them unsigned.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::history::{self, Event, History, Outcome};
use crate::host::Host;
use crate::names::{self, Version};
use crate::{Error, package};

/// Starts in a row that did not reach "healthy" before the image's copy is used instead.
pub const MAX_ATTEMPTS: u32 = 3;
/// How long an updated program has to come up before it is rolled back.
pub const START_TIMEOUT: Duration = Duration::from_secs(120);
/// Set by [`exec_newer`] in the program it starts, so that program does not start itself again.
const EXEC_ENV: &str = "KAONIC_CORE_EXEC";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreRecord {
    pub id: String,
    pub version: String,
    pub signed: bool,
    /// Unix seconds.
    pub installed_at: u64,
    /// The updater saw it come up healthy.
    pub confirmed: bool,
    pub highest_version: String,
    /// The version in `previous/`, if any.
    pub previous: Option<String>,
}

/// What the hub and the API show about a core program.
#[derive(Debug, Clone, Serialize)]
pub struct CoreStatus {
    pub id: String,
    /// The updated copy, if any.
    pub updated: Option<CoreRecord>,
    /// Starts since it last said it was healthy.
    pub attempts: u32,
}

/// A core update checked and unpacked into `next/`, ready to switch to.
#[derive(Debug)]
pub struct Staged {
    pub id: String,
    pub version: String,
    pub signed: bool,
}

pub struct Core {
    root: PathBuf,
    staging: PathBuf,
    release_keys: Vec<Vec<u8>>,
    host: Arc<dyn Host>,
    history: History,
}

impl Core {
    /// `root` holds the core programs; `state` is the installer's state directory (for
    /// staging and history).
    pub fn new(root: &Path, state: &Path, release_keys: Vec<Vec<u8>>, host: Arc<dyn Host>) -> Result<Self, Error> {
        fs::create_dir_all(root).map_err(Error::io("making the core directory"))?;
        Ok(Self { root: root.to_owned(), staging: state.join("staging"), release_keys, host, history: History::in_state(state) })
    }

    fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn record(&self, id: &str) -> Option<CoreRecord> {
        read_record(&self.root, id)
    }

    /// The record of core program `id` under `root`, without opening a [`Core`].
    pub fn record_in(root: &Path, id: &str) -> Option<CoreRecord> {
        read_record(root, id)
    }

    pub fn status(&self, id: &str) -> CoreStatus {
        CoreStatus { id: id.to_owned(), updated: self.record(id), attempts: attempts(&self.root, id) }
    }

    /// Checks a package for core program `id` and unpacks it into `next/`.
    pub fn stage(&self, id: &str, archive: &mut impl Read, allow_downgrade: bool) -> Result<Staged, Error> {
        if !names::is_core(id) {
            return Err(Error::invalid(format!("{id} is not a core program")));
        }
        let staging = self.staging.join(crate::hex(&crate::random::<8>().map_err(Error::io("random"))?));
        fs::create_dir_all(&staging).map_err(Error::io("making a staging directory"))?;
        let result = self.stage_from(id, archive, allow_downgrade, &staging);
        let _ = fs::remove_dir_all(&staging);
        result
    }

    fn stage_from(&self, id: &str, archive: &mut impl Read, allow_downgrade: bool, staging: &Path) -> Result<Staged, Error> {
        let package = package::open(archive, staging, &self.release_keys)?;
        let manifest = &package.manifest;
        if manifest.id != id {
            return Err(Error::invalid(format!("this is a package for {}, not {id}", manifest.id)));
        }
        if !self.release_keys.is_empty() && !package.signed {
            return Err(Error::forbidden(format!("{id} updates must be signed by a release key")));
        }
        let version = manifest.version();
        if let Some(record) = self.record(id)
            && let Ok(highest) = Version::parse(&record.highest_version)
            && version < highest
            && !allow_downgrade
        {
            return Err(Error::downgrade(format!("{id} {} is older than {} installed before", manifest.version, record.highest_version)));
        }
        let next = self.dir(id).join("next");
        let _ = fs::remove_dir_all(&next);
        fs::create_dir_all(&next).map_err(Error::io("making next/"))?;
        for path in package.files.keys() {
            let to = next.join(path);
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent).map_err(Error::io("making a directory"))?;
            }
            fs::rename(staging.join(path), &to).map_err(Error::io(format!("placing {path}")))?;
            let mode = if *path == manifest.program() { 0o755 } else { 0o644 };
            fs::set_permissions(&to, fs::Permissions::from_mode(mode)).map_err(Error::io("setting a file mode"))?;
        }
        Ok(Staged { id: id.to_owned(), version: manifest.version.clone(), signed: package.signed })
    }

    /// Makes the staged version current (the current one becomes previous) and records it
    /// as on trial. The caller then restarts the program and waits for it.
    pub fn switch(&self, staged: &Staged) -> Result<(), Error> {
        let dir = self.dir(&staged.id);
        let (next, current, previous) = (dir.join("next"), dir.join("current"), dir.join("previous"));
        if !next.is_dir() {
            return Err(Error::conflict(format!("no staged update of {}", staged.id)));
        }
        let old = self.record(&staged.id);
        if current.is_dir() {
            let _ = fs::remove_dir_all(&previous);
            fs::rename(&current, &previous).map_err(Error::io("keeping the previous version"))?;
        }
        fs::rename(&next, &current).map_err(Error::io("switching versions"))?;
        let highest = match &old {
            Some(old) if Version::parse(&old.highest_version).ok() > Version::parse(&staged.version).ok() => old.highest_version.clone(),
            _ => staged.version.clone(),
        };
        let record = CoreRecord {
            id: staged.id.clone(),
            version: staged.version.clone(),
            signed: staged.signed,
            installed_at: now(),
            confirmed: false,
            highest_version: highest,
            previous: old.filter(|_| previous.is_dir()).map(|old| old.version),
        };
        write_record(&self.root, &record)?;
        set_attempts(&self.root, &staged.id, 0);
        Ok(())
    }

    /// The updated program came up: keep it.
    pub fn confirm(&self, id: &str, actor: Option<&str>) -> Result<(), Error> {
        let mut record = self.record(id).ok_or_else(|| Error::not_found(format!("no update of {id}")))?;
        record.confirmed = true;
        write_record(&self.root, &record)?;
        self.history.add(
            Event::new(id, history::Action::Upgrade, Outcome::Done)
                .versions(record.previous.as_deref(), Some(&record.version))
                .signed(record.signed)
                .actor(actor),
        );
        log::info!("core: {id} {} confirmed", record.version);
        Ok(())
    }

    /// The updated program did not come up: put the previous version back (or none, so the
    /// image's copy runs).
    pub fn revert(&self, id: &str, why: &str, actor: Option<&str>) -> Result<(), Error> {
        let dir = self.dir(id);
        let (current, previous) = (dir.join("current"), dir.join("previous"));
        let record = self.record(id);
        let _ = fs::remove_dir_all(&current);
        let back = match record.as_ref().and_then(|record| record.previous.clone()) {
            Some(version) if previous.is_dir() => {
                fs::rename(&previous, &current).map_err(Error::io("restoring the previous version"))?;
                let old = record.as_ref().expect("checked");
                write_record(&self.root, &CoreRecord { version: version.clone(), confirmed: true, previous: None, ..old.clone() })?;
                Some(version)
            }
            _ => {
                let _ = fs::remove_file(dir.join("record.json"));
                None
            }
        };
        set_attempts(&self.root, id, 0);
        self.history.add(
            Event::new(id, history::Action::Upgrade, Outcome::RolledBack)
                .versions(back.as_deref(), record.as_ref().map(|record| record.version.as_str()))
                .actor(actor)
                .message(why),
        );
        log::warn!("core: {id} rolled back ({why})");
        Ok(())
    }

    /// Stage, switch, restart its unit (`<id>.service`), and wait until `healthy(version)` says the new version
    /// is up; otherwise revert and restart again. For a program other than the caller.
    pub fn update(
        &self,
        id: &str,
        archive: &mut impl Read,
        allow_downgrade: bool,
        actor: Option<&str>,
        healthy: &dyn Fn(&str) -> bool,
        timeout: Duration,
    ) -> Result<CoreRecord, Error> {
        let staged = self.stage(id, archive, allow_downgrade)?;
        self.run_switch(&staged, actor, healthy, timeout)
    }

    /// The second half of [`Core::update`], for an update already staged.
    pub fn run_switch(&self, staged: &Staged, actor: Option<&str>, healthy: &dyn Fn(&str) -> bool, timeout: Duration) -> Result<CoreRecord, Error> {
        let id = &staged.id;
        let unit = format!("{id}.service");
        let unit = unit.as_str();
        self.switch(staged)?;
        self.host.systemctl(&["restart", unit])?;
        let deadline = Instant::now() + timeout;
        loop {
            if healthy(&staged.version) {
                self.confirm(id, actor)?;
                return self.record(id).ok_or_else(|| Error::failed("the record went missing"));
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(500).min(timeout));
        }
        let why = format!("{id} {} did not come up within {} s", staged.version, timeout.as_secs());
        self.revert(id, &why, actor)?;
        self.host.systemctl(&["restart", unit])?;
        Err(Error::failed(format!("{why}; the previous version is back")))
    }
}

/// Reads the release keys. A missing file is skipped (no key: a development device); any
/// other error is returned, so a device with a key it cannot read never runs as a
/// development device.
pub fn read_release_keys(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, Error> {
    let mut keys = Vec::new();
    for path in paths {
        match fs::read(path) {
            Ok(key) => keys.push(key),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::failed(format!("release key {}: {error}", path.display()))),
        }
    }
    Ok(keys)
}

fn read_record(root: &Path, id: &str) -> Option<CoreRecord> {
    serde_json::from_slice(&fs::read(root.join(id).join("record.json")).ok()?).ok()
}

fn write_record(root: &Path, record: &CoreRecord) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(record).expect("a record serialises");
    crate::write_atomic(&root.join(&record.id).join("record.json"), &bytes, 0o600).map_err(Error::io("writing a core record"))
}

fn attempts(root: &Path, id: &str) -> u32 {
    fs::read_to_string(root.join(id).join("attempts")).ok().and_then(|text| text.trim().parse().ok()).unwrap_or(0)
}

fn set_attempts(root: &Path, id: &str, value: u32) {
    let dir = root.join(id);
    if dir.is_dir() {
        let _ = crate::write_atomic(&dir.join("attempts"), value.to_string().as_bytes(), 0o600);
    }
}

/// The program to run for core program `id`: the updated copy under `root` if it is at
/// least as new as `own_version` and has not failed to come up [`MAX_ATTEMPTS`] times;
/// None to keep running the image's copy. Counts the attempt.
pub fn choose(root: &Path, id: &str, own_version: &str) -> Option<PathBuf> {
    let record = read_record(root, id)?;
    let program = root.join(id).join("current/bin").join(id);
    if !program.is_file() {
        return None;
    }
    if Version::parse(&record.version).ok()? < Version::parse(own_version).ok()? {
        log::info!("core: the image's {id} {own_version} is newer than the update {}; using it", record.version);
        return None;
    }
    let tried = attempts(root, id);
    if tried >= MAX_ATTEMPTS {
        log::warn!("core: {id} {} failed to come up {tried} times; using the image's {own_version}", record.version);
        return None;
    }
    set_attempts(root, id, tried + 1);
    Some(program)
}

/// At the start of `kaonic-hub` or `kaonic-hub-installer`: replaces this process with the
/// updated copy when [`choose`] picks it. Returns when the current program should run.
pub fn exec_newer(root: &Path, id: &str, own_version: &str) {
    use std::os::unix::process::CommandExt;
    if std::env::var_os(EXEC_ENV).is_some_and(|value| value == id) {
        return;
    }
    let Some(program) = choose(root, id, own_version) else { return };
    log::info!("core: starting the updated {id} from {}", program.display());
    let error = std::process::Command::new(&program).args(std::env::args_os().skip(1)).env(EXEC_ENV, id).exec();
    log::warn!("core: could not start {}: {error}; using the image's copy", program.display());
}

/// Called by a core program once it is fully up: clears its failed-start count.
pub fn healthy(root: &Path, id: &str) {
    set_attempts(root, id, 0);
}

/// Where the system image keeps a core program's manifest and files (`kaonic-plugin.toml`,
/// `files/icon.png`), laid out as in its package, for programs that bring their own.
pub const IMAGE_FILES: &str = "/usr/share/kaonic-core";

/// The manifest of core program `id` and the directory its paths are relative to: the updated
/// copy's if there is one, else the system image's under `image`.
pub fn describe(root: &Path, image: &Path, id: &str) -> Option<(crate::manifest::Manifest, PathBuf)> {
    if !names::is_core(id) {
        return None;
    }
    [root.join(id).join("current"), image.join(id)].into_iter().find_map(|dir| {
        let text = fs::read_to_string(dir.join("kaonic-plugin.toml")).ok()?;
        let manifest = crate::manifest::parse(&text).ok().filter(|manifest| manifest.id == id)?;
        Some((manifest, dir))
    })
}

/// How long a launched core program must run its updated copy before the update counts as up.
pub const LAUNCHED_SETTLE: Duration = Duration::from_secs(20);
/// How long a launched core program must stay up before its start counts as good.
pub const LAUNCHED_GOOD: Duration = Duration::from_secs(60);

/// Whether launched core program `id` runs its updated copy and has for `settle`: the
/// health check of its update, as it cannot say its version.
pub fn runs_update(root: &Path, host: &dyn Host, id: &str, settle: Duration) -> bool {
    let Some((pid, up)) = host.main_process(&format!("{id}.service")) else { return false };
    let program = root.join(id).join("current/bin").join(id);
    let expected = fs::canonicalize(&program).unwrap_or(program);
    up >= settle && host.program_of(pid).is_some_and(|running| running == expected)
}

/// Marks each launched core program that has stayed up long enough as good, so its updated
/// copy keeps being used across restarts. Called every so often by the installer.
pub fn mark_launched_good(root: &Path, host: &dyn Host) {
    for id in names::LAUNCHED {
        if host.main_process(&format!("{id}.service")).is_some_and(|(_, up)| up >= LAUNCHED_GOOD) && attempts(root, id) > 0 {
            set_attempts(root, id, 0);
        }
    }
}

/// `kaonic-hub-installer run-core <id> <image program> <image version> [args...]`: starts
/// launched core program `id`, its updated copy when [`choose`] picks it, else the image's.
/// Only returns on failure.
pub fn launch(root: &Path, id: &str, image: &Path, image_version: &str, args: &[std::ffi::OsString]) -> Error {
    use std::os::unix::process::CommandExt;
    if !names::is_launched(id) {
        return Error::invalid(format!("{id} is not started through the installer"));
    }
    let program = choose(root, id, image_version).unwrap_or_else(|| image.to_owned());
    log::info!("core: starting {id} from {}", program.display());
    let error = std::process::Command::new(&program).args(args).env(EXEC_ENV, id).exec();
    Error::failed(format!("starting {}: {error}", program.display()))
}

fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Fake;
    use crate::package::testing::{Key, package, staging};

    fn core_package(id: &str, version: &str, key: Option<&Key>) -> Vec<u8> {
        let manifest = format!("[kaonic-plugin]\nformat = 2\nid = \"{id}\"\nname = \"{id}\"\nversion = \"{version}\"\ndeveloper = \"Beechat\"\n");
        let program = format!("#!/bin/sh\necho {version}\n");
        package(&[("kaonic-plugin.toml", manifest.as_bytes()), (&format!("bin/{id}"), program.as_bytes())], key)
    }

    fn core(keys: Vec<Vec<u8>>) -> (Core, PathBuf, Arc<Fake>) {
        let dir = staging();
        let host = Arc::new(Fake::default());
        (Core::new(&dir.join("core"), &dir.join("state"), keys, host.clone()).unwrap(), dir, host)
    }

    const HUB: &str = "kaonic-hub";

    #[test]
    fn an_update_that_comes_up_is_kept() {
        let (core, dir, host) = core(vec![]);
        let record = core.update(HUB, &mut core_package(HUB, "1.1", None).as_slice(), false, Some("admin"), &|version| version == "1.1", Duration::ZERO).unwrap();
        assert!(record.confirmed && record.version == "1.1" && !record.signed);
        assert!(host.state.lock().unwrap().calls.contains(&"restart kaonic-hub.service".to_owned()));
        assert!(dir.join("core/kaonic-hub/current/bin/kaonic-hub").is_file());
        let event = &History::in_state(&dir.join("state")).recent(Some(HUB), 1)[0];
        assert_eq!((event.outcome, event.actor.as_deref(), event.to.as_deref()), (Outcome::Done, Some("admin"), Some("1.1")));
    }

    #[test]
    fn an_update_that_does_not_come_up_is_rolled_back() {
        let (core, dir, host) = core(vec![]);
        core.update(HUB, &mut core_package(HUB, "1.1", None).as_slice(), false, None, &|_| true, Duration::ZERO).unwrap();
        let error = core.update(HUB, &mut core_package(HUB, "1.2", None).as_slice(), false, None, &|_| false, Duration::ZERO).unwrap_err();
        assert!(error.message.contains("previous version is back"));
        let record = core.record(HUB).unwrap();
        assert_eq!((record.version.as_str(), record.highest_version.as_str()), ("1.1", "1.2"));
        assert!(fs::read_to_string(dir.join("core/kaonic-hub/current/bin/kaonic-hub")).unwrap().contains("1.1"));
        assert_eq!(host.state.lock().unwrap().calls.iter().filter(|call| *call == "restart kaonic-hub.service").count(), 3);
        assert_eq!(History::in_state(&dir.join("state")).recent(Some(HUB), 1)[0].outcome, Outcome::RolledBack);
        // A first update that fails leaves no update at all: the image's copy runs.
        let (core, _, _) = self::core(vec![]);
        assert!(core.update(HUB, &mut core_package(HUB, "2", None).as_slice(), false, None, &|_| false, Duration::ZERO).is_err());
        assert!(core.record(HUB).is_none());
    }

    #[test]
    fn checks_the_package_is_for_this_program_and_signed_when_it_can_be() {
        let (core, _, _) = core(vec![]);
        assert!(core.stage(HUB, &mut core_package("kaonic-hub-installer", "1", None).as_slice(), false).is_err(), "wrong program");
        assert!(core.stage("sample", &mut core_package("sample", "1", None).as_slice(), false).is_err(), "not core");
        let key = Key::generate();
        let (core, _, _) = self::core(vec![key.public_pem()]);
        assert_eq!(core.stage(HUB, &mut core_package(HUB, "1", None).as_slice(), false).unwrap_err().kind, crate::Kind::Forbidden);
        assert!(core.stage(HUB, &mut core_package(HUB, "1", Some(&key)).as_slice(), false).unwrap().signed);
    }

    #[test]
    fn downgrades_need_permission() {
        let (core, _, _) = core(vec![]);
        core.update(HUB, &mut core_package(HUB, "2", None).as_slice(), false, None, &|_| true, Duration::ZERO).unwrap();
        assert_eq!(core.stage(HUB, &mut core_package(HUB, "1", None).as_slice(), false).unwrap_err().kind, crate::Kind::Downgrade);
        assert!(core.stage(HUB, &mut core_package(HUB, "1", None).as_slice(), true).is_ok());
    }

    #[test]
    fn only_a_missing_release_key_means_a_development_device() {
        let dir = staging();
        fs::write(dir.join("key.pem"), b"pem").unwrap();
        assert_eq!(read_release_keys(&[dir.join("key.pem"), dir.join("missing.pem")]).unwrap(), [b"pem".to_vec()]);
        assert!(read_release_keys(&[dir.join("missing.pem")]).unwrap().is_empty());
        assert!(read_release_keys(std::slice::from_ref(&dir)).is_err(), "a directory, not a key");
    }

    #[test]
    fn a_launched_program_is_up_when_its_unit_runs_the_update_long_enough() {
        const COMMD: &str = "kaonic-commd";
        let (core, dir, host) = core(vec![]);
        let root = dir.join("core");
        let unit = "kaonic-commd.service".to_owned();
        let image = PathBuf::from("/usr/bin/kaonic-commd");
        // Still the image's program: the update is not running, so it is rolled back.
        host.state.lock().unwrap().processes.insert(unit.clone(), (7, Duration::from_secs(60), image.clone()));
        let healthy = |_: &str| runs_update(&root, host.as_ref(), COMMD, LAUNCHED_SETTLE);
        assert!(core.update(COMMD, &mut core_package(COMMD, "1.1", None).as_slice(), false, None, &healthy, Duration::ZERO).is_err());
        assert!(core.record(COMMD).is_none());
        // The update runs, but only just started: not yet.
        core.stage(COMMD, &mut core_package(COMMD, "1.1", None).as_slice(), false).unwrap();
        core.switch(&Staged { id: COMMD.into(), version: "1.1".into(), signed: false }).unwrap();
        let updated = fs::canonicalize(root.join("kaonic-commd/current/bin/kaonic-commd")).unwrap();
        host.state.lock().unwrap().processes.insert(unit.clone(), (8, Duration::from_secs(2), updated.clone()));
        assert!(!runs_update(&root, host.as_ref(), COMMD, LAUNCHED_SETTLE));
        host.state.lock().unwrap().processes.insert(unit.clone(), (8, LAUNCHED_SETTLE, updated));
        assert!(runs_update(&root, host.as_ref(), COMMD, LAUNCHED_SETTLE));
        // Starts count until it has stayed up a while.
        assert!(choose(&root, COMMD, "1.0").is_some());
        assert_eq!(attempts(&root, COMMD), 1);
        mark_launched_good(&root, host.as_ref());
        assert_eq!(attempts(&root, COMMD), 1, "up for less than a minute");
        host.state.lock().unwrap().processes.get_mut(&unit).unwrap().1 = LAUNCHED_GOOD;
        mark_launched_good(&root, host.as_ref());
        assert_eq!(attempts(&root, COMMD), 0);
    }

    #[test]
    fn a_program_is_described_by_its_update_else_by_the_image() {
        const COMMD: &str = "kaonic-commd";
        let (core, dir, _) = core(vec![]);
        let (root, image) = (dir.join("core"), dir.join("image"));
        assert!(describe(&root, &image, COMMD).is_none(), "nothing yet");
        fs::create_dir_all(image.join(COMMD)).unwrap();
        let manifest = |name: &str| format!("[kaonic-plugin]\nformat = 2\nid = \"{COMMD}\"\nname = \"{name}\"\nversion = \"1.0\"\ndeveloper = \"Beechat\"\nicon = \"files/icon.png\"\n");
        fs::write(image.join(COMMD).join("kaonic-plugin.toml"), manifest("From the image")).unwrap();
        let (about, from) = describe(&root, &image, COMMD).unwrap();
        assert_eq!((about.name.as_str(), from), ("From the image", image.join(COMMD)));
        core.update(COMMD, &mut core_package(COMMD, "1.1", None).as_slice(), false, None, &|_| true, Duration::ZERO).unwrap();
        assert_eq!(describe(&root, &image, COMMD).unwrap().1, root.join("kaonic-commd/current"), "the update's own");
        // Only core programs, and a manifest must name the program it describes.
        fs::create_dir_all(image.join("sample")).unwrap();
        fs::write(image.join("sample").join("kaonic-plugin.toml"), manifest("x").replace(COMMD, "sample")).unwrap();
        assert!(describe(&root, &image, "sample").is_none());
        fs::write(image.join(COMMD).join("kaonic-plugin.toml"), manifest("x").replace(COMMD, "kaonic-factory")).unwrap();
        let _ = fs::remove_dir_all(root.join(COMMD));
        assert!(describe(&root, &image, COMMD).is_none());
    }

    #[test]
    fn only_commd_and_the_factory_server_are_launched() {
        let dir = staging();
        assert_eq!(launch(&dir, "kaonic-hub", Path::new("/bin/true"), "1", &[]).kind, crate::Kind::Invalid);
        assert!(names::is_core("kaonic-commd") && names::is_core("kaonic-factory"));
    }

    #[test]
    fn start_picks_the_update_until_it_keeps_failing() {
        let (core, dir, _) = core(vec![]);
        let root = dir.join("core");
        assert!(choose(&root, HUB, "1.0").is_none(), "no update");
        core.update(HUB, &mut core_package(HUB, "1.1", None).as_slice(), false, None, &|_| true, Duration::ZERO).unwrap();
        assert!(choose(&root, HUB, "1.2").is_none(), "the image is newer");
        for _ in 0..MAX_ATTEMPTS {
            assert!(choose(&root, HUB, "1.0").is_some());
        }
        assert!(choose(&root, HUB, "1.0").is_none(), "failed to come up too often");
        healthy(&root, HUB);
        assert!(choose(&root, HUB, "1.1").is_some(), "healthy again; same version as the image prefers the update");
    }
}
