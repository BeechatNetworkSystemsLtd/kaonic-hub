//! What the installer asks of the system: systemd and file owners. A trait, so the
//! installer's logic is tested anywhere with [`Fake`]. Plugins run as numeric uids
//! ([`crate::records::UIDS`]) with no user entry, so no users are made.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use crate::Error;

pub trait Host: Send + Sync {
    /// `systemctl <args>`.
    fn systemctl(&self, args: &[&str]) -> Result<(), Error>;
    fn is_active(&self, unit: &str) -> bool;
    /// Sets the owner of `path`, not following a symlink.
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<(), Error>;
    /// The unit's main process and how long it has run, while the unit is active.
    fn main_process(&self, unit: &str) -> Option<(u32, Duration)>;
    /// The program process `pid` runs.
    fn program_of(&self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

/// The real system. Tools are called by absolute path.
pub struct System;

const SYSTEMCTL: &str = "/bin/systemctl";

fn run(command: &mut Command) -> Result<(), Error> {
    let output = command.output().map_err(Error::io(format!("{command:?}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(Error::failed(format!("{command:?}: {}", String::from_utf8_lossy(&output.stderr).trim())))
}

impl Host for System {
    fn systemctl(&self, args: &[&str]) -> Result<(), Error> {
        run(Command::new(SYSTEMCTL).args(args))
    }

    fn is_active(&self, unit: &str) -> bool {
        Command::new(SYSTEMCTL).args(["is-active", "--quiet", unit]).status().is_ok_and(|status| status.success())
    }

    fn main_process(&self, unit: &str) -> Option<(u32, Duration)> {
        let output = Command::new(SYSTEMCTL).args(["show", "-p", "ActiveState", "-p", "MainPID", "-p", "ExecMainStartTimestampMonotonic", unit]).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let field = |name: &str| text.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix('='));
        if field("ActiveState")? != "active" {
            return None;
        }
        let pid: u32 = field("MainPID")?.parse().ok().filter(|pid| *pid != 0)?;
        let started_us: u64 = field("ExecMainStartTimestampMonotonic")?.parse().ok()?;
        // CLOCK_MONOTONIC, as systemd's monotonic timestamps.
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: a valid timespec to fill.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
            return None;
        }
        let now_us = now.tv_sec as u64 * 1_000_000 + now.tv_nsec as u64 / 1000;
        Some((pid, Duration::from_micros(now_us.saturating_sub(started_us))))
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<(), Error> {
        use std::os::unix::ffi::OsStrExt;
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::invalid("path with a NUL"))?;
        // SAFETY: a valid NUL-terminated path; lchown does not follow a final symlink.
        if unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } != 0 {
            return Err(Error::failed(format!("chown {}: {}", path.display(), std::io::Error::last_os_error())));
        }
        Ok(())
    }
}

/// A system in memory, for tests.
#[derive(Default)]
pub struct Fake {
    pub state: Mutex<FakeState>,
}

#[derive(Default)]
pub struct FakeState {
    pub calls: Vec<String>,
    pub active: HashSet<String>,
    /// Every chown asked for: path, uid, gid.
    pub chowned: Vec<(PathBuf, u32, u32)>,
    /// Units that fail to stay up when started.
    pub crashing: HashSet<String>,
    /// Main processes of active units: pid, how long it has run, and its program.
    pub processes: std::collections::HashMap<String, (u32, Duration, PathBuf)>,
}

impl Host for Fake {
    fn systemctl(&self, args: &[&str]) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(args.join(" "));
        let unit = args.last().map(|unit| unit.to_string()).unwrap_or_default();
        match args.first() {
            Some(&"start") | Some(&"restart") if !state.crashing.contains(&unit) => {
                state.active.insert(unit);
            }
            Some(&"start") | Some(&"restart") => {
                state.active.remove(&unit);
            }
            Some(&"stop") => {
                state.active.remove(&unit);
            }
            _ => {}
        }
        Ok(())
    }

    fn is_active(&self, unit: &str) -> bool {
        self.state.lock().unwrap().active.contains(unit)
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<(), Error> {
        self.state.lock().unwrap().chowned.push((path.to_owned(), uid, gid));
        Ok(())
    }

    fn main_process(&self, unit: &str) -> Option<(u32, Duration)> {
        let state = self.state.lock().unwrap();
        if !state.active.contains(unit) {
            return None;
        }
        state.processes.get(unit).map(|(pid, up, _)| (*pid, *up))
    }

    fn program_of(&self, pid: u32) -> Option<PathBuf> {
        self.state.lock().unwrap().processes.values().find(|(known, _, _)| *known == pid).map(|(_, _, program)| program.clone())
    }
}
