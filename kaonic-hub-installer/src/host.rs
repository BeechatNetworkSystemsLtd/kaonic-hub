//! What the installer asks of the system: systemd and file owners. A trait, so the
//! installer's logic is tested anywhere with [`Fake`]. Plugins run as numeric uids
//! ([`crate::records::UIDS`]) with no user entry, so no users are made.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use crate::Error;

pub trait Host: Send + Sync {
    /// `systemctl <args>`.
    fn systemctl(&self, args: &[&str]) -> Result<(), Error>;
    fn is_active(&self, unit: &str) -> bool;
    /// Sets the owner of `path`, not following a symlink.
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<(), Error>;
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
}
