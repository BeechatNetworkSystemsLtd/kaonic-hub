//! What happened to plugins and to the core programs, newest last: one JSON line per event
//! in `history.jsonl` in the installer's state directory. Kept to the last [`KEEP`] events.
//!
//! The installer writes it for plugins and for hub updates; the hub writes it for installer
//! updates, while the installer is stopped, so the two never write at once.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Events kept; the file is trimmed back to this when it reaches a quarter more.
pub const KEEP: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Install,
    Upgrade,
    Downgrade,
    Rollback,
    Start,
    Stop,
    Restart,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    /// The new version did not stay up; the previous one is back.
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub time: u64,
    pub id: String,
    pub action: Action,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default)]
    pub signed: bool,
    /// Who asked, as the hub said (the admin's name), or "boot".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

impl Event {
    pub fn new(id: &str, action: Action, outcome: Outcome) -> Self {
        Self { time: now(), id: id.to_owned(), action, outcome, from: None, to: None, signed: false, actor: None, message: String::new() }
    }
    pub fn versions(mut self, from: Option<&str>, to: Option<&str>) -> Self {
        self.from = from.map(str::to_owned);
        self.to = to.map(str::to_owned);
        self
    }
    pub fn signed(mut self, signed: bool) -> Self {
        self.signed = signed;
        self
    }
    pub fn actor(mut self, actor: Option<&str>) -> Self {
        self.actor = actor.map(str::to_owned);
        self
    }
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct History {
    path: PathBuf,
}

impl History {
    /// The history in the installer's state directory.
    pub fn in_state(state: &Path) -> Self {
        Self { path: state.join("history.jsonl") }
    }

    /// Appends an event. A failure is logged, never fatal: history must not block work.
    pub fn add(&self, event: Event) {
        let line = serde_json::to_string(&event).expect("an event serialises") + "\n";
        let result = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .and_then(|mut file| file.write_all(line.as_bytes()));
        if let Err(error) = result {
            log::warn!("installer: history: {error}");
            return;
        }
        self.trim(KEEP + KEEP / 4);
    }

    /// The last `limit` events, newest first, for one id or all.
    pub fn recent(&self, id: Option<&str>, limit: usize) -> Vec<Event> {
        let text = fs::read_to_string(&self.path).unwrap_or_default();
        text.lines()
            .rev()
            .filter_map(|line| serde_json::from_str::<Event>(line).ok())
            .filter(|event| id.is_none_or(|id| event.id == id))
            .take(limit)
            .collect()
    }

    /// Keeps the last [`KEEP`] events once the file holds more than `over`.
    fn trim(&self, over: usize) {
        let Ok(text) = fs::read_to_string(&self.path) else { return };
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() <= over {
            return;
        }
        let kept = lines[lines.len() - KEEP..].join("\n") + "\n";
        if let Err(error) = crate::write_atomic(&self.path, kept.as_bytes(), 0o600) {
            log::warn!("installer: history: {error}");
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_newest_events_and_filters_by_id() {
        let dir = crate::package::testing::staging();
        let history = History::in_state(&dir);
        for n in 0..KEEP + KEEP / 4 + 1 {
            let id = if n % 2 == 0 { "a" } else { "b" };
            history.add(Event::new(id, Action::Install, Outcome::Done).message(n.to_string()));
        }
        let all = history.recent(None, usize::MAX);
        assert_eq!(all.len(), KEEP, "trimmed");
        assert_eq!(all[0].message, (KEEP + KEEP / 4).to_string(), "newest first");
        assert!(history.recent(Some("b"), 5).iter().all(|event| event.id == "b"));
    }
}
