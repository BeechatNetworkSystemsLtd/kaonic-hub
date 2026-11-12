//! Which saved network the Wi-Fi client should be on, and when to scan.
//!
//! [`Policy`] is a pure state machine: it is fed scan results, events from
//! wpa_supplicant, the operator's commands and the time, and answers with
//! [`Action`]s for the caller to carry out. It does no I/O and reads no clock,
//! so every rule below is tested without a radio.
//!
//! - **Choice.** The first saved network in the operator's order that is in
//!   range, may be joined automatically, and is not waiting out a failure.
//! - **Staying put.** A working connection is kept. The client moves only when
//!   it is lost, or when a network earlier in the order has been seen at
//!   [`ROAM_MIN_DBM`] or better in [`ROAM_SCANS`] scans in a row.
//! - **Pinned.** A network joined by hand is kept, even when a preferred one
//!   appears, until it fails or is unpinned.
//! - **Retries.** A failed network waits [`RETRY_FIRST`], doubling up to
//!   [`RETRY_MAX`]. A wrong password is not retried until the password changes.
//! - **Scanning.** Often while searching, rarely while connected, never while
//!   a join is under way.

use std::collections::HashMap;

/// Monotonic seconds, from whatever clock the caller uses. Never wall-clock
/// time, which jumps when the device first learns the date.
pub type Secs = u64;

/// How long a join may take: association, then again for an address.
pub const JOIN_TIMEOUT: Secs = 20;
/// The first wait after a failure; it doubles on every failure in a row.
pub const RETRY_FIRST: Secs = 30;
pub const RETRY_MAX: Secs = 600;
/// A preferred network must be at least this strong, this many scans in a row, before the client moves to it.
pub const ROAM_MIN_DBM: i32 = -70;
pub const ROAM_SCANS: u8 = 2;
/// Scan intervals: while searching (fast, then slow after `SEARCH_FAST_FOR`), and while connected.
pub const SCAN_SEARCHING: Secs = 10;
pub const SCAN_SEARCHING_SLOW: Secs = 120;
pub const SEARCH_FAST_FOR: Secs = 300;
pub const SCAN_CONNECTED: Secs = 300;
/// A scan that has not answered by then is given up, so the next one can start.
pub const SCAN_TIMEOUT: Secs = 15;

/// Why joining a network failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Problem {
    /// The 4-way handshake failed.
    WrongPassword,
    /// Not in range.
    NotFound,
    /// The access point refused the association.
    Rejected,
    /// No association within [`JOIN_TIMEOUT`].
    Timeout,
    /// Associated, but no address within [`JOIN_TIMEOUT`].
    NoAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    Open,
    Wpa2,
    Wpa3,
}

/// One network name heard in a scan (its strongest access point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub ssid: String,
    pub signal_dbm: i32,
    pub security: Security,
    pub frequency_mhz: u32,
}

/// A network the client may join. Its password lives elsewhere (the keystore).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub ssid: String,
    pub secured: bool,
    pub hidden: bool,
    pub auto_connect: bool,
    pub last_connected: Option<Secs>,
    pub problem: Option<Problem>,
    /// Not tried automatically before this time.
    pub retry_at: Option<Secs>,
    failures: u32,
}

impl Saved {
    pub fn new(ssid: impl Into<String>, secured: bool) -> Self {
        Self {
            ssid: ssid.into(),
            secured,
            hidden: false,
            auto_connect: true,
            last_connected: None,
            problem: None,
            retry_at: None,
            failures: 0,
        }
    }

    /// Waiting out a failure, or a wrong password that only a new one can fix.
    fn blocked(&self, now: Secs) -> bool {
        self.problem == Some(Problem::WrongPassword) || self.retry_at.is_some_and(|at| now < at)
    }

    fn clear_problem(&mut self) {
        self.problem = None;
        self.retry_at = None;
        self.failures = 0;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The client is switched off.
    Off,
    /// Nothing it may join is in range, or everything is waiting out a failure.
    Searching { since: Secs },
    /// Joining `ssid`: associating, then (once `associated`) waiting for an address.
    Connecting { ssid: String, deadline: Secs, associated: bool },
    Connected { ssid: String, since: Secs },
}

/// What the caller must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Join this saved network, and only this one.
    Join(String),
    /// Leave whatever network the client is on, and stop trying.
    Disconnect,
    Scan,
}

/// What happened, as wpa_supplicant and the network stack report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    ScanResults(Vec<Seen>),
    /// Associated and authenticated with this network.
    Associated(String),
    /// The interface has an address (DHCP finished).
    AddressAcquired,
    /// The connection was lost.
    Disconnected,
    Failed(String, Problem),
}

/// The last failed try, kept until that network succeeds or another try fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub ssid: String,
    pub problem: Problem,
    pub at: Secs,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    NotSaved,
    /// `order` must name every saved network exactly once.
    BadOrder,
}

#[derive(Debug)]
pub struct Policy {
    saved: Vec<Saved>,
    state: State,
    pinned: Option<String>,
    attempt: Option<Attempt>,
    scan: Vec<Seen>,
    scanned_at: Option<Secs>,
    scan_started: Option<Secs>,
    next_scan: Option<Secs>,
    /// Scans in a row in which a network was strong enough to roam to.
    strong_streak: HashMap<String, u8>,
}

impl Policy {
    /// A client that is off, with these networks saved, most preferred first.
    pub fn new(saved: Vec<Saved>) -> Self {
        Self {
            saved,
            state: State::Off,
            pinned: None,
            attempt: None,
            scan: Vec::new(),
            scanned_at: None,
            scan_started: None,
            next_scan: None,
            strong_streak: HashMap::new(),
        }
    }

    /* ── what the API shows ── */

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn saved(&self) -> &[Saved] {
        &self.saved
    }

    pub fn pinned(&self) -> Option<&str> {
        self.pinned.as_deref()
    }

    pub fn attempt(&self) -> Option<&Attempt> {
        self.attempt.as_ref()
    }

    /// The latest scan, strongest first.
    pub fn scan(&self) -> &[Seen] {
        &self.scan
    }

    pub fn scanned_at(&self) -> Option<Secs> {
        self.scanned_at
    }

    pub fn in_range(&self, ssid: &str) -> Option<&Seen> {
        self.scan.iter().find(|seen| seen.ssid == ssid)
    }

    /// When `tick` next has something to do, so the caller can sleep until then.
    pub fn next_deadline(&self) -> Option<Secs> {
        let join = match &self.state {
            State::Connecting { deadline, .. } => Some(*deadline),
            _ => None,
        };
        let retry = self.saved.iter().filter_map(|saved| saved.retry_at).min();
        let scan = self.scan_started.map(|at| at + SCAN_TIMEOUT).or(self.next_scan);
        [join, retry, scan].into_iter().flatten().min()
    }

    /* ── the operator ── */

    /// Switch the client on or off (the `wifi_client` source).
    pub fn set_enabled(&mut self, enabled: bool, now: Secs) -> Vec<Action> {
        match (enabled, &self.state) {
            (false, State::Off) | (true, State::Searching { .. } | State::Connecting { .. } | State::Connected { .. }) => Vec::new(),
            (false, _) => {
                self.state = State::Off;
                self.next_scan = None;
                self.scan_started = None;
                vec![Action::Disconnect]
            }
            (true, State::Off) => {
                self.state = State::Searching { since: now };
                // Use what is already known, and look again.
                let mut actions = self.choose(now);
                actions.extend(self.scan_now(now));
                actions
            }
        }
    }

    /// Switch the client on while it is already associated with `ssid` (the hub restarted,
    /// wpa_supplicant did not): take the connection over instead of joining again.
    pub fn resume(&mut self, ssid: &str, now: Secs) -> Result<Vec<Action>, PolicyError> {
        self.index(ssid).ok_or(PolicyError::NotSaved)?;
        if self.state != State::Off {
            return Ok(Vec::new());
        }
        self.state = State::Connecting { ssid: ssid.to_owned(), deadline: now + JOIN_TIMEOUT, associated: true };
        Ok(Vec::new())
    }

    /// Save a network (or replace its password), put it first, and join it now: a pinned join.
    pub fn save(&mut self, mut network: Saved, now: Secs) -> Vec<Action> {
        if let Some(index) = self.index(&network.ssid) {
            let old = self.saved.remove(index);
            network.last_connected = old.last_connected;
        }
        network.clear_problem();
        let ssid = network.ssid.clone();
        self.saved.insert(0, network);
        self.pin(ssid, now)
    }

    pub fn forget(&mut self, ssid: &str, now: Secs) -> Result<Vec<Action>, PolicyError> {
        let index = self.index(ssid).ok_or(PolicyError::NotSaved)?;
        self.saved.remove(index);
        if self.pinned.as_deref() == Some(ssid) {
            self.pinned = None;
        }
        if self.current() == Some(ssid) {
            return Ok(self.leave(now));
        }
        Ok(Vec::new())
    }

    /// A new password: whatever went wrong before is forgotten, and the network may be tried at once.
    pub fn password_changed(&mut self, ssid: &str, secured: bool, now: Secs) -> Result<Vec<Action>, PolicyError> {
        let index = self.index(ssid).ok_or(PolicyError::NotSaved)?;
        self.saved[index].secured = secured;
        self.saved[index].clear_problem();
        // Join with the new password now: the one being joined, or any while nothing is connected.
        // A network that just failed for its password was in range a moment ago.
        if self.current() == Some(ssid) || matches!(self.state, State::Searching { .. }) {
            return Ok(self.join(ssid.to_owned(), now));
        }
        Ok(Vec::new())
    }

    pub fn set_auto_connect(&mut self, ssid: &str, auto_connect: bool, now: Secs) -> Result<Vec<Action>, PolicyError> {
        let index = self.index(ssid).ok_or(PolicyError::NotSaved)?;
        self.saved[index].auto_connect = auto_connect;
        Ok(self.choose_if_searching(now))
    }

    /// The operator's order of preference. Takes effect by the roaming rules, not by dropping a working connection.
    pub fn reorder(&mut self, ssids: &[String], now: Secs) -> Result<Vec<Action>, PolicyError> {
        if ssids.len() != self.saved.len() {
            return Err(PolicyError::BadOrder);
        }
        let mut reordered = Vec::with_capacity(ssids.len());
        for ssid in ssids {
            let index = self.index(ssid).ok_or(PolicyError::BadOrder)?;
            if reordered.iter().any(|saved: &Saved| &saved.ssid == ssid) {
                return Err(PolicyError::BadOrder);
            }
            reordered.push(self.saved[index].clone());
        }
        self.saved = reordered;
        Ok(self.choose_if_searching(now))
    }

    /// Join a saved network now and stay on it. A manual try overrides a wait or a wrong password.
    pub fn connect(&mut self, ssid: &str, now: Secs) -> Result<Vec<Action>, PolicyError> {
        let index = self.index(ssid).ok_or(PolicyError::NotSaved)?;
        self.saved[index].clear_problem();
        Ok(self.pin(ssid.to_owned(), now))
    }

    /// Let the policy choose again. The current connection is kept if it works.
    pub fn unpin(&mut self, now: Secs) -> Vec<Action> {
        self.pinned = None;
        self.choose_if_searching(now)
    }

    /* ── the radio ── */

    pub fn handle(&mut self, event: Event, now: Secs) -> Vec<Action> {
        if self.state == State::Off {
            // Late news from a client that is off. Scan results are still worth keeping.
            if let Event::ScanResults(seen) = event {
                self.take_scan(seen, now);
            }
            return Vec::new();
        }
        match event {
            Event::ScanResults(seen) => {
                self.take_scan(seen, now);
                self.after_scan(now)
            }
            Event::Associated(ssid) => {
                // Normally the network asked for; if wpa_supplicant joined another, follow it.
                self.state = State::Connecting { ssid, deadline: now + JOIN_TIMEOUT, associated: true };
                Vec::new()
            }
            Event::AddressAcquired => {
                let State::Connecting { ssid, associated: true, .. } = &self.state else {
                    return Vec::new();
                };
                let ssid = ssid.clone();
                if let Some(index) = self.index(&ssid) {
                    self.saved[index].clear_problem();
                    self.saved[index].last_connected = Some(now);
                }
                // The last failure stays visible until that network itself works: falling back to
                // another network must not hide why the one asked for did not.
                if self.attempt.as_ref().is_some_and(|attempt| attempt.ssid == ssid) {
                    self.attempt = None;
                }
                self.state = State::Connected { ssid, since: now };
                self.strong_streak.clear();
                self.next_scan = Some(now + SCAN_CONNECTED);
                Vec::new()
            }
            Event::Disconnected => match &self.state {
                // Lost a working connection: no penalty, the network may simply be back in a moment.
                State::Connected { .. } => self.leave(now),
                _ => Vec::new(),
            },
            Event::Failed(ssid, problem) => self.fail(&ssid, problem, now),
        }
    }

    /// Timeouts, retries and scheduled scans that are due.
    pub fn tick(&mut self, now: Secs) -> Vec<Action> {
        let mut actions = Vec::new();
        // A wait that has run out is over; the problem stays on show until a success.
        for saved in &mut self.saved {
            if saved.retry_at.is_some_and(|at| now >= at) {
                saved.retry_at = None;
            }
        }
        if let State::Connecting { ssid, deadline, associated } = &self.state
            && now >= *deadline
        {
            let problem = if *associated { Problem::NoAddress } else { Problem::Timeout };
            let ssid = ssid.clone();
            actions.extend(self.fail(&ssid, problem, now));
        }
        if self.scan_started.is_some_and(|at| now >= at + SCAN_TIMEOUT) {
            self.scan_started = None;
        }
        if self.next_scan.is_some_and(|at| now >= at) {
            actions.extend(self.scan_now(now));
        }
        // A wait just ran out: something may be joinable again.
        actions.extend(self.choose_if_searching(now));
        actions
    }

    /// The operator asked for a scan.
    pub fn request_scan(&mut self, now: Secs) -> Vec<Action> {
        self.scan_now(now)
    }

    /* ── rules ── */

    fn index(&self, ssid: &str) -> Option<usize> {
        self.saved.iter().position(|saved| saved.ssid == ssid)
    }

    fn current(&self) -> Option<&str> {
        match &self.state {
            State::Connecting { ssid, .. } | State::Connected { ssid, .. } => Some(ssid),
            _ => None,
        }
    }

    /// What the client should join now, if anything.
    fn best(&self, now: Secs) -> Option<&Saved> {
        let joinable = |saved: &&Saved| (saved.hidden || self.in_range(&saved.ssid).is_some()) && !saved.blocked(now);
        if let Some(pinned) = &self.pinned
            && let Some(saved) = self.saved.iter().find(|saved| &saved.ssid == pinned)
            && joinable(&saved)
        {
            return Some(saved);
        }
        self.saved.iter().filter(|saved| saved.auto_connect).find(joinable)
    }

    fn join(&mut self, ssid: String, now: Secs) -> Vec<Action> {
        self.state = State::Connecting { ssid: ssid.clone(), deadline: now + JOIN_TIMEOUT, associated: false };
        self.next_scan = None;
        vec![Action::Join(ssid)]
    }

    fn pin(&mut self, ssid: String, now: Secs) -> Vec<Action> {
        self.pinned = Some(ssid.clone());
        if self.state == State::Off {
            return Vec::new();
        }
        self.join(ssid, now)
    }

    /// Off the current network: join the next best one, or disconnect and search.
    fn leave(&mut self, now: Secs) -> Vec<Action> {
        self.state = State::Searching { since: now };
        let actions = self.choose(now);
        if actions.is_empty() {
            let mut actions = vec![Action::Disconnect];
            actions.extend(self.scan_now(now));
            return actions;
        }
        actions
    }

    fn fail(&mut self, ssid: &str, problem: Problem, now: Secs) -> Vec<Action> {
        if let Some(index) = self.index(ssid) {
            let saved = &mut self.saved[index];
            saved.failures += 1;
            saved.problem = Some(problem);
            saved.retry_at = match problem {
                Problem::WrongPassword => None,
                _ => Some(now + (RETRY_FIRST << (saved.failures - 1).min(5)).min(RETRY_MAX)),
            };
        }
        self.attempt = Some(Attempt { ssid: ssid.to_owned(), problem, at: now });
        if self.pinned.as_deref() == Some(ssid) {
            self.pinned = None;
        }
        // Only a failure of the network being joined changes course.
        if self.current() != Some(ssid) {
            return Vec::new();
        }
        self.leave(now)
    }

    fn choose(&mut self, now: Secs) -> Vec<Action> {
        match self.best(now).map(|saved| saved.ssid.clone()) {
            Some(ssid) => self.join(ssid, now),
            None => Vec::new(),
        }
    }

    fn choose_if_searching(&mut self, now: Secs) -> Vec<Action> {
        if matches!(self.state, State::Searching { .. }) { self.choose(now) } else { Vec::new() }
    }

    fn scan_now(&mut self, now: Secs) -> Vec<Action> {
        if self.state == State::Off || self.scan_started.is_some() {
            // Off, or one is already running: its results will do.
            return Vec::new();
        }
        self.scan_started = Some(now);
        self.next_scan = None;
        vec![Action::Scan]
    }

    fn take_scan(&mut self, mut seen: Vec<Seen>, now: Secs) {
        // One entry per name, its strongest access point first.
        seen.sort_by_key(|entry| std::cmp::Reverse(entry.signal_dbm));
        let mut unique: Vec<Seen> = Vec::with_capacity(seen.len());
        for entry in seen {
            if !entry.ssid.is_empty() && !unique.iter().any(|kept| kept.ssid == entry.ssid) {
                unique.push(entry);
            }
        }
        self.scan = unique;
        self.scanned_at = Some(now);
        self.scan_started = None;
    }

    fn after_scan(&mut self, now: Secs) -> Vec<Action> {
        let actions = match &self.state {
            State::Searching { .. } => self.choose(now),
            State::Connected { ssid, .. } => {
                let ssid = ssid.clone();
                self.roam_target(&ssid).map(|target| self.join(target, now)).unwrap_or_default()
            }
            State::Connecting { .. } | State::Off => Vec::new(),
        };
        self.schedule_scan(now);
        actions
    }

    /// A network earlier in the order that has been strong for long enough to move to.
    fn roam_target(&mut self, current: &str) -> Option<String> {
        if self.pinned.as_deref() == Some(current) {
            self.strong_streak.clear();
            return None;
        }
        let current_index = self.index(current)?;
        let mut streak = HashMap::new();
        for saved in &self.saved[..current_index] {
            let strong = saved.auto_connect && self.in_range(&saved.ssid).is_some_and(|seen| seen.signal_dbm >= ROAM_MIN_DBM);
            if strong {
                streak.insert(saved.ssid.clone(), self.strong_streak.get(&saved.ssid).copied().unwrap_or(0) + 1);
            }
        }
        self.strong_streak = streak;
        // The most preferred of those that qualify, unless its last try failed.
        self.saved[..current_index]
            .iter()
            .find(|saved| saved.problem.is_none() && self.strong_streak.get(&saved.ssid).is_some_and(|count| *count >= ROAM_SCANS))
            .map(|saved| saved.ssid.clone())
    }

    fn schedule_scan(&mut self, now: Secs) {
        self.next_scan = match &self.state {
            State::Searching { since } if now.saturating_sub(*since) < SEARCH_FAST_FOR => Some(now + SCAN_SEARCHING),
            State::Searching { .. } => Some(now + SCAN_SEARCHING_SLOW),
            State::Connected { .. } => Some(now + SCAN_CONNECTED),
            State::Connecting { .. } | State::Off => None,
        };
    }
}
