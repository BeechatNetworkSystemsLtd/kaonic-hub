//! Tickets for plugin pages.
//!
//! A plugin page runs sandboxed, in an opaque origin, so the browser does not send the
//! hub's `SameSite=Strict` session cookie with what the page loads. A signed-in user gets a
//! ticket instead, in the page's path: `/apps/<id>/~<ticket>/`. Relative URLs keep it, so
//! the page's scripts, styles and sockets carry it without any cookie. A ticket opens one
//! plugin's pages only, lasts at most [`LIFETIME`], and ends with the session it came from.
//! One session holds at most [`PER_SESSION`]; the hub at most [`MAX`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

pub const LIFETIME: Duration = Duration::from_secs(12 * 3600);
/// At most this many tickets live; the oldest go first.
pub const MAX: usize = 512;
/// At most this many per session; its oldest go first.
pub const PER_SESSION: usize = 16;
/// A ticket in a path: `~` and 64 hex characters.
pub const MARK: char = '~';

struct Ticket {
    plugin: String,
    /// The hash of the session token it was made from.
    session: Vec<u8>,
    made: Instant,
}

#[derive(Default)]
pub struct Tickets {
    /// By the ticket's SHA-256.
    live: Mutex<HashMap<[u8; 32], Ticket>>,
}

impl Tickets {
    /// A new ticket to `plugin`'s pages for the session with this token hash.
    pub fn mint(&self, plugin: &str, session: &[u8]) -> std::io::Result<String> {
        let ticket = crate::random::token()?;
        let mut live = self.live.lock().expect("tickets lock");
        live.retain(|_, held| held.made.elapsed() < LIFETIME);
        if live.values().filter(|held| held.session == session).count() >= PER_SESSION
            && let Some(oldest) = live.iter().filter(|(_, held)| held.session == session).min_by_key(|(_, held)| held.made).map(|(key, _)| *key)
        {
            live.remove(&oldest);
        }
        if live.len() >= MAX
            && let Some(oldest) = live.iter().min_by_key(|(_, held)| held.made).map(|(key, _)| *key)
        {
            live.remove(&oldest);
        }
        live.insert(Sha256::digest(ticket.as_bytes()).into(), Ticket { plugin: plugin.to_owned(), session: session.to_vec(), made: Instant::now() });
        Ok(ticket)
    }

    /// The session behind a ticket, if it opens `plugin` and has not run out.
    pub fn check(&self, plugin: &str, ticket: &str) -> Option<Vec<u8>> {
        let key: [u8; 32] = Sha256::digest(ticket.as_bytes()).into();
        let live = self.live.lock().expect("tickets lock");
        let held = live.get(&key)?;
        (held.plugin == plugin && held.made.elapsed() < LIFETIME).then(|| held.session.clone())
    }
}

/// Splits `~<ticket>/rest` into the ticket and the rest.
pub fn split(rest: &str) -> Option<(&str, &str)> {
    let rest = rest.strip_prefix(MARK)?;
    let (ticket, after) = rest.split_at_checked(64)?;
    if !ticket.bytes().all(|byte| byte.is_ascii_hexdigit()) || !(after.is_empty() || after.starts_with('/')) {
        return None;
    }
    Some((ticket, after.strip_prefix('/').unwrap_or(after)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_opens_one_plugin_for_one_session() {
        let tickets = Tickets::default();
        let ticket = tickets.mint("echo", b"session").unwrap();
        assert_eq!(tickets.check("echo", &ticket).as_deref(), Some(&b"session"[..]));
        assert!(tickets.check("other", &ticket).is_none());
        assert!(tickets.check("echo", &"0".repeat(64)).is_none());

        let path = format!("~{ticket}/assets/app.js");
        assert_eq!(split(&path), Some((ticket.as_str(), "assets/app.js")));
        assert_eq!(split(&format!("~{ticket}")), Some((ticket.as_str(), "")));
        assert!(split("assets/app.js").is_none() && split("~abc/x").is_none());
        assert!(split(&format!("~{ticket}x")).is_none());
    }

    #[test]
    fn one_session_cannot_push_out_the_others_tickets() {
        let tickets = Tickets::default();
        let kept = tickets.mint("echo", b"other").unwrap();
        let first = tickets.mint("echo", b"busy").unwrap();
        let mine: Vec<String> = (0..MAX).map(|_| tickets.mint("echo", b"busy").unwrap()).collect();
        assert!(tickets.check("echo", &kept).is_some(), "another session's ticket stays");
        assert!(tickets.check("echo", &first).is_none(), "the oldest of the session went");
        assert!(mine[MAX - PER_SESSION..].iter().all(|ticket| tickets.check("echo", ticket).is_some()));
        assert_eq!(tickets.live.lock().unwrap().len(), PER_SESSION + 1);
    }
}
