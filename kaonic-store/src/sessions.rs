//! Browser sessions. The cookie carries a random token; only its SHA-256 is stored,
//! so a copy of the database cannot be used to sign in.

use rusqlite::{Connection, OptionalExtension, params};

const INSERT: &str = include_str!("../sql/sessions/insert.sql");
const SELECT: &str = include_str!("../sql/sessions/select.sql");
const TOUCH: &str = include_str!("../sql/sessions/touch.sql");
const SELECT_TIMES: &str = include_str!("../sql/sessions/select_times.sql");
const DELETE: &str = include_str!("../sql/sessions/delete.sql");
const DELETE_ALL: &str = include_str!("../sql/sessions/delete_all.sql");
const PURGE_EXPIRED: &str = include_str!("../sql/sessions/purge_expired.sql");

/// A session ends after this long without use…
pub const IDLE_SECS: i64 = 12 * 3600;
/// …and after this long in all.
pub const MAX_SECS: i64 = 7 * 24 * 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub csrf_token: String,
    pub role: String,
    pub created_ts: i64,
    pub last_used_ts: i64,
}

pub fn create(connection: &Connection, token_hash: &[u8], csrf_token: &str, role: &str, now: i64) -> rusqlite::Result<()> {
    connection.execute(INSERT, params![token_hash, csrf_token, role, now])?;
    Ok(())
}

/// The live session, marked as used now. An expired one is deleted.
pub fn find_and_touch(connection: &Connection, token_hash: &[u8], now: i64) -> rusqlite::Result<Option<Session>> {
    let session = connection
        .query_row(SELECT, params![token_hash], |row| {
            Ok(Session { csrf_token: row.get(0)?, role: row.get(1)?, created_ts: row.get(2)?, last_used_ts: row.get(3)? })
        })
        .optional()?;
    let Some(session) = session else { return Ok(None) };
    if now - session.last_used_ts > IDLE_SECS || now - session.created_ts > MAX_SECS || now < session.created_ts {
        delete(connection, token_hash)?;
        return Ok(None);
    }
    // At most once a minute, to spare the flash.
    if now - session.last_used_ts >= 60 {
        connection.execute(TOUCH, params![token_hash, now])?;
    }
    Ok(Some(Session { last_used_ts: now, ..session }))
}

/// Whether the session is still live, without marking it used, so background checks (like
/// UDP audio) do not keep an idle sign-in alive.
pub fn is_live(connection: &Connection, token_hash: &[u8], now: i64) -> rusqlite::Result<bool> {
    let times: Option<(i64, i64)> = connection
        .query_row(SELECT_TIMES, params![token_hash], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    Ok(times.is_some_and(|(created, used)| now - used <= IDLE_SECS && now - created <= MAX_SECS && now >= created))
}

pub fn delete(connection: &Connection, token_hash: &[u8]) -> rusqlite::Result<()> {
    connection.execute(DELETE, params![token_hash])?;
    Ok(())
}

/// Ends every session: a password change or a factory reset.
pub fn delete_all(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(DELETE_ALL, [])?;
    Ok(())
}

pub fn purge_expired(connection: &Connection, now: i64) -> rusqlite::Result<usize> {
    connection.execute(PURGE_EXPIRED, params![now, IDLE_SECS, MAX_SECS])
}
