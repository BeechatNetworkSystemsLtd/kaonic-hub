//! What admins did, and when. `detail` names things; it never holds secrets.

use rusqlite::{Connection, params};

const INSERT: &str = include_str!("../sql/audit/insert.sql");
const TRIM: &str = include_str!("../sql/audit/trim.sql");
const SELECT_RECENT: &str = include_str!("../sql/audit/select_recent.sql");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

/// Entries beyond this many are dropped, oldest first.
pub const KEEP: i64 = 5000;

pub fn record(connection: &Connection, now: i64, actor: &str, action: &str, detail: &str) -> rusqlite::Result<()> {
    connection.execute(INSERT, params![now, actor, action, detail])?;
    connection.execute(TRIM, params![KEEP])?;
    Ok(())
}

/// Newest first.
pub fn recent(connection: &Connection, limit: usize) -> rusqlite::Result<Vec<Entry>> {
    let mut statement = connection.prepare(SELECT_RECENT)?;
    statement
        .query_map(params![limit as i64], |row| Ok(Entry { ts: row.get(0)?, actor: row.get(1)?, action: row.get(2)?, detail: row.get(3)? }))?
        .collect()
}
