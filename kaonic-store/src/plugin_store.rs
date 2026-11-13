//! Each plugin's own key/value store, for the plugin API. A plugin only ever names its keys;
//! the hub fills in which plugin it is, so one plugin cannot reach another's values.

use rusqlite::{Connection, OptionalExtension, params};

const SELECT: &str = include_str!("../sql/plugin_store/select.sql");
const SELECT_KEYS: &str = include_str!("../sql/plugin_store/select_keys.sql");
const USAGE_BESIDES: &str = include_str!("../sql/plugin_store/usage_besides.sql");
const UPSERT: &str = include_str!("../sql/plugin_store/upsert.sql");
const DELETE: &str = include_str!("../sql/plugin_store/delete.sql");
const DELETE_ALL: &str = include_str!("../sql/plugin_store/delete_all.sql");

/// The largest value.
pub const MAX_VALUE: usize = 64 * 1024;
/// Keys and values of one plugin together.
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_KEYS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    Stored,
    /// The value is over [`MAX_VALUE`].
    TooLarge,
    /// The plugin would go over [`MAX_BYTES`] or [`MAX_KEYS`].
    Full,
}

pub fn get(connection: &Connection, plugin: &str, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    connection.query_row(SELECT, params![plugin, key], |row| row.get(0)).optional()
}

/// The plugin's keys, sorted.
pub fn keys(connection: &Connection, plugin: &str) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(SELECT_KEYS)?;
    statement.query_map(params![plugin], |row| row.get(0))?.collect()
}

/// Stores `value` under `key`, within the plugin's limits.
pub fn put(connection: &mut Connection, plugin: &str, key: &str, value: &[u8]) -> rusqlite::Result<Put> {
    if value.len() > MAX_VALUE {
        return Ok(Put::TooLarge);
    }
    let transaction = connection.transaction()?;
    let (count, bytes): (i64, i64) = transaction.query_row(USAGE_BESIDES, params![plugin, key], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if count as usize + 1 > MAX_KEYS || bytes as usize + key.len() + value.len() > MAX_BYTES {
        return Ok(Put::Full);
    }
    transaction.execute(UPSERT, params![plugin, key, value])?;
    transaction.commit()?;
    Ok(Put::Stored)
}

/// True if there was such a key.
pub fn delete(connection: &Connection, plugin: &str, key: &str) -> rusqlite::Result<bool> {
    Ok(connection.execute(DELETE, params![plugin, key])? > 0)
}

/// Everything of one plugin (it was removed with its data).
pub fn delete_all(connection: &Connection, plugin: &str) -> rusqlite::Result<usize> {
    connection.execute(DELETE_ALL, params![plugin])
}
