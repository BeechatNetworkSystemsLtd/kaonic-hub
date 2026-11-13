//! Small settings as key → text. Each subsystem owns its keys (`wifi.client_enabled`, …).

use rusqlite::{Connection, OptionalExtension, params};

const SELECT: &str = include_str!("../sql/settings/select.sql");
const UPSERT: &str = include_str!("../sql/settings/upsert.sql");

pub fn get(connection: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    connection.query_row(SELECT, params![key], |row| row.get(0)).optional()
}

pub fn set(connection: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    connection.execute(UPSERT, params![key, value])?;
    Ok(())
}

pub fn get_bool(connection: &Connection, key: &str, default: bool) -> rusqlite::Result<bool> {
    Ok(get(connection, key)?.map_or(default, |value| value == "true"))
}

pub fn set_bool(connection: &Connection, key: &str, value: bool) -> rusqlite::Result<()> {
    set(connection, key, if value { "true" } else { "false" })
}
