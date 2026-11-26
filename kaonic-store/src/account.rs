//! The UI password, optional: one account. Only an Argon2id hash (PHC string) is stored.

use rusqlite::{Connection, OptionalExtension, params};

const SELECT_PASSWORD_HASH: &str = include_str!("../sql/account/select_password_hash.sql");
const UPSERT_PASSWORD_HASH: &str = include_str!("../sql/account/upsert_password_hash.sql");
const DELETE_PASSWORD_HASH: &str = include_str!("../sql/account/delete_password_hash.sql");

pub fn password_hash(connection: &Connection) -> rusqlite::Result<Option<String>> {
    connection.query_row(SELECT_PASSWORD_HASH, [], |row| row.get(0)).optional()
}

pub fn has_password(connection: &Connection) -> rusqlite::Result<bool> {
    Ok(password_hash(connection)?.is_some())
}

pub fn set_password_hash(connection: &Connection, hash: &str, now: i64) -> rusqlite::Result<()> {
    connection.execute(UPSERT_PASSWORD_HASH, params![hash, now])?;
    Ok(())
}

/// Turns the password off.
pub fn clear_password(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(DELETE_PASSWORD_HASH, [])?;
    Ok(())
}
