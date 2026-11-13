//! Saved Wi-Fi networks, in the operator's order. Their passwords are in the keystore.

use rusqlite::{Connection, params};

const SELECT_ALL: &str = include_str!("../sql/wifi/select_all.sql");
const DELETE_ALL: &str = include_str!("../sql/wifi/delete_all.sql");
const INSERT: &str = include_str!("../sql/wifi/insert.sql");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedNetwork {
    pub ssid: String,
    pub secured: bool,
    pub hidden: bool,
    pub auto_connect: bool,
    pub last_connected_ts: Option<i64>,
}

/// Most preferred first.
pub fn list(connection: &Connection) -> rusqlite::Result<Vec<SavedNetwork>> {
    let mut statement = connection.prepare(SELECT_ALL)?;
    statement
        .query_map([], |row| {
            Ok(SavedNetwork { ssid: row.get(0)?, secured: row.get(1)?, hidden: row.get(2)?, auto_connect: row.get(3)?, last_connected_ts: row.get(4)? })
        })?
        .collect()
}

/// Replaces the whole list, in order, in one transaction.
pub fn replace_all(connection: &mut Connection, networks: &[SavedNetwork]) -> rusqlite::Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute(DELETE_ALL, [])?;
    {
        let mut insert = transaction.prepare(INSERT)?;
        for (position, network) in networks.iter().enumerate() {
            insert.execute(params![network.ssid, position as i64, network.secured, network.hidden, network.auto_connect, network.last_connected_ts])?;
        }
    }
    transaction.commit()
}
