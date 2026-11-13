//! kaonic-hub's SQLite database: `hub.db` on userfs.
//!
//! It holds the UI password hash, sessions, settings, saved Wi-Fi networks and an audit log.
//! No secrets: passwords, keys and certificates are in `kaonic-keystore`.
//!
//! SQLite runs on its own thread. [`Store::call`] runs a closure there, so async code never
//! blocks on it; the functions in the modules below are what those closures call. The SQL is
//! in `sql/`, one statement per file.
//!
//! # Migrations
//!
//! After an upgrade the previous release may open this file again (a rollback), so an upgrade
//! must not break it until the new release is confirmed:
//!
//! - [`Change::Compatible`] migrations only add things. They run at open.
//! - [`Change::Breaking`] migrations wait for [`Store::complete_upgrade`].
//! - The file records the oldest release that can still open it. Older ones refuse it.

pub mod account;
pub mod audit;
pub mod sessions;
pub mod settings;
pub mod wifi;

use std::fmt;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

pub use rusqlite::Connection;
use rusqlite::TransactionBehavior;

/// What a migration does to the previous release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Only adds; the previous release keeps working. Runs at open.
    Compatible,
    /// Drops, renames or tightens; the previous release stops working. Runs in
    /// [`Store::complete_upgrade`].
    Breaking,
}

struct Migration {
    sql: &'static str,
    change: Change,
}

/// Oldest first: entry `n` takes `user_version` from `n` to `n + 1`. Never change a migration
/// that has shipped; add a new one.
const MIGRATIONS: &[Migration] = &[
    // 1: the first schema.
    Migration { sql: include_str!("../sql/migrations/0001_initial_schema.sql"), change: Change::Compatible },
    // 2: `schema_info`: the oldest release that can open the file.
    Migration { sql: include_str!("../sql/migrations/0002_schema_info.sql"), change: Change::Compatible },
];

/// The migration that creates `schema_info`.
const SCHEMA_INFO_SINCE: usize = 2;
const SELECT_MIN_READER: &str = include_str!("../sql/schema/select_min_reader.sql");
const SET_MIN_READER: &str = include_str!("../sql/schema/set_min_reader.sql");

/// Run on every connection before the migrations.
const PRAGMAS: &str = include_str!("../sql/connection/pragmas.sql");

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    /// A newer release made a change this one cannot use. The file is at schema `found`, this
    /// release knows up to `known`, and opening it needs at least `needs`.
    TooNew { found: usize, known: usize, needs: usize },
    /// The store thread is gone (it panicked or the store was shut down).
    Closed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "database: {e}"),
            Self::Io(e) => write!(f, "database file: {e}"),
            Self::TooNew { found, known, needs } => {
                write!(f, "database schema {found} needs a release that knows schema {needs}; this one knows {known}")
            }
            Self::Closed => f.write_str("database thread stopped"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// A handle to the store thread. Cheap to clone.
#[derive(Clone)]
pub struct Store {
    jobs: mpsc::Sender<Job>,
}

impl Store {
    /// Opens or creates (mode 0600) the database and runs the compatible migrations.
    pub fn open(path: &Path) -> Result<Self> {
        // Create it private first, so it is never readable by others, even briefly.
        OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let connection = Connection::open(path)?;
        Self::start(connection)
    }

    /// A store that lives in memory, for tests and development.
    pub fn open_in_memory() -> Result<Self> {
        Self::start(Connection::open_in_memory()?)
    }

    fn start(mut connection: Connection) -> Result<Self> {
        prepare(&mut connection)?;
        let (jobs, inbox) = mpsc::channel::<Job>();
        thread::Builder::new().name("kaonic-store".into()).spawn(move || {
            for job in inbox {
                job(&mut connection);
            }
        })?;
        Ok(Self { jobs })
    }

    /// Runs `work` on the store thread and returns its result.
    pub async fn call<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        self.run(move |connection| Ok(work(connection)?)).await
    }

    /// Runs the breaking migrations held back at open. Call it once the new release is
    /// confirmed: after this the previous release cannot open the file.
    pub async fn complete_upgrade(&self) -> Result<()> {
        self.run(|connection| migrate(connection, MIGRATIONS, Change::Breaking)).await
    }

    async fn run<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let job: Job = Box::new(move |connection| {
            let _ = reply.send(work(connection));
        });
        self.jobs.send(job).map_err(|_| Error::Closed)?;
        answer.await.map_err(|_| Error::Closed)?
    }
}

/// Sets the pragmas and runs the compatible migrations. Public for tests.
pub fn prepare(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(PRAGMAS)?;
    migrate(connection, MIGRATIONS, Change::Compatible)
}

/// Runs the pending migrations in one transaction, stopping at the first breaking one unless
/// `up_to` is [`Change::Breaking`].
fn migrate(connection: &mut Connection, migrations: &[Migration], up_to: Change) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let version = usize::try_from(found).unwrap_or(usize::MAX);
    if version > migrations.len() {
        // Written by a newer release: use it as is, if it still allows us.
        let needs = min_reader(&transaction, version)?;
        if needs > migrations.len() {
            return Err(Error::TooNew { found: version, known: migrations.len(), needs });
        }
        return Ok(());
    }
    let mut applied = version;
    for migration in &migrations[version..] {
        if migration.change == Change::Breaking && up_to == Change::Compatible {
            break;
        }
        transaction.execute_batch(migration.sql)?;
        applied += 1;
        transaction.pragma_update(None, "user_version", applied as i64)?;
    }
    if applied >= SCHEMA_INFO_SINCE {
        // A reader must know the newest breaking migration applied.
        let needs = migrations[..applied].iter().rposition(|m| m.change == Change::Breaking).map_or(1, |i| i + 1);
        transaction.execute(SET_MIN_READER, [needs as i64])?;
    }
    transaction.commit()?;
    Ok(())
}

/// The oldest release that can open a file at `version`. Without `schema_info`, it is
/// `version` itself.
fn min_reader(connection: &Connection, version: usize) -> Result<usize> {
    if version < SCHEMA_INFO_SINCE {
        return Ok(version);
    }
    match connection.query_row(SELECT_MIN_READER, [], |row| row.get::<_, i64>(0)) {
        Ok(needs) => Ok(usize::try_from(needs).unwrap_or(usize::MAX)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(version),
        Err(rusqlite::Error::SqliteFailure(_, Some(message))) if message.starts_with("no such table") => Ok(version),
        Err(error) => Err(error.into()),
    }
}

/// The schema version this release writes.
pub const SCHEMA_VERSION: usize = MIGRATIONS.len();

#[cfg(test)]
mod tests {
    use super::*;

    fn version(connection: &Connection) -> i64 {
        connection.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap()
    }

    fn has_table(connection: &Connection, name: &str) -> bool {
        connection.query_row("SELECT count(*) FROM sqlite_schema WHERE name = ?1", [name], |row| row.get::<_, i64>(0)).unwrap() == 1
    }

    #[test]
    fn breaking_migrations_wait_and_then_lock_out_older_releases() {
        // Release 3 drops something (breaking), release 4 adds a table.
        let later = [
            Migration { sql: "CREATE TABLE dropped_later (x INTEGER);", change: Change::Compatible },
            Migration { sql: "DROP TABLE dropped_later;", change: Change::Breaking },
            Migration { sql: "CREATE TABLE added (x INTEGER);", change: Change::Compatible },
        ];
        let all: Vec<Migration> = MIGRATIONS.iter().chain(&later).map(|m| Migration { sql: m.sql, change: m.change }).collect();
        let known = MIGRATIONS.len();
        let mut connection = Connection::open_in_memory().unwrap();

        // At open: everything up to the breaking one, which waits.
        migrate(&mut connection, &all, Change::Compatible).unwrap();
        assert_eq!(version(&connection) as usize, known + 1);
        assert!(has_table(&connection, "dropped_later") && !has_table(&connection, "added"));
        // The previous release still opens it.
        migrate(&mut connection, MIGRATIONS, Change::Compatible).unwrap();

        // Slot confirmed: the rest runs, and the previous release is refused.
        migrate(&mut connection, &all, Change::Breaking).unwrap();
        assert_eq!(version(&connection) as usize, all.len());
        assert!(!has_table(&connection, "dropped_later") && has_table(&connection, "added"));
        let needs = known + 2;
        assert!(matches!(migrate(&mut connection, MIGRATIONS, Change::Compatible), Err(Error::TooNew { needs: n, .. }) if n == needs));
        // A release that knows the breaking migration, but not the one after it, still opens it.
        migrate(&mut connection, &all[..needs], Change::Compatible).unwrap();
        assert_eq!(version(&connection) as usize, all.len());
    }
}
