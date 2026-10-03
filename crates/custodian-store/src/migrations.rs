//! Explicit, versioned, forward-only, checksum-verified migrations.
//!
//! Rules (docs/state-store.md, "Migrations"):
//! - versions are contiguous from 1; there is no down migration;
//! - each applied migration's SHA-256 is recorded and re-verified on every
//!   open, so an edited or divergent migration refuses to open;
//! - a database with a version this binary does not know (newer) refuses to
//!   open: it is never reinterpreted;
//! - all pending migrations apply in one `BEGIN IMMEDIATE` transaction, so a
//!   failure leaves the database at its previous version.

use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::error::StoreError;

/// SQLite `application_id` of a custodian store ("PCST").
pub const APPLICATION_ID: i64 = 0x5043_5354;

#[derive(Clone, Copy, Debug)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

impl Migration {
    /// Lowercase hex SHA-256 of the exact migration bytes.
    pub fn checksum(&self) -> String {
        hex(&Sha256::digest(self.sql.as_bytes()))
    }
}

/// The migrations this binary knows, in order.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial",
    sql: include_str!("../migrations/0001_initial.sql"),
}];

/// Highest schema version this binary knows.
pub fn latest_version() -> u32 {
    MIGRATIONS.last().map_or(0, |m| m.version)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    out
}

fn has_tables(conn: &Connection) -> Result<bool, StoreError> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Bring `conn` to the latest version of `list`, or refuse.
pub fn migrate(conn: &mut Connection, list: &[Migration], now: i64) -> Result<u32, StoreError> {
    // The list itself must be well formed: contiguous from 1.
    for (i, m) in list.iter().enumerate() {
        if usize::try_from(m.version).ok() != Some(i + 1) {
            return Err(StoreError::MigrationFailed);
        }
    }

    let app_id: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    if app_id != 0 && app_id != APPLICATION_ID {
        return Err(StoreError::NotAStore);
    }
    if app_id == 0 && has_tables(conn)? {
        return Err(StoreError::NotAStore);
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY,
             name       TEXT NOT NULL,
             checksum   TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         ) STRICT",
    )?;

    let applied: Vec<(i64, String)> = {
        let mut stmt =
            tx.prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };

    let known = i64::try_from(list.len()).map_err(|_| StoreError::MigrationFailed)?;
    for (expected, (version, checksum)) in (1i64..).zip(&applied) {
        if *version > known {
            return Err(StoreError::SchemaTooNew);
        }
        // Applied versions must be a contiguous prefix.
        if *version != expected {
            return Err(StoreError::MigrationChecksum);
        }
        let idx = usize::try_from(*version - 1).map_err(|_| StoreError::MigrationChecksum)?;
        if list[idx].checksum() != *checksum {
            return Err(StoreError::MigrationChecksum);
        }
    }

    let current = u32::try_from(applied.len()).map_err(|_| StoreError::MigrationFailed)?;
    for m in list.iter().skip(applied.len()) {
        tx.execute_batch(m.sql)
            .map_err(|_| StoreError::MigrationFailed)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            (i64::from(m.version), m.name, m.checksum(), now),
        )?;
    }
    let target = u32::try_from(list.len()).map_err(|_| StoreError::MigrationFailed)?;
    if target != current || app_id == 0 {
        tx.execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {target};"
        ))?;
    }
    tx.commit()?;
    Ok(target)
}
