//! The SQLite store: connection setup, the transaction wrapper and shared
//! row helpers. Lifecycle operations are in `ops`, outbox and integrity in
//! `outbox` and `integrity`, the core port adapter in `port`.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use custodian_core::{Exposure, ReasonCode, RunId, RunState};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};

use crate::clock::{Clock, SystemClock};
use crate::error::StoreError;
use crate::fault::{FaultInjector, FaultOp, FaultPhase, FaultPoint, NoFault};
use crate::migrations::{self, Migration};
use crate::model::{parse_exposure, parse_state, AttemptRecord};
use crate::secure_fs;

/// The export-acknowledged dispatch gate (R-2, ADR 0116).
///
/// `start_attempt` and `record_exposure` refuse with
/// [`StoreError::ExportPending`] while more than `max_unexported` budget
/// affecting audit events (reservations, approvals, starts, exposures,
/// settlements, disclosure charges, legacy imports) are not yet acknowledged
/// by the ledger export. With the bound at zero, no protected input can be
/// released for spend that a restored older backup would forget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportGate {
    /// No gate. The library default, kept so the synthetic suites that drive
    /// the store directly stay valid; the operator binary never uses it
    /// (`StoreConfig::enforced`).
    Off,
    /// Refuse dispatch while more than this many budget-affecting events are
    /// unacknowledged. Production value: zero.
    Enforced { max_unexported: u32 },
}

/// Store configuration. `Default` is the library default (gate off);
/// [`StoreConfig::enforced`] is the production configuration.
#[derive(Clone)]
pub struct StoreConfig {
    /// R-2 dispatch gate.
    pub export_gate: ExportGate,
    /// How long a writer waits for the lock before `StoreError::Busy`.
    pub busy_timeout_ms: u32,
    /// Time source for the core `StateStore` port only.
    pub clock: Arc<dyn Clock>,
    /// Crash simulation seam. `NoFault` in production.
    pub fault: Arc<dyn FaultInjector>,
    /// Port adapter: seconds a reserved attempt may wait to be started.
    pub port_reservation_secs: u64,
    /// Port adapter: lease length taken when an attempt starts.
    pub port_lease_secs: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            export_gate: ExportGate::Off,
            busy_timeout_ms: 5_000,
            clock: Arc::new(SystemClock),
            fault: Arc::new(NoFault),
            port_reservation_secs: 600,
            port_lease_secs: 3_600,
        }
    }
}

impl StoreConfig {
    /// The production configuration: dispatch is gated on export
    /// acknowledgement with a bound of zero (ADR 0116).
    pub fn enforced() -> Self {
        Self::default().with_export_gate(ExportGate::Enforced { max_unexported: 0 })
    }
    pub fn with_export_gate(mut self, gate: ExportGate) -> Self {
        self.export_gate = gate;
        self
    }
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
    pub fn with_fault(mut self, fault: Arc<dyn FaultInjector>) -> Self {
        self.fault = fault;
        self
    }
    pub fn with_busy_timeout_ms(mut self, ms: u32) -> Self {
        self.busy_timeout_ms = ms;
        self
    }
}

/// SQLite-backed runtime store. One instance owns one connection behind a
/// mutex; open one instance per thread (or process) for real write
/// contention, which SQLite serializes with `BEGIN IMMEDIATE`.
pub struct SqliteStore {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) cfg: StoreConfig,
}

pub(crate) fn sql_time(v: u64) -> Result<i64, StoreError> {
    if v > custodian_contracts::types::MAX_SAFE_INT {
        return Err(StoreError::InvalidInput);
    }
    i64::try_from(v).map_err(|_| StoreError::InvalidInput)
}

pub(crate) fn from_sql(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl SqliteStore {
    /// Open (creating if absent) the store at `path` with the latest schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(path, StoreConfig::default(), migrations::MIGRATIONS)
    }

    pub fn open_with_config(path: impl AsRef<Path>, cfg: StoreConfig) -> Result<Self, StoreError> {
        Self::open_with(path, cfg, migrations::MIGRATIONS)
    }

    /// Open with an explicit migration list (tests of the migration rules).
    pub fn open_with(
        path: impl AsRef<Path>,
        cfg: StoreConfig,
        list: &[Migration],
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        secure_fs::prepare(path)?;
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_millis(u64::from(
            cfg.busy_timeout_ms,
        )))?;
        // WAL: readers see a consistent snapshot while one writer commits.
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Database);
        }
        // FULL: a committed reservation survives power loss.
        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA cell_size_check = ON;
             PRAGMA secure_delete = ON;",
        )?;
        let quick: String = conn.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if quick != "ok" {
            return Err(StoreError::Corrupt);
        }
        let now = i64::try_from(cfg.clock.now()).unwrap_or(0);
        migrations::migrate(&mut conn, list, now)?;
        Ok(Self {
            conn: Mutex::new(conn),
            cfg,
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn crash(&self, op: FaultOp, phase: FaultPhase) -> Result<(), StoreError> {
        let point = FaultPoint { op, phase };
        if self.cfg.fault.crash_at(point) {
            Err(StoreError::InjectedCrash(point))
        } else {
            Ok(())
        }
    }

    /// Run `f` in one `BEGIN IMMEDIATE` transaction. The write lock is taken
    /// before the first read, so a check-then-write inside `f` cannot race
    /// another writer. Any error rolls back everything `f` did.
    pub(crate) fn write<T>(
        &self,
        op: FaultOp,
        f: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut guard = self.lock();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if op != FaultOp::Reconcile && reconcile_flag(&tx)? {
            return Err(StoreError::NeedsReconcile);
        }
        let out = f(&tx)?;
        self.crash(op, FaultPhase::BeforeCommit)?; // tx dropped: rolled back
        tx.commit()?;
        self.crash(op, FaultPhase::AfterCommit)?;
        Ok(out)
    }

    /// Run `f` in a deferred read transaction: one consistent WAL snapshot.
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut guard = self.lock();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Deferred)?;
        f(&tx)
    }

    /// The dispatch gate this store was opened with (ADR 0116).
    pub fn export_gate(&self) -> ExportGate {
        self.cfg.export_gate
    }

    /// Latest applied schema version.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        self.read(|tx| {
            let v: i64 = tx.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )?;
            u32::try_from(v).map_err(|_| StoreError::Corrupt)
        })
    }

    /// Random identity suffix from SQLite's CSPRNG (24 lowercase hex chars).
    pub(crate) fn new_suffix(tx: &Transaction<'_>) -> Result<String, StoreError> {
        Ok(tx.query_row("SELECT lower(hex(randomblob(12)))", [], |r| r.get(0))?)
    }

    pub fn attempt(&self, attempt: &RunId) -> Result<Option<AttemptRecord>, StoreError> {
        self.read(|tx| Ok(load_attempt(tx, attempt.as_str())?.map(|r| r.into_record())))
    }
}

pub(crate) fn reconcile_flag(tx: &Connection) -> Result<bool, StoreError> {
    let v: String = tx.query_row(
        "SELECT value FROM meta WHERE key = 'needs_reconcile'",
        [],
        |r| r.get(0),
    )?;
    Ok(v != "0")
}

/// An attempt row as stored.
#[derive(Clone, Debug)]
pub(crate) struct AttemptRow {
    pub attempt_id: String,
    pub request_id: String,
    pub attempt_no: i64,
    pub state: RunState,
    pub exposure: Exposure,
    pub authorization_ref: String,
    pub reservation_id: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_token: i64,
    pub lease_expires_at: Option<i64>,
    pub version: i64,
}

impl AttemptRow {
    pub fn into_record(self) -> AttemptRecord {
        AttemptRecord {
            attempt: RunId::new(self.attempt_id),
            request_id: self.request_id,
            attempt_no: u32::try_from(self.attempt_no).unwrap_or(0),
            state: self.state,
            exposure: self.exposure,
            authorization_ref: self.authorization_ref,
            reservation_id: self.reservation_id,
            lease_owner: self.lease_owner,
            lease_token: from_sql(self.lease_token),
            lease_expires_at: self.lease_expires_at.map(from_sql),
        }
    }
}

const ATTEMPT_COLS: &str =
    "attempt_id, request_id, attempt_no, state, exposure, authorization_ref, \
     reservation_id, lease_owner, lease_token, lease_expires_at, version";

fn map_attempt(r: &rusqlite::Row<'_>) -> rusqlite::Result<(AttemptRowRaw,)> {
    Ok((AttemptRowRaw {
        attempt_id: r.get(0)?,
        request_id: r.get(1)?,
        attempt_no: r.get(2)?,
        state: r.get(3)?,
        exposure: r.get(4)?,
        authorization_ref: r.get(5)?,
        reservation_id: r.get(6)?,
        lease_owner: r.get(7)?,
        lease_token: r.get(8)?,
        lease_expires_at: r.get(9)?,
        version: r.get(10)?,
    },))
}

struct AttemptRowRaw {
    attempt_id: String,
    request_id: String,
    attempt_no: i64,
    state: String,
    exposure: String,
    authorization_ref: String,
    reservation_id: Option<String>,
    lease_owner: Option<String>,
    lease_token: i64,
    lease_expires_at: Option<i64>,
    version: i64,
}

impl AttemptRowRaw {
    fn parse(self) -> Result<AttemptRow, StoreError> {
        Ok(AttemptRow {
            attempt_id: self.attempt_id,
            request_id: self.request_id,
            attempt_no: self.attempt_no,
            state: parse_state(&self.state).ok_or(StoreError::Corrupt)?,
            exposure: parse_exposure(&self.exposure).ok_or(StoreError::Corrupt)?,
            authorization_ref: self.authorization_ref,
            reservation_id: self.reservation_id,
            lease_owner: self.lease_owner,
            lease_token: self.lease_token,
            lease_expires_at: self.lease_expires_at,
            version: self.version,
        })
    }
}

pub(crate) fn load_attempt(tx: &Connection, id: &str) -> Result<Option<AttemptRow>, StoreError> {
    let raw = tx
        .query_row(
            &format!("SELECT {ATTEMPT_COLS} FROM attempts WHERE attempt_id = ?1"),
            [id],
            map_attempt,
        )
        .optional()?;
    raw.map(|(r,)| r.parse()).transpose()
}

/// Latest attempt of a request.
pub(crate) fn load_latest_attempt(
    tx: &Connection,
    request_id: &str,
) -> Result<Option<AttemptRow>, StoreError> {
    let raw = tx
        .query_row(
            &format!(
                "SELECT {ATTEMPT_COLS} FROM attempts WHERE request_id = ?1 \
                 ORDER BY attempt_no DESC LIMIT 1"
            ),
            [request_id],
            map_attempt,
        )
        .optional()?;
    raw.map(|(r,)| r.parse()).transpose()
}

pub(crate) fn load_attempt_by_no(
    tx: &Connection,
    request_id: &str,
    no: i64,
) -> Result<Option<AttemptRow>, StoreError> {
    let raw = tx
        .query_row(
            &format!(
                "SELECT {ATTEMPT_COLS} FROM attempts WHERE request_id = ?1 AND attempt_no = ?2"
            ),
            (request_id, no),
            map_attempt,
        )
        .optional()?;
    raw.map(|(r,)| r.parse()).transpose()
}

/// Reason of the most recent transition row (for replays).
pub(crate) fn last_reason(tx: &Connection, attempt_id: &str) -> Result<ReasonCode, StoreError> {
    let s: String = tx.query_row(
        "SELECT reason FROM transitions WHERE attempt_id = ?1 AND kind = 'transition' \
         ORDER BY seq DESC LIMIT 1",
        [attempt_id],
        |r| r.get(0),
    )?;
    crate::model::parse_reason(&s).ok_or(StoreError::Corrupt)
}
