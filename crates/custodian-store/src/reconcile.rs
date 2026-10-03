//! Read and restrict operations the operator CLI needs around the restore
//! block (C10, ADR 0082). None of them can raise or lower a budget; the only
//! way out of a block is the existing, audited [`SqliteStore::clear_reconcile`].

use rusqlite::OptionalExtension;

use crate::error::StoreError;
use crate::model::Checkpoint;
use crate::store::{sql_time, SqliteStore};

impl SqliteStore {
    /// The store's random identity (`meta.store_id`). Operators name it in
    /// repair commands so a command aimed at one database cannot run against
    /// another.
    pub fn store_id(&self) -> Result<String, StoreError> {
        self.read(|tx| {
            Ok(
                tx.query_row("SELECT value FROM meta WHERE key = 'store_id'", [], |r| {
                    r.get(0)
                })?,
            )
        })
    }

    /// Persist the write block (`needs_reconcile`) without waiting for a
    /// checkpoint comparison. Used when a startup check refuses for a reason
    /// that makes the store untrustworthy to write to. It only restricts:
    /// every write is refused until [`SqliteStore::clear_reconcile`]. It does
    /// not append to the outbox (the block may be set because the outbox
    /// cannot be trusted) and is idempotent.
    pub fn block_for_reconcile(&self) -> Result<(), StoreError> {
        let mut guard = self.lock();
        let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE meta SET value = '1' WHERE key = 'needs_reconcile'",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// True when this database's outbox chain contains `cp`: it is at or
    /// after the checkpoint and not diverged from it. Read-only: unlike
    /// [`SqliteStore::verify_external_checkpoint`] it never sets the write
    /// block, so a blocked store can be compared safely.
    pub fn contains_checkpoint(&self, cp: &Checkpoint) -> Result<bool, StoreError> {
        let seq = sql_time(cp.seq)?;
        self.read(|tx| {
            let chain: Option<String> = tx
                .query_row("SELECT chain FROM outbox WHERE seq = ?1", [seq], |r| {
                    r.get(0)
                })
                .optional()?;
            Ok(chain.as_deref() == Some(cp.chain.as_str()))
        })
    }

    /// Submissions waiting for a decision.
    pub fn pending_submission_count(&self) -> Result<u64, StoreError> {
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM submissions WHERE status = 'pending'",
                [],
                |r| r.get(0),
            )?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// Attempts whose lease or reservation window lapsed by `now` and that
    /// `recover` would settle. Read-only.
    pub fn recoverable_attempt_count(&self, now: u64) -> Result<u64, StoreError> {
        let now = sql_time(now)?;
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM attempts WHERE state IN ('reserved', 'running', 'validating') \
                 AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?1",
                [now],
                |r| r.get(0),
            )?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// Outbox events not yet acknowledged by the ledger.
    pub fn outbox_pending_count(&self) -> Result<u64, StoreError> {
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM outbox WHERE exported_at IS NULL",
                [],
                |r| r.get(0),
            )?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }
}
