//! The outbox port the exporter drains. `SqliteStore` implements it by
//! delegating to the C4 API; tests may substitute a fake. The exporter holds
//! no other handle on the store: it cannot reserve, settle or run anything,
//! so an export retry cannot re-measure or charge budget.

use custodian_store::{AckOutcome, Checkpoint, OutboxEvent, SqliteStore, StoreError};

pub trait OutboxSource {
    fn pending(&self, limit: u32) -> Result<Vec<OutboxEvent>, StoreError>;
    fn event(&self, seq: u64) -> Result<Option<OutboxEvent>, StoreError>;
    /// Idempotent for the same reference; a different reference is refused.
    fn ack(&self, seq: u64, export_ref: &str, now: u64) -> Result<AckOutcome, StoreError>;
    fn latest_checkpoint(&self) -> Result<Option<Checkpoint>, StoreError>;
    /// `Err(NeedsReconcile)` when the store is older than, or diverged from,
    /// the checkpoint; the store persists the block.
    fn verify_external_checkpoint(&self, cp: &Checkpoint) -> Result<(), StoreError>;
    fn needs_reconcile(&self) -> Result<bool, StoreError>;
}

impl OutboxSource for SqliteStore {
    fn pending(&self, limit: u32) -> Result<Vec<OutboxEvent>, StoreError> {
        self.outbox_pending(limit)
    }

    fn event(&self, seq: u64) -> Result<Option<OutboxEvent>, StoreError> {
        self.outbox_event(seq)
    }

    fn ack(&self, seq: u64, export_ref: &str, now: u64) -> Result<AckOutcome, StoreError> {
        self.outbox_ack(seq, export_ref, now)
    }

    fn latest_checkpoint(&self) -> Result<Option<Checkpoint>, StoreError> {
        SqliteStore::latest_checkpoint(self)
    }

    fn verify_external_checkpoint(&self, cp: &Checkpoint) -> Result<(), StoreError> {
        SqliteStore::verify_external_checkpoint(self, cp)
    }

    fn needs_reconcile(&self) -> Result<bool, StoreError> {
        SqliteStore::needs_reconcile(self)
    }
}
