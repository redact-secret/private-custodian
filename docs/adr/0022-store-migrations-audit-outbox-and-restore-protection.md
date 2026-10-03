# 0022. Store migrations, audit outbox and restore protection

- Status: accepted (design); implemented in `crates/custodian-store` (C4); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

CONVENTIONS.md says to version store migrations separately from schemas, policies and protocols. ADR 0001
(T3) says restoring a database older than the last exported checkpoint must not lower consumed budget.
ARCHITECTURE.md says terminal state, settlement and audit intent must not diverge and that an export
failure must not silently authorize disclosure. Signing and the private-ledger write belong to C7.

## Options

| Option | Criteria: refuses unknown state, detects tampering, atomic with state |
| --- | --- |
| Numbered forward-only SQL migrations with recorded SHA-256 | Explicit, reviewable, tamper-evident. Needs a rule for newer databases. |
| Ad hoc `CREATE IF NOT EXISTS` at startup | Silently reinterprets a divergent or newer schema. Rejected. |
| Down migrations | A downgrade can drop consumed-budget columns or history. Rejected. |
| Outbox row in the same transaction | Atomic with state; export retried until acknowledged. |
| Export first, then commit | A crash between them diverges the ledger from the store. Rejected. |
| Defer | Blocks C7, C9 and C12. Rejected. |

## Decision

**Migrations.** Files in `crates/custodian-store/migrations/` are numbered, contiguous from 1, forward
only, and compiled into the binary. The SHA-256 of each file's exact bytes is stored in
`schema_migrations` and re-verified on every open. Open refuses when: an applied version is unknown to
the binary (`SchemaTooNew`, never reinterpreted); a recorded checksum differs or applied versions have a
gap (`MigrationChecksum`); the file is not a custodian store (`NotAStore`, via `application_id`). All
pending migrations apply in one `BEGIN IMMEDIATE` transaction, so a failing migration leaves the previous
version intact. A released migration is never edited; fixes are new migrations. A migration may add
tables, columns and indexes; it must not delete history, lower a counter or reinterpret a column, and the
reviewer checks that.

**Audit outbox.** Each state change that must reach the ledger writes an `outbox` row in the same
transaction: budget provisioned, reservation created, attempt started, exposure recorded, terminal
state with settlement, denial, refused retry, reconciliation. Event ids are deterministic
(`terminal:<attempt>`), so redelivery is harmless. Payloads are bounded JSON with identities, digests,
counts and fixed vocabulary only: no input values, candidate or population detail (budget scopes appear
as digests). Rows are append-only except the one-time acknowledgement. Each row carries a hash chain
(`chain = SHA-256(prev chain, seq, payload digest)`) so edits and truncation are detectable.

**Acknowledgement.** C7 reads `outbox_pending`, writes a signed ledger entry, then calls `outbox_ack(seq,
export_ref, now)`. Ack is idempotent for the same reference and refuses a different one.

**Export failure cannot authorize disclosure.** A failed or missing export leaves the row pending.
`check_disclosure_precondition(attempt)` is closed unless the attempt is `completed`, settled, and its
terminal event is acknowledged, and the store is not awaiting reconciliation. It is necessary, not
sufficient: approval and disclosure policy (C8) still apply.

**Restore protection.** The private ledger records the latest `Checkpoint { seq, chain }` with each
export. At startup, and after any restore, the service calls `verify_external_checkpoint`. If the
checkpoint's event is absent or its chain value differs, the store persists `needs_reconcile`, and every
write fails with `NeedsReconcile` until an operator calls `clear_reconcile` after a reviewed
reconciliation that raises consumed budget to at least the exported figures. The block survives
restarts.

**Backup.** `backup_to` writes a consistent snapshot with `VACUUM INTO` to a new owner-only file. A
backup is data at rest with the same sensitivity as the database.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Newer, tampered or foreign schema is refused | `tests/migrations.rs::a_newer_schema_is_refused_not_reinterpreted`, `a_tampered_or_divergent_migration_is_refused`, `a_gap_in_applied_versions_is_refused`, `a_foreign_sqlite_file_is_not_adopted` |
| Migration is atomic | `tests/migrations.rs::a_failing_migration_rolls_back_completely` |
| Terminal state, settlement and export intent share one commit | `tests/outbox.rs::terminal_state_settlement_and_export_intent_share_one_commit`; invariant `terminal_attempt_has_audit_event` in `verify_invariants` |
| Ack is idempotent and never rewrites | `tests/outbox.rs::ack_is_idempotent_and_never_rewrites`, `tests/crash.rs::crash_around_ack_and_provision_and_exhaustion_denial` |
| Export failure keeps disclosure closed | `tests/outbox.rs::export_failure_keeps_disclosure_closed` |
| Outbox edits are detected | `tests/outbox.rs::outbox_chain_detects_edits` |
| A stale restore cannot silently lower consumed budget | `tests/migrations.rs::backup_is_owner_only_consistent_and_a_stale_restore_is_blocked` |

## Adapter contract

Outbox and checkpoint types (`OutboxEvent`, `Checkpoint`, `AckOutcome`) are store-neutral; C7 depends on
them, not on SQLite. Replacing the store means reproducing the same append, ack and checkpoint
semantics.

## Failure and recovery

Crash before commit: no state and no event. Crash after commit: both exist; the exporter finds the event
pending. Crash between ledger write and ack: the exporter repeats the ledger write (the ledger entry
must be idempotent on `event_id`) and acks again. Ledger unavailable: events stay pending, disclosure
stays closed, nothing is lost. Hash chain or checkpoint mismatch: fail closed.

## Performance evidence plan

Outbox append adds one row and one hash per state change; measure it inside the reserve and finish
transaction latency, not separately from them. Do not batch or defer audit writes to save latency.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Migrations, outbox, checkpoint, reconcile block | yes | yes (synthetic tests) | no |
| Signing and ledger write | yes | no (C7) | no |
| Operator reconcile procedure and runbook | yes | no (C10, C12) | no |

## Consequences, migration, exit

Because only a checkpoint held outside the database detects a stale restore, the ledger writer must
record checkpoints and the service must verify them at startup; until C7 and C12 do that, a restore is
protected only by procedure. Moving to another store requires carrying over consumed counts and
the chain head.

## Open risks and revisit triggers

An attacker with host root can rewrite both the database and the chain; the outside ledger is the
defence, and only after C7. Revisit if outbox volume makes the full-chain verification in
`verify_invariants` too slow (move to windowed verification from the last verified checkpoint).
