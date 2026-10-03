# 0073. Store migration 0003, audit events and the rotation protocol

- Status: accepted (design); implemented in `custodian-store`, `custodian-ledger` and `custodian-lifecycle`
  (C9); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

C4 fixed forward-only checksummed migrations (0001, 0002 exist) and an audit outbox exported by C7. Contamination
state must be durable, atomic with the use gates and with the audit trail, and must never reset or edit a
budget. C5 says a new reviewed population requires a new epoch and seal. ADR 0003 says a migration cannot
clear a contamination mark.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Where contamination state lives | the registry log (C5); a separate database; the runtime store |
| Schema change | edit 0001; a new table set in a new migration |
| Audit | a new ledger record kind; existing audit events through the outbox with an extended payload allowlist |
| Rotation shape | a new store operation that moves budgets; a link between two epochs plus budgets under the successor's own scope keys |
| Rotation atomicity | one distributed transaction; ordered idempotent steps, each failing closed |

## Decision

1. **Migration `0003_lifecycle.sql`** (the next number) adds `epoch_standing`, `epoch_events`,
   `epoch_rotations`, `feed_obligations`, `feed_envelopes` and `feed_deliveries`, all `STRICT`, all append-only by
   trigger except the two guarded updates (standing: monotonic by trigger; obligation: one `published_seq`
   stamp). It edits and drops nothing; budgets are untouched. Migration 0001 and 0002 files are unchanged.
2. **The runtime store holds the state**, so the use gates, the standing change, the feed obligation and the
   audit outbox event share one transaction. Absence of a standing row means unaffected.
3. **Audit through the existing outbox.** New event kinds (`epoch.standing`, `epoch.rotated`, `feed.obligation`,
   `feed.published`, `feed.delivered`) use the exporter unchanged. The ledger's payload allowlist gains seven
   keys (`actor_kind`, `retired`, `target_kind`, `successor_epoch`, `feed_sequence`, `document_digest`,
   `destination`); values stay bounded identifiers or integers. No ledger record kind, domain or schema changed.
4. **Rotation is a link, not a move.** `epoch_rotations` has one successor per epoch and one predecessor per
   epoch. The successor's budgets are provisioned with the ordinary raise-only operation under scope keys that
   digest the successor epoch; the store has no operation that lowers a limit or consumption. A budget scope for
   any epoch other than the successor is refused before anything changes.
5. **Rotation order** (each step idempotent, each state fail-closed): store retire, registry retire, link,
   budgets, registry activate (last, so the successor becomes usable only when everything else is in place).
6. **Fault injection** in the store's style: five new `FaultOp`s at the new transaction boundaries and eight
   `LifecyclePoint`s between the durable steps of the orchestration.
7. **`verify_lifecycle_invariants`** adds consistency checks (standing equals the fold of its events, every
   event and obligation has its audit event, the feed is contiguous, every stamped obligation names an
   envelope).

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Migration applies forward-only to existing databases; checksum rules unchanged | `custodian-store/tests/migrations.rs` (synthetic migration moved to version 4) |
| Old budgets unchanged by rotation; new scope key; exhausted stays exhausted | `epochs.rs::rotation_gives...`; `epoch_standing.rs::rotation_links...` |
| One successor per predecessor; successor must not be blocked; predecessor must be retired | `epoch_standing.rs::rotation_links...` |
| Crash at every new store boundary is all-or-nothing and repeatable | `epoch_standing.rs::crash_at_...` |
| Crash at every rotation step fails closed and converges | `epochs.rs::crash_at_every_rotation_boundary...` |
| Every new audit event kind exports | `feed.rs::every_new_audit_event_kind_exports...` |
| History tables cannot be edited or deleted | `epoch_standing.rs` raw-SQL assertions |
| Invariants hold after every scenario | `verify_lifecycle_invariants` calls throughout |

## Adapter contract

`SqliteStore` methods (`apply_epoch_change`, `enqueue_obligation`, `append_feed_envelope`,
`mark_feed_delivered`, `record_rotation`, reads); `ProtectedPopulations` (registry retire and activate);
`Exporter` (unchanged).

## Failure and recovery

A rollback to a backup before 0003 is a restore plus the checkpoint check (C4): a restored database that lacks
a contamination is detected by the external checkpoint, refuses writes, and makes eligibility `unknown`.
A failed migration rolls back completely (C4).

## Performance evidence plan

Gate reads are primary-key lookups. Measure the standing change and feed append transactions separately from
reserve and start.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Migration 0003, store API, audit events, invariants | yes | yes | no |
| Rotation orchestration with fault points | yes | yes | no |
| Registry rotation checkpointed in the private ledger by reviewed procedure | yes (C12) | no | no |

## Consequences, migration, exit

Existing databases gain empty tables on first open. Standing and event rows are never reinterpreted; a future
state is a new CHECK list in a new migration. The ledger allowlist change is additive (older readers reject
newer records, which is the safe direction).

## Open risks and revisit triggers

The standing table is as trustworthy as the database file and its checkpoints (C4, C7). Revisit if a second
store replaces SQLite: the gates must move with the transaction boundary or be re-proved.
