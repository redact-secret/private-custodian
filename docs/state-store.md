# Runtime state store (C4)

Status: **implemented** in `crates/custodian-store` and tested with synthetic data only; **not deployed**.
Decisions: [ADR 0020](adr/0020-sqlite-runtime-store-and-dependency-pins.md) (driver, settings, files),
[ADR 0021](adr/0021-budget-accounting-run-state-and-recovery-policy.md) (accounting, leases, recovery),
[ADR 0022](adr/0022-store-migrations-audit-outbox-and-restore-protection.md) (migrations, outbox,
restore). This repository is maintained by the Redact Secret project; nothing here is independent
validation, and the tests prove mechanism, not protected-corpus quality.

The store holds identities, digests, counters and fixed reason codes. It never holds protected corpora,
seeds, keys, raw findings or input values, and its errors never echo them.

## Interfaces

- `custodian_core::ports::StateStore` is implemented by `SqliteStore` (opaque-string identities, one
  transaction per call). Budgets for this path are per population: `provision_port_budget`.
- The contract-typed API on `SqliteStore` takes `EvaluationRequest`, `Approval` and `ObservedActivation`
  and runs the C2 checks itself (`Approval::check_for_execution`, `Reservation::check_for_execution`)
  before it writes. Time is an integer supplied by the caller; the store has no clock except
  `StoreConfig::clock`, used only by the port adapter.

| Operation | What it does (one transaction) |
| --- | --- |
| `provision_budget(kind, scope, limit, actor, now)` | Create or raise a limit. Never lowers, never resets consumption. |
| `reserve_request(&ReserveCommand)` | Check approval and activation, dedupe by idempotency key, check and charge budget, `proposed -> authorized -> reserved`, outbox event. Replays return the existing attempt. Insufficient budget records a `denied` attempt. |
| `retry_attempt(&RetryCommand)` | New attempt after `failed` or `expired`, same checks, charged again. |
| `start_attempt(&StartCommand)` | `reserved -> running` and take the lease. Re-checks approval and reservation against fresh activation state. |
| `renew_lease(&Lease, now, secs)` | Extend a live lease. |
| `record_exposure(&Lease, actor, now)` | Write-ahead record that protected bytes may be acquired. Idempotent. |
| `begin_validation(&Lease, actor, now)` | `running -> validating`. Requires exposure. Idempotent. |
| `finish(&Lease, outcome, reason, actor, now)` | Terminal state, settlement and outbox event. Idempotent for the holder. |
| `cancel(attempt, actor, reason, now)` | From `reserved` (refund) or `running` (presumed exposure, consumed, fenced). |
| `fail_before_start(attempt, actor, reason, now)` | `reserved -> failed`, refunded. |
| `recover(actor, now)` | Settle lapsed reservations and leases (policy below). Safe to run repeatedly. |
| `outbox_pending(limit)`, `outbox_event(seq)`, `outbox_ack(seq, ref, now)` | Producer side of the audit export (for C7). |
| `latest_checkpoint()`, `verify_external_checkpoint(&Checkpoint)`, `needs_reconcile()`, `clear_reconcile(actor, now)` | Restore protection. |
| `check_disclosure_precondition(attempt)` | Closed unless completed, settled and the terminal event is exported. |
| `provision_release_budget`, `release_budget_status`, `charge_release_query`, `charge_audit_exported`, `disclosure_history`, `append_disclosure_history` | Release and query budgets and the disclosure history (C8, migration 0002, [ADR 0062](adr/0062-release-query-budgets-and-composition-accounting.md), [docs/disclosure.md](disclosure.md)). |
| `attempt`, `request_attempts`, `history`, `budget_status`, `reservation` | Reads in one WAL snapshot. |
| `verify_invariants()`, `integrity_check()`, `backup_to(dest)`, `schema_version()` | Integrity and operations. |

## Schema (migration 0001; migration 0002 adds `disclosure_charges` and `disclosure_history`, see docs/disclosure.md; migration 0003 adds the epoch standing, event, rotation and revocation-feed tables, see docs/lifecycle-and-revocation.md; migration 0004 adds the durable intake tables, submissions and the policy activation history, see ADR 0083 and docs/operator-runbook.md)

All tables are `STRICT`. History tables are append-only by trigger.

| Table | Contents |
| --- | --- |
| `meta` | `store_id`, `needs_reconcile` flag. |
| `schema_migrations` | Applied version, name, SHA-256 checksum, time. |
| `budgets` | Per scope key: limit, held, consumed, refunded. `CHECK (held + consumed <= limit)`; triggers forbid lowering the limit, consumed or refunded, and deletes. |
| `requests` | Request id, **unique idempotency key**, request digest, plan digest, scope key, units, max retries, actor, origin (`contract` or `port`). |
| `approvals` | Approval id, digest, approver, activation binding, validity window (and canonical document for contract origin). |
| `attempts` | The state machine unit and the lease: state, exposure, authorization reference, reservation id, lease owner, **fencing token**, lease expiry, version. Unique `(request, attempt_no)`; partial unique index allows one live attempt per request. Terminal rows are immutable; exposure is sticky. |
| `reservations` | Units, kind, scope key, `held`/`consumed`/`refunded`, exposure, window. Settles once; `refunded` with `exposed` is a `CHECK` violation. |
| `transitions` | Every transition and exposure record: attempt, sequence, from, to, actor, reason code, authorization reference, time. |
| `settlements` | One row per settled reservation: result, exposure, outcome, reason. |
| `outbox` | Audit export intents with payload, payload digest, hash chain, acknowledgement. |

The budget key is `SHA-256("budget-scope/v1" | kind | canonical BudgetScope)`. A blind
`CandidateLineageEpoch` scope contains the lineage, so a new candidate digest alone shares the lineage
budget.

## State machine

The table is `RunState::can_transition` in `custodian-core`; the store calls it before every change and
adds no transitions.

Happy path: `proposed -> authorized -> reserved -> running -> validating -> completed`.

Exact allowed pairs: `proposed -> authorized|denied`; `authorized -> reserved|denied|expired`;
`reserved -> running|cancelled|expired|failed`; `running -> validating|failed|cancelled`;
`validating -> completed|failed`. Terminal states (`completed`, `denied`, `failed`, `cancelled`,
`expired`) have no outgoing transition. The attempt that `reserve` creates passes through `proposed` and
`authorized` inside the reservation transaction (three transition rows). Each row records actor, reason
code, prior state and authorization reference (the approval id, or the authorization id on the port path).
Exposure is a separate row (`from == to`, reason `protected_bytes_acquired`).

Store-level rules on top of the table: `running -> validating` and `Success` require recorded exposure;
`Success` requires `validating`; `start` is valid only from `reserved`; `cancel` is not allowed from
`validating`.

## Accounting policy (written, not defaulted)

1. **Charge at reservation.** The units are held when the request is reserved. A crash can leave units
   held, never free.
2. **One settlement.** A reservation settles once, in the terminal transaction, through
   `Reservation::settled_state(exposure, outcome)`. Nothing else refunds.
3. **Refund only when no protected bytes were acquired**: cancelled or failed before start, a reservation
   window that lapsed unstarted, or a failure reported by the live lease holder before exposure was
   recorded.
4. **Uncertain is consumed.** Cancelling a running attempt, or recovering a running or validating attempt
   whose lease lapsed, presumes exposure: consumed.
5. **No automatic free retry.** A retry is a new attempt with a new reservation, charged again, subject to
   `max_retries` and to the same approval, activation and budget checks. A refused retry creates no
   attempt and is audited.
6. **No reset.** Limits only rise (audited); consumption never decreases.
7. **Write-ahead exposure.** Callers (C6) must commit `record_exposure` before opening protected bytes.

## Idempotency and concurrency

- Idempotency key (unique) maps to one request. Same key and same request digest is a replay (no charge,
  no execution, current state returned). Same key with a different request is
  `IdempotencyConflict`; the same request id under another key is `IdentityConflict`.
- Every mutating call is one `BEGIN IMMEDIATE` transaction; the lock is taken before the first read.
- Duplicate `start` is refused (`InvalidTransition`); exactly one worker holds the lease.
- A stale lease holder (expired, fenced by cancel or recovery, wrong owner or token) gets `LeaseLost`.
- `finish`, `record_exposure`, `begin_validation`, `cancel` and `fail_before_start` are idempotent so a
  caller that lost an acknowledgement can repeat them.

## Crash windows

Each window is exercised by `tests/crash.rs` (fault injection before and after each commit, then a
restart on the same file).

| # | Window | Durable result | Recovery |
| --- | --- | --- | --- |
| 1 | Before `reserve` commits | Nothing | Redelivery reserves normally |
| 2 | `reserve` committed, caller not told | Reserved, units held | Redelivery replays; if never started the window lapses: expired, refunded |
| 3 | `start` committed, lease value lost | Running | Lease lapses: failed, consumed, fenced. A restart cannot start it again |
| 4 | Started, exposure not yet recorded | Running, unexposed | Treated as possibly exposed at recovery: consumed |
| 5 | Exposure recorded, bytes opened or not | Running, exposed | Holder resumes with its lease, or lease lapses: consumed |
| 6 | Validation began | Validating | Holder resumes, or lapses: failed, consumed |
| 7 | `finish` committed, caller not told | Terminal, settled, outbox row pending | Holder repeats `finish` (idempotent); exporter sees the pending event |
| 8 | Ack lost | Event exported but still pending | Exporter repeats the idempotent ledger write and ack |
| 9 | Crash inside `recover` | Some attempts settled | Run `recover` again |
| 10 | Crash around `cancel`, `retry`, `provision_budget` | Either none or all of the call | Repeat the call; results are idempotent |

## Recovery procedure

On every start: open the store (migrations and checks run), call `verify_external_checkpoint` with the
latest checkpoint from the private ledger, run `recover(actor, now)`, then run the exporter. A lapsed
`reserved` attempt becomes `expired` and refunded; a lapsed `running` or `validating` attempt becomes
`failed` and consumed. `recover` never starts, resumes or retries work and never relaxes a check.

## Migrations

Forward-only SQL files in `crates/custodian-store/migrations/`, numbered from 1, compiled in, SHA-256
recorded and re-verified on every open. The store refuses to open when: the database has a version this
binary does not know (`SchemaTooNew`), a recorded checksum or order differs (`MigrationChecksum`), the file
is not a custodian store (`NotAStore`), or the migration list is malformed. All pending migrations apply in
one transaction. To change the schema add `000N_name.sql` and append it to `MIGRATIONS`; never edit a
released file; never drop history, lower a counter or reinterpret a column. A rollback is a restore of a
backup taken before the migration, followed by the checkpoint check below.

## Files, busy handling and isolation

- Directory `0700`, database `0600` (`-wal` and `-shm` inherit). Existing wider modes and symlinks are
  refused, not repaired. Unix only.
- WAL, `synchronous = FULL`, foreign keys on, `trusted_schema = OFF`, `quick_check` at open.
- Isolation: writers are serialized by SQLite (serializable); readers use a deferred transaction on a WAL
  snapshot and never see a half-applied reservation.
- Busy: after `busy_timeout` (default 5 s) a writer returns `StoreError::Busy`, which maps to
  `Refusal(StoreUnavailable)`. Nothing was written; retrying is safe.

## Integrity checks

`integrity_check()` runs SQLite `integrity_check` and `foreign_key_check`, then `verify_invariants()`:
budget counters equal the sum of reservations and settlements; no budget over-committed; every settled
reservation has exactly one settlement; terminal attempts are settled and live attempts hold their
reservation; no refund after exposure; transitions contiguous and consistent with attempt state; every
reservation, denial and terminal attempt has its outbox event; the outbox hash chain is intact.

## Audit outbox API (for C7)

1. `outbox_pending(limit)` returns unacknowledged events in `seq` order. Each has `event_id`,
   `kind` (`budget.provisioned`, `reservation.created`, `attempt.started`, `exposure.recorded`,
   `attempt.terminal`, `request.denied`, `retry.denied`, `store.reconciled`), bounded `payload` JSON,
   `payload_digest` and `chain`.
2. Write the signed ledger entry idempotently keyed by `event_id`.
3. `outbox_ack(seq, export_ref, now)`: `Acked` or `AlreadyAcked`; a different reference is refused.
4. Record `latest_checkpoint()` in the ledger with each export.

A failed export leaves the row pending. `check_disclosure_precondition` stays closed until the terminal
event is acknowledged.

## Backup and restore

- `backup_to(path)` writes a consistent snapshot (`VACUUM INTO`) to a new `0600` file. A backup is as
  sensitive as the database; keep it in restricted storage, including its retention.
- Test restores on a copy. After any restore call `verify_external_checkpoint`. If the restored database
  is older than the ledger (or diverged), writes are refused with `NeedsReconcile` until an operator
  reconciles consumed budget with the ledger by a reviewed procedure and calls `clear_reconcile`. The
  block persists across restarts.
- Do not copy only the main file of a live database; use `backup_to`.
- Restoring never lowers consumed budget by design. Operational runbooks and drills belong to C12.

## Tests

| Area | Evidence |
| --- | --- |
| Concurrency (real threads, file database) | `crates/custodian-store/tests/concurrency.rs` |
| Crash injection at every state boundary | `crates/custodian-store/tests/crash.rs` |
| State machine, settlement, leases, retries, exhaustion | `crates/custodian-store/tests/lifecycle.rs` |
| Transaction isolation and schema constraints | `crates/custodian-store/tests/isolation.rs` |
| Migrations, permissions, backup and stale restore | `crates/custodian-store/tests/migrations.rs` |
| Outbox, ack, disclosure precondition, chain | `crates/custodian-store/tests/outbox.rs` |
| `StateStore` port parity with the service scaffold | `crates/custodian-store/tests/port.rs` |

## Not in scope here

GitHub intake (C3), protected storage (C5), the worker sandbox and the recovery scheduler (C6), signing and
the ledger write (C7), the disclosure policy and its decisions (C8; the store only holds the release budgets and history), epoch standing, rotation and revocation (C9: migration 0003 and the use gates are in this store, see [lifecycle-and-revocation.md](lifecycle-and-revocation.md)), the operator CLI (C10: `crates/custodian-cli`; the store provides the intake ports, submissions and activation history of migration 0004),
and operational drills (C12). The store provides the primitives those issues call.
