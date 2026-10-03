# 0020. SQLite runtime store: crate, connection settings and dependency pins

- Status: accepted (design); implemented in `crates/custodian-store` (C4); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0002 chose a SQLite-first runtime store behind the `StateStore` port and deferred the schema,
migrations and driver to C4. The store must make "check budget, charge it, change state, write audit
intent" one atomic step, survive a crash at any point, refuse to run on a database it does not
understand, and keep the database owner-only. ADR 0001 (T3) adds that a restore of an old backup must not
lower consumed budget. The store is infrastructure: it holds identities, digests, counters and fixed
reason codes, never protected corpora, seeds, keys or raw findings.

Threat assumptions that apply: a crash or power loss at any instruction, two or more workers writing at
once, a hostile or buggy caller of the store API, an operator restoring an old file, and a second local
user on the host (ADR 0001).

## Options

| Option | Judged against: atomic multi-table commit, audited code, no server credential, pinned reproducible build |
| --- | --- |
| `rusqlite` with the `bundled` feature | Thin binding over the SQLite C amalgamation, which is built from source into the binary. One ACID commit across all tables, no server. The engine version does not depend on the host. Largest, most widely reviewed Rust SQLite binding. Adds a C compile step (`cc`). |
| `rusqlite` linking the system `libsqlite3` | Smaller build, but the engine version and compile options vary per host, which changes isolation and `STRICT` support silently. Rejected. |
| `sqlx` or `diesel` | Query layers aimed at servers and migrations by convention; larger dependency trees and async runtimes for no gain on one local file. Rejected. |
| Embedded Rust key-value stores | No SQL constraints or triggers, so "the schema refuses an over-commit" cannot be enforced below the code. Rejected. |
| Postgres | Needs a server, a network credential and operations the first deployment does not have (ADR 0002 exit path). Deferred behind the port. |
| Defer | Blocks C6, C7, C9, C10 and C12. Rejected. |

## Decision

1. **Driver.** `rusqlite = "=0.40.2"` with `features = ["bundled"]` (which pulls `libsqlite3-sys` and
   `cc` at build time; the exact transitive versions are fixed by the committed `Cargo.lock`). The
   remaining new dependencies are already pinned workspace crates: `serde_json = "=1.0.151"` and
   `sha2 = "=0.10.9"` (ADR 0004). Upgrades are deliberate, reviewed changes with `Cargo.lock`, and
   `cargo test --workspace --locked` runs in CI.
2. **Port boundary.** SQLite types and paths appear only in `custodian-store`. `custodian-core` and
   `custodian-contracts` do not depend on it. The store implements `custodian_core::ports::StateStore`
   (opaque-string identities, `Refusal(ReasonCode)` errors) and also exposes a richer contract-typed API.
3. **Connection settings**, applied on every open and verified:
   - `journal_mode = WAL` (open fails if SQLite does not report `wal`): readers see a consistent snapshot
     and are never blocked by the writer.
   - `synchronous = FULL`: a committed reservation survives power loss. Throughput is traded for
     correctness; measured separately (below).
   - `foreign_keys = ON`, `trusted_schema = OFF`, `cell_size_check = ON`, `secure_delete = ON`.
   - `busy_timeout` (default 5 s). Past it a writer returns `StoreError::Busy`, changes nothing, and maps
     to `Refusal(StoreUnavailable)`. Every mutating operation is idempotent, so the caller may retry.
   - `PRAGMA quick_check` at open; a failure refuses to open (`Corrupt`).
4. **Transactions and isolation.** Every mutating operation is exactly one `BEGIN IMMEDIATE` transaction:
   the single write lock is taken before the first read, so a check-then-write cannot race another
   writer. SQLite's isolation is serializable for writers; readers use a deferred transaction on a WAL
   snapshot. No operation holds a transaction across a call to the corpus, the executor or the network.
5. **Files.** The parent directory is created `0700` and the database `0600`; `-wal` and `-shm` inherit
   the database mode. An existing path with any group or other permission, or a symlink, is refused
   rather than silently changed, because a wider mode may mean prior exposure. Non-Unix platforms are
   refused.
6. **Schema as the last line of defence.** `CHECK` constraints and triggers make an over-committed
   budget, a refund after exposure, a shrinking budget, a second live attempt per request and edits or
   deletes of history unrepresentable even if the code were wrong. Tests bypass the API to prove it.
7. **No Git as a lock or budget authority.** The private ledger is an outside tamper-evident copy
   (ADR 0002), never consulted to decide a reservation.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Concurrent requests cannot exceed a budget | `tests/concurrency.rs::concurrent_requests_cannot_exceed_the_budget`, `exactly_one_wins_the_last_unit` |
| Reservation and state change are one atomic commit; readers never see a half-applied reservation | `tests/isolation.rs::readers_never_observe_a_half_applied_reservation`, `rolled_back_writer_leaves_no_partial_state` |
| A lock-holder stall fails closed without partial effect | `tests/isolation.rs::reader_sees_only_committed_state_and_writer_fails_closed_when_busy` |
| Schema refuses invariant violations independently of code | `tests/isolation.rs::database_constraints_hold_even_if_the_code_were_wrong` |
| Database and sidecar files are owner-only; wider modes and symlinks are refused | `tests/migrations.rs::files_and_directory_are_owner_only_and_wider_modes_are_refused` |
| Errors carry no SQL text, paths or input values | `StoreError` has fixed variants only (`crates/custodian-store/src/error.rs`) |

The database is tamper-evident at the audit layer (ADR 0022), not tamper-proof: anyone with host root can
edit the file.

## Adapter contract

`StateStore` (core) is the vendor-neutral interface. This ADR fixes how the SQLite adapter satisfies it:
`reserve` is one atomic dedupe, check, charge and transition; `transition` rejects anything outside
`RunState::can_transition`; `get` returns history with reason codes. The contract-typed API adds explicit
time, leases and settlement (see `docs/state-store.md`).

## Failure and recovery

Crash before commit: the operation leaves no trace. Crash after commit: the change is durable and the
caller redelivers; idempotency keys, deterministic event ids and compare-and-swap return the existing
result. Corruption detected at open refuses to open. Lock timeout fails closed. Disk full surfaces as a
`Database` error from the failing statement and rolls the transaction back. Details and the crash-window
list are in `docs/state-store.md`.

## Performance evidence plan

Measure coordinator transaction latency (reserve, start, finish), lock wait under contention and WAL
checkpoint time separately from worker startup and engine time. Never relax `synchronous = FULL`, skip
audit writes or reset budgets to improve a benchmark. No measurement is claimed here.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| `custodian-store` crate, pinned `rusqlite` (bundled) | yes | yes (synthetic tests) | no |
| Owner-only files, WAL, `BEGIN IMMEDIATE` | yes | yes | no |
| Production database location, backups, monitoring | yes | no | no |

## Consequences, migration, exit

Single host, single writer at a time, no high availability (ADR 0002). Adding a new driver means a new
adapter plus an explicit migration with budget carry-over; it never changes the contracts. A change of
connection settings that weakens durability or isolation needs a superseding ADR.

## Open risks and revisit triggers

Write contention if request volume grows; the bundled SQLite version must be tracked for advisories
(`cargo audit` or equivalent in C12); network filesystems are unsupported (WAL requires shared memory on
one host).
