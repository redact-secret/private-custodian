# 0082. Startup sequence, the write block and operational repair

- Status: accepted (design); implemented in `custodian-cli` and `custodian-store` (C10); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0054 says the service must call `startup_check` before it serves and after any restore, and that a store
older than the last exported checkpoint must not run. C9 added three more startup steps (registry sweep, feed
delivery, one shared eligibility) and the wiring rules (wrap every `RunLedger` in `GuardedRunLedger`, take the
feed reference from the publisher). C7 left `clear_reconcile` as a store method with the comment that
consumed budget is "raised to at least the exported figures by a reviewed procedure", but no such procedure
exists in the store: there is no operation that raises consumption, and there must not be one. The issue wants
operational repair separate from normal evaluation and a runbook that never instructs resetting a spent
budget.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Where the check runs | only in a service process; also before every state-changing CLI command |
| Bypass | a flag for emergencies; none |
| What a refusal persists | nothing; the store's write block for every refusal; the block only for refusals that make the store untrustworthy |
| Order of startup | `recover` first as C9 sketched; `startup_check` first |
| Clearing the block | an operator flag; preconditions the code verifies |
| Repair surface | any store method; a closed set of idempotent operations the service already runs |

## Decision

1. **The startup check runs before every state-changing command and before `Service::start`.** There is no
   flag, environment variable or role that skips it. A CLI process is a writer to the same database as the
   service, so a restored-old database must not be writable through the CLI either.
2. **Order:** `startup_check` (ledger walk against the pinned roots, store checkpoint, registry checkpoint) ->
   `recover` -> `EpochManager::reconcile_registry` -> `FeedPublisher::deliver_pending` -> ledger export and
   the store and registry checkpoints -> build the one `LifecycleEligibility`. The check comes before `recover`
   (this refines the C9 sketch) because `recover` writes, and an older restore must not be written to before it
   is compared with the ledger. `Service::start` is the only constructor of a `Service`; it hands out
   `eligibility()`, `guard_run_ledger()` (the only way the crate yields a `RunLedger`), `disclosure_service()`
   (built over the same eligibility object, pointer-equal in the test) and `feed_ref()`.
3. **A refusal that makes the store untrustworthy to write to persists the write block.** `StoreRolledBack`,
   `RegistryRolledBack` and `LedgerUntrusted` call the new `SqliteStore::block_for_reconcile` (a restriction
   only; idempotent; no outbox append because the outbox may be the thing in doubt). `LedgerUnavailable` does
   not: it refuses the command and changes nothing, because an outage is not evidence of a problem in the
   store. A store already blocked refuses with `store_needs_reconcile`.
4. **`repair clear-reconcile` is the only way out and is verified, not trusted.** It requires a human
   operator, the exact store id and the exact local checkpoint sequence, and the code checks: the ledger walk
   is trustworthy; the store's outbox chain contains the ledger's newest store checkpoint
   (`SqliteStore::contains_checkpoint`, a read-only comparison); the registry is not behind its checkpoint.
   If the store is behind the ledger the result is `store_behind_ledger` whatever the operator types. The
   remedy for a store that is behind is a newer copy of the database, or retiring the affected epochs so their
   budgets can never be used again (a human decision, see the runbook); it is never a command that lowers or
   edits a count. The clearing itself is audited through the existing `store.reconciled` outbox event with the
   operator as actor.
5. **The `repair` group is closed:** `recover`, `registry-sweep`, `export`, `ledger-reconcile` (re-write
   identical bytes, ack; a conflicting record is never repaired automatically), `feed-deliver`,
   `clear-reconcile`. Each is idempotent and each is an operation the service runs at startup, except the
   audited clearing. None can reset or raise a budget, edit history, or read protected content.
   `reconcile` (store, ledger, feed) is the read-only diagnosis that precedes them and is available to the
   auditor role.
6. **Fail closed on uncertainty.** An unreadable registry, an unreachable ledger, a refused signature, a
   destination holding other bytes are all fixed reason codes with exit classes 7 or 8; nothing is skipped.

## Security properties claimed

| Property | Evidence |
| --- | --- |
| Startup refusal blocks writes until an audited clear; the clear is refused when the store is behind the ledger | `tests/startup.rs::a_restored_older_store_blocks_writes_and_no_flag_can_clear_it` |
| An untrusted ledger persists the block; clearing needs exact ids, a human operator and a trustworthy ledger; the clear is audited | `tests/startup.rs::an_untrusted_ledger_persists_the_block_and_clearing_needs_exact_confirmations` |
| A ledger outage refuses and changes nothing | `tests/startup.rs::a_ledger_outage_refuses_every_mutation_and_changes_nothing` |
| `Service::start` runs the check before any write; order of the later steps | `tests/startup.rs::startup_refuses_before_writing_when_the_store_is_older_than_the_ledger`, `startup_runs_the_checks_then_recover_sweep_delivery_and_export_in_order` |
| Guarded run ledgers and the shared eligibility refuse a revoked candidate, contamination, a revoked activation | `tests/startup.rs` (`every_run_ledger_is_guarded...`, `a_contaminated_epoch...`, `a_revoked_or_superseded_activation...`) |
| `recover` refunds only unstarted reservations; an exposed lapse is consumed | `tests/operator.rs::repair_needs_the_exact_store_id...`, `an_exposed_attempt_that_lapses...` |

## Adapter contract

New store methods (read or restrict only): `store_id`, `block_for_reconcile`, `contains_checkpoint`,
`pending_submission_count`, `recoverable_attempt_count`, `outbox_pending_count`. `ActivationSource` is
implemented over the store's activation history by `StoreActivations` (ADR 0083).

## Failure and recovery

See docs/operator-runbook.md for the procedures. In short: crash -> restart, startup recovers; ledger outage
-> writes refused (exit 7), reads of the store work, nothing to repair; restore from backup -> the check
decides, a stale copy stays blocked; contamination -> `lifecycle report`, then `feed publish`; key or feed
issues -> `reconcile feed`, `repair feed-deliver`, `feed publish`.

## Performance evidence plan

The ledger walk per command is O(records). Measure it separately from store transaction latency when a real
ledger exists (C12).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Startup sequence, no-bypass check, persisted block, verified clear, closed repair group | yes | yes (synthetic tests) | no |
| A long-running service process, a real signer transport, a real feed destination | yes (C12) | no | no |

## Consequences, migration, exit

A transient ledger outage stops state-changing commands, by design; reads and verification of the store keep
working. A persisted block can only be cleared by a human after the ledger is trustworthy and the store is
at or past the ledger.

## Open risks and revisit triggers

* Whoever can write the database file as the service owner can still set or clear the flag directly; the
  checkpoint and chain make this detectable, not impossible (C4, C7).
* `block_for_reconcile` is itself a denial-of-service lever for a caller with store access; callers with that
  access already control the database.
