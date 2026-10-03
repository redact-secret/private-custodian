# 0054. External checkpoints, startup check and independent verification

- Status: accepted (design); implemented in `crates/custodian-ledger` (C7); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0022 left restore protection "by procedure only" until the ledger records checkpoints and the service
checks them at startup. ADR 0031 designates the corpus registry head as the value to checkpoint externally.
ARCHITECTURE.md requires that restoring a database older than the last exported checkpoint must not lower
consumed budgets and that the service refuse to run until reconciled.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Where | signed records in the private ledger; a separate checkpoint file; trust the database |
| What | store `(seq, chain)` and registry `(head, event_count)`; full copies; counters only |
| When | with every audit record and periodically; startup only; never |
| Failure | refuse to serve on unreachable or unverifiable ledger; serve degraded |

## Decision

1. **Checkpoints are signed ledger records.** Every audit record already carries `(seq, chain)`; the exporter
   also writes `store_checkpoint` records (for position without new events) and `registry_checkpoint`
   records `(head, event_count)` from `RegistryView::event_count` and `head`, on a schedule chosen by the
   scheduler (C10, C12) and at least after every registry change.
2. **Startup and post-restore check** (`startup_check`): walk and verify the ledger from pinned roots; refuse
   if it cannot be read (`startup_ledger_unavailable`) or has any integrity finding
   (`startup_ledger_untrusted`); refuse if the store is already blocked (`startup_store_blocked`); verify the
   newest valid `(seq, chain)` with `verify_external_checkpoint` and refuse on mismatch
   (`startup_store_rolled_back`, with the store's persisted `needs_reconcile` block); verify that the registry
   has at least the checkpointed event count and the same head at that count (`startup_registry_rolled_back`).
   Quarantine entries are reported, not blocking. The service must call it before serving and after any
   restore; there is no bypass flag. A store ahead of the ledger is normal (events not yet exported).
3. **Reconciliation after a rollback.** The store block is cleared only by `clear_reconcile` after a reviewed
   procedure that raises consumed budget to at least the figures in the ledger's audit records (the ledger
   holds the consumed units in each terminal event). The check then passes only when the store really contains
   the checkpointed chain.
4. **Independent checkpoint and backup verification.** The ledger is a Git repository: history is mutable by
   anyone with force-push, so it is a tamper-evident outside copy, not a tamper-proof archive. Procedure
   (in `docs/ledger.md`): keep a second copy of the newest checkpoint where the ledger writer and host root
   cannot change it (for example an offline note or a separately owned repository mirror updated by a different
   identity), compare it with the ledger and the store at each review, and keep the pinned root public keys out
   of the repository holding the ledger. A restored backup is verified with `startup_check` before it serves.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| A consistent store and ledger start | `tests/checkpoint.rs::startup_passes_on_a_consistent_store_and_ledger` |
| A restored older database is refused, blocked across restarts, and refused again | `restored_older_database_is_refused_and_stays_blocked` |
| A diverged database of equal length is refused | `diverged_database_with_the_same_length_is_refused` |
| An unreachable ledger refuses to serve | `unavailable_ledger_makes_the_walk_fail_closed`, `unavailable_ledger_refuses_to_serve` |
| A forged checkpoint signed by an untrusted key makes the ledger untrusted and does not poison the store | `forged_checkpoint_cannot_lower_or_raise_trust` |
| Registry rollback and divergence are detected; growth is accepted | `registry_rollback_and_divergence_are_detected` |
| A ledger behind the store is normal; first run is allowed | `a_ledger_that_is_behind_the_store_is_normal`, `first_run_with_an_empty_ledger_is_allowed_and_reports_no_checkpoint` |
| Checkpoints survive recovery: a new clone of the remote verifies and the store check passes after restart | `tests/git_backend.rs::exporter_writes_through_git_and_survives_loss_of_the_writer_clone` |

## Adapter contract

`startup_check(backend, roots, store: &dyn OutboxSource, registry: Option<&RegistryView>)` returns a
`StartupReport` or a `StartupRefusal` with a fixed code.

## Failure and recovery

Rollback: serve nothing, reconcile, re-run. Ledger unavailable at boot: do not serve. Forked or forged
ledger: treat as an incident (SECURITY.md incident handling); do not clear the store block.

## Performance evidence plan

Startup walk is linear in ledger size. Measure it with realistic record counts; if slow, walk from the last
independently confirmed checkpoint.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Checkpoint records, walker, startup check, registry check | yes | yes (synthetic) | no |
| Service wiring that calls the check before serving | yes | no (C9, C10, C12) | no |
| Independent checkpoint copy and review cadence | yes | documented only | no |

## Consequences, migration, exit

A deleted or truncated ledger tail cannot be detected from the ledger alone: the store would be ahead of the
ledger, which is also the normal state. Only the independent checkpoint copy detects it.

## Open risks and revisit triggers

An attacker with host root can rewrite the database and the exporter together; the independent copy and
off-host pinned keys are the defence and are procedural until C12. Revisit if checkpoint frequency should be
tied to budget spend rather than a schedule.
