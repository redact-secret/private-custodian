# 0062. Release and query budgets and composition accounting

- Status: accepted (design); implemented in `crates/custodian-store` (migration 0002) and
  `crates/custodian-disclosure` (C8); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

SECURITY.md: aggregates leak through repeated and adaptive queries; record all queries, including
withheld and failed ones when policy requires it. C4 created `budgets.kind = 'release_query'` in the schema
only; `reserve_request` accepts only run plans. Composition accounting needs durable memory of what past
releases revealed, updated atomically with the check.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Budget storage | reuse `reservations` and `settlements`; a new charge table with an invariant change |
| Scopes | population only; population, lineage and requester |
| Refund | refund withheld or failed attempts; never refund |
| Charge point | at request receipt; after validation, before building |
| History | in memory; in the ledger only; durable append-only table in the store |
| Concurrency | serialize all releases; conditional append with replayable charge |

## Decision

1. Migration `0002_disclosure.sql` adds append-only `disclosure_charges` (charge id, scope key, units, actor)
   and `disclosure_history` (series key, sequence, release id, payload). Release budgets reuse `budgets`
   (kind `release_query`); a charge adds to `consumed_units`; the integrity invariant
   `budget_counters_match_reservations` now also sums `disclosure_charges`, and a new check requires an outbox
   event per charge. Attempts and reservations are untouched.
2. Scopes: population epoch (and family), candidate lineage (when the plan's scope is a lineage), requester.
   A charge draws `units_per_attempt` from all applicable scopes in one transaction, all or none. Requester
   scope is a new canonical scope `{"scope":"requester","actor":...}` (`ReleaseScope::Requester`).
3. A charge is final: no refund path. The policy fields `withheld_attempts` and `failed_attempts` are
   single-valued `"charged"`. The charge is taken after the internal record validates and before anything is
   built; earlier rejections reveal nothing and are not charged.
4. Idempotent per release key (`charge_id`): a replay draws nothing. Exhaustion draws nothing and writes a
   `disclosure.denied` outbox event. Limits only rise (`provision_release_budget`); consumption never resets.
5. Each charge writes `disclosure.charged` outbox events (one per scope) within the transaction; release
   requires them acknowledged (`charge_audit_exported`). Writes are refused while `needs_reconcile` is set, so
   a restored older database cannot lower or skip charges.
6. History is per population series (the population-epoch scope key). `append_disclosure_history` is
   conditional on the sequence read; a race is `StoreError::Conflict` (`history_conflict`) and the retry
   replays the charge and recomputes against the new history. A prepared projection is recorded at prepare
   time and treated as revealed even if never released.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| All-or-nothing across scopes, final, idempotent, exhaustion audited | `store/tests/disclosure.rs::charge_is_all_or_nothing_across_scopes_and_never_refunded` |
| Concurrent charges cannot overdraw; one append wins | `store/tests/disclosure.rs::concurrent_charges_and_history_appends_cannot_overdraw_or_fork` |
| Run and release budgets are separate kinds | `store/tests/disclosure.rs::run_and_release_budgets_are_separate_kinds` |
| History is conditional, ordered and idempotent | `store/tests/disclosure.rs::history_appends_are_conditional_idempotent_and_ordered` |
| Release waits for charge audit acknowledgement | `store/tests/disclosure.rs::charge_audit_is_exported_only_after_ack`, `disclosure/tests/release.rs::pending_ledger_export_blocks_prepare_and_release` |
| Exhaustion across requester, population and lineage scopes | `release.rs::exhausted_requester_budget...`, `blind_lineage_budget_is_charged...`, `unprovisioned_budget_refuses` |
| Retry is not charged twice; a race is a conflict then a replay | `release.rs::a_retry_of_the_same_attempt_is_not_charged_twice`, `history_race_is_a_conflict_and_the_retry_replays_the_charge` |
| Invariants hold | `integrity_check()` in the store tests |

## Adapter contract

`DisclosureStore` in `custodian-disclosure`, implemented for `SqliteStore`. The store exposes
`provision_release_budget`, `release_budget_status`, `charge_release_query`, `charge_audit_exported`,
`disclosure_history`, `append_disclosure_history`.

## Failure and recovery

Crash before commit: no trace; after commit: the charge and event exist and a retry replays. Crash between
charge and history append: the charge stands, the retry recomputes and appends. A history entry that fails to
parse refuses all later releases for that series (never skipped). Restore of an older database: blocked until
reconciled (ADR 0022).

## Performance evidence plan

One write transaction per charge and per append; history is read in full per prepare, bounded by the
population budget. Measure with the budget at its maximum before raising limits.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Charge, history, audit gate | yes | yes | no |
| Provisioning from an activated policy | yes (C10) | helper only | no |
| Time-windowed or decaying budgets | no | no | no |

## Consequences, migration, exit

Migration 0002 is forward-only. The migration tests now use a synthetic migration 3. Raising a limit is a
reviewed policy revision. There is no administrative reset, by design.

## Open risks and revisit triggers

Per-requester budgets do not stop collusion across requesters; the population and lineage budgets bound the
total. Revisit with real traffic patterns and if a decaying budget is proposed (needs its own policy and ADR).
