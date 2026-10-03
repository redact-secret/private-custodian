# 0021. Budget accounting, run state, leases and recovery policy

- Status: accepted (design); implemented in `crates/custodian-store` (C4); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ARCHITECTURE.md requires "refund rules, recovery, retry limits, and lease expiry" to be explicit policy,
not code defaults. ADR 0003 keeps two legacy budget semantics distinct (holdout per population epoch,
blind per candidate lineage per epoch). C2 fixed `Reservation::settled_state` as the only refund
implementation and made time an integer supplied by callers. A repeated aggregate query can reveal a
holdout, so a hidden reset, a free retry or an implicit refund after exposure is a disclosure failure,
not an accounting nicety.

## Options

| Option | Criteria: no free exposure, no double charge, explainable audit |
| --- | --- |
| Charge at reservation, settle once to consumed or refunded | One counter move at the moment of decision; a crash leaves the units held, never free. Settlement is a single audited step. |
| Charge at completion | A crash between exposure and completion leaves the budget untouched: a free exposure. Rejected. |
| Charge at exposure | Needs a second write on the exposure path and still leaves a gap between reservation and exposure for concurrent requests to overbook. Rejected. |
| Automatic free retry after failure | Restores budget after possible exposure. Rejected (ARCHITECTURE.md, SECURITY.md). |
| Defer | Blocks C6 and C7. Rejected. |

## Decision

**Charge at reservation.** `reserve` checks `limit - held - consumed >= units` and increments `held` in
the same transaction that records the request, approval, reservation and `proposed -> authorized ->
reserved`. The budget row's `CHECK (held + consumed <= limit)` makes over-commit unrepresentable.

**Budget identity.** The budget key is a digest of the kind and the canonical `BudgetScope`. A blind
`CandidateLineageEpoch` scope contains the lineage, so a new candidate digest in the same lineage maps to
the same budget and gets no fresh units. A holdout `PopulationEpoch` scope is per population epoch.
Limits are provisioned explicitly; an unprovisioned scope denies. A limit can be raised but never lowered,
consumption is never reset, and raising is an outbox event. Restoring budget is a reviewed policy
revision outside this store.

**Settlement.** A reservation settles exactly once, in the transaction that makes the attempt terminal, to
`Consumed` or `Refunded`, by calling `Reservation::settled_state(exposure, outcome)`. The store has no
other refund path. The schema forbids `refunded` with `exposed`.

**Exposure is write-ahead.** The worker records exposure (`record_exposure`) and the store commits it
before protected bytes are opened. After that commit no outcome refunds the reservation.

**Uncertain is consumed.** The store cannot know what a worker did. Therefore:
- cancellation of a `running` attempt presumes exposure: cancelled, consumed, lease fenced;
- a `running` or `validating` attempt whose lease lapsed is `failed` with presumed exposure: consumed,
  lease fenced, never retried automatically;
- only an attempt that never reached `running` (reserved and unstarted, or cancelled or failed before
  start) is refunded, because no code path can have acquired bytes;
- a failure reported by the live lease holder with exposure still unrecorded (for example the corpus
  could not be opened) is refunded, which relies on the write-ahead rule above.

**Leases.** A lease is a compare-and-swap on the attempt: owner, a fencing token that increases on every
take, and an expiry. `start` is valid only from `reserved`, so a duplicate start is refused and nothing
executes twice. Every holder call presents owner and token; cancellation, recovery and terminal fencing
bump the token so a stale holder is rejected even if its clock says the lease is valid. A reservation that
is not started within its window lapses; `start` after the window is refused.

**Retries.** A retry is a new attempt (`attempt_no + 1`) with its own reservation. It is allowed only from
`failed` or `expired`, up to `max_retries`, re-runs the approval and activation checks, and charges the
budget again. Naming the attempt being retried makes a duplicate delivery find the attempt already
created. A refused retry (budget, count, binding) creates no attempt and is audited. No retry is free;
an earlier exposure stays consumed.

**Denial is recorded.** Budget exhaustion on a first request records a `denied` attempt and an outbox
event, and a replay of the same key returns the same denial. Binding failures (wrong plan, stale
activation, expired approval) are rejected before any write.

**Terminal reason for a lapsed reservation** is `authorization_expired` (the closest fixed code; adding a
reason code is a core change deferred to a reviewed revision).

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Duplicate delivery neither charges nor executes twice | `tests/lifecycle.rs::duplicate_delivery_neither_charges_nor_executes_twice`, `tests/concurrency.rs::concurrent_duplicate_delivery_charges_once`, `concurrent_start_lets_exactly_one_worker_execute` |
| Blind budget is per lineage, not per candidate digest | `tests/lifecycle.rs::blind_budget_is_per_lineage_not_per_candidate_digest` |
| Refund only per `settled_state`; presumed exposure consumes | `tests/lifecycle.rs::refund_follows_settled_state_only`, `recovery_policy_expired_reservation_refunds_and_lapsed_run_consumes` |
| Crash at every state boundary: no lost settlement, no double charge, no implicit refund | `tests/crash.rs::crash_at_every_boundary_recovers_without_loss_double_charge_or_refund` and the cancel, retry, recovery and ack crash tests |
| No limit lowering or consumption reset | `tests/lifecycle.rs::budget_provisioning_never_shrinks_or_resets`, `tests/isolation.rs::database_constraints_hold_even_if_the_code_were_wrong` |
| Retries re-pass the same checks and charge again | `tests/lifecycle.rs::retries_are_new_attempts_that_charge_again`, `retry_passes_the_same_budget_and_approval_checks` |
| Lease loss and fencing | `tests/lifecycle.rs::lease_expiry_renewal_and_loss`, `refund_follows_settled_state_only` (cancel case) |

## Adapter contract

The transition table is `RunState::can_transition` in `custodian-core`; the store adds no transition of
its own and calls it before every state change. `Running -> Validating` additionally requires recorded
exposure, and `Success` requires `Validating`.

## Failure and recovery

`recover(actor, now)` sweeps lapsed attempts, each in its own transaction, so a crash during recovery is
resumed by running it again. Reserved and lapsed: `expired`, refunded. Running or validating and lapsed:
`failed`, presumed exposure, consumed. Recovery never starts, resumes or retries work.

## Performance evidence plan

Reserve and settle are single short transactions; measure p50 and p99 under N concurrent writers
separately from engine time. Do not weaken fencing or settlement to speed them up.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Policy above in `custodian-store` | yes | yes (synthetic tests) | no |
| Recovery scheduler (who calls `recover`, how often) | yes | no (C6, C10) | no |
| Release/query budgets (`BudgetKind::ReleaseQuery`) wiring | yes | schema only (C8) | no |

## Consequences, migration, exit

Changing any rule above (for example allowing refund of a presumed-exposed attempt) is a policy revision
needing a superseding ADR and a migration that never lowers consumed budget. Migrating a legacy lifecycle
carries consumed counts over and erases no receipt (ADR 0003).

## Open risks and revisit triggers

A worker that opens protected bytes without first recording exposure breaks the write-ahead rule; C6 must
enforce the order and a probe should verify it. Lease lengths versus wall limits are tuned by C6. Revisit
if a second host is introduced.
