# 0125. Queue consumer, poison handling, scheduler and migration 0007

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The intake queue (migration 0003, ADR 0117 retention) had leases and fencing but no consumer. A consumer must
be idempotent under redelivery and crashes, bounded in retries, and must never let a poisonous message loop,
change a budget or leak its content.

## Options

1. Delete on first failure. Loses deliveries; hides outages.
2. Retry forever. A poison message blocks nothing but burns the process and the log.
3. Bounded leases with deterministic backoff and a terminal, audited set-aside state.

## Decision

Option 3. `src/consumer.rs` claims one item with a lease and a fencing token, handles it and settles it.

- **Outcomes** are recorded in `queue_outcomes` (migration 0007, additive): a settled item keeps a fixed
  reason word and never its payload. `request_links` ties an item to the request it created.
- **Terminal refusals** (an unreadable document, a repository not installed, a policy refusal) settle with a
  fixed code and have no budget effect.
- **Transient failures** (a missing document, an unavailable ledger or signer or GitHub) call `queue_defer`
  with exponential backoff, 5 s doubling to 300 s, computed from the attempt count (deterministic, testable
  with a manual clock).
- **Poison**: after `max_attempts` leases (a crash-looping item counts too, because the count is taken at
  lease time) the item is settled with the fixed reason `poison_message`, an audit event is queued, no budget
  is touched and the content is not processed again.
- **Submission** is `ExecutionGate::authorize(..., None, ...)` where `ApprovalRequired` means every other
  check passed, then `submit_request` through the App channel. The daemon never creates an approval.
- **Checks** are best effort through `CheckSink` with fixed codes; a failing sink never changes the outcome.
- **Shutdown**: a consumer stops claiming and releases (`queue_release`) what it leased.
- **Scheduler** (`src/schedule.rs`) runs, on monotonic seconds, `recover`, `reconcile_registry`,
  `deliver_pending`, `export`, `checkpoint` (export plus ledger checkpoints), `startup_check` and
  `signer_liveness`. A failed `startup_check` marks the daemon degraded: no pipeline or consumer work starts
  until it passes, and it is retried every 2 s. `Signer::liveness()` is a new default trait method; the
  remote signer probes with an unknown domain and expects `sign_unknown_domain`.

Migration 0007 is additive (new tables, new fault points, new integrity checks); no existing record is
reinterpreted.

## Security properties claimed

`tests/consumer.rs` (nine tests: idempotent redelivery, terminal refusals, exact backoff, poison, crash-loop
poison, failing check sink, shutdown, many real threads exactly once), `tests/scheduler.rs`,
`custodian-store/tests/pipeline.rs`, and the C12 crash-window coverage rule (the new fault points are
declared covered elsewhere and exercised in `tests/crash.rs`).

## Failure and recovery

A crash between claim and settle leaves a lapsed lease; the next claim redelivers it. Settlement is
write-once per item. Recovery of lapsed attempt leases settles the spend as consumed, never refunded (R-2).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Consumer, backoff, poison | yes | yes | no |
| Scheduler | yes | yes | no |

## Consequences, migration, exit

Migration 0007 is forward-only, like the earlier ones. Functional verification on public synthetic data, not
independent protected evaluation.

## Open risks and revisit triggers

Backoff constants are config-free; revisit with real GitHub rate-limit behaviour.
