# 0053. Outbox exporter, acknowledgement protocol and reconciliation

- Status: accepted (design); implemented in `crates/custodian-ledger` (C7); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0022 makes the store outbox the producer side: events are written in the state transaction, carry
deterministic ids and a hash chain, and are acknowledged once with an `export_ref`. A failed or missing
export must never authorize disclosure. Export must not re-run measurement or charge budget.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Order | write the ledger then ack; ack then write; two-phase with a marker |
| Failure handling | bounded retry with backoff then defer; block indefinitely; drop after N failures |
| Conflicts | quarantine and keep pending; overwrite; skip silently |
| Store access | only the outbox port; the full store handle |

## Decision

1. **Ack only after a durable ledger write.** For each pending event, in sequence order: build the record,
   sign it, verify the signature with the exporter's own keyring (misconfiguration surfaces as `SelfCheck`),
   `put_new`, then `outbox_ack(seq, "ledger/<record_id>")`. The reference is deterministic, so a repeated ack
   is `AlreadyAcked`; a different reference in the store is `AckConflict` and an error.
2. **Idempotent by construction.** The record id and bytes are functions of the event. A crash between write
   and ack leaves a durable record and a pending event; the retry finds identical bytes (`Identical`), acks, and
   continues. A write whose response was lost is recovered the same way.
3. **Backoff and deferral.** Retryable backend errors (`Unavailable`, `Busy`) are retried up to
   `max_attempts` with deterministic exponential delay (`base * 2^n`, capped); a `Sleeper` is injected. After
   the budget the pass returns `Deferred { retry_after_secs }`: nothing is acked, every event stays pending, the
   store's disclosure precondition stays closed. Jitter is the scheduler's concern.
4. **Conflict, refusal and blocking.** A conflict is quarantined (ADR 0051) and the pass stops with `Blocked`;
   a refused event (`PayloadNotExportable`, `EventInconsistent`) stops the pass the same way. Later events are
   not attempted, so the ledger always holds a gap-free prefix of the outbox. Neither outcome is retried into
   success: a human reviews.
5. **Budget neutrality.** The exporter reaches the store only through `OutboxSource` (pending, event, ack,
   checkpoint, verify, needs_reconcile). It has no reserve, start, finish or retry operation, so export cannot
   run measurement or consume budget. If the store is blocked by `needs_reconcile`, the ack fails with the
   store error and is surfaced.
6. **Reconciliation.** `Exporter::reconcile` compares every outbox event with the ledger: acked-but-missing,
   present-but-unacked (crash window), and conflicting or unverifiable records. With `repair`, the first two are
   fixed by the exporter's own idempotent steps (rewrite identical bytes; ack). A conflict is never repaired
   automatically. It can append a signed `reconciliation` record with counts and an outcome
   (`consistent`, `repaired`, `divergent`).
7. **Checkpoints** are recorded by `record_store_checkpoint` and `record_registry_checkpoint` (ADR 0054).

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Drain acks only after a durable write and opens the disclosure precondition | `tests/exporter.rs::export_drains_outbox_acks_after_durable_write_and_opens_disclosure` |
| Crash between ledger write and ack recovers idempotently | `crash_between_ledger_write_and_ack_is_recovered_idempotently` |
| Crashes before write and after ack leave a consistent prefix | `crash_before_write_and_after_ack_leave_a_consistent_prefix` |
| Write landed but response lost recovers | `write_landed_but_response_lost_is_recovered_by_retry` |
| Unavailable ledger retries with backoff then defers, acks nothing, keeps disclosure closed, recovers | `ledger_unavailable_retries_with_backoff_then_defers_without_acking`, `transient_failures_within_the_retry_budget_succeed` |
| Conflicts are quarantined, the event stays pending, retries do not multiply quarantine | `export_conflict_is_quarantined_not_overwritten_and_event_stays_pending` |
| Export retries do not charge budget or create events | `export_retries_never_charge_budget_or_create_events` |
| A different ack reference is refused | `different_ack_reference_in_the_store_is_a_conflict` |
| Key rotation between retries does not quarantine the same record | `key_rotation_between_retries_does_not_quarantine_the_same_record` |
| Untrusted or out-of-purpose signing key writes nothing | `exporter_refuses_to_write_with_a_key_the_verifier_does_not_trust` |
| Reconciliation repairs unacked and missing records and never repairs conflicts | `reconcile_repairs_unacked_and_missing_and_refuses_to_repair_conflicts`, `reconciliation_record_is_idempotent_for_the_same_observation` |

## Adapter contract

`OutboxSource` is implemented for `SqliteStore` by delegation to the C4 API; any store that preserves
append, ack and checkpoint semantics can implement it.

## Failure and recovery

Ledger unavailable: defer, retry later; nothing lost. Signer unavailable: error, nothing written. Store
unavailable or blocked: error. Ledger content problems: blocked with a report; review, then supersede or
repair the producer. After a store restore, run startup check first (ADR 0054), then reconcile.

## Performance evidence plan

Export latency per event is signature plus one ledger write. Measure it separately from reserve and finish
transaction latency; never batch ahead of the durable ack to hide it.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Exporter, backoff, quarantine, reconciliation | yes | yes (synthetic) | no |
| Scheduler that runs the exporter and alerts on `Blocked` or long deferral | yes | no (C10, C12) | no |

## Consequences, migration, exit

The store has no public way to set `needs_reconcile` from export failures and this design does not add one:
an unreachable ledger defers disclosure through the precondition, which is the intended fail-closed path.

## Open risks and revisit triggers

A permanently blocked event blocks later exports by design; an operator runbook (C12) must say who reviews
and how. Revisit if blocking proves too coarse and per-event independence is wanted, which would need a
different gap-detection rule in the walker.
