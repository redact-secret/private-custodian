# 0083. Store migration 0004: durable intake, submissions and policy activations

- Status: accepted (design); implemented in `custodian-store` and `custodian-ledger` (C10); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

C3 defined `DeliveryStore`, `InstallationRegistry` and `IntakeQueue` and shipped only in-memory doubles
(ADR 0010: "do not enable the webhook on the in-memory doubles"). C4 and C9 consume `ObservedActivation` but
no store holds activation state. The issue requires that the CLI and the GitHub App share idempotency keys and
budget accounting, and that an approval is explicit and audited. The existing contract path
(`reserve_request`) needs a request document and an approval document at the same time, so something must
hold a request between "asked for" and "approved".

## Options

| Choice | Alternatives considered |
| --- | --- |
| Durable intake | keep doubles; a second database; tables in the runtime store |
| Claim and queue atomicity | claim then enqueue as two independent commits; claim lapses if never enqueued |
| Waiting request | in-memory; a row in `requests`; a separate `submissions` table |
| Charging from the CLI | a second reservation implementation; the same `reserve_tx` |
| Activation state | a file read at use; an append-only table |
| Audit of new events | a new ledger record kind; existing audit events with four more allowlisted keys |

## Decision

**Migration `0004_intake.sql`** (forward-only, checksummed, `STRICT`, appended to `MIGRATIONS`; the
migration test's synthetic migration moves to version 5):

1. `intake_deliveries` (`delivery_id`, `claimed_at`, `enqueued`): `DeliveryStore::claim` is one
   `BEGIN IMMEDIATE` check-and-insert; of any number of concurrent claims exactly one gets `New`. A claim that
   produced a queue row is permanent (a trigger refuses to delete it). A claim that never did lapses after 300
   seconds and is handed to exactly one new claimant, so a crash between claim and enqueue cannot lose a
   delivery forever. `release` forgets only an un-enqueued claim.
2. `intake_removals`: installation and repository removals (repository id 0 = whole installation). Rows are
   never updated or deleted; there is no operation that re-enables anything.
3. `intake_queue`: identifiers only (no title, body, branch, label or comment column exists), unique per
   delivery, FIFO by sequence, states `queued`/`leased`/`done`. `enqueue` is idempotent per delivery and
   refuses at 4096 waiting items rather than evicting. The consumer side is `queue_lease` (oldest queued or
   lapsed item, fencing token rises per lease), `queue_complete` (idempotent; a stale holder gets `LeaseLost`)
   and `queue_depth`. Delivery is **at-least-once**; the consumer is idempotent because the reservation is
   keyed by the request's idempotency key.
4. `submissions`: a validated request waiting for an explicit approval, with `channel` `cli` or `app`, status
   `pending`/`approved`/`cancelled`, and `CHECK` constraints that make an approval by an agent or by the
   requester unrepresentable. It holds no budget. The only transition out of `pending` besides cancellation is
   inside `approve_submission`.
5. `policy_activations`: append-only history, one row per (activation, sequence); a trigger enforces strictly
   increasing sequences. The newest row is the current state.

**One charging path.** `SqliteStore::approve_submission` re-checks everything (self-approval, agent approver,
plan, candidate, population, budget scope, activation binding and expiry, epoch standing), reads the
activation **inside the same transaction**, then calls the `reserve_tx` that `reserve_request` calls, marks
the submission approved and appends an `approval.granted` outbox event, all in one transaction. Consequences:

* **Same idempotency.** The unit is the request's idempotency key in `requests`. If the key is already
  reserved by either path, `submit` reports `reserved_elsewhere` and records nothing, a later `approve` is
  `already_decided`, and the other path's `reserve_request` replays. Same key with a different document is
  `idempotency_conflict`.
* **Same accounting.** The same `budgets` row, the same `CHECK` (no over-commit), the same refusal to refund
  an exposed attempt. An exhausted budget is a recorded denial exactly as on the contract path.
* **Same gates.** The C9 epoch gate runs in `submit` (early) and in the reservation transaction.
* **Atomic.** A crash before commit leaves the submission pending and nothing charged; after commit the
  approval is durable and a retry is `already_decided`.

**Ledger payload allowlist.** The closed ledger layout refuses unknown payload keys (ADR 0051). The new
events reuse existing keys where they exist (`actor`, `actor_kind`, `approval_id`, `plan_digest`, `state`,
`document_digest`, `request_id`, `attempt_id`, `reason`, `at`) and add four: `requester`, `channel`,
`activation_id`, `activation_sequence`. Event kinds: `request.submitted`, `approval.granted`,
`request.cancelled`, `activation.recorded`. The layout and domains are unchanged; `tests/operator.rs::verify_walks...`
exports a store holding `request.submitted`, `approval.granted` and `activation.recorded` and walks the ledger clean.

**Retention.** Delivery claims and removals are never deleted (replay protection must not evict). Done queue
rows and decided submissions are history; pruning them is a future reviewed policy, not part of this change.

## Security properties claimed

| Property | Evidence |
| --- | --- |
| Exactly one concurrent claim wins; replay survives restart; lapsed claim recoverable | `custodian-store/tests/intake.rs` (`concurrent_claims_...`, `a_delivery_is_claimed_once_and_survives_restart`, `a_claim_that_never_produced_a_queue_row_lapses`) |
| Removal durable and irreversible | `...::removal_survives_restart_and_cannot_be_undone` |
| Queue order, at-least-once, fencing, no loss on consumer crash, bounded | `...::queue_is_fifo...`, `a_lapsed_lease_is_delivered_again...`, `a_consumer_that_crashes...`, `a_full_queue_refuses_and_never_evicts`, `queue_content_is_identifiers_only` |
| Crash injection at each new transaction boundary | `...::crash_injection_at_every_intake_boundary...`, `crash_during_approval_is_all_or_nothing` |
| Same request charges once via either path, both orders, concurrently | `...::the_same_request_charges_once_whichever_path_reserves_first`, `concurrent_approvals_of_one_submission_charge_once`, `custodian-cli/tests/edge.rs` |
| Idempotent consumer under redelivery | `custodian-cli/tests/edge.rs::the_consumer_is_idempotent_across_redelivery_of_a_lapsed_lease` |
| Activation history append-only and monotonic; stale/revoked/missing activation fails approval | `...::activation_history_is_append_only_and_monotonic`, `a_stale_or_revoked_policy_activation_fails_the_approval`, `a_missing_activation_or_an_expired_approval_fails` |
| Writes refused while awaiting reconcile; reads still work | `...::a_store_awaiting_reconcile_refuses_intake_writes_but_not_reads`, `submissions_and_approvals_are_refused_while_the_store_awaits_reconcile` |
| Invariants: approved submission has approval, attempt and audit event; queue rows have permanent claims | `integrity.rs` checks, run by `integrity_check` in the tests above |

## Adapter contract

`SqliteStore` implements `custodian_intake::ports::{DeliveryStore, InstallationRegistry, IntakeQueue}`
(fixed `IntakeReason`s; any store failure is `StoreUnavailable`/`QueueUnavailable`, so the edge fails
closed). `custodian-store` now depends on `custodian-intake` (types only; no cycle). The control plane's queue
consumer is a loop over `queue_lease` / gate / `reserve_request` / `queue_complete`; it is exercised in tests
but no daemon is shipped (unwired for deployment).

## Failure and recovery

Crash windows are the C4 windows plus: claim committed but enqueue not (claim lapses, redelivery works);
enqueue committed, consumer died (lease lapses, redelivered, idempotent charge); approval committed, caller
saw an error (retry is `already_decided`; `request status` shows the attempt). A restore from an older backup
may lose delivery claims and queue rows after its snapshot; the startup check blocks that store (ADR 0082), and
a redelivered request is harmless because reservation is keyed by idempotency key.

## Performance evidence plan

Measured separately later: claim/enqueue latency (small, one write transaction each), approval latency (one
reservation transaction plus one read).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Durable intake ports, submissions, activation history, shared charging path | yes | yes (synthetic tests) | no |
| A queue-consumer daemon, an HTTP listener, a live App | yes (C12) | no | no |

## Consequences, migration, exit

Forward-only; no down migration. A newer database is refused by this binary and vice versa (C4 rules). No
existing row is reinterpreted. Activation state previously had no home; a deployment must import its reviewed
activation(s) with `policy import-activation` before any approval can succeed.

## Open risks and revisit triggers

* `submissions.document` stores the canonical request, which contains digests and identities but no protected
  content; it is treated as restricted operational metadata like `requests.document`.
* The queue and claim tables grow without bound until a reviewed retention policy exists.
