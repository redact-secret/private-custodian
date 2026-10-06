# 0144. EC2 attempt fencing, uncertain-outcome recovery and independent janitor

- Status: proposed; offline logic and deterministic synthetic crash matrix implemented in
  `crates/custodian-worker-ec2`; no live host, no AWS client, no actual remote crash/restart evidence,
  worker and control-plane NO-GO unchanged
- Date: 2026-10-06
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions
  are project-maintained, not independent validation.
- Tracking: issue #44 under epic #40; builds on ADR 0142 (fresh instance per attempt) and ADR 0143
  (adapter boundary); coordinates #56 (resource exhaustion) and #72

## Context

PR #62 proves SQLite attempt/lease settlement controls but not VM identity correlation or remote
fencing. With EC2 (ADR 0142) a lost run response, a coordinator crash or a retry could deliver protected
inputs to two instances, accept a stale or foreign result, refund a run whose inputs were exposed, or leave
a billable instance running. The worker and provider tokens are not authority.

## Options

1. Trust coordinator in-process state and the worker's own shutdown. Rejected: lost on crash, and depends on
   worker honesty.
2. Stop/start (or hibernate) and reuse instances. Not selected by ADR 0142; stopping alone does not prove
   data cleanup.
3. Write-ahead mapping, single live fence owner, monotonic exposure, verified terminate, and a janitor that
   needs only the provider's owned inventory and the custodian store. Chosen.
4. Defer. Rejected: blocks #44 acceptance.

## Decision

- Write-ahead mapping: the attempt record (execution, attempt, fence, token, pins) is durable before any
  provider call (ADR 0143). The launch token is derived from the full attempt identity, so a provider
  launch is idempotent per attempt; the instance id is recorded after create and recovered by token.
- Single live-fence owner: per execution, fences strictly increase (a non-increasing fence is
  `StaleFence`), and a new attempt is refused (`FenceHeld`) until every earlier attempt is `terminated`,
  meaning termination was verified. Same attempt with a different binding or pins is `Conflict`.
- Ambiguous, duplicate and stale delivery are rejected: `Ambiguous` (lost launch response) never receives
  input; a token answering to two instances is `ProviderError::Ambiguous` and is never adopted; delivery
  and collection require a current lease and a describe of the exact recorded instance (token, AMI,
  manifest, `Running`); a result envelope must carry the durable binding, so another attempt's or a
  delayed writer's result is refused; a result for a cancelled or closed attempt is refused by phase.
- Exposure is monotonic: `exposed` is written durably with `Delivering`, before the first byte is sent,
  and is never cleared (`is_exposed` also derives it from phase). Exposed uncertainty (lost send response,
  crash after send start, cancellation, janitor closure, failed terminate) stays `ExposedConsumed`.
  `Outcome` is deterministic: `ResultAccepted` (at most once, byte-identical replays idempotent),
  `ExposedConsumed`, `NotExposed`, or `Open`. This crate never refunds and exposes no refund API;
  `NotExposed` only states that no input reached any instance, leaving release to the ledger policy
  (PR #62 store). Charging is keyed per attempt, so replays, restarts and janitor sweeps cannot double
  charge; a retry is a new attempt with a new fence and instance.
- Cancellation is verified terminate then `Outcome`; it never converts an exposed run into a refund.
- Bounded lifetime and no reuse: instances are only ever terminated, never stopped, suspended or reused. The
  janitor enforces `max_lifetime_secs` on provider-reported launch time, independent of coordinator
  liveness, so billable lifetime is at most max lifetime plus the sweep interval (the interval and the
  numeric maximum are plan inputs, unmeasured).
- Verified terminate: `terminate` calls the provider and then `describe`; only `Terminated` closes the
  attempt. A failed call or a provider that claims success but leaves the instance running leaves the
  attempt open (`TerminateUnverified`) and is retried by the janitor.
- Independent janitor (`Janitor::sweep(now)`): inputs are only `Provider::list_owned` (exact inventory by
  ownership tag, never name or prefix) and the attempt store; it ignores gates, results, the worker and
  transport tokens, delivers nothing, and only terminates. It terminates owned instances with no
  record (orphans), a recorded different instance or several instances for an unrecorded token
  (duplicates), instances of closed, failed, ambiguous or settled attempts, and any instance past max
  lifetime. It then closes attempts that can no longer have a live instance, preserving exposure. A
  pre-launch intent is left to its coordinator unless the janitor killed its instance. Record writes are
  compare-and-swap; a lost race is retried by the next sweep. Sweeps are idempotent.
- Selected store mapping (not built): an additive SQLite attempt table mirroring `AttemptRecord`, with
  explicit migration, `UNIQUE(execution, attempt)`, a unique partial index for one non-terminated attempt
  per execution, and version compare-and-swap.

## Security properties claimed (synthetic, project-owned)

`crates/custodian-worker-ec2/tests/crash_matrix.rs` (deterministic, in-memory) covers: coordinator loss
before intent, after intent, after create before record, lost create response, after launch, delivery
dropped before send, delivery sent with lost response, delivered before result, result present before
settlement, settled before terminate, failed terminate, lying terminate; each with fixed expected
`Outcome`, at most one delivery in total, one charge, exposure never hidden, no instance running past
max lifetime, sweep idempotence and no acceptance of a late result. Also: retry storms after lost launch
response; conflicting retries, single live fence and stale fences; delayed-writer/cross-attempt result
refusal; four racing coordinators deliver at most once; duplicate-instance tokens; cancellation before
launch, after launch and after exposure (with and without lost send response); orphan, foreign and
expired instances; hung and lying terminate; janitor-only closure followed by restart.
`tests/adapter.rs` retains the ADR 0143 controls.

## Not claimed

Remote crash/restart evidence, a real provider or ownership-tag enforcement (the double filters a
marker), real clock or eventual-consistency behavior of the provider inventory, durable store semantics
(in-memory only), the SQLite table and migration, `Gates` backed by the real `RunLedger`, janitor
deployment, IAM scope for the janitor, process-tree and local-process cleanup on the host (#43, #56),
measured cost or lifetime, or independent validation. Provider tokens and transport TTL are not authority.

## Open work for #44

Actual remote crash and restart rehearsal on an authorized synthetic account (separately authorized under
#40); the durable SQLite attempt table with migration and concurrency/partial-failure/restart tests;
real `Gates` and ledger settlement wiring against PR #62; janitor deployment on an independent schedule
and identity with an exact-tag IAM scope; host process-tree and disk cleanup evidence (#43, #56); live
orphan reconciliation evidence.
