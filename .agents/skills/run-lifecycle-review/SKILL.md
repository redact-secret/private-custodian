---
name: run-lifecycle-review
description: Review plan binding, authorization, atomic budget reservation, state transitions, idempotency, crash/retry recovery, and audit for the run coordinator and related stores. Use when touching or designing anything that changes run, budget, or audit state. Read-only.
---

# Run lifecycle review

Reference: [_shared/identities-and-lifecycle.md](../_shared/identities-and-lifecycle.md). Report shape:
[_shared/finding-format.md](../_shared/finding-format.md).

Read the `Plan and authorization`, `Lifecycle`, and `Audit, recovery, and retention` sections of
`ARCHITECTURE.md` and `Identity and transitions` in `CONVENTIONS.md`, then the scoped code, schemas, and ADRs.

## Checklist (verdict each: pass / fail / not assessable)

**Plan and authorization**
- `EvaluationPlan` binds purpose, population custody identity/version, candidate digest, engine/protocol,
  adapter/scanner identities, configuration, accounting, seed policy, resource limits, disclosure policy,
  permitted retries.
- Authorization binds actor, approval authority, exact plan digest, operation, expiry, reservation scope;
  stale authorization and any changed plan are rejected; proposer cannot be the approver.
- Canonical serialization and digest rules are specified and tested; identities are never conflated.

**Budget and state**
- Reservation is transactional and happens before protected bytes are acquired.
- Unique run IDs, idempotency keys, compare-and-swap or transactional leases on every mutating operation;
  concurrency semantics documented.
- Transition table is explicit; unexpected transitions rejected; each transition persists actor, reason code,
  prior state, authorization reference.
- Exposure is recorded (before/after). No silent refund after exposure; refund, retry limit, and lease expiry
  are explicit policy, not code defaults.

**Recovery**
- Crash, partial artifact write, exhausted storage, duplicate dispatch, expired authorization, unavailable
  signing/store each have a defined, tested outcome. Uncertainty fails closed.
- Resume proves exact candidate/plan/state identity; no double publication, no duplicate charge. A retry is
  auditable and re-checked.

**Audit**
- Append-only events with integrity checkpoints outside the writer's control where practical; stored refs
  (actor, authorization, plan, state, budget, disclosure) contain no input values; restricted metadata is
  separate from public receipts.
- Retention and deletion cover corpora, observations, results, scratch, backups, and failed runs; incidents
  and failed runs are retained, not edited away.

Cite `path:line` or section. Do not change approval, retention, budget, or signer policy.
