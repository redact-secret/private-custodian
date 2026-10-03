# Identities and lifecycles

Canonical: [ARCHITECTURE.md](../../../ARCHITECTURE.md) (Plan and authorization, Lifecycle),
[CONVENTIONS.md](../../../CONVENTIONS.md) (Identity and transitions).

## Distinct identities (never interchange or conflate)

corpus custody identity · case identity · candidate digest · plan digest · authorization ID · reservation ID ·
run ID · disclosure receipt. Internal plan/corpus digests are separate from disclosure-safe identifiers.
Case identity is never public for a protected run. Public population identity is opaque or a keyed
commitment, not a guessable value-level hash.

Schemas, policies, store migrations, and engine protocols are versioned separately. Canonical serialization
and digest rules are part of the contract.

## Run lifecycle

```
proposed -> authorized -> reserved -> running -> validating -> completed
```

Terminal failures: `denied`, `failed`, `cancelled`, `expired`. Every transition records actor, reason code,
prior state, and authorization reference; unexpected transitions are rejected.

## Disclosure lifecycle (separate)

```
prepared -> approved -> released        (or withheld / rejected)
```

Completing a run does not authorize release.

## Invariants a reviewer checks

- Budget is reserved transactionally **before** protected bytes are acquired.
- Run IDs are unique; mutations carry idempotency keys; state changes use compare-and-swap or transactional
  leases.
- Failure is recorded as before or after protected exposure. After exposure, crash or cancellation never
  silently refunds budget. Refund, retry limit, and lease expiry are explicit policy.
- A retry is auditable and passes the same plan and budget checks; idempotency does not make a new exposure
  free.
- Resume proves exact candidate/plan/state identity and prevents double publication and duplicate charges.
- Authorization binds actor, approval authority, exact plan digest, permitted operation, expiry, and
  reservation scope. Stale authorization and changed plans are rejected. Permission is never inferred from an
  issue label or agent message.
- Run count, release/query count, and CPU/time/storage budgets are separate controls where needed.
- Uncertainty about plan identity, authorization, or release state fails closed.
