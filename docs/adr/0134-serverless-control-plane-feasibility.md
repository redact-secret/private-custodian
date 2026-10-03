# ADR 0134: ordinary Lambda control-plane feasibility

- Status: proposed assessment; no distributed domain adapters or custody Lambda handlers implemented
- Date: 2026-10-03
- Decision owner: custody maintainer
- Tracking: #40, #46, #47

## Context and options

A successful worker VM would not migrate the daemon's concrete SQLite authority,
filesystem corpus/blob storage, long-running scheduler or isolated Unix-socket
signer. `StateStore` alone is not the replacement seam. The dependency and
transaction map is in `docs/poc/lambda-control-plane.md`.

| Option | Transactions/recovery | Signing/storage boundaries | Cost and complexity |
| --- | --- | --- | --- |
| Put current daemon and SQLite in Lambda /tmp | Ephemeral, disconnected instances; unacceptable authority | Socket and local paths do not create remote boundaries | Reject |
| Distributed adapters and separate Lambda handlers | Requires conditionally atomic reservation/leases/outbox and complete conformance port | Separate authenticated signer and versioned blobs | Possible design; unproven implementation and total cost |
| Retain single-host custody, remote worker only | Existing authoritative transactions preserved | Existing signer/storage separation retained | Smaller migration; remote worker still requires proof |
| Defer both migrations | No new authority | Current host rehearsal remains required | Recommended until worker and engine blockers resolve |

## Recommendation

NO-GO for conversion of the current custody control plane to ordinary Lambda.
This is an implementation-readiness decision, not a claim that AWS cannot support
the design. Assess the remote worker separately. Do not add an AWS dependency to
`custodian-core`, use /tmp SQLite as authority, or silently replace Ed25519 with
another signing algorithm. No production topology is selected by this assessment.

## Adapter contract and recovery requirements

Extract application-facing ports for intake/installations, approvals/activation,
atomic budget/run/queue/pipeline operations, standing/revocation, disclosure and
release/query budgets, private blobs, audit export/checkpoints and recovery.
Map every transaction and invariants before replacing concrete store calls.

DynamoDB is a candidate for conditional transactions, not an implemented store.
Reservation and deduplication must conditionally commit budget, request, attempt,
reservation and outbox together. Enforce live lease/fence conditions in every
attempt, exposure and result mutation; use strongly consistent reads where
freshness is authoritative. Account for transaction and item-size limits and
split private blobs from metadata without allowing partial blob writes to commit
an authorized success. DynamoDB client tokens have bounded retention and cannot
replace permanent domain idempotency. Failed conditional writes do not authorize
retry with a different identity or reset exhausted budgets.

S3 is a candidate blob store: immutable object versions, exact digest/length,
conditional publication, owner-scoped authorization and explicit retention.
Object storage is not the multi-row budget authority. Worker runtimes get no S3
role or signed URL that can bypass the exposure/export gate. Stage via an
authenticated coordinator only after the durable gate.

A network `SignerTransport` must authenticate caller role, bind freshness and
purpose, preserve Ed25519 domain-separated bytes, enforce bounded frames and
verify returned signatures with pinned public keys. A worker never invokes it.
Keep signer permission separate from request-facing intake and ledger writer.
KMS availability or an IAM role does not prove current signer semantics.

An export handler uses idempotent append-only writes, content-conflict refusal,
durable remote acknowledgement and checkpoint checks. A signing or Git timeout
leaves audit pending and blocks dispatch/disclosure as today. Scheduled recovery
runs as a distinct identity, reclaims expired leases conservatively, reconciles
orphans and pending exports, and never lowers consumed budgets. Missing blob,
unavailable signer/store, stale checkpoint and uncertain exposure fail closed.

## Evidence and performance

Existing synthetic suites exercise concurrency/deduplication, cancel races,
export acknowledgement crash/restart, daemon pipeline crashes and signer
purpose/freshness/bounds using SQLite, disposable local Git and test keys.
They establish baseline requirements, not DynamoDB, S3 or Lambda behavior.
No emulator or in-memory double will be described as distributed runtime proof.

Before a deployment decision, port these cases to candidate adapters, run parallel
invocations and injected crash windows, verify restoration/checkpoints and bound
queue/janitor liveness. Measure transaction contention, orchestration, signing,
export/checkpoint latency, blob transfer, retries and scheduled idle work. Include
all charges and retained resources, not just Lambda function duration.

## Policy and migration

No policy change, no data migration, no key or ledger activation. Legacy receipts,
spent budgets, standing, activation and revocation history remain immutable.
A future migration requires additive schema/version mapping and a reviewed
monotone import/rollback plan. Follow-up work must satisfy the complete minimum
backlog in the assessment before reconsidering this NO-GO.

The authorized live primitive experiment is recorded in [ADR 0136](0136-authorized-microvm-experiment-findings.md). Atomic AWS transactions succeeded; domain migration remains NO-GO.
