# Architecture

## Design status and trust model

This is a proposed operational design, not a claim of an implemented sandbox or verified deployment. Protected synthetic data is the initial scope. Real personal data requires a separate approved governance design before ingestion.

The system assumes engine/scanner code can be buggy or malicious, agent prompts and external content are untrusted, execution can crash, and repeated aggregate queries can reveal a holdout. Custody enforces controls outside the agent and measurement kernel.

## Logical components

| Component | Responsibility |
| --- | --- |
| Agent interface | Propose plans, request authorized operations, prepare reports |
| Policy and authorization service | Validate actor, purpose, allowed identities, approval and capabilities |
| Run coordinator | Atomic budget reservations, leases, state transitions, retry/idempotency |
| Corpus store | Sealed encrypted populations, access scope, integrity and retention |
| Isolated execution worker | Enforced process/network/filesystem/resource boundary |
| Artifact validator | Bind results to plan/candidate/engine and validate measurement contracts |
| Disclosure service | Projection rules, query budget, suppression, receipt signing |
| Audit store | Append-only lifecycle/decision trail and integrity verification |

These are responsibilities, not mandatory microservices. Start with a small deployment and explicit interfaces. Choose runtime, durable store, isolation platform, key provider, and deployment topology through ADRs and failure tests. Redis, Postgres, or an AWS SDK is not required by the core contract.

## Data boundaries

Repository code and public synthetic conformance controls are distinct from operational storage. Operational storage holds protected corpora, seeds, private manifests, budget/audit ledgers, raw observations, result detail, and signing material references.

Use storage contracts for sealed corpus reads, atomic state/budget transactions, private artifact writes, and audit append. Durability, encryption, recovery, and integrity properties are requirements of an adapter; document and test them before production use.

An engine receives the authorized corpus and frozen plan only inside the worker. It receives no storage, signing, approval, or organization-wide credentials. Scanner children receive only the files/configuration they need. The orchestration control plane must not expose case bytes to the language model.

## Plan and authorization

A proposed `EvaluationPlan` binds purpose, population custody identity/version, candidate artifact digest, engine/protocol, adapter/scanner identities, activation/configuration, accounting settings, seed policy, resource limits, disclosure policy, and permitted retries.

The authorization record binds an authenticated actor, approval authority, exact plan digest, permitted operation, expiry, and reservation scope. Run count, release/query count, CPU/time/storage budgets are separate controls where needed. Reject stale authorization and changed plans; do not infer permission from a repository issue label or agent message.

## Lifecycle

The minimum run lifecycle is:

`proposed -> authorized -> reserved -> running -> validating -> completed`

Terminal failure states distinguish denied, failed, cancelled, and expired. Disclosure is a separate lifecycle: `prepared -> approved -> released`, or withheld/rejected. Completing execution does not authorize release.

Reserve budget transactionally before acquiring protected bytes. Use unique run IDs, idempotency keys, and compare-and-swap/transactional leases. Record whether a failure occurred before or after protected exposure. Once data was exposed, a crash or cancellation must not silently refund the evaluation budget. Refund rules, recovery, retry limits, and lease expiry are explicit policy.

Resuming a run must prove its exact candidate/plan/state identity and avoid double publication or duplicate budget charges. A retry is auditable; idempotency does not make a new exposure free.

## Isolation and artifact integrity

Use a worker boundary with no external egress by default, no host credentials, restricted writable scratch, least-privilege identity, bounded stdout/stderr, limits for CPU/memory/processes/storage, and timeout/process-tree cleanup. Validate archive/path/symlink behavior before materialization.

A manifest flag cannot enforce isolation. The deployment must prove its sandbox configuration and failure behavior; containers alone are not an assurance statement. Privileged or shared-host execution requires its own explicit risk decision.

Stage candidate bytes immutably; verify engine/scanner/configuration identity and candidate integrity before and after execution. Validate that results cover the authorized input roster, versions, counters, and failure states. Raw data stays private. Engine measurement logic remains in credential-eval/pii-eval, not duplicated in the custodian.

## Disclosure and receipts

Private result detail and public aggregate are different contracts. The disclosure service uses an allowlist and explicit policy version. It excludes input text, seeds, case IDs, paths, individual value hashes, raw ranges, free-form errors and sensitive configuration.

Define minimum stratum sizes, allowable dimensions, composition rules, and cumulative query/release budgets before enabling repeated public comparisons. Suppressing individual small cells is insufficient when overlapping totals reveal them. Do not add noise silently; any statistical disclosure mechanism needs a versioned policy and stated measurement consequences.

Expose an opaque population release identity or approved keyed commitment, not guessable value-level hashes. Separate internal plan/corpus digests from disclosure-safe identifiers when metadata could reveal protected details.

A receipt may bind the disclosure-safe candidate/engine/protocol identities, run scope, policy version, aggregate digest, issuer/key identifier and approved independence claims. The signer accepts only validated approved projections and is isolated from scanner/agent execution. Key rotation/revocation and offline verification are documented.

Signatures attest origin and binding. They do not prove true expectations, an independent reviewer, or scanner quality. State project-owned/custodian-declared evidence honestly.

## Audit, recovery, and retention

Use append-only audit events with integrity checkpoints stored outside the writer's control where practical. Tamper-evident logging is not tamper-proof storage. Retain actor/authorization/plan/state/budget/disclosure references without input values. Separate restricted operational metadata from safe public receipts.

Retention and deletion schedules cover corpora, observations, results, scratch, backups, and failed runs. Define recovery for crash, partial artifact write, exhausted storage, duplicate dispatch, expired authorization, and unavailable signing/store services. Fail closed on uncertainty about plan identity, authorization, or public release state.

## Acceptance

Public synthetic lifecycle controls must test concurrency, duplicate requests, budget exhaustion, crash after exposure, cancellation, malicious output, filesystem/network denial, cross-run reuse, invalid bindings, suppressed strata, signing refusal and recovery. Protected runs occur only after those controls and operational review pass. Product support decisions remain downstream.
