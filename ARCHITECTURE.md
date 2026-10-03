# Architecture

## Design status and trust model

This is a proposed operational design, not a claim of an implemented sandbox or verified deployment. Only a synthetic, in-memory scaffold exists (see "Chosen stack" below); nothing is deployed. Trust zones and the threat model are frozen in [ADR 0001](docs/adr/0001-trust-boundaries-and-threat-model.md). Protected synthetic data is the initial scope. Real personal data requires a separate approved governance design before ingestion.

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

These are responsibilities, not mandatory microservices. Start with a small deployment and explicit interfaces. Choose isolation platform, key provider, and remaining deployment details through ADRs and failure tests. Redis, Postgres, or an AWS SDK is not required by the core contract.

## Chosen stack (design baseline)

[ADR 0002](docs/adr/0002-implementation-stack-and-runtime-identities.md) records these choices. They are planned unless marked otherwise.

- **Rust policy/state core** (`crates/custodian-core`, std only, no I/O) holds identities, lifecycle, refund policy and the ports for authorization, corpus access, atomic budget/state, execution and disclosure. A control-service crate (`crates/custodian-service`) orders the lifecycle over those ports, and `crates/custodian-contracts` holds the versioned contracts, canonical encoding, digests and checked-in JSON Schemas ([docs/contracts.md](docs/contracts.md), ADR 0004 and 0005). Implemented: scaffold with in-memory synthetic doubles, plus the contract types and checks; no service uses them yet.
- **SQLite-first runtime store** behind the state port: run state, budgets, idempotency keys and the audit outbox in one control-service-owned database. Single host; exit by adapter. Implemented in `crates/custodian-store` (C4, [docs/state-store.md](docs/state-store.md)) with synthetic tests; not deployed.
- **Aggregate disclosure** (`crates/custodian-disclosure`, C8, [docs/disclosure.md](docs/disclosure.md), ADR 0060 to 0063): validates the complete internal record, builds a separate public projection from an explicit allowlist, applies small-cell, complementary and composition-aware suppression under a versioned policy (no perturbation), charges release and query budgets (store migration 0002), and releases only after a distinct release approval, a durable audit acknowledgement and a ledgered publication decision. Aggregate-only disclosure does not by itself guarantee privacy; residual leakage is stated. Implemented with synthetic tests; no policy is activated and nothing is deployed.
- **Signed receipts and ledger export** (`crates/custodian-ledger`, C7, [docs/ledger.md](docs/ledger.md), ADR 0050 to 0054): Ed25519 signatures over domain-separated canonical payloads, a closed ledger record layout, an idempotent outbox exporter that acks only after a durable ledger write, a conflict-aware local-repository backend, and the checkpoint startup check. Implemented with synthetic tests and test-generated keys; the private-ledger repository, signer process and key provider are not provisioned and nothing is deployed.
- **Filesystem-first protected storage** in a restricted directory behind the corpus port.
- **Restricted private-ledger repository** for signed audit exports written only by a separate ledger-writer identity. It is an outside tamper-evident copy, not the budget authority, and benchmarks cannot read it. The public review ledger is benchmark-owned and different.
- **No GitHub in measurement.** Engines run as pinned binaries in the worker; GitHub appears only in the request-facing App adapter and the ledger-writer.
- **Identities:** request-facing App, control service, runtime DB, protected storage, isolated workers, receipt signer, ledger-writer. Roles and prohibitions are in ADR 0002; ownership across repositories is in the [responsibility map](docs/responsibility-map.md).
- **Eventual publication is code only.** The database, protected storage, private ledger, corpora, keys, raw results and operational history stay private.

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

Use append-only audit events with integrity checkpoints stored outside the writer's control where practical; the private-ledger export is the first such copy. Tamper-evident logging is not tamper-proof storage. Restoring a database older than the last exported checkpoint must not lower consumed budgets: the service refuses to run until reconciled. Retain actor/authorization/plan/state/budget/disclosure references without input values. Separate restricted operational metadata from safe public receipts.

Retention and deletion schedules cover corpora, observations, results, scratch, backups, and failed runs. Define recovery for crash, partial artifact write, exhausted storage, duplicate dispatch, expired authorization, and unavailable signing/store services. Fail closed on uncertainty about plan identity, authorization, or public release state.

## Acceptance

Public synthetic lifecycle controls must test concurrency, duplicate requests, budget exhaustion, crash after exposure, cancellation, malicious output, filesystem/network denial, cross-run reuse, invalid bindings, suppressed strata, signing refusal and recovery. Protected runs occur only after those controls and operational review pass, and after the deployment prerequisites in ADR 0001 are demonstrated. Existing benchmark protected lifecycles stay authoritative until a reviewed handoff that erases no receipt and resets no exhausted budget ([ADR 0003](docs/adr/0003-legacy-protected-lifecycle-handoff.md)). Product support decisions remain downstream.

## Request edge (C3)

`crates/custodian-intake` is the request-facing App adapter (Z1): signed webhook intake with event, installation, repository and actor allowlists, delivery replay protection, fork/cross-repository/comment/workflow denial, an execution gate that requires a separate approval record, App JWT and scoped installation-token logic behind traits, and sanitized Check output. It validates and enqueues; it never evaluates. It depends on `custodian-core` and `custodian-contracts`, and holds only the request-facing App credential. Decisions and limits: [ADR 0010](docs/adr/0010-github-app-request-intake.md); operator guide: [docs/github-app.md](docs/github-app.md). Implemented as a library with in-memory doubles; no listener, durable store or live App is deployed.

## Worker boundary (C6)

`crates/custodian-worker` runs pinned engines inside a `Sandbox`: bubblewrap namespaces, a read-only root, size-capped scratch, rlimits, bounded output and process-tree cleanup on Linux, and a refusing backend that runs nothing elsewhere. A dispatcher cannot be built without a startup self-check that ran a probe inside that sandbox and recorded the verification. Identities are verified before protected input access and again after staging and after execution; `record_exposure` is committed before the corpus opens; worker output is a strict bounded document mapped to `ExecutionOutcome`, and a crash is never clean. Decisions: ADR 0040 to 0042. Supported deployment and the list of what is not claimed: [docs/worker-isolation.md](docs/worker-isolation.md). Implemented against synthetic data; nothing is deployed and no production host has been proven.

