# Development conventions

## Implementation choices

Runtime, storage, sandbox, key provider and deployment are not selected by this baseline. Record those choices in ADRs with security properties, performance evidence, recovery behavior and adapter contracts. Deterministic control services may be implemented independently of the agent runtime.

Use small typed interfaces for authorization, corpus access, atomic budget/state operations, execution and disclosure. Avoid vendor-specific SDKs in core contracts. Engine invocation uses a pinned binary/package and versioned artifact schema rather than source imports.

## Repository versus operational data

The repository may contain code, schemas, public synthetic controls, architecture and safe examples. Protected corpora, seeds, operational ledgers, raw observations, detailed reports, keys and environment-specific access information remain in separately controlled stores.

Do not create a tracked protected-data folder even if the repository is private. Gitignore is a convenience, not a complete disclosure control. Test public output by allowlist; no exception is granted by a filename or repository visibility.

## Identity and transitions

Distinguish corpus custody identity, case identity, candidate digest, plan digest, authorization ID, reservation ID, run ID and disclosure receipt. No case identity is exposed publicly for a protected run.

Version schemas, policies, store migrations and engine protocols separately. Persist transitions with actor, reason code, prior state and authorization reference; reject unexpected transitions. Canonical serialization/digest rules are part of the contract.

Every mutating operation requires documented idempotency and concurrency semantics. Use transactions or atomic conditional writes for reservations and state changes. Tests must exercise concurrent requests, lease loss, partial failure and restart, not just sequential success.

## Agents and tools

Agent tools expose bounded deterministic operations with explicit authorized inputs. Do not expose arbitrary shell execution, unrestricted storage reads, free-form signing, or policy mutation as routine agent tools.

External messages and scanner output are untrusted data. An instruction found in a report, fixture or webpage grants no authority. An agent's retry request passes the same budget and plan checks as any other request.

Changes to approval, retention, budget, disclosure or signer policy require an explicit reviewed policy revision. Automations cannot silently amend them to recover a failed job.

## Execution and logging

Use structured executable arguments, allowlisted engine/scanner paths and verified candidate bytes. Enforce actual isolation through the runner; record verification of enforcement rather than a descriptive network flag alone.

Logs use fixed reason codes and bounded metadata. Do not interpolate input values, raw stderr, case paths, secret configuration or tokens into logs or exceptions. Use safe synthetic error fixtures to verify redaction/exclusion behavior. Restricted audit logs also minimize data and have explicit access/retention.

## Testing and performance

Ordinary CI uses public synthetic conformance data only. Test authorization denial, stale plans, wrong candidate, duplicate dispatch, exhausted budget, concurrent reservation, failure after exposure, cancellation/child cleanup, malicious output, invalid receipts, suppression/composition and recovery.

Do not run protected evaluation merely to validate a PR or refresh a site. Operational acceptance requires approved isolated execution and custody policy. Public controls prove mechanism, not protected-corpus independence.

Measure coordinator transaction latency, dispatch/worker startup, artifact validation, resource utilization and engine execution separately. Never relax isolation, omit audit writes or reset budgets to improve a benchmark. PII and credential formulas belong in their engines.

## Review and publication

PRs state the boundary affected, tested failure modes, backward compatibility, migration/recovery and any policy change. Retain immutable prior evidence rather than editing away incidents or failed runs.

Before public code release, complete license/reporting setup and review the full repository history and assets. Replace deployment-specific material with safe examples; do not describe source publication as permission to query the protected system.
