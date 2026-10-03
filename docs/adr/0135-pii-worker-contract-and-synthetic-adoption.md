# 0135. PII worker contract and synthetic adoption

- Status: accepted (contract design, as requested in #37); synthetic reference adoption implemented; not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer, through the explicit #37 implementation request
- Maintenance: project-maintained decisions and evidence, not independent validation.

## Context

[Issue #37](https://github.com/redact-secret/private-custodian/issues/37),
[pii-eval PR #29](https://github.com/redact-secret/pii-eval/pull/29) and
[follow-up #30](https://github.com/redact-secret/pii-eval/issues/30) require an exact engine handoff.
The merged engine at `6157cbc5918b3888c8e84b1884719ea8f3278b36` deliberately refuses production
worker jobs. Its old synthetic example transports aggregates through scratch and stderr to a replica
validator. Neither is the custodian contract. ADR 0127 already decided embedded aggregates and implemented
receipt assembly. Engines and scanner output remain untrusted, including in the synthetic exercise.

## Options

1. Defer all integration until App/server activation. Unnecessary: artifact, CLI and synthetic isolation
   verification require neither; this does not solve the engine's contract refusal.
2. Replace the roster unit or widen aggregate denominator bounds to publish all ten metrics. Rejected:
   changes population accounting and the established disclosure contract.
3. Preserve the v1 worker and aggregates contracts, accept engine-owned packaging behind the artifact
   adapter, and verify a clearly identified reference adoption separately from the unchanged upstream CLI.

## Decision

Option 3. The exact handoff is [../pii-eval-adoption.md](../pii-eval-adoption.md).

- **Q1:** one entry is one authored case, including its variants/expectations. Custodian counts opaque
  flat entries; pii-eval owns `pii-eval-worker-entry/1`, semantic population assembly and case validation.
- **Q2:** embed `aggregates` as an object in the single `worker-result/1` stdout document, bounded as a
  whole to 64 KiB. No scratch collection, stderr transport, writable host bind or second stdout document.
  The pipeline binds canonical aggregate bytes to the receipt and validates them with `PrivateAggregates`.
- **Q3:** the case-based PII profile permits only `overall` and the nine labels listed in the handoff.
  `measurable-share` remains engine-private because its axis-assertion denominator may exceed the case
  roster. Never clamp, rescale, substitute or compute metrics here. Additional strata/labels require a
  separately reviewed disclosure policy revision. This is a contract/profile decision, **not an activated
  operational disclosure policy**. The checked test policy is synthetic only; HG-9 remains open.
- **Q4/Q9:** accept opaque single-file `pii-eval-bundle/1` archives as adapter and candidate artifacts.
  Engine = pii-eval CLI; adapter = Node shim bundle; candidate = scanner package bundle; scanner-0 = Node
  executable; config = engine-owned worker config. Custodian verifies SHA-256 of each exact file. Engine
  safely extracts into private scratch and additionally verifies its package tree and shim identities.
  Bundle digest, tree digest, semantic population digest and custody commitment remain different identities.
- **Coverage/failure:** preserve the outcome table. `complete` means `observed == expected`, including
  scanner failures with `failed > 0`. Those settle `Partial`, consume after exposure, and never release.
  Incomplete coverage uses `partial` with `observed < expected`. A full-roster failure keeps its execution
  record without an `InternalReceipt`; no schema revision or falsified roster is needed.
- **P-A:** size the explicitly approved plan for the pinned runtime, scanner and population. The existing
  512 MiB Rust fixture is not a PII profile. Use 1024 and 1536 MiB as separate synthetic x86_64 Node
  v22.23.3 profiles, with the same enforced limits and operator caps; retain 512 MiB as a negative.
  The prior measured startup boundary (>768, <=800 MiB) is evidence for that runtime/runner only, not a
  universal minimum or production headroom guarantee. RLIMIT_AS is virtual address space, not VM RAM.
- **P-B:** defer a dispatcher pre-exposure engine probe. No agreed probe invocation exists, and it would
  require a new bounded protocol, isolated scratch without a corpus mount, identity checks, timeout and
  lease/recovery tests. Do not call an untrusted runtime on the host or invoke the worker on empty
  protected input as a probe. Existing sandbox self-check remains mandatory and unchanged.
- **P-C:** accept runtime sizing evidence as **artifact-side metadata**, bound to runtime/engine/scanner
  file digests, architecture and launcher/limit profile. pii-eval should declare the tested profile and
  measured interval separately from a claimed minimum. It is approver information, not permission to raise
  a limit. No job/config freshness or minimum-memory field is added to the core protocol. Admission-time
  enforcement of a new declaration is deferred until that metadata contract is reviewed.

## Security properties claimed and adapter contract

The artifact/worker/validator/disclosure boundaries are affected. Core remains vendor-neutral; no engine
crate is imported and no measurement formula is implemented here. The reference patch is an external
engine adoption handoff, applied only while building public synthetic test artifacts. Neither the patch nor
an artifact grants authorization. `Dispatcher`, `ArtifactSources`, `Sandbox`, `ValidatedResult`, existing
pipeline assembly and `PrivateAggregates` remain the typed boundaries.

`tests/pii_engine.rs` exercises the actual dispatcher/pipeline with separately pinned upstream and adopted
CLI artifacts and real pinned Node, following the startup self-check. It covers successful assembly/release,
unchanged-engine refusal, 512 MiB failure, scanner crash, population/run-class/bundle/tree/runtime mismatches,
consumed budgets and replay. CLI `tests/artifact.rs` covers receipt/plan/content binding, missing aggregates,
wrong domain, failed counters, hostile fields, bounds and output exclusion. Existing pipeline tests cover
missing/invalid aggregates, concurrency and durable crash windows. These are project-owned synthetic tests.

## Failure and recovery

No approval, budget, retention, signer or operational disclosure policy changes. Existing write-ahead
exposure, export acknowledgement, leases and consumption rules remain authoritative. A refusal after
exposure is consumed; no reset or synthetic success is substituted. Replay uses durable pipeline artifacts,
receipts and release steps, never re-evaluates for a new aggregate. Missing/invalid artifacts close release.
Unavailable ledger/store/signer retains the established fail-closed path. No migration is required and no
prior evidence is rewritten.

## Performance evidence plan

Record source commit, patch digest and both rebuilt binary digests, Node binary digest, architecture,
launcher/kernel and explicit limits. Measure worker execution separately from build and coordinator timing.
The synthetic fixture builder is never staged as the engine. Do not treat test sizes as real-corpus growth
measurements. Repeat on the production host and ARM64/MicroVM under #40/#45 before claiming those profiles.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Custodian contract decisions and exact handoff | yes | yes | no |
| Reference engine adoption patch and pinned synthetic build | yes | yes | no |
| Actual custodian pipeline synthetic CI gate | yes | yes | no |
| pii-eval upstream adoption/released artifact | yes | no (downstream handoff) | no |
| Operational PII policy, production sizing, App/webhook activation | yes | no | no |

Executed evidence and its limits are recorded in the handoff. A workflow existing is not evidence it ran.

## Consequences, migration, exit and open risks

This accepts engine-owned formats for this adapter, not vendor-specific core contracts. Once pii-eval adopts
and publishes an identified artifact, replace the reference patch/build with that pinned artifact and verify
its provenance and binary digest. A patched binary must never inherit the upstream binary's identity.
Upstream must update its old TestOnly channel tests and status documents; an adoption patch is not a merged
upstream change. Live App provisioning and webhook activation are deferred, as are production policies,
protected inputs, operational keys/ledgers and cloud resources. Revisit for new metric units, protocols,
runtime builds, architectures or isolation backends.
