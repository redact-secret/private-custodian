---
name: dependency-audit
description: Audit private-custodian's control-plane, worker, adapter, and tooling dependencies for known vulnerabilities and supply-chain risk, weighted by trust boundary. Use for dependency or supply-chain audits. Report-only unless fixes are requested.
---

# Dependency audit

Shared rules: [_shared/README.md](../_shared/README.md). Report shape: [_shared/finding-format.md](../_shared/finding-format.md).

Inventory real manifests and lockfiles first. Runtime, store, sandbox, and key provider are not selected by the
baseline (`CONVENTIONS.md`), so do not assume npm, Cargo, Go, or Python tooling exists. If no manifest exists,
report `not assessable` and stop.

## Steps

1. Detect ecosystems from the tree. Run each ecosystem's native locked-graph audit and record tool and
   advisory-database versions and the repository revision.
2. Classify every dependency by the boundary it sits on:
   - **signing / key / auth**: receipt signer, key provider SDK, token or crypto libraries;
   - **state / budget**: durable-store clients, transaction and lease libraries;
   - **isolation**: sandbox, container, process-supervision, archive, and path libraries;
   - **artifact validation**: schema, serialization, canonical-digest, YAML/JSON parsers;
   - **disclosure**: projection, statistics, and serialization code;
   - **agent interface**: tool-server and model-client libraries;
   - **dev / CI only**.
3. Prioritize libraries that parse untrusted engine or scanner output, extract archives, materialize paths,
   or sign data; and anything that executes in the worker or sees the corpus.
4. For each advisory report: locked version, affected capability, reachability from engine/scanner output or
   agent input, severity, and a compatible remediation.
5. Inspect supply-chain hygiene: unpinned or git-sourced dependencies, floating tags, unpinned CI actions,
   install scripts, missing integrity hashes, and the pinned engine binary/package (`CONVENTIONS.md`: engines
   are pinned artifacts, not source imports). Check that vendor SDKs do not leak into core contracts.

## Do not

- Treat the engine or scanner under test as a trusted dependency; it is untrusted by design.
- Upgrade or edit manifests unless asked. Do not touch lockfiles during an audit.
