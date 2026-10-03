---
name: boundary-review
description: Check a change, design, or document against private-custodian's ownership boundary (what the custodian owns vs engines, corpus authors, and product consumers) and its agent boundary. Use before and during any feature, schema, or doc change. Read-only.
---

# Boundary review

Reference: [_shared/boundaries.md](../_shared/boundaries.md). Shared rules: [_shared/README.md](../_shared/README.md).

Read `README.md` and `ARCHITECTURE.md`, then the diff or proposal.

## Steps

1. Name the component(s) touched from the `ARCHITECTURE.md` table (agent interface, policy/authorization, run
   coordinator, corpus store, isolated worker, artifact validator, disclosure service, audit store).
2. Run the four architectural tests in `boundaries.md` on each change.
3. Flag ownership leaks:
   - measurement formulas, metric definitions, or ranking logic (belongs in `credential-eval`/`pii-eval`);
   - ground-truth or expectation authoring (belongs to corpus author/reviewer);
   - thresholds, support status, release decisions, or site content (downstream consumers);
   - detector tuning hints derived from protected failures.
4. Flag coupling leaks: a specific runtime, store, cloud, or sandbox vendor in a core contract (Redis,
   Postgres, AWS SDK are explicitly not required by the core contract); engines imported as source rather than
   invoked as a pinned binary/package with a versioned artifact schema.
5. Flag agent-boundary leaks: any path where the model can approve, widen scope, read the store, sign, mutate
   policy, or see case bytes.
6. Check wording: nothing calls project-maintained evidence or controls independent; a public conformance
   control is never described as holdout evidence.
7. If a choice (runtime, store, isolation platform, key provider, topology) is being made implicitly, require
   an ADR (`adr-author`).

## Output

Per change: owning component, verdict (`in-boundary` / `leak` / `needs ADR`), the specific rule violated, and
where the work should live instead. Do not edit; do not decide policy.
