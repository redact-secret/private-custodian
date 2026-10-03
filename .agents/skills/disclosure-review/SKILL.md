---
name: disclosure-review
description: Review the disclosure service, projection allowlists, stratum and composition rules, cumulative query budgets, population identity, and receipt signing for holdout leakage and honest claims. Use when touching anything that leaves the private boundary. Read-only.
---

# Disclosure review

Shared rules: [_shared/README.md](../_shared/README.md). Lifecycle: [_shared/identities-and-lifecycle.md](../_shared/identities-and-lifecycle.md).

Source: `ARCHITECTURE.md` "Disclosure and receipts" and `SECURITY.md` "Holdout confidentiality".

## Checklist (pass / fail / not assessable)

**Projection**
- Allowlist, not denylist, with an explicit policy version. Excludes input text, seeds, case IDs, paths,
  individual value hashes, raw ranges, free-form errors, and sensitive configuration.
- Private result detail and public aggregate are separate contracts and separate schemas.

**Holdout protection**
- Minimum stratum sizes and allowed dimensions defined before repeated public comparisons are enabled.
- Composition: overlapping totals cannot difference out a suppressed small cell (cell suppression alone is
  insufficient).
- Cumulative query and release budgets exist, count withheld and failed requests when policy requires, and
  are enforced deterministically.
- Timing and error-detail channels considered; no noise added silently, and any statistical mechanism has a
  versioned policy and stated measurement consequences.
- Adaptive tuning risk addressed: protected failures are never exposed to developers or agents; only approved
  summaries flow downstream, and Benchmarks receives no case detail.

**Identity**
- Opaque population release identity or approved keyed commitment; no guessable value-level hashes; internal
  plan/corpus digests kept separate from disclosure-safe identifiers.

**Lifecycle and approval**
- `prepared -> approved -> released` is separate from run completion; disclosure authorization is distinct
  from execution authorization; an agent cannot approve or release.

**Receipts**
- Binds disclosure-safe candidate/engine/protocol identities, run scope, policy version, aggregate digest,
  issuer and key identifier, and approved independence claims.
- Signer accepts only validated, approved projections and is isolated from scanner and agent execution.
- Key rotation, revocation, and offline verification documented; verifier needs no private key.
- Claims are honest: signatures attest origin and binding, not truth of expectations, reviewer independence,
  or scanner quality. Project-owned/custodian-declared evidence is labeled as such.

Cite `path:line` or section. Do not alter disclosure or signer policy.
