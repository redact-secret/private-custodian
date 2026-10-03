# Boundaries

Canonical: [README.md](../../../README.md) (Responsibilities, Agent boundary), [ARCHITECTURE.md](../../../ARCHITECTURE.md)
(Logical components, Data boundaries).

## The custodian owns

Sealed population registration and permitted use; candidate/engine/adapter/scanner/configuration identity
verification; authorization and atomic budget reservation; invocation of engines inside an enforced isolation
boundary; private evidence and append-only audit; disclosure of validated projections under an explicit policy.

## The custodian does not own

| Not ours | Owner |
| --- | --- |
| Scanner-neutral ground truth, expectations, case reasoning | Corpus author/reviewer (`credential-evidence` and similar) |
| Measurement formulas (credential or PII metrics) | `credential-eval`, `pii-eval` |
| Detector tuning, scanner behavior | The scanner under test |
| Thresholds, support status, release decisions | Product qualification consumer |
| Site presentation | Benchmarks |

## Architectural tests

Apply to any change or design:

1. Would this still make sense with a different engine, scanner, runtime, store, or cloud? If it only works
   with one, it belongs in an adapter behind a typed interface, not in core contracts.
2. Is the enforcement deterministic and outside both the agent and the measurement kernel? A prompt, a
   manifest flag, a label, or a convention is not enforcement.
3. Does anything here compute a metric, rank scanners, or state support status? Then it moved into the wrong
   repository.
4. Does the model, an engine, or a scanner child receive more than it needs (storage, signing, approval,
   org-wide credentials, case bytes)?

## Agent boundary

An agent may propose a run, collect approved provenance, invoke deterministic operations under an issued
authorization, and prepare a reviewable report. It may not approve its own plan, alter a sealed corpus,
broaden access, expand a budget, sign a receipt, or bypass a disclosure rule through conversation. Agent tools
are bounded and deterministic: no arbitrary shell, unrestricted store reads, free-form signing, or policy
mutation.
