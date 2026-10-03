---
name: scorecard-check
description: Run OpenSSF Scorecard against the private-custodian repository and turn low scores into repository-specific supply-chain actions. Report-only.
---

# Scorecard check

Shared rules: [_shared/README.md](../_shared/README.md). Report shape: [_shared/finding-format.md](../_shared/finding-format.md).

Determine the repository's real remote with `git remote -v`. The repository starts private; Scorecard may not
be able to read it. If access or a remote is missing, report `not assessable` with the reason rather than
estimating a score. Never pass a token to a third party beyond what the user authorized.

When it runs, record Scorecard version, date, repository revision, and unavailable checks.

## Interpret by this repository's risk

Inspect the evidence behind low scores: pinned CI actions, least-privilege workflow permissions, branch
protection and required review, dependency update automation, SAST and secret scanning, vulnerability
disclosure (`SECURITY.md` and private reporting route configured), and signed or provenance-bearing
release artifacts.

Weight these higher here: CI must never receive protected data or signing credentials; workflows must be
non-privileged for pull requests from forks; no workflow may run protected evaluation. Mark release-oriented
checks `not applicable` when no release mechanism exists; do not fabricate failures in an early repository.

Route dependency detail to `dependency-audit`, static findings to `sast-sweep`, history review to
`scan-secrets-in-history`, and the pre-publication decision to `publication-readiness`.

Do not change repository settings or invent scores that were not returned.
