# Security policy

## Status and reporting

This repository is an initial design baseline. No production deployment or supported release is claimed.

Report vulnerabilities privately to a repository maintainer through an established private channel. Use GitHub private vulnerability reporting once configured. Do not put private corpus details, operational IDs, keys, raw logs, or exploit payloads involving protected data in public issues. Before publication, maintainers must document a verified reporting route and incident owner. Response timelines are not yet guaranteed.

Use a minimal synthetic reproduction with affected revision, boundary crossed, and preconditions. Do not submit real PII, production logs, or real credentials.

## Assets and adversaries

Protected synthetic corpora and seeds, authorization records, frozen candidates, budgets, private observations, audit state, signing keys, and disclosure policy are security assets. Threats include untrusted agents, malicious scanners, compromised dependencies, unauthorized operators, repeated adaptive evaluation, accidental publication, and crash/retry races.

Private repository access is not the security boundary for operational data. A future public release of code must not disclose that data or permit protected execution.

## Mandatory boundaries

- Never commit protected corpora, seeds, runtime ledgers, raw findings, signing keys, access tokens, or sensitive storage paths to source control.
- Keep these assets out of ordinary CI logs, artifacts, caches, screenshots, model prompts and tracing.
- Give agents neither direct protected-store reads nor signing/approval credentials. Deterministic services enforce access, plan binding and budgets.
- Separate proposal, execution authorization and disclosure authorization. Agents cannot approve their own work.
- Freeze exact candidate/engine/scanner/configuration identities and reject mutations or stale observations.
- Reserve budgets atomically; crash, timeout and retry rules account for data exposure and cumulative queries.
- Enforce worker isolation, bounded resources, no default external egress and least-privilege mounts/identity.
- Validate schema and provenance before any result is accepted. Public release uses allowlisted fields and a separate approval policy.

## Holdout confidentiality

An aggregate can leak information through small groups, overlapping queries, timing, detailed errors, or repeated candidate tuning. Use policy-controlled strata and cumulative disclosure budgets; record all queries, including withheld/failed requests when policy requires it. Do not expose raw fingerprints or per-case identifiers as substitutes for plaintext protection.

Agents and developers must not tune against protected failures. Only approved summaries are available downstream. A public conformance control is not private holdout evidence and cannot establish independence.

## Keys, stores, and cleanup

Use separate access scopes for corpus encryption, operational storage, authorization, and receipt signing. Keep key material in an approved runtime provider; define rotation, revocation, access audit and recovery. The public verifier must not need a private key.

Temporary file deletion is cleanup, not guaranteed secure erasure on every storage medium. Reduce persistence, control mounts and backups, and use encryption/key lifecycle where required. Test retention and deletion behavior, including failed runs and snapshots.

## Incident handling

On suspected exposure, stop affected execution/disclosure, preserve restricted audit evidence, revoke affected access/keys, identify released projections and impacted plans, and coordinate private investigation. Do not erase the budget/audit history to hide a failed run. Resume only after the relevant boundary and replay/recovery rules are validated.

## Public release gate

Review all history and release assets; configure private reporting; choose a license; demonstrate isolation, concurrency/budget recovery and disclosure tests; document limitations and key verification. Keep deployment inventories and protected operational state outside the public repository. Source publication does not change authorized data use.
