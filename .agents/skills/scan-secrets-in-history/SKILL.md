---
name: scan-secrets-in-history
description: Scan private-custodian's full Git history for accidentally committed real credentials, keys, seeds, or protected-corpus material, while safely triaging intentional synthetic conformance fixtures. Report-only and never prints matched plaintext.
---

# Scan secrets in history

Shared rules: [_shared/README.md](../_shared/README.md). Data rules: [_shared/data-handling.md](../_shared/data-handling.md).

Run a history-aware scanner with redaction enabled over every commit reachable from all refs, not just `HEAD`
and not just the working tree. Record tool version, rule set, and scope. Include branches, tags, and stashes
that exist.

## Triage

Every hit needs provenance-based triage. A fixture is expected only if it is under public synthetic
conformance controls and its construction is documented as synthetic or as a provider-published test value.
Shape, revocation, or location under a fixtures directory is not enough.

Look beyond classic API keys: signing/encryption key material, key-provider references, seeds, authorization
or reservation records, ledger exports, raw observations, storage paths or bucket names, environment
identifiers, and anything resembling a protected corpus or case list.

Give extra scrutiny to hits in docs, examples, CI config, logs, test output, notebooks, and assets.

## Report

Per hit: commit, path, rule ID, and one disposition:

- `verified synthetic`
- `verified public test value`
- `unclear: maintainer review`
- `needs private rotation and history remediation`

Never print or partially quote a match. This is also the check `SECURITY.md` requires before any public code
release; state clearly that it does not replace the full release gate (see `publication-readiness`).

## Do not

Rewrite history, rotate or contact anyone about a credential, open a public issue, or paste a hit into a
public channel. Escalate real exposure through the private incident route (`incident-triage`).
