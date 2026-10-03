---
name: protected-asset-sweep
description: Sweep the tracked tree, ignore rules, CI configuration, fixtures, examples, logs, and docs for protected-data leakage paths (protected corpora, seeds, ledgers, keys, raw findings, operational identifiers). Use before commits, PRs, and releases. Complements scan-secrets-in-history, which covers past commits. Report-only.
---

# Protected-asset sweep

Data rules: [_shared/data-handling.md](../_shared/data-handling.md). Report shape:
[_shared/finding-format.md](../_shared/finding-format.md).

Scope is the current tree and its configuration; use `scan-secrets-in-history` for earlier commits.

## Steps

1. **Tracked content**: look for corpus-like files, seed values, ledger or audit exports, raw observation
   or report dumps, key material, tokens, storage URIs/paths, bucket and account identifiers, hostnames of
   protected systems. Do this with a redacting scanner where available; never print a match.
2. **Tracked protected-data folders**: none may exist, regardless of repository visibility. `.gitignore` is
   only a convenience; verify tracked-ness with `git ls-files`, not by reading ignore rules. Note ignore rules
   that look inherited from another project (e.g. site/build paths) and may fail to cover this repo's real
   operational paths.
3. **Fixtures and examples**: every credential-shaped or PII-shaped value must be unmistakably synthetic or a
   documented public-test value, with provenance. Anything real-looking and unexplained is a finding.
4. **CI**: workflows, caches, artifacts, and logs must not receive protected data or signing secrets; PRs
   from forks must not reach secrets; no workflow runs a protected evaluation (`CONVENTIONS.md`).
5. **Public-output tests**: confirm outputs are tested by allowlist and that error/log fixtures prove
   redaction; no exception is granted by filename.
6. **Docs and prompts**: no deployment inventory, operational IDs, or environment-specific access details in
   docs, ADRs, issue templates, skill files, or agent memory.
7. **Model context**: nothing instructs or enables placing protected material in prompts, traces, or
   screenshots (including browser-automation tools).

Report location (`path:line`), class of asset, and disposition (`ok` / `synthetic verified` / `remove` /
`escalate`). Escalate possible real exposure through `incident-triage`; do not copy the content into the
report, a commit message, or an issue.
