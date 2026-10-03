---
name: owasp-review
description: Review private-custodian's control plane, worker, validator, disclosure, and agent surfaces against applicable OWASP guidance (ASVS, API Top 10, LLM Top 10) and the repository's trust model. Use for secure-design reviews. Read-only.
---

# OWASP review

Shared rules: [_shared/README.md](../_shared/README.md). Report shape: [_shared/finding-format.md](../_shared/finding-format.md).

Start from `ARCHITECTURE.md`, `SECURITY.md`, `CONVENTIONS.md`, then the scoped implementation, schemas, and
ADRs. The threat model assumes: buggy or malicious engine/scanner code, untrusted agent prompts and external
content, crashes, and repeated adaptive queries.

## Control areas to assess

| Area | Look for |
| --- | --- |
| Authentication / authorization | Authenticated actor, exact plan-digest binding, expiry, scope; no permission inferred from labels or messages; proposal, execution, and disclosure approval separated |
| Access control (BOLA/BFLA) | Per-population and per-operation scope; agent cannot read the store or call signing/approval |
| Business-logic abuse | Budget bypass via retries, cancellation, duplicate dispatch, parallel requests; adaptive tuning through repeated queries |
| Injection / unsafe execution | Structured argv, allowlisted engine/scanner paths, no shell interpolation; archive, path, symlink handling |
| Deserialization / validation | Strict schemas, unknown/duplicate keys, canonical serialization, validation before consumption |
| Cryptography / keys | Key scopes separated (corpus, store, authorization, signing); rotation, revocation, offline verification; no private key needed to verify |
| Data exposure | Logs, errors, traces, CI artifacts, caches; allowlisted disclosure fields; timing and error-detail leakage |
| SSRF / egress | Worker has no default egress; any fetch is scheme/host/size/timeout/redirect-controlled |
| Resource consumption | CPU/memory/process/storage/stdout limits, timeouts, process-tree cleanup |
| Logging and audit | Append-only, integrity checkpoints, fixed reason codes, no input values |
| LLM-specific | Prompt injection through scanner output or reports, excessive agency, sensitive disclosure to the model, insecure tool design |
| Supply chain / CI | Pinned actions, least-privilege tokens, no protected data in CI |

Report each applicable control as `pass`, `fail`, or `not assessable` with file/line evidence. Many controls
will be `not assessable` until implementation ships; say which artifact is missing.

Do not edit code or policy, and do not judge scanner detection quality.
