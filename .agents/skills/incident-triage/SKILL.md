---
name: incident-triage
description: Triage a suspected exposure, budget or holdout breach, isolation failure, or unauthorized release following SECURITY.md incident handling. Produces a private, containment-first assessment. Use when protected data, keys, budgets, or a released projection may be compromised.
---

# Incident triage

Data rules: [_shared/data-handling.md](../_shared/data-handling.md). Lifecycle: [_shared/identities-and-lifecycle.md](../_shared/identities-and-lifecycle.md).

Source: `SECURITY.md` "Incident handling". Keep the investigation private: never put corpus details,
operational IDs, keys, raw logs, or exploit payloads in a public issue, PR, commit message, or chat that is not
private. Do not paste suspected secret values anywhere, including this conversation.

## Order of work

1. **Contain** (recommend; act only on explicit instruction): stop affected execution and disclosure; revoke
   affected access and keys; pause the signer if a release is implicated. Containment actions on production
   systems are the user's decision.
2. **Preserve**: retain restricted audit evidence and ledgers. Never erase budget or audit history to hide a
   failed run; incidents and failed runs are retained immutably.
3. **Scope** using identities, not content: which populations (custody identity), candidates (digest), plans
   (digest), authorizations, reservations, runs, and disclosure receipts are affected; which projections were
   already released and to whom; what cumulative query budget was consumed.
4. **Classify** the boundary crossed: agent authority, authorization/plan binding, budget or race, isolation
   or egress, artifact integrity, disclosure/holdout leakage, key or signer, repository/CI leakage.
5. **Assess holdout impact**: could released aggregates or errors have revealed small cells or enabled
   adaptive tuning? Decide whether affected evidence must be marked withdrawn.
6. **Plan remediation**: key rotation/revocation, receipt invalidation, history remediation, tests that
   would have caught it (`conformance-controls`), and any policy revision, which needs explicit review.
7. **Resume criteria**: only after the relevant boundary and replay/recovery rules are validated.

Output: timeline of known facts (with sources), affected identities, boundary crossed, containment status,
open questions, and recommended next actions. Mark unknowns as unknown. Do not contact providers or
third parties, rewrite history, or publish anything.
