---
name: adr-author
description: Draft an Architecture Decision Record for a runtime, durable store, isolation platform, key provider, deployment topology, schema/protocol, or policy decision, with the security properties, failure tests, and recovery behavior this repository requires. Use when a choice the baseline deliberately left open is being made.
---

# ADR author

Shared rules: [_shared/README.md](../_shared/README.md). Boundary: [_shared/boundaries.md](../_shared/boundaries.md).

`CONVENTIONS.md` requires runtime, storage, sandbox, key provider, and deployment choices (some now made in ADRs
0001 to 0003, others still open) to be recorded in ADRs "with security properties, performance evidence, recovery behavior and adapter
contracts". ADRs live in `docs/adr/` (index `README.md`, template `template.md`, numbered `NNNN-title.md`; 0001 to 0003
exist). Read the index for the next number; never reuse or renumber. Open decisions and their owners are listed in
the index. Do not invent prior ADR numbers.

## Template

1. **Title and status** (proposed / accepted / superseded), date, deciders by role.
2. **Context**: the requirement from `ARCHITECTURE.md` or `SECURITY.md` driving the decision, and the threat
   assumptions that apply (buggy/malicious engine, untrusted agent, crash, adaptive querying).
3. **Options**: at least two real alternatives, including "defer". Judge each against the same criteria.
4. **Decision**: stated plainly; a recommendation, not a survey.
5. **Security properties claimed**, each tied to a failure test: atomicity of reservation, durability and
   encryption of the store, isolation guarantees, key scope and rotation, tamper-evidence of audit.
   Distinguish "tamper-evident" from "tamper-proof" and containers from an assurance statement.
6. **Adapter contract**: the small typed interface (authorization, corpus access, atomic budget/state, execution,
   disclosure) the choice sits behind, so core contracts stay vendor-neutral.
7. **Failure and recovery behavior**: crash after exposure, partial write, exhausted storage, expired lease,
   unavailable signer/store; fail-closed defaults.
8. **Performance evidence plan**: what is measured separately (coordinator latency, worker startup,
   validation, utilization, engine time) without relaxing isolation or audit.
9. **Consequences, migration, and exit plan**; policy impact (approval, retention, budget, disclosure,
   signer), which needs an explicit reviewed revision.
10. **Open risks** and what would trigger revisiting.

Never state that something is implemented or verified when it is only proposed. Do not put deployment
inventories, keys, or environment-specific identifiers in an ADR.
