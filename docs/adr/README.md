# Architecture decision records

Decisions the baseline left open (runtime, durable store, isolation, key provider, topology, schemas, policy)
are recorded here. Use [template.md](template.md). Numbers are sequential and never reused; a superseded ADR
stays in place with its status changed.

Every ADR separates **planned**, **implemented** and **deployed**. Writing an ADR does not make a control
exist. Do not put keys, deployment inventories, hostnames, protected paths or operational identifiers in an
ADR.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-trust-boundaries-and-threat-model.md) | Trust boundaries and threat model | Accepted (design) |
| [0002](0002-implementation-stack-and-runtime-identities.md) | Implementation stack and runtime identities | Accepted (design) |
| [0003](0003-legacy-protected-lifecycle-handoff.md) | Legacy protected lifecycle handoff | Accepted (design) |

Accepted (design) means the decision is frozen for downstream issues (C2 to C12). It does not mean any of it
is implemented or deployed. See each ADR's status table.

Decisions deliberately deferred and the issue that owns them: canonical encoding and digest rules (C2);
request-intake authentication details (C3); SQLite schema and migrations (C4); sealing format and key
provider (C5); sandbox platform and probes (C6); signing key provider and receipt format (C7);
disclosure policy parameters (C8).
