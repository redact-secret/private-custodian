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
| [0004](0004-canonical-encoding-digests-and-contract-dependencies.md) | Canonical encoding, digests, domain separation, time and contract dependencies | Accepted (design) |
| [0005](0005-contract-set-freshness-and-versioning.md) | Contract set, internal versus public split, freshness and versioning | Accepted (design) |
| [0010](0010-github-app-request-intake.md) | GitHub App request intake, authentication and credential separation | Accepted (design); implemented as a library, not deployed |
| [0020](0020-sqlite-runtime-store-and-dependency-pins.md) | SQLite runtime store: crate, connection settings and dependency pins | Accepted (design); implemented, not deployed |
| [0021](0021-budget-accounting-run-state-and-recovery-policy.md) | Budget accounting, run state, leases and recovery policy | Accepted (design); implemented, not deployed |
| [0022](0022-store-migrations-audit-outbox-and-restore-protection.md) | Store migrations, audit outbox and restore protection | Accepted (design); implemented, not deployed |
| [0030](0030-protected-population-storage-layout-and-adapter-contract.md) | Protected population storage layout and adapter contract | Accepted (design) |
| [0031](0031-corpus-commitment-seal-and-keyed-public-commitment.md) | Corpus commitment, seal and keyed public commitment | Accepted (design) |

Accepted (design) means the decision is frozen for downstream issues (C2 to C12). It does not mean any of it
is implemented or deployed. See each ADR's status table.

Decided by C2 (ADR 0004, ADR 0005): canonical encoding, digest and domain-separation rules, time handling,
contract set, public projection and revocation envelopes, freshness and contract versioning. Still
deferred, with the issue that owns each: request-intake authentication details (C3); SQLite schema and migrations (C4); sealing format and key
provider (C5); sandbox platform and probes (C6); signing key provider and receipt format (C7);
disclosure policy parameters (C8).

Decided by C4 (ADR 0020 to 0022): the SQLite driver and pins, connection and file settings, the written budget accounting, lease and recovery policy, migrations, the audit outbox and restore protection. Details: [docs/state-store.md](../state-store.md). Implemented in `crates/custodian-store` with synthetic tests; not deployed.
