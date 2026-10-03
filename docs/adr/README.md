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
| [0040](0040-worker-sandbox-interface-linux-backend-and-dependencies.md) | Worker sandbox interface, Linux backend and dependencies | Accepted (design); implemented, not deployed |
| [0041](0041-isolation-self-check-verification-record-and-supported-deployments.md) | Isolation self-check, verification record and supported deployments | Accepted (design); implemented, not deployed |
| [0042](0042-dispatch-order-identity-verification-staging-and-result-protocol.md) | Dispatch order, identity verification, staging and result protocol | Accepted (design); implemented, not deployed |
| [0050](0050-receipt-signature-algorithm-keys-and-signer-isolation.md) | Receipt signature algorithm, key identifiers, key lifecycle and signer isolation | Accepted (design); implemented, not deployed |
| [0051](0051-ledger-record-layout-identity-and-supersession.md) | Ledger record layout, identity, append-only semantics and supersession | Accepted (design); implemented, not deployed |
| [0052](0052-ledger-backend-port-and-git-writer.md) | Ledger backend port and conflict-aware Git writer | Accepted (design); implemented, not deployed |
| [0053](0053-outbox-exporter-acknowledgement-and-reconciliation.md) | Outbox exporter, acknowledgement protocol and reconciliation | Accepted (design); implemented, not deployed |
| [0054](0054-external-checkpoints-startup-check-and-independent-verification.md) | External checkpoints, startup check and independent verification | Accepted (design); implemented, not deployed |

Accepted (design) means the decision is frozen for downstream issues (C2 to C12). It does not mean any of it
is implemented or deployed. See each ADR's status table.

Decided by C2 (ADR 0004, ADR 0005): canonical encoding, digest and domain-separation rules, time handling,
contract set, public projection and revocation envelopes, freshness and contract versioning. Still
deferred, with the issue that owns each: request-intake authentication details (C3); SQLite schema and migrations (C4); sealing format and key
provider (C5); sandbox platform and probes (C6); signing key provider and receipt format (C7);
disclosure policy parameters (C8).

Decided by C4 (ADR 0020 to 0022): the SQLite driver and pins, connection and file settings, the written budget accounting, lease and recovery policy, migrations, the audit outbox and restore protection. Details: [docs/state-store.md](../state-store.md). Implemented in `crates/custodian-store` with synthetic tests; not deployed.

Decided by C7 (ADR 0050 to 0054): Ed25519 receipts with domain separation and isolated signing, key lifecycle, the ledger record layout and supersession, the conflict-aware ledger writer, the outbox exporter and reconciliation, external checkpoints and the startup rollback check. Details: [docs/ledger.md](../ledger.md). Implemented in `crates/custodian-ledger` with synthetic tests and test-generated keys; the private-ledger repository, signer process and key provider are not provisioned.

Decided by C6 (ADR 0040 to 0042): the `Sandbox` interface and Linux backend (bubblewrap and `prlimit`, no new Rust dependency), the fail-closed refusing backend, the startup isolation self-check and verification record, supported deployment isolation and the test skip policy, the dispatch order (identity checks before protected input, write-ahead exposure), immutable staging, and worker protocol v1 with its outcome mapping. Details: [docs/worker-isolation.md](../worker-isolation.md). Implemented in `crates/custodian-worker` with synthetic tests; not deployed.
