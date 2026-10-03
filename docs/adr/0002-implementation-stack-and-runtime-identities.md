# 0002. Implementation stack and runtime identities

- Status: accepted (design baseline)
- Date: 2026-10-02
- Deciders (by role): repository maintainer (single human operator)
- Maintenance: this repository is maintained by the Redact Secret project; decisions here are
  project-maintained, not independent validation.

## Context

ARCHITECTURE.md and CONVENTIONS.md left runtime, durable store, isolation, key provider and topology open.
Epic #1 directs a Rust measurement engine in the sibling engines, thin internal GitHub Apps as request and
status adapters, and states that the database and protected storage are infrastructure, not extra
repositories. C2 to C12 need a fixed crate layout, store choice and set of identities.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Core language | Rust; TypeScript (matches benchmarks); defer |
| Runtime store | SQLite; Postgres; GitHub issues/repo as store; defer |
| Protected storage | restricted directory behind an adapter; object store; separate repo; defer |
| Audit export | restricted private repository; append-only file only; hosted log service |

Criteria: atomic reservation without a network service, small attack surface, no coupling of measurement to
GitHub, honest tamper-evidence, ability to migrate without changing contracts.

## Decision

1. **Rust policy/state core.** Deterministic authorization, plan binding, lifecycle, refund and disclosure
   rules live in a std-only Rust crate with no I/O. Rationale: memory safety for code that handles
   untrusted bytes, enums that make illegal transitions unrepresentable, one language with the Rust
   engines, no runtime to patch. TypeScript is not used for the core. The pinned TypeScript evaluators remain
   migration oracles owned by the engines and benchmarks, invoked only as pinned binaries or packages.
2. **SQLite-first runtime store.** Run state, budgets, idempotency keys, leases, authorizations and the audit
   outbox live in one SQLite database owned by the control service (WAL, `BEGIN IMMEDIATE` transactions,
   single writer). Rationale: reservation and state change are one local ACID transaction, no database
   server or network credential to protect, easy snapshot and rehearsed restore. Limits: single host, no
   high availability, backups need care so a restore cannot lower consumed budget (ADR 0001 T3). The store
   is behind `StateStore`; Postgres or another store replaces it by adapter plus explicit migration, not by
   changing contracts.
3. **Filesystem-first protected storage behind an adapter.** Sealed, versioned populations sit in a
   restricted directory (owner-only, no symlinks, outside the repository and CI) behind `CorpusAccess`. The
   adapter validates integrity at open. Sealing and key provider are decided in C5. Rationale: matches the
   existing holdout and blind lifecycles (mode 0700 directories, 0600 files, commitment-only manifests) so
   migration is mechanical; an object store can replace it later.
4. **Restricted private-ledger repository.** A private GitHub repository holds signed audit exports and
   decisions: metadata, digests, state and reason codes, revocation records. No corpus, case detail, seeds,
   raw results, DB files or keys. Only the ledger-writer identity can write it; benchmarks and the App
   adapter cannot read it. It is a tamper-evident outside copy, not the budget authority: the runtime DB
   remains authoritative for live budgets, and GitHub unavailability never changes a budget. The public
   review ledger stays benchmark-owned and is a different record.
5. **No measurement coupling to GitHub.** Engines (credential-eval, pii-eval) are CLIs invoked by the
   custodian as pinned binaries with versioned artifacts. GitHub appears only in two adapters: the
   request-facing App (Z1) and the ledger-writer (Z6). Workers receive no GitHub token. Public and synthetic
   evaluation works without the custodian or GitHub.
6. **Code-only eventual publication.** Source may become public after the publication gate in SECURITY.md.
   The DB, protected storage, private-ledger, corpora, keys, raw results and operational history stay
   private. Public source grants no permission to execute or query the protected system.

### Crate layout (fixed for C2 to C12)

```
Cargo.toml                       workspace
crates/custodian-core/           policy and state core, ports, synthetic doubles (std only)
crates/custodian-contracts/      versioned contracts; placeholder until C2
crates/custodian-service/        control service: lifecycle orchestration; adapters added by C3 to C8
```

Dependency direction: `custodian-service` -> `custodian-core`, `custodian-contracts`. `custodian-core` depends on
nothing. Contracts depend on nothing in the workspace until C2 decides. Vendor and I/O dependencies (SQLite,
HTTP, signing) enter only in adapter code in `custodian-service` or later adapter crates, never in
`custodian-core`.

### Runtime identities

Roles, not accounts. Real accounts, hostnames and credentials are deployment material and stay out of the
repository.

| Identity | Does | Holds | Must not |
| --- | --- | --- | --- |
| Request-facing App (Z1) | Verifies GitHub events, enqueues requests, posts sanitized status | Its own App credential (C3) | Read the DB, corpus, signer or ledger; approve; run anything |
| Control service (Z2) | Authorizes, binds plans, reserves, tracks state, validates results, writes the outbox | DB write; corpus-open capability gated by a reservation | Hold the signing key or ledger credential; run candidate code |
| Runtime DB (Z2) | Durable state and budgets | Owned by the control-service OS user, owner-only | Be readable by workers, App adapter, CI or developers |
| Protected storage (Z3) | Sealed populations | Owner-only restricted directory | Live in a repository, CI cache or artifact |
| Isolated workers (Z4) | Run engine and scanner on staged inputs | Scratch only | Egress, host or GitHub credentials, DB, storage, signer |
| Receipt signer (Z5) | Signs validated approved projections | Signing key reference | Accept scanner output, agent input or unapproved data |
| Ledger-writer (Z6) | Pushes signed exports from the outbox to the private ledger | Write to the private-ledger only | Read corpus or DB beyond the export queue; modify history |

The signer and ledger-writer are separate from the control service so that compromise of request handling
does not yield signing or ledger authority. In the first deployment they may run on one host under separate OS
users; sharing one OS user would void the separation and requires an explicit risk decision.

## Security properties claimed

All properties are requirements, unproven. Proof obligations: atomic reservation under concurrent and
duplicate requests (C4, scaffolded in-memory in `crates/custodian-service/tests/smoke.rs`); store durability
and restore without budget rollback (C4, C12); corpus integrity at open (C5); worker isolation probes (C6);
signer refusal and idempotent export (C7). Ledger and audit are tamper-evident, not tamper-proof.

## Adapter contract

`custodian_core::ports`: `Authorizer`, `CorpusAccess`, `StateStore`, `Executor`, `Disclosure`. No port
mentions SQLite, filesystem, GitHub or a cloud.

## Failure and recovery

Unavailable ledger: runs continue, exports queue, release of new public projections pauses if the policy
requires a ledger record first. Unavailable DB: no new reservation. Corrupt or rolled-back DB: refuse to run
and reconcile against the last exported checkpoint. Unavailable signer: no release.

## Performance evidence plan

C4 measures reservation transaction latency and contention; C6 worker startup and resource use; C7 export
lag. Engine execution time is reported by the engines, not by custodian code.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Rust workspace, core ports, synthetic smoke test | yes | yes (scaffold, in-memory) | no |
| SQLite store, restricted storage, workers, signer, ledger-writer, App | yes | no | no |
| Private-ledger repository | yes | not created | no |

## Consequences, migration, exit

Choosing SQLite and a directory fixes the first deployment to one host. Exit: implement `StateStore` and
`CorpusAccess` for another backend, run both against the same conformance tests, migrate state with a
recorded budget carry-over, and supersede this ADR. Contracts (C2) must not leak SQLite types or paths.
Canonical encoding and digest rules are deliberately not decided here; C2 owns them.

## Open risks and revisit triggers

Single-host availability and single-operator custody; SQLite write contention if request volume grows;
the private-ledger depends on GitHub availability and access controls. Revisit if the deployment needs more
than one writer host, a second operator, or a non-GitHub ledger.
