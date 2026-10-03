# private-custodian

Custody and controlled execution for protected credential and PII evaluation.

This project coordinates frozen candidates, protected synthetic corpora, execution budgets, isolated measurement, and approved aggregate release. It is the private operational boundary around scanner-neutral engines such as [credential-eval](https://github.com/redact-secret/credential-eval) and [pii-eval](https://github.com/redact-secret/pii-eval).

## Status

**Design baseline with a scaffold — nothing is deployed.** The repository starts privately. Selected source code and these design documents may be published after security and operational readiness review. A public repository does not make protected data, operational state, or evaluation access public.

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Stack and trust boundaries ([ADRs](docs/adr/README.md)) | yes | decisions recorded | no |
| Rust workspace with policy/state core, control-service scaffold and synthetic smoke test | yes | yes (in-memory, synthetic) | no |
| Versioned request, approval, reservation, execution, receipt, public projection and revocation contracts ([docs/contracts.md](docs/contracts.md)) | yes | yes (types, schemas, checks; no service uses them) | no |
| Protected population storage, sealing and reviewed registry (`custodian-corpus`, [docs/protected-storage.md](docs/protected-storage.md)) | yes | yes (filesystem adapter, synthetic tests) | no |
| SQLite runtime store: transactional budgets, durable run state, leases, audit outbox ([docs/state-store.md](docs/state-store.md)) | yes | yes (synthetic tests; no listener, no ledger writer) | no |
| Request-facing App, isolated workers, signer, ledger export | yes | no | no |

First deployment (planned): a Rust policy/state core and control service, a SQLite runtime store, protected populations in a restricted directory behind an adapter, and a separate restricted private-ledger repository for signed audit exports. The database and protected storage are infrastructure, not extra repositories. Eventual publication is code only: the private ledger, runtime database, protected corpora, raw results, secrets and operational history remain private. Rationale and limits: [ADR 0002](docs/adr/0002-implementation-stack-and-runtime-identities.md).

“Private” describes custody and access boundaries, not a requirement that all implementation code remain secret. Security must not depend on source obscurity.

## Responsibilities

- Register sealed, versioned protected synthetic populations and their permitted uses.
- Verify engine, adapter, scanner, configuration, and frozen candidate identities.
- Authorize and reserve bounded evaluation budgets before execution.
- Invoke measurement engines inside an enforced isolation boundary.
- Retain private evidence and append-only decision/audit records.
- Release only validated projections allowed by an explicit disclosure policy.

The custodian does not decide scanner-neutral ground truth, implement measurement formulas, tune detectors, declare product support status, or guarantee that project-owned evidence is independent.

## Agent boundary

An agent can propose a run, collect approved provenance, invoke deterministic operations under an issued authorization, and prepare a reviewable report. It cannot approve its own plan, alter a sealed corpus, broaden access, expand a budget, sign a public receipt, or bypass a disclosure rule through conversation instructions.

Authorization, budget accounting, state transitions, identity checks, and publication rules are deterministic enforcement components. The model is not the security authority.

## Intended workflow

1. Seal a reviewed synthetic population and record its custody identity.
2. Freeze candidate bytes and a complete measurement plan.
3. Authorize the plan and atomically reserve the allowed budget.
4. Run the pinned engine and scanners in an isolated worker.
5. Validate private results and finalize the audit/budget state.
6. Approve an aggregate projection and issue a verifiable receipt.

Failure, cancellation, interruption, and retries have recorded outcomes; they do not silently reset the budget.

## Ecosystem

| Component | Role |
| --- | --- |
| `private-custodian` | Authorization, custody, isolation, audit, disclosure |
| Evaluation engine | Deterministic measurement of supplied cases and observations |
| Corpus author/reviewer | Expectations, provenance, and review claims |
| Product qualification consumer | Thresholds, support status, release decisions |

Benchmarks consumes approved evidence bound to the exact candidate and plan. It receives no protected case detail merely to fill a page or diagnose a failed gate. It cannot read the private ledger; it receives signed approved projections and revocation updates. The public review ledger stays benchmark-owned and is distinct from private audit records. See the [responsibility map](docs/responsibility-map.md), including how existing benchmark holdout and blind lifecycles hand off without erasing receipts or resetting exhausted budgets.

## Reading and contribution

Read [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [CONVENTIONS.md](CONVENTIONS.md), [docs/adr/](docs/adr/README.md), the [responsibility map](docs/responsibility-map.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). This repository is maintained by the Redact Secret project; its evidence and controls are project-maintained, not independent validation. Checks: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. All development and ordinary CI use public synthetic conformance controls. Those controls prove lifecycle behavior, not independent holdout quality.

Protected corpora, seeds, keys, ledgers, raw reports, and operational identifiers belong in separately controlled storage, never this repository or its CI artifacts. Real personal data, production logs, and real credentials are out of scope.

## Publication and licensing

Before publishing code, select a license and review repository history, fixtures, examples, logs, and assets. No license is granted by these documents. Operational secrets and protected evidence remain private even if the repository is public; moving code to public access does not grant permission to execute or query protected evaluation.
