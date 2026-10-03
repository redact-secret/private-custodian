# Ordinary Lambda custody migration assessment (P6)

Assessment date: 2026-10-03. Baseline: custodian
`00e1bb0` (S6 merged). **NO-GO for migrating the current control plane.**
No Lambda handler, DynamoDB adapter, S3 custody adapter or network signer
transport is implemented or deployed. [ADR 0134](../adr/0134-serverless-control-plane-feasibility.md)
records the recommendation separately from the worker decision.

## Dependency and authority map

| Boundary | Current dependency and exact seam | Required replacement and authoritative transaction groups |
| --- | --- | --- |
| Daemon composition | `crates/custodian-daemon/src/main.rs:83`, deployment parts, `pipeline/mod.rs:298` concrete `SqliteStore` | Separate intake, status, orchestration, export and recovery handlers; no scanner code. Explicit authenticated identity per handler |
| Runtime store | `crates/custodian-store/src/store.rs:95`, `Mutex<Connection>` | Shared durable transactional adapter; /tmp is only scratch, never distributed authority |
| Reservation/start/exposure/settlement | `store/src/ops.rs:606`, `:622`, `:679`, `:761`, `:792`, `:835`, `:881`, `:927`, `:966`, `:1006` | Atomic request/idempotency/approval/budget/reservation/attempt/outbox; leases, live fences, standing and export barriers in the same conditional transaction; uncertain exposed outcomes consumed |
| Intake and authorization | Store `intake.rs`, `lifecycle.rs`, migrations 0004/0006; CLI `control.rs` | Durable delivery deduplication, installation revoke/recheck, queue publication, independent approval, activation freshness/history, retention with acknowledged exports |
| Queue and pipeline | `store/src/pipeline.rs:120`, `:151`, `:181`, `:547`, `:616`, `:648`, `:706`, `:830`; migration 0007 | Claim/defer/release/settle by lease token; monotone enrollment/advance; identity-conflict refusal; private result and receipt assembly durability; prepare mark bound to release approval |
| Protected population/registry | `custodian-corpus` filesystem adapter, store epoch registry/standing; `worker/src/ports.rs:200` | Authenticated immutable versioned blob reads plus transactional reviewed registry and standing. No object path or corpus credential in request/worker |
| Artifact staging and publication | `main.rs:156`, `DirRequestSource`, `DirStager`, `DirApprovals`, `DirSink` | Conditional immutable blobs with length/digest verification; stage after exposure/export only; output delivery idempotency; approved destination binding |
| Disclosure authority | `custodian-disclosure::DisclosureService`, store `disclosure.rs`, migration 0002 | Atomic release/query budgets, cumulative composition, independent approval, exact destination and activation; preserve suppression and domain rules |
| Revocation and legacy state | Store `lifecycle.rs`, `imports.rs`, migrations 0003/0005 | Monotone standing/retirement, reviewed rotation, sequenced feed obligations/publication CAS; additive legacy consumption; no exhausted-budget reset |
| Audit/export/checkpoint | Store `outbox.rs`, `integrity.rs`; ledger `exporter.rs:315`, `git.rs:203` | Append-only content-conflict-safe export, durable ack, external checkpoints, startup rollback/write block. Git write failure keeps dispatch/release closed |
| Signer | `custodian-ledger/src/signer.rs:410` `RemoteSigner<T>`; Unix transport in `custodian-signer` | Separately authenticated bounded transport preserving Ed25519 domains, purposes, freshness and public-key verification; no worker or intake signing authority |
| Recovery and reissue | Store `loss.rs`, migration 0008; CLI `control/recovery.rs`; ledger `reissue.rs:388` | Human-reviewed exact loss acceptance, monotone budget reconstruction/retirement, append-only superseding receipts and key revocation; no invocation-time policy amendment |
| Scheduler/liveness | Long-running scheduler, process shutdown/signals | Leased scheduled recovery/export/checkpoints, reliable orphan janitor, bounded retries and queue progress independent of any single invocation |

Source locations identify the reviewed baseline; new distributed ports must cover
all methods within each group, including their private helpers and migrations.
This is an inventory, not a statement that the existing `StateStore` port supports
all of them. Before implementing a replacement, enumerate every SQL transaction
and compare port coverage; an uncovered authoritative operation blocks cutover.

## Minimum migration backlog and exit evidence

1. Extract complete application-facing store and blob ports while running the
   same current conformance suites. Preserve SQLite as the reference adapter.
2. Specify DynamoDB conditional transaction keys/versions, permanent idempotency,
   request/attempt fences, outbox sequencing and budget arithmetic. Prove the
   actual item/transaction bounds for maximum plans and audit records. Compare
   strong/transactional reads with stale activation/standing decisions.
3. Implement S3 immutable-version/digest adapter. Test missing/partial objects,
   conflicting bytes, stale version, wrong roster, malicious archive paths and
   cleanup/retention. Multi-object publication needs explicit recovery;
   a bucket does not replace a transaction.
4. Implement network signer transport and handler authorization without changing
   algorithms or domains. Test wrong caller/purpose, stale payload, oversize,
   unavailable signer, hostile response and concurrency with disposable keys.
5. Implement export/checkpoint transport with disposable Git. Test crash before
   write, after durable write but before ack, replay/conflict and stale restore.
6. Split intake/status/orchestrator/export/recovery handlers with separate roles,
   no scanner code and no worker access to DB/ledger/signer/corpus credentials.
   Exercise replayed/parallel invocations, last-unit races, cancellation, fence
   loss, pending exposure export and outbox starvation on actual adapters.
7. Implement monotone migration/rollback, remote VM creation-intent mapping and
   independent orphan reconciliation. Rehearse S6 loss/key recovery without
   deleting receipts, resetting budgets or bypassing human confirmations.
8. Measure total service usage and demonstrate cleanup before proposing a
   production topology or policy activation.

## Existing critical-path controls to preserve

These run against the actual SQLite/signer/Git components, using public synthetic
fixtures and disposable keys. They are **not evidence about DynamoDB or Lambda**.

| Failure/positive control | Existing runnable suite |
| --- | --- |
| Last budget unit, duplicate request, parallel start, cancellation race | `cargo test -p custodian-store --locked --test concurrency` |
| Start/exposure export gates, unavailable ledger, ack crash and restart/restore | `cargo test -p custodian-store --locked --test export_gate` |
| Crash after pipeline stages and store transactions; killed run remains consumed | `cargo test -p custodian-daemon --locked --test crash` |
| Valid signature, wrong purpose/domain, stale request, overflow and restart | `cargo test -p custodian-signer --locked --test signer` |
| Disposable Git append-only content conflict and retry | `cargo test -p custodian-ledger --locked --test git_backend` |
| Release/query races and composition | `cargo test -p custodian-store --locked --test disclosure` |
| Full request-to-consumer rejection and S6 recovery | `.github/workflows/full-synthetic-flow.yml` (Linux CI; not a cloud migration test) |

These suites are included in `cargo test --workspace --locked`. No new shared
state or signer prototype is falsely credited with their results.
