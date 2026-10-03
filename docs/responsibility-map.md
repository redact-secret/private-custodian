# Responsibility map

Maintained by the Redact Secret project. Describes the design baseline; nothing here is deployed.
Related: [ADR 0001](adr/0001-trust-boundaries-and-threat-model.md),
[ADR 0002](adr/0002-implementation-stack-and-runtime-identities.md),
[ADR 0003](adr/0003-legacy-protected-lifecycle-handoff.md).

## 1. Four concerns, four owners

| Concern | Question it answers | Owner | Output | Must not |
| --- | --- | --- | --- | --- |
| Authorization (custody) | May this exact frozen candidate and plan touch this population now, and for how much? | private-custodian | Authorization, reservation, run state, private audit, signed approved projection | Compute metrics, decide ground truth, set thresholds, declare support |
| Measurement | What do these scanner observations score on these cases? | Engines: credential-eval, pii-eval (Rust) | Versioned measurement artifacts | Authorize, hold budgets, see approval or signing material, publish |
| Product qualification | Is the candidate good enough to support or release? | redact-secret-benchmarks (product policy) | Thresholds, support status, accepted tradeoffs, release decisions | Read the private-ledger or corpus, re-run protected evaluation to refresh a page |
| Public review ledger | What adjudicated evidence is public? | redact-secret-benchmarks | Public records that cite approved receipts | Contain private audit records, case detail or budget internals |

Adjacent, not in the four: scanner-neutral ground truth (cases, expectations, provenance) belongs to corpus
authors and reviewers (for example `credential-evidence`). The custodian seals and protects populations; it
does not author expectations.

The **private audit record** (runtime DB plus signed exports in the private-ledger) is a fifth, distinct
record. It is not the public review ledger and is never copied into it. Benchmarks sees only signed approved
projections, receipts and freshness or revocation updates.

Independence: custody, signatures and the private-ledger attest origin, binding and history. They do not prove
true expectations, an independent reviewer or scanner quality. The first deployment has one human operator,
so separation of roles is procedural.

## 2. Runtime identities and who talks to whom

```
GitHub events -> [Request-facing App] -> request queue -> [Control service] <-> [Runtime DB]
                                                          |  stages inputs     [Protected storage]
                                                          v
                                                    [Isolated worker] (no creds, no egress)
                                                          | validated result only
                                                          v
                                  [Control service] -> outbox -> [Receipt signer] -> [Ledger-writer] -> private-ledger
                                                                                  \-> signed projection -> benchmarks
```

Details and prohibitions per identity are in ADR 0002. The measurement engines are invoked as pinned
binaries inside the worker; they never see GitHub.

## 3. Reviewed ownership and cutover map of existing benchmark protected lifecycles

Review status: inventory compiled on 2026-10-02 from benchmark-repository documentation and issue metadata
only (holdout README, PII custodian guide, blind evaluation spec and decision record, issues 652, 664, 665,
666 and pii-eval issue 1). No protected data, corpus, seed, ledger or private directory was read. The
maintainer review of this map is recorded in the pull request that introduces it. Facts the importer needs
(exact file schemas) are for C11 to confirm against code.

Rules for every row (ADR 0003): the legacy lifecycle stays authoritative until a reviewed handoff; no prior
receipt is erased; no exhausted budget is reset; ambiguous spent attempts count as consumed; contaminated
epochs stay contaminated; no population has dual authority.

| Lifecycle (benchmarks) | Today's authority and state locus | Budget semantics today | Evidence produced | Target owner after handoff | What carries over | Gate |
| --- | --- | --- | --- | --- | --- | --- |
| In-repo holdout (`holdout/`, public conformance controls and protected manifests) | Benchmarks runner; ignored `holdout/generated/` plus checked-in commitment-only manifests | Per corpus epoch: sealed with a one-attempt budget (`maxRuns`), reserved under an exclusive lock before reading inputs; failed or interrupted attempts still consume it; never reset automatically | Schema-validated aggregate; `independence` is `public-control` for controls and `custodian-declared` for protected | Custodian runs protected execution; benchmarks keeps public conformance controls and product policy | Seals, commitments, reservations and aggregates as immutable evidence; spent attempts as consumed units | C11 import dry run, signed-envelope verification, legacy runner disabled for that population |
| PII protected corpus, six families (`holdout/PII-CUSTODIAN.md`, evidence under `evidence/901/...`) | Benchmarks `pii:beta11:protected` commands; custodian-authored private input in ignored storage; seal and per-family manifests checked in | Per family, one attempt per sealed epoch; a new candidate commit needs a new epoch and seal; refusal when public gates are unmet does not spend | Per-family aggregate, resolve (accepted or rejected) and disposition bound to the candidate record; no `stable` from this route | Custodian executes under authorization; benchmarks keeps resolve and disposition as product acceptance of protected evidence | Six seals, manifests, aggregates and resolve decisions; each family's attempt state | Same gate; pii-eval parity (P4 to P6, issues 664 to 666) must not change protected state |
| Custodian-held blind evaluation (`benchmarks/blind/`, spec `docs/specs/blind-evaluation.md`) | Isolated custodian agent session; private root outside every repository (freeze, ledger, runs, archive) | Per candidate identity per epoch: one run, spent at reservation so a crash counts; epoch rotates on disclosure or contamination; same fixtures under a new label refused | `blind-aggregate-v1` whitelist; `evidenceClass: custodian-blind`; `independence: procedural-separation`, `organisationalIndependence: false` | Custodian; the private root content migrates by copy under custody, never into a repository | Epoch ledger entries, consumed candidate identities, archive of rotated corpora, released aggregates and reports | Same gate; the private root is moved only by a recorded custody transfer |
| Credential policy holdout receipts (`benchmarks/support/policy-holdout-receipt.ts`, `credential-policy-holdout-report-v1`) | Benchmarks validates receipts bound to product and benchmark revisions | Inherits the holdout budget above | Receipts requiring a complete protected report with `independence: custodian-declared` | Custodian issues signed receipts; benchmarks keeps validation and product use | Existing receipts remain valid as legacy evidence, labelled as such | Dual-verification of old and new receipt formats for a bounded period (C11) |
| Statistical scorer tuning rule | Benchmarks policy: tuning manifests attest no holdout access; a retune prompted by a holdout result is contamination | n/a | Contamination records | Custodian records contamination and revocation (C9); benchmarks applies product consequences | Existing contamination marks and the rule itself | C9 |

### Differences C2 and C4 must preserve

1. Two budget scopes exist: per population epoch (and per family) in holdout, and per candidate identity per
   epoch in blind. Model a budget key that can express both.
2. A refusal before exposure does not spend a budget in the PII flow; a failure after reservation does.
   This matches the core refund rule (refund only when no protected bytes were acquired).
3. The legacy independence vocabulary (`public-control`, `custodian-declared`, `procedural-separation`)
   must stay representable. Do not map any of them to "independent".
4. Legacy blind uses a maintainer-local private root path in its docs; that is deployment material and is
   not reproduced here.
5. Legacy state is stored as local files with lock files; the custodian uses a transactional store. Import
   must record consumption, not recompute it.

### What is deliberately not moved

Product thresholds, support status, accepted tradeoffs, product populations, activation binding and UI
remain in benchmarks (issue 652). Measurement formulas remain in the engines. Corpus authoring and review
remain with corpus authors. The custodian takes execution authorization, budgets, storage, isolation and
disclosure.

## 4. Planned, implemented, deployed

| Component | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Responsibility and cutover map | yes | yes (this document, documentation) | n/a |
| Core lifecycle and ports | yes | scaffold, in-memory, synthetic | no |
| SQLite runtime store (`custodian-store`) | yes | yes (synthetic tests) | no |
| App adapter, storage, workers, signer, ledger-writer | yes | no | no |
| Contamination, rotation and revocation feed (`custodian-lifecycle`) | yes | yes (synthetic tests) | no |
| Handoff of any legacy population | yes | no | no |
