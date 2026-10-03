# Legacy lifecycle inventory, metadata import and handoff gates

Maintained by the Redact Secret project. Design baseline plus synthetic-tested tooling; nothing here is
deployed and no legacy population has been handed off. Related: [ADR 0003](adr/0003-legacy-protected-lifecycle-handoff.md),
[ADR 0091](adr/0091-legacy-metadata-import-rules.md), [ADR 0092](adr/0092-reviewed-handoff-rollback-and-retirement-gates.md),
[responsibility map](responsibility-map.md), [benchmarks integration](benchmarks-integration.md).

Review status: the inventory below was compiled on 2026-10-03 from benchmark documentation, committed schemas
and committed public metadata, read-only, plus the open issues named in the integration document. No protected
data, corpus, seed, private root, ledger or generated holdout directory was read. It must be reviewed by the
maintainer against the benchmark code before an extract is prepared; the points that need that review are
listed in section 4.

## 1. What exists today

All paths are repository-relative in the benchmarks repository. A maintainer-local private root appears in the
blind specification; it is deployment material and is not reproduced here.

| Lifecycle | Public or committed metadata | Held privately by the legacy runner | Budget |
| --- | --- | --- | --- |
| In-repo holdout (credential, credential-policy, PII conformance and protected manifests) | Manifest (`holdout/manifest.json` or a sealed manifest): `schemaVersion`, `id`, `revision`, `purpose` (`public-conformance` or `protected`), `review`, `corpusHash`, `seedHash`, `dataDirectory`, `maxRuns` (sealing sets 1), `evaluation`. Aggregate (`schemas/holdout-report-v1.json`, `schemas/credential-policy-holdout-report-v1.json`): `runId`, `planHash`, `startedAt`, `finishedAt`, `status`, `independence` (`public-control` or `custodian-declared`), `corpus`, `candidate`, scanner results | Corpus and seed; a state file with `status` (`sealed`, `contaminated`, `retired`), `runs` (the consumed run ids) and `reason`; a lock file; plan and aggregate copies | One attempt per sealed corpus epoch (`maxRuns`). The run id is appended to the state before the corpus is read, so a crash after that point is spent. A failed or interrupted run emits no aggregate |
| PII protected corpus, six families | Seal (`holdout/pii-b11-<sealId>-seal.json`): `inputCommitment`, `seedCommitment`, `artifactCommitment`, `review`, `families[6]` each with `manifestCommitment`, `maxRuns: 1`, and `absentFamilies`. Per-family manifests. Per-family aggregate, trust resolution (`attempts`, `decision`, `custodian`, `reviewer`, `reviewedAt`), disposition (`protected.runs` such as `1/1`), and an unspent attestation (`runs: 0`) under `evidence/` | As above, per family | One attempt per family per sealed epoch; a new candidate needs a new epoch and seal; a refusal because public gates are unmet does not spend |
| Custodian-held blind evaluation | Released aggregates under `docs/reports/`: `evidenceClass: custodian-blind`, `independence {level, achieved: procedural-separation, organisationalIndependence: false, statement}`, `candidate` (facade digest and artifacts), `freeze`, `corpus {epoch, commitment}`. Carry-over records: `includedInTotals: false`, `privateFixturesAccessed: false`, `supersedes`, `carriedTo` | Fixtures, freeze, a ledger of epochs and runs (`reserved`, `complete`, `incomplete`), per-run freezes and aggregates, an archive of rotated corpora, all in a private root outside every repository | One run per candidate identity (facade digest) per epoch, spent at reservation; same fixtures under a new label refused; epoch rotates on disclosure or contamination; contamination is procedural, with no machine-readable field |
| Credential policy holdout receipt (`credential-policy-holdout-report-v1`, validated in `benchmarks/support/policy-holdout-receipt.ts`) | Receipt keys `schemaVersion`, `profileId`, `productRevision`, `benchmarkRevision`, `report`; accepted when the report is complete, protected, `custodian-declared` and the product scanner is complete. It is supplied on a command line; none is committed | The holdout state it was produced from | Inherits the holdout budget; carries no budget of its own |
| Statistical scorer tuning rule | Policy text: a retune prompted by a holdout result is contamination | Contamination marks | n/a |

Facts the importer relies on: public metadata shows a spent attempt only through an aggregate, resolution or
disposition; the authoritative spent counter and the contamination status are private; a blind reservation is
never public; epoch creation dates are public only for the PII seal (`reviewedAt`).

## 2. Mapping to the import

| Legacy fact | Extract field | Import result |
| --- | --- | --- |
| Holdout or PII scope: population or manifest `id`, epoch, family | `scope: population_epoch {population, epoch, family?}`, lifecycle `holdout` or `pii-protected` | Custodian `population_epoch` budget scope |
| Blind scope: facade digest and epoch | `scope: candidate_epoch {candidate, epoch}`, lifecycle `blind` | Custodian `candidate_lineage_epoch` budget scope; lineage grouping is decided at handoff |
| `maxRuns`, or one per candidate per epoch | `declared_limit` | `limit`; unknown limit is an exhausted budget |
| Run ids in the legacy state, blind ledger `runs[]` | `attempts[]` with the legacy state | Every attempt counts as consumed, including `reserved`, `incomplete`, `failed`, `unknown` |
| PII refusal before exposure | `refused_before_exposure` with a cited source | Not counted; without a cited source it counts |
| Summary counts (`runs`, `1/1`, receipts) | `reported_consumed`, `reported_receipts` | Larger count wins; a disagreement is an unexplained difference |
| Unspent attestation | source kind `unspent-attestation` | The only positive evidence of zero consumption |
| No attempt, count or attestation | nothing | Whole limit counts as consumed (ambiguous) |
| `independence`, `evidenceClass`, `organisationalIndependence`, statement text | `independence {claim, evidence_class, organisational_independence_claimed, statement_sha256}` | Claim kept verbatim; only the three legacy values; organizational independence only `not_claimed`; statement kept by digest in the cited source |
| Contamination status or mark | `contamination {marked, none_recorded, unknown}` | Marked stays contaminated; unknown blocks the gate and is never clean |
| Manifests, seals, aggregates, receipts, resolutions, dispositions, carry-overs | `sources[]` with kind, repository-relative locator, SHA-256 of the public file, observed-at | Recorded with provenance; receipts counted from `aggregate`, `policy-receipt`, `blind-aggregate` |
| State only the legacy runner holds | source kind `custodian-statement`: a one-segment logical label, no digest, no path | Reviewed assertion; the private file is not read |

Preparing an extract is a human, reviewed step. The tooling takes the extract as bytes. Run the dry run with
`cargo run -p custodian-bridge --example legacy_import -- <extract.json>`; it reads that one file, writes
nothing and prints the report with a gate line and the report digest.

## 3. Dry-run report and handoff

The report lists, per scope, reported against imported consumption and receipts, the explained (conservative)
and unexplained differences, refused scopes with fixed codes, totals, and a gate: zero unexplained
differences, zero refused scopes, zero unknown contamination. It states `executed: nothing`.

A handoff record (`private-custodian.legacy-handoff/1`) binds to the report digest and names, per imported
record, the custodian budget scope the consumption will be recorded against. It is a proposal until the
following have cited evidence; the code recomputes everything that can be recomputed.

| Gate | Source of truth |
| --- | --- |
| Inventory reviewed by the maintainer | cited review reference |
| Dry run with zero unexplained differences between legacy and imported budget and receipt counts | recomputed from the report |
| Benchmarks verifies signed envelopes with freshness and revocation | cited result of the benchmarks client against the bridge ([benchmarks integration](benchmarks-integration.md)) |
| Rollback rehearsed | cited rehearsal |
| Legacy runner disabled for that population in the same change | cited change in benchmarks |
| Credential domain's own readiness (credential handoffs only) | cited readiness evidence |
| Population moves whole, no partial or dual authority | recomputed from the records |

## 4. Rollback and retirement gates

1. **Evidence is preserved.** No gate, rollback or retirement deletes or edits an import record, a legacy
   receipt, a seal, a manifest, an aggregate or a contamination mark. Legacy artifacts are archived, not removed.
2. **No budget reset in any direction.** Rolling back to the legacy runner first reconciles consumption
   recorded under custodian authority into the legacy state; a spent attempt stays spent.
3. **Any new protected execution requires an explicit execution `Approval`**, bound to the exact request, plan,
   candidate, population, budget scope and policy activation. Migration, verification, a ready handoff and a
   passing dry run are never authorization.
4. **No protected rerun for parity.** Parity is by metadata only. Reusing an approved aggregate receipt is
   preferred to any rerun, as benchmarks issue 664 also requires.
5. **Credential domain is not forced.** Its handoff waits for its own readiness evidence; PII readiness does not
   imply it. credential-eval keeps holdout, blind and policy qualification out of its current scope.
6. **Oracle-exit period and retirement are separate acts.** The legacy runner is disabled for a population in the
   same change as its cutover (a handoff gate). Retiring it for good follows the oracle-exit period benchmarks
   issue 666 records, needs the maintainer's explicit written authorization, and keeps dual verification of old and
   new receipt formats for a bounded period benchmarks owns.
7. **A contaminated or rotated epoch stays contaminated** across every step.

## 5. Needs maintainer review

* The extract itself: which scopes exist, and for each sealed epoch without an aggregate or attestation, the
  true count from the legacy state (otherwise it imports as fully consumed).
* Whether each blind candidate identity (facade digest) maps to its own custodian lineage, or several share one.
* Blind carry-over records have no defined budget effect in the legacy lifecycle. The importer records them as
  evidence only; the carried-to identity must be its own scope with an explicit state or be left out.
* The `custodian-declared` and PII `custodian` and `reviewer` strings are agent labels from the maintainer-directed
  process; they are preserved as stated and do not mean independent review.
* The same facade digest ran on two blind epochs, which is legal under the per-epoch rule; scopes are keyed by
  candidate and epoch.
* Whether the credential policy holdout receipts in use trace to a sealed epoch whose state is recorded; no
  committed credential protected manifest or receipt was found.

## 6. Planned, implemented, deployed

| Component | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Inventory (this document) | yes | yes, documentation | n/a |
| Extract, importer, dry-run report, import store port | yes | yes (synthetic) | no |
| Handoff record and gate checks | yes | yes (synthetic) | no |
| A real extract and its maintainer review | yes | no | no |
| Writing consumed units into the runtime budget store (`legacy apply`, migration 0005, ADR 0115) | yes | yes (synthetic) | no |
| Cutover, runner disablement, rollback rehearsal, retirement | yes | no | no |

## 7. Applying the import to the runtime store (S3)

`custodian legacy apply --extract F --handoff F --confirm-handoff-digest D --confirm-report-digest D` re-imports
the reviewed extract deterministically, checks the handoff is ready and that both digests match what the operator
typed, then writes the consumed units into the store through `apply_legacy_imports` (additive, idempotent;
ADR 0115). Refusals are `handoff_not_ready` and `import_refused`.

**Legacy contamination marks are not carried by `legacy apply`.** The command writes budget units only and reports
contamination counts. Each mark that matters must be recorded separately with `lifecycle report`.

No real legacy extract has been applied; no population has been handed off.
