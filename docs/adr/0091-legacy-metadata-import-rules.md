# 0091. Legacy metadata import rules

- Status: accepted (design); implemented in `custodian-bridge::legacy` (C11); not executed against any real
  legacy population
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0003 keeps the legacy holdout, PII protected and blind lifecycles authoritative until a reviewed handoff
and requires that no receipt is erased, no exhausted budget is reset, an ambiguous spent attempt counts as
consumed and a contaminated epoch stays contaminated. The inventory (docs/legacy-migration.md, compiled from
benchmark documentation, schemas and committed public metadata only) shows what an importer can and cannot
know: the legacy runner keeps the authoritative spent counter and the contamination status in a protected
state file; public metadata (manifests, seals, aggregates, resolutions, unspent attestations, blind
aggregates) shows a spent attempt only when an aggregate or resolution exists, and a failed or interrupted
run leaves none. The importer must not read protected corpora or rerun protected data for parity.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Input | read the legacy directories directly; a reviewed metadata extract (counts, labels, public-file digests, dates) |
| Spend rule | count only attempts with a receipt; count every attempt unless positively shown refused; treat missing evidence as unspent |
| Silence | an unevidenced scope is unspent; an unevidenced scope is fully consumed |
| Persistence | write straight into the runtime budget store; produce immutable import records and apply them through a port |
| Parity | rerun protected data on both sides; compare metadata counts and receipts |
| Identity | hash of everything including the reviewer; hash of the facts |

## Decision

1. **Input is a reviewed extract**, `private-custodian.legacy-extract/1`: per legacy scope, the lifecycle,
   domain, scope (population/epoch/family, or candidate/epoch), declared limit, attempts with their legacy
   state, the legacy summary counts, the independence statement, the contamination state, and the sources
   (kind, repository-relative locator, SHA-256 of the public file, observed-at). State that only the legacy
   runner holds is carried as a `custodian-statement` source: a one-segment logical label with no digest and no
   path, because the private file is not read. The importer is a pure function of the extract bytes: it opens
   no file, store or ledger and reads no clock.
2. **Spent stays spent.** Every attempt counts as consumed unless a cited source positively shows it was
   refused before any protected input was read (the PII flow only). A state the reviewer cannot classify
   (`unknown`) counts.
3. **Silence is consumption.** A scope with no attempt, no reported count and no unspent attestation counts
   its whole declared limit as consumed; an unknown limit is an exhausted budget. A cited unspent attestation
   is the only positive evidence of zero. An attestation next to a spent attempt does not lower the count and is
   an unexplained difference.
4. **Disagreement takes the larger count.** A legacy summary count and the attempt list that disagree import
   the larger and are recorded as an unexplained difference that blocks handoff. A receipt count that differs
   from the receipts listed is also unexplained.
5. **Both budget semantics stay distinct.** Population/family epoch scopes map to `population_epoch`; blind
   candidate-identity-per-epoch scopes map to `candidate_lineage_epoch`. A scope shape that does not match its
   lifecycle is refused. Mapping a legacy candidate identity to a custodian lineage is a handoff decision.
6. **Independence is the legacy vocabulary or a refusal.** `public-control`, `custodian-declared` and
   `procedural-separation` are kept verbatim with the original evidence class and the digest of the original
   statement text. Any other value (including "independent") refuses the scope. A claim of organizational
   independence refuses the scope; the only representable value is `not_claimed`.
7. **Contamination is carried, never cleared.** A legacy mark imports as contaminated. A reviewer's "none
   recorded" is recorded as that. "Unknown" (blind contamination has no machine-readable field) is never
   treated as clean and blocks the handoff gate.
8. **Local and protected paths are refused, not echoed.** A locator that is absolute, home-relative, a drive
   path, contains `..` or a backslash, or has a segment naming protected material (`generated`, `private`,
   `corpus.json`, `fixtures.json`, `state.json`, `ledger.json`, `archive`, `runs`, `seed`, `.lock`, ...) fails
   the whole extract with a fixed code. Labels are `[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}`: no spaces, quotes or
   slashes, so free text cannot ride in.
9. **Records are immutable and monotone.** Output records carry a facts-only identity
   (`lgi_` plus 32 hex of the domain-separated digest of the facts) so re-reading or re-reviewing the same
   facts is the same record. Applying a record to an import store: the same id is a no-op; a new id for a known
   scope must not lower consumption, change a stated limit, drop a mark, change or remove the independence
   claim or change the scope kind; it is stored as a new record linked to the one it supersedes, and a batch
   applies all or none. Duplicate scope statements in one extract refuse both.
10. **Parity is by metadata.** The dry-run report compares reported against imported consumption and receipt
    counts per scope, separates explained (conservative) from unexplained differences, and says in its own
    field that nothing was executed. Zero unexplained differences, zero refused scopes and zero unknown
    contamination are the figures the handoff gate reads. No protected data is rerun.
11. **No store migration here.** Writing consumed units into the runtime budget table is part of the reviewed
    cutover and needs a store adapter and migration owned by the operator CLI work (C10) and deployment (C12).

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Ambiguity, silence, unknown state and unsupported refusal count as consumed | `tests/legacy.rs` `ambiguity_counts_as_consumed` |
| Both budget scope kinds stay distinct; spent stays spent | `spent_stays_spent_and_both_budget_semantics_stay_distinct` |
| Independence vocabulary preserved; "independent" and organizational claims refused | `the_legacy_independence_vocabulary_is_preserved_verbatim` |
| Deterministic and order independent; stable identity | `import_is_deterministic_and_independent_of_scope_order` |
| Idempotent, monotone, atomic re-import | `reimport_is_idempotent_and_never_lowers_anything` |
| Malformed, oversized, path-like, protected-path and mismatched input refused | `malformed_ambiguous_and_path_like_input_is_refused` |
| No protected or local-path detail reaches any output | `canary_protected_details_never_reach_any_output` |
| Contamination carried and unknown never clean | `contamination_marks_and_unknowns_are_carried_never_cleared` |

## Adapter contract

`ImportStore` (`contains`, `latest`, `insert`) is the port; `MemoryImportStore` is the synthetic double. The
importer has no other port and no I/O.

## Failure and recovery

An extract that fails is refused whole or per scope with a fixed code and nothing is written. A crash while
applying cannot leave part of a batch (the in-memory store checks all records before inserting; a durable
adapter must make the batch atomic). Re-running the same extract is a no-op.

## Performance evidence plan

Not performance sensitive: bounded at 256 scopes, 64 attempts and 64 sources per scope, 1 MiB per extract.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Extract format, importer, dry-run report | yes | yes (synthetic) | no |
| Real extract of the legacy lifecycles | yes (maintainer) | no | no |
| Durable import store and budget write | yes (C10, C12) | no | no |

## Consequences, migration, exit

The extract schema is versioned; a change is a new major. The conservative rules can only be relaxed by a
reviewed policy revision recorded as a new ADR, never by an edit to an import record.

## Open risks and revisit triggers

Public metadata cannot show a crashed run, so most sealed epochs without an aggregate or attestation import as
fully consumed until a maintainer supplies a reviewed `custodian-statement` count; that is intended, and the
maintainer review of the mapping in docs/legacy-migration.md is a human gate. The blind carry-over records have
no defined budget effect in the legacy lifecycle and are evidence only (kind `carry-over`); a reviewer must list
the carried-to identity as its own scope with an explicit state. Revisit if a legacy record cannot be
classified: keep it consumed and flag it.
