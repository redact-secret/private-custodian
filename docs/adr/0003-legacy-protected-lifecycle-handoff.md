# 0003. Legacy protected lifecycle handoff

- Status: accepted (design baseline)
- Date: 2026-10-02
- Deciders (by role): repository maintainer (single human operator)
- Maintenance: project-maintained; not independent validation.

## Context

The benchmark repository already runs protected lifecycles (in-repo holdout, six-family PII protected
corpus, custodian-held blind evaluation, credential policy holdout receipts). They have spent budgets,
receipts, sealed epochs and contamination records. The new custodian must not reset, reinterpret or erase
them. The inventory and per-lifecycle map are in [../responsibility-map.md](../responsibility-map.md).

## Decision

1. **The current lifecycle stays authoritative until a reviewed handoff** (C11). Until then the custodian
   authorizes and executes nothing against a population that a legacy lifecycle still governs.
2. **No receipt is erased and no exhausted budget is reset.** Legacy aggregates, seals, ledgers, freezes and
   contamination marks are imported as immutable prior evidence. Each legacy spent attempt becomes a
   consumed budget unit in the matching custodian budget scope. If the legacy record is ambiguous, the unit
   is treated as consumed.
3. **Budget scopes must be modelled for both legacy semantics**: per-corpus (or per-family) epoch attempts in
   the holdout lifecycle, and per-candidate-identity-per-epoch attempts in the blind lifecycle. C2 and C4
   must not collapse them into one counter.
4. **Contaminated or rotated epochs stay contaminated.** Evidence consumed from an epoch marked
   contaminated remains invalid for independent qualification; migration cannot clear a mark.
5. **Handoff gate.** A population moves only after: inventory reviewed by the maintainer; import dry run
   showing zero unexplained differences between legacy and imported budget and receipt counts; benchmarks
   verifying signed envelopes with freshness and revocation (C9, C11); rollback rehearsed; legacy runner
   disabled for that population in the same change. Partial dual authority over one population is refused.
6. **Benchmarks never reads the private-ledger.** It receives signed approved projections and revocation
   updates through the public contract.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Inventory and map (docs) | yes | yes, documentation only | n/a |
| Import tooling and dual-run check | yes (C11) | no | no |
| Handoff of any population | yes (C11) | no | no |

## Consequences, open risks

Legacy facts live in benchmark-side files whose exact schemas C11 must read. Where the legacy lifecycle
records a custodian only by local convention, the importer must not invent provenance. Revisit if a legacy
record cannot be classified: keep it consumed and flag it.

## Update (C11)

The import tooling, dry-run report and handoff record now exist as synthetic-tested library code (ADR 0091 and
0092, `docs/legacy-migration.md`). The status table above is unchanged for the handoff itself: no population has
been handed off and nothing is deployed.
