# 0061. Disclosure policy document and suppression algorithm

- Status: accepted (design); implemented in `crates/custodian-disclosure` (C8); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ARCHITECTURE.md requires minimum stratum sizes, allowable dimensions and composition rules before repeated
public comparisons, says suppressing individual small cells is insufficient when overlapping totals reveal
them, and forbids silent noise. The public contract can represent a suppressed cell and nothing else
(integer counts, `reported` or `suppressed`).

## Options

| Choice | Alternatives considered |
| --- | --- |
| Primary rule | denominator below a minimum; also suppress extreme values; both |
| Secondary protection | none; second cell by rule; exact determination plus interval width over declared relations |
| Candidate choice | smallest denominator; random; policy order |
| Statistical mechanism | none; rounding; noise (differential privacy) |
| Composition | per release; over a population series |

## Decision

1. A `DisclosurePolicy` document (`private-custodian.disclosure-policy/1`, canonical, closed, versioned,
   digest in the ledger `policy` record) holds the allowlists, relations, `min_stratum_size`,
   `min_interval_width`, the perturbation (`none` only), budgets, destinations and freshness (docs/disclosure.md
   section 3).
2. Primary rule: denominator below `min_stratum_size`. A rule on extreme values (numerator 0 or equal to the
   denominator) is **not** adopted: it would make the suppression pattern depend on the secret value; the
   leakage it leaves is documented as residual.
3. Secondary protection: for numerators and denominators separately, find unknown cells that are determined by
   the relations (exact rational row reduction, `i128`, checked overflow fails closed) or whose
   propagated interval is narrower than `min_interval_width`; withhold the first cell in **policy order**
   that shares a relation and removes the exposure; repeat; refuse (`composition_unresolvable`) if none.
   Policy order, not denominators, keeps the pattern independent of withheld values.
4. Composition: the same procedure runs over the union of knowledge from earlier releases of the population
   series (numerators per measurement, denominators per population) and the union of relations. Contradicting
   an earlier release is `measurement_conflict`.
5. No perturbation. The only representable mechanism is `{"mechanism":"none"}`. Rounding or noise is a new
   policy schema major whose ADR states the measurement consequences (bias, variance, effect on rank
   comparisons) before it exists.
6. The residual leakage is stated in docs/disclosure.md section 4: undeclared relations, bound propagation is
   not linear programming, uniform outcomes in reported cells, suppression as a signal, adaptive tuning,
   timing and error channels, external knowledge.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| A naive publication is differenced; the real one is not | `tests/composition.rs::naive_primary_only_publication_is_differenced_but_real_suppression_is_not` |
| Overlapping totals cannot difference a withheld cell | `composition.rs::overlapping_dimensions_cannot_be_used_to_difference_a_withheld_cell` |
| Successive releases cannot difference a withheld cell | `composition.rs::successive_releases_cannot_difference_a_withheld_cell`, `denominators_compose_across_different_candidates_on_one_population` |
| Randomized tables and sequences stay unpinned against a brute-force oracle | `composition.rs::randomized_tables_and_release_sequences_never_pin_a_withheld_cell` |
| A cycle that single-unknown solving misses is found | `src/suppress.rs` unit test `exact_solver_finds_a_three_way_cycle...` |
| Contradiction and unsafe releases are refused | `composition.rs::a_release_that_contradicts_an_earlier_one_is_a_conflict`, `a_release_that_cannot_be_made_safe_is_refused` |
| Policy is closed; noise is unrepresentable | `release.rs::policy_documents_reject_unknown_fields_and_inconsistent_structure` |

## Adapter contract

Pure functions (`suppress`, `compose::decide`) with no I/O; history is read and appended through
`DisclosureStore` (ADR 0062).

## Failure and recovery

Unreadable history, overflow, contradiction and unresolvable structure refuse the release; nothing is
published. A refused attempt after the charge stays charged.

## Performance evidence plan

Bounded by 256 cells, 64 relations and 32 parts per relation; row reduction is cubic in the unknown columns.
Measure with maximum-size policies before enabling large strata sets.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Policy, exact and interval protection, composition | yes | yes | no |
| Linear-programming interval test | no | no | no |
| Rounding or noise | no | no | no |

## Consequences, migration, exit

Policy values (minimum size, width, relations, order, budgets) are placeholders for tests. A real policy is an
explicit reviewed revision with its own activation. Tightening is a new version; loosening needs review.

## Open risks and revisit triggers

Revisit for a stronger interval test (LP) if strata structures become cyclic, for extreme-value protection if
small uniform strata are published, and for any statistical mechanism.
