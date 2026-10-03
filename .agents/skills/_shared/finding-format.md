# Finding format

## Control verdicts

Report each applicable control as one of:

- `pass`: evidence cited (file:line, test name, ADR, or tool output).
- `fail`: the boundary or invariant is violated or unenforced; evidence cited.
- `not assessable`: the artifact needed to judge it does not exist yet (say which). In a design-baseline
  repository this is an honest and frequent answer; never convert it to `pass`.

## Finding fields

| Field | Content |
| --- | --- |
| Title | One line, names the boundary crossed |
| Severity | `critical` protected data or signing authority exposed, or budget/holdout bypass possible · `high` boundary unenforced or race permits double charge/release · `medium` weak control, partial mitigation · `low` hygiene, documentation gap |
| Location | `path:line` (or the document section when no code exists) |
| Precondition | What an attacker, buggy engine, or crash must provide |
| Impact | Which asset or invariant is affected |
| Evidence | Safe, synthetic, minimal; never protected content |
| Fix | Smallest change, plus the regression test that would catch it |

## Rules

- Rank most severe first. Separate security defects from design gaps and from documentation gaps.
- A confirmed active-test finding reproduces twice.
- Do not report scanner quality, metric values, or support status; those are out of scope here.
- State what was not checked and why.
- Do not propose changing approval, retention, budget, disclosure, or signer policy as a "fix" to make a
  failing job pass. Policy changes need an explicit reviewed revision.
