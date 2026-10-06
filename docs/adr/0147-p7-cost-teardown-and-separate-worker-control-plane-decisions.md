# 0147. P7 cost model, teardown verification and separate worker and control-plane decisions

- Status: accepted (offline decision and tooling only); worker No-Go until live host evidence; control-plane NO-GO unchanged
- Date: 2026-10-06
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions
  are project-maintained, not independent validation.
- Tracking: issue #47 (P7) under epic #40; follows ADR 0133, 0134, 0136, 0140 to 0146

## Context

#47 asks for measured total cost, verified teardown and separate worker and control-plane decisions. No live
experiment has run: the EC2 worker exists as a design (ADR 0142), an adapter and janitor against a synthetic double
(ADR 0143, 0144), and an empty sizing template (ADR 0145). The real sandbox did not verify on Lambda MicroVM
(ADR 0136, 0140) and has never run its self-check on an EC2 host. ADR 0141's cost tables are placeholders.

## Options

| Option | Verdict |
| --- | --- |
| Publish a cost estimate from ADR 0141 numbers | Rejected: placeholders, would read as measured |
| Declare conditional Go on design review | Rejected: no live evidence, and ADR 0142 forbids skipped success |
| Defer all P7 work | Rejected: the cost model, teardown checklist and decision structure can be fixed offline |
| **Offline structure now, decisions at current evidence, measurements UNMEASURED** | **Chosen** |

## Decision

1. Adopt `docs/poc/ec2-p7-report.md` as the report and template, with `tools/poc/cost_estimator.py` and
   `docs/poc/ec2-cost-inputs.template.json`. The estimator refuses to emit any total unless every required
   component is MEASURED with billed unit, basis, quantity, unit price and source; ESTIMATE is refused; unknown
   components are refused. It applies no Lambda free-tier or discount assumption and reads no ADR 0141 figure.
2. Worker decision: **No-Go until live host evidence**. Control-plane decision: **NO-GO, unchanged** (ADR 0134,
   0136). They are separate; neither is upgraded and neither is conditional Go.
3. Fallback is the existing Linux backend with its single-host lifecycle and export gates (ADR 0133). No migration
   or cutover.
4. A P7 pass requires the report's teardown checklist: tag-scoped before/after inventory, instances observed gone,
   no residual billable resource unless in a retained register with owner and expiry, janitor sweep and next-day
   billing check. Residuals not in the register fail P7.
5. PoC success never authorizes production custody. Production follow-up blockers are listed in the report; closing
   them still requires a reviewed policy revision and explicit authorization.
6. Private-ledger #8/#2 hand-off is documentation only; nothing is activated and ledger changes stay proposals.

## Security properties claimed

- The estimator cannot produce a cost total from unmeasured input: `tests/poc-cost` (template refusal,
  one-unmeasured, ESTIMATE, missing/unknown/null/negative/NaN, CLI exit code and no total on refusal).
- Not claimed: any measured cost, verified teardown, live isolation, or independent validation.

## Failure and recovery

Offline tooling only; no mutating operation, no store, no AWS call, so no idempotency or concurrency semantics
apply. A live run that aborts leaves its tag-scoped inventory to the janitor (ADR 0144) and the teardown checklist.

## Performance evidence plan

Measure the windows listed in the report on one immutable image, N>=5, without relaxing isolation. Record billed
units from the account's own billing data, not list prices.

## Consequences, migration, exit

No policy, schema, budget or signer change; no migration. Revisit when a live experiment is authorized under #40: the
worker decision changes only by a new ADR citing the recorded live evidence.

## Open for #47

Live measurements, live teardown evidence, actual billed units and the sanitized linked child evidence remain open;
the acceptance items needing a live host are not met.
