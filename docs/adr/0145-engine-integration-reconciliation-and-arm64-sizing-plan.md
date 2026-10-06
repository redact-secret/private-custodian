# 0145. Engine integration reconciliation (#37 vs ADR 0127) and the ARM64 sizing measurement plan

- Status: accepted (reconciliation and offline contract tests); the real-engine run and every ARM64 measurement are
  open and UNMEASURED
- Date: 2026-10-06
- Deciders (by role): project maintainer
- Maintenance: project-maintained decisions and evidence, not independent validation.

## Context

Issue #45 asks for the pinned credential and PII engines to be run on public synthetic inputs and for Node and
Rust startup and headroom to be re-measured on the exact ARM64 EC2 host (ADR 0141 to 0144, after ADR 0140's
failed MicroVM self-check). Only the offline part can be done here. The real pinned engines were not available in
this offline work (no pinned artifacts were fetched, the development host is x86_64 macOS), and test-only engines
are not substituted for them. ADR 0127 and ADR 0135 already decided most of the #37 questions; this ADR records
the reconciliation in one place and the rules that stay fixed.

## Decision

1. **Embedded aggregates.** Unchanged from ADR 0127/0135: one optional `aggregates` object inside the single
   `worker-result/1` stdout document, 64 KiB for the whole document. Additive; results without it stay valid and
   close as `no_aggregates`. No scratch file, stderr or second stdout document.
2. **Digest identities stay distinct.** The candidate or adapter archive is pinned by the SHA-256 of the exact
   file the custodian stages. The extracted tree digest is engine-owned evidence computed after safe extraction in
   scratch; it is never substituted for the file digest, and a mismatch of either refuses. Semantic population
   digest and custody commitment are further, separate identities.
3. **Node placement.** Node is an engine-declared runtime artifact (scanner-0 slot), pinned by file digest like
   the other artifacts, staged read-only under `/stage`. The custodian never resolves Node from the host `PATH`
   and never runs it outside the sandbox. Architecture is part of the pin: an x86_64 Node digest is not an
   ARM64 pin.
4. **Allowed PII labels and roster units.** The case-based PII profile publishes only stratum `overall` and the
   nine labels in `docs/pii-eval-adoption.md`; one roster unit is one authored case. `measurable-share` and any
   other label stay engine-private. Cells are kept exactly or refused: `numerator <= denominator <= observed`,
   no clamping, rescaling or substitution, duplicates refused. Additional labels or strata need a reviewed
   disclosure policy revision. This is a profile, not an activated policy (HG-9 stays open).
4a. **Hostile output.** Engine stdout is untrusted. Attestation fields come only from the plan, approval and
   daemon declaration (ADR 0127); `worker-result/1` and `private-custodian.aggregates/1` are closed
   (`deny_unknown_fields`), so an engine cannot add or mint an attestation, receipt, signature or outcome.
5. **Pre-exposure runtime probe and minimum declaration.** Still deferred (ADR 0135 P-B/P-C). If adopted later,
   the probe must run only inside the sandbox, with no corpus mount and a bounded protocol, and a declared
   minimum is approver metadata bound to runtime/engine/scanner file digests, architecture and limit profile; it
   never raises a limit and is not a core-protocol field. Until then the existing sandbox self-check is the only
   pre-exposure gate. A real startup failure after exposure is settled by the existing consumed-after-exposure
   rules.
6. **Memory vocabulary.** `RLIMIT_AS` bounds virtual address space per process, not resident memory, VM RAM or
   tmpfs scratch pages; a runtime such as Node may reserve far more address space than it touches. The
   measurements in the plan therefore record, separately: the enforced RLIMIT_AS, peak resident set, host
   baseline (OS, agent, sandbox tooling) and burst headroom, and instance memory. None substitutes for another.
7. **`--jitless`.** Not a custodian default and never applied automatically. It is an explicit, engine-declared
   launch option, part of the pinned job/config identity, and is measured as a separate profile because it
   changes performance and possibly behavior. The custodian does not treat it as a memory fix.
8. **Sizing evidence.** `docs/arm64-sizing-measurement-plan.md` is the template. Every value is `UNMEASURED`
   until recorded from the exact ARM64 host under an authorized experiment. The x86_64 Node v22 measurements
   cited in ADR 0135 are evidence for that runtime and runner only and are never ARM64 proof.

## Security properties claimed

Offline synthetic tests: `crates/custodian-worker/tests/contract_compat.rs` (exact `worker-job/1` keys,
additive aggregates, closed `worker-result/1`, hostile attestation-shaped fields refused, outcome only from roster
counters) and `crates/custodian-disclosure/tests/aggregate_contract.rs` (fail-closed aggregate binding, no
clamping, nine-label profile, `measurable-share` and foreign strata refused by policy). Not claimed: that any real
engine emits these documents, that the pinned engines pass, or any ARM64 sizing.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Contract tests on synthetic documents | yes | yes | no |
| Both pinned engines run on public synthetic inputs | yes | no (engines unavailable offline) | no |
| ARM64 startup, resident memory, headroom | yes | no, UNMEASURED | no |
| Pre-exposure probe / minimum declaration | deferred | no | no |

## Consequences, migration, exit

No schema, protocol or policy change; tests and documents only. Revisit when pii-eval #30 ships production
adoption and an authorized ARM64 host experiment (#40, #72) exists.
