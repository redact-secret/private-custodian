# 0122. Destination binding rollout, compatibility and the HG-2 disposition

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Builds on [ADR 0119](0119-public-projection-schema-major-2-with-a-signed-destination.md),
  [ADR 0120](0120-bound-release-flow-v2-signing-gate-and-ledger-domain.md) and
  [ADR 0121](0121-consumer-destination-verification-and-the-unbound-v1-outcome.md).

## Decision

1. **Overlap and retention.** v1 and v2 are both accepted by new readers. v1 golden vectors, the v1 schema and the
   v1 digest line are frozen (a test pins the v1 digest line). v1 is not given an end date here; removal of v1
   acceptance is a later reviewed change that needs its own ADR and a new reader version.
2. **Who emits what.** New releases should be prepared with `prepare_bound`. `prepare` (v1) stays as the
   documented legacy path. The bridge answers with whatever the approved catalog holds; it never converts a v1
   release into v2, because a v2 document needs its own digest, approval and signature.
3. **Reissue, not reinterpretation.** Making an old v1 release available as v2 means a new preparation, a new
   release approval and a new signature, under the usual budget rules. This ADR adds no tool for it.
4. **Wire.** Bridge request and manifest stay at major 1 (see ADR 0121 section 6).
5. **HG-2 disposition.** The code and test gap recorded in `docs/release-readiness.md` is closed: a consumer
   verifies destination binding from the signed envelope alone, and v1 is labelled. What remains is deployment
   work, not a design gap: a production caller of `prepare_bound` (D1), benchmarks adopting
   `require_destination_binding()`, and the signing key being authorized for the v2 domain when it is created.
6. **Evidence class.** This is functional verification with synthetic data and test keys. The project that
   maintains this repository also wrote the tests; it is not independent validation, and no protected run, real
   ledger write or benchmarks cutover has occurred.

## Verification map

| Claim | Evidence |
| --- | --- |
| v1 vectors unchanged, v2 vector added, second implementation agrees | `crates/custodian-contracts/tests/golden.rs`, `testdata/verify_golden.py` |
| Schema drift, closed and bounded, no leak path | `crates/custodian-contracts/tests/schemas.rs` (v1 and v2 directories) |
| Downgrade, upgrade, strip, unknown field, oversize, label bounds, revocation across majors | `crates/custodian-contracts/tests/destination.rs` |
| Signing gate, key scope per major, signature does not cross majors | `crates/custodian-ledger/tests/destination.rs` |
| Prepare/release/verify with destination; v1 legacy path | `crates/custodian-disclosure/tests/destination.rs` |
| Disclosure to ledger to bridge consumer round trip; `destination_unbound`; revocation | `crates/custodian-bridge/tests/destination.rs` |

## Failure and recovery

If a v2 defect is found, stop calling `prepare_bound` and issue v1; revoke affected v2 projections through the
existing feed (revocation targets are shared by both majors).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| HG-2 destination binding in the signed projection | yes | yes | no |
