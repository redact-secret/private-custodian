# 0121. Consumer destination verification and the unbound v1 outcome

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Builds on [ADR 0090](0090-benchmarks-bridge-contract-and-consumer-verification.md) and
  [ADR 0119](0119-public-projection-schema-major-2-with-a-signed-destination.md).

## Context

ADR 0090 stated that the reference consumer cannot verify destination binding and only checks an unsigned
manifest label. With v2 it can, for v2. v1 envelopes keep arriving until every release is reissued, and they must
never be mistaken for bound ones.

## Decision

1. **Verification.** `BridgeConsumer::verify_projection` decodes either major through
   `AnyProjectionEnvelope`, verifies the signature under the major's own domain (`verify_any_projection`), and
   then compares the signed destination with `ConsumerPins::destination`. A v2 mismatch is
   `Rejection::DestinationMismatch` (code `destination_mismatch`), decided from the envelope and the pins alone,
   with no catalog, manifest or ledger access. A tampered destination fails earlier as `bad_signature`.
2. **v1 is a distinct outcome.** A v1 projection that otherwise verifies is accepted with
   `VerificationOutcome::DestinationUnbound` (code `destination_unbound`); a v2 projection is
   `DestinationBound` (code `destination_bound`). `VerifiedProjection` exposes `major()`, `destination()`
   (`None` for v1), `binding()` and `outcome()`. There is no code path that reports a v1 projection as bound.
3. **Policy knob without breaking construction.** `BridgeConsumer::require_destination_binding()` (a builder
   method) rejects v1 with `Rejection::DestinationUnbound` (same code, `destination_unbound`). The default keeps
   accepting v1 with the label so existing callers behave as before. `ConsumerPins` gains no field, so struct
   literals elsewhere still compile.
4. **The manifest destination stays an unsigned routing hint** for both majors; its check (`wrong_destination`)
   is kept. A forged manifest label cannot make a v2 projection acceptable for a different pin.
5. **Service.** `BridgeService::answer` skips a catalog row whose v2 signed destination differs from the one the
   service answers for, in addition to the existing catalog destination check, and computes manifest digests with
   each envelope's own domain.
6. **Wire.** The request, manifest and response schemas are unchanged in structure (projections travel as
   canonical bytes of either major); only descriptions changed. The consumer does not announce support in the
   request: adding a request field would be a new bridge major, and the strict reader already rejects what it
   cannot parse.
7. **API compatibility.** Source compatible: `VerifiedProjection::projection()` still returns `&PublicProjection`,
   now documented as the version-neutral common-fields view (for v2 its schema tag is v1 and its digest is not the
   signed one; use `digest()`). Additive: `Rejection::DestinationMismatch`, `Rejection::DestinationUnbound`
   (`Rejection` is not `#[non_exhaustive]`, so an exhaustive `match` in a downstream crate must add two arms),
   `VerificationOutcome`, `VerifiedProjection::{major, destination, binding, outcome}`,
   `BridgeConsumer::require_destination_binding`, and `AnyProjectionEnvelope` in contracts.

## Security properties claimed

Wrong destination rejected; stripped, downgraded or upgraded envelopes rejected; v1 never reported as bound;
unknown fields, oversize and non-label destinations rejected; revocation entries (which target fields both
majors share) apply to both. Tests: `crates/custodian-bridge/tests/destination.rs`.

## Failure and recovery

All fixed codes, no input echoed. A consumer that cannot yet handle v2 rejects it as `malformed` (strict major
reader) rather than misreading it.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Destination verified from the envelope alone (v2) | yes | yes | no |
| v1 labelled `destination_unbound`, optionally refused | yes | yes | no |
| Benchmarks adopting these checks | yes | no (benchmarks repository) | no |

## Consequences, migration, exit

Benchmarks should call `require_destination_binding()` once the custodian issues v2, and treat any
`destination_unbound` result as evidence that cannot support a destination-specific claim (see
`docs/benchmarks-integration.md`). Exit: drop the builder call to accept v1 with the label.
