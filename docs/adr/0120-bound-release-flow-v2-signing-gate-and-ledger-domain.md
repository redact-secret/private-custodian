# 0120. Bound release flow: prepare for a destination, v2 signing gate, ledger domain

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Builds on [ADR 0119](0119-public-projection-schema-major-2-with-a-signed-destination.md),
  [ADR 0050](0050-receipt-signature-algorithm-keys-and-signer-isolation.md),
  [ADR 0060](0060-disclosure-service-flow-and-type-level-separation.md) and
  [ADR 0063](0063-publication-decision-approval-and-failure-codes.md).

## Context

ADR 0102 said the disclosure service would set the destination "after the policy check" and that `prepare` would
take the intended destination. The release approval binds the projection digest, so for the approval to cover the
destination, the destination must be part of the projection before the digest is computed, that is, at prepare
time.

## Decision

1. **`DisclosureService::prepare_bound(input, destination, now)`** builds a `PublicProjectionV2` from the same
   allowlisted builder as `prepare`, then `PublicProjectionV2::bind`. The destination must be in the policy's
   destination allowlist or the call fails with `destination_not_allowed` before anything is charged. The prepared
   release exposes `projection_v2()` and `destination()`; `digest()` is the v2 digest the approval must bind.
   `PreparedRelease::projection()` keeps its v1-shaped common-fields view for review and says it is not what is
   signed. `prepare` is unchanged and remains the legacy v1 path.
2. **`release`** refuses `destination_mismatch` when the request's destination differs from the one a bound
   release was prepared for, and delivers nothing. It signs through the new
   `ApprovedPayload::projection_v2`, which applies `Approval::check_for_release` to the v2 digest, so an approval
   for destination A cannot sign destination B, and an approval of the v1 digest cannot sign the v2 document. The
   signer's wire gate (`ApprovedPayload::from_wire`) accepts the v2 domain tag only with the release digest of the
   v2 document it decodes.
3. **Ledger signing domain.** `SignDomain::PublicProjectionV2` with tag `private-custodian/v2/public-projection`
   (the contracts tag, byte for byte), added additively to the table. Keys list signing domains explicitly: a key
   authorized for the v1 projection domain is not thereby authorized for v2, in the signer (`wrong_domain`) and in
   the verifier (`Verifier::verify_projection_v2`, `verify_any_projection`).
4. **Publication record unchanged.** `PublicationBody` already records `decision.destination` and the projection
   digest. For a v2 release the digest is the v2 digest, so the record is bound to the v2 document; for v1 it is
   as before. Existing record bytes and ids are untouched (no migration).
5. **`verify_release`** decodes either major. For v2 it also requires the signed destination to equal both the
   ledger decision's destination and the caller's expected destination (`destination_mismatch`). It returns
   `VerifiedRelease { binding }`: `Bound` for v2, `Unbound` for v1 even though the ledger decision names a
   destination (that proof needs the private record and is not a property of the envelope).
6. **`ReleasedEnvelope`** holds an `AnyProjectionEnvelope`; its `envelope()` accessor changes type accordingly.
   The only in-repository caller is the bridge service, updated here. `binding()` is added.

## Security properties claimed

Destination is chosen before the digest, approved with the digest, signed inside the payload, written to the
ledger decision, checked again at release and by every verifier. Tests: `crates/custodian-disclosure/tests/destination.rs`,
`crates/custodian-ledger/tests/destination.rs`.

## Failure and recovery

Every refusal precedes delivery: allowlist and mismatch checks run before audit acknowledgement and signing; a
failed release leaves the prepared release usable for its own destination. A retry with the same release key
replays the charge as before.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| `prepare_bound`, v2 signing gate, `SignDomain::PublicProjectionV2` | yes | yes | no |
| `verify_release` for both majors | yes | yes | no |
| A production caller of `prepare_bound` | yes | no (no daemon exists, HG-4) | no |

## Consequences, migration, exit

Callers that want destination binding switch from `prepare` to `prepare_bound`; there is no production caller yet
because the control service does not exist. Keys that should sign v2 need `private-custodian/v2/public-projection`
in their authorized domains (a key event, as for any domain). Exit: keep using `prepare`.
