# 0119. Public projection schema major 2 with a signed destination

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Supersedes the design recorded in [ADR 0102](0102-deferred-destination-binding-and-legacy-consumption-import.md)
  for destination binding (0102 still holds the legacy consumption design). Follow-up of issue #31, epic #27.

## Context

`PublicProjection` v1 has no destination field. The destination was enforced by the bridge service and by the
signed `publication` decision in the private ledger, so a consumer holding only public inputs could not verify
that an envelope was approved for the destination it arrived from (HG-2). `docs/contracts.md` section 8 makes
any additive change a new schema major with its own golden vectors, forbids reinterpreting stored records, and
requires a new domain tag version for any new signing input.

## Decision

1. **Schema major 2.** `private-custodian.public-projection/2` (`public_v2::PublicProjectionV2`) has every v1
   field plus `destination: DestinationId`. The envelope is `PublicProjectionEnvelopeV2` (`payload`,
   `signature`). Schema file: `crates/custodian-contracts/schemas/v2/public-projection.schema.json`. v1's schema
   file, types and golden vectors are not edited.
2. **New domain tag.** `private-custodian/v2/public-projection` (`DomainTag::PublicProjectionV2`). The digest and
   the signing input of a v2 document use it, so a v1 and a v2 document never share a digest or a signature, even
   for byte-identical payloads. The tag list in `DomainTag::ALL` grows to ten; the v1 tags are unchanged.
3. **The destination is a bounded label.** Same type as the policy vocabulary (`DestinationId`:
   `[a-z0-9][a-z0-9._-]{0,63}`), so no URL, path, host with a scheme, query, credential or free text can be
   represented. It is allowlisted by the disclosure policy when the projection is prepared. The projection
   allowlist, bounds (cells 256, document 65,536 bytes) and cross-field checks are shared code
   (`public::validate_common`) so the majors cannot drift apart.
4. **Strict readers, no merge.** A reader of a major accepts exactly that major. `AnyProjectionEnvelope::decode`
   only chooses which closed decoder to apply from the payload's schema tag; any other tag, a v2 body labelled v1
   (unknown field), a v2 body with its destination removed (missing field) or a v1 body labelled v2 (missing
   field) is rejected, and a stripped body relabelled v1 fails the signature, which was made under the v2 domain
   over different bytes.
5. **v1 stays decodable and verifiable and is labelled.** `AnyProjectionEnvelope::binding()` returns
   `DestinationBinding::Unbound` for v1 and `Bound` for v2. Nothing converts a stored v1 record. See ADR 0121 for
   how the consumer reports it.
6. **Version-neutral view.** `PublicProjectionV2::common_fields()` returns the v1-shaped common fields for code
   that only needs them (revocation targets, feed tracking). It is a derived view, never signed or digested as a
   document, and its documentation says so. This keeps `custodian-lifecycle` and the revocation contract
   unchanged: revocation entries target only fields both majors share.
7. **Second implementation.** `verify_golden.py` reproduces the new vector from the written rules and checks the
   destination-binding shape (exactly one added member, bounded label, v1 without destination, tag separation).

## Security properties claimed

- A consumer verifies destination binding from the signed envelope and its own pins alone (ADR 0121).
- The release approval binds the v2 projection digest, so it covers the destination: an approval for destination
  A cannot sign destination B, and an approval of the v1 digest of the same fields cannot sign the v2 document
  (ADR 0120).
- Tampering with the destination fails signature verification; moving a signature between majors fails it.
- No new leak path: the only added field is the bounded label, enforced by the type, the schema and a test that
  asserts the added member set.

Not claimed: that the destination label is the right place to publish, anything about the transport, or that v1
documents already issued were released to any particular destination.

## Failure and recovery

Fails closed: an unknown major, tag or field is `malformed`; a wrong or altered destination is a signature or
destination failure with a fixed code. Stored v1 documents remain readable and verifiable under v1 rules; there is
nothing to migrate. Rollback is to keep issuing v1 (`prepare`), which stays available.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Schema major 2, domain tag, golden vector, second implementation | yes | yes | no |
| Destination in the signed payload, verified without a catalog | yes | yes | no |

## Consequences, migration, exit

Additive: new type, new schema directory, new tag, new golden line (appended). Downstream readers of major 1
keep working on v1 documents and reject v2 documents until upgraded. Regeneration: `UPDATE_SCHEMAS=1 cargo test
-p custodian-contracts --test schemas` (writes `schemas/v2/` too) and `UPDATE_GOLDEN=1 cargo test -p
custodian-contracts --test golden`; review the diff, then record the change in an ADR.
