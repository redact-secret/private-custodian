# 0090. Benchmarks bridge contract and consumer verification

- Status: accepted (design); implemented in `custodian-bridge` (C11); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

Benchmarks must use protected evidence without ever reading the private-ledger, the runtime store or a
protected corpus (ADR 0003 item 6, C1 boundary). C8 released signed projections and C9 published the signed
revocation feed, but nothing yet defines how benchmarks asks for the evidence of one frozen candidate, what it
gets back, or what it must verify. `PublicProjection` has no destination field (ADR 0063), so a consumer
without the ledger cannot verify the destination binding. The issue asks for a request and response contract
benchmarks can implement in its own repository, a reference verifier, and a statement of what stays product
policy.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Transport shape | one signed bundle (a new signed contract and domain); a manifest plus the existing separately signed documents |
| Request content | candidate digest only; candidate plus frozen configuration digest, feed pin, read position and optional public population filter |
| What the custodian can return | any projection the filter selects; only a `ReleasedEnvelope` (the type a completed release produces) |
| Consumer feed logic | reimplement; wrap the C9 `FeedConsumer` |
| Destination binding | add a field now (new schema major); document the limit and check the channel label |
| Verifier location | inside the service crate only; a reference library with no store, ledger or corpus parameter |

## Decision

1. **Manifest plus existing documents.** A response is a small unsigned manifest
   (`private-custodian.bridge-response/1`) and the canonical bytes of each released
   `PublicProjectionEnvelope` and each `SignedRevocationEnvelope`. Nothing a consumer relies on is unsigned.
   No new signing domain, no new signed contract, no change to a v1 contract.
2. **Closed, bounded request** (`private-custodian.bridge-request/1`, at most 4096 bytes, canonical, unknown
   fields rejected): evaluation domain, candidate digest, configuration digest, the feed id benchmarks pinned,
   the last feed sequence it verified, and at most 8 public population references it will accept. No free
   text, path, internal identity or credential is representable. The response names the request by a
   domain-separated digest (`private-custodian/v1/bridge`), so an answer cannot be replayed against another
   request.
3. **Only released envelopes can leave.** `BridgeService` takes its projections from an `ApprovedCatalog`
   that returns `custodian_disclosure::ReleasedEnvelope`, which only a completed, approved release produces.
   It re-checks domain, candidate, population filter and the channel's destination, caps the count at 16 and
   copies feed envelopes unchanged from the public feed source (at most 32, from `known + 1`). It signs
   nothing, opens no store and reads no population. A gap in the feed or a request ahead of the feed head is a
   fixed refusal.
4. **The reference consumer verifies with public inputs only** (`BridgeConsumer`). Pins come from outside
   the response: the evaluation domain, the feed id, the channel label, the public verification keys (a
   `Verifier`), the public populations and disclosure policy versions the product accepts. An empty pin list
   accepts nothing. Per projection, in order and fail closed: size and strict canonical decode (a missing
   signature is malformed), signature under a pinned key authorized for the projection domain, domain,
   candidate, population, disclosure policy, feed id, then standing at `now` from the feed state held
   (`Valid` only; revoked, contaminated, superseded, stale, expired are each distinct). Per response: request
   digest, feed id and channel label match; feed envelopes are applied in order through the C9 `FeedConsumer`
   and stop at the first failure (gap, fork, bad signature, broken chain); projections are judged on the state
   after that. The consumer reports which tracked projections stopped being valid; it does not decide what the
   product does about them.
5. **Destination binding is a stated limit.** The destination is bound only in the signed `publication`
   ledger record, which benchmarks cannot read. The consumer checks the channel label the response says it
   was prepared for against its pin, and the service only includes releases approved for that channel. This is
   routing hygiene, not proof. A cryptographic consumer-side check needs a destination field in a new
   projection schema major (open, unchanged from ADR 0063).
6. **The configuration digest is custodian-side only.** It selects the approved release in the catalog but
   is not in the public projection, so a consumer cannot check it there. Benchmarks binds configuration on its
   own side (it froze it) and the candidate digest is the public binding.
7. **Completeness is not authenticated.** A response may omit a projection the custodian holds; absence
   never validates anything, and the consumer relies only on what it holds and verified. The manifest lists
   projection digests so an included but unlisted projection is rejected.
8. **Product policy and adjudication stay with benchmarks.** Whether a valid projection supports a claim,
   thresholds, support status and release decisions are not in this repository. The public review ledger
   records product adjudication and cites approved receipts; it is not the private audit export and nothing
   in the bridge reads or writes either.
9. **No new third-party crate.** `custodian-bridge` reuses `serde`, `serde_json`, `sha2` and `schemars` at the
   pins already in the workspace. `custodian-store`, `custodian-corpus` and `custodian-worker` are test-only
   dependencies. Because it wraps `FeedConsumer`, the crate links `custodian-lifecycle` and `custodian-ledger`
   transitively; the consumer module's public surface and source never use them for anything private, and
   tests enforce it.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Stale, wrong-domain, wrong-candidate, wrong-population, tampered, unsigned, foreign-key, revoked, contaminated, superseded, forked and gapped inputs are rejected | `tests/roundtrip.rs`, `tests/feed_lifecycle.rs` |
| The service returns only released envelopes for the requested candidate, domain, population and channel | `tests/roundtrip.rs` (`wrong_domain_candidate_and_population_are_rejected_on_both_sides`, `a_response_for_another_request_channel_or_feed_is_rejected`) |
| Requests and responses are bounded, canonical and closed | `tests/roundtrip.rs` (`the_service_refuses_bad_requests_and_unavailable_state_with_fixed_reasons`), `tests/schemas.rs` |
| Nothing private appears in the request, the response or the outcome | `tests/roundtrip.rs` (`nothing_private_appears_in_the_request_the_response_or_the_outcome`, canary identities) |
| The consumer API takes public inputs only | `tests/no_private_access.rs`, `compile_fail` doctest on `BridgeConsumer` |
| A stale or partial feed never validates | `a_stale_feed_never_validates_and_an_old_projection_expires`, `a_feed_that_goes_quiet_stops_validating_and_a_gap_stops_the_feed` |

Signatures and chains are tamper-evident, not tamper-proof. Nothing here makes custody an independent
validator: attestation fields arrive unchanged (`ground_truth: not_established`, organizational independence
`not_claimed`, legacy independence vocabulary only).

## Adapter contract

`ApprovedCatalog::released(&ReleaseQuery) -> Vec<ReleasedEnvelope>` is the only port that touches custodian
state. `FeedSource` (C9) is the public feed read side. A deployment implements the catalog over release
records and serves the bridge over a transport it chooses; this crate defines no transport.

## Failure and recovery

Catalog or feed unavailable: a fixed refusal, nothing partial is sent. Consumer: any rejection leaves
previously accepted state unchanged; a feed error stops the feed part at that point, later projections are
judged on the state held, and a stale state fails closed. A consumer that restarts re-reads the feed from
sequence 1; there is no mutable head to trust.

## Performance evidence plan

Measure request decode, catalog lookup, response assembly and consumer verification (signature check per
document) separately once a deployment exists. Bounds (16 projections, 32 feed envelopes, 64 KiB per document)
cap the work per request. No isolation or audit step is relaxed for speed.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Request and response contract, schemas | yes | yes | no |
| Custodian-side service and catalog port | yes | yes (synthetic) | no |
| Reference consumer | yes | yes (synthetic) | no |
| Benchmarks client, CI and support re-evaluation | yes (benchmarks) | no | no |
| Transport and serving endpoint | yes (C12 and deployment) | no | no |
| Destination field in the public projection | open | no | no |

## Consequences, migration, exit

A new wire major or a destination field is a new schema major and a new ADR. Benchmarks implements the
equivalent of the consumer steps in its own repository; this crate is the reference and the test oracle.

## Open risks and revisit triggers

Destination binding is not consumer-verifiable. Omission is not detectable. A catalog implementation that
returns a wrong release is caught only for domain, candidate, population and channel, so the catalog must be
reviewed with the release records. Revisit when a destination field is added or when a transport is chosen.
