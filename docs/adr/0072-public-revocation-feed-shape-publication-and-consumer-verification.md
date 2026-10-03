# 0072. Public revocation feed: shape, publication and consumer verification

- Status: accepted (design); implemented in `custodian-lifecycle` and `custodian-store` (C9); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

C2 defined `RevocationEnvelope` and the consumer-side `RevocationLog` (chained, sequenced, freshness-bounded;
a stale feed can revoke but never validate; a prior receipt never overrides a revocation). C7 added the
`revocation-envelope` signing domain and `ApprovedPayload::revocation`. Benchmarks cannot read the private
ledger and consumes the feed (C11). The issue asks for safe signed revocation, supersession and contamination
envelopes with freshness metadata, a feed a public consumer can use without private access, and a consumer
that demonstrates freshness and revocation without corpus details.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Document shape | a new feed document type (new contract major); the existing signed envelope, one file per sequence |
| Discovery | an index or mutable "latest" pointer; sequential probing from `known + 1` |
| When an entry is created | at publish time from the operator; as a durable obligation in the decision's own transaction |
| Publish ordering | deliver then record; record then deliver |
| Concurrent publishers | a lock service; compare-and-swap on the sequence |
| Population target | internal epoch; the public reference the disclosure service uses |
| Freshness renewal | none; an empty envelope (the contract's own mechanism) |

## Decision

1. **The feed is the C2 envelope, unchanged.** Files `<feed_id>/<sequence, 10 digits>.json`, each the canonical
   `SignedRevocationEnvelope`, written once, never edited or removed. No new contract, schema or domain.
2. **No index, no mutable pointer.** A consumer asks for `known + 1` until absent; a missing `n + 1` with an
   existing `n + 2` is a gap. A mutable head would let an attacker replay an old head to hide a revocation.
3. **Entries are durable obligations.** A standing change records its obligation in the same transaction
   (`feed_obligations`), and operators record theirs with `record_revocation`. An obligation names internal
   targets; the publisher translates to the public form (public population reference via the same naming
   object the disclosure service uses, candidate digest, projection, receipt, policy reference). Nothing
   public carries an epoch, corpus, family, lineage, case, budget or actor.
4. **Publish = deliver the undelivered, then append, then deliver.** The envelope is signed through
   `ApprovedPayload::revocation` and the `Signer` (domain `private-custodian/v1/revocation-envelope`), then
   appended in one transaction that enforces contiguity and the `previous` link (code and trigger) and stamps
   its obligations published exactly once, then written to the destination, then marked delivered
   (insert-only). Delivery is in order. Every boundary is a fault point; a re-run finishes the work once.
5. **Concurrency by compare-and-swap.** Racing publishers cannot both commit a sequence; the loser re-reads.
6. **Freshness is renewed by an empty envelope** when the head would expire within `renew_margin_secs`;
   `fresh_until = issued_at + ttl_secs`. The destination contract is create-if-absent, identical repeat
   accepted, different bytes refused, in-order, readable without private access, holding only these documents.
7. **Consumer steps** (docs/lifecycle-and-revocation.md section 5): pin keys and feed id; sequential fetch and
   gap detection; strict canonical decode; feed id; signature under a pinned key for the domain; replay is
   harmless, a signed different document at an accepted sequence is a fork alarm, an unsigned imitation is a bad
   signature; sequence and `previous`; standing from `RevocationLog::standing`; re-evaluate what stopped being
   `Valid`. `FeedConsumer` is a working reference.
8. **A projection's feed reference** (`FeedRef`) must be obtained from `FeedPublisher::feed_ref`, which refuses
   while any obligation is unpublished, so `min_sequence` always covers every revocation known at preparation.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| A contamination reaches a consumer with no private access; no private detail in the bytes | `feed.rs::a_contamination_reaches...` |
| Stale, missing, other-feed or behind-`min_sequence` is `Stale`, never `Valid` | `feed.rs::freshness_is_renewed...`; `consumer_demo.rs` |
| Replay, fork, gap, misorder, broken chain, forged, wrong feed, non-canonical, unpinned or unauthorized key rejected | `feed.rs::replayed_forked_gapped...`, `a_gap_in_the_source...` |
| A signature is bound to its document type | `feed.rs::a_signature_is_bound_to_its_document_type` |
| One contiguous chain under concurrent publishers; each entry once | `feed.rs::concurrent_publishers...`; `epoch_standing.rs::two_publishers_racing...` |
| Crash at each publish boundary converges once | `feed.rs::what_a_crash_leaves...` |
| Destination outage keeps the envelope durable; conflicting destination never overwritten | `feed.rs::a_destination_outage...`, `a_destination_holding_different_bytes...` |
| Obligations are never removed or edited; a feed gap or fork cannot be committed | `epoch_standing.rs` raw-SQL assertions |
| An untranslatable target blocks publication, fail closed | `feed.rs::an_obligation_that_cannot_be_made_public...` |
| Supersession, candidate, policy entries and bulk splitting | `feed.rs::operator_entries...`, `more_than_one_envelope...` |

## Adapter contract

`FeedDestination` (write), `FeedSource` (read), `PublicPopulations` (epoch to public reference, normally
`RegistryPopulations` over the registry and `PublicPopulationNames`), `Signer` (C7), `OperatorAuthority`.

## Failure and recovery

Destination down: durable, stale for consumers, delivered later. Signer down or refusing: nothing appended.
Untranslatable target: `unpublishable`, eligibility still refuses. Clock behind the head: `clock_skew`.
Forged bytes at the destination: `destination_conflict`, human review.

## Performance evidence plan

One signature, one transaction and one destination write per envelope; measure them separately. Batch size is
at most 128 entries (the contract bound).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Envelope building, signing, storage, delivery, reference consumer | yes | yes | no |
| Real destination (static hosting or object store) and signer process | yes (C12) | no | no |
| Benchmarks-side consumer | yes (C11) | no | no |
| Destination field in projections | open | no | no |

## Consequences, migration, exit

No contract change. A new envelope major would need a new feed path and an overlap period. Entries are never
removed, so the feed grows; a compaction or checkpoint scheme is a future reviewed change that must keep the
chain verifiable.

## Open risks and revisit triggers

A consumer that never syncs fails closed forever (by design). `ttl_secs` trades consumer staleness against
publisher uptime. Revisit if feeds grow large enough to need checkpoints, or if a push channel is added.
