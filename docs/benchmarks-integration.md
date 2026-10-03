# Benchmarks and engine integration

Maintained by the Redact Secret project. Describes the bridge contract, what benchmarks must verify, who owns
which deliverable in which repository, and unposted coordination text. Implemented in `crates/custodian-bridge`
with synthetic tests and test-generated keys; nothing is deployed. Decisions:
[ADR 0090](adr/0090-benchmarks-bridge-contract-and-consumer-verification.md),
[ADR 0091](adr/0091-legacy-metadata-import-rules.md),
[ADR 0092](adr/0092-reviewed-handoff-rollback-and-retirement-gates.md). Related:
[lifecycle and revocation](lifecycle-and-revocation.md) (feed), [disclosure](disclosure.md) (release),
[contracts](contracts.md), [legacy migration](legacy-migration.md), [responsibility map](responsibility-map.md).

Boundary: benchmarks has no private-ledger credential, no runtime-store access and no protected corpus access.
It sends a frozen identity and receives validated approved projections and revocation updates. Custody does not
establish independent ground truth; the repository is maintained by the Redact Secret project and its evidence is
not independent validation. Downstream code and CI edits are benchmark-owned and engine-owned deliverables:
this document records them and changes none of them.

## 1. The bridge

```
benchmarks                                   custodian (bridge service)
----------                                   --------------------------
BridgeRequest  ----------------------------> decode strictly (<= 4096 bytes, canonical, closed)
 domain, candidate digest, config digest,    look up approved releases for (domain, candidate, config)
 pinned feed id, last verified sequence,     keep only: this domain, candidate, population filter, channel
 optional public population filter           copy public feed envelopes known+1 ... (<= 32, no gap)
              <---------------------------- manifest + released projection envelopes (<= 16) + feed envelopes
verify (section 2) with public keys only
```

* Request: `private-custodian.bridge-request/1`, schema `crates/custodian-bridge/schemas/v1/bridge-request.schema.json`.
  Fields: `domain`, `candidate` (SHA-256 of the exact candidate bytes), `config` (digest of the frozen
  configuration benchmarks holds), `feed_id`, `known_sequence`, `populations` (at most 8 public population
  references; empty means any the product pins). No free text, path, internal identity or credential exists
  in the schema.
* Response: a manifest (`private-custodian.bridge-response/1`: request digest, feed id, channel label,
  projection digests, first and last feed sequence) plus the canonical bytes of each released
  `PublicProjectionEnvelope` (schema `public-projection.schema.json`) and each `SignedRevocationEnvelope`
  (`revocation-envelope.schema.json`). The manifest is unsigned and only routes the answer; every document a
  consumer relies on carries its own signature.
* Digest of a request: SHA-256 of `private-custodian/v1/bridge || 0x00 || canonical request`, as
  `sha256:` and 64 hex characters.
* Transport is not defined here. Whatever carries the bytes must give benchmarks the response without giving it
  a private-ledger, store or corpus credential.
* Only released envelopes can be returned: the custodian side takes them from the type a completed, approved
  release produces. An internal receipt, aggregate artifact, ledger record or unreleased projection has no path
  into a response.

## 2. What benchmarks must verify

`custodian_bridge::BridgeConsumer` is the reference and the test oracle. Benchmarks implements the same steps
in its own language; the golden vectors in `crates/custodian-contracts/testdata/golden/` fix canonical bytes and
digests.

Pin out of band, never from a response: the evaluation domain; the revocation feed id; the public verification
keys with the domains they are authorized for (`public-projection`, `revocation-envelope`); the channel label;
the public populations the product relies on; the disclosure policy versions the product accepts. An empty
population or policy pin list accepts nothing.

Per projection, in this order, rejecting at the first failure:

| # | Check | Rejection code |
| --- | --- | --- |
| 1 | At most 65,536 bytes; strict parse (unknown and duplicate fields, wrong schema tag, out-of-bound values rejected); bytes equal the canonical encoding. An envelope without a signature fails here | `malformed` |
| 2 | Ed25519 signature over `private-custodian/v1/public-projection \|\| 0x00 \|\| canonical(payload)` verifies under a pinned key that is authorized for that domain, not revoked and valid at `issued_at` | `bad_signature`, `key_not_acceptable` |
| 3 | `domain` equals the pinned and requested domain | `wrong_domain` |
| 4 | `candidate` equals the candidate digest benchmarks froze and requested | `wrong_candidate` |
| 5 | `population` is in the request filter (if any) and in the product's pinned population list | `wrong_population` |
| 6 | `disclosure_policy` is a policy version the product accepts | `policy_not_accepted` |
| 7 | `revocation_feed.feed_id` is the pinned feed | `wrong_feed` |
| 8 | Standing at `now` is valid: no entry revokes, contaminates or supersedes it (`revoked`, `superseded`); the feed state held is for that feed, at or beyond `revocation_feed.min_sequence` and not past its `fresh_until` (`stale`); `now` is not before `issued_at` (`stale`) and before the projection's `fresh_until` (`expired`) | `revoked`, `superseded`, `stale`, `expired` |

Per response: the manifest's request digest equals the digest of the request benchmarks sent
(`wrong_request`); its feed id equals the pin (`wrong_feed`); its channel label equals the pin
(`wrong_destination`); every accepted projection's digest is listed in the manifest (`manifest_mismatch`).
Feed envelopes are applied in sequence order through the verification steps of
[lifecycle and revocation, section 5](lifecycle-and-revocation.md) and stop at the first failure: a gap, a
fork (a correctly signed different document for an accepted sequence, an alarm never resolved silently), a
bad signature, a broken chain. Projections are judged on the feed state held after that, and a stale or
partial feed never validates (it can still revoke).

Re-evaluation: after every sync and on a clock tick, benchmarks re-evaluates every projection it relied on
and re-derives whatever it concluded from each one that stopped being valid
(`BridgeConsumer::reevaluate` reports only losses). Regaining validity after a renewal is not a trigger.

What the consumer cannot verify, and what to do about it:

| Limit | Consequence |
| --- | --- |
| Destination binding lives only in the signed private `publication` record. The channel label in the manifest is routing, not proof | Treat the channel as part of the transport's own authentication; a destination field needs a new projection schema major (open) |
| The configuration digest is not in the public projection | Benchmarks binds configuration on its own side; the candidate digest is the public binding |
| Omission cannot be detected | Absence never validates anything; rely only on what was verified |
| Population and policy meaning | The product decides which public populations and disclosure policy versions it accepts |
| Ground truth | `attestation` arrives unchanged: `ground_truth: not_established`, organizational independence `not_claimed`, independence only in the legacy vocabulary (`public-control`, `custodian-declared`, `procedural-separation`). None means independent |

## 3. What stays benchmark-owned

* Product qualification: thresholds, support status, accepted tradeoffs, release decisions, requalification
  rules, denominators and evidence-class separation (public synthetic against protected).
* The public review ledger is product adjudication that cites approved receipts. It is not the private audit
  export, never contains private audit records, case detail or budget internals, and is never populated by
  reading the private-ledger.
* Re-evaluating support when a projection stops being valid, and never re-running protected evaluation to
  refresh a page. A missing, stale or revoked projection never passes.
* Any change to the support-matrix shape that consumes this evidence is announced by benchmarks (issue 665 notes
  the `piiFamilies` shape).

## 4. Deliverables by repository

Custodian deliverables of C11 (this repository, done in this change): bridge request and response contract and
schemas; custodian-side service and catalog port; reference consumer; synthetic integration round trip and
rejection tests; legacy metadata import with dry-run report; handoff record and gates; rollback and
retirement gates; this document. Not done here and owned elsewhere: everything below.

| Owner | Deliverable | Depends on | Notes |
| --- | --- | --- | --- |
| private-custodian (later) | A real `ApprovedCatalog` over release records; a transport that serves the bridge; writing consumed legacy units into the budget store; cutover tooling through the operator CLI | C10, C12 | Not in C11 |
| private-custodian (later) | Destination field in the public projection (new schema major) | ADR | Open since ADR 0063 |
| pii-eval (`worker-result/1`) | Emit `private-custodian.worker-result/1` on stdout inside a custodian-authorized run, within the 64 KiB bound, with domain, protocol and roster counters only | custodian `docs/worker-isolation.md` | Not present in the repository today; pii-eval issue 13 owns the job contract jointly |
| pii-eval (aggregate artifact) | Emit the strict, closed `private-custodian.aggregates/1` artifact (domain, protocol, roster, integer numerator and denominator per policy stratum and metric, at most 256 cells, 64 KiB), bound to the receipt's roster counters | custodian `PrivateAggregates`, `docs/disclosure.md` | Never case identities, paths, seeds, ranges, per-case hashes, messages. Not present today |
| pii-eval | Keep the protected artifact internal (no publication code path); reject `population-binding-mismatch` and `run-class-mismatch`; synthetic custodian round trip that validates domain, candidate, activation and population bindings (issue 13) | custodian jobs | |
| credential-eval | The same two engine contracts for the credential domain: `worker-result/1` and `private-custodian.aggregates/1`, behind its own readiness | credential readiness | Holdout, blind and policy qualification are out of its current scope; no custodian issue exists. The only coordination item found is its compatibility retirement and consumer inventory issue (33) |
| redact-secret-benchmarks 665 | Consume custodian artifacts: implement the section 2 steps in the benchmarks client and CI; never read the private-ledger from CI; keep evidence classes and denominators separate; keep the support-matrix shape (or announce a change) | bridge, a real transport | Protected consumption verifies signatures, schema, candidate, configuration, population bindings and current revocation and freshness |
| redact-secret-benchmarks 664 | Parity on frozen synthetic populations (public data, dual run); reuse approved aggregate receipts where valid instead of protected reruns; reject wrong activation, candidate or population bindings | engine contracts | Protected parity must not rerun protected data; metadata comparison via the legacy dry run |
| redact-secret-benchmarks 666 | Switch authority and retire the legacy runner after the recorded oracle-exit period and a rehearsed rollback; disable the legacy runner for a population in the same change as its handoff; record engine tag and digest, contracts, artifacts, populations and policy revision; announce the switch | handoff record, 665 | PII readiness is not credential readiness |
| redact-secret-benchmarks 652 | Epic: keep the PII measurement extraction and the ownership statements consistent with this document; accept signed projections and freshness and revocation updates only | all of the above | |

Sequencing: contract design with the engines can proceed now. Runnable integration waits for the engines to emit
the two contracts and for a real catalog and transport. No protected execution happens until then, and none
without an explicit `Approval`.

## 5. Coordination comments (not posted)

These are drafts for the maintainer to paste. Nothing has been posted to any repository.

### redact-secret-benchmarks issue 652 (epic)

> private-custodian C11 (issue 12) now defines the benchmarks bridge: a closed, bounded request
> (`private-custodian.bridge-request/1`) carrying the frozen candidate and configuration digests, and a response
> of released projection envelopes plus public revocation feed envelopes. Benchmarks needs no private-ledger,
> runtime-store or corpus access. The verification checklist and rejection codes are in
> `docs/benchmarks-integration.md` of private-custodian, with a Rust reference consumer and a synthetic round
> trip. Product policy, support status and the public review ledger stay with benchmarks. Legacy lifecycles
> stay authoritative until a reviewed handoff; a metadata-only importer, dry-run report and handoff record exist
> but no cutover has been run. Destination binding is not consumer-verifiable today (it is in the private
> publication record); we propose a destination field in a future projection schema major.

### redact-secret-benchmarks issue 664 (P4 parity)

> For parity on frozen synthetic populations nothing changes. For protected state, private-custodian C11 compares
> by metadata only: the importer reads a reviewed extract of counts, labels and digests of committed public
> files, never a corpus, and reports reported against imported budget and receipt counts. Any ambiguity counts
> as consumed. A protected rerun is never used for parity, and any new protected execution needs an explicit
> execution Approval bound to the exact request and plan. Please reuse approved aggregate receipts where valid
> and keep rejecting wrong activation, candidate and population bindings, as the bridge consumer does.

### redact-secret-benchmarks issue 665 (P5 consume artifacts)

> The reference verifier is `custodian_bridge::BridgeConsumer` in private-custodian. Please implement the same
> steps: pin the feed id, public keys and their domains, channel label, accepted public populations and
> disclosure policy versions out of band; strict canonical decode; signature; domain; candidate; population;
> policy; feed id; then standing from the signed feed (revoked, contaminated, superseded, stale and expired are
> distinct, only valid may be relied on); apply feed envelopes in order and stop at a gap or fork; re-evaluate
> support for anything that stops being valid. Please keep the `piiFamilies` shape or announce a change. The
> response never contains the configuration digest or any internal identity. Attestation fields arrive as
> released: ground truth not established, organizational independence not claimed, legacy independence values
> only. Details and the full rejection table: `docs/benchmarks-integration.md`.

### redact-secret-benchmarks issue 666 (P6 switch authority and retire legacy)

> private-custodian C11 records the rollback and retirement gates in ADR 0092 and `docs/legacy-migration.md`:
> a population moves whole to one authority; a typed handoff record can only propose (it cannot express an
> executed cutover, a protected rerun or execution without Approval); gates are recomputed from the dry run; the
> legacy runner must be disabled for that population in the same change; rollback preserves every receipt and
> never resets a budget; credential cutover waits for its own readiness evidence. Retirement after your recorded
> oracle-exit period needs explicit maintainer authorization. Please cite your rollback rehearsal and the
> runner-disablement change as evidence on the handoff record. Please keep the pending and provisional
> semantics unchanged.

### pii-eval issue 13 (P12 consumer handoff)

> private-custodian defines two engine-facing documents that pii-eval does not emit yet. (1)
> `private-custodian.worker-result/1`: one JSON document on stdout, at most 64 KiB, with `status`
> (`complete` or `partial`), the domain, the protocol name and version, and roster counters
> (`expected`, `observed`, `failed`) that match the authorized roster. (2)
> `private-custodian.aggregates/1`: a strict, closed artifact of integer numerator and denominator per
> custodian-policy stratum and metric, at most 256 cells and 64 KiB, bound to the receipt's roster counters;
> no case identity, path, seed, range, per-case hash or message. Please emit both only inside a
> custodian-authorized run and keep the protected artifact internal. The bridge, the consumer verification
> steps and the rejection table are in private-custodian `docs/benchmarks-integration.md`; a synthetic
> custodian round trip that validates domain, candidate, activation and population bindings is the acceptance
> we propose to run together.

### credential-eval issue 33 (or a new issue if the maintainer prefers)

> For the credential domain, private-custodian will need the same two engine documents
> (`private-custodian.worker-result/1` and `private-custodian.aggregates/1`) when credential holdout, blind and
> policy qualification are brought under custody. The credential cutover is not forced: it waits for its own
> readiness evidence (ADR 0092). Please add the two contracts to the compatibility retirement and consumer
> inventory, and keep holdout, blind and policy qualification out of scope until then. Details:
> private-custodian `docs/benchmarks-integration.md`.

## 6. Planned, implemented, deployed

| Item | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Bridge contract, schemas, service, reference consumer, rejection tests | yes | yes (synthetic) | no |
| Benchmarks client and CI verification, support re-evaluation | yes (benchmarks) | no | no |
| Engine `worker-result/1` and aggregate artifact emission | yes (engines) | no | no |
| Real catalog, transport and serving endpoint | yes (C10, C12) | no | no |
| Destination field in the public projection | open | no | no |
| Legacy import tooling, handoff record, gates | yes | yes (synthetic) | no |
| Any legacy population handed off | yes | no | no |
