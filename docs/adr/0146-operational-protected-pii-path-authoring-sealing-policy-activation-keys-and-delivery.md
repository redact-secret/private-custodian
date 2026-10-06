# 0146. Operational protected PII path: authoring and sealing, policy activation, signer keys, delivery

- Status: accepted (the procedure and its gates); every operational step is PENDING and unauthorized
- Date: 2026-10-06
- Deciders (by role): project maintainer
- Maintenance: project-maintained decisions and evidence, not independent validation.
- Tracking: issue #72 (parent #1; host feasibility #40). Offline documentation and template portion only.

## Context

Issue #72 asks for the path from a sealed catalog to a signed publication and revocation to be prepared, not
activated. ADR 0135 and ADR 0145 already decided the custodian-owned PII contracts (one entry is one authored
case, embedded aggregates, the nine-label `overall` profile, file digest vs tree digest). Those are decided and
are not open questions. What is open is operational: the real catalog, the real policies, the real signing
key, and a consumer transport. ADR 0141 to 0144 select the EC2 worker arrangement. None of it is deployed, no
protected data was used, and this ADR creates no key, policy, epoch, host or credential. The control functions
stay on a long-lived custody control host; the optional serverless migration (#46) is not assumed.

## Decision

The operational path is the ordered steps below. Each step is a human, reviewed act with evidence in the private
operations log (never this repository, CI or the private ledger). Nothing here grants authority; a step that does
not exist in code is marked NOT IMPLEMENTED and must not be described as available.

### 1. Catalog and entry authoring, epoch sealing

State today: `custodian-corpus` implements `begin_epoch`, `add_entry`, `seal`, `activate`, `retire` and
`verify_epoch` (docs/protected-storage.md) on synthetic data. There is **no operator command** to author or seal
a real epoch: NOT IMPLEMENTED at the CLI; the sealing procedure is programmatic only.

1. Authoring is engine-owned (ADR 0135 Q1): one authored case per opaque flat entry in the engine's
   `pii-eval-worker-entry/1` format. The custodian counts entries and never interprets, scores or edits them.
2. Real catalog content is authored and reviewed only inside the protected zone. It never appears in an issue,
   Git, a build image, Actions, a prompt or a log. Public synthetic data is the only content used anywhere else.
3. Review attestation is recorded before sealing (`not_reviewed` is refused). The reviewer is a role, not a model.
4. `seal` binds the configuration digest, budget scope, provenance and review attestation. A sealed epoch is
   immutable: any change is a new epoch with a new seal and, by policy, a new budget. The old epoch stays as
   evidence.
5. `activate` makes the epoch usable and `retire` ends its use. Standing (contamination, retirement) follows
   docs/lifecycle-and-revocation.md; only a human clears an unreviewed change.
6. Record, as separate identities that are never substituted for each other: custody commitment, semantic
   population digest (engine-owned), engine file digest, adapter, scanner and Node file digests (architecture
   specific), configuration digest, candidate digest, plan digest. A mismatch of any refuses.
7. Durable exposure and export gates are authoritative (ADR 0116, 0144): inputs reach a worker only after
   exposure is written and the export is acknowledged; exposed uncertainty stays consumed; no refund.

### 2. Operator policy and disclosure policy activation

1. Operator policy: a reviewed revision (identities, roles, credential digests, validity window). Agents hold
   only `requester`; services only `requester` and `auditor` (docs/operator-runbook.md).
2. Disclosure policy: a reviewed, versioned document with exact labels, minimum stratum sizes, composition
   relations, release and query budgets, destinations and freshness (docs/disclosure.md). The label set for the
   case-based PII profile is closed to the nine labels in docs/pii-eval-adoption.md plus stratum `overall`;
   `measurable-share` stays engine-private. Any other label or stratum needs a new reviewed revision.
3. The numeric values (minimum sizes, budgets, freshness) are **(decide)** items. This ADR chooses none of them.
   The synthetic test policy is never copied into an operational activation (HG-9 stays open).
4. Activation: `policy import-activation --document F --confirm-activation-id A --confirm-sequence N` appends a
   state with a higher sequence; the daemon names `release.policy_activation` and `required_activations`.
   A superseded or revoked activation makes a bound plan stale; a new activation means a new plan and request.
5. `custodiand check-config` and `custodian policy validate` must pass before anything starts. A model never
   approves a plan, widens access, expands a budget or changes policy.

### 3. Signer key setup, out-of-band pins, rotation, revocation, backup

The procedure is already specified and synthetically tested; this ADR only places it in the activation order
and does not restate it: docs/signer.md, docs/backup-recovery.md section 7, ADR 0050, ADR 0131.

- The Ed25519 root key is generated on the signer host (never a developer machine or CI), under a uid the
  control uid cannot become. Only the public key is recorded.
- The public key is pinned out of band in the operator `roots.json`, the independent checkpoint location and every
  consumer; never taken from the ledger or the feed. The key must be authorized for the v2
  `public-projection` and `revocation-envelope` domains before a consumer relies on it (HG-2 remaining item).
- Rotation (planned) and compromise (re-issue under a new key, R-4/R-5/R-6) are rehearsed on a throwaway key with
  synthetic data before relying on either. Operator command for publishing and retiring a key for planned
  rotation: NOT IMPLEMENTED (S6-2); revocation has `repair revoke-key`.
- Key backup is a recorded decision; the recommended default is no backup (backup-recovery.md 7.1).
- Private-ledger repository work (private-ledger #9 to #12, #15) is coordinated by reference only. This ADR
  changes nothing there and assumes none of its outcomes. The existing non-empty ledger repository finding
  (S6-1) must be resolved first.

### 4. Bounded authenticated projection and feed delivery with destination binding

Implemented (synthetic, test keys): the signed public projection major 2 with `destination` inside the signed
payload, the release approval that binds the v2 digest, the revocation feed envelope with `fresh_until` and
bounded new entries, the `FeedDestination` contract (create-if-absent, identical bytes accepted, different
bytes refused, in order) over in-memory and directory doubles, the bridge response bounds and the reference
consumer that rejects `destination_mismatch`, `wrong_feed`, `revoked`, `superseded`, `stale` and `expired`.

NOT IMPLEMENTED: any authenticated network transport, object-store or HTTPS destination, TLS endpoint,
consumer-side fetch client, and a production replacement for `DirFeed::put` (S-8). "Authenticated" therefore
means, today, signature verification against out-of-band pins plus a write identity restricted to the control
service; there is no network-level client authentication, and none is claimed. A transport is a separate ADR with
its own tests (replay and conflict refusal, partial write, outage and restart, revocation first). The consumer
sees approved signed outputs only and never the ledger, the store or the corpus.

The shape for the destination and bounds is `deploy/examples/protected-delivery.example.json`.

### 5. Evidence classes and the two further approvals

Synthetic evidence is never labelled live protected. The restricted activation (this path provisioned and
reviewed), the first protected evaluation, and the benchmark authority cutover are three separate approvals,
none of which implies another. The checklist is [../pii-operational-activation-checklist.md](../pii-operational-activation-checklist.md).

## Security properties claimed

Only what exists: contract and flow tests listed in ADR 0135, 0145 and docs/release-readiness.md, and the
placeholder scanner and PENDING checks in `crates/custodian-daemon/tests/deploy_examples.rs`
(`the_custody_arrangement_templates_are_pending_and_authorize_nothing`,
`the_activation_pins_keep_the_three_approvals_separate_and_every_pin_empty`,
`the_topology_keeps_control_functions_off_serverless_and_the_signer_key_off_the_control_host`). Not claimed: any
host, key, policy, epoch, transport, real engine result or ARM64 measurement.

## Failure and recovery

No state mutation is introduced. Existing idempotency and recovery stand: epoch seal is atomic and immutable;
policy import is append-only with a higher sequence; feed publication is create-if-absent and in order, so a
retry after a crash is safe and a conflicting write is refused. Unavailable signer, store or ledger fails closed.
A lost-evidence reevaluation is a new request, plan and budget decision, never a reset.

## Consequences, migration, exit

Documentation and templates only; no schema or protocol change. Open engineering follow-ups, not authorized by
this ADR: operator authoring/sealing command, key publish/retire command, authenticated transport, durable
EC2 attempt table and daemon selection of the EC2 adapter. Revisit when an authorized host exists.
