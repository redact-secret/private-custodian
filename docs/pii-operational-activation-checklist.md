# Restricted activation checklist: operational protected PII path (issue 72)

Status: a checklist. **Every item is PENDING and unauthorized.** No host, key, policy, catalog, epoch, ledger
deploy key, feed destination or credential exists, and this document provisions none. Decisions: [ADR 0146](adr/0146-operational-protected-pii-path-authoring-sealing-policy-activation-keys-and-delivery.md)
(with ADR 0135, 0141 to 0145). The detailed host steps live in [server-prerequisites-checklist.md](server-prerequisites-checklist.md);
this list adds the PII-specific pins, owners and the two separate approvals. Pin values are filled in the private
operations store from [`deploy/examples/activation-pins.example.json`](../deploy/examples/activation-pins.example.json),
never in this repository, an issue, CI or a prompt. Evidence recorded here is project-maintained, not independent validation.

Roles are roles, not people (one person may hold several in solo-maintainer mode, ADR 0103; then the separation is procedural).

## Three separate approvals

| Approval | Status | Granted by completing this checklist? |
| --- | --- | --- |
| A. Restricted activation (the path below is provisioned and reviewed) | PENDING | this is what the checklist leads to; it authorizes no evaluation |
| B. First protected evaluation (a request, exact plan digest typed by an approver who is not the requester) | NOT AUTHORIZED | no |
| C. Benchmark authority cutover (checklist section 13, legacy-migration.md) | NOT AUTHORIZED | no |

B needs A complete and its own approval. C needs B's evidence and its own decision. Releasing any projection is a
further approval bound to the exact projection digest and destination.

## A. Items, owners, pins

| # | Item | Owner role | Exact pin to record (placeholder) | State |
| --- | --- | --- | --- | --- |
| A1 | Host and accounts, encrypted protected volume, backup (server checklist sections 1, 2) | operations | host class; volume encrypted yes/no | PENDING |
| A2 | Isolation self-check on the exact host image, `Verified`, no skipped success; isolation risk decision | operations, maintainer | `worker_image_manifest_sha256 = <PIN>`; self-check record id | PENDING |
| A3 | Pinned AMI and worker pins for the per-attempt EC2 worker (ADR 0142 to 0144); adapter selected in the daemon is NOT IMPLEMENTED | operations, engineering | `ami_id = ami-<PIN>`, manifest digest `<PIN>` | PENDING |
| A4 | Signer host, on-host Ed25519 key, out-of-band pins in `roots.json`, checkpoint copy and every consumer; key authorized for the v2 domains | signer custodian, maintainer | `signer_key_id = <PIN>`, `signer_public_key_hex = <PIN>` | PENDING |
| A5 | Rotation and compromise rehearsed on a throwaway key (publish/retire command NOT IMPLEMENTED; `repair revoke-key` exists) | maintainer | rehearsal date and codes | PENDING |
| A6 | Private ledger: resolve the non-empty repository (S6-1), writer deploy key, branch protection, access checks; coordinate private-ledger #9 to #12 by reference only | maintainer | first `(seq, chain) = <PIN>` | PENDING |
| A7 | Operator policy reviewed revision; credentials issued | maintainer, second reviewer | `operator_policy_sha256 = <PIN>` | PENDING |
| A8 | Disclosure policy reviewed: exact labels (nine plus `overall`), minimum sizes, composition, release and query budgets, destinations, freshness; values are (decide) | maintainer, second reviewer | `disclosure_policy_sha256 = <PIN>` | PENDING |
| A9 | Policy activation imported with exact id and sequence; daemon `required_activations` set | maintainer | `activation_id = <PIN>`, `sequence = <PIN>` | PENDING |
| A10 | Pinned engine, adapter, scanner/candidate, Node (aarch64) and engine config by file SHA-256; real engine run on public synthetic inputs (UNMEASURED, not yet run) | engineering | `engine_sha256`, `adapter_sha256`, `scanner_candidate_sha256`, `node_runtime_sha256_aarch64`, `engine_config_sha256` = `<PIN>` each | PENDING |
| A11 | Catalog authored and reviewed in the protected zone; epoch sealed and activated (CLI authoring command NOT IMPLEMENTED) | maintainer | `epoch_id = <PIN>`, `epoch_commitment_sha256 = <PIN>` | PENDING |
| A12 | Daemon config checked (`custodiand check-config`), binary pins recorded | operations | `control_binary_sha256`, `signer_binary_sha256`, `daemon_config_sha256` = `<PIN>` | PENDING |
| A13 | Feed and projection destination meeting the contract; transport NOT IMPLEMENTED; consumer pins (feed id, keys, domain, destination) | maintainer, benchmarks owner | `feed_id = <PIN>`, `destination_id = <PIN>` | PENDING |
| A14 | Public-synthetic end-to-end on the deployed host: pinned engine, isolated worker, durable state and export, v2 projection and feed, benchmark consumer; outages, restart, revocation, lost-evidence reevaluation. Evidence labelled synthetic | operations | run id, result codes | PENDING |
| A15 | Restore rehearsal with synthetic data, tabletop, incident owner reachable | operations, maintainer | dates | PENDING |
| A16 | Review sign-off for approval A, citing every pin above; records that B and C are not granted | maintainer | review note id | PENDING |

An item is ticked only with evidence recorded in the private operations log. A missing pin blocks A16. A changed
pin invalidates the review of everything that depends on it.

## What remains open after this checklist

Engineering: operator epoch-sealing command, key publish/retire command, authenticated transport, durable
EC2 attempt table and daemon selection of the EC2 adapter, upstream pii-eval adoption (#30), ARM64 measurements.
Decisions: every (decide) value above. None is made by this repository.
