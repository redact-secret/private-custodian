# Architecture decision records

Decisions the baseline left open (runtime, durable store, isolation, key provider, topology, schemas, policy)
are recorded here. Use [template.md](template.md). Numbers are sequential and never reused; a superseded ADR
stays in place with its status changed.

Every ADR separates **planned**, **implemented** and **deployed**. Writing an ADR does not make a control
exist. Do not put keys, deployment inventories, hostnames, protected paths or operational identifiers in an
ADR.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-trust-boundaries-and-threat-model.md) | Trust boundaries and threat model | Accepted (design) |
| [0002](0002-implementation-stack-and-runtime-identities.md) | Implementation stack and runtime identities | Accepted (design) |
| [0003](0003-legacy-protected-lifecycle-handoff.md) | Legacy protected lifecycle handoff | Accepted (design) |
| [0004](0004-canonical-encoding-digests-and-contract-dependencies.md) | Canonical encoding, digests, domain separation, time and contract dependencies | Accepted (design) |
| [0005](0005-contract-set-freshness-and-versioning.md) | Contract set, internal versus public split, freshness and versioning | Accepted (design) |
| [0010](0010-github-app-request-intake.md) | GitHub App request intake, authentication and credential separation | Accepted (design); implemented as a library, not deployed |
| [0020](0020-sqlite-runtime-store-and-dependency-pins.md) | SQLite runtime store: crate, connection settings and dependency pins | Accepted (design); implemented, not deployed |
| [0021](0021-budget-accounting-run-state-and-recovery-policy.md) | Budget accounting, run state, leases and recovery policy | Accepted (design); implemented, not deployed |
| [0022](0022-store-migrations-audit-outbox-and-restore-protection.md) | Store migrations, audit outbox and restore protection | Accepted (design); implemented, not deployed |
| [0030](0030-protected-population-storage-layout-and-adapter-contract.md) | Protected population storage layout and adapter contract | Accepted (design) |
| [0031](0031-corpus-commitment-seal-and-keyed-public-commitment.md) | Corpus commitment, seal and keyed public commitment | Accepted (design) |
| [0040](0040-worker-sandbox-interface-linux-backend-and-dependencies.md) | Worker sandbox interface, Linux backend and dependencies | Accepted (design); implemented, not deployed |
| [0041](0041-isolation-self-check-verification-record-and-supported-deployments.md) | Isolation self-check, verification record and supported deployments | Accepted (design); implemented, not deployed |
| [0042](0042-dispatch-order-identity-verification-staging-and-result-protocol.md) | Dispatch order, identity verification, staging and result protocol | Accepted (design); implemented, not deployed |
| [0050](0050-receipt-signature-algorithm-keys-and-signer-isolation.md) | Receipt signature algorithm, key identifiers, key lifecycle and signer isolation | Accepted (design); implemented, not deployed |
| [0051](0051-ledger-record-layout-identity-and-supersession.md) | Ledger record layout, identity, append-only semantics and supersession | Accepted (design); implemented, not deployed |
| [0052](0052-ledger-backend-port-and-git-writer.md) | Ledger backend port and conflict-aware Git writer | Accepted (design); implemented, not deployed |
| [0053](0053-outbox-exporter-acknowledgement-and-reconciliation.md) | Outbox exporter, acknowledgement protocol and reconciliation | Accepted (design); implemented, not deployed |
| [0054](0054-external-checkpoints-startup-check-and-independent-verification.md) | External checkpoints, startup check and independent verification | Accepted (design); implemented, not deployed |
| [0060](0060-disclosure-service-flow-and-type-level-separation.md) | Disclosure service flow, crate boundary and type-level separation | Accepted (design); implemented, not deployed |
| [0061](0061-disclosure-policy-and-suppression-algorithm.md) | Disclosure policy document and suppression algorithm | Accepted (design); implemented, not deployed |
| [0062](0062-release-query-budgets-and-composition-accounting.md) | Release and query budgets and composition accounting | Accepted (design); implemented, not deployed |
| [0063](0063-publication-decision-approval-and-failure-codes.md) | Publication decision, release approval, destination binding and failure codes | Accepted (design); implemented, not deployed |
| [0070](0070-epoch-standing-contamination-states-and-authorization.md) | Epoch standing: contamination states, retirement and authorization | Accepted (design); implemented, not deployed |
| [0071](0071-eligibility-gates-and-race-semantics.md) | Eligibility gates and race semantics | Accepted (design); implemented, not deployed |
| [0072](0072-public-revocation-feed-shape-publication-and-consumer-verification.md) | Public revocation feed: shape, publication and consumer verification | Accepted (design); implemented, not deployed |
| [0073](0073-store-migration-0003-audit-events-and-rotation-protocol.md) | Store migration 0003, audit events and the rotation protocol | Accepted (design); implemented, not deployed |
| [0080](0080-operator-cli-command-set-output-and-exit-codes.md) | Operator CLI: command set, parsing, sanitized output and exit codes | Accepted (design); implemented, not deployed |
| [0081](0081-authenticated-roles-operator-authority-and-separation-of-duties.md) | Authenticated roles, the operator authority and separation of duties | Accepted (design); implemented, not deployed |
| [0082](0082-startup-sequence-write-block-and-operational-repair.md) | Startup sequence, the write block and operational repair | Accepted (design); implemented, not deployed |
| [0083](0083-store-migration-0004-durable-intake-submissions-and-activations.md) | Store migration 0004: durable intake, submissions and policy activations | Accepted (design); implemented, not deployed |
| [0084](0084-retire-the-core-disclosure-port.md) | Retire the core `Disclosure` port | Accepted (design); implemented |
| [0090](0090-benchmarks-bridge-contract-and-consumer-verification.md) | Benchmarks bridge contract and consumer verification | Accepted (design); implemented, not deployed |
| [0091](0091-legacy-metadata-import-rules.md) | Legacy metadata import rules | Accepted (design); implemented, not executed against a real population |
| [0092](0092-reviewed-handoff-rollback-and-retirement-gates.md) | Reviewed handoff, rollback and retirement gates | Accepted (design); record and checks implemented, no handoff performed |
| [0100](0100-operational-readiness-validation-and-release-posture.md) | Operational readiness validation and the code-only release posture | Accepted (design); validation implemented on synthetic data, nothing deployed |
| [0101](0101-restore-recovery-window-and-signing-key-operating-constraints.md) | Restore recovery window and signing-key operating constraints | Accepted (operating rules, deferred designs); behavior pinned by tests |
| [0102](0102-deferred-destination-binding-and-legacy-consumption-import.md) | Deferred changes: destination binding in the public projection and legacy consumption import | Accepted as designs; destination binding implemented by ADR 0119 to 0122, legacy consumption import not implemented |
| [0103](0103-solo-maintainer-operating-decisions-license-reporting-and-publication.md) | Solo-maintainer operating decisions: license, reporting route, requester and approver, clean-snapshot publication | Accepted |
| [0115](0115-legacy-consumption-import-migration-0005.md) | Legacy consumption import: migration 0005 and the additive budget import | Accepted |
| [0116](0116-export-acknowledged-dispatch-gate.md) | Export-acknowledged dispatch gate | Accepted |
| [0117](0117-queue-and-submission-retention.md) | Queue and submission retention: migration 0006 and repair retention | Accepted |
| [0118](0118-legacy-apply-command-and-enforced-deployment.md) | legacy apply, repair retention and gate enforcement in deployments | Accepted |
| [0110](0110-serverless-verification-with-github-actions.md) | Server-less verification with GitHub Actions: verifier CLI, reusable workflow, locked build, synthetic conformance set | Accepted; implemented on synthetic data, not deployed |
| [0111](0111-isolated-signer-process-socket-transport-and-framed-protocol.md) | Isolated signer process, local-socket transport and framed protocol | Accepted (design); implemented with test keys, not deployed |
| [0112](0112-signer-key-provider-contract-key-file-rules-and-process-hardening.md) | Signer key provider contract, key file rules and process hardening | Accepted (design); implemented with test keys, not deployed |
| [0113](0113-signer-crate-dependencies-and-no-unsafe.md) | Signer crate dependencies and the no-`unsafe` rule | Accepted (design); implemented |
| [0114](0114-control-service-signer-wiring-fail-closed-semantics-and-platform-limits.md) | Control-service signer wiring, fail-closed semantics and platform limits | Accepted (design); implemented, not deployed |
| [0119](0119-public-projection-schema-major-2-with-a-signed-destination.md) | Public projection schema major 2 with a signed destination | Accepted; implemented, not deployed |
| [0120](0120-bound-release-flow-v2-signing-gate-and-ledger-domain.md) | Bound release flow: prepare for a destination, v2 signing gate, ledger domain | Accepted; implemented, not deployed |
| [0121](0121-consumer-destination-verification-and-the-unbound-v1-outcome.md) | Consumer destination verification and the unbound v1 outcome | Accepted; implemented, not deployed |
| [0122](0122-destination-binding-rollout-compatibility-and-hg-2-disposition.md) | Destination binding rollout, compatibility and the HG-2 disposition | Accepted; implemented, not deployed |
| [0123](0123-std-only-http-listener-for-the-daemon.md) | A std-only HTTP/1.1 listener for the service daemon | Accepted; implemented, not deployed |
| [0124](0124-rs256-app-jwt-with-ring-and-an-offline-github-adapter.md) | RS256 App JWT with ring, and the GitHub adapter behind a trait with an offline fake | Accepted; implemented, not deployed |
| [0125](0125-queue-consumer-poison-handling-scheduler-and-migration-0007.md) | Queue consumer, poison handling, scheduler and migration 0007 | Accepted; implemented, not deployed |
| [0126](0126-request-to-projection-pipeline-steps-and-crash-resume.md) | Request-to-projection pipeline: steps, idempotence and crash resume | Accepted; implemented, not deployed |
| [0127](0127-receipt-assembly-and-the-aggregates-channel.md) | Receipt assembly from a dispatch report and the aggregates channel | Accepted; fixture only, real engines do not emit it |
| [0128](0128-daemon-configuration-process-model-and-shutdown.md) | Daemon configuration, process model and shutdown | Accepted; implemented, not deployed |
| [0129](0129-daemon-verification-claims-fixtures-and-dispositions.md) | Daemon verification claims, fixtures and release-readiness dispositions | Accepted; implemented, not deployed |

Accepted (design) means the decision is frozen for downstream issues (C2 to C12). It does not mean any of it
is implemented or deployed. See each ADR's status table.

Decided by C2 (ADR 0004, ADR 0005): canonical encoding, digest and domain-separation rules, time handling,
contract set, public projection and revocation envelopes, freshness and contract versioning. Still
deferred, with the issue that owns each: request-intake authentication details (C3); SQLite schema and migrations (C4); sealing format and key
provider (C5); sandbox platform and probes (C6); signing key provider and receipt format (C7);
disclosure policy parameters (C8).

Decided by C4 (ADR 0020 to 0022): the SQLite driver and pins, connection and file settings, the written budget accounting, lease and recovery policy, migrations, the audit outbox and restore protection. Details: [docs/state-store.md](../state-store.md). Implemented in `crates/custodian-store` with synthetic tests; not deployed.

Decided by C7 (ADR 0050 to 0054): Ed25519 receipts with domain separation and isolated signing, key lifecycle, the ledger record layout and supersession, the conflict-aware ledger writer, the outbox exporter and reconciliation, external checkpoints and the startup rollback check. Details: [docs/ledger.md](../ledger.md). Implemented in `crates/custodian-ledger` with synthetic tests and test-generated keys; the private-ledger repository, signer process and key provider are not provisioned.

Decided by C8 (ADR 0060 to 0063): the disclosure service flow and type-level separation of internal and public records, the versioned disclosure policy and the suppression algorithm with its stated limits (no perturbation), release and query budgets with composition accounting (store migration 0002), and the publication decision, release approval, destination binding and fixed failure codes. Details: [docs/disclosure.md](../disclosure.md). Implemented in `crates/custodian-disclosure` with synthetic tests; no policy is activated, no budget provisioned and nothing deployed.

Decided by C6 (ADR 0040 to 0042): the `Sandbox` interface and Linux backend (bubblewrap and `prlimit`, no new Rust dependency), the fail-closed refusing backend, the startup isolation self-check and verification record, supported deployment isolation and the test skip policy, the dispatch order (identity checks before protected input, write-ahead exposure), immutable staging, and worker protocol v1 with its outcome mapping. Details: [docs/worker-isolation.md](../worker-isolation.md). Implemented in `crates/custodian-worker` with synthetic tests; not deployed.

Decided by C9 (ADR 0070 to 0073): the epoch standing state machine (contamination severity plus one-way retirement, only an unreviewed change is clearable, by a human under a permit), the eligibility gates and the documented race semantics (store gates inside the reserve, retry, start and exposure transactions, a dispatch guard, prepare and release checks), the public revocation feed (the C2 signed envelope, one file per sequence, durable obligations, compare-and-swap publication, consumer verification steps), and store migration 0003 with its audit events and the rotation protocol. Details: [docs/lifecycle-and-revocation.md](../lifecycle-and-revocation.md). Implemented in `crates/custodian-lifecycle` and `crates/custodian-store` with synthetic tests; not deployed.

Decided by C10 (ADR 0080 to 0084): the operator CLI command set, the standard-library parser, sanitized JSON output and stable exit classes, authenticated roles from a reviewed policy file with structural limits for agent and automation identities and three-layer separation of duties, the startup sequence with a no-bypass check, the persisted write block and the closed `repair` group, store migration 0004 (durable intake ports, submissions, activation history, shared idempotency and budget path) with four added ledger payload keys, and the retirement of the core `Disclosure` port. Details: [docs/operator-runbook.md](../operator-runbook.md). Implemented in `crates/custodian-cli` and `crates/custodian-store` with synthetic tests; not deployed.

Decided by C11 (ADR 0090 to 0092): the benchmarks bridge (a closed, bounded request; a response of released projection envelopes and public feed envelopes behind an unsigned manifest; a reference consumer that verifies with public keys and pins only, with the destination-binding limit stated), the legacy metadata import rules (a reviewed extract, spent stays spent, silence and ambiguity count as consumed, the legacy independence vocabulary kept verbatim, immutable monotone records, metadata-only parity), and the reviewed handoff with its rollback and retirement gates (a record that can only propose, no protected rerun, any new protected execution needs an explicit Approval, credential cutover not forced). Details: [docs/benchmarks-integration.md](../benchmarks-integration.md) and [docs/legacy-migration.md](../legacy-migration.md). Implemented in `crates/custodian-bridge` with synthetic tests; not deployed, and no legacy population has been handed off.

Decided by S4 (ADR 0119 to 0122, follow-up issue 31): public projection schema major 2 with the destination inside the signed payload and a new domain tag, the bound release flow (`prepare_bound`, v2 signing gate, ledger signing domain), consumer verification from the envelope alone with a distinct `destination_unbound` outcome for v1, and the rollout and HG-2 disposition. Details: [docs/contracts.md](../contracts.md) section 8, [docs/disclosure.md](../disclosure.md), [docs/benchmarks-integration.md](../benchmarks-integration.md). Implemented with synthetic data and test keys; not deployed.

Decided by C12 (ADR 0100 to 0102): how operational readiness is validated and recorded (a cross-layer synthetic suite over the real components with an in-process sandbox double, a crash sweep with a coverage rule over every fault point, canary leakage scans, non-gating measurements, an explicit go or no-go), the operating rules and deferred designs that the restore drill and key flow tests exposed (recovery window, ledger-lineage rollover, key rotation and revocation constraints), and the designs for destination binding and legacy consumption import. Details: [docs/release-readiness.md](../release-readiness.md), [docs/backup-recovery.md](../backup-recovery.md). Validation implemented with synthetic data; nothing is deployed.

Decided by S3 (ADR 0115 to 0118): the legacy consumption import (migration 0005, additive and idempotent, exhausted means all headroom consumed), the export-acknowledged dispatch gate (`store_export_pending`, worker export barrier and exposure acknowledgement), queue and submission retention (migration 0006, hard floors, explicit ages), and the `legacy apply` and `repair retention` commands with gate enforcement in deployments. Implemented with synthetic tests; not deployed.
