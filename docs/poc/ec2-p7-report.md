# PoC P7 report and template: cost, teardown and separate Go/No-Go (#47, ADR 0147)

Status: **template with decisions; nothing was measured.** No live AWS experiment has run. Every measured field is
`UNMEASURED`. Synthetic public data only; no protected input, credential, account id, region-specific identifier or
live ledger export belongs here. This is project-owned evidence, not independent validation. Live provisioning needs
a separately authorized account, region, cost ceiling and cleanup plan under #40.

## 1. Evidence index (what exists, what does not)

| Child | Evidence available | Live host evidence |
| --- | --- | --- |
| #41 / ADR 0136, 0140 (Lambda MicroVM) | Recorded live findings: real runner `verified: false` on Lambda MicroVM; historical only | n/a (target abandoned, ADR 0141) |
| #71 / ADR 0142 | Fresh-instance-per-attempt design, design-only IaC template, offline static tests | none |
| #42 / ADR 0143, #44 / ADR 0144 | Rust adapter, fencing, janitor against a synthetic in-memory provider double | none |
| #45 / ADR 0145 | Reconciliation and ARM64 sizing template (`docs/arm64-sizing-measurement-plan.md`) | none, all UNMEASURED |
| #72 / ADR 0146 | Operational PII path and PENDING placeholders | none |
| #43 / #46 / P-series live items | Not linked here as evidence; link only sanitized, committed results when they exist | none |

The mandatory `run_self_check` has never passed on an EC2 host. ADR 0141's cost tables are placeholders and are
**not** quoted as measurements anywhere in this report.

## 2. Timing windows to measure (immutable build, one row per window)

Startup (launch to running), boot to self-check, self-check, staging/transfer in, execution, validation, transfer out,
termination to verified gone, retries (each a new instance and attempt), idle window (should be zero), orphan window
(janitor detection to reap). All `UNMEASURED`: min / median / max over N>=5 per ADR 0145 method, plus the immutable
image id and manifest digest they were taken on.

## 3. Cost components (billed unit, source, status, exclusions)

Estimator: `python3 tools/poc/cost_estimator.py INPUTS.json`, inputs template `docs/poc/ec2-cost-inputs.template.json`.
It refuses to print any total unless every required component is `MEASURED` with billed unit, basis, quantity, unit
price and source. `ESTIMATE` is refused too. Sizing band: 4 and 8 runs/day, 30-day month by convention.

| Component id | Billed unit to record | Source (when measured) | Status |
| --- | --- | --- | --- |
| compute_burst | instance-seconds running, launch to terminate, per attempt incl. retries, per instance type | EC2 billing/usage data for the PoC account tag | UNMEASURED |
| ebs_volumes | GiB-month, provisioned IOPS/throughput, until deletion | billing usage plus volume inventory | UNMEASURED |
| ami_snapshot_storage | snapshot GiB-month, copies, restore reads | billing usage plus AMI/snapshot inventory | UNMEASURED |
| interface_endpoint_hours | endpoint-hours per AZ | billing usage | UNMEASURED |
| endpoint_data_processing | GB processed | billing usage | UNMEASURED |
| gateway_endpoint_and_transfer | S3 requests, GB transferred (gateway endpoint has no hourly charge) | billing usage | UNMEASURED |
| logs | ingested GB, retained GB-month | billing usage | UNMEASURED |
| janitor_and_control_services | compute, requests of the janitor and control services (no free-tier assumption) | billing usage | UNMEASURED |
| signing | signer operations and key-provider charges (worker never signs) | billing usage | UNMEASURED |
| retained_resources | anything kept, with owner and expiry; zero must be measured, not assumed | inventory plus billing | UNMEASURED |

Explicit exclusions: support plans, taxes, credits and free-tier offsets, Savings Plans/Reserved discounts, engineer and
CI time, protected corpus storage and private-ledger hosting outside this path, any unlisted resource (a new resource
becomes a new required component), a self-hosted CI runner (separate host), and ordinary Lambda free-tier assumptions,
which are never applied (the same applies to the janitor and control services). Total daily/monthly cost at 4 and 8
runs/day: **UNMEASURED (estimator refuses)**.

## 4. Teardown and resource inventory verification checklist

Run only after an authorized live experiment; each line is `PENDING` until evidenced with sanitized output (counts and
tag-scoped ids by reference, never account ids or raw identifiers in the repository).

| Check | Evidence | Status |
| --- | --- | --- |
| Inventory taken by the exact ownership tag (never name or prefix), before and after | tag-scoped lists: instances, volumes, ENIs, snapshots, AMIs, endpoints, security groups, launch templates, log groups, roles/policies, queues/tables, keys | PENDING |
| Every instance terminated and observed gone (not merely stopping) | provider describe results after terminate | PENDING |
| Volumes: zero left (DeleteOnTermination verified), no unattached volume | volume inventory | PENDING |
| Snapshots/AMIs: only the pinned image and its snapshot remain, with owner and expiry, or are deleted | inventory | PENDING |
| Endpoints, ENIs, security groups, launch templates deleted or retained with owner and expiry | inventory | PENDING |
| Log groups deleted or retention-bounded; no protected content in logs | inventory plus sampled synthetic check | PENDING |
| IAM roles/policies and credentials created for the PoC revoked or deleted | inventory | PENDING |
| Janitor sweep over exact inventory finds nothing owned and live; orphan injection found and reaped | ADR 0144 janitor output on the live account | PENDING |
| Billing check next day: no residual usage on the tag | billing data after teardown | PENDING |
| Retained resource register: each item has owner and expiry | register | PENDING (none authorized) |

Any non-empty residual that is not in the retained register fails P7 and is reported, not hidden.

## 5. Security evidence, limitations, recovery gaps, constraints

- Security evidence on EC2: none. Lambda MicroVM evidence (ADR 0136/0140) shows the real sandbox did not verify there.
- Engine limitations: real engines not run on ARM64; ADR 0145 table UNMEASURED; `RLIMIT_AS` is not resident memory.
- Recovery gaps: durable SQLite attempt table open; no remote crash/restart evidence; janitor undeployed;
  client-token launch idempotency unimplemented (ADR 0142/0144).
- Account/region constraints: not recorded; instance-type availability, quotas, endpoint service availability and
  pricing are region-specific and UNMEASURED.

## 6. Decisions (separate, not upgraded)

| Subject | Decision | Basis |
| --- | --- | --- |
| EC2 worker | **No-Go until live host evidence** | Design and synthetic double only; `run_self_check` never run on the pinned image; no adversarial probes, timings, sizing or cost measured |
| Control plane (serverless conversion) | **NO-GO, unchanged** (ADR 0134, 0136) | Domain migration unresolved; no new evidence |

Fallback: keep the existing Linux backend and single-host lifecycle with its export gates (ADR 0133 defer option); no
migration, cutover or benchmark switch. Neither decision is conditional Go.

Production follow-up blockers (each must be closed with evidence before any production consideration): live passing
self-check and #55/#56 probes on the pinned AMI with positive controls; measured timings, sizing and a complete cost
report from the estimator; verified teardown with an empty or owner-and-expiry inventory; durable attempt table and
remote crash/restart tests; deployed janitor evidence; interface-endpoint control channel design (#42); reviewed policy
revision, authorization, and an explicit custody decision. **PoC success never authorizes production custody**; it
changes no approval, retention, budget, disclosure or signer policy.

## 7. Hand-off to private-ledger #8 and #2 (nothing activated)

- Audit compatibility: the worker emits no new identity; attempt, instance, fence and worker-job/worker-result
  identities (ADR 0143/0144) remain distinct from authorization, reservation, run and receipt. Any ledger event for
  launch, terminate, janitor closure or `TerminateUnverified` is a proposal, additive, and needs a reviewed ledger
  schema revision in private-ledger #8 before use.
- Policy compatibility: any reliance on EC2 lifecycle in #2 policy needs an explicit reviewed policy revision; this
  report is not one. No live export, webhook, key, or ledger write is performed or implied.
- Cost and teardown results, once measured, are operational evidence for review, not budget authority.
