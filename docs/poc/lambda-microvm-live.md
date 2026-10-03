# Authorized AWS synthetic feasibility experiment

Date: 2026-10-03. Baseline: `23f75304d4cf53fc8604379255bbf058f642daeb`.
The user explicitly authorized a **total US$50 ceiling**, using the account
selected by `AWS_PROFILE=redact-secret`, region `us-east-1`, synthetic inputs only
and deletion of all experiment resources on completion or failure. Account,
resource names/ARNs, image versions, endpoints and API responses are in an
owner-only inventory outside Git. Endpoint tokens were kept in memory.

**Protected worker: NO-GO. Current control-plane migration: NO-GO.** AWS ARM64
packaging and lifecycle work; the current implementation lacks required inner
isolation and distributed custody adapters. This does not establish that AWS
cannot implement those boundaries. No protected input, production key, live
private-ledger write, webhook, policy activation or production cutover occurred.
This is project-maintained synthetic functional evidence, not independent
measurement validation. The [machine-readable record](lambda-microvm-live-evidence.json)
contains counts, booleans, source hashes, measured times and partial cost units.
The [initial preparation record](lambda-microvm.md) is retained as historical evidence.

## P1/P2: actual image builds and exact configuration

All builds used the pinned ARM64 Rust compiler and AWS container manifests from
`deploy/aws/microvm/`, and an explicit version of the public managed `al2023-1`
MicroVM base. Each zip contained exactly one Dockerfile and one public Rust
source. No corpus, candidate, engine, operational key or credentials were copied.
Compiled AWS binary hashes, complete restored package inventory and build-role
snapshot residue were not collected; source pins are not binary attestation.

| Trial | Result | What it establishes |
| --- | --- | --- |
| B1: health source, denied VPC build egress, 512 MiB | FAILED, generic unknown build error | Reproducible failed trial; no detailed cause retained or inferred |
| B2: same zip, update with public build egress and omitted configuration fields | SUCCESSFUL, defaults replaced settings (2048 MiB; hooks/logging no longer matched) | A successful build is insufficient. Not selected for runtime probes |
| B3: same health zip, all configuration fields explicit, 512 MiB | SUCCESSFUL/ACTIVE; ready/validate hooks enabled, logging disabled | Actual ARM64 health/lifecycle experiment; exact returned configuration checked before run |
| B4: fixed public diagnostic source, same explicit settings | SUCCESSFUL/ACTIVE | Both allowed and denied egress probes used this exact image version |

Changing build egress alone did **not** establish B1's root cause: the first
update also replaced omitted configuration fields. Future creates and updates
must specify every security/resource field and compare the returned version
before launching. The health sampler rejects replacement defaults before
`RunMicrovm`; its negative control covers this behavior.

Builds used a disposable role that could read only the experiment's two public
build objects. Runtime requests supplied no execution role, disabled logging,
selected exact image versions, excluded shell ingress, restricted tokens to
8080, disabled auto-resume and bounded VM lifetime to 60–180 seconds. No custody
dispatcher was installed or selected. The VPC connector was initially PENDING;
after changing the experiment role's trust principal to `lambda.amazonaws.com`
it was observed ACTIVE. This is a local observation, not proof that the original
principal can never work. ENI create permissions were restricted to the owned
subnet/security group; neither NAT nor paid interface endpoints were created.

## P3: real positive controls and failed denials

The diagnostic image runs a fixed child with a cleared environment and no inner
sandbox. It deliberately tests whether VM separation alone protects a runner's
0600 file. The canary is public synthetic text; only booleans are returned. TCP
probes send no canary or application payload. No metadata credential was fetched.

| Control on B4 | Allowed internet VM | Denied VPC VM | Disposition |
| --- | --- | --- | --- |
| Child runs; runner can read its own canary | yes | yes | Working execution/file positive controls |
| Public IPv4 TCP to resolved `example.com:443` | connects | refuses | Denial demonstrated for this destination/port only |
| DNS resolution of `example.com` | resolves | resolves | **Denied DNS claim fails**; SG/no-NAT alone is insufficient |
| Link-local TCP `169.254.169.254:80` | connects | connects | **Denied link-local claim fails**; no HTTP/credential-access claim |
| Child reads runner-owned 0600 canary | reads | reads | **Inner filesystem/process trust boundary fails** without a sandbox |
| IPv6 TCP | refuses | refuses | Not assessable: allowed positive control failed |
| User namespace command | tool absent | tool absent | Not assessable; absence of `unshare` does not prove kernel denial |
| Child credential environment | absent after explicit scrub | absent after explicit scrub | Limited environment observation; not complete snapshot/file/credential isolation proof |

The health positive control passed. Missing/invalid tokens, wrong VM, wrong port,
shell-token request without shell connector and evaluation jobs refused. Jobs
returned empty 403 responses; no request values were reflected. Persisted
CloudWatch log-group queries for the experiment returned zero groups.

The 1-minute token expiry denial at 65 seconds **failed**. A separate fresh-VM
probe observed health 200 at about 2.4, 65.1 and 90.4 seconds after token response,
then 403 at about 125.1 seconds. No universal grace duration or server cause is
inferred. A JWE token is not an authoritative attempt lease, cancellation fence
or revocation channel. The original failed check remains in the evidence.

Filesystem/archive confinement, runner memory/signals, arbitrary internal
endpoints, complete credential absence, stdout/stderr floods and hostile process
resource limits remain unverified. Do not interpret unavailable controls as
passed. No isolation attestation or protected worker acceptance follows.

## P4: lifecycle and uncertainty

Two identical `RunMicrovm` requests with the same client token returned the same
VM; separate tokens produced distinct fresh VMs. This proves the sampled provider
replay behavior, not retention beyond the tested window or durable custody
fencing. One unattended VM configured for a 60-second maximum lifetime reached
TERMINATED (observed service interval 61.736 seconds). Explicit termination and
terminal-state queries succeeded for all five VMs. No suspend/reuse was attempted.

The local sampler atomically claims its inventory file, persists intents before
creation, and preserves known IDs on a conflicting replay. Cleanup never calls
`RunMicrovm`. Unknown initial/replay outcomes force an incomplete-reconciliation
result, even when known VMs terminate; the exact owned-image inventory must be
queried by a separate cleanup owner. Synthetic tests cover lost responses,
conflicting replay, concurrent sampler invocation, hostile errors and cleanup
failure. Restart refuses an existing inventory instead of overwriting it.

No real orchestrator kill after exposure/result/settlement, OOM, disk/PID/CPU
exhaustion, malicious child tree or authoritative remote fence was tested. No
custody budget was charged/refunded. These missing controls block a production
adapter; provider client tokens and a local JSON file cannot replace its store.

## P5: engine boundary

Both engine heads still match the immutable source pins in the initial record.
The pinned upstream credential CLI has no custodian worker entrypoint; pinned
upstream PII production adapters remain contract-not-final. During this experiment,
PR #52 merged the custodian PII contract decisions and a reference adoption patch
with a pinned synthetic Linux pipeline gate. See [the handoff](../pii-eval-adoption.md)
and ADR 0135: upstream adoption and ARM64/real-scanner sizing remain pending.
That Linux evidence does not validate the MicroVM boundary. Inner isolation also failed above.
Therefore neither engine was represented as integrated or run in an accepted
protected worker. No test-only adapter substitution, denominator clamp, policy
activation, Node `--jitless` substitution or automatic limit increase was made.
ARM64 Node/real-engine corpus sizing remains unmeasured. The fixed Rust health
and diagnostic processes establish only ARM64 packaging/runtime compatibility.

## P6: actual Lambda/DynamoDB primitive prototype

`infra/aws/poc/transaction_probe.py` ran in a disposable ARM64 Python 3.14 Lambda,
with no function URL and a role scoped to one disposable DynamoDB table's
Get/Put/Update actions. It had no corpus, signer, ledger, S3 or logging permission.
Its source zip hash is recorded; it uses the managed runtime's boto3, not an
added workspace dependency. Managed runtime/SDK patch identity was not pinned.

Sixteen parallel IAM-authenticated invocations raced on one unit in a new
synthetic fixture namespace: one CHARGED, fifteen NOT_COMMITTED. Strong reads
confirmed remaining=0, held=1, exactly one intent and one outbox item, committed
together. Same-key/same-binding replay returned REPLAY without another write;
changed binding returned BINDING_CONFLICT. Each invocation uses a different
DynamoDB service token; permanent stored intent conditions enforce the replay
result. A diagnostic fixture's depleted counter was retained; a new namespace
was initialized rather than resetting it. Both namespaces were public synthetic
and the whole disposable table was deleted during authorized teardown.

This is an AWS conditional-transaction feasibility probe, **not** a StateStore
implementation or the custody authorization/outcome rules. Standing, approvals,
leases, queue/exposure/export barriers, disclosure composition, recovery, S3
custody and separately authenticated Ed25519 signer/export adapters remain
absent. Existing real SQLite/Unix-signer/disposable-Git suites passed locally;
they do not validate remote equivalents. [The complete adapter inventory and
minimum backlog](lambda-control-plane.md) remain the migration requirements.

## P7: measurements, cost and verified teardown

Five VMs ran for a service-reported total **301.557 seconds**. The health sampler
took 87.601 seconds including client/API/HTTP overhead and cleanup. Source zip
sizes and hashes, configured memory, failed builds and runtime intervals are
recorded. No real engine staging/execution/validation timing is implied.

The public US East Lambda pricing file published 2026-10-01 supplies the exact
rates in the JSON record. For these five 512-MiB VMs only, measured duration times
configured baseline gives about **US$0.00264** compute; charging every second at
the documented 4x peak gives about **US$0.01056**. These are partial pricing bounds,
not an invoice or the experiment total. One actual Lambda transaction invocation
reported 447 billed ms, 128 MiB configured and 98 MiB peak usage; that one sample
does not stand in for all control-plane work.

Build compute, actual CPU/memory burst, snapshot byte sizes/read/write/storage,
S3/DynamoDB/API/transfer charges and final attributed invoice remain unmeasured
or not yet attributed. Snapshot storage has a one-week minimum; deletion does
not mean zero charge. No ordinary Lambda free tier was assumed. A defensible
4/8-per-day **real-engine** total is unavailable without engine duration, image
size and those missing units. The US$50 approval was an experiment ceiling, not
a claimed automatic account-wide billing guard or a verified final spend.

Created: one VPC/subnet/custom SG/connector/bucket/image/table/function, three
roles, two build objects, four image versions and five VMs. The first table delete
failed; retry succeeded without altering protection settings or expanding roles.
All five VMs were verified terminal. Get/Describe/Head queries confirmed absence
of the image and all four versions, connector, subnet/SG/VPC, bucket, function,
table and all roles; owned VPC ENI query was empty. **Retained billable experiment
resources: 0.** Private inventory is retained for inspection, not committed.
Service deletion is not a claim of physical secure erasure or zero minimum charge.

## Decisions and issue disposition

| Item | Current disposition |
| --- | --- |
| #41 | Compatibility plus actual authorized ARM64 build/run/terminate and teardown evidence complete; no claim of quota exhaustion testing |
| #42 | Contract, image preparation, fixed authenticated transport/lifecycle probes exist; remote job delivery, image residue inventory and trusted runner still absent |
| #43 | Concrete denial failures and unsupported controls establish NO-GO for this prototype; full isolation acceptance not met |
| #44 | Provider replay, maximum lifetime, termination/orphan inventory and local negative controls established; full authoritative crash/resource/fencing matrix absent |
| #45 | Blocked by pending upstream engine adoption/ARM64 sizing and failed inner-isolation boundary; both-engine acceptance not met |
| #46 | Actual parallel Lambda/DynamoDB critical primitive plus complete map/backlog; full distributed store/signer/export migration remains NO-GO |
| #47 | Separate decisions, partial actual units/times and verified teardown recorded; full engine cost and final invoice unavailable |

Outstanding children and the epic must not be closed as successful implementation.
Fallback remains the existing Linux worker, whose production-host rehearsal and
normal custody approval remain separate. Follow-up requires internal sandbox
packaging with tested denial, authoritative remote delivery/fencing/cleanup,
engine-owned contracts and sizing, complete distributed ports, signer/export
failure proofs and a new cost/operational acceptance review. [ADR 0136](../adr/0136-authorized-microvm-experiment-findings.md)
records the recommendation without selecting or activating production policy.

## Reproduction and sources

[The runbook](lambda-microvm-live-runbook.md) specifies input/private inventory,
build/update fields, sampled controls and teardown. CI receives no AWS credentials.
Run local controls with `python3 -m unittest discover -s tests/microvm-conformance`
and the normal Rust workspace checks. The actual experiment is not a CI step.

- [AWS image/sizing model](https://docs.aws.amazon.com/lambda/latest/dg/microvms-images.html)
- [AWS networking and connector](https://docs.aws.amazon.com/lambda/latest/dg/microvms-networking.html)
- [AWS roles and token scope](https://docs.aws.amazon.com/lambda/latest/dg/microvms-security.html)
- [AWS lifetime/lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/microvms-launching.html)
- [AWS sample role-trust observation](https://aws-samples.github.io/sample-autonomous-cloud-coding-agents/decisions/adr-021-lambda-microvms-compute-backend/)
- [US East public Lambda rate file](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/current/us-east-1/index.json)
- [MicroVM pricing and minimum retention](https://aws.amazon.com/lambda/pricing/)
- [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
