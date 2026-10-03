# Reproducing the synthetic AWS experiments

This runbook accompanies the [dated findings](lambda-microvm-live.md). It is
manual disposable provisioning plus the implemented health harness and primitive
probe, not a custody deployment or a general cleanup service. New experiments
require their own operator authorization and cost ceiling. Use public synthetic
data only. AWS authority and reviewed policy remain outside these programs.

## Private inventory and provisioning

Use AWS CLI v2 with `lambda-microvms` and `lambda-core` support. Set
`AWS_PROFILE=redact-secret` and region `us-east-1` for the authorized experiment.
Capture service responses/errors into an owner-only directory outside this
repository, never terminal/CI output. Record the account identity privately and
compare it before every destructive cleanup. Record each creation intent before
calling AWS, then the returned exact identifiers and tags. Names, account IDs,
ARNs, endpoints and tokens must never enter the public report.

Create one isolated VPC/subnet, no internet gateway/NAT/endpoints, and a custom
security group with all default egress removed. Create a `lambda-core` IPv4 VPC
network connector for that subnet/group. Its role trusts `lambda.amazonaws.com`
and permits ENI creation only in those resources, plus the managed-operator ENI
tag operation. Poll connector state before use. This configuration alone is not
a DNS/link-local or child isolation boundary.

Create one owner-enforced, public-blocked, encrypted S3 bucket. Package exactly
`Dockerfile` and `health.rs` from `deploy/aws/microvm/` for the health image;
package `Dockerfile.probe` renamed `Dockerfile` plus `probe.rs` for the diagnostic
image. Record SHA-256 of each ZIP. The build role reads only those exact objects.
The Dockerfiles pin compiler and final ARM64 base digests. Source ZIP digests do
not prove the compiled binary digest or absence of snapshot credentials.

Create/update one MicroVM image with the AWS-managed AL2023 base and the staged
ZIP. Consult the CLI operation's input skeleton for the installed SDK shape.
Always supply the complete configuration: ARM64, 512 MiB baseline, no additional
OS capabilities, empty environment, Ready/Validate HTTP hooks on port 8080,
disabled runtime hooks and disabled logging. This experiment needed public
**build** egress; runtime egress must be supplied separately. Poll the exact
version to SUCCESSFUL/ACTIVE and read it back. Never launch a version that
replaced requested hooks, resources or logging with defaults. Do not interpret
a failed build's generic error as a proven networking diagnosis.

## Implemented health/lifecycle harness

Create an owner-only config file in an owner-only directory outside Git:

```json
{
  "syntheticOnly": true,
  "maxUsd": 50,
  "profile": "redact-secret",
  "region": "us-east-1",
  "imageArn": "<privately recorded owned image ARN>",
  "imageVersion": "<privately recorded successful health version>",
  "egressConnectorArn": "<privately recorded denied VPC connector ARN>"
}
```

Run the existing program with the absolute private path:

```sh
python3 infra/aws/poc/live_health.py --private-config /outside/repository/private/config.json
```

Read the program's configuration checks before use. It creates two health-only
VMs with finite 180/60-second lifetimes, HTTP ingress, no execution role, disabled
logs and explicit VPC egress. It persists intents and checks exact-token creation
replay. It tests fixed health bytes, missing/invalid/wrong-port/wrong-VM tokens,
job and shell refusal, a 65-second expiry observation and lifetime termination.
Endpoint tokens remain in memory and HTTPS requests do not forward redirects.
The expiry check failed in the dated experiment; never silently turn it green.

The harness writes private ownership inventory and refuses an existing one.
An unresolved creation cannot be declared cleaned merely because known VMs were
terminated. Reconcile `list-microvms` against the exact owned image/version and
persisted intent before terminating recovered VMs; poll each exact VM terminal.
Never run creation to discover an orphan during cleanup. After crashes, perform
independent inventory reconciliation. No persistent janitor is implemented.

## Diagnostic image comparison

Build the diagnostic version with the same explicit configuration and check it
before use. Launch one short-lived VM with public internet egress and one with
the denied VPC connector, using the **same immutable version**, no execution role
and disabled logs. Persist both creation intents/identifiers privately. Request
`/probe` on port 8080 with VM-specific one-minute tokens held in memory. The
source returns only fixed booleans from the public synthetic canary, child
environment check, DNS, public IPv4/IPv6 and link-local TCP attempts, and tool
availability. It sends no credentials or canary file contents over the network.

Use `live_health.py`'s `aws`/HTTPS request helpers when scripting these calls;
there is no implemented general isolation orchestration command. Preserve
positive-control failures as unassessed, not successful denials. Terminate both
VMs in a finally path and independently check terminal state. A same-uid child
reading the owner-only file is an isolation failure, not an engine evaluation.

## Ordinary Lambda transaction primitive

Create one on-demand DynamoDB table with string partition key `pk`, and a Lambda
execution role allowing only GetItem, PutItem and UpdateItem on that table. No
logging permission, function URL, S3/corpus access or signer access is needed.
ZIP only `infra/aws/poc/transaction_probe.py`, deploy an ARM64 Python 3.14 function
with `transaction_probe.handler`, 128 MiB memory and private `PROBE_TABLE` env.
This uses the runtime's managed boto3; its exact SDK patch was not pinned.

Conditionally insert `synthetic-race:counter` with numeric `remaining=1` and
`held=0` only when the key does not exist. Never reset an exhausted fixture;
use a distinct disposable table/namespace for a new approved experiment.
Invoke sixteen distinct `{ "id": "synthetic-N", "binding": "valid" }` events
concurrently through IAM. For AWS CLI invocation, use direct `--function-name`,
`--payload fileb://<private payload path>` and a private output file; do not use
the unsuccessful CLI-input-JSON streaming invocation path from the first attempt.
Capture all outputs privately. Reinvoke the winner with the same binding and
then `conflicting`; expect REPLAY and BINDING_CONFLICT. Strongly read the new
namespace: remaining zero, held one, exactly one intent and one outbox. Keep any
earlier diagnostic namespace intact. This is not the custodian StateStore.

## Teardown and evidence gate

Always perform scoped teardown, including on failed probes. Compare the account
to the private inventory, then terminate all exact owned VMs and poll terminal.
Delete the Lambda function and table; require ResourceNotFound on subsequent
reads. Delete the image and check every recorded build version absent. Delete
the connector and poll absent; reconcile owned ENIs. Remove exact S3 objects and
bucket, detach/delete owned inline role policies and roles, then delete the
custom group, subnet and VPC in dependency order. Inspect only owned log-group
prefixes, never enumerate/delete unrelated account resources. Retry a failed
delete with its original owned identifier; do not report success before readback.

The dated run's first table delete failed and its scoped retry/readback succeeded.
All four versions, the connector, VPC/ENIs, bucket, function, table and roles were
checked absent, and all five VMs terminal. Keep private inventory for reconciliation
and an allowlisted public summary of counts, fixed codes, booleans, durations,
source digests and failures. No raw service output or identifiers go into Git.
Deletion does not prove provider physical erasure; snapshot minimum billing and
delayed invoice attribution still apply. Include unknown cost components instead
of presenting measured VM compute as the complete experiment cost.
