# Synthetic MicroVM image preparation

This directory is **not** a protected worker. The health binary accepts only a
fixed health route and AWS build-ready/validate hooks; all evaluation jobs refuse.
No engine is embedded and no isolation attestation is issued.

Build locally with the explicit ARM64 compiler and base manifests in Dockerfile:

```sh
docker build --platform linux/arm64 -t custodian-microvm-synthetic:local deploy/aws/microvm
```

The context allowlist is Dockerfile + health.rs only. The build has no package
manager/network dependency install; the compiler container is separate from the
final AWS container. Final image adds one static Rust binary and runs as uid/gid
65534. The base includes AWS-managed components whose inventory and build-role
residue still require verification on the actual restored AWS snapshot.

An authorized AWS image build consumes a zip containing these two files at the
archive root, not the full repository. Record SHA-256 of archive, source and
compiled runner, compiler version, base manifest, managed base version and AWS
image version. Do not use latest-active version at dispatch. Never add corpus,
job, keys, environment credentials or worker input to COPY or image environment.

`infra/aws/poc/image.template.json` prepares the CloudFormation image/build role
with a single build-object read permission, ARM64, no added capabilities, no
runtime environment values and disabled logs. It requires an explicitly chosen
customer VPC egress connector; the template does not create or prove that
connector's DNS/network isolation. CloudFormation validation does not establish
resource-handler deployment support or runtime security. SAM also documents a
MicrovmImage resource; the experiment does not assume only one provisioning tool.

Read-only preflight:

```sh
AWS_PROFILE=redact-secret python3 infra/aws/poc/preflight.py
```

No provisioning command is automated here. Under Epic #40, record explicit
account/region, cost ceiling and cleanup authorization before any billable call.
A live synthetic health experiment uses one fresh VM, exact image version,
no execution role, disabled runtime logging, no shell connector, a token for
port 8080 only, disabled auto-resume and a service maximum lifetime. A trusted
external orchestrator must explicitly terminate and verify absence even if
health fails. Keep endpoint/auth token/private inventory outside source control.
Health success is packaging/lifecycle evidence only; it never authorizes an engine
or protected input. See the [evidence record](../../../docs/poc/lambda-microvm.md)
and the exact-image adversarial/cleanup requirements before any further work.
