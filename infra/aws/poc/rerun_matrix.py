#!/usr/bin/env python3
"""S4 (issue #57) reproducible rerun matrix: offline planning only.

This module builds, and can print, the exact matrix of probes issue #57 (S4,
epic #40) says the next authorized live AWS MicroVM rerun must cover: every
control the one authorized experiment in ADR 0136 already ran (same-uid
runner-file read, DNS resolution, link-local `169.254.169.254`, the IPv6
positive control, token-TTL enforcement, and the rest of the P3/health
tables), plus every ARM64 adversarial case from ADR 0137/0138/0139 that
already has real CI evidence from the `worker-isolation-arm64` job, so the
live rerun is not scoped narrower than what is already proven in CI. It also
lists, separately and without claiming CI evidence for them, the ADR
0138/0139 probe-matrix items that are still design-only (DNS-by-name,
link-local-by-name, IPv6, inherited-descriptor count, proxy/resolver
environment canaries, symlink/hardlink/writable-mount escape, the
supplementary-group escape, and a dedicated forged-attestation probe) --
those are tracked as a parallel, separate S2/S3 implementation effort and are
reported here as "design_only", never silently upgraded to "proven".

This file makes **no AWS API call of any kind**. It imports no `boto3`, no
`subprocess`, opens no network socket, and has no code path capable of one --
not a missing credential check, an actual absence of the capability. Its only
I/O is reading files already committed to this repository (to opportunistically
note, informationally, whether a pending probe's test name already exists
somewhere in the tree -- see `_grep_hint`) and writing to stdout. It never
provisions, mutates, or spends against any real cloud resource.

Running it (`python3 infra/aws/poc/rerun_matrix.py --plan`) only ever prints
the matrix below as JSON; there is no other mode. The live AWS rerun this
matrix describes is NOT attempted by this script and requires its own fresh
cost/operational acceptance review and explicit authorization (account,
region, cost ceiling, cleanup plan) that does not exist yet -- see
`docs/poc/lambda-microvm-live-runbook.md`.
"""
import argparse
import json
from pathlib import Path

SCHEMA = "private-custodian.microvm-rerun-matrix/1"

# Reused verbatim from ADR 0137's capability-probe vocabulary; this matrix
# invents no new outcome vocabulary. "untested" covers both "the probe could
# not run" and "its positive control could not connect" -- never silently a
# pass. See ADR 0138 decision 3 for the IPv6-specific restatement of this rule.
OUTCOME_VOCABULARY = {
    "supported": "The mechanism was proven to work as intended on the exact pinned target.",
    "blocked": "The mechanism was proven absent/denied as intended on the exact pinned target.",
    "untested": (
        "The probe could not run (missing tool/runner/positive control), or its "
        "required positive control itself failed to connect/execute. Never read "
        "as a passing or failing denial; matches issue #55's explicit IPv6 rule "
        "and ADR 0137's three-outcome vocabulary."
    ),
}

# Every immutable pin category issue #57 requires ("immutable source/image-
# version/binary/tool/config pins"). The rerun must record an exact value for
# each, the same way ADR 0136/live_health.py already requires the returned
# image version to match the explicit requested configuration before launch.
REQUIRED_PINS = [
    {
        "pin": "aws_microvm_image_arn_and_version",
        "why": "ADR 0136 B1 vs B2: an omitted-field update silently replaced 512 MiB with a "
               "2048 MiB default and changed hooks/logging. The rerun must poll the exact "
               "returned version and refuse one that replaced any requested field with a "
               "service default, exactly as live_health.py's experiment() already does.",
        "source_of_truth": "docs/poc/lambda-microvm-live-evidence.json sourcePins / builds; "
                            "infra/aws/poc/live_health.py's IMAGE_CONFIGURATION_REFUSED check",
    },
    {
        "pin": "diagnostic_and_health_zip_sha256",
        "why": "The exact same immutable diagnostic/health image version used in the original "
               "experiment (or, if rebuilt, a newly pinned sha256 recorded before launch) must "
               "be used, not merely 'the same source files'.",
        "source_of_truth": "docs/poc/lambda-microvm-live-evidence.json sourcePins."
                            "diagnosticZipSha256 / healthZipSha256",
    },
    {
        "pin": "bubblewrap_and_prlimit_version",
        "why": "ADR 0137's addendum observed launcher=\"bubblewrap 0.9.0\" on the ARM64 CI "
               "runner. If the AWS MicroVM image ships a sandbox, its bwrap/prlimit versions "
               "must be recorded and compared; a different version is not the same evidence.",
        "source_of_truth": "ADR 0137 addendum (2026-10-04) log excerpt",
    },
    {
        "pin": "arm64_sandbox_image_manifest",
        "why": "deploy/examples/arm64-sandbox-image.example.json states the packages/kernel/"
               "mount contract an ARM64 image must provide before BubblewrapSandbox::detect() "
               "and run_self_check are even attempted. The rerun's actual AWS image must be "
               "checked against it line by line, not assumed to match.",
        "source_of_truth": "deploy/examples/arm64-sandbox-image.example.json",
    },
    {
        "pin": "worker_isolation_arm64_ci_run_identity",
        "why": "Every probe claimed below as proven_arm64_ci cites a specific CI job "
               "(worker-isolation-arm64) and log excerpt (ADR 0137/0139 addenda). The rerun "
               "must record which exact CI run (commit SHA, run id) it is treating as that "
               "evidence, so a later drift in crates/custodian-worker does not silently keep "
               "citing a stale pass.",
        "source_of_truth": "ADR 0137 addendum (2026-10-04); ADR 0139 addendum (2026-10-04)",
    },
    {
        "pin": "account_region_cost_ceiling_cleanup_plan",
        "why": "ADR 0136's $50 ceiling was for the one already-completed, torn-down "
               "experiment. docs/poc/lambda-microvm-live.md explicitly calls for 'a new "
               "cost/operational acceptance review' before further paid work. No quantified "
               "remaining budget exists in this repository's records.",
        "source_of_truth": "docs/poc/lambda-microvm-live.md 'Decisions and issue disposition'; "
                            "docs/poc/lambda-microvm-live-runbook.md",
    },
]


def _original_isolation_probes():
    """Every `isolation.controls.*.child.*` field from ADR 0136 / the
    evidence JSON, i.e. the exact P3 matrix S4 must rerun on the same exact
    image. `original_result` is copied from the committed evidence file, not
    recomputed -- this module reads no AWS output and never overwrites that
    record."""
    return [
        {
            "id": "runner_file_read",
            "evidence_field": "controlStateReadable",
            "description": "Same-uid child opens/reads the trusted runner's owner-only (0600) "
                            "synthetic control file.",
            "original_result": "reads (both allowed and denied VMs) -- FAILED; inner "
                                "filesystem/process trust boundary fails without a sandbox",
            "positive_control": "The runner process itself can read its own canary file "
                                 "(confirms the file exists and is readable at all before "
                                 "testing whether the child can).",
            "rerun_requirement": "Repeat on the exact image. If the image now wires a real "
                                  "inner sandbox (ADR 0137), additionally confirm the child's "
                                  "mount namespace never bind-mounts the runner's directory at "
                                  "all (ADR 0139's 'not present, not merely denied' property), "
                                  "not only that the read call fails.",
        },
        {
            "id": "dns_resolution",
            "evidence_field": "dnsResolved",
            "description": "Child resolves a public hostname (`example.com`) via the system "
                            "resolver.",
            "original_result": "resolves (both allowed and denied VMs) -- FAILED; "
                                "'Denied DNS claim fails'; SG/no-NAT alone is insufficient",
            "positive_control": "Allowed-egress VM resolving the same hostname.",
            "rerun_requirement": "Repeat on the exact image. If a real sandbox with "
                                  "--unshare-net is wired in, this is a strict consequence of "
                                  "'no network interface at all' (ADR 0138 addendum), not a "
                                  "dedicated name-resolution-attempt denial -- record both the "
                                  "named-resolution outcome and whether a network interface "
                                  "exists at all inside the child.",
        },
        {
            "id": "link_local_metadata",
            "evidence_field": "linkLocalTcpConnected",
            "description": "TCP connect from the child to `169.254.169.254:80` (and the "
                            "RFC 3927 / fe80::/10 link-local ranges generally).",
            "original_result": "connects (both allowed and denied VMs) -- FAILED; "
                                "'Denied link-local claim fails'; no HTTP/credential-access "
                                "claim was made or tested",
            "positive_control": "Allowed-egress VM connecting to the same address/port.",
            "rerun_requirement": "Repeat on the exact image, including the exact address ADR "
                                  "0136 found reachable. Do not substitute a generic egress "
                                  "probe for this named address.",
        },
        {
            "id": "ipv4_positive_control",
            "evidence_field": "ipv4Connected",
            "description": "TCP connect from the child to a resolved public IPv4 address "
                            "(`example.com:443`).",
            "original_result": "allowed VM connects, denied VM refuses -- the one control that "
                                "demonstrated denial, for this destination/port only",
            "positive_control": "The allowed-egress VM's own successful connect is the "
                                 "control; a denied-side refusal is only meaningful if the "
                                 "allowed side actually connected.",
            "rerun_requirement": "Repeat on the exact image; record pass/fail of the positive "
                                  "control itself, not only the denial.",
        },
        {
            "id": "ipv6_positive_control",
            "evidence_field": "ipv6Connected",
            "description": "TCP connect from the child over IPv6 to a public address.",
            "original_result": "refuses in BOTH allowed and denied VMs -- 'not assessable: "
                                "allowed positive control failed'; recorded untested, not "
                                "denied",
            "positive_control": "Allowed-egress VM connecting over IPv6; this is the exact "
                                 "control that failed last time.",
            "rerun_requirement": "Repeat on the exact image. If the allowed-side IPv6 control "
                                  "still cannot connect, this probe's outcome MUST be recorded "
                                  "'untested', never 'blocked' -- this is issue #55's explicit "
                                  "acceptance rule, restated verbatim in ADR 0138 decision 3.",
        },
        {
            "id": "unshare_tool_presence",
            "evidence_field": "unshareToolPresent",
            "description": "Whether the `unshare` binary is present at all inside the child "
                            "(a prerequisite for the user_namespace_support probe below).",
            "original_result": "absent on the unsandboxed diagnostic -- recorded untested; "
                                "tool absence does not prove kernel denial either way",
            "positive_control": "N/A for a tool-presence probe.",
            "rerun_requirement": "Check again on the exact image. ADR 0137's ARM64 capability "
                                  "probe already found `unshare` supported on a bare "
                                  "GitHub-hosted ARM64 runner; the AWS image may differ.",
        },
        {
            "id": "user_namespace_support",
            "evidence_field": "userNamespaceWorks",
            "description": "Whether an unprivileged user-namespace command (`unshare`) works "
                            "inside the child.",
            "original_result": "unshare tool absent on the unsandboxed diagnostic -- recorded "
                                "untested; absence of the tool does not prove kernel denial",
            "positive_control": "N/A for a tool-presence probe; the probe itself must report "
                                 "'untested' rather than inferring a kernel property from a "
                                 "missing binary.",
            "rerun_requirement": "ADR 0137's ARM64 capability probe already answered this for "
                                  "a bare GitHub-hosted ARM64 runner (supported). The rerun "
                                  "must check it again on the actual AWS image, since 'a pass "
                                  "on ubuntu-24.04-arm is evidence for that runner, not for "
                                  "every ARM64 execution environment' (ADR 0137 open risks).",
        },
        {
            "id": "credential_environment_absence",
            "evidence_field": "credentialEnvironmentPresent",
            "description": "Whether the child's environment, after an explicit clear/scrub, "
                            "still carries any credential-shaped variable.",
            "original_result": "absent after explicit scrub (both VMs) -- a limited "
                                "environment observation, not a complete snapshot/file/"
                                "credential isolation proof",
            "positive_control": "The launcher's own environment, pre-scrub, is known to "
                                 "contain the canary (confirms the scrub step did something).",
            "rerun_requirement": "Repeat on the exact image. If a real sandbox is wired in, "
                                  "additionally run against the expanded proxy/resolver "
                                  "canary list ADR 0138 decision 2 specifies "
                                  "(HTTP_PROXY/http_proxy/HTTPS_PROXY/ALL_PROXY/NO_PROXY/"
                                  "RES_OPTIONS/HOSTALIASES) if that probe code has landed by "
                                  "rerun time -- see the design_only matrix below if not.",
        },
        {
            "id": "child_executes_at_all",
            "evidence_field": "trueToolWorks",
            "description": "The child process can run a trivial command (`true`) and exit "
                            "cleanly -- the base positive control every denial above depends "
                            "on.",
            "original_result": "works (both VMs)",
            "positive_control": "This probe IS the positive control for 'the child runs at "
                                 "all'; every other probe above is meaningless if this fails.",
            "rerun_requirement": "Repeat first, before any denial probe; a failure here voids "
                                  "every other result in this table for that VM.",
        },
    ]


def _original_health_lifecycle_probes():
    """Every `healthLifecycle.checks.*` field from ADR 0136 / the evidence
    JSON. The token-TTL failure must stay explicit per issue #57's own text
    ('Keep the endpoint-token expiry failure explicit ... Do not claim those
    implementations exist if still absent')."""
    return [
        {
            "id": "token_ttl_enforcement",
            "evidence_field": "expiredTokenDenied",
            "description": "A one-minute endpoint auth token is denied (403) once its "
                            "requested expiration has passed.",
            "original_result": "FAILED -- health 200 observed at 65.1s and 90.4s after a "
                                "1-minute-expiry token response, 403 only at 125.1s; no "
                                "universal grace duration or server cause is inferred",
            "positive_control": "The token works at all shortly after issuance (observed "
                                 "200 at ~2.4s) -- confirms the token mechanism functions "
                                 "before testing its expiry.",
            "rerun_requirement": "Repeat the exact timed observation sequence. This issue's "
                                  "own acceptance criteria require proving caller/attempt "
                                  "authorization and a live lease/cancellation refusal "
                                  "INDEPENDENTLY of provider token TTL (coordinate with #42/"
                                  "#44) -- a passing token-expiry timing observation must "
                                  "never be read as 'the custodian has an authoritative "
                                  "fence'; it is provider UX only.",
        },
        {
            "id": "creation_replay_same_vm",
            "evidence_field": "creationReplaySameVm",
            "description": "Two identical RunMicrovm requests with the same client token "
                            "return the same VM.",
            "original_result": "true -- proves the sampled provider replay behavior, not "
                                "retention beyond the tested window or durable custody fencing",
            "positive_control": "A distinct client token on the same request shape returns a "
                                 "distinct VM (freshVmDistinct).",
            "rerun_requirement": "Repeat; do not generalize beyond the tested replay window.",
        },
        {
            "id": "fresh_vm_distinct",
            "evidence_field": "freshVmDistinct",
            "description": "A distinct client token produces a distinct fresh VM.",
            "original_result": "true",
            "positive_control": "Same as above, inverse case.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "explicit_image_configuration",
            "evidence_field": "explicitImageConfiguration",
            "description": "The returned image version matches every explicitly requested "
                            "field (memory, hooks, logging) with no service default "
                            "substituted.",
            "original_result": "true on B3/B4 after B1/B2 showed an update can silently "
                                "replace omitted fields with defaults",
            "positive_control": "N/A -- this check IS the positive/negative gate; "
                                 "live_health.py already refuses to proceed without it "
                                 "(IMAGE_CONFIGURATION_REFUSED).",
            "rerun_requirement": "Repeat verbatim; this is a hard precondition, not a "
                                  "probe result to interpret.",
        },
        {
            "id": "health_endpoint_fixed_body",
            "evidence_field": "health",
            "description": "`/health` on port 8080 with a valid token returns 200 and the "
                            "fixed synthetic JSON body.",
            "original_result": "true",
            "positive_control": "This IS the positive control the missing/invalid/wrong-port/"
                                 "wrong-VM denials below depend on.",
            "rerun_requirement": "Repeat first, before the denial checks below.",
        },
        {
            "id": "missing_token_denied",
            "evidence_field": "missingTokenDenied",
            "description": "`/health` without a token returns 403.",
            "original_result": "true",
            "positive_control": "health_endpoint_fixed_body above.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "invalid_token_denied",
            "evidence_field": "invalidTokenDenied",
            "description": "`/health` with a syntactically-invalid token returns 403.",
            "original_result": "true",
            "positive_control": "health_endpoint_fixed_body above.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "wrong_port_denied",
            "evidence_field": "wrongPortDenied",
            "description": "A valid token for port 8080 is rejected on port 8081.",
            "original_result": "true",
            "positive_control": "health_endpoint_fixed_body above.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "wrong_vm_denied",
            "evidence_field": "wrongVmDenied",
            "description": "A token issued for one VM is rejected by a different VM.",
            "original_result": "true",
            "positive_control": "health_endpoint_fixed_body above.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "job_refused",
            "evidence_field": "jobRefused",
            "description": "POST `/job` is refused (403, empty body) -- this diagnostic image "
                            "accepts no evaluation job.",
            "original_result": "true",
            "positive_control": "N/A -- a refusal-by-design check.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "shell_token_denied",
            "evidence_field": "shellTokenDenied",
            "description": "Requesting a shell auth token without a shell connector is "
                            "refused with ValidationException.",
            "original_result": "true",
            "positive_control": "N/A -- a refusal-by-design check.",
            "rerun_requirement": "Repeat.",
        },
        {
            "id": "maximum_lifetime_terminates",
            "evidence_field": "maximumLifetimeTerminates",
            "description": "A VM configured with a 60-second maximum lifetime reaches "
                            "TERMINATED on its own.",
            "original_result": "true -- observed service interval 61.736 seconds",
            "positive_control": "N/A -- this is itself the control being measured.",
            "rerun_requirement": "Repeat; record the exact observed interval again. Finite "
                                  "lifetime bounds exposure but does not prove cleanup or "
                                  "authoritative fencing after coordinator failure -- do not "
                                  "claim more than that from a repeat pass.",
        },
    ]


def _arm64_ci_proven_probes():
    """Adversarial/positive cases from ADR 0137/0138/0139 that already have
    real, observed ARM64 CI evidence (the `worker-isolation-arm64` job), per
    both ADRs' 2026-10-04 addenda. Each entry cites the exact test name and
    the ADR that recorded the passing run. None of these have been rerun
    against the real AWS MicroVM image -- that is exactly what S4 adds."""
    required_checks = [
        "egress_denied", "host_files_absent", "env_scrubbed",
        "write_outside_scratch_denied", "scratch_writable",
        "pid_namespace", "no_capabilities", "rlimits_applied",
    ]
    entries = [
        {
            "id": f"self_check_{check}",
            "category": "s1_self_check_required_check",
            "description": f"Startup self-check required check '{check}' "
                            "(crates/custodian-worker/src/isolation.rs REQUIRED_CHECKS), run "
                            "inside the real BubblewrapSandbox.",
            "ci_test": "linux_self_check_records_real_verification",
            "ci_citation": "ADR 0137 addendum (2026-10-04): 15 passed; 0 failed on "
                            "ubuntu-24.04-arm, launcher=\"bubblewrap 0.9.0\"",
            "aws_rerun_requirement": "Run the real self-check (not a capability probe) inside "
                                      "the actual AWS MicroVM image's sandbox, if/when one is "
                                      "wired into that image; record per-check supported/"
                                      "blocked/untested exactly as the self-check already does.",
        }
        for check in required_checks
    ]
    entries += [
        {
            "id": "network_egress_denied_full_suite",
            "category": "s1_s2_network",
            "description": "Loopback, public, TEST-NET and RFC 1918 TCP, plus a UDP send, all "
                            "denied from inside the sandbox, with host_listener_untouched "
                            "confirming the host side saw no connection.",
            "ci_test": "linux_network_egress_is_denied_including_host_loopback",
            "ci_citation": "ADR 0137/0138 addenda (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the exact AWS image's sandboxed child, "
                                      "if wired in. Note (ADR 0138 addendum): this proves "
                                      "'--unshare-net leaves no interface up at all', a "
                                      "stronger property than a dedicated DNS/link-local probe "
                                      "by name -- it does not substitute for the named "
                                      "dns_resolution/link_local_metadata probes above, which "
                                      "must still be run by name against the real AWS image.",
        },
        {
            "id": "host_files_not_reachable",
            "category": "s1_s3_filesystem",
            "description": "Direct answer to ADR 0136's same-uid runner-file-read finding: "
                            "the runner's control file, credentials and host paths are not "
                            "present (not merely denied) in the sandboxed child's mount "
                            "namespace.",
            "ci_test": "linux_host_files_are_not_reachable",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "This is the exact AWS rerun target for the "
                                      "'runner_file_read' probe above: repeat on the real AWS "
                                      "image with the real sandbox wired in, and confirm the "
                                      "same absence property, not just a permission-denied "
                                      "error.",
        },
        {
            "id": "launcher_credentials_and_env_never_reach_worker",
            "category": "s1_s3_environment",
            "description": "Launcher environment/credentials never reach the sandboxed "
                            "child; only the allowlisted names survive --clearenv.",
            "ci_test": "linux_launcher_credentials_and_env_never_reach_the_worker",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "staged_artifacts_read_only",
            "category": "s1_s3_filesystem",
            "description": "Staged engine/adapter/scanner/candidate/config artifacts are "
                            "read-only to the worker.",
            "ci_test": "linux_staged_artifacts_are_read_only_to_the_worker",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "fork_bomb_bounded",
            "category": "s3_resource",
            "description": "A fork-bomb child is bounded by RLIMIT_NPROC and cleaned up.",
            "ci_test": "linux_fork_bomb_is_bounded_and_cleaned",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "memory_exhaustion_bounded",
            "category": "s3_resource",
            "description": "A memory-exhaustion attempt is bounded by RLIMIT_AS.",
            "ci_test": "linux_memory_exhaustion_is_bounded",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "disk_exhaustion_bounded",
            "category": "s3_resource",
            "description": "A disk-exhaustion attempt against /scratch is bounded to the "
                            "quota.",
            "ci_test": "linux_disk_exhaustion_is_bounded_to_the_scratch_quota",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "cpu_spin_bounded",
            "category": "s3_resource",
            "description": "A CPU-spin attempt is stopped by RLIMIT_CPU.",
            "ci_test": "linux_cpu_spin_is_stopped_by_the_cpu_limit",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "stdout_flood_bounded",
            "category": "s3_resource",
            "description": "A stdout-flood attempt trips OutputLimit and kills the tree "
                            "without blocking the supervisor.",
            "ci_test": "linux_stdout_flood_is_bounded",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "timeout_kills_whole_tree",
            "category": "s3_resource",
            "description": "A wall-clock timeout kills the whole process tree, including a "
                            "daemonized grandchild.",
            "ci_test": "linux_timeout_kills_the_whole_tree",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "cancellation_cleans_up_tree",
            "category": "s3_lifecycle",
            "description": "Cancellation during a run cleans up the whole worker process "
                            "tree.",
            "ci_test": "linux_cancellation_cleans_up_the_worker_tree",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox. Note: this "
                                      "is cleanup of the worker's own process tree, not the "
                                      "separate, still-absent authoritative remote VM "
                                      "fence/janitor issue #57 and #44 track.",
        },
        {
            "id": "identity_tampering_fails_closed",
            "category": "s1_s3_integrity",
            "description": "Artifact identity tampering (digest mismatch) after staging "
                            "fails closed under the real sandbox.",
            "ci_test": "linux_identity_tampering_fails_closed_under_the_real_sandbox",
            "ci_citation": "ADR 0139 addendum (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
        {
            "id": "hostile_engine_cannot_leak_bytes",
            "category": "s3_pipeline_forged_result",
            "description": "A hostile engine inside the real sandbox cannot carry protected "
                            "bytes out through the result channel or any other path.",
            "ci_test": "a_hostile_engine_inside_real_bubblewrap_still_cannot_carry_"
                       "protected_bytes_out",
            "ci_citation": "ADR 0137/0139 addenda (2026-10-04): passed on ubuntu-24.04-arm "
                            "(linux_pipeline.rs, 2 passed; 0 failed)",
            "aws_rerun_requirement": "Repeat end to end through the daemon pipeline against "
                                      "the real AWS image's sandbox, if wired in.",
        },
        {
            "id": "pipeline_releases_verifiable_projection",
            "category": "s3_pipeline",
            "description": "The pipeline releases a verifiable projection with the engine "
                            "running inside the real sandbox.",
            "ci_test": "the_pipeline_releases_a_verifiable_projection_with_the_engine_"
                       "inside_real_bubblewrap",
            "ci_citation": "ADR 0137/0139 addenda (2026-10-04): passed on ubuntu-24.04-arm",
            "aws_rerun_requirement": "Repeat against the real AWS image's sandbox.",
        },
    ]
    return entries


# ADR 0138 decision 2 and ADR 0139 decision 2's new matrix items that are, as
# of this writing, still DESIGN ONLY -- specified but not implemented or run,
# per both ADRs' own "Status of the claim" tables and their 2026-10-04
# addenda ("What did NOT change"). A separate, parallel PR is reported to be
# implementing some of these now; this module never assumes that work has
# landed or passed -- see `_grep_hint` below, which only ever adds an
# informational note, never upgrades an entry's `ci_evidence_status`.
_PENDING_DESIGN_ONLY_PROBES = [
    {
        "id": "dns_by_name_and_raw_socket",
        "adr": "ADR 0138 decision 2",
        "description": "DNS over UDP/TCP to a public resolver and to loopback, by name "
                        "resolution attempt and by raw socket connect to a well-known DNS "
                        "port.",
        "grep_hint_patterns": ["fn linux_dns", "fn .*dns_denied", "fn .*dns_resolution"],
    },
    {
        "id": "link_local_by_name_and_range",
        "adr": "ADR 0138 decision 2",
        "description": "169.254.169.254 by name, the RFC 3927 IPv4 link-local range "
                        "generally, and the fe80::/10 IPv6 range.",
        "grep_hint_patterns": ["fn linux_link_local", "fn .*169_254", "fn .*link_local"],
    },
    {
        "id": "ipv6_dedicated_probe",
        "adr": "ADR 0138 decision 2",
        "description": "IPv6 positive control and denial, as a dedicated named case "
                        "(distinct from the egress_denied suite's current IPv4-only "
                        "targets).",
        "grep_hint_patterns": ["fn linux_ipv6", "fn .*ipv6"],
    },
    {
        "id": "inherited_descriptor_count",
        "adr": "ADR 0138 decision 2 / ADR 0139 decision 2",
        "description": "Count of open file descriptors visible to the child via "
                        "/proc/self/fd, asserted to equal exactly the three standard streams.",
        "grep_hint_patterns": ["fn linux_fd_count", "fn .*descriptor", "fn .*inherited_fd"],
    },
    {
        "id": "proxy_resolver_environment_canaries",
        "adr": "ADR 0138 decision 2",
        "description": "Extended CANARY_ENV-style check for HTTP_PROXY/http_proxy/"
                        "HTTPS_PROXY/ALL_PROXY/NO_PROXY/RES_OPTIONS/HOSTALIASES.",
        "grep_hint_patterns": ["HTTP_PROXY", "RES_OPTIONS", "HOSTALIASES"],
    },
    {
        "id": "symlink_hardlink_scratch_escape",
        "adr": "ADR 0139 decision 2 (filesystem)",
        "description": "Symlink/hardlink construction inside /scratch confirmed unable to "
                        "reach outside it.",
        "grep_hint_patterns": ["fn linux_symlink", "fn linux_hardlink", "fn .*scratch_escape"],
    },
    {
        "id": "writable_mount_escape_through_ro_mount",
        "adr": "ADR 0139 decision 2 (filesystem)",
        "description": "Attempted write through a RoMount, confirming --remount-ro / still "
                        "denies it.",
        "grep_hint_patterns": ["fn linux_ro_mount_escape", "fn .*mount_escape"],
    },
    {
        "id": "supplementary_group_escape",
        "adr": "ADR 0137 privilege-drop step 7; ADR 0139 decision 2 (privilege)",
        "description": "Attempted escape via an inherited supplementary group; an explicit "
                        "open risk, not yet a positive control (getgroups() is not asserted "
                        "by the self-check today).",
        "grep_hint_patterns": ["getgroups", "fn .*supplementary_group"],
    },
    {
        "id": "forged_worker_result_adversarial_probe",
        "adr": "ADR 0139 decision 2 (forged completion)",
        "description": "A dedicated adversarial probe (distinct from the existing parser "
                        "unit tests) that attempts to make a hostile engine's forged "
                        "worker-result/1 document pass as a complete/full-roster Success.",
        "grep_hint_patterns": ["fn .*forged_result", "fn .*forged_worker_result"],
    },
    {
        "id": "descendant_daemonized_process_survival",
        "adr": "ADR 0139 decision 2 (process)",
        "description": "Descendant/daemonized process survival across a normal exit, a "
                        "timeout, and a kill_group sweep, beyond what the existing fork-bomb "
                        "test covers.",
        "grep_hint_patterns": ["fn .*daemonized_descendant", "fn .*process_survival"],
    },
]


def _grep_hint(repo_root, patterns):
    """Best-effort, informational only: note whether any `.rs` test file in
    this repository already contains a name matching one of the given
    substrings. This NEVER asserts the probe ran, passed, or is CI-proven --
    only that a human should check whether the parallel S2/S3 implementation
    PR mentioned in issue #57's context has landed a candidate test with this
    shape, so this matrix does not have to be hand-edited to find out. No
    subprocess, no shell, no network: plain-text file reads only."""
    import re as _re

    hits = []
    tests_root = Path(repo_root) / "crates"
    if not tests_root.is_dir():
        return hits
    compiled = [_re.compile(p) for p in patterns]
    for rs_file in sorted(tests_root.glob("*/tests/*.rs")):
        try:
            text = rs_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in compiled:
            for match in pattern.finditer(text):
                hits.append(f"{rs_file.relative_to(repo_root)}: {match.group(0)}")
    return sorted(set(hits))


def _pending_design_only_probes(repo_root):
    entries = []
    for item in _PENDING_DESIGN_ONLY_PROBES:
        entries.append({
            "id": item["id"],
            "category": "design_only_pending_s2_s3",
            "description": item["description"],
            "specified_in": item["adr"],
            "ci_evidence_status": "design_only",
            "note": "Specified, not implemented or run on any architecture as of the ADRs' "
                    "2026-10-04 addenda. A parallel S2/S3 implementation effort is reported "
                    "to be in progress; this matrix does not assume it has landed or passed.",
            "repo_grep_hint": _grep_hint(repo_root, item["grep_hint_patterns"]),
        })
    return entries


def build_matrix(repo_root="."):
    repo_root = Path(repo_root).resolve()
    return {
        "schema": SCHEMA,
        "issue": 57,
        "epic": 40,
        "executed": False,
        "awsApiCallsMade": 0,
        "requiresFreshAuthorization": True,
        "authorizationRequirements": [
            "account", "region", "cost_ceiling", "cleanup_plan",
        ],
        "authorizationStatus": (
            "No fresh authorization exists. ADR 0136's $50 ceiling covered one "
            "already-completed, torn-down experiment. docs/poc/lambda-microvm-live.md "
            "explicitly calls for a new cost/operational acceptance review before any "
            "further paid AWS work."
        ),
        "outcomeVocabulary": OUTCOME_VOCABULARY,
        "requiredPins": REQUIRED_PINS,
        "originalIsolationProbes": _original_isolation_probes(),
        "originalHealthLifecycleProbes": _original_health_lifecycle_probes(),
        "arm64CiProvenProbes": _arm64_ci_proven_probes(),
        "pendingDesignOnlyProbes": _pending_design_only_probes(repo_root),
    }


def _plan_text(matrix):
    lines = [
        "S4 (#57) reproducible rerun matrix -- PLAN ONLY, NOT EXECUTED.",
        "No AWS API call was made to produce this plan.",
        "",
        f"Original ADR 0136 isolation probes to rerun: {len(matrix['originalIsolationProbes'])}",
        f"Original ADR 0136 health/lifecycle probes to rerun: "
        f"{len(matrix['originalHealthLifecycleProbes'])}",
        f"ARM64 CI-proven probes to repeat against the real AWS image: "
        f"{len(matrix['arm64CiProvenProbes'])}",
        f"Design-only ADR 0138/0139 probes not yet CI-evidenced (reported, not required "
        f"to pass before the rerun, but must not be silently dropped from scope): "
        f"{len(matrix['pendingDesignOnlyProbes'])}",
        "",
        "Fresh authorization required before any AWS call: "
        + ", ".join(matrix["authorizationRequirements"]),
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan", action="store_true", default=True,
        help="Print the rerun matrix as JSON. This is the only mode; no AWS call is ever "
             "made by this script.",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print a short human-readable summary instead of the full JSON matrix.",
    )
    args = parser.parse_args()
    built = build_matrix(Path(__file__).resolve().parents[3])
    if args.summary:
        print(_plan_text(built))
    else:
        print(json.dumps(built, indent=2, sort_keys=True))
