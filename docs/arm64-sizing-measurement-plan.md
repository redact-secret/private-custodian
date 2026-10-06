# ARM64 EC2 sizing measurement plan and template (#45, ADR 0145)

Status: plan and empty template. **Nothing here has been measured.** Every value is `UNMEASURED` until it is
recorded from the exact ARM64 EC2 host by an authorized experiment (#40 cost ceiling and cleanup plan, #72).
Linux x86_64 reference numbers (including ADR 0135's Node v22 interval) must not be copied into this table or
cited as ARM64 proof. Synthetic public inputs only; no protected data, no production credentials.

## Method

1. Record the host identity first: instance type, AMI id, `uname -m`, kernel, bwrap/prlimit versions, the result
   of the mandatory sandbox self-check on that host. If the self-check fails or is skipped, stop; do not record
   sizing as accepted.
2. Pin runtimes by file digest for ARM64 (Node, engine binary, scanner bundle). An x86_64 digest is a different
   artifact.
3. Per profile, run N>=5 cold starts through the real dispatcher path and record the minimum, median and
   maximum. Measure startup, peak resident set (not RLIMIT_AS) and wall time separately.
4. Find the enforced `RLIMIT_AS` boundary by bisection between a failing and a passing value; record both ends.
   Treat this as virtual-address-space evidence only.
5. Record host baseline resident memory with no job running and the burst headroom with the job at peak.
6. `--jitless` is measured as its own profile and only if the engine declares it; never as a replacement.

## Template (fill from the host only)

| Item | Credential engine (Rust) | PII engine (Node) | PII engine (Node, `--jitless`, only if engine declares it) |
| --- | --- | --- | --- |
| Instance type / vCPU / RAM | UNMEASURED | UNMEASURED | UNMEASURED |
| Architecture and kernel | UNMEASURED | UNMEASURED | UNMEASURED |
| Sandbox self-check result | UNMEASURED | UNMEASURED | UNMEASURED |
| Runtime / engine / scanner file digests (ARM64) | UNMEASURED | UNMEASURED | UNMEASURED |
| Cold start, min / median / max | UNMEASURED | UNMEASURED | UNMEASURED |
| Peak resident set | UNMEASURED | UNMEASURED | UNMEASURED |
| RLIMIT_AS failing / passing boundary | UNMEASURED | UNMEASURED | UNMEASURED |
| Host baseline resident memory | UNMEASURED | UNMEASURED | UNMEASURED |
| Burst headroom at peak | UNMEASURED | UNMEASURED | UNMEASURED |
| Corpus headroom (synthetic roster size tested) | UNMEASURED | UNMEASURED | UNMEASURED |
| Bundle and scanner size on disk | UNMEASURED | UNMEASURED | UNMEASURED |
| Enforced limits used (AS, CPU, NPROC, FSIZE, output) | UNMEASURED | UNMEASURED | UNMEASURED |
| Positive/negative contract cases passed | UNMEASURED | UNMEASURED | UNMEASURED |

Recorded values are approver information, not permission to raise a limit, and are project-owned evidence, not
independent validation.
