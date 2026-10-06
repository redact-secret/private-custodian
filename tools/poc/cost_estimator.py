#!/usr/bin/env python3
"""Offline P7 cost estimator for the EC2 worker PoC (ADR 0147, issue #47).

Reads a JSON inputs file, validates every required cost component, and prints a
daily/monthly estimate only when EVERY required input is MEASURED and complete.
Any UNMEASURED, ESTIMATE, missing, null, negative, or non-numeric input makes it
refuse (exit 2) and list the blockers; it never fills a default, never reads
ADR 0141 placeholder figures, and never assumes a Lambda free tier. It makes no
network call and needs no AWS credentials. Python standard library only.
Project-owned arithmetic, not independent validation.
"""
import json
import math
import sys

STATUSES = ("MEASURED", "ESTIMATE", "UNMEASURED")
BASES = ("per_run", "per_day", "per_month")
RUNS_PER_DAY = (4, 8)  # issue #47 sizing band
DAYS_PER_MONTH = 30  # stated convention, not a billing statement

# component id -> (description, required billed-unit hint)
REQUIRED = {
    "compute_burst": "EC2 on-demand instance-seconds while running (launch to terminate)",
    "ebs_volumes": "EBS GiB-month and any provisioned IOPS/throughput for root/data volumes (until deleted)",
    "ami_snapshot_storage": "AMI backing snapshot GiB-month plus any copy/restore reads",
    "interface_endpoint_hours": "interface VPC endpoint hours (per AZ) for the control channel",
    "endpoint_data_processing": "GB processed through interface endpoints",
    "gateway_endpoint_and_transfer": "S3 gateway endpoint (no hourly charge) plus request and data transfer charges",
    "logs": "log ingestion GB and retained GB-month",
    "janitor_and_control_services": "independent janitor and control-service compute and requests",
    "signing": "signer operations and key-provider charges (the worker never signs)",
    "retained_resources": "anything intentionally retained with owner and expiry (else zero, measured)",
}

EXCLUSIONS = (
    "AWS Support plans, taxes, credits, free-tier offsets, Savings Plans or Reserved discounts",
    "engineer time, review time and CI minutes",
    "protected corpus storage and private-ledger hosting outside this worker path",
    "any resource not in the component list (a new resource is a new required component)",
    "ordinary Lambda free-tier assumptions are never applied",
    "self-hosted CI runner (must be a separate host, ADR 0141/0142)",
)


class Refusal(Exception):
    pass


def _check(inputs):
    problems = []
    comps = inputs.get("components")
    if not isinstance(comps, dict):
        raise Refusal(["components object missing"])
    for extra in sorted(set(comps) - set(REQUIRED)):
        problems.append(f"{extra}: unknown component (add it to REQUIRED with a decision)")
    for cid in REQUIRED:
        c = comps.get(cid)
        if not isinstance(c, dict):
            problems.append(f"{cid}: missing")
            continue
        st = c.get("status")
        if st not in STATUSES:
            problems.append(f"{cid}: status must be one of {STATUSES}")
            continue
        if st != "MEASURED":
            problems.append(f"{cid}: status {st}, need MEASURED")
            continue
        for k in ("billed_unit", "source"):
            if not isinstance(c.get(k), str) or not c[k].strip():
                problems.append(f"{cid}: {k} required for a MEASURED input")
        if c.get("basis") not in BASES:
            problems.append(f"{cid}: basis must be one of {BASES}")
        for k in ("quantity", "unit_price_usd"):
            v = c.get(k)
            if isinstance(v, bool) or not isinstance(v, (int, float)) \
                    or not math.isfinite(v) or v < 0:
                problems.append(f"{cid}: {k} must be a finite number >= 0")
    if problems:
        raise Refusal(problems)


def estimate(inputs):
    """Return the estimate dict or raise Refusal listing every blocker."""
    _check(inputs)
    out = {"runs_per_day": {}, "exclusions": list(EXCLUSIONS),
           "days_per_month": DAYS_PER_MONTH}
    for runs in RUNS_PER_DAY:
        daily = 0.0
        for c in inputs["components"].values():
            cost = c["quantity"] * c["unit_price_usd"]
            if c["basis"] == "per_run":
                daily += cost * runs
            elif c["basis"] == "per_day":
                daily += cost
            else:
                daily += cost / DAYS_PER_MONTH
        out["runs_per_day"][str(runs)] = {
            "daily_usd": round(daily, 4),
            "monthly_usd": round(daily * DAYS_PER_MONTH, 4),
        }
    return out


def main(argv):
    if len(argv) != 2:
        print("usage: cost_estimator.py INPUTS.json", file=sys.stderr)
        return 64
    with open(argv[1], encoding="utf-8") as f:
        inputs = json.load(f)
    try:
        result = estimate(inputs)
    except Refusal as r:
        print("REFUSED: no total emitted; required inputs are not all MEASURED")
        for p in r.args[0]:
            print(f"  - {p}")
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
