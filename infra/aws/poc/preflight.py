#!/usr/bin/env python3
"""Read-only AWS support check. Emits an allowlist, never raw API responses."""
import argparse
import json
import os
import subprocess


def aws(service, operation, *args):
    env = dict(os.environ, AWS_PAGER="", AWS_PROFILE="redact-secret")
    try:
        result = subprocess.run(
            ["aws", service, operation, *args, "--region", "us-east-1",
             "--output", "json", "--cli-connect-timeout", "10", "--cli-read-timeout", "15"],
            capture_output=True, timeout=120, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None  # Never emit account, paths, ARNs, error text or credentials.
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        return None


def report(call=aws):
    identity = call("sts", "get-caller-identity")
    managed = call("lambda-microvms", "list-managed-microvm-images")
    running = call("lambda-microvms", "list-microvms")
    versions = call(
        "lambda-microvms", "list-managed-microvm-image-versions",
        "--image-identifier", "arn:aws:lambda:us-east-1:aws:microvm-image:al2023-1",
    )
    return {
        "schema": "private-custodian.microvm-preflight/1",
        "region": "us-east-1",
        "authenticated": isinstance(identity, dict) and bool(identity.get("Account")),
        "managed_image_api": isinstance(managed, dict) and isinstance(managed.get("items"), list) and bool(managed["items"]),
        "managed_version_api": isinstance(versions, dict) and isinstance(versions.get("items"), list) and bool(versions["items"]),
        "inventory_api": isinstance(running, dict) and isinstance(running.get("items"), list),
        # A count is not a resource inventory or proof of cleanup.
        "resources_created_by_preflight": 0,
        "runtime_verified": False,
        "worker_decision": "NO-GO",
        "control_plane_decision": "NO-GO",
    }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(report(), sort_keys=True))
