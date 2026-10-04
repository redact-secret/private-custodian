#!/usr/bin/env python3
"""Offline synthetic build-context inventory check for the MicroVM image.

No AWS call, no network access, no protected data. This enumerates the exact
files `docker build` would send into the image build context for this
directory, by replicating this directory's own flat `.dockerignore`
allow-list semantics, and classifies every included path against an explicit
denylist of corpus/seed/ledger/key/token/operational-identifier patterns.

This proves the in-repo build context (what `COPY` can reach) is free of
such material and matches the one reviewed allowlist. It does NOT verify the
restored AWS snapshot, build-role residue, or anything about a deployed
image; see docs/poc/lambda-microvm.md and docs/poc/lambda-microvm-live.md for
what remains unverified there. This is a synthetic/offline conformance
check, not independent validation and not a deployment attestation.
"""
import re
from pathlib import Path

# Matched case-insensitively against each included file's bare name. Keep
# this list explicit and reviewed by hand; do not generalize to "any
# non-source extension" since that would also reject legitimate new tool
# sources. A hit here fails the check regardless of the allowlist below.
DENYLIST_PATTERNS = (
    r"corpus",
    r"seed",
    r"ledger",
    r"receipt",
    r"disclosure",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"token",
    r"secret",
    r"credential",
    r"\.env(\.|$)",
    r"id_rsa",
    r"id_ed25519",
    r"\.aws",
)

# The reviewed, exact set of files this image build context is allowed to
# contain. A new file must be added here deliberately by a reviewer, never
# inferred from whatever the directory happens to hold.
ALLOWED_FILES = frozenset({"Dockerfile", "health.rs", "Dockerfile.probe", "probe.rs"})


def parse_dockerignore(text):
    """Return (ignore_all, allow_names) for a flat `.dockerignore`.

    This repository's `.dockerignore` for the image directory is
    intentionally flat: a leading `*` followed by exact `!name` allow
    lines. This parser fails closed: it raises on any pattern outside that
    narrow shape (globs, negated directories, nested paths) rather than
    silently approximating full Docker ignore-file glob semantics.
    """
    ignore_all = False
    allow = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "*":
            ignore_all = True
            continue
        if line.startswith("!") and "/" not in line[1:] and "*" not in line[1:]:
            allow.add(line[1:])
            continue
        raise ValueError(f"unsupported .dockerignore pattern: {line!r}")
    return ignore_all, allow


def build_context_files(image_dir):
    """Return the sorted file names Docker would include as build context.

    Raises if `.dockerignore` is missing or unparseable; a missing allowlist
    must never be silently treated as "include everything".
    """
    image_dir = Path(image_dir)
    dockerignore_text = (image_dir / ".dockerignore").read_text(encoding="utf-8")
    ignore_all, allow = parse_dockerignore(dockerignore_text)
    names = {p.name for p in image_dir.iterdir() if p.is_file() and p.name != ".dockerignore"}
    included = (names & allow) if ignore_all else names
    return sorted(included)


def denylist_hits(paths):
    """Return {path: [matched_pattern, ...]} for every path matching the denylist."""
    hits = {}
    for path in paths:
        matched = [pattern for pattern in DENYLIST_PATTERNS if re.search(pattern, path, re.IGNORECASE)]
        if matched:
            hits[path] = matched
    return hits


def report(image_dir):
    included = build_context_files(image_dir)
    return {
        "schema": "private-custodian.microvm-image-inventory/1",
        "included_files": included,
        "matches_reviewed_allowlist": set(included) == ALLOWED_FILES,
        "denylist_hits": denylist_hits(included),
        # Explicit, so this is never mistaken for deployment or snapshot proof.
        "snapshot_build_or_restore_verified": False,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(report(Path(__file__).resolve().parent), sort_keys=True))
