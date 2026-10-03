#!/usr/bin/env python3
"""Second, independent implementation of custodian-canonical-json/1 and of the
domain-separated digest, checked against the golden vectors (C12).

This is deliberately NOT a port of the Rust code. It is written from the rules
in docs/adr/0004-canonical-encoding-digests-and-contract-dependencies.md:

  * compact JSON, object members sorted by key (RFC 8785 subset);
  * integers only, 0..=2^53-1, no sign, fraction or exponent;
  * strings restricted to printable ASCII 0x20..0x7e without '"' or '\\';
  * no null; no duplicate members;
  * digest = SHA-256(domain || 0x00 || canonical_bytes), "sha256:" + 64 hex.

It uses only the Python standard library. Exit status 0 means every golden
vector re-canonicalizes to the identical bytes and every digest matches the
value recorded in digests.txt. It proves the encoding and digest rules can be
reproduced by a second implementation; it says nothing about the content of
any document. Run: python3 crates/custodian-contracts/testdata/verify_golden.py
"""

import hashlib
import json
import os
import sys

MAX_INT = 2**53 - 1


class NotCanonicalizable(Exception):
    pass


def _string(s):
    if any(not (0x20 <= ord(c) <= 0x7E) or c in '"\\' for c in s):
        raise NotCanonicalizable("string outside the allowed subset")
    return '"' + s + '"'


def canon(v):
    if v is None:
        raise NotCanonicalizable("null")
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if v < 0 or v > MAX_INT:
            raise NotCanonicalizable("integer out of range")
        return str(v)
    if isinstance(v, float):
        raise NotCanonicalizable("float")
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        # Keys are ASCII, so code point order equals UTF-16 order (JCS).
        return "{" + ",".join(_string(k) + ":" + canon(v[k]) for k in sorted(v)) + "}"
    raise NotCanonicalizable("unsupported type")


def _no_duplicates(pairs):
    seen = {}
    for k, val in pairs:
        if k in seen:
            raise NotCanonicalizable("duplicate member")
        seen[k] = val
    return seen


def _reject_float(text):
    raise NotCanonicalizable("float " + text[:0])


def parse(raw):
    return json.loads(
        raw.decode("ascii"),
        object_pairs_hook=_no_duplicates,
        parse_float=_reject_float,
        parse_constant=_reject_float,
    )


def digest(domain, canonical_bytes):
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical_bytes)
    return "sha256:" + h.hexdigest()


def negative_controls():
    """The implementation must refuse what the rules refuse."""
    for bad in (
        b'{"a":null}',
        b'{"a":1.5}',
        b'{"a":-1}',
        b'{"a":9007199254740992}',
        b'{"a":"caf\xc3\xa9"}',
        b'{"a":1,"a":2}',
    ):
        try:
            canon(parse(bad))
        except (NotCanonicalizable, UnicodeDecodeError, ValueError):
            continue
        raise SystemExit("negative control accepted: %r" % bad)
    # Unsorted input is accepted by the parser but must canonicalize sorted.
    assert canon(parse(b'{"b":1,"a":[true,false,"x y"]}')) == '{"a":[true,false,"x y"],"b":1}'
    # The fixed digest construction used in the Rust cross-check test.
    d = hashlib.sha256(b"private-custodian/v1/plan\x00{}").hexdigest()
    assert d == "e40cf9eb35e482e790cc78c51035e6ee07cc8667ed46acad19326af063951acc", d


def main():
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")
    negative_controls()
    recorded = {}
    with open(os.path.join(here, "digests.txt"), encoding="ascii") as f:
        for line in f:
            name, domain, dig = line.split()
            recorded[name] = (domain, dig)
    if not recorded:
        raise SystemExit("no vectors recorded")
    failures = 0
    for name, (domain, expected) in sorted(recorded.items()):
        path = os.path.join(here, name + ".canonical.json")
        with open(path, "rb") as f:
            raw = f.read()
        mine = canon(parse(raw)).encode("ascii")
        ok_bytes = mine == raw
        got = digest(domain, mine)
        ok_digest = got == expected
        print("%-22s canonical=%s digest=%s" % (name, "ok" if ok_bytes else "DIFFERS", "ok" if ok_digest else "DIFFERS"))
        if not (ok_bytes and ok_digest):
            failures += 1
    if failures:
        raise SystemExit("%d golden vector(s) differ" % failures)
    print("all %d golden vectors reproduced by the second implementation" % len(recorded))


if __name__ == "__main__":
    sys.exit(main())
