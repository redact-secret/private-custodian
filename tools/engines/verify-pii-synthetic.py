#!/usr/bin/env python3
"""Verify untrusted synthetic artifact delivery. Never print input content or paths."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

UPSTREAM = '6157cbc5918b3888c8e84b1884719ea8f3278b36'
NODE = 'fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48'
SCENARIOS = ('normal', 'population-mismatch', 'run-class-mismatch',
             'wrong-bundle-digest', 'wrong-tree-digest', 'wrong-runtime-digest', 'scanner-crash')


def regular(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError()
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError()
    return data


def digest(path):
    return 'sha256:' + hashlib.sha256(regular(path, 256 << 20)).hexdigest()


def closed_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError()
        out[key] = value
    return out


def document(path):
    return json.loads(regular(path, 1 << 20), object_pairs_hook=closed_pairs)


def verify(root, adopted, upstream):
    for pin in (adopted, upstream):
        if not re.fullmatch('[0-9a-f]{64}', pin):
            raise ValueError()
    if root.is_symlink() or not root.is_dir():
        raise ValueError()
    prov = document(root / 'provenance.json')
    patch = Path(__file__).with_name('pii-adoption.patch')
    if (prov['schema'] != 'custodian-pii-synthetic-build/1'
            or prov['upstream_commit'] != UPSTREAM or prov['node_binary'] != 'sha256:' + NODE
            or prov['adoption_patch'] != digest(patch)
            or prov['synthetic_only'] is not True or prov['deployed'] is not False):
        raise ValueError()
    for name, pin, field in (('adopted-pii-eval', adopted, 'adopted_binary'),
                             ('unadopted-pii-eval', upstream, 'upstream_binary')):
        path = root / name
        if digest(path) != 'sha256:' + pin or prov[field] != 'sha256:' + pin:
            raise ValueError()
        if b'pii-eval-worker-test-adapters' in regular(path, 256 << 20):
            raise ValueError()
        path.chmod(0o500)
    for scenario in SCENARIOS:
        base = root / scenario
        for directory in (base, base/'stage', base/'input', base/'job'):
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError()
        pins = document(base / 'pins.json')
        if pins['schema'] != 'pii-eval-worker-e2e-pins/1' or pins['roster'] != 75:
            raise ValueError()
        names = {'engine', 'adapter', 'candidate', 'config', 'scanner-0'}
        if set(pins['pins']) != names or {p.name for p in (base/'stage').iterdir()} != names:
            raise ValueError()
        for name in names:
            path = base/'stage'/name
            if digest(path) != pins['pins'][name]:
                raise ValueError()
            path.chmod(0o500 if name in ('engine', 'scanner-0') else 0o400)
        if pins['pins']['engine'] != 'sha256:' + adopted:
            raise ValueError()
        if scenario != 'scanner-crash' and pins['pins']['scanner-0'] != 'sha256:' + NODE:
            raise ValueError()
        job = document(base/'job/job.json')
        entries = job['entries']
        if (job['schema'] != 'private-custodian.worker-job/1' or job['domain'] != 'pii'
                or job['protocol'] != {'name': 'pii-v1', 'version': '2'}
                or job['roster'] != 75 or len(entries) != 75 or len(set(entries)) != 75):
            raise ValueError()
        if {p.name for p in (base/'input').iterdir()} != set(entries):
            raise ValueError()
        for name in entries:
            if not isinstance(name, str) or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}', name) or '..' in name:
                raise ValueError()
            entry = base/'input'/name
            regular(entry, 16 << 20)
            entry.chmod(0o400)


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError()
        verify(Path(sys.argv[1]), os.environ.get('ADOPTED_SHA256', ''),
               os.environ.get('UPSTREAM_SHA256', ''))
    except (OSError, ValueError, KeyError, TypeError):
        print('{"code":"synthetic_artifact_refused"}')
        return 2
    print('{"code":"synthetic_artifact_pins_verified","source_attestation":"not_verified"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
