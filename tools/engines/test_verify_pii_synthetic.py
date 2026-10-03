"""Hostile artifact delivery controls, public synthetic bytes only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('verify_pii', Path(__file__).with_name('verify-pii-synthetic.py'))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.old_node = verify.NODE
        verify.NODE = hashlib.sha256(b'synthetic-node').hexdigest()
        self.addCleanup(setattr, verify, 'NODE', self.old_node)
        self.put(self.root/'adopted-pii-eval', b'synthetic-adopted-cli')
        self.put(self.root/'unadopted-pii-eval', b'synthetic-upstream-cli')
        self.adopted = verify.digest(self.root/'adopted-pii-eval')[7:]
        self.upstream = verify.digest(self.root/'unadopted-pii-eval')[7:]
        self.doc(self.root/'provenance.json', {
            'schema':'custodian-pii-synthetic-build/1', 'upstream_commit':verify.UPSTREAM,
            'node_binary':'sha256:'+verify.NODE, 'adoption_patch':verify.digest(Path(verify.__file__).with_name('pii-adoption.patch')),
            'synthetic_only':True, 'deployed':False, 'adopted_binary':'sha256:'+self.adopted,
            'upstream_binary':'sha256:'+self.upstream})
        for scenario in verify.SCENARIOS:
            base = self.root/scenario
            for directory in ('stage','input','job'):
                (base/directory).mkdir(parents=True)
            stage = {'engine':b'synthetic-adopted-cli', 'adapter':b'shim-bundle', 'candidate':b'package-bundle',
                     'config':b'config', 'scanner-0':b'synthetic-node'}
            for name, data in stage.items():
                self.put(base/'stage'/name, data)
            entries = [f'entry{i:04}' for i in range(75)]
            for name in entries:
                self.put(base/'input'/name, b'synthetic-entry')
            self.doc(base/'pins.json', {'schema':'pii-eval-worker-e2e-pins/1', 'roster':75,
                     'pins':{n:verify.digest(base/'stage'/n) for n in stage}})
            self.doc(base/'job/job.json', {'schema':'private-custodian.worker-job/1', 'domain':'pii',
                     'protocol':{'name':'pii-v1','version':'2'}, 'roster':75, 'entries':entries})

    @staticmethod
    def put(path, data):
        path.write_bytes(data)

    @staticmethod
    def doc(path, value):
        path.write_text(json.dumps(value))

    def check(self):
        verify.verify(self.root, self.adopted, self.upstream)

    def test_delivery_restores_modes_only_after_pins_verify(self):
        self.check()
        self.assertEqual((self.root/'adopted-pii-eval').stat().st_mode & 0o777, 0o500)

    def test_tampered_binary_and_foreign_source_are_refused(self):
        self.put(self.root/'adopted-pii-eval', b'tampered')
        with self.assertRaises(ValueError):
            self.check()
        self.put(self.root/'adopted-pii-eval', b'synthetic-adopted-cli')
        prov = json.loads((self.root/'provenance.json').read_text())
        prov['upstream_commit'] = '0'*40
        self.doc(self.root/'provenance.json', prov)
        with self.assertRaises(ValueError):
            self.check()

    def test_symlink_entry_and_duplicate_json_are_refused(self):
        entry = self.root/'normal/input/entry0000'
        entry.unlink()
        entry.symlink_to(self.root/'adopted-pii-eval')
        with self.assertRaises(ValueError):
            self.check()
        entry.unlink()
        entry.write_bytes(b'synthetic-entry')
        pins = self.root/'normal/pins.json'
        pins.write_text('{"roster":75,"roster":74}')
        with self.assertRaises(ValueError):
            self.check()

    def test_unpinned_arguments_do_not_trigger_any_execution(self):
        for pin in ('', 'latest', '../path', 'a'*63, 'a'*65):
            with self.assertRaises(ValueError):
                verify.verify(self.root, pin, self.upstream)


if __name__ == '__main__':
    unittest.main()
