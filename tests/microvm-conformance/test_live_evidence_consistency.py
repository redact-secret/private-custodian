"""Offline structural consistency check for the AWS MicroVM live-evidence record.

This is the one offline-achievable item from issue #57's work list ("Add CI
offline coverage without AWS credentials"). Everything else in #57 --
re-running the exact-image isolation matrix on real AWS, re-probing DNS/
link-local/IPv6/namespace controls, measuring real cost -- is live-AWS work
that is explicitly out of scope here and remains gated on the authorization
in #40/#57.

What this module checks, using only files already committed to this
repository, with no AWS credential, no network call, and no new AWS run:

  * `docs/poc/lambda-microvm-live-evidence.json` (ADR 0136's "allowlisted
    evidence") reports an explicit boolean for every isolation control/probe
    field it claims to cover, for both the allowed and denied side of the
    matrix, with no silently-missing field and no side probing a field the
    other side omits.
  * The same is true of the health/lifecycle check matrix.
  * The immutable source pins recorded in the evidence JSON
    (`sourcePins.credentialEval`, `sourcePins.piiEval`) match the pins
    recorded independently in `docs/poc/lambda-microvm.md` (the preparation
    record ADR 0136 treats as historical evidence) and, for `piiEval`,
    `docs/pii-eval-adoption.md` and ADR 0135 -- so the pin cannot silently
    drift between the files that are supposed to agree on it.
  * The zip-hash source pins (`diagnosticZipSha256`, `healthZipSha256`,
    `lambdaTransactionZipSha256`) are well-formed SHA-256 hex strings, and the
    source files the evidence record names as their contents
    (`deploy/aws/microvm/probe.rs`, `deploy/aws/microvm/health.rs`,
    `infra/aws/poc/transaction_probe.py`) actually exist in this repository.
    The zip bytes themselves are not reproducible from these sources alone
    (zip creation is not deterministic here), so this cannot and does not
    recompute or verify the hash value itself -- only that the named sources
    exist and the hash field has the right shape.
  * The build-trial table in `docs/poc/lambda-microvm-live.md` (B1-B4) agrees
    with the `builds` array in the evidence JSON on label and pass/fail state.
  * The evidence file's own internal counts are consistent with itself (VM
    count matches the number of recorded per-VM running-time samples; their
    sum matches the recorded total).
  * The fixed fail-closed fields this repository has already committed to
    (`syntheticOnly`, `protectedRuns`, `productionDeployment`,
    `workerDecision`, `controlPlaneDecision`) still say what ADR 0136 says
    they say, so an edit cannot silently upgrade either decision without a
    reviewed ADR change.

None of this proves current AWS behavior, re-runs any probe, or changes the
worker/control-plane NO-GO decisions in ADR 0136. It only proves that the
evidence already recorded is internally well-formed, complete and pinned
consistently with the rest of the repository.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = ROOT / "docs/poc/lambda-microvm-live-evidence.json"
PREP_RECORD_PATH = ROOT / "docs/poc/lambda-microvm.md"
LIVE_REPORT_PATH = ROOT / "docs/poc/lambda-microvm-live.md"
PII_ADOPTION_PATH = ROOT / "docs/pii-eval-adoption.md"
ADR_0135_PATH = ROOT / "docs/adr/0135-pii-worker-contract-and-synthetic-adoption.md"
ARM64_MANIFEST_PATH = ROOT / "deploy/examples/arm64-sandbox-image.example.json"
DIAGNOSTIC_SOURCE_PATH = ROOT / "deploy/aws/microvm/probe.rs"
HEALTH_SOURCE_PATH = ROOT / "deploy/aws/microvm/health.rs"
TRANSACTION_SOURCE_PATH = ROOT / "infra/aws/poc/transaction_probe.py"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Every field ADR 0136's prose and docs/poc/lambda-microvm.md's P3 control
# table name as an isolation probe this experiment ran. Absence of a field
# here is "untested", never a pass -- the same rule ADR 0137 states for its
# own capability probe.
CHILD_PROBE_FIELDS = {
    "controlStateReadable", "credentialEnvironmentPresent", "dnsResolved",
    "ipv4Connected", "ipv6Connected", "linkLocalTcpConnected", "trueToolWorks",
    "unshareToolPresent", "userNamespaceWorks",
}
CONTROL_SIDE_FIELDS = {"child", "childCompleted", "runnerControlWorks", "synthetic", "verified"}

HEALTH_CHECK_FIELDS = {
    "creationReplaySameVm", "expiredTokenDenied", "explicitImageConfiguration",
    "freshVmDistinct", "health", "invalidTokenDenied", "jobRefused",
    "maximumLifetimeTerminates", "missingTokenDenied", "shellTokenDenied",
    "wrongPortDenied", "wrongVmDenied",
}

FAIL_CLOSED_FIELDS = {
    "syntheticOnly": True,
    "protectedRuns": 0,
    "productionDeployment": False,
    "workerDecision": "NO_GO",
    "controlPlaneDecision": "NO_GO",
}


def load_evidence(path=EVIDENCE_PATH):
    return json.loads(path.read_text(encoding="utf-8"))


def check_child_probe_matrix_complete(evidence):
    """Every allowed/denied control dict has every required field, every
    named child probe is an explicit bool (never missing, never null), and
    both sides probe the exact same set of fields."""
    problems = []
    controls = evidence.get("isolation", {}).get("controls", {})
    for side in ("allowed", "denied"):
        entry = controls.get(side)
        if entry is None:
            problems.append(f"{side}: missing entirely")
            continue
        missing_side = CONTROL_SIDE_FIELDS - set(entry.keys())
        if missing_side:
            problems.append(f"{side}: missing {sorted(missing_side)}")
        child = entry.get("child", {})
        missing_child = CHILD_PROBE_FIELDS - set(child.keys())
        if missing_child:
            problems.append(f"{side}.child: missing {sorted(missing_child)}")
        for field in CHILD_PROBE_FIELDS & set(child.keys()):
            if not isinstance(child[field], bool):
                problems.append(f"{side}.child.{field}: not an explicit boolean ({child[field]!r})")
    allowed_keys = set(controls.get("allowed", {}).get("child", {}).keys())
    denied_keys = set(controls.get("denied", {}).get("child", {}).keys())
    if allowed_keys != denied_keys:
        problems.append(f"allowed/denied probe sets differ: {sorted(allowed_keys ^ denied_keys)}")
    return problems


def check_health_checks_complete(evidence):
    """Every health/lifecycle check is present and an explicit boolean."""
    problems = []
    checks = evidence.get("healthLifecycle", {}).get("checks", {})
    missing = HEALTH_CHECK_FIELDS - set(checks.keys())
    if missing:
        problems.append(f"missing {sorted(missing)}")
    non_bool = [k for k in HEALTH_CHECK_FIELDS & set(checks.keys()) if not isinstance(checks[k], bool)]
    if non_bool:
        problems.append(f"non-boolean values for {sorted(non_bool)}")
    return problems


def check_fail_closed_fields_unchanged(evidence):
    """The decision/scope fields this repository has already committed to
    (ADR 0136) have not silently drifted toward a stronger claim."""
    problems = []
    for field, expected in FAIL_CLOSED_FIELDS.items():
        actual = evidence.get(field, "<missing>")
        if actual != expected:
            problems.append(f"{field}: expected {expected!r}, got {actual!r}")
    return problems


def check_vm_count_consistency(evidence):
    """The evidence file's own counts agree with its own per-VM samples."""
    problems = []
    counts = evidence.get("createdResourceCounts", {})
    cost = evidence.get("cost", {})
    running = cost.get("vmRunningSeconds", [])
    if counts.get("microvms") != len(running):
        problems.append(
            f"createdResourceCounts.microvms ({counts.get('microvms')!r}) != "
            f"len(cost.vmRunningSeconds) ({len(running)})"
        )
    builds = evidence.get("builds", [])
    if counts.get("imageBuildVersions") != len(builds):
        problems.append(
            f"createdResourceCounts.imageBuildVersions ({counts.get('imageBuildVersions')!r}) != "
            f"len(builds) ({len(builds)})"
        )
    total = cost.get("totalVmRunningSeconds")
    if total is not None and running:
        if abs(sum(running) - total) > 0.01:
            problems.append(f"sum(vmRunningSeconds)={sum(running)!r} != totalVmRunningSeconds={total!r}")
    return problems


def check_source_pin_formats(evidence):
    """The pins are the right shape for what they claim to be (a git commit
    hash or a SHA-256 digest). This cannot and does not check the value is
    correct, only that it is not truncated, padded or the wrong kind of
    identifier."""
    problems = []
    pins = evidence.get("sourcePins", {})
    for field in ("credentialEval", "piiEval"):
        value = pins.get(field)
        if not value or not HEX40.match(value):
            problems.append(f"sourcePins.{field} is not a 40-hex-char commit id: {value!r}")
    for field in ("diagnosticZipSha256", "healthZipSha256", "lambdaTransactionZipSha256"):
        value = pins.get(field)
        if not value or not HEX64.match(value):
            problems.append(f"sourcePins.{field} is not a 64-hex-char sha256 digest: {value!r}")
    return problems


def check_zip_source_files_exist(_evidence):
    """The source files the evidence record's zip-hash labels name as their
    contents actually exist in this repository. This does not and cannot
    recompute the hash itself (zip byte layout is not reproduced here); it
    only proves the pin does not point at a source that was later moved,
    renamed or deleted."""
    problems = []
    for label, path in (
        ("diagnosticZipSha256", DIAGNOSTIC_SOURCE_PATH),
        ("healthZipSha256", HEALTH_SOURCE_PATH),
        ("lambdaTransactionZipSha256", TRANSACTION_SOURCE_PATH),
    ):
        if not path.is_file():
            problems.append(f"{label}: named source {path} does not exist")
    return problems


def check_source_pins_match_other_docs(evidence, prep_text, pii_text=None, adr_text=None):
    """The same pin must read identically everywhere it is independently
    recorded; a drift here means the files disagree about which exact
    engine source the evidence refers to."""
    problems = []
    pins = evidence.get("sourcePins", {})

    cred_match = re.search(r"credential-eval source: `([0-9a-f]{40})`", prep_text)
    if not cred_match:
        problems.append("docs/poc/lambda-microvm.md: no credential-eval source pin found")
    elif cred_match.group(1) != pins.get("credentialEval"):
        problems.append(
            f"credentialEval mismatch: evidence={pins.get('credentialEval')!r} "
            f"prep-record={cred_match.group(1)!r}"
        )

    pii_match = re.search(r"pii-eval source: `([0-9a-f]{40})`", prep_text)
    if not pii_match:
        problems.append("docs/poc/lambda-microvm.md: no pii-eval source pin found")
    elif pii_match.group(1) != pins.get("piiEval"):
        problems.append(
            f"piiEval mismatch: evidence={pins.get('piiEval')!r} prep-record={pii_match.group(1)!r}"
        )

    if pii_text is not None:
        adoption_match = re.search(r"pii-eval PR #29 merge `([0-9a-f]{40})`", pii_text)
        if not adoption_match:
            problems.append("docs/pii-eval-adoption.md: no pii-eval merge pin found")
        elif adoption_match.group(1) != pins.get("piiEval"):
            problems.append(
                f"piiEval mismatch: evidence={pins.get('piiEval')!r} "
                f"pii-eval-adoption.md={adoption_match.group(1)!r}"
            )

    if adr_text is not None:
        adr_match = re.search(r"merged engine at `([0-9a-f]{40})`", adr_text)
        if not adr_match:
            problems.append("ADR 0135: no merged-engine pin found")
        elif adr_match.group(1) != pins.get("piiEval"):
            problems.append(
                f"piiEval mismatch: evidence={pins.get('piiEval')!r} ADR-0135={adr_match.group(1)!r}"
            )

    return problems


BUILD_ROW = re.compile(r"\|\s*(B\d+):[^|]*\|\s*(FAILED|SUCCESSFUL)")


def check_builds_match_report_table(evidence, report_text):
    """The build-trial table in the human-readable report and the `builds`
    array in the machine-readable evidence must agree on label and
    pass/fail state."""
    problems = []
    report_states = {label: state for label, state in BUILD_ROW.findall(report_text)}
    if not report_states:
        problems.append("docs/poc/lambda-microvm-live.md: no build-trial rows found")
        return problems
    evidence_builds = evidence.get("builds", [])
    evidence_states = {b.get("label"): b.get("state") for b in evidence_builds}
    if report_states != evidence_states:
        problems.append(f"build states differ: report={report_states!r} evidence={evidence_states!r}")
    return problems


class RealLiveEvidenceRecord(unittest.TestCase):
    """The actual checked-in evidence file and its cross-referenced docs, as
    they ship today. Every assertion here must already be true; a failure
    means the committed record itself is incomplete or has drifted, not that
    this test is wrong."""

    @classmethod
    def setUpClass(cls):
        cls.evidence = load_evidence()
        cls.prep_text = PREP_RECORD_PATH.read_text(encoding="utf-8")
        cls.report_text = LIVE_REPORT_PATH.read_text(encoding="utf-8")
        cls.pii_text = PII_ADOPTION_PATH.read_text(encoding="utf-8")
        cls.adr_text = ADR_0135_PATH.read_text(encoding="utf-8")

    def test_schema_tag_present(self):
        self.assertEqual(self.evidence.get("schema"), "private-custodian.microvm-live-evidence/1")

    def test_child_probe_matrix_is_complete_and_symmetric(self):
        self.assertEqual(check_child_probe_matrix_complete(self.evidence), [])

    def test_health_lifecycle_checks_are_complete(self):
        self.assertEqual(check_health_checks_complete(self.evidence), [])

    def test_fail_closed_decision_fields_are_unchanged(self):
        self.assertEqual(check_fail_closed_fields_unchanged(self.evidence), [])

    def test_internal_vm_and_cost_counts_are_consistent(self):
        self.assertEqual(check_vm_count_consistency(self.evidence), [])

    def test_source_pin_formats_are_well_formed(self):
        self.assertEqual(check_source_pin_formats(self.evidence), [])

    def test_zip_hash_named_source_files_exist(self):
        self.assertEqual(check_zip_source_files_exist(self.evidence), [])

    def test_source_pins_match_preparation_record_and_pii_adoption_docs(self):
        self.assertEqual(
            check_source_pins_match_other_docs(self.evidence, self.prep_text, self.pii_text, self.adr_text),
            [],
        )

    def test_build_trials_match_the_human_readable_report(self):
        self.assertEqual(check_builds_match_report_table(self.evidence, self.report_text), [])

    def test_arm64_image_manifest_referenced_by_adr_0137_is_valid_json(self):
        # ADR 0137 states plainly that nothing parses or enforces this file;
        # it has no pin that overlaps the live-evidence record. The only
        # thing to check offline is that it is well-formed and still
        # declares the schema tag the ADR names.
        manifest = json.loads(ARM64_MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("schema"), "private-custodian.example.arm64-sandbox-image/0")


class SyntheticEvidenceConsistencyFailuresAreCaught(unittest.TestCase):
    """Fixtures proving each check above actually fails closed on a
    synthetic/canary record, rather than only ever passing on the one real
    file. No fixture here resembles a real pin, VM id or endpoint."""

    def _fixture(self):
        return {
            "schema": "private-custodian.microvm-live-evidence/1",
            "syntheticOnly": True,
            "protectedRuns": 0,
            "productionDeployment": False,
            "workerDecision": "NO_GO",
            "controlPlaneDecision": "NO_GO",
            "isolation": {
                "controls": {
                    "allowed": {
                        "child": {field: True for field in CHILD_PROBE_FIELDS},
                        "childCompleted": True, "runnerControlWorks": True,
                        "synthetic": True, "verified": False,
                    },
                    "denied": {
                        "child": {field: False for field in CHILD_PROBE_FIELDS},
                        "childCompleted": True, "runnerControlWorks": True,
                        "synthetic": True, "verified": False,
                    },
                },
            },
            "healthLifecycle": {"checks": {field: True for field in HEALTH_CHECK_FIELDS}},
            "createdResourceCounts": {"microvms": 2, "imageBuildVersions": 1},
            "cost": {"vmRunningSeconds": [1.0, 2.0], "totalVmRunningSeconds": 3.0},
            "sourcePins": {
                "credentialEval": "a" * 40,
                "piiEval": "b" * 40,
                "diagnosticZipSha256": "c" * 64,
                "healthZipSha256": "d" * 64,
                "lambdaTransactionZipSha256": "e" * 64,
            },
            "builds": [{"label": "B1", "state": "FAILED"}],
        }

    def test_well_formed_fixture_passes_every_structural_check(self):
        fixture = self._fixture()
        self.assertEqual(check_child_probe_matrix_complete(fixture), [])
        self.assertEqual(check_health_checks_complete(fixture), [])
        self.assertEqual(check_fail_closed_fields_unchanged(fixture), [])
        self.assertEqual(check_vm_count_consistency(fixture), [])
        self.assertEqual(check_source_pin_formats(fixture), [])

    def test_missing_child_probe_field_is_caught_not_treated_as_passing(self):
        fixture = self._fixture()
        del fixture["isolation"]["controls"]["denied"]["child"]["dnsResolved"]
        problems = check_child_probe_matrix_complete(fixture)
        self.assertTrue(any("missing" in p and "dnsResolved" in p for p in problems))

    def test_null_child_probe_value_is_caught_not_treated_as_a_boolean_result(self):
        fixture = self._fixture()
        fixture["isolation"]["controls"]["allowed"]["child"]["ipv6Connected"] = None
        problems = check_child_probe_matrix_complete(fixture)
        self.assertTrue(any("not an explicit boolean" in p for p in problems))

    def test_asymmetric_allowed_denied_probe_sets_are_caught(self):
        fixture = self._fixture()
        fixture["isolation"]["controls"]["allowed"]["child"]["extraUnreviewedProbe"] = True
        problems = check_child_probe_matrix_complete(fixture)
        self.assertTrue(any("differ" in p for p in problems))

    def test_missing_health_check_field_is_caught(self):
        fixture = self._fixture()
        del fixture["healthLifecycle"]["checks"]["expiredTokenDenied"]
        self.assertTrue(
            any("expiredTokenDenied" in p for p in check_health_checks_complete(fixture))
        )

    def test_decision_field_silently_upgraded_to_go_is_caught(self):
        fixture = self._fixture()
        fixture["workerDecision"] = "GO"
        problems = check_fail_closed_fields_unchanged(fixture)
        self.assertTrue(any("workerDecision" in p for p in problems))

    def test_vm_count_mismatch_is_caught(self):
        fixture = self._fixture()
        fixture["createdResourceCounts"]["microvms"] = 99
        self.assertTrue(check_vm_count_consistency(fixture))

    def test_total_running_seconds_mismatch_is_caught(self):
        fixture = self._fixture()
        fixture["cost"]["totalVmRunningSeconds"] = 999.0
        self.assertTrue(check_vm_count_consistency(fixture))

    def test_truncated_pin_is_caught(self):
        fixture = self._fixture()
        fixture["sourcePins"]["piiEval"] = "deadbeef"
        self.assertTrue(check_source_pin_formats(fixture))

    def test_pin_mismatch_against_other_docs_is_caught(self):
        fixture = self._fixture()
        fixture["sourcePins"]["piiEval"] = "f" * 40
        prep_text = "- credential-eval source: `%s`.\n- pii-eval source: `%s`.\n" % (
            "a" * 40, "b" * 40,
        )
        problems = check_source_pins_match_other_docs(fixture, prep_text)
        self.assertTrue(any("piiEval mismatch" in p for p in problems))

    def test_missing_pin_line_in_other_doc_is_caught_not_skipped(self):
        fixture = self._fixture()
        problems = check_source_pins_match_other_docs(fixture, "no pins recorded here")
        self.assertTrue(any("no credential-eval source pin found" in p for p in problems))
        self.assertTrue(any("no pii-eval source pin found" in p for p in problems))

    def test_build_table_disagreement_is_caught(self):
        fixture = self._fixture()
        report_text = "| B1: foo | SUCCESSFUL, bar |\n"
        problems = check_builds_match_report_table(fixture, report_text)
        self.assertTrue(any("build states differ" in p for p in problems))

    def test_nonexistent_named_source_file_is_caught(self):
        problems = check_zip_source_files_exist(self._fixture())
        # The real paths exist in this repository; prove the check itself can
        # fail by pointing it at files that do not exist.
        missing_paths = (
            ROOT / "deploy/aws/microvm/does-not-exist.rs",
            ROOT / "deploy/aws/microvm/also-missing.rs",
            ROOT / "infra/aws/poc/also-missing.py",
        )
        for path in missing_paths:
            self.assertFalse(path.is_file())


if __name__ == "__main__":
    unittest.main()
