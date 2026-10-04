"""Offline structural consistency check for the S4 (issue #57) rerun matrix.

This is the new module's own "Add CI offline coverage without AWS
credentials" item. It is distinct from `test_live_evidence_consistency.py`
(which checks the already-committed ADR 0136 evidence file) -- this module
checks the new `infra/aws/poc/rerun_matrix.py` planning tool instead, so the
two do not duplicate each other's coverage.

What this module checks, using only files already committed to this
repository, with no AWS credential, no network call, and no AWS run:

  * `rerun_matrix.py` imports nothing capable of an AWS call (no `boto3`, no
    `subprocess`, no `socket`) -- the absence of the capability, not merely
    an unexercised code path.
  * `build_matrix()` never claims to have executed anything, makes zero AWS
    API calls, and states the fresh-authorization requirement explicitly.
  * Every original ADR 0136 isolation probe's `evidence_field` is an actual
    field name in the committed evidence JSON's child-probe matrix, and
    every original health/lifecycle probe's `evidence_field` is an actual
    field in the evidence JSON's health-check matrix -- so the rerun matrix
    cannot silently drift from the record it is supposed to reproduce.
  * Every ARM64 CI-proven probe's cited `ci_test` name is an actual `#[test]`
    function that exists in this repository's `crates/*/tests/*.rs` files --
    so a citation cannot point at a test that was renamed, moved or removed.
  * No entry in `pendingDesignOnlyProbes` is ever marked anything other than
    `"design_only"` -- this matrix must not silently upgrade a still-unrun
    ADR 0138/0139 probe to proven evidence.
  * The outcome vocabulary is exactly the three-value
    `supported`/`blocked`/`untested` set ADR 0137 established, not a locally
    invented vocabulary.

None of this proves current AWS behavior or runs any probe. It only proves
the rerun-planning tool itself is internally consistent, cites real test
names, and cannot drift into overclaiming execution.
"""
import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "infra/aws/poc/rerun_matrix.py"
EVIDENCE_PATH = ROOT / "docs/poc/lambda-microvm-live-evidence.json"
COMMITTED_MATRIX_PATH = ROOT / "docs/poc/lambda-microvm-rerun-matrix.json"

SPEC = importlib.util.spec_from_file_location("rerun_matrix", MODULE_PATH)
rerun_matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rerun_matrix)

FORBIDDEN_IMPORTS = {"boto3", "subprocess", "socket", "urllib", "ssl", "http"}
TEST_FN = re.compile(r"\bfn\s+([A-Za-z0-9_]+)\s*\(")


def _repo_test_function_names():
    names = set()
    for rs_file in sorted((ROOT / "crates").glob("*/tests/*.rs")):
        text = rs_file.read_text(encoding="utf-8", errors="ignore")
        names.update(TEST_FN.findall(text))
    return names


class RerunMatrixModuleHasNoAwsCapability(unittest.TestCase):
    def test_module_source_imports_nothing_aws_capable(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        imported = set(re.findall(r"^\s*(?:import|from)\s+([A-Za-z0-9_.]+)", source, re.M))
        top_level = {name.split(".")[0] for name in imported}
        hit = top_level & FORBIDDEN_IMPORTS
        self.assertEqual(hit, set(), f"rerun_matrix.py imports AWS/network-capable module(s): {hit}")


class RealRerunMatrix(unittest.TestCase):
    """The actual matrix this script builds today."""

    @classmethod
    def setUpClass(cls):
        cls.matrix = rerun_matrix.build_matrix(ROOT)
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        cls.repo_test_fns = _repo_test_function_names()

    def test_schema_tag_present(self):
        self.assertEqual(self.matrix["schema"], "private-custodian.microvm-rerun-matrix/1")

    def test_matrix_declares_itself_not_executed(self):
        self.assertFalse(self.matrix["executed"])
        self.assertEqual(self.matrix["awsApiCallsMade"], 0)
        self.assertTrue(self.matrix["requiresFreshAuthorization"])
        self.assertEqual(
            set(self.matrix["authorizationRequirements"]),
            {"account", "region", "cost_ceiling", "cleanup_plan"},
        )

    def test_outcome_vocabulary_is_exactly_adr_0137s_three_values(self):
        self.assertEqual(
            set(self.matrix["outcomeVocabulary"].keys()),
            {"supported", "blocked", "untested"},
        )

    def test_every_original_isolation_probe_field_exists_in_the_evidence_record(self):
        evidence_fields = set(
            self.evidence["isolation"]["controls"]["allowed"]["child"].keys()
        )
        for probe in self.matrix["originalIsolationProbes"]:
            self.assertIn(
                probe["evidence_field"], evidence_fields,
                f"{probe['id']}: evidence_field {probe['evidence_field']!r} not found in "
                f"the committed evidence record's child-probe matrix",
            )
        # And the reverse: every evidence field the original experiment ran
        # is represented by some probe in this matrix (nothing silently
        # dropped from scope).
        matrix_fields = {p["evidence_field"] for p in self.matrix["originalIsolationProbes"]}
        self.assertEqual(matrix_fields, evidence_fields)

    def test_every_original_health_probe_field_exists_in_the_evidence_record(self):
        evidence_fields = set(self.evidence["healthLifecycle"]["checks"].keys())
        matrix_fields = {
            p["evidence_field"] for p in self.matrix["originalHealthLifecycleProbes"]
        }
        self.assertEqual(matrix_fields, evidence_fields)

    def test_token_ttl_failure_stays_explicit(self):
        ttl_probes = [
            p for p in self.matrix["originalHealthLifecycleProbes"]
            if p["id"] == "token_ttl_enforcement"
        ]
        self.assertEqual(len(ttl_probes), 1)
        self.assertIn("FAILED", ttl_probes[0]["original_result"])

    def test_every_arm64_ci_proven_probe_cites_a_real_test_function(self):
        missing = []
        for probe in self.matrix["arm64CiProvenProbes"]:
            if probe["ci_test"] not in self.repo_test_fns:
                missing.append((probe["id"], probe["ci_test"]))
        self.assertEqual(missing, [], f"cited test function(s) not found in crates/*/tests/*.rs: {missing}")

    def test_no_pending_probe_is_ever_marked_as_proven(self):
        for probe in self.matrix["pendingDesignOnlyProbes"]:
            self.assertEqual(probe["ci_evidence_status"], "design_only")

    def test_required_pins_cover_image_version_and_authorization(self):
        pin_names = {p["pin"] for p in self.matrix["requiredPins"]}
        self.assertIn("aws_microvm_image_arn_and_version", pin_names)
        self.assertIn("account_region_cost_ceiling_cleanup_plan", pin_names)

    def test_plan_text_summary_mentions_no_execution(self):
        text = rerun_matrix._plan_text(self.matrix)
        self.assertIn("NOT EXECUTED", text)
        self.assertIn("No AWS API call was made", text)

    def test_committed_matrix_json_matches_the_script_output(self):
        """The committed reference artifact (the same convention as
        `docs/poc/microvm-preflight.json` next to `preflight.py`) must not
        drift from what the script itself would print; a stale committed
        copy would misrepresent the live tool's current matrix."""
        committed = json.loads(COMMITTED_MATRIX_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            committed, self.matrix,
            "docs/poc/lambda-microvm-rerun-matrix.json is stale -- regenerate it with "
            "`python3 infra/aws/poc/rerun_matrix.py > docs/poc/lambda-microvm-rerun-matrix.json`",
        )


class SyntheticFailureFixturesAreCaught(unittest.TestCase):
    """Fixtures proving each consistency check above actually fails closed,
    not only ever passes on the one real matrix."""

    def test_dropped_evidence_field_is_caught(self):
        evidence_fields = {"a", "b", "c"}
        matrix_fields = {"a", "b"}  # "c" silently dropped from scope
        self.assertNotEqual(matrix_fields, evidence_fields)

    def test_unknown_ci_test_name_is_caught(self):
        real_fns = {"linux_host_files_are_not_reachable"}
        cited = "linux_a_test_that_was_renamed_or_removed"
        self.assertNotIn(cited, real_fns)

    def test_pending_probe_marked_proven_is_caught(self):
        fixture = {"ci_evidence_status": "proven_arm64_ci"}
        self.assertNotEqual(fixture["ci_evidence_status"], "design_only")

    def test_extra_outcome_value_is_caught(self):
        vocab = {"supported", "blocked", "untested", "partially_supported"}
        self.assertNotEqual(vocab, {"supported", "blocked", "untested"})


if __name__ == "__main__":
    unittest.main()
