"""Public synthetic build-context fixtures only. No AWS call, no protected data."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGE_DIR = ROOT / "deploy/aws/microvm"
SPEC = importlib.util.spec_from_file_location("image_inventory", IMAGE_DIR / "image_inventory.py")
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


class RealBuildContext(unittest.TestCase):
    """The actual `deploy/aws/microvm` directory, as it ships today."""

    def test_real_build_context_matches_reviewed_allowlist_with_no_denylist_hits(self):
        result = INVENTORY.report(IMAGE_DIR)
        self.assertEqual(result["included_files"], sorted(INVENTORY.ALLOWED_FILES))
        self.assertTrue(result["matches_reviewed_allowlist"])
        self.assertEqual(result["denylist_hits"], {})
        self.assertFalse(result["snapshot_build_or_restore_verified"])

    def test_real_dockerignore_excludes_the_readme_and_itself(self):
        included = INVENTORY.build_context_files(IMAGE_DIR)
        self.assertNotIn("README.md", included)
        self.assertNotIn(".dockerignore", included)


class SyntheticBuildContext(unittest.TestCase):
    """Synthetic fixtures proving the check actually fails closed."""

    def _write_dir(self, files, dockerignore_lines):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        image_dir = Path(tmp.name)
        for name, contents in files.items():
            (image_dir / name).write_text(contents, encoding="utf-8")
        (image_dir / ".dockerignore").write_text("\n".join(dockerignore_lines) + "\n", encoding="utf-8")
        return image_dir

    def test_denylist_catches_corpus_seed_ledger_key_token_and_identifier_lookalikes(self):
        suspect_names = [
            "corpus.bin",
            "seed.json",
            "private-ledger.db",
            "signing.pem",
            "aws_credentials.key",
            "operator_token.txt",
            "receipt.sig",
            ".aws_config",
        ]
        image_dir = self._write_dir(
            {name: "synthetic-canary" for name in suspect_names},
            ["*"] + [f"!{name}" for name in suspect_names],
        )
        result = INVENTORY.report(image_dir)
        self.assertFalse(result["matches_reviewed_allowlist"])
        self.assertEqual(sorted(result["denylist_hits"].keys()), sorted(suspect_names))

    def test_unreviewed_extra_source_file_fails_the_allowlist_even_if_not_denylisted(self):
        # A plausible future addition (e.g. a new tool source) that nobody
        # reviewed into ALLOWED_FILES yet: not malicious, but still must not
        # pass silently just because it isn't on the denylist.
        image_dir = self._write_dir(
            {"Dockerfile": "x", "health.rs": "x", "notes.rs": "x"},
            ["*", "!Dockerfile", "!health.rs", "!notes.rs"],
        )
        result = INVENTORY.report(image_dir)
        self.assertEqual(result["denylist_hits"], {})
        self.assertFalse(result["matches_reviewed_allowlist"])
        self.assertIn("notes.rs", result["included_files"])

    def test_missing_dockerignore_fails_closed_instead_of_defaulting_to_include_everything(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        image_dir = Path(tmp.name)
        (image_dir / "corpus.bin").write_text("synthetic-canary", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            INVENTORY.build_context_files(image_dir)

    def test_dockerignore_pattern_outside_the_flat_allowlist_shape_refuses(self):
        for hostile_line in ["!*.rs", "!sub/", "!**/secret"]:
            image_dir = self._write_dir({"Dockerfile": "x"}, ["*", hostile_line])
            with self.assertRaises(ValueError):
                INVENTORY.build_context_files(image_dir)


if __name__ == "__main__":
    unittest.main()
