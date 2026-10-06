"""Offline tests for the P7 cost estimator (ADR 0147). Synthetic arithmetic only."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "poc"))
import cost_estimator as ce  # noqa: E402

TEMPLATE = ROOT / "docs" / "poc" / "ec2-cost-inputs.template.json"


def filled():
    comps = {}
    for cid in ce.REQUIRED:  # synthetic round numbers for arithmetic tests only
        comps[cid] = {"status": "MEASURED", "billed_unit": "unit", "basis": "per_run",
                      "quantity": 1, "unit_price_usd": 0.5, "source": "synthetic test"}
    return {"components": comps}


class Estimator(unittest.TestCase):
    def test_shipped_template_is_all_unmeasured_and_refused(self):
        t = json.loads(TEMPLATE.read_text())
        self.assertEqual(set(t["components"]), set(ce.REQUIRED))
        for c in t["components"].values():
            self.assertEqual(c["status"], "UNMEASURED")
            self.assertIsNone(c["quantity"])
        with self.assertRaises(ce.Refusal):
            ce.estimate(t)

    def test_one_unmeasured_input_refuses_total(self):
        d = filled()
        d["components"]["logs"]["status"] = "UNMEASURED"
        with self.assertRaises(ce.Refusal) as r:
            ce.estimate(d)
        self.assertTrue(any("logs" in p for p in r.exception.args[0]))

    def test_estimate_status_is_not_accepted_as_measured(self):
        d = filled()
        d["components"]["signing"]["status"] = "ESTIMATE"
        with self.assertRaises(ce.Refusal):
            ce.estimate(d)

    def test_missing_unknown_null_negative_bool_nan_refuse(self):
        d = filled(); del d["components"]["signing"]
        with self.assertRaises(ce.Refusal): ce.estimate(d)
        d = filled(); d["components"]["extra"] = copy.deepcopy(d["components"]["logs"])
        with self.assertRaises(ce.Refusal): ce.estimate(d)
        for bad in (None, -1, True, float("nan"), float("inf"), "1"):
            d = filled(); d["components"]["logs"]["quantity"] = bad
            with self.assertRaises(ce.Refusal): ce.estimate(d)

    def test_measured_requires_unit_source_and_basis(self):
        for k, v in (("billed_unit", ""), ("source", None), ("basis", "per_week")):
            d = filled(); d["components"]["logs"][k] = v
            with self.assertRaises(ce.Refusal): ce.estimate(d)

    def test_arithmetic_per_run_per_day_per_month(self):
        d = filled()
        n = len(ce.REQUIRED)
        out = ce.estimate(d)  # all per_run, 0.5 each
        self.assertAlmostEqual(out["runs_per_day"]["4"]["daily_usd"], 0.5 * n * 4)
        self.assertAlmostEqual(out["runs_per_day"]["8"]["daily_usd"], 0.5 * n * 8)
        d["components"]["logs"]["basis"] = "per_day"
        d["components"]["signing"]["basis"] = "per_month"
        d["components"]["signing"]["quantity"] = 30
        out = ce.estimate(d)  # 8 per_run*runs + 0.5 + 15/30
        self.assertAlmostEqual(out["runs_per_day"]["4"]["daily_usd"], 0.5 * 8 * 4 + 0.5 + 0.5)
        self.assertIn("exclusions", out)

    def test_cli_exit_codes_and_no_total_on_refusal(self):
        script = str(ROOT / "tools" / "poc" / "cost_estimator.py")
        r = subprocess.run([sys.executable, script, str(TEMPLATE)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("daily_usd", r.stdout)
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump(filled(), f); f.flush()
            r = subprocess.run([sys.executable, script, f.name], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("daily_usd", r.stdout)

    def test_no_lambda_free_tier_or_adr0141_figures_in_source(self):
        src = (ROOT / "tools" / "poc" / "cost_estimator.py").read_text().lower()
        self.assertNotIn("free_tier = ", src)
        self.assertNotIn("24.55", src)


if __name__ == "__main__":
    unittest.main()
