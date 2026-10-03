"""Public synthetic API/error fixtures only."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("preflight", ROOT / "infra/aws/poc/preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class Preflight(unittest.TestCase):
    def test_positive_support_is_not_runtime_or_deployment_approval(self):
        def call(service, operation, *args):
            if service == "sts":
                return {"Account": "SYNTHETIC-ACCOUNT-CANARY", "Arn": "SYNTHETIC-ARN-CANARY"}
            return {"items": [{"id": "SYNTHETIC-RESOURCE-CANARY"}]}
        result = preflight.report(call)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["managed_image_api"])
        self.assertFalse(result["runtime_verified"])
        self.assertEqual(result["worker_decision"], "NO-GO")
        self.assertNotIn("CANARY", json.dumps(result))

    def test_api_errors_and_missing_service_fail_closed(self):
        result = preflight.report(lambda *args: None)
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["inventory_api"])
        self.assertEqual(result["resources_created_by_preflight"], 0)

    def test_empty_image_inventory_does_not_prove_support(self):
        result = preflight.report(lambda *args: {"items": []})
        self.assertFalse(result["managed_image_api"])
        self.assertFalse(result["managed_version_api"])
        self.assertTrue(result["inventory_api"])


if __name__ == "__main__":
    unittest.main()
