import importlib.util
import concurrent.futures
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "live_health", Path(__file__).parents[2] / "infra/aws/poc/live_health.py")
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)
CANARY = "SYNTHETIC-PRIVATE-ENDPOINT-TOKEN"


class Fake:
    def __init__(self):
        self.now = 0
        self.calls = []
        self.tokens = {}
        self.failure = None
        self.conflict = False
        self.defaults = False

    def call(self, config, operation, params):
        self.calls.append((operation, params))
        if operation == "get-microvm-image-version":
            return {"state": "SUCCESSFUL", "status": "ACTIVE", "imageArn": config["imageArn"],
                    "imageVersion": config["imageVersion"], "logging": {"disabled": {}},
                    "cpuConfigurations": [{"architecture": "ARM_64"}],
                    "resources": [{"minimumMemoryInMiB": 2048 if self.defaults else 512}],
                    "hooks": {"microvmImageHooks": {"ready": "ENABLED", "validate": "ENABLED"}}}
        if self.failure == "unknown" and operation == "run-microvm":
            raise TimeoutError(CANARY)
        if self.failure == "unknown-replay" and operation == "run-microvm" and len(self.calls) == 3:
            raise TimeoutError(CANARY)
        if operation == "run-microvm":
            token = params["clientToken"]
            self.tokens.setdefault(token, len(self.tokens) + 1)
            number = self.tokens[token]
            if self.conflict and len(self.calls) == 3:
                number = 9
            return {"microvmId": f"synthetic-{number}",
                    "endpoint": f"synthetic-{number}.lambda-microvm.us-east-1.on.aws"}
        if operation == "create-microvm-auth-token":
            return {"authToken": {"X-aws-proxy-auth": CANARY}}
        if operation == "create-microvm-shell-auth-token":
            raise LIVE.Refused("ValidationException")
        if operation == "terminate-microvm" and self.failure == "cleanup":
            raise LIVE.Refused(CANARY)
        if operation == "get-microvm":
            return {"state": "TERMINATED"}
        return {}

    def request(self, endpoint, path, token=None, port=8080, method="GET"):
        if self.failure == "http":
            raise LIVE.Refused(CANARY)
        if (token != CANARY or port != 8080 or "synthetic-2" in endpoint
                or self.now >= 65):
            return 403, b"untrusted proxy response " + CANARY.encode()
        if path == "/job":
            return 403, b""
        return 200, b'{"synthetic":true,"verified":false}'

    def sleep(self, duration):
        self.now += duration


class LiveHealth(unittest.TestCase):
    def run_case(self, fake):
        config = {"syntheticOnly": True, "maxUsd": 50, "profile": "synthetic",
                  "region": "us-east-1", "imageArn": CANARY,
                  "imageVersion": "synthetic-1", "egressConnectorArn": CANARY}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            report = LIVE.experiment(config, path, fake.call, fake.request,
                                     lambda: fake.now, fake.sleep)
            inventory = LIVE.private_read(path)
            self.assertEqual(inventory["report"], report)
            self.assertNotIn(CANARY, json.dumps(report))
            return report

    def test_positive_and_denial_controls_replay_and_cleanup(self):
        fake = Fake()
        result = self.run_case(fake)
        self.assertTrue(all(result["checks"].values()))
        self.assertTrue(result["vmCleanupVerified"])
        runs = [p for op, p in fake.calls if op == "run-microvm"]
        self.assertEqual(len(runs), 4)
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[2], runs[3])
        for params in runs:
            self.assertNotIn("executionRoleArn", params)
            self.assertEqual(params["logging"], {"disabled": {}})
            self.assertFalse(params["idlePolicy"]["autoResumeEnabled"])
            self.assertLessEqual(params["maximumDurationInSeconds"], 180)

    def test_unknown_creation_is_reported_without_launching_during_cleanup(self):
        fake = Fake()
        fake.failure = "unknown"
        result = self.run_case(fake)
        self.assertTrue(result["creationReconciliationIncomplete"])
        self.assertFalse(result["vmCleanupVerified"])
        self.assertEqual(sum(op == "run-microvm" for op, _ in fake.calls), 1)

    def test_conflicting_replay_preserves_and_terminates_both_ids(self):
        fake = Fake()
        fake.conflict = True
        result = self.run_case(fake)
        self.assertEqual(result["refusal"], "CREATION_REPLAY_CONFLICT")
        self.assertEqual(result["vmCount"], 2)
        terminated = [p["microvmIdentifier"] for op, p in fake.calls
                      if op == "terminate-microvm"]
        self.assertEqual(set(terminated), {"synthetic-1", "synthetic-9"})

    def test_uncertain_replay_never_claims_all_orphans_are_cleaned(self):
        fake = Fake()
        fake.failure = "unknown-replay"
        result = self.run_case(fake)
        self.assertTrue(result["creationReconciliationIncomplete"])
        self.assertFalse(result["vmCleanupVerified"])
        self.assertEqual(result["vmCount"], 1)

    def test_hostile_http_refusal_is_fixed_and_cleanup_still_runs(self):
        fake = Fake()
        fake.failure = "http"
        result = self.run_case(fake)
        self.assertEqual(result["refusal"], "EXPERIMENT_FAILED")
        self.assertTrue(result["vmCleanupVerified"])

    def test_cleanup_failure_is_not_counted_as_deleted(self):
        fake = Fake()
        fake.failure = "cleanup"
        self.assertFalse(self.run_case(fake)["vmCleanupVerified"])

    def test_replaced_service_defaults_refuse_before_vm_creation(self):
        fake = Fake()
        fake.defaults = True
        result = self.run_case(fake)
        self.assertEqual(result["refusal"], "IMAGE_CONFIGURATION_REFUSED")
        self.assertFalse(any(op == "run-microvm" for op, _ in fake.calls))

    def test_existing_inventory_and_missing_authorization_refuse_before_aws(self):
        fake = Fake()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            config = {"syntheticOnly": True, "maxUsd": 50,
                      "egressConnectorArn": CANARY, "imageVersion": "synthetic"}
            path.write_text("{}")
            with self.assertRaises(LIVE.Refused):
                LIVE.experiment(config, path, fake.call)
            path.unlink()
            config["maxUsd"] = 0
            with self.assertRaises(LIVE.Refused):
                LIVE.experiment(config, path, fake.call)
        self.assertEqual(fake.calls, [])

    def test_endpoint_redirect_credentials_and_private_file_modes_refuse(self):
        for endpoint in ["http://example.com", "https://example.com",
                         "https://user:secret@synthetic.lambda-microvm.us-east-1.on.aws",
                         "https://synthetic.lambda-microvm.us-east-1.on.aws?token=secret"]:
            with self.assertRaises(LIVE.Refused):
                LIVE.http(endpoint, "/health", CANARY)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("{}")
            path.chmod(0o644)
            with self.assertRaises(LIVE.Refused):
                LIVE.private_read(path)

    def test_concurrent_invocations_have_exactly_one_inventory_writer(self):
        fake = Fake()
        config = {"syntheticOnly": True, "maxUsd": 50, "profile": "synthetic",
                  "region": "us-east-1", "imageArn": CANARY,
                  "imageVersion": "synthetic-1", "egressConnectorArn": CANARY}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            def run():
                try:
                    LIVE.experiment(config, path, fake.call, fake.request,
                                    lambda: fake.now, fake.sleep)
                    return "completed"
                except LIVE.Refused:
                    return "refused"
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: run(), range(2)))
            self.assertEqual(sorted(outcomes), ["completed", "refused"])
            self.assertEqual(sum(op == "run-microvm" for op, _ in fake.calls), 4)


if __name__ == "__main__":
    unittest.main()
