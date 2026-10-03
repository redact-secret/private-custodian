import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "transaction_probe", Path(__file__).parents[2] / "infra/aws/poc/transaction_probe.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class Client:
    def __init__(self):
        self.item = None
        self.calls = []
        self.lose_response = False
        self.reject = False

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        return {"Item": self.item} if self.item else {}

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)
        if self.reject:
            raise RuntimeError("SYNTHETIC-CANARY")
        self.item = kwargs["TransactItems"][1]["Put"]["Item"]
        if self.lose_response:
            raise RuntimeError("SYNTHETIC-CANARY")


class TransactionProbe(unittest.TestCase):
    def test_durable_replay_does_not_transact_again_and_conflict_refuses(self):
        client = Client()
        event = {"id": "synthetic-1", "binding": "valid"}
        self.assertEqual(PROBE.probe(client, "synthetic", event), {"code": "CHARGED"})
        self.assertEqual(PROBE.probe(client, "synthetic", event), {"code": "REPLAY"})
        self.assertEqual(PROBE.probe(client, "synthetic", dict(event, binding="conflicting")),
                         {"code": "BINDING_CONFLICT"})
        self.assertEqual(sum("TransactItems" in call for call in client.calls), 1)

    def test_lost_commit_response_resolves_from_exact_durable_intent(self):
        client = Client()
        client.lose_response = True
        self.assertEqual(PROBE.probe(client, "synthetic", {"id": "synthetic-1", "binding": "valid"}),
                         {"code": "REPLAY"})

    def test_failed_transaction_and_hostile_inputs_never_echo(self):
        client = Client()
        client.reject = True
        self.assertEqual(PROBE.probe(client, "synthetic", {"id": "synthetic-1", "binding": "valid"}),
                         {"code": "NOT_COMMITTED"})
        for event in [None, {}, {"id": "SYNTHETIC-CANARY", "binding": "valid"},
                      {"id": "synthetic-1", "binding": "valid", "extra": "SYNTHETIC-CANARY"}]:
            before = len(client.calls)
            self.assertEqual(PROBE.probe(client, "synthetic", event), {"code": "INPUT_REFUSED"})
            self.assertEqual(len(client.calls), before)


if __name__ == "__main__":
    unittest.main()
