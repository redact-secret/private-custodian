"""Static checks of the EC2 worker template against ADR 0142. Offline; deploys nothing."""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra" / "aws" / "ec2" / "worker.template.json"


class WorkerTemplate(unittest.TestCase):
    def setUp(self):
        self.t = json.loads(TEMPLATE.read_text())
        self.res = self.t["Resources"]
        self.lt = self.res["WorkerLaunchTemplate"]["Properties"]["LaunchTemplateData"]

    def test_ami_is_pinned_not_an_alias(self):
        p = self.t["Parameters"]["PinnedAmiId"]
        self.assertTrue(p["AllowedPattern"].startswith("^ami-"))
        self.assertNotIn("ssm", json.dumps(self.t).lower())

    def test_fresh_instance_terminates_and_storage_dies_with_it(self):
        self.assertEqual(self.lt["InstanceInitiatedShutdownBehavior"], "terminate")
        for ebs in (m["Ebs"] for m in self.lt["BlockDeviceMappings"]):
            self.assertTrue(ebs["DeleteOnTermination"])
            self.assertTrue(ebs["Encrypted"])
        self.assertTrue(self.lt["NetworkInterfaces"][0]["DeleteOnTermination"])

    def test_no_hibernation_or_reuse_knob(self):
        text = json.dumps(self.t)
        self.assertNotIn("HibernationOptions", text)
        self.assertNotIn("stop-start", text)

    def test_imdsv2_only_and_hop_limit_one(self):
        m = self.lt["MetadataOptions"]
        self.assertEqual(m["HttpTokens"], "required")
        self.assertEqual(m["HttpPutResponseHopLimit"], 1)

    def test_no_public_ip_and_no_ingress(self):
        self.assertFalse(self.lt["NetworkInterfaces"][0]["AssociatePublicIpAddress"])
        self.assertEqual(self.res["WorkerSecurityGroup"]["Properties"]["SecurityGroupIngress"], [])

    def test_no_open_cidr_anywhere(self):
        self.assertNotIn("0.0.0.0/0", json.dumps(self.t))
        self.assertNotIn("::/0", json.dumps(self.t))

    def test_iam_has_no_wildcard_action_or_resource(self):
        for r in self.res.values():
            if r["Type"] != "AWS::IAM::Role":
                continue
            for pol in r["Properties"]["Policies"]:
                for st in pol["PolicyDocument"]["Statement"]:
                    acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                    self.assertFalse(any("*" in a for a in acts))
                    self.assertNotEqual(st["Resource"], "*")

    def test_worker_role_cannot_manage_instances_or_keys(self):
        for pol in self.res["WorkerRole"]["Properties"]["Policies"]:
            for st in pol["PolicyDocument"]["Statement"]:
                for a in st["Action"]:
                    self.assertTrue(a.startswith("s3:"), a)

    def test_budget_ceiling_is_bounded(self):
        c = self.t["Parameters"]["AuthorizationCeilingUsd"]
        self.assertLessEqual(c["MaxValue"], 50)


if __name__ == "__main__":
    unittest.main()
