import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import enroll_reference as er


ROOT = Path(__file__).resolve().parents[1]
ENTRY = "entries/azure-snp-vtpm-ima-1/azure-genoa-ubuntu2204-kernel-1071-stage"
COMMIT = "a" * 40


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.issuer_policy = json.loads((ROOT / "profiles/reference-issuers-stage.json").read_text())
        self.platform = json.loads((ROOT / "profiles/platform-genoa-stage.json").read_text())
        self.manifest_path = f"{ENTRY}/manifest.json"
        self.reference = json.dumps({"ima_measurements": [{"PCR": 10}], "pcr10_sha256": "0" * 64}).encode()
        self.manifest = json.dumps({
            "schema_version": 1,
            "id": "azure-genoa-ubuntu2204-kernel-1071-stage",
            "profile": "azure-snp-vtpm-ima/1",
            "environment": {"tee": "AMD SEV-SNP", "product": "Genoa"},
            "reference": {"path": f"{ENTRY}/reference.json", "sha256": hashlib.sha256(self.reference).hexdigest(), "ima_entries": 1},
            "provenance": {"review_status": "stage-candidate"},
            "coverage": ["boot_aggregate", "kernel_modules"],
        }).encode()
        self.bundle = b"bundle-test-placeholder"
        self.objects = {self.manifest_path: self.manifest,
                        f"{ENTRY}/reference.json": self.reference,
                        f"{ENTRY}/endorsements/genxt.sigstore.json": self.bundle}

    def reader(self, path):
        return self.objects[path]

    def verification(self, predicate=None):
        digest = hashlib.sha256(self.manifest).hexdigest()
        expected = {"schema_version": 1, "claim": "published-reference-manifest", "publisher": "GENXT",
                    "registry_repository": "teraveri/reference-value-registry",
                    "manifest_path": self.manifest_path, "manifest_sha256": digest}
        record = [{"verificationResult": {"statement": {
            "subject": [{"name": f"teraveri/reference-value-registry/{self.manifest_path}",
                         "digest": {"sha256": digest}}],
            "predicate": predicate or expected}}}]
        return SimpleNamespace(stdout=json.dumps(record))

    @patch("enroll_reference.subprocess.run")
    def test_enrolls_only_verified_publisher_statement(self, run):
        run.return_value = self.verification()
        policy = er.enroll("teraveri/reference-value-registry", COMMIT, ENTRY,
                           self.issuer_policy, self.platform, self.reader, "gh")
        self.assertEqual(policy["reference"]["sha256"], hashlib.sha256(self.reference).hexdigest())
        command = run.call_args.args[0]
        self.assertIn("--signer-workflow", command)
        self.assertIn("--source-ref", command)
        self.assertIn("--predicate-type", command)
        self.assertTrue(run.call_args.kwargs["check"])

    @patch("enroll_reference.subprocess.run")
    def test_rejects_signed_wrong_claim(self, run):
        run.return_value = self.verification({"claim": "unrelated"})
        with self.assertRaisesRegex(ValueError, "signed subject or publisher claim mismatch"):
            er.enroll("teraveri/reference-value-registry", COMMIT, ENTRY,
                      self.issuer_policy, self.platform, self.reader, "gh")

    @patch("enroll_reference.subprocess.run")
    def test_rejects_reference_change_before_signature_check(self, run):
        self.objects[f"{ENTRY}/reference.json"] += b" "
        with self.assertRaisesRegex(ValueError, "reference digest mismatch"):
            er.enroll("teraveri/reference-value-registry", COMMIT, ENTRY,
                      self.issuer_policy, self.platform, self.reader, "gh")
        run.assert_not_called()

    @patch("enroll_reference.subprocess.run")
    def test_rejects_unapproved_publisher(self, run):
        with self.assertRaisesRegex(ValueError, "issuer is not uniquely authorized"):
            er.enroll("teraveri/reference-value-registry", COMMIT, ENTRY,
                      self.issuer_policy, self.platform, self.reader, "gh", "other")
        run.assert_not_called()

    @patch("enroll_reference.subprocess.run")
    def test_rejects_unsafe_publisher_name(self, run):
        with self.assertRaisesRegex(ValueError, "invalid issuer name"):
            er.enroll("teraveri/reference-value-registry", COMMIT, ENTRY,
                      self.issuer_policy, self.platform, self.reader, "gh", "../other")
        run.assert_not_called()

    def test_stage_negative_uses_same_genoa_platform_and_alternate_reference(self):
        negative = json.loads((ROOT / "profiles/verifier-genoa-stage-mismatch.json").read_text())
        self.assertEqual(negative["platform"], self.platform)
        self.assertNotEqual(negative["reference"]["sha256"], hashlib.sha256(self.reference).hexdigest())


if __name__ == "__main__":
    unittest.main()
