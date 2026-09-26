"""Installed-wheel boundaries; no network or hardware required."""
import json
from pathlib import Path
import unittest
import confido_verifier as verifier
POLICY = (Path(__file__).resolve().parents[2]/"profiles/verifier-match.json").read_bytes()
class VerifierTests(unittest.TestCase):
    def call(self, report=b"", nonce=bytes(32), at=1750000000):
        return verifier.verify(report, b"", b"", b"", POLICY, nonce, at)
    def test_no_transport_api(self):
        for name in ("connect_py", "discover_py", "appraise_offline_py", "request", "AttestedSession"):
            self.assertFalse(hasattr(verifier, name))
        self.assertEqual(verifier.__version__, "0.4.0")
    def test_build_metadata_is_separate_from_result(self):
        info=verifier.build_info()
        self.assertEqual(info['core']['pipeline_revision'], 2)
        for item in (info['core'], info['wrapper']):
            self.assertRegex(item['source_sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(item['rustc'].startswith('rustc '))
            self.assertIn('features', item)
            self.assertIn('build_profile', item)
        self.assertNotIn('pipeline_revision', self.call())
        self.assertNotIn('core', self.call())

    def test_incomplete_result_has_no_admission(self):
        result=self.call()
        self.assertEqual(result["status"], "incomplete_input")
        self.assertEqual(result["scope"], "evidence_only")
        self.assertNotIn("application_admitted", result)
        self.assertNotIn("origin", result)
        self.assertFalse(result["bindings"]["challenge_matches"])
    def test_explicit_context_and_bounded_input(self):
        for nonce in (b"", bytes(31), bytes(33)):
            with self.assertRaises(ValueError): self.call(nonce=nonce)
        for at in (-1, 253402300800):
            with self.assertRaises(ValueError): self.call(at=at)
        with self.assertRaises(ValueError): self.call(report=b" "*(4*1024*1024+1))
    def test_result_schema_rejects_admission_claim(self):
        try: import jsonschema
        except ImportError: self.skipTest("Install jsonschema for schema checks")
        schema=json.loads((Path(__file__).resolve().parents[2]/"schemas/verification-result-v2.json").read_bytes())
        result=self.call()
        jsonschema.validate(result,schema)
        for key in ("application_admitted","origin","fresh_quote","https_peer"):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(dict(result, **{key:True}),schema)

    def test_inspection_never_accepts_malformed_report(self):
        for raw in (b"", b"{}", b"null", b"[]"):
            with self.assertRaises(ValueError): verifier.inspect_requirements(raw)
if __name__ == "__main__": unittest.main()
