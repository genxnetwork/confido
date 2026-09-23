"""Offline smoke tests for the installed wheel: python -m unittest discover -s tests."""

import inspect
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

import confido


class AttestationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlsplit(self.path).path != "/service-info":
            self.send_error(404)
            return
        advertisement = {
            "teeReport": {
                "endpoint": self.server.advertisement_endpoint, "method": "POST",
                "nonce": {"name": "nonce", "in": "body", "encoding": "base64", "sizeBytes": 32},
                "response": {"evidenceField": "evidence", "certificateField": "certificate"},
            }
        }
        body = json.dumps(advertisement).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlsplit(self.path).path != "/tee-report":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.nonces.append(json.loads(body)["nonce"])
        self.send_response(self.server.response_status)
        self.end_headers()
        self.wfile.write(self.server.response_body)

    def log_message(self, *_args):
        pass


class PythonApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), AttestationHandler)
        cls.server.nonces = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.server.response_status = 200
        self.server.response_body = b"{}"
        self.server.advertisement_endpoint = "/tee-report"

    def test_registry_is_optional_and_accepts_positional_and_keyword_arguments(self):
        signature = inspect.signature(confido.aTLS_connect_py)
        self.assertIsNone(signature.parameters["trs_registry"].default)
        calls = [
            lambda: confido.aTLS_connect_py(self.url),
            lambda: confido.aTLS_connect_py(self.url, "owner/repository"),
            lambda: confido.aTLS_connect_py(self.url, trs_registry="owner/repository"),
        ]
        for call in calls:
            with self.assertRaisesRegex(RuntimeError, "Failed to deserialize JSON"):
                call()
        self.assertEqual(len(set(self.server.nonces[-3:])), 3)

    def test_rejects_untrusted_report_endpoint_before_posting_nonce(self):
        before = len(self.server.nonces)
        self.server.advertisement_endpoint = "https://example.invalid/steal"
        with self.assertRaisesRegex(RuntimeError, "Unsupported service-info TEE report advertisement"):
            confido.aTLS_connect_py(self.url)
        self.assertEqual(len(self.server.nonces), before)

    def test_http_error_is_reported_before_deserialization(self):
        self.server.response_status = 503
        with self.assertRaisesRegex(RuntimeError, "503"):
            confido.aTLS_connect_py(self.url)

    def test_malformed_certificate_raises_runtime_error(self):
        response = {
            "certificate": list(b"invalid PEM"),
            "evidence": {
                "report": [],
                "quote": {"signature": [], "message": [], "pcr_banks": []},
                "cgpu_attestation": None,
                "module_load_order": {"kernel": "", "order": []},
                "ima_measurements": [],
            },
        }
        self.server.response_body = json.dumps(response).encode()
        with self.assertRaisesRegex(RuntimeError, "Failed to parse aTLS certificate"):
            confido.aTLS_connect_py(self.url)

    def test_debug_aliases_are_available_and_idempotent(self):
        confido.atls_debug()
        confido.atls_debug_py()
        confido.atls_debug()


if __name__ == "__main__":
    unittest.main()
