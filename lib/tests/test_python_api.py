"""Offline smoke tests for the installed wheel: python -m unittest discover -s tests."""

import inspect
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import confido


class AttestationHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.nonces.append(request["nonce"])
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
