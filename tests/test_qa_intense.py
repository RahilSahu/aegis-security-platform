"""Intense QA: edge cases, hostile inputs, load, TLS, diffing, CLI."""

import json
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_verify_live import FixtureHandler, FixtureHandlerFixed, serve

from aegis import ai, diff, ingest, verify
from aegis.models import Finding
from aegis.store import FindingStore

BURP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<issues burpVersion="2024.1">
  <issue>
    <type>1048832</type>
    <name>Cross-origin resource sharing</name>
    <host ip="127.0.0.1">http://127.0.0.1:8911</host>
    <path>/api/data</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail>The response reflects the Origin header.</issueDetail>
  </issue>
  <issue>
    <type>4194304</type>
    <name>Strict transport security not enforced</name>
    <host ip="127.0.0.1">https://127.0.0.1:8912</host>
    <path>/</path>
    <severity>Low</severity>
    <confidence>Certain</confidence>
    <issueDetail base64="true">VGhlIHNpdGUgZG9lcyBub3Qgc2VuZCBIU1RTLg==</issueDetail>
  </issue>
</issues>
"""


class ParserEdgeTests(unittest.TestCase):
    def test_burp_xml_with_base64_detail(self):
        findings = ingest.parse(BURP_XML)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].vuln_class, "cors")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].sources, ["burp"])
        self.assertIn("does not send HSTS", findings[1].description)

    def test_nuclei_malformed_lines_skipped(self):
        text = '{"template-id": "a", "info": {"name": "X", "severity": "low"}, "host": "http://h"}\nNOT JSON\n\n{"template-id": "b", "info": {"name": "Y", "severity": "low"}, "host": "http://h"}'
        self.assertEqual(len(ingest.parse_nuclei(text)), 2)

    def test_empty_inputs(self):
        store = FindingStore()
        self.assertEqual(store.add_many([]), {"added": 0, "merged": 0, "total": 0})
        self.assertEqual(store.list(), [])


class NewVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln_server, cls.vuln = serve(FixtureHandler)
        cls.fixed_server, cls.fixed = serve(FixtureHandlerFixed)

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()
        cls.fixed_server.shutdown()

    def _f(self, vuln_class, base, endpoint="/"):
        return Finding(title="t", vuln_class=vuln_class, severity="high", target=base, endpoint=base + endpoint)

    def test_sensitive_files(self):
        self.assertEqual(verify.verify_sensitive_files(self._f("sensitive-files", self.vuln))["status"], "verified")
        self.assertEqual(verify.verify_sensitive_files(self._f("sensitive-files", self.fixed))["status"], "refuted")

    def test_directory_listing(self):
        self.assertEqual(
            verify.verify_directory_listing(self._f("directory-listing", self.vuln, "/files/"))["status"], "verified"
        )
        self.assertEqual(
            verify.verify_directory_listing(self._f("directory-listing", self.fixed, "/files/"))["status"], "refuted"
        )

    def test_unreachable_target_is_inconclusive_not_crash(self):
        outcome = verify.verify_security_headers(self._f("security-headers", "http://127.0.0.1:1"))
        self.assertEqual(outcome["status"], "inconclusive")


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        key, cert = f"{cls.tmp}/k.pem", f"{cls.tmp}/c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "30", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, capture_output=True,
        )
        cls.server, _ = serve(FixtureHandlerFixed)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.url = f"https://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_self_signed_is_verified_as_tls_problem(self):
        f = Finding(title="TLS", vuln_class="tls", severity="medium", target=self.url, endpoint=self.url)
        self.assertEqual(verify.verify_tls(f)["status"], "verified")

    def test_plain_http_port_is_inconclusive(self):
        server, url = serve(FixtureHandler)
        try:
            f = Finding(title="TLS", vuln_class="tls", severity="medium", target=url, endpoint=url)
            self.assertEqual(verify.verify_tls(f)["status"], "inconclusive")
        finally:
            server.shutdown()


class StoreConcurrencyAndLoadTests(unittest.TestCase):
    def test_concurrent_duplicate_ingest_is_consistent(self):
        store = FindingStore()
        batch = ingest.parse((ROOT / "samples" / "nuclei.jsonl").read_text())

        def add():
            store.add_many([Finding(**f.to_dict()) for f in batch])

        threads = [threading.Thread(target=add) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(store.findings), 3)

    def test_load_1000_findings_and_bulk_verify(self):
        items = [
            {"title": f"Missing Content Security Policy {i}", "severity": "medium",
             "target": "http://127.0.0.1:9", "url": f"http://127.0.0.1:9/p{i}"}
            for i in range(1000)
        ]
        start = time.time()
        parsed = ingest.parse_generic(json.dumps(items))
        store = FindingStore()
        store.add_many(parsed)
        self.assertEqual(len(store.findings), 1000)
        self.assertLess(time.time() - start, 10)

    def test_bulk_verify_against_fixture(self):
        server, base = serve(FixtureHandler)
        try:
            store = FindingStore()
            store.add_many([
                Finding(title=f"h{i}", vuln_class="security-headers", severity="medium",
                        target=base, endpoint=f"{base}/p{i}")
                for i in range(40)
            ])
            start = time.time()
            counts = verify.run_verifications(store, workers=8)
            self.assertEqual(counts["verified"], 40)
            self.assertLess(time.time() - start, 30)
        finally:
            server.shutdown()


class DiffTests(unittest.TestCase):
    def _store(self, spec: dict[str, str]) -> FindingStore:
        store = FindingStore()
        for key, status in spec.items():
            f = Finding(title=key, vuln_class="cors", severity="high",
                        target="https://a.example", endpoint=f"https://a.example/{key}")
            f.id = key
            f.status = status
            store.findings[key] = f
        return store

    def test_fixed_persistent_regressed_new(self):
        before = self._store({"a": "verified", "b": "verified", "c": "refuted"})
        after = self._store({"a": "refuted", "b": "verified", "c": "verified", "d": "verified"})
        result = diff.compare(before, after)
        self.assertEqual(result["summary"], {"fixed": 1, "persistent": 1, "regressed": 1, "new": 1})


class CliTests(unittest.TestCase):
    def test_cli_roundtrip_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = f"{tmp}/a.json"
            run = subprocess.run(
                [sys.executable, "-m", "aegis.cli", "ingest",
                 str(ROOT / "samples" / "nuclei.jsonl"), "--db", db],
                capture_output=True, text=True, cwd=ROOT,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("3 new", run.stdout)
            run = subprocess.run(
                [sys.executable, "-m", "aegis.cli", "diff", db, db],
                capture_output=True, text=True, cwd=ROOT,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("fixed: 0", run.stdout)


class ApiHardeningTests(unittest.TestCase):
    def test_garbage_upload_is_422_not_500(self):
        from fastapi.testclient import TestClient

        import api

        api.STORE = FindingStore()
        client = TestClient(api.app, raise_server_exceptions=False)
        resp = client.post("/api/ingest", files={"file": ("x.txt", b"\x00\x01 not a scan")})
        self.assertEqual(resp.status_code, 422)

    def test_dashboard_escapes_finding_html(self):
        from fastapi.testclient import TestClient

        import api

        api.STORE = FindingStore()
        api.STORE.add_many([Finding(title="<script>alert(1)</script>", vuln_class="other",
                                    severity="low", target="http://x.example")])
        client = TestClient(api.app)
        page = client.get("/").text
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_status_filter(self):
        from fastapi.testclient import TestClient

        import api

        api.STORE = FindingStore()
        f = Finding(title="OnlyVerified", vuln_class="cors", severity="high", target="http://x.example")
        f.status = "verified"
        api.STORE.findings[f.id] = f
        client = TestClient(api.app)
        self.assertIn("OnlyVerified", client.get("/?status=verified").text)
        self.assertNotIn("OnlyVerified", client.get("/?status=refuted").text)


if __name__ == "__main__":
    unittest.main()
