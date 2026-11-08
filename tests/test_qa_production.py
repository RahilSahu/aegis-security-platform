"""Production-grade QA: fingerprint identity, SSRF guard, report
quality, determinism, fuzz dedupe, LLM fallback, idempotency."""

import json
import os
import random
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_verify_live import FixtureHandler, serve

from aegis import ai, ingest, report, verify
from aegis.models import Finding, fingerprint
from aegis.store import FindingStore


class FingerprintIdentityTests(unittest.TestCase):
    def test_port_separates_apps(self):
        a = fingerprint("cors", "https://h.example:8443", "https://h.example:8443/x")
        b = fingerprint("cors", "https://h.example", "https://h.example/x")
        self.assertNotEqual(a, b)

    def test_scheme_and_trailing_slash_merge(self):
        a = fingerprint("cors", "http://h.example", "http://h.example/api/data")
        b = fingerprint("cors", "https://h.example", "https://h.example/api/data/")
        self.assertEqual(a, b)

    def test_numeric_segments_template(self):
        a = fingerprint("jwt", "https://h.example", "https://h.example/users/42/token")
        b = fingerprint("jwt", "https://h.example", "https://h.example/users/987/token")
        self.assertEqual(a, b)

    def test_fuzz_dedupe_exact_count(self):
        random.seed(7)
        classes = ["cors", "security-headers", "jwt"]
        store = FindingStore()
        expected = set()
        batch = []
        for i in range(300):
            cls = random.choice(classes)
            user_id = random.choice([1, 2, 3])
            host = random.choice(["a.example", "b.example"])
            f = Finding(title=f"scanner wording variant {i}", vuln_class=cls,
                        severity="medium", target=f"https://{host}",
                        endpoint=f"https://{host}/users/{user_id}/x",
                        sources=[f"tool{random.randint(1, 3)}"])
            expected.add((cls, host))
            batch.append(f)
        store.add_many(batch)
        # identity = class x host x templated path: 3 classes x 2 hosts
        self.assertEqual(len(store.findings), len(expected) * 1)
        self.assertEqual(len(store.findings), 6)


class SsrfGuardTests(unittest.TestCase):
    def test_metadata_ip_blocked_without_any_request(self):
        f = Finding(title="headers", vuln_class="security-headers", severity="low",
                    target="http://169.254.169.254", endpoint="http://169.254.169.254/latest/meta-data/")
        start = __import__("time").time()
        outcome = verify.verify_security_headers(f, timeout=3)
        self.assertEqual(outcome["status"], "inconclusive")
        self.assertIn("SSRF guard", outcome["detail"])
        self.assertLess(__import__("time").time() - start, 3, "guard must fire before any network call")

    def test_metadata_hostname_blocked(self):
        self.assertIsNotNone(verify._blocked("http://metadata.google.internal/computeMetadata/v1/"))

    def test_private_and_loopback_allowed(self):
        self.assertIsNone(verify._blocked("http://192.168.1.10/admin"))
        self.assertIsNone(verify._blocked("http://127.0.0.1:8080/"))


class RedirectAndBinaryTests(unittest.TestCase):
    def test_redirect_and_binary_body_do_not_crash(self):
        import http.server

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", "/bin")
                    self.end_headers()
                else:
                    body = bytes(range(256)) * 8
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), H) if False else None
        from http.server import ThreadingHTTPServer

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            f = Finding(title="listing", vuln_class="directory-listing", severity="low",
                        target=base, endpoint=base + "/redir")
            outcome = verify.verify_directory_listing(f)
            self.assertEqual(outcome["status"], "refuted")
        finally:
            server.shutdown()


class ReportQualityTests(unittest.TestCase):
    def _store(self) -> FindingStore:
        store = FindingStore()
        v = Finding(title="CORS Misconfiguration", vuln_class="cors", severity="high",
                    target="https://app.example", endpoint="https://app.example/api", cwe="CWE-942",
                    sources=["nuclei", "zap"])
        v.status = "verified"
        v.verification = {"detail": "origin is reflected"}
        v.recompute_score()
        r = Finding(title="Missing CSP", vuln_class="security-headers", severity="medium",
                    target="https://app.example", endpoint="https://app.example/")
        r.status = "refuted"
        r.verification = {"detail": "all core security headers are present"}
        r.recompute_score()
        store.findings[v.id] = v
        store.findings[r.id] = r
        ai.run_triages(store, provider="none")
        return store

    def test_metrics_math(self):
        m = report.summary_metrics(self._store())
        self.assertEqual(m["total"], 2)
        self.assertEqual(m["noise_reduction_pct"], 50.0)
        self.assertEqual(m["coverage_pct"], 100.0)
        self.assertEqual(m["critical_verified"], 1)

    def test_markdown_is_deterministic(self):
        store = self._store()
        self.assertEqual(report.markdown_report(store), report.markdown_report(store))

    def test_markdown_has_exec_summary_and_sla(self):
        text = report.markdown_report(self._store())
        self.assertIn("Executive summary", text)
        self.assertIn("noise eliminated", text)
        self.assertIn("SLA 7 days", text)  # verified high cors, 2 sources: risk 82.5 = P1
        self.assertIn("CWE: CWE-942", text)

    def test_html_report_escapes_and_renders(self):
        store = self._store()
        store.findings[list(store.findings)[0]].title = "<img src=x onerror=alert(1)>"
        page = report.html_report(store)
        self.assertNotIn("<img src=x onerror=alert(1)>", page)
        self.assertIn("noise eliminated", page)
        self.assertIn("@media print", page)

    def test_json_report_parses_and_matches(self):
        store = self._store()
        payload = json.loads(report.json_report(store))
        self.assertEqual(payload["tool"], "aegis")
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual(payload["summary"]["total"], 2)


class TriageEnrichmentTests(unittest.TestCase):
    def test_enrichment_fields_present(self):
        f = Finding(title="JWT none", vuln_class="jwt", severity="high", target="https://a.example")
        f.status = "verified"
        f.recompute_score()
        result = ai.triage_finding(f, provider="none")
        self.assertEqual(result["owasp"], "A07:2021 Identification and Authentication Failures")
        self.assertIn("sla_days", result)
        self.assertIn("effort", result)

    def test_llm_failure_falls_back_to_heuristic(self):
        f = Finding(title="CORS", vuln_class="cors", severity="medium", target="https://a.example")
        # No OPENAI_API_KEY in the test environment: constructing the
        # provider model must fail and the fallback must engage.
        os.environ.pop("OPENAI_API_KEY", None)
        result = ai.triage_finding(f, provider="openai")
        self.assertEqual(result["engine"], "heuristic")
        self.assertEqual(f.status, "new")


class PersistenceTests(unittest.TestCase):
    def test_atomic_save_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "db.json"
            store = FindingStore()
            f = Finding(title="CORS", vuln_class="cors", severity="high", target="https://a.example")
            f.status = "verified"
            f.triage = {"priority": "P1"}
            store.findings[f.id] = f
            store.save(db)
            self.assertFalse(Path(str(db) + ".tmp").exists(), "temp file must be renamed away")
            loaded = FindingStore.load(db)
            self.assertEqual(loaded.findings[f.id].status, "verified")
            self.assertEqual(loaded.findings[f.id].triage["priority"], "P1")

    def test_load_missing_file_is_empty_store(self):
        store = FindingStore.load("/nonexistent/dir/db.json")
        self.assertEqual(len(store.findings), 0)


class ApiIdempotencyTests(unittest.TestCase):
    def test_double_ingest_is_idempotent(self):
        from fastapi.testclient import TestClient

        import api

        api.STORE = FindingStore()
        client = TestClient(api.app)
        data = (ROOT / "samples" / "nuclei.jsonl").read_bytes()
        first = client.post("/api/ingest", files={"file": ("n.jsonl", data)}).json()
        second = client.post("/api/ingest", files={"file": ("n.jsonl", data)}).json()
        self.assertEqual(first["added"], 3)
        self.assertEqual(second["added"], 0)
        self.assertEqual(second["merged"], 3)
        self.assertEqual(second["total"], 3)

    def test_report_formats_via_api(self):
        from fastapi.testclient import TestClient

        import api

        api.STORE = FindingStore()
        client = TestClient(api.app)
        html_resp = client.get("/api/report?format=html")
        self.assertIn("text/html", html_resp.headers["content-type"])
        json_resp = client.get("/api/report?format=json")
        self.assertEqual(json.loads(json_resp.text)["tool"], "aegis")


if __name__ == "__main__":
    unittest.main()
