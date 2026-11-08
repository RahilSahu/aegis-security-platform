"""QA round 3: verifier precision and real-world data realism."""

import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aegis import ingest, verify
from aegis.models import Finding
from aegis.store import FindingStore


def serve(handler) -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class PrecisionHandler(BaseHTTPRequestHandler):
    """Configurable precision fixture: partial headers, mixed cookies,
    a slow endpoint, and CORS variants by path."""

    def log_message(self, *args):
        pass

    def _send(self, body=b"ok", extra=None):
        self.send_response(200)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(3)
            return self._send()
        if self.path == "/partial-headers":
            # CSP + XCTO present (http target: HSTS not applicable)
            return self._send(extra={
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
            })
        if self.path == "/http-complete":
            return self._send(extra={
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            })
        if self.path == "/mixed-cookies":
            body = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "good=1; Secure; HttpOnly; SameSite=Lax")
            self.send_header("Set-Cookie", "bad=2")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if self.path == "/cors-wildcard":
            return self._send(extra={"Access-Control-Allow-Origin": "*"})
        if self.path == "/cors-fixed":
            return self._send(extra={"Access-Control-Allow-Origin": "https://app.example"})
        return self._send()


class VerifierPrecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base = serve(PrecisionHandler)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _f(self, vuln_class, path):
        return Finding(title="t", vuln_class=vuln_class, severity="medium",
                       target=self.base, endpoint=self.base + path)

    def test_partial_headers_lists_only_missing(self):
        outcome = verify.verify_security_headers(self._f("security-headers", "/partial-headers"))
        self.assertEqual(outcome["status"], "verified")
        missing = outcome["evidence"]["missing"]
        self.assertNotIn("content-security-policy", missing)
        self.assertIn("referrer-policy", missing)
        self.assertIn("x-frame-options", missing)
        self.assertNotIn("strict-transport-security", missing, "HSTS must not be required over plain HTTP")

    def test_http_complete_headers_refute(self):
        outcome = verify.verify_security_headers(self._f("security-headers", "/http-complete"))
        self.assertEqual(outcome["status"], "refuted")

    def test_mixed_cookies_flags_only_the_bad_one(self):
        outcome = verify.verify_cookie_flags(self._f("cookie-flags", "/mixed-cookies"))
        self.assertEqual(outcome["status"], "verified")
        problems = outcome["evidence"]["problems"]
        self.assertEqual([p["cookie"] for p in problems], ["bad"])

    def test_cors_wildcard_without_credentials_refutes(self):
        outcome = verify.verify_cors(self._f("cors", "/cors-wildcard"))
        self.assertEqual(outcome["status"], "refuted")

    def test_cors_fixed_origin_refutes(self):
        outcome = verify.verify_cors(self._f("cors", "/cors-fixed"))
        self.assertEqual(outcome["status"], "refuted")

    def test_slow_target_times_out_to_inconclusive(self):
        start = time.time()
        outcome = verify.verify_security_headers(self._f("security-headers", "/slow"), timeout=1.0)
        elapsed = time.time() - start
        self.assertEqual(outcome["status"], "inconclusive")
        self.assertLess(elapsed, 8, "two attempts at 1s timeout plus backoff must stay bounded")


class RealWorldDataTests(unittest.TestCase):
    def test_zap_cwe_minus_one_is_no_cwe(self):
        text = json.dumps({"site": [{"@name": "http://h", "alerts": [
            {"name": "X", "riskcode": "1", "cweid": "-1", "desc": "", "instances": [{"uri": "http://h/"}]},
            {"name": "Y", "riskcode": "2", "cweid": "79", "desc": "", "instances": [{"uri": "http://h/a"}]},
        ]}]})
        findings = ingest.parse_zap(text)
        self.assertEqual(findings[0].cwe, "")
        self.assertEqual(findings[1].cwe, "CWE-79")

    def test_nuclei_missing_optional_fields(self):
        line = json.dumps({"template-id": "t1", "host": "http://h.example"})
        findings = ingest.parse_nuclei(line)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")

    def test_burp_information_severity_normalises(self):
        xml = ('<issues><issue><name>X</name><host>http://h</host><path>/</path>'
               '<severity>Information</severity><issueDetail>d</issueDetail></issue></issues>')
        self.assertEqual(ingest.parse_burp(xml)[0].severity, "info")

    def test_unicode_and_long_titles_survive_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "u.json"
            store = FindingStore()
            title = "Sécurité 🔐 " + "x" * 500
            store.add_many([Finding(title=title, vuln_class="other", severity="low",
                                    target="https://a.example")])
            store.save(db)
            loaded = FindingStore.load(db)
            self.assertEqual(list(loaded.findings.values())[0].title, title)

    def test_first_seen_set_and_last_seen_updates(self):
        store = FindingStore()
        f = Finding(title="CORS", vuln_class="cors", severity="low", target="https://a.example")
        store.add_many([f])
        self.assertGreater(f.first_seen, 0)
        first = f.first_seen
        time.sleep(0.02)
        store.add_many([Finding(title="CORS again", vuln_class="cors", severity="low",
                                target="https://a.example")])
        self.assertEqual(f.first_seen, first)
        self.assertGreater(f.last_seen, first)


class BlackBoxCliTests(unittest.TestCase):
    def test_full_pipeline_subprocess(self):
        """The whole product as a user runs it: ingest real samples,
        verify against the live fixture on the samples' port, triage,
        and produce all three report formats."""
        from test_verify_live import FixtureHandler

        fixture = ThreadingHTTPServer(("127.0.0.1", 8911), FixtureHandler)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                db = f"{tmp}/e2e.json"
                def run(*args):
                    r = subprocess.run([sys.executable, "-m", "aegis.cli", *args],
                                       capture_output=True, text=True, cwd=ROOT)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    return r.stdout

                out = run("ingest", str(ROOT / "samples" / "nuclei.jsonl"),
                          str(ROOT / "samples" / "zap.json"), "--db", db)
                self.assertIn("4 total", out)
                out = run("verify", "--db", db, "--timeout", "5", "--workers", "4")
                self.assertIn("'verified': 4", out)
                out = run("triage", "--db", db)
                self.assertIn("triaged 4", out)
                md = run("report", "--db", db)
                self.assertIn("Executive summary", md)
                html_out = run("report", "--db", db, "--format", "html")
                self.assertIn("<title>Aegis Security Verification Report</title>", html_out)
                payload = json.loads(run("report", "--db", db, "--format", "json"))
                self.assertEqual(payload["schema"], "aegis.report/1")
                self.assertIn("generated_at", payload)
                self.assertTrue(all(f["first_seen"] > 0 for f in payload["findings"]))
        finally:
            fixture.shutdown()


if __name__ == "__main__":
    unittest.main()
