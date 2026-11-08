import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import ai
from aegis.models import Finding
from aegis.store import FindingStore


class TriageTests(unittest.TestCase):
    def test_heuristic_triage_shape_and_invariant(self):
        f = Finding(title="CORS Misconfiguration", vuln_class="cors", severity="medium",
                    target="https://a.example", sources=["nuclei", "zap"])
        f.status = "verified"
        f.verification = {"detail": "origin is reflected"}
        f.recompute_score()
        before_status = f.status
        result = ai.triage_finding(f, provider="none")
        self.assertEqual(result["engine"], "heuristic")
        self.assertGreaterEqual(result["exploitability"], 8)
        self.assertIn("allowlist", result["remediation"])
        self.assertEqual(f.status, before_status, "triage must never change verification status")

    def test_refuted_finding_gets_zero_exploitability(self):
        f = Finding(title="CORS", vuln_class="cors", severity="medium", target="https://a.example")
        f.status = "refuted"
        f.recompute_score()
        result = ai.triage_finding(f, provider="none")
        self.assertEqual(result["exploitability"], 0)


class ApiTests(unittest.TestCase):
    def test_full_flow(self):
        from fastapi.testclient import TestClient

        import api

        api.STORE = FindingStore()  # isolate from any on-disk state
        client = TestClient(api.app)
        self.assertEqual(client.get("/api/health").json()["status"], "ok")
        nuclei = (ROOT / "samples" / "nuclei.jsonl").read_text()
        resp = client.post("/api/ingest", files={"file": ("nuclei.jsonl", nuclei)})
        self.assertEqual(resp.json()["added"], 3)
        zap = (ROOT / "samples" / "zap.json").read_text()
        resp = client.post("/api/ingest", files={"file": ("zap.json", zap)})
        self.assertEqual(resp.json()["merged"], 2)
        resp = client.post("/api/triage")
        self.assertEqual(resp.status_code, 200)
        findings = client.get("/api/findings").json()
        self.assertTrue(all(f["triage"] for f in findings))
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Aegis", page.text)
        report = client.get("/api/report")
        self.assertIn("Aegis Security Verification Report", report.text)


if __name__ == "__main__":
    unittest.main()
