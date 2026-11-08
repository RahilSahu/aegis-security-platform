import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import ingest
from aegis.models import Finding
from aegis.store import FindingStore


class IngestTests(unittest.TestCase):
    def test_samples_merge_across_tools(self):
        store = FindingStore()
        r1 = store.add_many(ingest.parse((ROOT / "samples" / "nuclei.jsonl").read_text()))
        r2 = store.add_many(ingest.parse((ROOT / "samples" / "zap.json").read_text()))
        self.assertEqual(r1["added"], 3)
        self.assertEqual(r2["added"], 1)  # cookie finding is new
        self.assertEqual(r2["merged"], 2)  # CSP and CORS merge with Nuclei's
        self.assertEqual(len(store.findings), 4)
        cors = [f for f in store.findings.values() if f.vuln_class == "cors"][0]
        self.assertEqual(sorted(cors.sources), ["nuclei", "zap"])

    def test_generic_and_csv(self):
        generic = ingest.parse(
            '[{"title": "Missing Content Security Policy", "severity": "medium",'
            ' "target": "https://a.example", "url": "https://a.example/"}]'
        )
        self.assertEqual(generic[0].vuln_class, "security-headers")
        rows = ingest.parse(
            "title,severity,target\nJWT alg none accepted,high,https://b.example\n", fmt="csv"
        )
        self.assertEqual(rows[0].vuln_class, "jwt")

    def test_severity_normalisation(self):
        f = Finding(title="x", vuln_class="other", severity="High", target="https://a.example")
        self.assertEqual(f.severity, "high")


class ScoringTests(unittest.TestCase):
    def test_verified_outranks_new_and_refuted_collapses(self):
        f = Finding(title="CORS", vuln_class="cors", severity="medium",
                    target="https://a.example", sources=["nuclei"])
        new_score = f.risk_score
        f.status = "verified"
        f.recompute_score()
        self.assertGreater(f.risk_score, new_score)
        f.status = "refuted"
        f.recompute_score()
        self.assertLess(f.risk_score, 5)

    def test_corroboration_boosts_score(self):
        one = Finding(title="CORS", vuln_class="cors", severity="medium",
                      target="https://a.example", sources=["nuclei"])
        two = Finding(title="CORS", vuln_class="cors", severity="medium",
                      target="https://a.example", sources=["nuclei", "zap"])
        self.assertGreater(two.risk_score, one.risk_score)


if __name__ == "__main__":
    unittest.main()
