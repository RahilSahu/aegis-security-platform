"""Finding store: deduplication across tools and JSON persistence."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


class FindingStore:
    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}

    def add_many(self, incoming: list[Finding]) -> dict:
        """Add findings, merging duplicates by fingerprint.
        Returns counts: added vs merged."""
        added = merged = 0
        for finding in incoming:
            existing = self.findings.get(finding.id)
            if existing is None:
                self.findings[finding.id] = finding
                added += 1
            else:
                existing.merge(finding)
                merged += 1
        return {"added": added, "merged": merged, "total": len(self.findings)}

    def list(self, status: str | None = None) -> list[Finding]:
        out = list(self.findings.values())
        if status:
            out = [f for f in out if f.status == status]
        return sorted(out, key=lambda f: f.risk_score, reverse=True)

    def stats(self) -> dict:
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for f in self.findings.values():
            by_status[f.status] = by_status.get(f.status, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {"total": len(self.findings), "by_status": by_status, "by_severity": by_severity}

    def save(self, path: str | Path) -> None:
        """Atomic save: write to a temp file in the same directory and
        rename, so a crash mid-write can never corrupt the database."""
        import os

        path = Path(path)
        data = {fid: f.to_dict() for fid, f in self.findings.items()}
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str | Path) -> "FindingStore":
        store = cls()
        file = Path(path)
        if file.exists():
            data = json.loads(file.read_text(encoding="utf-8"))
            for fid, raw in data.items():
                store.findings[fid] = Finding.from_dict(raw)
        return store
