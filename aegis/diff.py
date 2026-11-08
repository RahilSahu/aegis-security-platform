"""Retest diffing: what changed between two verification runs.

This is the sprint-over-sprint view a security team actually needs:
what we proved last time is fixed now, what is still open, what is
new, and the one nobody wants, what regressed.
"""

from __future__ import annotations

from .store import FindingStore


def _label(store: FindingStore, fid: str) -> dict:
    f = store.findings.get(fid)
    if f is None:
        return {"id": fid, "title": "(removed)", "target": ""}
    return {"id": fid, "title": f.title, "target": f.endpoint or f.target, "severity": f.severity}


def compare(before: FindingStore, after: FindingStore) -> dict:
    fixed, persistent, regressed, new = [], [], [], []
    before_ids = set(before.findings)
    after_ids = set(after.findings)
    for fid in before_ids | after_ids:
        b = before.findings.get(fid)
        a = after.findings.get(fid)
        b_state = b.status if b else None
        a_state = a.status if a else None
        if b_state == "verified" and a_state in ("refuted", None):
            fixed.append(_label(before, fid))
        elif b_state == "refuted" and a_state == "verified":
            regressed.append(_label(after, fid))
        elif b_state == "verified" and a_state == "verified":
            persistent.append(_label(after, fid))
        elif b is None and a_state == "verified":
            new.append(_label(after, fid))
    return {
        "fixed": fixed,
        "persistent": persistent,
        "regressed": regressed,
        "new": new,
        "summary": {
            "fixed": len(fixed),
            "persistent": len(persistent),
            "regressed": len(regressed),
            "new": len(new),
        },
    }
