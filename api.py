#!/usr/bin/env python3
"""Aegis web service and dashboard.

    uvicorn api:app --port 8200

Upload scanner exports, watch duplicates merge, run verification,
triage, and read the evidence report. State persists to AEGIS_DB
(default ./aegis.json).
"""

from __future__ import annotations

import html
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, File, HTTPException, UploadFile  # noqa: E402
from fastapi.responses import HTMLResponse, PlainTextResponse  # noqa: E402

from aegis import ai, ingest, report, verify  # noqa: E402
from aegis.store import FindingStore  # noqa: E402

DB = Path(os.environ.get("AEGIS_DB", "aegis.json"))
STORE = FindingStore.load(DB)

app = FastAPI(title="Aegis", description="The verification layer for security findings")


def _persist() -> None:
    STORE.save(DB)


@app.get("/api/health")
def health():
    return {"status": "ok", "ai_provider": ai.detect_provider(), **STORE.stats()}


@app.get("/api/findings")
def findings():
    return [f.to_dict() for f in STORE.list()]


@app.get("/api/stats")
def stats():
    return STORE.stats()


@app.post("/api/ingest")
async def ingest_file(file: UploadFile = File(...)):
    text = (await file.read()).decode("utf-8", errors="replace")
    try:
        parsed = ingest.parse(text)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"could not parse this file as scanner output: {exc}")
    if not parsed:
        raise HTTPException(status_code=422, detail="no findings found in this file")
    result = STORE.add_many(parsed)
    _persist()
    return result


@app.post("/api/verify")
def run_verify():
    counts = verify.run_verifications(STORE)
    _persist()
    return counts


@app.post("/api/triage")
def run_triage():
    count = ai.run_triages(STORE)
    _persist()
    return {"triaged": count, "provider": ai.detect_provider()}


@app.get("/api/report")
def get_report(format: str = "md"):
    if format == "html":
        return HTMLResponse(report.html_report(STORE))
    if format == "json":
        return PlainTextResponse(report.json_report(STORE), media_type="application/json")
    return PlainTextResponse(report.markdown_report(STORE))


@app.get("/", response_class=HTMLResponse)
def dashboard(status: str | None = None):
    stats = STORE.stats()
    by = stats["by_status"]
    rows = []
    chip = {"verified": "#b3261e", "refuted": "#2e7d32", "inconclusive": "#b26a00", "new": "#5f6368"}
    pchip = {"P1": "#b3261e", "P2": "#b26a00", "P3": "#8a6d00", "P4": "#5f6368"}
    for f in STORE.list(status=status):
        priority = f.triage.get("priority", "")
        pcell = f"<span class='chip' style='background:{pchip.get(priority, '#666')}'>{priority}</span>" if priority else ""
        rows.append(
            f"<tr><td><b>{f.risk_score:.0f}</b></td><td>{html.escape(f.title)}</td>"
            f"<td>{html.escape(f.severity)}</td>"
            f"<td><span class='chip' style='background:{chip.get(f.status, '#666')}'>{f.status}</span></td>"
            f"<td>{pcell}</td>"
            f"<td>{html.escape(', '.join(f.sources))}</td>"
            f"<td class='mono'>{html.escape((f.endpoint or f.target)[:60])}</td>"
            f"<td>{html.escape(f.verification.get('detail', ''))}</td></tr>"
        )
    filters = " ".join(
        f"<a class='filter' href='/?status={s}'>{s}</a>" for s in ("verified", "refuted", "inconclusive", "new")
    )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Aegis</title>
<style>body{{background:#0b0e14;color:#e6e6e6;font-family:system-ui;margin:0;padding:28px}}
h1{{font-size:22px}} .cards{{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}}
.card{{background:#131824;border:1px solid #26314a;border-radius:10px;padding:12px 18px}}
.card b{{font-size:22px;display:block}}
.tablewrap{{overflow-x:auto;border-radius:10px}}
table{{width:100%;border-collapse:collapse;background:#131824;min-width:760px}}
td,th{{padding:8px 10px;border-bottom:1px solid #26314a;text-align:left;font-size:13px}}
.chip{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;white-space:nowrap}} .mono{{font-family:monospace}}
button{{background:#2b5cff;color:#fff;border:0;padding:9px 16px;border-radius:8px;cursor:pointer;margin:4px 8px 4px 0}}
input{{margin:10px 0;color:#e6e6e6}} .filter{{color:#9db8ff;margin-right:10px}}
@media (max-width:700px){{body{{padding:14px}} h1{{font-size:18px}} .card{{padding:8px 12px}} .card b{{font-size:17px}}
button{{width:100%;margin-right:0}} td,th{{font-size:12px;padding:6px 8px}}}}</style></head><body>
<h1>Aegis: verified security findings</h1>
<p>Scanners find. Aegis proves. Verification status is set only by deterministic checks; the AI only writes triage.</p>
<div class="cards">
<div class="card"><b>{stats['total']}</b>findings</div>
<div class="card"><b>{by.get('verified', 0)}</b>verified</div>
<div class="card"><b>{by.get('refuted', 0)}</b>refuted (noise removed)</div>
<div class="card"><b>{by.get('inconclusive', 0)}</b>inconclusive</div>
<div class="card"><b>{by.get('new', 0)}</b>unchecked</div></div>
<input type="file" id="file"><button onclick="ingest()">Ingest scanner export</button>
<button onclick="act('/api/verify')">Run verification</button>
<button onclick="act('/api/triage')">Run AI triage</button>
<button onclick="window.open('/api/report')">Open report</button>
<p>Filter: <a class='filter' href='/'>all</a>{filters}</p>
<div class="tablewrap">
<table><tr><th>Risk</th><th>Finding</th><th>Severity</th><th>Status</th><th>Priority</th><th>Sources</th><th>Target</th><th>Evidence</th></tr>
{''.join(rows) or '<tr><td colspan=8>No findings in this view. Ingest a Nuclei, ZAP or Burp export to begin.</td></tr>'}
</table></div>
<script>
async function ingest(){{const f=document.getElementById('file').files[0];if(!f)return;
const fd=new FormData();fd.append('file',f);
await fetch('/api/ingest',{{method:'POST',body:fd}});location.reload();}}
async function act(u){{await fetch(u,{{method:'POST'}});location.reload();}}
</script></body></html>"""
