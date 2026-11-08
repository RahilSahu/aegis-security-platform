"""Reporting: the deliverable a security team actually sends.

Three formats over one evidence base:
- Markdown for tickets, wikis and pull requests.
- Standalone HTML (inline CSS, print-friendly) for management and
  client delivery.
- JSON for pipelines and ticketing integrations.

Every format leads with the executive metrics a CISO reads first:
how much scanner noise was eliminated, what fraction of findings
could be decided automatically, and what is actually proven.
Statuses in every format come only from deterministic verification.
"""

from __future__ import annotations

import html
import json

from .store import FindingStore


def summary_metrics(store: FindingStore) -> dict:
    stats = store.stats()
    by = stats["by_status"]
    checked = by.get("verified", 0) + by.get("refuted", 0) + by.get("inconclusive", 0)
    decided = by.get("verified", 0) + by.get("refuted", 0)
    verified = store.list(status="verified")
    return {
        "total": stats["total"],
        "by_status": by,
        "by_severity": stats["by_severity"],
        "checked": checked,
        "coverage_pct": round(100 * decided / checked, 1) if checked else 0.0,
        "noise_reduction_pct": round(100 * by.get("refuted", 0) / checked, 1) if checked else 0.0,
        "critical_verified": sum(1 for f in verified if f.severity in ("critical", "high")),
        "mean_verified_risk": round(sum(f.risk_score for f in verified) / len(verified), 1) if verified else 0.0,
    }


def _finding_lines(f, lines: list[str]) -> None:
    lines += [
        f"### [{f.risk_score:.0f}] {f.title} ({f.severity})",
        "",
        f"- Target: {f.endpoint or f.target}",
        f"- Reported by: {', '.join(f.sources)}",
    ]
    if f.cwe:
        lines.append(f"- CWE: {f.cwe}")
    lines.append(f"- Evidence: {f.verification.get('detail', '')}")
    if f.triage:
        lines += [
            f"- OWASP: {f.triage.get('owasp', '')}",
            f"- Why it matters: {f.triage.get('business_impact', '')}",
            f"- Fix: {f.triage.get('remediation', '')}",
            f"- Priority: {f.triage.get('priority', '')} (exploitability {f.triage.get('exploitability', '?')}/10), "
            f"fix effort {f.triage.get('effort', '')}, SLA {f.triage.get('sla_days', '')} days",
        ]
    lines.append("")


def markdown_report(store: FindingStore) -> str:
    m = summary_metrics(store)
    by = m["by_status"]
    lines = [
        "# Aegis Security Verification Report",
        "",
        "## Executive summary",
        "",
        f"- Findings ingested (after cross-tool deduplication): {m['total']}",
        f"- Proven real (verified): {by.get('verified', 0)} ({m['critical_verified']} critical or high)",
        f"- Scanner noise eliminated (refuted, with evidence): {by.get('refuted', 0)} "
        f"({m['noise_reduction_pct']}% of everything checked)",
        f"- Automatic decision coverage: {m['coverage_pct']}% of checked findings decided without a human",
        f"- Inconclusive (human review queue): {by.get('inconclusive', 0)}",
        f"- Not yet checked: {by.get('new', 0)}",
        "",
        "Every status below was decided by a deterministic check, not by a scanner's "
        "say-so and not by the AI. The AI's role is the triage text: impact and fix.",
        "",
        "## Verified findings (proven, fix these first)",
        "",
    ]
    verified = store.list(status="verified")
    if not verified:
        lines.append("None.")
    for f in verified:
        _finding_lines(f, lines)
    lines += ["## Refuted findings (scanner noise, removed with evidence)", ""]
    refuted = store.list(status="refuted")
    if not refuted:
        lines.append("None.")
    for f in refuted:
        lines.append(f"- {f.title} on {f.endpoint or f.target}: {f.verification.get('detail', '')}")
    lines += ["", "## Inconclusive (could not be decided automatically)", ""]
    inconclusive = store.list(status="inconclusive")
    if not inconclusive:
        lines.append("None.")
    for f in inconclusive:
        lines.append(f"- {f.title} on {f.endpoint or f.target}: {f.verification.get('detail', '')}")
    lines.append("")
    return "\n".join(lines)


def json_report(store: FindingStore) -> str:
    from datetime import datetime, timezone

    payload = {
        "tool": "aegis",
        "schema": "aegis.report/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary_metrics(store),
        "findings": [f.to_dict() for f in store.list()],
    }
    return json.dumps(payload, indent=1)


def html_report(store: FindingStore) -> str:
    m = summary_metrics(store)
    by = m["by_status"]
    chip = {"verified": "#b3261e", "refuted": "#2e7d32", "inconclusive": "#b26a00", "new": "#5f6368"}

    def rows(findings) -> str:
        out = []
        for f in findings:
            out.append(
                f"<tr><td><b>{f.risk_score:.0f}</b></td><td>{html.escape(f.title)}</td>"
                f"<td>{html.escape(f.severity)}</td>"
                f"<td><span class='chip' style='background:{chip.get(f.status, '#666')}'>{f.status}</span></td>"
                f"<td>{html.escape(f.triage.get('priority', ''))}</td>"
                f"<td class='mono'>{html.escape((f.endpoint or f.target)[:70])}</td>"
                f"<td>{html.escape(f.verification.get('detail', ''))}</td></tr>"
            )
        return "".join(out) or "<tr><td colspan='7'>None</td></tr>"

    detail_blocks = []
    for f in store.list(status="verified"):
        detail_blocks.append(
            f"<div class='finding'><h3>[{f.risk_score:.0f}] {html.escape(f.title)} "
            f"<small>({html.escape(f.severity)})</small></h3>"
            f"<p class='mono'>{html.escape(f.endpoint or f.target)}</p>"
            f"<p><b>Evidence:</b> {html.escape(f.verification.get('detail', ''))}</p>"
            f"<p><b>Why it matters:</b> {html.escape(f.triage.get('business_impact', ''))}</p>"
            f"<p><b>Fix:</b> {html.escape(f.triage.get('remediation', ''))}</p>"
            f"<p><b>Priority:</b> {html.escape(f.triage.get('priority', ''))} | "
            f"<b>OWASP:</b> {html.escape(f.triage.get('owasp', ''))} | "
            f"<b>Effort:</b> {html.escape(f.triage.get('effort', ''))} | "
            f"<b>SLA:</b> {f.triage.get('sla_days', '')} days</p></div>"
        )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis Security Verification Report</title>
<style>body{{font-family:system-ui;margin:0;padding:32px;color:#1a1a2e;background:#fff}}
h1{{font-size:24px}} .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}}
.card{{border:1px solid #d0d4e0;border-radius:10px;padding:12px 18px;background:#f7f8fc}}
.card b{{font-size:24px;display:block}} table{{width:100%;border-collapse:collapse;margin-bottom:24px}}
td,th{{padding:7px 9px;border-bottom:1px solid #e2e4ec;text-align:left;font-size:13px}}
.chip{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px}} .mono{{font-family:monospace}}
.finding{{border:1px solid #d0d4e0;border-radius:10px;padding:14px 18px;margin-bottom:12px;background:#fbfbfe}}
@media print{{body{{padding:0}} .finding{{break-inside:avoid}}}}
@media (max-width:700px){{body{{padding:14px}}}}</style></head><body>
<h1>Aegis Security Verification Report</h1>
<p>Statuses were decided by deterministic verification checks. The AI layer wrote triage text only.</p>
<div class="cards">
<div class="card"><b>{m['total']}</b>findings</div>
<div class="card"><b>{by.get('verified', 0)}</b>verified</div>
<div class="card"><b>{by.get('refuted', 0)}</b>refuted</div>
<div class="card"><b>{m['noise_reduction_pct']}%</b>noise eliminated</div>
<div class="card"><b>{m['coverage_pct']}%</b>decided automatically</div>
<div class="card"><b>{by.get('inconclusive', 0)}</b>need human review</div></div>
<h2>All findings</h2>
<table><tr><th>Risk</th><th>Finding</th><th>Severity</th><th>Status</th><th>Priority</th><th>Target</th><th>Evidence</th></tr>
{rows(store.list())}</table>
<h2>Verified findings in detail</h2>
{''.join(detail_blocks) or '<p>None</p>'}
</body></html>"""
