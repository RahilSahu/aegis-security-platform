"""Reporting: the deliverable a security team actually sends.

The report leads with what was PROVEN, lists what was refuted (the
scanner noise Aegis removed, which is half the product's value), and
keeps inconclusive items visible instead of quietly dropping them.
"""

from __future__ import annotations

from .store import FindingStore


def markdown_report(store: FindingStore) -> str:
    stats = store.stats()
    by = stats["by_status"]
    lines = [
        "# Aegis Security Verification Report",
        "",
        f"Total findings ingested: {stats['total']} | "
        f"Verified: {by.get('verified', 0)} | Refuted: {by.get('refuted', 0)} | "
        f"Inconclusive: {by.get('inconclusive', 0)} | Not yet checked: {by.get('new', 0)}",
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
        lines += [
            f"### [{f.risk_score:.0f}] {f.title} ({f.severity})",
            "",
            f"- Target: {f.endpoint or f.target}",
            f"- Reported by: {', '.join(f.sources)}",
            f"- Evidence: {f.verification.get('detail', '')}",
        ]
        if f.triage:
            lines += [
                f"- Why it matters: {f.triage.get('business_impact', '')}",
                f"- Fix: {f.triage.get('remediation', '')}",
                f"- Priority: {f.triage.get('priority', '')} (exploitability {f.triage.get('exploitability', '?')}/10)",
            ]
        lines.append("")
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
