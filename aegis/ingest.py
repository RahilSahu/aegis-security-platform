"""Scanner output parsers: Nuclei, OWASP ZAP, generic JSON and CSV.

Each parser produces Finding objects in the unified schema. Format
detection is by content shape, not filename, so exports can be fed
in any order.
"""

from __future__ import annotations

import csv
import io
import json

from .models import Finding, classify


def _finding(**kw) -> Finding:
    kw.setdefault("vuln_class", classify(kw.get("title", ""), kw.get("description", "")))
    return Finding(**kw)


def parse_nuclei(text: str) -> list[Finding]:
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue  # one corrupt line must not kill a 10k-line scan export
        info = item.get("info", {})
        target = item.get("host") or item.get("matched-at") or ""
        findings.append(
            _finding(
                title=info.get("name") or item.get("template-id", "Nuclei finding"),
                severity=info.get("severity", "info"),
                target=target,
                endpoint=item.get("matched-at", ""),
                description=info.get("description", ""),
                cwe=((info.get("classification") or {}).get("cwe-id") or [""])[0]
                if isinstance((info.get("classification") or {}).get("cwe-id"), list)
                else (info.get("classification") or {}).get("cwe-id", ""),
                sources=["nuclei"],
                raw_evidence={"template_id": item.get("template-id"), "matcher": item.get("matcher-name")},
            )
        )
    return findings


def parse_zap(text: str) -> list[Finding]:
    data = json.loads(text)
    findings = []
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in data.get("site", []):
        target = site.get("@name", "")
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])
            endpoint = instances[0].get("uri", target) if instances else target
            findings.append(
                _finding(
                    title=alert.get("name", "ZAP alert"),
                    severity=risk.get(str(alert.get("riskcode", "0")), "info"),
                    target=target,
                    endpoint=endpoint,
                    description=alert.get("desc", ""),
                    cwe=f"CWE-{alert.get('cweid')}"
                    if str(alert.get("cweid") or "") not in ("", "-1")
                    else "",  # ZAP uses cweid -1 for "no CWE", which is not CWE--1
                    sources=["zap"],
                    raw_evidence={"instances": len(instances), "solution": alert.get("solution", "")},
                )
            )
    return findings


def parse_burp(text: str) -> list[Finding]:
    """Burp Suite issue export (XML). Burp base64-encodes some fields
    in real exports; plain exports are handled, base64 fields are
    detected and decoded when they decode cleanly as UTF-8."""
    import base64
    import xml.etree.ElementTree as ET

    def field(issue, tag: str) -> str:
        el = issue.find(tag)
        if el is None or el.text is None:
            return ""
        value = el.text.strip()
        if el.get("base64") == "true":
            try:
                return base64.b64decode(value).decode("utf-8", errors="replace")
            except Exception:
                return value
        return value

    root = ET.fromstring(text)
    findings = []
    for issue in root.iter("issue"):
        host_el = issue.find("host")
        host = host_el.text.strip() if host_el is not None and host_el.text else ""
        path = field(issue, "path")
        findings.append(
            _finding(
                title=field(issue, "name") or "Burp issue",
                severity=field(issue, "severity") or "info",
                target=host,
                endpoint=(host + path) if host else path,
                description=field(issue, "issueDetail") or field(issue, "issueBackground"),
                sources=["burp"],
                raw_evidence={"confidence": field(issue, "confidence")},
            )
        )
    return findings


def parse_generic(text: str) -> list[Finding]:
    """A list of objects with title/severity/target fields (any naming
    close to: title|name, severity|risk, target|url|host)."""
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or [data]
    findings = []
    for item in data:
        target = item.get("target") or item.get("url") or item.get("host") or ""
        findings.append(
            _finding(
                title=item.get("title") or item.get("name") or "Finding",
                severity=item.get("severity") or item.get("risk") or "info",
                target=target,
                endpoint=item.get("endpoint") or item.get("url") or target,
                description=item.get("description", ""),
                cwe=item.get("cwe", ""),
                sources=[item.get("source", "generic")],
            )
        )
    return findings


def parse_csv(text: str) -> list[Finding]:
    findings = []
    for row in csv.DictReader(io.StringIO(text)):
        row = {(k or "").lower(): v for k, v in row.items()}
        target = row.get("target") or row.get("url") or row.get("host") or ""
        findings.append(
            _finding(
                title=row.get("title") or row.get("name") or "Finding",
                severity=row.get("severity") or row.get("risk") or "info",
                target=target,
                endpoint=row.get("endpoint") or target,
                description=row.get("description", ""),
                cwe=row.get("cwe", ""),
                sources=[row.get("source", "csv")],
            )
        )
    return findings


def parse(text: str, fmt: str = "auto") -> list[Finding]:
    """Parse scanner output, auto-detecting the format when asked."""
    if fmt == "nuclei":
        return parse_nuclei(text)
    if fmt == "zap":
        return parse_zap(text)
    if fmt == "burp":
        return parse_burp(text)
    if fmt == "csv":
        return parse_csv(text)
    if fmt == "generic":
        return parse_generic(text)
    stripped = text.lstrip()
    if stripped.startswith("<") and "<issues" in stripped[:2000]:
        return parse_burp(text)
    if stripped.startswith("{") and '"site"' in stripped[:2000]:
        return parse_zap(text)
    if stripped.startswith("{") and '"template-id"' in stripped[:2000]:
        return parse_nuclei(text)
    if stripped.startswith(("{", "[")):
        return parse_generic(text)
    if "," in stripped.splitlines()[0] and "severity" in stripped.splitlines()[0].lower():
        return parse_csv(text)
    # Last resort: line-delimited JSON is probably Nuclei.
    return parse_nuclei(text)
