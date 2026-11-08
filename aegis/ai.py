"""AI triage: the advisory layer.

The model reads a finding plus its verification evidence and
produces what a senior analyst would write: how exploitable this
really is, what it means for the business, and how to fix it, in
developer-ready language.

Hard rule, enforced by the code layout: triage can only write to
finding.triage. It can never change finding.status or
finding.verification. Verification belongs to deterministic checks;
an LLM's confidence is not evidence.

With an API key (OPENAI_API_KEY, ANTHROPIC_API_KEY or GOOGLE_API_KEY)
the configured provider's model is used. Without one, a transparent
heuristic engine produces the same output shape, so the platform
works fully offline and the demo never depends on a key.
"""

from __future__ import annotations

import json
import os

from .models import Finding
from .store import FindingStore

CLASS_GUIDANCE = {
    "security-headers": {
        "impact": "Missing browser security headers weaken defence in depth: clickjacking, MIME sniffing and downgrade attacks get easier, though this alone rarely compromises data.",
        "remediation": "Add the missing headers at the edge (load balancer or framework middleware): Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy and frame-ancestors or X-Frame-Options. Roll CSP out in report-only mode first.",
        "exploitability": 3,
    },
    "cors": {
        "impact": "A reflected CORS policy with credentials lets any website read authenticated API responses from a victim's browser, which can mean full account data exposure.",
        "remediation": "Replace origin reflection with a strict allowlist of trusted origins. Never combine Access-Control-Allow-Origin reflection or wildcard with Access-Control-Allow-Credentials: true.",
        "exploitability": 8,
    },
    "cookie-flags": {
        "impact": "Cookies without HttpOnly are readable by any XSS payload; without Secure they can travel over plain HTTP; without SameSite they ride cross-site requests. Impact depends on what the cookie authorises.",
        "remediation": "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies at the framework or edge level, and re-issue existing sessions after the change.",
        "exploitability": 5,
    },
    "tls": {
        "impact": "Expired, mismatched or untrusted certificates train users to click through warnings and open the door to man-in-the-middle interception of everything the site carries.",
        "remediation": "Renew or replace the certificate, automate renewal (ACME), and add expiry alerting at 30, 14 and 7 days so this is caught before users see it.",
        "exploitability": 6,
    },
    "jwt": {
        "impact": "An unsigned or alg=none token means anyone can forge a session for any user, including administrators, with no secret at all.",
        "remediation": "Reject alg=none at the library level, pin the expected algorithm server-side, verify signatures with the correct key type, and enforce exp validation.",
        "exploitability": 9,
    },
    "sensitive-files": {
        "impact": "A publicly readable .env or .git directory hands attackers credentials, API keys and full source code: this is the first step of most real-world breaches, not a theoretical weakness.",
        "remediation": "Block /.env, /.git and other dotfiles at the server and CDN level, remove them from the web root, and rotate every secret the file contained, because it must be assumed compromised.",
        "exploitability": 9,
    },
    "directory-listing": {
        "impact": "Directory listings expose backup files, configs and upload folders that were never meant to be linked, giving attackers a map of everything unprotected on the server.",
        "remediation": "Disable autoindex / directory browsing at the server level and add an index file to sensitive folders as defence in depth.",
        "exploitability": 6,
    },
    "info-disclosure": {
        "impact": "Version banners hand attackers a shopping list: every disclosed version maps to known CVEs and exploit modules, cutting their reconnaissance time to minutes.",
        "remediation": "Suppress version tokens (server_tokens off, ServerTokens Prod, remove X-Powered-By) at the server and framework level.",
        "exploitability": 2,
    },
}


def detect_provider() -> str:
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("GOOGLE_API_KEY"):
        return "google"
    return "none"


def _priority(score: float) -> str:
    if score >= 80:
        return "P1"
    if score >= 55:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def heuristic_triage(finding: Finding) -> dict:
    guide = CLASS_GUIDANCE.get(finding.vuln_class, {
        "impact": "Impact depends on the affected asset and data; review with the owning team.",
        "remediation": "Fix per the scanner's guidance and the owning team's secure coding standards, then re-run verification.",
        "exploitability": 5,
    })
    exploitability = guide["exploitability"]
    if finding.status == "refuted":
        exploitability = 0
    elif finding.status == "verified":
        exploitability = min(exploitability + 1, 10)
    rationale = (
        f"Status is {finding.status}"
        + (f" ({finding.verification.get('detail')})" if finding.verification else "")
        + f"; reported by {', '.join(finding.sources) or 'one tool'}; severity {finding.severity}."
    )
    return {
        "engine": "heuristic",
        "exploitability": exploitability,
        "business_impact": guide["impact"],
        "remediation": guide["remediation"],
        "priority": _priority(finding.risk_score),
        "rationale": rationale,
    }


def _llm_triage(finding: Finding, provider: str) -> dict:
    from langchain_core.messages import HumanMessage

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        model = ChatOpenAI(model="gpt-4o-mini", temperature=0.1)
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        model = ChatAnthropic(model="claude-sonnet-4-5", temperature=0.1)
    else:
        from langchain_google_genai import ChatGoogleGenerativeAI

        model = ChatGoogleGenerativeAI(model="gemini-2.0-flash", temperature=0.1)

    prompt = (
        "You are a senior application security analyst triaging one verified-or-refuted scanner finding.\n"
        "Respond with ONLY a JSON object with keys: exploitability (0-10 integer), business_impact "
        "(2 sentences, plain business language), remediation (concrete developer steps), priority "
        "(P1-P4), rationale (one sentence citing the verification evidence).\n\n"
        f"Finding: {json.dumps(finding.to_dict(), default=str)}"
    )
    raw = model.invoke([HumanMessage(content=prompt)]).content
    data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
    return {"engine": f"llm:{provider}", **data}


def triage_finding(finding: Finding, provider: str | None = None) -> dict:
    provider = provider if provider is not None else detect_provider()
    if provider != "none":
        try:
            finding.triage = _llm_triage(finding, provider)
            return finding.triage
        except Exception:
            pass  # fall through to the heuristic engine, stated in the output
    finding.triage = heuristic_triage(finding)
    return finding.triage


def run_triages(store: FindingStore, provider: str | None = None) -> int:
    count = 0
    for finding in store.findings.values():
        triage_finding(finding, provider=provider)
        count += 1
    return count
