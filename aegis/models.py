"""The unified Finding model, cross-tool fingerprinting and scoring.

Every scanner describes the same problem differently. Aegis maps all
of them onto one schema and one fingerprint, so "Missing CSP" from
ZAP and "http-missing-security-headers" from Nuclei on the same URL
become a single finding with two sources, which is stronger evidence
than either alone.

Verification status can only be set by a deterministic verifier
(aegis/verify.py), never by the AI layer. That separation is the
core design rule of this platform: AI advises, evidence decides.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

SEVERITY_BASE = {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 10}
STATUS_MULTIPLIER = {"verified": 1.0, "new": 0.6, "inconclusive": 0.6, "refuted": 0.05}

# Map scanner wording onto Aegis vulnerability classes. The class is
# what verifiers key on, so it has to be normalised aggressively.
CLASS_PATTERNS: list[tuple[str, str]] = [
    (r"content[ -]security[ -]policy|missing.*(security )?headers|http-missing-security|\bcsp\b", "security-headers"),
    (r"cors|cross-origin", "cors"),
    (r"cookie|httponly|secure flag|samesite", "cookie-flags"),
    (r"tls|ssl|certificate|expir", "tls"),
    (r"jwt|json web token", "jwt"),
    (r"sensitive file|\.env|git (config|expos)|exposed.*(config|backup|\.git)|source code disclosure", "sensitive-files"),
    (r"directory listing|directory browsing|index of /", "directory-listing"),
    (r"version disclosure|server banner|x-powered-by|information disclosure|server leaks", "info-disclosure"),
]


def classify(title: str, description: str = "") -> str:
    text = f"{title} {description}".lower()
    for pattern, vuln_class in CLASS_PATTERNS:
        if re.search(pattern, text):
            return vuln_class
    return "other"


def _normalise_severity(value: str | None) -> str:
    value = (value or "info").lower()
    for name in SEVERITY_BASE:
        if value.startswith(name) or (name == "info" and value in ("informational", "informational/low")):
            return name
    return "info"


def fingerprint(vuln_class: str, target: str, endpoint: str) -> str:
    """Stable identity of an issue, independent of which tool saw it.

    Identity is class + host + port + normalised path. The port
    matters (an app on :8443 is not the app on :443), the scheme does
    not (http and https views of one app are one issue), numeric path
    segments are templated (/users/42 == /users/43), and a trailing
    slash never splits an issue in two."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = (parsed.hostname or target).lower()
    port = parsed.port
    if port is None and endpoint:
        port = urlparse(endpoint).port
    path = (urlparse(endpoint).path if endpoint else parsed.path) or "/"
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)  # /users/42 -> /users/{id}
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    raw = f"{vuln_class}|{host}|{port or ''}|{path}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


@dataclass
class Finding:
    title: str
    vuln_class: str
    severity: str
    target: str
    endpoint: str = ""
    description: str = ""
    cwe: str = ""
    sources: list[str] = field(default_factory=list)  # tools that reported it
    raw_evidence: dict = field(default_factory=dict)
    status: str = "new"  # new | verified | refuted | inconclusive
    verification: dict = field(default_factory=dict)  # verifier output + evidence
    triage: dict = field(default_factory=dict)  # AI or heuristic assessment
    risk_score: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = _normalise_severity(self.severity)
        if not self.id:
            self.id = fingerprint(self.vuln_class, self.target, self.endpoint)
        self.recompute_score()

    def merge(self, other: "Finding") -> None:
        """Fold a duplicate report of the same issue into this one."""
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        if SEVERITY_BASE[other.severity] > SEVERITY_BASE[self.severity]:
            self.severity = other.severity
        if not self.description and other.description:
            self.description = other.description
        if not self.cwe and other.cwe:
            self.cwe = other.cwe
        self.raw_evidence.setdefault("also_reported_as", []).append(other.title)
        self.recompute_score()

    def recompute_score(self) -> None:
        base = SEVERITY_BASE[self.severity]
        mult = STATUS_MULTIPLIER.get(self.status, 0.6)
        corroboration = 1.0 + min(0.1 * max(len(self.sources) - 1, 0), 0.3)
        self.risk_score = round(min(base * mult * corroboration, 100.0), 1)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(**data)
