"""Deterministic, non-destructive verifiers.

This is the layer that turns scanner claims into evidence. Every
verifier makes only safe, read-only checks: a GET request, a header
inspection, a certificate read, a token decode. No payloads, no
exploitation, nothing that changes state on the target. Run them
only against systems you own or are authorised to test.

A verifier returns verified (the problem is really there), refuted
(it is not, whatever the scanner said) or inconclusive (the check
could not decide, stated honestly). Only verifiers may set a
finding's verification status.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import Finding
from .store import FindingStore

EVIL_ORIGIN = "https://attacker.example"
_UA = {"User-Agent": "AegisVerifier/1.0 (authorised security verification)"}


def _url(finding: Finding) -> str:
    url = finding.endpoint or finding.target
    if "://" not in url:
        url = "http://" + url
    return url


def _blocked(url: str) -> str | None:
    """SSRF guard. Aegis fetches whatever URLs a scanner export
    contains, and a crafted export is an attack: a finding pointed at
    a cloud metadata endpoint would make the verifier fetch it.
    Link-local and metadata targets are therefore refused unless the
    operator explicitly opts in with AEGIS_ALLOW_METADATA=1. Internal
    RFC1918 and loopback targets are normal for authorised testing
    and are not blocked."""
    if os.environ.get("AEGIS_ALLOW_METADATA") == "1":
        return None
    host = (urlparse(url).hostname or "").lower()
    if host in ("metadata.google.internal", "metadata"):
        return f"blocked by SSRF guard: {host} is a cloud metadata endpoint"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.is_link_local:
        return f"blocked by SSRF guard: {host} is a link-local address (cloud metadata range)"
    return None


def _get(url: str, headers: dict | None = None, timeout: float = 8.0):
    """GET that returns error responses instead of raising on them:
    a 404 page still carries real headers worth judging. Connection
    failures get one retry (verification runs against real networks,
    and a single dropped packet should not mark a finding
    inconclusive)."""
    req = urllib.request.Request(url, headers={**_UA, **(headers or {})}, method="GET")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as err:
            return err
        except Exception as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(0.3)
    raise last_exc  # type: ignore[misc]


def _result(status: str, detail: str, evidence: dict | None = None) -> dict:
    return {"status": status, "detail": detail, "evidence": evidence or {}, "checked_at": time.time()}


def verify_security_headers(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    url = _url(finding)
    try:
        resp = _get(url, timeout=timeout)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        return _result("inconclusive", f"could not fetch {url}: {exc}")
    required = ["content-security-policy", "x-content-type-options", "referrer-policy"]
    if url.startswith("https://"):
        required.append("strict-transport-security")
    missing = [h for h in required if h not in headers]
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        missing.append("x-frame-options")
    if missing:
        return _result("verified", f"missing headers: {', '.join(missing)}", {"missing": missing})
    return _result("refuted", "all core security headers are present", {"present": required})


def verify_cors(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    url = _url(finding)
    try:
        resp = _get(url, headers={"Origin": EVIL_ORIGIN}, timeout=timeout)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
    except Exception as exc:
        return _result("inconclusive", f"could not fetch {url}: {exc}")
    if acao == EVIL_ORIGIN:
        return _result("verified", "origin is reflected", {"acao": acao, "acac": acac})
    if acao == "*" and (acac or "").lower() == "true":
        return _result("verified", "wildcard origin sent with credentials flag", {"acao": acao, "acac": acac})
    if acao is None:
        return _result("refuted", "no Access-Control-Allow-Origin header returned", {})
    return _result("refuted", f"fixed allow-origin ({acao}), attacker origin not trusted", {"acao": acao})


def verify_cookie_flags(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    url = _url(finding)
    try:
        resp = _get(url, timeout=timeout)
        cookies = resp.headers.get_all("Set-Cookie") or []
    except Exception as exc:
        return _result("inconclusive", f"could not fetch {url}: {exc}")
    if not cookies:
        return _result("inconclusive", "no cookies set by this response, cannot judge flags", {})
    problems = []
    for cookie in cookies:
        low = cookie.lower()
        name = cookie.split("=", 1)[0]
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if url.startswith("https://") and "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            problems.append({"cookie": name, "missing": missing})
    if problems:
        return _result("verified", "cookies missing protective flags", {"problems": problems})
    return _result("refuted", "all observed cookies carry Secure/HttpOnly/SameSite", {})


def verify_info_disclosure(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    url = _url(finding)
    try:
        resp = _get(url, timeout=timeout)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        return _result("inconclusive", f"could not fetch {url}: {exc}")
    version_re = re.compile(r"\d+\.\d+")
    leaked = {k: v for k, v in headers.items() if k in ("server", "x-powered-by") and version_re.search(v)}
    if leaked:
        return _result("verified", "version numbers disclosed in headers", leaked)
    return _result("refuted", "no version numbers in Server or X-Powered-By headers", {})


def verify_jwt(finding: Finding, timeout: float = 8.0) -> dict:
    blob = json.dumps(finding.raw_evidence) + " " + finding.endpoint + " " + finding.description
    match = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", blob)
    if not match:
        return _result("inconclusive", "no token attached to this finding, nothing to decode", {})
    token = match.group(0)
    try:
        head_b64, payload_b64, signature = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(head_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
    except Exception as exc:
        return _result("inconclusive", f"token present but not decodable: {exc}")
    problems = []
    if str(header.get("alg", "")).lower() == "none" or signature == "":
        problems.append("unsigned or alg=none")
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        problems.append("token is expired but was still reported in use")
    if problems:
        return _result("verified", "; ".join(problems), {"alg": header.get("alg"), "problems": problems})
    return _result("refuted", "token uses a real algorithm and is not expired", {"alg": header.get("alg")})


def verify_tls(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    parsed = urlparse(_url(finding))
    host = parsed.hostname
    if not host:
        return _result("inconclusive", "no host to check", {})
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return _result("verified", f"certificate fails validation: {exc.verify_message}", {})
    except Exception as exc:
        return _result("inconclusive", f"could not complete TLS handshake with {host}:{port}: {exc}")
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (not_after - datetime.now(timezone.utc)).days
    evidence = {"not_after": cert["notAfter"], "days_remaining": days}
    if days < 0:
        return _result("verified", "certificate is expired", evidence)
    if days <= 14:
        return _result("verified", f"certificate expires in {days} days", evidence)
    return _result("refuted", f"certificate valid with {days} days remaining", evidence)


def _origin(finding: Finding) -> str:
    parsed = urlparse(_url(finding))
    return f"{parsed.scheme}://{parsed.netloc}"


def verify_sensitive_files(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    """Read-only probe of the two classic exposures: /.env and
    /.git/HEAD. Verified only on content markers, never on a bare
    200 (many apps return 200 for every path with a soft-404 page)."""
    origin = _origin(finding)
    probes = [
        ("/.env", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+")),
        ("/.git/HEAD", re.compile(r"^ref:\s+refs/")),
    ]
    exposed = []
    errors = 0
    for path, marker in probes:
        try:
            resp = _get(origin + path, timeout=timeout)
            body = resp.read(8192).decode("utf-8", errors="replace")
            if resp.getcode() == 200 and marker.search(body):
                exposed.append(path)
        except Exception:
            errors += 1
    if exposed:
        return _result("verified", f"sensitive file(s) publicly readable: {', '.join(exposed)}", {"exposed": exposed})
    if errors == len(probes):
        return _result("inconclusive", f"could not reach {origin}", {})
    return _result("refuted", "neither /.env nor /.git/HEAD is publicly readable", {})


def verify_directory_listing(finding: Finding, timeout: float = 8.0) -> dict:
    blocked = _blocked(_url(finding))
    if blocked:
        return _result("inconclusive", blocked, {})
    url = _url(finding)
    try:
        resp = _get(url, timeout=timeout)
        body = resp.read(16384).decode("utf-8", errors="replace")
    except Exception as exc:
        return _result("inconclusive", f"could not fetch {url}: {exc}")
    if re.search(r"<title>Index of /", body) or re.search(r"<h1>Index of /", body):
        return _result("verified", "directory listing is enabled (Index of page)", {})
    return _result("refuted", "no directory listing signature in the response", {})


VERIFIERS = {
    "security-headers": verify_security_headers,
    "cors": verify_cors,
    "cookie-flags": verify_cookie_flags,
    "info-disclosure": verify_info_disclosure,
    "jwt": verify_jwt,
    "tls": verify_tls,
    "sensitive-files": verify_sensitive_files,
    "directory-listing": verify_directory_listing,
}


def run_verifications(store: FindingStore, timeout: float = 8.0, workers: int = 8) -> dict:
    """Verify every finding that has a verifier, concurrently.
    Returns counts. Verification is I/O-bound (one or two GETs per
    finding), so a thread pool takes a 500-finding backlog from
    minutes to seconds."""
    from concurrent.futures import ThreadPoolExecutor

    counts = {"verified": 0, "refuted": 0, "inconclusive": 0, "skipped": 0}
    jobs = []
    for finding in store.findings.values():
        verifier = VERIFIERS.get(finding.vuln_class)
        if verifier is None:
            counts["skipped"] += 1
        else:
            jobs.append((finding, verifier))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        outcomes = list(pool.map(lambda j: j[1](j[0], timeout=timeout), jobs))
    for (finding, _), outcome in zip(jobs, outcomes):
        finding.status = outcome["status"]
        finding.verification = {"verifier": finding.vuln_class, **outcome}
        finding.recompute_score()
        counts[outcome["status"]] += 1
    return counts
