#!/usr/bin/env python3
"""
WebSecAudit - Automated Web Scanner for secure headers and CORS flaws
=====================================================================

IBM SkillsBuild National Cybersecurity Bootcamp
Project Topic: Automated Web Scanner - a Python script to audit sites for
secure headers and CORS flaws.

Author: Soumadeep Mondal

What it does
------------
For every target URL the scanner performs a small number of READ-ONLY HTTP
requests (GET / OPTIONS, no payloads, no fuzzing, no crawling) and audits:

  * Security response headers  - HSTS, CSP, clickjacking protection,
                                 X-Content-Type-Options, Referrer-Policy,
                                 Permissions-Policy, COOP/COEP/CORP,
                                 information-disclosure headers
  * Cookie attributes          - Secure, HttpOnly, SameSite, __Host-/__Secure-
  * Transport                  - plain-HTTP serving, HTTP -> HTTPS redirect
  * CORS configuration         - reflected origins, wildcard, null origin,
                                 prefix/suffix/subdomain/scheme validation
                                 bypasses, missing Vary: Origin, risky
                                 preflight answers

Findings carry a severity, evidence, remediation advice and a CWE id, and are
rolled up into a score and letter grade. Reports: console, JSON and a
self-contained HTML file.

Use it ONLY on systems you own or are explicitly authorised to test.

Exit codes: 0 ok | 1 findings at/above --fail-on | 2 bad input |
            3 authorisation not confirmed | 4 a target could not be scanned
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from requests.structures import CaseInsensitiveDict

__version__ = "1.0.0"
TOOL_NAME = "WebSecAudit"
USER_AGENT = f"{TOOL_NAME}/{__version__} (authorized security audit; read-only checks)"

# An origin that is syntactically valid but can never belong to the target.
EVIL_ORIGIN = "https://evil-attacker.example"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES), start=1)}  # info=1 .. critical=5
SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}

# Reference links (kept short and stable).
REF_HSTS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
REF_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
REF_XFO = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
REF_XCTO = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
REF_REFERRER = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
REF_PERMS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
REF_COOKIE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
REF_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
REF_PORTSWIGGER_CORS = "https://portswigger.net/web-security/cors"
REF_OWASP_HEADERS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    check_id: str
    category: str          # headers | cookies | transport | cors | scope
    title: str
    severity: str          # critical | high | medium | low | info
    description: str
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    cwe: str = ""


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status_code: Optional[int] = None
    scanned_at: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    requests_made: int = 0
    error: str = ""
    findings: List[Finding] = field(default_factory=list)
    passed: List[Dict[str, str]] = field(default_factory=list)
    score: int = 100
    grade: str = "A"

    def counts(self) -> Dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c


class Audit:
    """Collects findings and passed checks for one target."""

    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.passed: List[Dict[str, str]] = []

    def add(self, check_id: str, category: str, title: str, severity: str,
            description: str, evidence: str = "", remediation: str = "",
            reference: str = "", cwe: str = "") -> None:
        assert severity in SEVERITY_RANK, severity
        self.findings.append(Finding(check_id, category, title, severity,
                                     description, evidence, remediation,
                                     reference, cwe))

    def ok(self, check_id: str, text: str) -> None:
        self.passed.append({"id": check_id, "description": text})

    def has(self, check_id: str) -> bool:
        return any(f.check_id == check_id for f in self.findings)


@dataclass
class Resp:
    """The few bits of an HTTP response the checks need."""
    url: str
    status: int
    headers: CaseInsensitiveDict
    set_cookies: List[str] = field(default_factory=list)

    REDIRECTS = (301, 302, 303, 307, 308)

    @property
    def redirect_location(self) -> Optional[str]:
        if self.status in self.REDIRECTS:
            return self.headers.get("Location")
        return None


# --------------------------------------------------------------------------- #
# HTTP client (polite: delay between requests, bounded redirects, no bodies)
# --------------------------------------------------------------------------- #
class Client:
    def __init__(self, timeout: float = 10.0, delay: float = 0.5,
                 verify: bool = True, max_redirects: int = 5) -> None:
        self.timeout = timeout
        self.delay = delay
        self.verify = verify
        self.max_redirects = max_redirects
        self.request_count = 0
        self._last = 0.0

    def request(self, method: str, url: str,
                headers: Optional[Dict[str, str]] = None) -> Resp:
        if self.request_count:
            wait = self.delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        r = requests.request(method, url, headers=hdrs, timeout=self.timeout,
                             verify=self.verify, allow_redirects=False,
                             stream=True)  # stream: we only want headers
        try:
            raw = getattr(r.raw, "headers", None)
            cookies = list(raw.getlist("Set-Cookie")) if raw is not None and hasattr(raw, "getlist") else []
            resp = Resp(url=url, status=r.status_code,
                        headers=CaseInsensitiveDict(r.headers), set_cookies=cookies)
        finally:
            r.close()
        self._last = time.monotonic()
        self.request_count += 1
        return resp

    def fetch(self, url: str) -> List[Resp]:
        """GET url, following redirects manually (so every hop is visible)."""
        hops: List[Resp] = []
        current = url
        for _ in range(self.max_redirects + 1):
            resp = self.request("GET", current)
            hops.append(resp)
            loc = resp.redirect_location
            if not loc:
                return hops
            current = urljoin(current, loc)
        raise requests.exceptions.TooManyRedirects(
            f"more than {self.max_redirects} redirects")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def normalize_target(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError(f"not a valid http(s) URL: {raw!r}")
    return raw


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_loopback(host: Optional[str]) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def parse_csp(value: str) -> Dict[str, List[str]]:
    """'a b; c d' -> {'a': ['b'], 'c': ['d']} (first occurrence of a directive wins)."""
    out: Dict[str, List[str]] = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            out.setdefault(bits[0].lower(), bits[1:])
    return out


def parse_set_cookie(raw: str) -> Tuple[str, Dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: Dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip():
            attrs[k.strip().lower()] = v.strip()
    return name, attrs


SESSION_COOKIE_RE = re.compile(r"(sess|sid|auth|token|jwt|login|remember)", re.I)


# --------------------------------------------------------------------------- #
# Check group 1: security response headers
# --------------------------------------------------------------------------- #
def analyze_headers(a: Audit, resp: Resp, is_https: bool, loopback: bool) -> None:
    h = resp.headers
    csp_value = h.get("Content-Security-Policy")
    csp = parse_csp(csp_value) if csp_value else {}
    _check_hsts(a, h, is_https, loopback)
    _check_csp(a, h, csp)
    _check_clickjacking(a, h, csp)
    _check_nosniff(a, h)
    _check_referrer(a, h)
    _check_permissions_policy(a, h)
    _check_cross_origin_isolation(a, h)
    _check_disclosure(a, h)


def _check_hsts(a: Audit, h, is_https: bool, loopback: bool) -> None:
    if not is_https or loopback:
        return  # HSTS is only honoured over HTTPS; plain HTTP is reported under transport
    v = h.get("Strict-Transport-Security")
    if v is None:
        a.add("HDR-HSTS-MISSING", "headers", "Strict-Transport-Security (HSTS) missing", "medium",
              "Without HSTS browsers will still attempt plain HTTP first, which lets a "
              "network attacker strip TLS (SSL-stripping) on the first visit.",
              evidence="Header not present in the response.",
              remediation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
              reference=REF_HSTS, cwe="CWE-319")
        return
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    if not m:
        a.add("HDR-HSTS-INVALID", "headers", "HSTS header has no valid max-age", "medium",
              "The header is ignored by browsers unless it contains max-age.",
              evidence=f"Strict-Transport-Security: {v}",
              remediation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
              reference=REF_HSTS, cwe="CWE-319")
        return
    age = int(m.group(1))
    if age == 0:
        a.add("HDR-HSTS-DISABLED", "headers", "HSTS explicitly disabled (max-age=0)", "medium",
              "max-age=0 tells browsers to forget the HSTS policy.",
              evidence=f"Strict-Transport-Security: {v}",
              remediation="Use at least max-age=15552000 (180 days); 31536000 recommended.",
              reference=REF_HSTS, cwe="CWE-319")
    elif age < 15552000:
        a.add("HDR-HSTS-SHORT", "headers", "HSTS max-age is short", "low",
              f"max-age={age}s is under 180 days, so the protection window is short.",
              evidence=f"Strict-Transport-Security: {v}",
              remediation="Raise max-age to at least 15552000 (180 days); 31536000 recommended.",
              reference=REF_HSTS, cwe="CWE-319")
    else:
        a.ok("HDR-HSTS", f"HSTS enabled (max-age={age})")
    if age > 0 and "includesubdomains" not in v.lower():
        a.add("HDR-HSTS-SUBDOMAINS", "headers", "HSTS does not cover subdomains", "info",
              "Without includeSubDomains, subdomains can still be reached over HTTP.",
              evidence=f"Strict-Transport-Security: {v}",
              remediation="Add includeSubDomains once all subdomains support HTTPS.",
              reference=REF_HSTS)


def _check_csp(a: Audit, h, csp: Dict[str, List[str]]) -> None:
    if not h.get("Content-Security-Policy"):
        if h.get("Content-Security-Policy-Report-Only"):
            a.add("HDR-CSP-REPORT-ONLY", "headers", "CSP is report-only (not enforced)", "low",
                  "Content-Security-Policy-Report-Only logs violations but does not block anything.",
                  evidence="Only Content-Security-Policy-Report-Only is present.",
                  remediation="Promote the policy to Content-Security-Policy once violations are resolved.",
                  reference=REF_CSP, cwe="CWE-693")
        else:
            a.add("HDR-CSP-MISSING", "headers", "Content-Security-Policy missing", "medium",
                  "CSP is the main defence-in-depth control against XSS and data injection.",
                  evidence="Header not present in the response.",
                  remediation="Start from: default-src 'self'; object-src 'none'; base-uri 'none'; "
                              "frame-ancestors 'none'  and tighten per page.",
                  reference=REF_CSP, cwe="CWE-693")
        return

    issues = 0
    script = csp.get("script-src", csp.get("default-src"))
    if script is None:
        issues += 1
        a.add("HDR-CSP-NO-SCRIPT-RESTRICTION", "headers", "CSP does not restrict scripts", "medium",
              "Neither script-src nor default-src is set, so any script source is allowed.",
              evidence=f"Content-Security-Policy: {h.get('Content-Security-Policy')}",
              remediation="Add script-src 'self' (plus nonces/hashes for inline code).",
              reference=REF_CSP, cwe="CWE-693")
    else:
        toks = [t.lower() for t in script]
        protected = "'strict-dynamic'" in toks or any(
            t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in toks)
        if "'unsafe-inline'" in toks and not protected:
            issues += 1
            a.add("HDR-CSP-UNSAFE-INLINE", "headers", "CSP allows 'unsafe-inline' scripts", "medium",
                  "Inline <script> and event handlers are allowed, which defeats most of CSP's XSS protection.",
                  evidence=f"script-src: {' '.join(script)}",
                  remediation="Remove 'unsafe-inline'; use nonces or hashes instead.",
                  reference=REF_CSP, cwe="CWE-693")
        if "'unsafe-eval'" in toks:
            issues += 1
            a.add("HDR-CSP-UNSAFE-EVAL", "headers", "CSP allows 'unsafe-eval'", "low",
                  "eval()/Function() style code execution is permitted.",
                  evidence=f"script-src: {' '.join(script)}",
                  remediation="Remove 'unsafe-eval' and refactor code that needs it.",
                  reference=REF_CSP, cwe="CWE-693")
        broad = [t for t in toks if t in ("*", "http:", "https:", "data:")]
        if broad:
            issues += 1
            a.add("HDR-CSP-BROAD-SOURCE", "headers", "CSP allows scripts from overly broad sources", "medium",
                  "Scheme-wide or wildcard script sources let an attacker load code from any host.",
                  evidence=f"script-src contains: {', '.join(broad)}",
                  remediation="List explicit trusted hosts or use nonces with 'strict-dynamic'.",
                  reference=REF_CSP, cwe="CWE-693")

    obj = csp.get("object-src", csp.get("default-src"))
    if obj is None or [t.lower() for t in obj] not in (["'none'"], ["'self'"]):
        issues += 1
        a.add("HDR-CSP-OBJECT-SRC", "headers", "CSP does not lock down object-src", "low",
              "Plugins (<object>/<embed>) are not restricted to 'none'.",
              evidence="object-src: " + (" ".join(obj) if obj else "(not set, no default-src fallback)"),
              remediation="Add object-src 'none'.", reference=REF_CSP, cwe="CWE-693")
    if "base-uri" not in csp:
        issues += 1
        a.add("HDR-CSP-BASE-URI", "headers", "CSP does not restrict base-uri", "low",
              "An injected <base> tag could redirect relative URLs; base-uri is not covered by default-src.",
              evidence="base-uri directive not present.",
              remediation="Add base-uri 'none' (or 'self').", reference=REF_CSP, cwe="CWE-693")
    if issues == 0:
        a.ok("HDR-CSP", "Content-Security-Policy present and free of common weaknesses")


def _check_clickjacking(a: Audit, h, csp: Dict[str, List[str]]) -> None:
    xfo = h.get("X-Frame-Options")
    fa = csp.get("frame-ancestors")
    if fa is not None:
        if "*" in fa:
            a.add("HDR-FRAME-ANCESTORS-ANY", "headers", "CSP frame-ancestors allows any site", "medium",
                  "Any website may embed this page in a frame (clickjacking).",
                  evidence=f"frame-ancestors {' '.join(fa)}",
                  remediation="Use frame-ancestors 'none' or 'self'.",
                  reference=REF_CSP, cwe="CWE-1021")
        else:
            a.ok("HDR-FRAMING", "Clickjacking protection via CSP frame-ancestors")
    elif xfo:
        v = xfo.strip().lower()
        if v in ("deny", "sameorigin"):
            a.ok("HDR-FRAMING", f"Clickjacking protection via X-Frame-Options: {xfo.strip()}")
        elif v.startswith("allow-from"):
            a.add("HDR-XFO-ALLOW-FROM", "headers", "X-Frame-Options uses obsolete ALLOW-FROM", "low",
                  "ALLOW-FROM is ignored by modern browsers, leaving the page frameable.",
                  evidence=f"X-Frame-Options: {xfo}",
                  remediation="Use CSP frame-ancestors instead.", reference=REF_XFO, cwe="CWE-1021")
        else:
            a.add("HDR-XFO-INVALID", "headers", "X-Frame-Options has an invalid value", "low",
                  "Only DENY and SAMEORIGIN are valid; other values are ignored.",
                  evidence=f"X-Frame-Options: {xfo}",
                  remediation="X-Frame-Options: DENY  (and CSP frame-ancestors 'none').",
                  reference=REF_XFO, cwe="CWE-1021")
    else:
        a.add("HDR-XFO-MISSING", "headers", "No clickjacking protection", "medium",
              "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed "
              "by any site (UI redressing / clickjacking).",
              evidence="X-Frame-Options and CSP frame-ancestors not present.",
              remediation="Content-Security-Policy: frame-ancestors 'none'  (or 'self'); "
                          "add X-Frame-Options: DENY for legacy browsers.",
              reference=REF_XFO, cwe="CWE-1021")


def _check_nosniff(a: Audit, h) -> None:
    v = h.get("X-Content-Type-Options")
    if v and v.strip().lower() == "nosniff":
        a.ok("HDR-XCTO", "X-Content-Type-Options: nosniff")
    else:
        a.add("HDR-XCTO-MISSING", "headers", "X-Content-Type-Options: nosniff missing", "low",
              "Browsers may MIME-sniff responses and execute content as a different type.",
              evidence=f"X-Content-Type-Options: {v}" if v else "Header not present in the response.",
              remediation="X-Content-Type-Options: nosniff", reference=REF_XCTO, cwe="CWE-693")


def _check_referrer(a: Audit, h) -> None:
    rp = h.get("Referrer-Policy")
    if not rp:
        a.add("HDR-REFERRER-MISSING", "headers", "Referrer-Policy missing", "low",
              "Without an explicit policy, referrer leakage depends on browser defaults.",
              evidence="Header not present in the response.",
              remediation="Referrer-Policy: strict-origin-when-cross-origin  (or no-referrer)",
              reference=REF_REFERRER, cwe="CWE-200")
        return
    last = rp.split(",")[-1].strip().lower()  # the last recognised token wins
    if last == "unsafe-url":
        a.add("HDR-REFERRER-UNSAFE", "headers", "Referrer-Policy leaks full URLs", "medium",
              "unsafe-url sends the full URL (path and query) to every destination, including over HTTP.",
              evidence=f"Referrer-Policy: {rp}",
              remediation="Referrer-Policy: strict-origin-when-cross-origin  (or no-referrer)",
              reference=REF_REFERRER, cwe="CWE-200")
    elif last == "no-referrer-when-downgrade":
        a.add("HDR-REFERRER-WEAK", "headers", "Referrer-Policy is weak", "low",
              "no-referrer-when-downgrade still leaks full URLs to other HTTPS sites.",
              evidence=f"Referrer-Policy: {rp}",
              remediation="Referrer-Policy: strict-origin-when-cross-origin  (or no-referrer)",
              reference=REF_REFERRER, cwe="CWE-200")
    else:
        a.ok("HDR-REFERRER", f"Referrer-Policy: {rp}")


def _check_permissions_policy(a: Audit, h) -> None:
    if h.get("Permissions-Policy"):
        a.ok("HDR-PERMISSIONS", "Permissions-Policy present")
    else:
        a.add("HDR-PERMISSIONS-MISSING", "headers", "Permissions-Policy missing", "low",
              "Powerful browser features (camera, microphone, geolocation...) are not explicitly restricted.",
              evidence="Header not present in the response.",
              remediation="Permissions-Policy: geolocation=(), camera=(), microphone=()",
              reference=REF_PERMS, cwe="CWE-693")


def _check_cross_origin_isolation(a: Audit, h) -> None:
    names = ["Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"]
    missing = [n for n in names if not h.get(n)]
    if missing:
        a.add("HDR-CROSS-ORIGIN-ISOLATION", "headers", "Cross-origin isolation headers not set", "info",
              "COOP/COEP/CORP mitigate cross-origin leaks (Spectre-style) and window handle abuse. "
              "They are recommended hardening rather than a vulnerability.",
              evidence="Missing: " + ", ".join(missing),
              remediation="Cross-Origin-Opener-Policy: same-origin; "
                          "Cross-Origin-Resource-Policy: same-origin (where compatible).",
              reference=REF_OWASP_HEADERS)
    else:
        a.ok("HDR-CROSS-ORIGIN-ISOLATION", "COOP, COEP and CORP all set")


def _check_disclosure(a: Audit, h) -> None:
    srv = h.get("Server")
    if srv and re.search(r"\d+\.\d+", srv):
        a.add("INFO-SERVER-VERSION", "headers", "Server header discloses a version", "low",
              "Version banners help attackers pick exploits for known vulnerabilities.",
              evidence=f"Server: {srv}",
              remediation="Strip the version (e.g. nginx: server_tokens off; Apache: ServerTokens Prod).",
              reference=REF_OWASP_HEADERS, cwe="CWE-200")
    elif srv:
        a.ok("INFO-SERVER", "Server header does not reveal a version")
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        v = h.get(name)
        if v:
            a.add("INFO-" + name.upper(), "headers", f"{name} header discloses technology", "low",
                  "Framework/runtime banners reveal the technology stack.",
                  evidence=f"{name}: {v}",
                  remediation=f"Remove the {name} header in the framework or reverse-proxy configuration.",
                  reference=REF_OWASP_HEADERS, cwe="CWE-200")
    xxp = h.get("X-XSS-Protection")
    if xxp and xxp.strip().startswith("1"):
        a.add("HDR-XXSS-LEGACY", "headers", "Legacy X-XSS-Protection filter enabled", "info",
              "The old XSS auditor is removed from modern browsers and could itself introduce "
              "side-channel issues in older ones.",
              evidence=f"X-XSS-Protection: {xxp}",
              remediation="Send X-XSS-Protection: 0 (or omit) and rely on a strict CSP.",
              reference=REF_OWASP_HEADERS)


# --------------------------------------------------------------------------- #
# Check group 2: cookies
# --------------------------------------------------------------------------- #
def analyze_cookies(a: Audit, set_cookies: List[str], is_https: bool, loopback: bool) -> None:
    seen = set()
    for raw in set_cookies:
        name, attrs = parse_set_cookie(raw)
        if not name or name in seen:
            continue
        seen.add(name)
        session_like = bool(SESSION_COOKIE_RE.search(name))
        shown = ", ".join(sorted(attrs)) or "(none)"
        ev = f"Cookie '{name}' (value redacted); attributes: {shown}"
        problems = 0

        if is_https and not loopback and "secure" not in attrs:
            problems += 1
            a.add(f"COOKIE-SECURE-{name}", "cookies", f"Cookie '{name}' missing Secure flag",
                  "medium" if session_like else "low",
                  "Without Secure the cookie can be sent over plain HTTP and sniffed.",
                  evidence=ev, remediation="Add the Secure attribute.",
                  reference=REF_COOKIE, cwe="CWE-614")
        if "httponly" not in attrs:
            problems += 1
            a.add(f"COOKIE-HTTPONLY-{name}", "cookies", f"Cookie '{name}' missing HttpOnly flag",
                  "medium" if session_like else "low",
                  "JavaScript can read the cookie, so any XSS can steal it.",
                  evidence=ev, remediation="Add the HttpOnly attribute.",
                  reference=REF_COOKIE, cwe="CWE-1004")
        ss = attrs.get("samesite", "").lower()
        if not ss:
            problems += 1
            a.add(f"COOKIE-SAMESITE-{name}", "cookies", f"Cookie '{name}' has no SameSite attribute", "low",
                  "Behaviour then depends on the browser default; explicit SameSite helps against CSRF.",
                  evidence=ev, remediation="Add SameSite=Lax (or Strict).",
                  reference=REF_COOKIE, cwe="CWE-1275")
        elif ss == "none" and "secure" not in attrs:
            problems += 1
            a.add(f"COOKIE-SAMESITE-NONE-{name}", "cookies",
                  f"Cookie '{name}' uses SameSite=None without Secure", "medium",
                  "Browsers reject SameSite=None cookies that are not Secure, and it exposes the "
                  "cookie to cross-site requests.",
                  evidence=ev, remediation="Add Secure, or use SameSite=Lax/Strict.",
                  reference=REF_COOKIE, cwe="CWE-1275")
        if name.startswith("__Host-") and not (
                "secure" in attrs and attrs.get("path") == "/" and "domain" not in attrs):
            problems += 1
            a.add(f"COOKIE-PREFIX-{name}", "cookies", f"Cookie '{name}' violates the __Host- prefix rules",
                  "low", "__Host- cookies must be Secure, have Path=/ and no Domain attribute.",
                  evidence=ev, remediation="Fix the attributes or drop the prefix.",
                  reference=REF_COOKIE, cwe="CWE-1275")
        elif name.startswith("__Secure-") and "secure" not in attrs:
            problems += 1
            a.add(f"COOKIE-PREFIX-{name}", "cookies", f"Cookie '{name}' violates the __Secure- prefix rules",
                  "low", "__Secure- cookies must carry the Secure attribute.",
                  evidence=ev, remediation="Add Secure or drop the prefix.",
                  reference=REF_COOKIE, cwe="CWE-1275")
        if problems == 0:
            a.ok(f"COOKIE-{name}", f"Cookie '{name}' has secure attributes")


# --------------------------------------------------------------------------- #
# Check group 3: transport
# --------------------------------------------------------------------------- #
def analyze_transport(a: Audit, client: Client, start_url: str, hops: List[Resp],
                      final: Resp, loopback: bool, check_redirect: bool) -> None:
    p0, pf = urlparse(start_url), urlparse(final.url)
    if loopback:
        if pf.scheme == "http":
            a.add("TLS-LOOPBACK-SKIPPED", "transport", "HTTPS checks skipped for loopback target", "info",
                  "HSTS, Secure-cookie and HTTP->HTTPS checks are not meaningful on localhost.",
                  evidence=f"Target host: {pf.hostname}")
        return
    if pf.scheme == "http":
        a.add("TLS-NO-HTTPS", "transport", "Page is served over unencrypted HTTP", "high",
              "Traffic (including cookies and credentials) can be read or modified by anyone on the path.",
              evidence=f"Final URL: {final.url}",
              remediation="Serve the site over HTTPS and redirect all HTTP traffic to it.",
              reference=REF_HSTS, cwe="CWE-319")
    elif p0.scheme == "http":
        a.ok("TLS-REDIRECT", "HTTP request was redirected to HTTPS")

    if check_redirect and p0.scheme == "https" and p0.port in (None, 443):
        http_url = urlunparse(("http", p0.hostname, "/", "", "", ""))
        try:
            r = client.request("GET", http_url)
        except requests.RequestException:
            a.ok("TLS-HTTP-REDIRECT", "Plain-HTTP port 80 is not serving content")
            return
        loc = r.redirect_location
        if loc and urljoin(http_url, loc).startswith("https://"):
            a.ok("TLS-HTTP-REDIRECT", "http:// redirects to https://")
        elif loc:
            a.add("TLS-HTTP-REDIRECT-INSECURE", "transport", "HTTP redirects to another HTTP URL", "medium",
                  "The redirect from http:// does not upgrade the connection to HTTPS.",
                  evidence=f"GET {http_url} -> {r.status} Location: {loc}",
                  remediation="Redirect http:// requests straight to the https:// equivalent.",
                  reference=REF_HSTS, cwe="CWE-319")
        else:
            a.add("TLS-HTTP-NO-REDIRECT", "transport", "Site reachable over HTTP without redirect to HTTPS",
                  "medium",
                  "Users who type the bare hostname are served content in clear text.",
                  evidence=f"GET {http_url} -> {r.status} (no redirect)",
                  remediation="Redirect http:// requests to https:// and enable HSTS.",
                  reference=REF_HSTS, cwe="CWE-319")


# --------------------------------------------------------------------------- #
# Check group 4: CORS
# --------------------------------------------------------------------------- #
@dataclass
class CorsProbe:
    origin: str
    status: int
    acao: Optional[str]
    acac: bool
    vary: str

    @property
    def reflected(self) -> bool:
        return self.acao is not None and self.acao == self.origin


def _probe(client: Client, url: str, origin: str) -> CorsProbe:
    r = client.request("GET", url, headers={"Origin": origin})
    return CorsProbe(
        origin=origin, status=r.status, acao=r.headers.get("Access-Control-Allow-Origin"),
        acac=(r.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true",
        vary=r.headers.get("Vary", ""))


def analyze_cors(a: Audit, client: Client, url: str) -> None:
    p = urlparse(url)
    host, scheme = p.hostname or "", p.scheme
    hostport = host + (f":{p.port}" if p.port else "")
    dynamic = False  # True once we see the server derive ACAO from the request Origin

    # 1. Completely unrelated origin -------------------------------------------------
    ev = _probe(client, url, EVIL_ORIGIN)
    if ev.reflected:
        dynamic = True
        creds = ev.acac
        a.add("CORS-REFLECT-ORIGIN", "cors",
              "Arbitrary Origin is reflected" + (" WITH credentials" if creds else ""),
              "critical" if creds else "medium",
              "The server echoes whatever Origin it receives into Access-Control-Allow-Origin"
              + (" and allows credentials, so any website can make authenticated requests as the "
                 "victim and read the responses." if creds else
                 ". Any website can read responses; this becomes critical if the endpoint ever "
                 "relies on cookies, IP allow-lists or intranet position."),
              evidence=f"Origin: {EVIL_ORIGIN} -> Access-Control-Allow-Origin: {ev.acao}; "
                       f"Access-Control-Allow-Credentials: {'true' if creds else 'not set'}",
              remediation="Validate Origin against an exact allow-list of trusted origins and only "
                          "then echo it; never combine reflection with Allow-Credentials.",
              reference=REF_PORTSWIGGER_CORS, cwe="CWE-942")
    elif ev.acao == "*":
        a.add("CORS-WILDCARD", "cors",
              "Access-Control-Allow-Origin: * with credentials header" if ev.acac
              else "Access-Control-Allow-Origin is a wildcard",
              "medium" if ev.acac else "low",
              ("The wildcard is combined with Allow-Credentials: true. Browsers refuse this pairing, "
               "which signals a broken configuration that developers often 'fix' by reflecting the "
               "Origin." if ev.acac else
               "Any website can read responses from this URL. That is fine for fully public, "
               "unauthenticated data but wrong for anything user-specific."),
              evidence=f"Access-Control-Allow-Origin: * (Allow-Credentials: {'true' if ev.acac else 'not set'})",
              remediation="Replace * with an allow-list of origins unless the resource is intentionally public.",
              reference=REF_CORS, cwe="CWE-942")
    elif ev.acao is None:
        a.ok("CORS-ARBITRARY", "Unrelated origins are not granted CORS access")
    else:
        a.ok("CORS-ARBITRARY", f"ACAO is a fixed value ({ev.acao}), not reflected")

    # 2. Derived-origin probes (only meaningful if arbitrary origins are refused) ----
    if not ev.reflected:
        probes: List[Tuple[str, str]] = [("null", "null")]
        if not is_ip(host):
            probes.append(("prefix", f"{scheme}://{host}.evil-attacker.example"))
            probes.append(("suffix", f"{scheme}://evil{host}"))
            if not is_loopback(host):
                probes.append(("subdomain", f"{scheme}://attacker.{host}"))
        else:
            probes.append(("prefix", f"{scheme}://{host}.evil-attacker.example"))
        if scheme == "https":
            probes.append(("http-scheme", f"http://{hostport}"))

        bypass: List[CorsProbe] = []
        for kind, origin in probes:
            pr = _probe(client, url, origin)
            if not pr.reflected:
                continue
            dynamic = True
            if kind == "null":
                a.add("CORS-NULL-ORIGIN", "cors",
                      "Origin 'null' is trusted" + (" with credentials" if pr.acac else ""),
                      "high" if pr.acac else "low",
                      "Sandboxed iframes, data: URLs and local files send Origin: null, so an attacker "
                      "can trigger requests that the server will accept.",
                      evidence=f"Origin: null -> Access-Control-Allow-Origin: null; "
                               f"Allow-Credentials: {'true' if pr.acac else 'not set'}",
                      remediation="Never allow 'null' in the origin allow-list.",
                      reference=REF_PORTSWIGGER_CORS, cwe="CWE-942")
            elif kind in ("prefix", "suffix"):
                bypass.append(pr)
            elif kind == "subdomain":
                a.add("CORS-TRUSTS-SUBDOMAINS", "cors",
                      "Any subdomain is trusted" + (" with credentials" if pr.acac else ""),
                      "medium" if pr.acac else "low",
                      "A wildcard-subdomain trust means an XSS bug or subdomain takeover anywhere under "
                      "the domain exposes this API.",
                      evidence=f"Origin: {pr.origin} -> Access-Control-Allow-Origin: {pr.acao}",
                      remediation="Trust only the specific subdomains that need access.",
                      reference=REF_PORTSWIGGER_CORS, cwe="CWE-942")
            elif kind == "http-scheme":
                a.add("CORS-TRUSTS-HTTP-ORIGIN", "cors",
                      "Plain-HTTP origin is trusted by an HTTPS site" + (" with credentials" if pr.acac else ""),
                      "medium" if pr.acac else "low",
                      "A network attacker can serve a page over HTTP at this origin and read data "
                      "from the HTTPS API.",
                      evidence=f"Origin: {pr.origin} -> Access-Control-Allow-Origin: {pr.acao}",
                      remediation="Only allow https:// origins.",
                      reference=REF_PORTSWIGGER_CORS, cwe="CWE-942")
        if bypass:
            creds = any(b.acac for b in bypass)
            a.add("CORS-ORIGIN-VALIDATION-BYPASS", "cors",
                  "Origin validation can be bypassed" + (" (credentials allowed)" if creds else ""),
                  "high" if creds else "medium",
                  "Look-alike origins that merely start or end with the real hostname are accepted, "
                  "which indicates substring/prefix/suffix matching instead of exact comparison.",
                  evidence="; ".join(f"{b.origin} -> {b.acao}" for b in bypass),
                  remediation="Compare the full, parsed origin against an exact allow-list; avoid "
                              "startswith/endswith/regex shortcuts.",
                  reference=REF_PORTSWIGGER_CORS, cwe="CWE-942")

    # 3. Vary: Origin when ACAO is dynamic ------------------------------------------
    if dynamic:
        if "origin" not in ev.vary.lower():
            a.add("CORS-VARY-MISSING", "cors", "Dynamic CORS response lacks Vary: Origin", "low",
                  "Shared caches may serve one origin's CORS headers to another origin (cache poisoning "
                  "or intermittent breakage).",
                  evidence=f"Vary: {ev.vary or '(not set)'}",
                  remediation="Add 'Vary: Origin' whenever Access-Control-Allow-Origin depends on the request.",
                  reference=REF_CORS, cwe="CWE-942")
        else:
            a.ok("CORS-VARY", "Vary: Origin present on dynamic CORS responses")

    # 4. Preflight --------------------------------------------------------------------
    _check_preflight(a, client, url)


def _check_preflight(a: Audit, client: Client, url: str) -> None:
    r = client.request("OPTIONS", url, headers={
        "Origin": EVIL_ORIGIN,
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "authorization, x-audit-probe",
    })
    acao = r.headers.get("Access-Control-Allow-Origin")
    if acao not in ("*", EVIL_ORIGIN):
        a.ok("CORS-PREFLIGHT", "Preflight is not granted to an untrusted origin")
        return
    reflected = acao == EVIL_ORIGIN
    problems = 0

    methods = {m.strip().upper() for m in r.headers.get("Access-Control-Allow-Methods", "").split(",") if m.strip()}
    risky = sorted(methods & {"PUT", "DELETE", "PATCH"}) + (["*"] if "*" in methods else [])
    if risky:
        problems += 1
        a.add("CORS-PREFLIGHT-METHODS", "cors",
              "State-changing methods allowed cross-origin to an untrusted origin",
              "medium" if reflected else "low",
              "The preflight response approves methods that change server state for an origin that "
              "should not be trusted.",
              evidence=f"Access-Control-Allow-Methods: {r.headers.get('Access-Control-Allow-Methods')}",
              remediation="Allow only the methods the trusted front-end needs, and only for trusted origins.",
              reference=REF_CORS, cwe="CWE-942")

    ah = r.headers.get("Access-Control-Allow-Headers", "")
    if "*" in ah or "x-audit-probe" in ah.lower():
        problems += 1
        a.add("CORS-PREFLIGHT-HEADERS", "cors",
              "Preflight allows arbitrary request headers", "low",
              "A wildcard or echoed Allow-Headers lets untrusted origins send any custom header, "
              "e.g. Authorization.",
              evidence=f"Access-Control-Allow-Headers: {ah}",
              remediation="List the exact headers required.", reference=REF_CORS, cwe="CWE-942")

    ma = r.headers.get("Access-Control-Max-Age", "")
    if ma.isdigit() and int(ma) > 86400:
        a.add("CORS-PREFLIGHT-MAXAGE", "cors", "Very long preflight cache time", "info",
              "Policy changes take a long time to take effect (browsers cap the value anyway).",
              evidence=f"Access-Control-Max-Age: {ma}",
              remediation="Use 600-7200 seconds.", reference=REF_CORS)

    if (r.headers.get("Access-Control-Allow-Private-Network") or "").strip().lower() == "true":
        problems += 1
        a.add("CORS-PRIVATE-NETWORK", "cors", "Private Network Access granted to an untrusted origin", "medium",
              "Public websites could reach devices/services on the visitor's internal network through "
              "this endpoint.",
              evidence="Access-Control-Allow-Private-Network: true",
              remediation="Only send this header for explicitly trusted origins.",
              reference=REF_CORS, cwe="CWE-942")
    if problems == 0:
        a.ok("CORS-PREFLIGHT", "Preflight answer is permissive in origin only; methods/headers are tight")


# --------------------------------------------------------------------------- #
# Scoring and orchestration
# --------------------------------------------------------------------------- #
def compute_score(findings: List[Finding]) -> Tuple[int, str]:
    score = max(0, 100 - sum(SEVERITY_POINTS[f.severity] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 80 else
             "C" if score >= 65 else "D" if score >= 50 else "F")
    sevs = {f.severity for f in findings}
    if "critical" in sevs:
        grade = "F"
    elif "high" in sevs and grade in ("A", "B", "C"):
        grade = "D"
    return score, grade


def scan_target(client: Client, target: str, do_cors: bool = True,
                check_http_redirect: bool = True) -> ScanResult:
    res = ScanResult(target=target, scanned_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
    start_count = client.request_count
    a = Audit()
    try:
        hops = client.fetch(target)
    except requests.exceptions.SSLError as e:
        res.error = f"TLS error: {e.__class__.__name__} (use --insecure to skip certificate verification)"
        return res
    except requests.RequestException as e:
        res.error = f"{e.__class__.__name__}: {e}"
        return res

    final = hops[-1]
    res.final_url, res.status_code = final.url, final.status
    res.redirect_chain = [f"{h.status} {h.url}" for h in hops]
    pf = urlparse(final.url)
    is_https = pf.scheme == "https"
    loopback = is_loopback(pf.hostname)
    offsite = _strip_www(pf.hostname or "") != _strip_www(urlparse(target).hostname or "")

    analyze_transport(a, client, target, hops, final, loopback,
                      check_redirect=check_http_redirect and not offsite)
    analyze_headers(a, final, is_https, loopback)
    analyze_cookies(a, [c for hop in hops for c in hop.set_cookies], is_https, loopback)

    if offsite:
        a.add("SCOPE-OFFSITE-REDIRECT", "scope", "Target redirects to a different host", "info",
              "Active CORS probes were skipped because the final host may be outside the authorised scope.",
              evidence=f"{target} -> {final.url}",
              remediation="Scan the destination host directly if you are authorised to test it.")
    elif do_cors:
        try:
            analyze_cors(a, client, final.url)
        except requests.RequestException as e:
            a.add("CORS-ERROR", "cors", "CORS probes could not be completed", "info",
                  "A network error interrupted the CORS checks.", evidence=f"{e.__class__.__name__}: {e}")

    res.findings = sorted(a.findings, key=lambda f: -SEVERITY_RANK[f.severity])
    res.passed = a.passed
    res.score, res.grade = compute_score(res.findings)
    res.requests_made = client.request_count - start_count
    return res


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
ANSI = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[93m",
        "low": "\033[96m", "info": "\033[90m", "reset": "\033[0m", "bold": "\033[1m"}


def render_console(results: List[ScanResult], color: bool = False) -> str:
    def c(key: str, text: str) -> str:
        return f"{ANSI[key]}{text}{ANSI['reset']}" if color else text

    lines: List[str] = []
    for r in results:
        lines.append("=" * 78)
        lines.append(c("bold", f"Target : {r.target}"))
        if r.error:
            lines.append(f"ERROR  : {r.error}")
            continue
        lines.append(f"Final  : {r.final_url}   (HTTP {r.status_code}, {r.requests_made} requests)")
        counts = r.counts()
        lines.append(f"Grade  : {r.grade}   Score: {r.score}/100   " +
                     "  ".join(f"{k}={v}" for k, v in counts.items() if v))
        lines.append("-" * 78)
        if not r.findings:
            lines.append("No findings.")
        for f in r.findings:
            lines.append(f"[{c(f.severity, f.severity.upper())}] {f.title}  ({f.check_id})")
            lines.append(f"    {f.description}")
            if f.evidence:
                lines.append(f"    Evidence   : {f.evidence}")
            if f.remediation:
                lines.append(f"    Remediation: {f.remediation}")
            if f.cwe:
                lines.append(f"    CWE        : {f.cwe}")
            lines.append("")
        lines.append(f"Passed checks ({len(r.passed)}):")
        for p in r.passed:
            lines.append(f"  + {p['description']}")
    lines.append("=" * 78)
    if len(results) > 1:
        lines.append("Summary")
        for r in results:
            lines.append(f"  {r.grade:>1}  {r.score:>3}/100  {r.target}" + (f"   [{r.error}]" if r.error else ""))
    return "\n".join(lines)


def to_json(results: List[ScanResult]) -> str:
    payload = {
        "tool": TOOL_NAME, "version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "results": [asdict(r) | {"counts": r.counts()} for r in results],
    }
    return json.dumps(payload, indent=2)


_SEV_COLORS = {"critical": "#8b0000", "high": "#d62828", "medium": "#e07a00",
               "low": "#1f77b4", "info": "#6c757d"}
_GRADE_COLORS = {"A": "#1b8a3a", "B": "#5aa02c", "C": "#c9a100", "D": "#e07a00", "F": "#c1121f"}


def render_html(results: List[ScanResult]) -> str:
    e = html.escape  # every dynamic value is escaped: headers are attacker-controlled
    parts: List[str] = []
    parts.append(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f6f8;color:#1b1f23}}
main{{max-width:960px;margin:0 auto;padding:24px 16px 64px}}
h1{{margin:0 0 4px}} .muted{{color:#5b6670;font-size:.9rem}}
table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden}}
th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #e5e8eb;font-size:.92rem}}
th{{background:#1b2a41;color:#fff}}
.card{{background:#fff;border-radius:10px;padding:16px 18px;margin:20px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.grade{{display:inline-block;min-width:2.2em;text-align:center;color:#fff;border-radius:6px;padding:2px 8px;font-weight:700}}
.sev{{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:.75rem;font-weight:700;letter-spacing:.04em}}
.finding{{border-left:4px solid #ccc;padding:6px 12px;margin:14px 0;background:#fafbfc}}
code,.ev{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.84rem;word-break:break-all}}
.ev{{background:#eef1f4;padding:4px 6px;border-radius:4px;display:block;margin:4px 0}}
ul.pass{{margin:6px 0 0 18px;padding:0;font-size:.9rem;color:#2d5a3a}}
</style></head><body><main>
<h1>{TOOL_NAME} report</h1>
<div class="muted">Generated {e(dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))} &middot; v{__version__} &middot; read-only checks (GET/OPTIONS)</div>
<h2>Summary</h2>
<table><tr><th>Target</th><th>Grade</th><th>Score</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th></tr>""")
    for r in results:
        cn = r.counts()
        parts.append(
            f"<tr><td>{e(r.target)}</td>"
            f"<td><span class='grade' style='background:{_GRADE_COLORS.get(r.grade, '#555')}'>{e(r.grade)}</span></td>"
            f"<td>{r.score}/100</td><td>{cn['critical']}</td><td>{cn['high']}</td><td>{cn['medium']}</td>"
            f"<td>{cn['low']}</td><td>{cn['info']}</td></tr>")
    parts.append("</table>")
    for r in results:
        parts.append(f"<div class='card'><h2 style='margin-top:0'>{e(r.target)}</h2>")
        if r.error:
            parts.append(f"<p><b>Scan error:</b> {e(r.error)}</p></div>")
            continue
        parts.append(f"<div class='muted'>Final URL: <code>{e(r.final_url)}</code> &middot; HTTP {r.status_code} "
                     f"&middot; {r.requests_made} requests &middot; {e(r.scanned_at)}</div>")
        if len(r.redirect_chain) > 1:
            parts.append("<div class='muted'>Redirects: " + " &rarr; ".join(f"<code>{e(x)}</code>" for x in r.redirect_chain) + "</div>")
        if not r.findings:
            parts.append("<p>No findings.</p>")
        for f in r.findings:
            col = _SEV_COLORS[f.severity]
            parts.append(f"<div class='finding' style='border-left-color:{col}'>"
                         f"<span class='sev' style='background:{col}'>{e(f.severity.upper())}</span> "
                         f"<b>{e(f.title)}</b> <span class='muted'>{e(f.check_id)}"
                         f"{(' &middot; ' + e(f.cwe)) if f.cwe else ''}</span>"
                         f"<p>{e(f.description)}</p>")
            if f.evidence:
                parts.append(f"<span class='ev'>Evidence: {e(f.evidence)}</span>")
            if f.remediation:
                parts.append(f"<p><b>Fix:</b> {e(f.remediation)}</p>")
            if f.reference:
                parts.append(f"<p class='muted'>Reference: {e(f.reference)}</p>")
            parts.append("</div>")
        if r.passed:
            parts.append(f"<b>Passed checks ({len(r.passed)})</b><ul class='pass'>" +
                         "".join(f"<li>{e(p['description'])}</li>" for p in r.passed) + "</ul>")
        parts.append("</div>")
    parts.append("<p class='muted'>Automated results can contain false positives/negatives. "
                 "Review findings manually before acting on them.</p></main></body></html>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
BANNER = f"""{TOOL_NAME} v{__version__} - secure-header & CORS auditor
Only scan systems you own or have EXPLICIT written permission to test.
This tool sends a handful of read-only GET/OPTIONS requests per target."""


def confirm_authorization(targets: List[str], assume_yes: bool) -> bool:
    print(BANNER, file=sys.stderr)
    print("Targets: " + ", ".join(targets), file=sys.stderr)
    if assume_yes:
        print("Authorisation confirmed via --yes.", file=sys.stderr)
        return True
    if not sys.stdin.isatty():
        print("Non-interactive session: re-run with --yes to confirm you are authorised.", file=sys.stderr)
        return False
    ans = input("Do you have authorisation to test these targets? [y/N] ").strip().lower()
    return ans in ("y", "yes")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="web_security_scanner.py",
        description="Audit websites for missing security headers, weak cookie flags and CORS misconfiguration.",
        epilog="Use only on systems you are authorised to test.")
    ap.add_argument("targets", nargs="*", help="URL(s) or hostnames (https:// is assumed if no scheme)")
    ap.add_argument("-f", "--file", help="file with one target per line ('#' starts a comment)")
    ap.add_argument("--json", metavar="PATH", help="write a JSON report")
    ap.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds (default 10)")
    ap.add_argument("--delay", type=float, default=0.5, help="pause between requests in seconds (default 0.5)")
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    ap.add_argument("--skip-cors", action="store_true", help="only audit headers/cookies/transport")
    ap.add_argument("--no-http-redirect-check", action="store_true",
                    help="do not request http://host/ to test the HTTP->HTTPS redirect")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                    help="exit with code 1 if any finding is at or above this severity (for CI use)")
    ap.add_argument("--yes", action="store_true", help="confirm you are authorised to test the targets")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress the console report")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    raw = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                raw.extend(fh.read().splitlines())
        except OSError as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
    targets: List[str] = []
    for item in raw:
        try:
            t = normalize_target(item)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if t and t not in targets:
            targets.append(t)
    if not targets:
        print("error: no targets supplied (give URLs or use --file)", file=sys.stderr)
        return 2
    if not confirm_authorization(targets, args.yes):
        print("Aborted: authorisation not confirmed.", file=sys.stderr)
        return 3

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    client = Client(timeout=args.timeout, delay=args.delay, verify=not args.insecure)

    results: List[ScanResult] = []
    for t in targets:
        print(f"[*] scanning {t}", file=sys.stderr)
        results.append(scan_target(client, t, do_cors=not args.skip_cors,
                                   check_http_redirect=not args.no_http_redirect_check))

    if not args.quiet:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(render_console(results, color=use_color))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(results))
        print(f"[+] JSON report written to {args.json}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(results))
        print(f"[+] HTML report written to {args.html}", file=sys.stderr)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for r in results for f in r.findings):
            return 1
    if any(r.error for r in results):
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
