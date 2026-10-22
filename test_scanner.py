#!/usr/bin/env python3
"""Unit + integration tests for WebSecAudit.  Run:  python3 -m unittest -v"""
import json
import os
import tempfile
import unittest
from io import StringIO
from contextlib import redirect_stderr, redirect_stdout

from requests.structures import CaseInsensitiveDict

import lab_servers
import web_security_scanner as ws


def resp(headers=None, cookies=None, status=200, url="https://example.test/"):
    return ws.Resp(url=url, status=status, headers=CaseInsensitiveDict(headers or {}),
                   set_cookies=cookies or [])


def ids(audit):
    return {f.check_id for f in audit.findings}


class HeaderTests(unittest.TestCase):
    def run_headers(self, headers, https=True, loopback=False):
        a = ws.Audit()
        ws.analyze_headers(a, resp(headers), https, loopback)
        return a

    def test_everything_missing(self):
        a = self.run_headers({})
        for expected in ("HDR-HSTS-MISSING", "HDR-CSP-MISSING", "HDR-XFO-MISSING",
                         "HDR-XCTO-MISSING", "HDR-REFERRER-MISSING", "HDR-PERMISSIONS-MISSING"):
            self.assertIn(expected, ids(a))

    def test_hsts_not_required_on_http_or_loopback(self):
        self.assertNotIn("HDR-HSTS-MISSING", ids(self.run_headers({}, https=False)))
        self.assertNotIn("HDR-HSTS-MISSING", ids(self.run_headers({}, loopback=True)))

    def test_hsts_variants(self):
        self.assertIn("HDR-HSTS-SHORT", ids(self.run_headers({"Strict-Transport-Security": "max-age=300"})))
        self.assertIn("HDR-HSTS-DISABLED", ids(self.run_headers({"Strict-Transport-Security": "max-age=0"})))
        self.assertIn("HDR-HSTS-INVALID", ids(self.run_headers({"Strict-Transport-Security": "includeSubDomains"})))
        good = self.run_headers({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
        self.assertFalse({"HDR-HSTS-SHORT", "HDR-HSTS-MISSING", "HDR-HSTS-SUBDOMAINS"} & ids(good))

    def test_csp_weaknesses(self):
        a = self.run_headers({"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"})
        self.assertTrue({"HDR-CSP-UNSAFE-INLINE", "HDR-CSP-UNSAFE-EVAL", "HDR-CSP-BROAD-SOURCE",
                         "HDR-CSP-OBJECT-SRC", "HDR-CSP-BASE-URI"} <= ids(a))

    def test_csp_unsafe_inline_ignored_when_nonce_present(self):
        a = self.run_headers({"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'"})
        self.assertNotIn("HDR-CSP-UNSAFE-INLINE", ids(a))

    def test_csp_without_script_restriction(self):
        a = self.run_headers({"Content-Security-Policy": "img-src 'self'"})
        self.assertIn("HDR-CSP-NO-SCRIPT-RESTRICTION", ids(a))

    def test_csp_report_only(self):
        a = self.run_headers({"Content-Security-Policy-Report-Only": "default-src 'self'"})
        self.assertIn("HDR-CSP-REPORT-ONLY", ids(a))
        self.assertNotIn("HDR-CSP-MISSING", ids(a))

    def test_clickjacking_accepts_either_control(self):
        self.assertNotIn("HDR-XFO-MISSING", ids(self.run_headers({"X-Frame-Options": "DENY"})))
        self.assertNotIn("HDR-XFO-MISSING", ids(self.run_headers(
            {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})))
        self.assertIn("HDR-XFO-ALLOW-FROM", ids(self.run_headers({"X-Frame-Options": "ALLOW-FROM https://x"})))
        self.assertIn("HDR-FRAME-ANCESTORS-ANY", ids(self.run_headers(
            {"Content-Security-Policy": "frame-ancestors *"})))

    def test_referrer_policy(self):
        self.assertIn("HDR-REFERRER-UNSAFE", ids(self.run_headers({"Referrer-Policy": "unsafe-url"})))
        self.assertIn("HDR-REFERRER-WEAK", ids(self.run_headers({"Referrer-Policy": "no-referrer-when-downgrade"})))
        a = self.run_headers({"Referrer-Policy": "no-referrer, strict-origin-when-cross-origin"})
        self.assertFalse({"HDR-REFERRER-UNSAFE", "HDR-REFERRER-WEAK", "HDR-REFERRER-MISSING"} & ids(a))

    def test_information_disclosure(self):
        a = self.run_headers({"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4"})
        self.assertIn("INFO-SERVER-VERSION", ids(a))
        self.assertIn("INFO-X-POWERED-BY", ids(a))
        self.assertNotIn("INFO-SERVER-VERSION", ids(self.run_headers({"Server": "nginx"})))

    def test_header_names_are_case_insensitive(self):
        a = self.run_headers({"x-content-type-options": "nosniff"})
        self.assertNotIn("HDR-XCTO-MISSING", ids(a))


class CookieTests(unittest.TestCase):
    def run_cookies(self, cookies, https=True, loopback=False):
        a = ws.Audit()
        ws.analyze_cookies(a, cookies, https, loopback)
        return a

    def test_bare_session_cookie(self):
        a = self.run_cookies(["sessionid=abc; Path=/"])
        self.assertTrue({"COOKIE-SECURE-sessionid", "COOKIE-HTTPONLY-sessionid",
                         "COOKIE-SAMESITE-sessionid"} <= ids(a))
        sev = {f.check_id: f.severity for f in a.findings}
        self.assertEqual(sev["COOKIE-SECURE-sessionid"], "medium")   # session-like name -> higher

    def test_non_session_cookie_is_low(self):
        a = self.run_cookies(["theme=dark"])
        self.assertEqual({f.severity for f in a.findings}, {"low"})

    def test_good_cookie(self):
        a = self.run_cookies(["__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Strict"])
        self.assertEqual(a.findings, [])
        self.assertEqual(len(a.passed), 1)

    def test_samesite_none_requires_secure(self):
        a = self.run_cookies(["sid=1; HttpOnly; SameSite=None"], https=False)
        self.assertIn("COOKIE-SAMESITE-NONE-sid", ids(a))

    def test_prefix_rules(self):
        a = self.run_cookies(["__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=/x"])
        self.assertIn("COOKIE-PREFIX-__Host-a", ids(a))
        b = self.run_cookies(["__Secure-b=1; HttpOnly; SameSite=Lax"], https=False)
        self.assertIn("COOKIE-PREFIX-__Secure-b", ids(b))

    def test_secure_flag_not_demanded_on_loopback_or_http(self):
        self.assertNotIn("COOKIE-SECURE-x", ids(self.run_cookies(["x=1; HttpOnly; SameSite=Lax"], loopback=True)))
        self.assertNotIn("COOKIE-SECURE-x", ids(self.run_cookies(["x=1; HttpOnly; SameSite=Lax"], https=False)))

    def test_duplicates_reported_once(self):
        a = self.run_cookies(["a=1", "a=2"])
        self.assertEqual(len([f for f in a.findings if f.check_id == "COOKIE-HTTPONLY-a"]), 1)


class HelperTests(unittest.TestCase):
    def test_normalize_target(self):
        self.assertEqual(ws.normalize_target("example.com"), "https://example.com")
        self.assertEqual(ws.normalize_target("http://x.test:8080/a"), "http://x.test:8080/a")
        self.assertIsNone(ws.normalize_target("   "))
        self.assertIsNone(ws.normalize_target("# comment"))
        with self.assertRaises(ValueError):
            ws.normalize_target("ftp://example.com")

    def test_parse_csp(self):
        self.assertEqual(ws.parse_csp("default-src 'self'; img-src a b ;"),
                         {"default-src": ["'self'"], "img-src": ["a", "b"]})

    def test_parse_set_cookie(self):
        name, attrs = ws.parse_set_cookie("id=1; Path=/; Secure; SameSite=Lax")
        self.assertEqual(name, "id")
        self.assertEqual(attrs, {"path": "/", "secure": "", "samesite": "Lax"})

    def test_loopback(self):
        for h in ("localhost", "127.0.0.1", "::1", "a.localhost"):
            self.assertTrue(ws.is_loopback(h), h)
        self.assertFalse(ws.is_loopback("example.com"))
        self.assertFalse(ws.is_loopback(None))

    def test_scoring(self):
        self.assertEqual(ws.compute_score([]), (100, "A"))
        crit = [ws.Finding("x", "cors", "t", "critical", "d")]
        self.assertEqual(ws.compute_score(crit)[1], "F")
        high = [ws.Finding("x", "cors", "t", "high", "d")]
        self.assertEqual(ws.compute_score(high), (75, "D"))   # high caps the grade at D
        infos = [ws.Finding("x", "h", "t", "info", "d")] * 20
        self.assertEqual(ws.compute_score(infos), (100, "A"))


class LabIntegrationTests(unittest.TestCase):
    """Scan the four local lab servers end to end."""

    @classmethod
    def setUpClass(cls):
        cls.servers, cls.urls = [], {}
        for mode in ("vulnerable", "weakcors", "wildcard", "hardened"):
            srv, port = lab_servers.start_server(mode)
            cls.servers.append(srv)
            cls.urls[mode] = f"http://localhost:{port}/"
        cls.client = ws.Client(timeout=5, delay=0)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def scan(self, mode, **kw):
        return ws.scan_target(self.client, self.urls[mode], **kw)

    def test_vulnerable_server(self):
        r = self.scan("vulnerable")
        found = {f.check_id: f for f in r.findings}
        self.assertEqual(found["CORS-REFLECT-ORIGIN"].severity, "critical")
        self.assertIn("CORS-VARY-MISSING", found)
        self.assertIn("CORS-PREFLIGHT-METHODS", found)
        self.assertIn("CORS-PREFLIGHT-HEADERS", found)
        self.assertIn("INFO-SERVER-VERSION", found)
        self.assertIn("COOKIE-HTTPONLY-sessionid", found)
        self.assertIn("HDR-CSP-UNSAFE-INLINE", found)
        self.assertEqual(r.grade, "F")
        self.assertLess(r.score, 10)

    def test_weak_origin_validation_detected(self):
        r = self.scan("weakcors")
        found = {f.check_id: f for f in r.findings}
        self.assertIn("CORS-ORIGIN-VALIDATION-BYPASS", found)
        self.assertEqual(found["CORS-ORIGIN-VALIDATION-BYPASS"].severity, "high")
        self.assertIn("CORS-NULL-ORIGIN", found)
        self.assertEqual(found["CORS-NULL-ORIGIN"].severity, "high")
        self.assertNotIn("CORS-REFLECT-ORIGIN", found)
        self.assertNotIn("CORS-VARY-MISSING", found)       # server sends Vary: Origin
        self.assertIn("COOKIE-SAMESITE-NONE-sid", found)

    def test_wildcard_detected(self):
        r = self.scan("wildcard")
        self.assertIn("CORS-WILDCARD", {f.check_id for f in r.findings})
        self.assertNotIn("CORS-REFLECT-ORIGIN", {f.check_id for f in r.findings})

    def test_hardened_server_has_no_medium_or_worse(self):
        r = self.scan("hardened")
        bad = [f for f in r.findings if ws.SEVERITY_RANK[f.severity] >= ws.SEVERITY_RANK["low"]]
        self.assertEqual(bad, [], [f.check_id for f in bad])
        self.assertGreaterEqual(r.score, 90)
        self.assertEqual(r.grade, "A")
        self.assertIn("CORS-ARBITRARY", {p["id"] for p in r.passed})

    def test_skip_cors(self):
        r = self.scan("vulnerable", do_cors=False)
        self.assertFalse([f for f in r.findings if f.category == "cors"])

    def test_requests_are_bounded_and_read_only(self):
        r = self.scan("vulnerable")
        self.assertLessEqual(r.requests_made, 12)

    def test_unreachable_target_reports_error(self):
        r = ws.scan_target(self.client, "http://127.0.0.1:9/")
        self.assertTrue(r.error)
        self.assertEqual(r.findings, [])


class ReportAndCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        srv, port = lab_servers.start_server("vulnerable")
        cls.srv, cls.url = srv, f"http://localhost:{port}/"
        cls.results = [ws.scan_target(ws.Client(timeout=5, delay=0), cls.url)]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_json_report_round_trips(self):
        data = json.loads(ws.to_json(self.results))
        self.assertEqual(data["tool"], "WebSecAudit")
        self.assertEqual(data["results"][0]["grade"], "F")
        self.assertTrue(data["results"][0]["findings"][0]["remediation"])

    def test_html_report_escapes_untrusted_values(self):
        evil = ws.ScanResult(target="http://x/<script>alert(1)</script>")
        evil.findings = [ws.Finding("T", "headers", "<img src=x onerror=alert(1)>", "low",
                                    "d", evidence="Server: <b>x</b>")]
        out = ws.render_html([evil])
        self.assertNotIn("<script>alert(1)", out)
        self.assertNotIn("<img src=x", out)
        self.assertIn("&lt;img src=x", out)

    def test_console_report(self):
        text = ws.render_console(self.results)
        self.assertIn("CORS-REFLECT-ORIGIN", text)
        self.assertIn("Grade  : F", text)

    def test_cli_requires_authorisation(self):
        with redirect_stderr(StringIO()):
            self.assertEqual(ws.main([self.url]), 3)          # stdin is not a tty -> refused

    def test_cli_no_targets(self):
        with redirect_stderr(StringIO()):
            self.assertEqual(ws.main([]), 2)

    def test_cli_reports_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            j, h = os.path.join(d, "r.json"), os.path.join(d, "r.html")
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                code = ws.main([self.url, "--yes", "--delay", "0", "--json", j, "--html", h,
                                "--fail-on", "high"])
            self.assertEqual(code, 1)
            with open(j, encoding="utf-8") as fh:
                self.assertTrue(json.load(fh)["results"])
            with open(h, encoding="utf-8") as fh:
                self.assertIn("<!doctype html>", fh.read())

    def test_cli_target_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.txt")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(f"# lab\n{self.url}\n\n")
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()) as out:
                code = ws.main(["-f", p, "--yes", "--delay", "0", "-q"])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
