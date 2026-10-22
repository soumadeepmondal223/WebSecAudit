#!/usr/bin/env python3
"""
Local test lab for WebSecAudit.

Starts small HTTP servers on 127.0.0.1 that are deliberately configured in
different ways, so the scanner can be demonstrated and tested WITHOUT touching
any third-party website:

  vulnerable : no security headers, version banners, weak cookies, reflects any
               Origin with credentials, permissive preflight
  weakcors   : headers OK but CORS validated with a substring check, trusts 'null'
  wildcard   : Access-Control-Allow-Origin: *
  hardened   : full set of security headers, safe cookies, strict CORS allow-list

Run standalone for a manual demo:   python3 lab_servers.py
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple

TRUSTED_ORIGIN = "https://app.lab.example"

HARDENED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; object-src 'none'; "
                                "base-uri 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class LabHandler(BaseHTTPRequestHandler):
    mode = "vulnerable"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args, **kwargs):  # keep test output clean
        pass

    def version_string(self) -> str:
        """The single Server header value (replaces http.server's own banner)."""
        return {"vulnerable": "Apache/2.4.49 (Unix)", "wildcard": "nginx"}.get(self.mode, "lab")

    # -- helpers ------------------------------------------------------------
    def _cors(self) -> Dict[str, str]:
        origin = self.headers.get("Origin")
        out: Dict[str, str] = {}
        if not origin:
            return out
        mode = self.mode
        if mode == "vulnerable":
            out["Access-Control-Allow-Origin"] = origin          # reflect anything
            out["Access-Control-Allow-Credentials"] = "true"     # ...with cookies
        elif mode == "weakcors":
            if "localhost" in origin or origin == "null":        # substring check + null
                out["Access-Control-Allow-Origin"] = origin
                out["Access-Control-Allow-Credentials"] = "true"
            out["Vary"] = "Origin"
        elif mode == "wildcard":
            out["Access-Control-Allow-Origin"] = "*"
        elif mode == "hardened":
            if origin == TRUSTED_ORIGIN:                         # exact allow-list
                out["Access-Control-Allow-Origin"] = origin
                out["Access-Control-Allow-Credentials"] = "true"
            out["Vary"] = "Origin"
        return out

    def _base_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "text/html; charset=utf-8"}
        if self.mode == "vulnerable":
            h["X-Powered-By"] = "PHP/7.4.3"
            h["X-XSS-Protection"] = "1; mode=block"
            h["Referrer-Policy"] = "unsafe-url"
            h["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"
        elif self.mode == "weakcors":
            h.update(HARDENED_HEADERS)
        elif self.mode == "wildcard":
            h["X-Content-Type-Options"] = "nosniff"
            h["X-Frame-Options"] = "SAMEORIGIN"
        elif self.mode == "hardened":
            h.update(HARDENED_HEADERS)
        return h

    def _cookies(self) -> Tuple[str, ...]:
        if self.mode == "vulnerable":
            return ("sessionid=abc123; Path=/", "theme=dark; Path=/")
        if self.mode == "weakcors":
            return ("sid=xyz; Path=/; HttpOnly; SameSite=None",)
        if self.mode == "hardened":
            return ("__Host-session=s3cr3t; Path=/; Secure; HttpOnly; SameSite=Strict",)
        return ()

    def _send(self, status: int, extra: Dict[str, str], body: bytes, cookies=()) -> None:
        self.send_response(status)
        for k, v in {**self._base_headers(), **extra}.items():
            self.send_header(k, v)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- verbs --------------------------------------------------------------
    def do_GET(self):
        if self.path == "/redirect":
            return self._send(302, {"Location": "/"}, b"")
        body = f"<html><body><h1>Lab: {self.mode}</h1></body></html>".encode()
        self._send(200, self._cors(), body, self._cookies())

    do_HEAD = do_GET

    def do_OPTIONS(self):
        extra = self._cors()
        if "Access-Control-Allow-Origin" in extra and self.mode in ("vulnerable", "weakcors"):
            extra["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
            req_h = self.headers.get("Access-Control-Request-Headers", "")
            extra["Access-Control-Allow-Headers"] = req_h or "*"       # echo whatever is asked
            extra["Access-Control-Max-Age"] = "86400000" if self.mode == "vulnerable" else "600"
        elif "Access-Control-Allow-Origin" in extra and self.mode == "hardened":
            extra["Access-Control-Allow-Methods"] = "GET, POST"
            extra["Access-Control-Allow-Headers"] = "Content-Type"
        self._send(204, extra, b"")


def start_server(mode: str, port: int = 0) -> Tuple[ThreadingHTTPServer, int]:
    handler = type(f"Lab_{mode}", (LabHandler,), {"mode": mode})
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


if __name__ == "__main__":
    import time
    ports = {"vulnerable": 8081, "weakcors": 8082, "wildcard": 8083, "hardened": 8084}
    servers = [start_server(m, p)[0] for m, p in ports.items()]
    print("Lab servers running (Ctrl+C to stop):")
    for m, p in ports.items():
        print(f"  {m:<10} http://localhost:{p}/")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for s in servers:
            s.shutdown()
