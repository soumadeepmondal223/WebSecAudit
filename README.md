# WebSecAudit - Automated Web Scanner for Secure Headers and CORS Flaws

IBM SkillsBuild National Cybersecurity Bootcamp (BharatCares / CSRBOX)

**Project Topic: Automated Web Scanner** - a Python script that audits sites for secure headers and CORS flaws.

**Author:** Soumadeep Mondal

WebSecAudit is a single-file Python 3 command-line tool. For each target URL it sends a few
**read-only** requests (`GET` and `OPTIONS`; no payloads, no crawling, no fuzzing), then reports
what is missing or misconfigured, with evidence and a fix for every finding.

## What it checks

| Area | Checks |
|---|---|
| **Secure headers** | HSTS (missing / short / invalid), Content-Security-Policy (missing, report-only, `unsafe-inline`, `unsafe-eval`, wildcard sources, `object-src`, `base-uri`), clickjacking protection (`X-Frame-Options` / `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/COEP/CORP, legacy `X-XSS-Protection`, version-disclosure headers (`Server`, `X-Powered-By`, ...) |
| **CORS flaws** | arbitrary `Origin` reflected (with / without credentials), wildcard `*`, trusted `null` origin, prefix/suffix (substring) validation bypass, trusted subdomains, trusted `http://` origin on an HTTPS site, missing `Vary: Origin`, over-permissive preflight (methods, headers, max-age, Private Network Access) |
| Cookies (supporting) | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure`, `__Host-` / `__Secure-` prefix rules |
| Transport (supporting) | page served over HTTP, `http://` to `https://` redirect |

Each finding has a **severity**, **evidence**, **remediation advice**, a **CWE id** and a reference link.
Each target receives a **score (0-100)** and a **grade (A-F)**. Output formats: console, JSON and a
self-contained HTML report.

## Install and run

```bash
pip install -r requirements.txt          # only dependency: requests
python3 web_security_scanner.py https://your-site.example --yes
python3 web_security_scanner.py https://a.example https://b.example --json out.json --html out.html --yes
python3 web_security_scanner.py -f targets.txt --fail-on high --yes     # CI gate: exit code 1 on high/critical
```

Options: `--timeout`, `--delay` (pause between requests, default 0.5 s), `--insecure`, `--skip-cors`,
`--no-http-redirect-check`, `--fail-on {low,medium,high,critical}`, `-q`, `--version`.

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` bad input, `3` authorisation not confirmed,
`4` a target could not be scanned.

## Try it safely (no third-party sites)

`lab_servers.py` starts four local servers with deliberately different configurations:

```bash
python3 lab_servers.py &                 # ports 8081-8084
python3 web_security_scanner.py http://localhost:8081/ http://localhost:8082/ \
        http://localhost:8083/ http://localhost:8084/ --yes --html report.html
```

| Lab server | Configuration | Result |
|---|---|---|
| `:8081` vulnerable | no hardening, version banners, bare cookies, reflects any Origin **with credentials** | **F, 0/100** |
| `:8082` weakcors | good headers, but substring Origin check and `null` trusted | **F, 38/100** |
| `:8083` wildcard | `Access-Control-Allow-Origin: *`, partial headers | **C, 76/100** |
| `:8084` hardened | full header set, safe cookie, exact CORS allow-list | **A, 100/100** |

The saved output of this run is in `sample_output/`.

## Tests

```bash
python3 -m unittest -v        # 37 tests, about 2 seconds, no internet required
```

## How it works

1. **Fetch** - `GET` the target, following up to 5 redirects manually so every hop is recorded.
2. **Headers, cookies, transport** - pure functions over the captured response (easy to unit test).
3. **CORS** - one `GET` with an untrusted `Origin`. If it is not reflected, the scanner tries look-alike
   origins (`null`, a host-prefixed and a host-suffixed origin, an invented subdomain, `http://` version of the site),
   then sends an `OPTIONS` preflight to see which methods and headers an untrusted origin is granted.
4. **Score** - start at 100; subtract 40 / 25 / 12 / 4 / 0 per critical / high / medium / low / info finding.
   Any critical finding forces grade F; any high finding caps the grade at D.

## Responsible use

* Scan **only** systems you own or have explicit written permission to test. The tool asks you to confirm
  authorisation (or pass `--yes`) before it sends anything.
* It is read-only and rate-limited, identifies itself in the `User-Agent`, and never sends exploit payloads.
* If a target redirects to another host, active CORS probes are skipped (the new host may be out of scope).
* Cookie values are never printed; the HTML report escapes every dynamic value.

## Limitations

* Checks only the URL given; CORS behaviour can differ per path, so pass the API endpoints you care about.
* CSP analysis is heuristic and results can include false positives or negatives; review them manually.
* Not an application-logic scanner (no XSS / SQLi testing) and no TLS certificate or cipher analysis.
* The HTTPS-only rules (HSTS, `Secure` cookies, HTTP to HTTPS redirect) are covered by unit tests but were
  validated only against the local lab, not a live HTTPS site.

## Repository layout

```
web_security_scanner.py   the scanner (CLI and library)
lab_servers.py            local vulnerable / hardened test servers
test_scanner.py           37 unit and integration tests
requirements.txt          requests
sample_output/            console, JSON and HTML output from the lab scan
docs/Project_Report.pdf   full project report
```
