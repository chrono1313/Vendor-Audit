# Vendor Audit

A passive, lightweight, fast audit of a domain's maturity, security,
and alignment with best practices. Audits DNS, email, TLS, HTTP, and
web-tier posture — and produces a categorical score, a CSV row, and
an optional plain-text report suitable for sharing with the vendor.
See `example_reports_and_screenshots/` for a console screenshot and
sample `.txt` and `.csv` outputs.

A default-mode run audits 60+ scored data points in roughly a second.
`--deep` adds two or three seconds. In bulk mode
(`--file`), domains are audited 10 at a time in parallel — over 200
domains in under a minute is typical. `--ssl` is sequential and adds 1–2
minutes per domain because SSL Labs runs the assessment server-side.

```
$ python vendor_audit.py example.com

  OVERALL SCORE   54 / 88   ████████████████████░░  61%

    Email     ███████░░░  11/19  (58%)
    DNS       █████████░  7/9    (78%)
    Routing   ████████░░  6/8    (75%)
    TLS       █████████░  14/19  (74%)
    HTTP      █████░░░░░  3/5    (60%)
    Website   ███░░░░░░░  13/28  (46%)
```

(Point totals shown are the maximum baseline. Detected EOL libraries and
operating systems add to the denominator dynamically — one point per EOL
library, three points per EOL OS — and `--ssl` adds the SSL Labs grade.)

## Demo Video

[vendor_audit_example.webm](https://github.com/user-attachments/assets/a35e5c2f-12ad-42db-957f-41ac44dee42d)

## How it's meant to be used

Vendor Audit is a due-diligence tool. Run it on a vendor's domain before
purchasing a product or service to get a quick, evidence-based read on
how their domain configuration aligns with current best practices.
A weak score isn't a deal-breaker on its own, but it's a useful
conversation starter and a data point alongside everything else you're
evaluating.

**Please share the report with the vendor.** The plain-text output
(`--report`) is designed to be readable by their technical team, and
every finding cites the standard it's measured against — so the report
reads as feedback, not as an accusation. Most vendors appreciate a
heads-up they can act on; the report gives them one in a form they can
take straight to the people who can address it. When more than one
prospect shares these reports with the same vendor, they're more likely
to prioritize the issues raised.

## Project scope

Vendor Audit is a lightweight maturity and best-practices audit. The
guiding constraint is that a default run should complete in about a second.
New checks that can't meet that bar belong behind `--deep`, and even
`--deep` checks should add no more than a couple of seconds total.

**Not in scope: anything offensive.** No port scanning, directory
brute-forcing, file or path guessing, login probing, or other behaviour
a WAF or firewall would treat as an attack. There are good tools for
that work; this isn't one of them. Vendor Audit reads what a domain
voluntarily publishes (DNS records, HTTP responses to a single GET, SMTP
EHLO banners, public APIs like SSL Labs and RIPEstat) and scores it
against published standards.

## What it checks

Vendor Audit groups checks into six categories. Every check maps to a published
standard (RFC, W3C spec, OWASP, or CA/Browser Forum baseline requirement) — no
made-up checks.

**Email** — SPF (record presence, lookup count, `redirect=` resolution),
DKIM (common-selector probe), DMARC (presence, `p=` policy, `pct=`, `sp=`,
`rua=` reporting address), MX records, MTA-STS, TLS-RPT, DANE TLSA on MX
(`--deep`), STARTTLS-MX (`--deep`).

**DNS** — DNSSEC chain validation (TLD signing, DNSKEY, AD flag), CAA records,
nameserver count. SOA serial is reported for change tracking but not scored.

**Routing** — IPv6 reachability, IPv4 / IPv6 RPKI ROA coverage, IPv4 / IPv6
IRR/RIS presence (via RIPEstat). ASN is reported for context but not scored.

**TLS** — Cert validity, SAN coverage, lifetime, name match, `www`-variant
coverage, TLS 1.3 support, HSTS (presence, `includeSubDomains`, preload list,
`max-age` strength), and an optional SSL Labs grade with per-condition
findings (`--ssl`).

**HTTP** — HTTP/2 / HTTP/3 (Alt-Svc) support, HTTP→HTTPS redirect presence,
first-hop redirect hygiene. Response time and clock skew are captured but not
scored.

**Website** — Server / X-Powered-By header disclosure, security headers (CSP
analyzed Google-Evaluator-style with sub-scoring for `script-src`,
`object-src`, `base-uri`, `frame-ancestors`, and enforcement mode;
X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy,
Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, X-XSS-Protection
deprecation), cookie attributes (Secure, HttpOnly, SameSite, `__Host-` /
`__Secure-` prefixes), security.txt, server-side EOL OS detection from
headers, client-side EOL library detection, and under `--deep` a regex-light
page parse for Subresource Integrity, mixed content, third-party origins,
and a basic accessibility subset.

## Installation

Python 3.10 or later. Clone the repo and install dependencies:

On Linux via apt:

```bash
sudo apt install python3-dnspython python3-requests python3-httpx python3-tldextract
git clone https://github.com/chrono1313/vendor-audit.git
cd vendor-audit
python3 vendor_audit.py --help

```

On Windows:

```bash
git clone https://github.com/chrono1313/vendor-audit.git
cd vendor-audit
pip install -r requirements.txt
python vendor_audit.py --help
```

## Usage

### Single domain

```bash
python vendor_audit.py example.com                    # terminal report only
python vendor_audit.py example.com --outcsv out.csv   # also write CSV
python vendor_audit.py example.com --report           # also write .txt report
python vendor_audit.py example.com --json             # raw JSON for piping
```

### Bulk (one domain per line)

```bash
python vendor_audit.py --file domains.txt --outcsv results.csv
python vendor_audit.py --file domains.txt --outcsv results.csv --report reports/
```

In bulk mode, domains are audited in parallel (10 at a time by default,
adjustable via `--concurrency`). With `--report`, each successfully-audited
domain produces a separate `<domain>_<ISO>.txt` report in the given directory.

### Deep mode

`--deep` enables three extra checks that are slower or have a higher false-
positive rate on bot-mitigated sites:

- DANE TLSA on each MX host (DNS queries that often time out on non-DNSSEC
  zones)
- STARTTLS-MX cert probe (port 25 egress; blocked on most cloud providers and
  residential ISPs)
- HTML page parse for Subresource Integrity, mixed content, third-party
  origins, and accessibility signals

Default-mode runs typically complete in 1–2 seconds per domain. `--deep` adds
2–5 seconds depending on MX count and server responsiveness.

### SSL Labs

`--ssl your@email.com` requests an SSL Labs API v4 assessment for the domain.
Requires a one-time email registration with Qualys (free):

```bash
python vendor_audit.py --sslregistration --ssl your@email.com
```

The grade contributes 5 points to the score, and the report includes a
Findings list explaining the conditions affecting the grade (vulnerable
protocols, named CVEs like Heartbleed/ROBOT/POODLE, missing forward secrecy,
certificate chain issues, etc.).

SSL Labs assessments take 60–120 seconds per domain and are run sequentially
to respect the API rate limit; cached reports up to 24 hours old are accepted
by default (override with `--ssl-no-cache`).

## Output

Three output formats, used independently or together:

- **Terminal report** (default) — color-coded, scrollable, suitable for
  interactive review.
- **CSV** (`--outcsv`) — one row per domain with every measured field. The CSV
  schema is versioned (`meta_schema_version`); upgrades that change the schema
  cause Vendor Audit to refuse to append to the old file.
- **Plain-text report** (`--report`) — 100-column UTF-8, severity-grouped
  findings, suitable for sharing with the vendor's technical team.

## End-of-life data

`library_eol.json` and `os_eol.json` carry hand-curated end-of-life dates for
client-side libraries and server operating systems. The detector recognises
~185 client-side libraries; 28 of those (jQuery, Bootstrap, Angular, Vue,
Drupal, etc.) have curated EOL annotations and are flagged with their last-
release dates when an old major is detected. The remaining ~150 are reported
with their version but no EOL judgment.

OS detection covers RHEL, Ubuntu, CentOS, Debian, FreeBSD, IIS / Windows
Server, etc. — best-effort, from the `Server` HTTP header.

Both JSON files have a `_verified_on` field and `_note` entries explaining
how each support floor was set. Periodic review is recommended — projects
that ship a new major every six months (Angular, Ionic, Vuetify) move their
support floor frequently.

## Limitations

- **Passive only.** See "Project scope" above. Safe to run against any
  third party without prior coordination.
- **External view only.** A vendor with strong externally-visible posture can
  still have weak internal controls; Vendor Audit makes no claim about what
  it can't see.
- **Single point in time.** The report reflects the moment of the scan.
  Re-run periodically or wire into a scheduled CI job for trend tracking.
- **Bot-mitigated sites.** Cloudflare / Akamai / AWS WAF challenge pages
  produce unreliable page-level findings, which is why page parsing is
  gated behind `--deep` rather than running by default.

## Contributing

Contributions welcome. New checks should map to a published standard
(RFC, W3C spec, OWASP, or CA/Browser Forum baseline requirement) — the audit's
value comes from being able to point at a citation for everything it flags.
Open an issue or pull request on GitHub.

## License

GNU General Public License v3.0 or later. See `LICENSE` for the full text.

This is free software: you are welcome to redistribute and modify it under
the terms of the GPL. There is **NO WARRANTY**, to the extent permitted by
applicable law.
