#!/usr/bin/env python3
# Vendor Audit — lightweight third-party domain security health check.
# Copyright (C) 2026  <your name or organization>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
vendor_audit.py — Lightweight DNS / email / TLS / HTTP security health check.

The project is split into seven files:
    vendor_audit.py        — CLI, runner, SSL Labs integration  (this file)
    audit_checks.py        — network primitives, all check_* functions, scoring
    audit_render.py        — terminal report and CSV output
    audit_txt_report.py    — detailed plain-text report
    scoring_rubric.json    — score weights, thresholds, label maps
    library_eol.json       — end-of-life data for client-side libraries
    os_eol.json            — end-of-life data for server operating systems

VERSIONING POLICY
-----------------
The four .py files (vendor_audit, audit_checks, audit_render, audit_txt_report)
and scoring_rubric.json SHARE a single MAJOR.MINOR.BUGFIX version number,
displayed by --version and enforced at startup (mismatched versions refuse
to run). Every change to ANY of these five components bumps the version in
ALL of them, so __version__ stays identical across the codebase. Choose the
bump level according to the change:

    BUGFIX (1.0.0 → 1.0.1)   bug fixes, doc/help-text edits, no behaviour
                             change beyond fixing the bug.
    MINOR  (1.0.0 → 1.1.0)   new features, new checks, new flags. Existing
                             functionality unchanged.
    MAJOR  (1.0.0 → 2.0.0)   breaking changes: rubric weight changes that
                             move scores, CSV schema changes, removed flags,
                             changed CLI semantics.

Always update __version__ in all four .py files and rubric_version in
scoring_rubric.json in the same commit.

The two EOL data files (library_eol.json, os_eol.json) are versioned by
their own _verified_on date field and updated independently of the code
version.

Usage:
    python3 vendor_audit.py example.com
    python3 vendor_audit.py example.com --json
    python3 vendor_audit.py example.com --dns-server 1.1.1.1
    python3 vendor_audit.py example.com --deep      # adds DANE + STARTTLS-MX + Page Analysis
    python3 vendor_audit.py example.com --outcsv           # auto-named CSV in cwd
    python3 vendor_audit.py example.com --outcsv out.csv   # explicit path
    python3 vendor_audit.py --file domains.txt --outcsv results.csv
    python3 vendor_audit.py --file domains.txt --outcsv results.csv --dns-server 1.1.1.1
    python3 vendor_audit.py example.com --ssl you@yourorg.com
    python3 vendor_audit.py example.com --report            # text report
    python3 vendor_audit.py example.com --report report.txt  # explicit path
    python3 vendor_audit.py --file domains.txt --outcsv out.csv --report   # one report per domain in cwd
    python3 vendor_audit.py --file domains.txt --outcsv out.csv --report reports/  # in named directory

Exit codes:
    0 — script ran successfully (domain findings do not affect exit code)
    1 — hard failure: bad arguments, missing file, unrecoverable startup error

Dependencies:
    pip install dnspython requests 'httpx[http2]' tldextract idna

Minimum Python version: 3.8+

"""
from __future__ import annotations

__version__ = "1.2.2"

import os
import sys
import csv
import json
import time
import random
import socket
import argparse
import logging
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ── Dependency check (must run BEFORE importing audit_checks) ─────────────────
# audit_checks imports dnspython/requests/httpx/tldextract at module level, so
# if any of those are missing we want a friendly install message rather than
# a raw ImportError. We do this check by attempting each import here first.

_MISSING = []
try:
    import dns.resolver  # noqa: F401
    import dns.message   # noqa: F401
    import dns.query     # noqa: F401
    import dns.rdatatype # noqa: F401
    import dns.flags     # noqa: F401
    import dns.exception # noqa: F401
except ImportError:
    _MISSING.append("dnspython")

try:
    import httpx  # noqa: F401
    try:
        import h2  # noqa: F401
    except ImportError:
        _MISSING.append("httpx[http2]")
except ImportError:
    _MISSING.append("httpx[http2]")

try:
    import tldextract  # noqa: F401
except ImportError:
    _MISSING.append("tldextract")

try:
    import idna  # noqa: F401
except ImportError:
    _MISSING.append("idna")

if _MISSING:
    print("[!] Missing dependencies. Install with:\n")
    for dep in _MISSING:
        # Square brackets need quoting in zsh/bash to suppress glob expansion.
        quoted = f"'{dep}'" if "[" in dep else dep
        print(f"    pip install {quoted}")
    print()
    sys.exit(1)

# Now safe to import the rest of the package
from . import audit_checks
from . import audit  # extracted run_audit, normalize_domain, safe_run_audit
from .audit_checks import (
    check_spf, check_dmarc, check_mx, check_ip_routing, check_dnssec,
    check_tls, check_http_version, check_hsts, check_redirect,
    check_http_redirect, check_security_txt, check_server_header,
    set_dns_server, set_http_timeout, set_deep,
    # 2.1.0 additions
    check_caa, check_mta_sts, check_mta_sts_policy,
    check_tls_rpt, check_dane, check_dkim_common, check_ns_soa,
    analyze_csp, check_clock_skew, check_cert_covers_variant,
    check_page_security_signals, check_starttls_mx,
    # 2.8.0 additions
    check_versioned_libraries,
    # 2.9.0 additions
    check_os_eol,
)
from .audit_render import (
    render, results_to_csv_row, error_csv_row, CSV_FIELDS,
    BOLD, GREY, RED, GREEN, YELLOW, CYAN, RESET, c,
)

# ── Cross-module version sanity check ─────────────────────────────────────────
# All four files (this one, audit_checks, audit_render, scoring_rubric.json)
# carry their own version. If they're out of sync — usually because someone
# updated one file but not the others — fail loudly at startup rather than
# producing subtly wrong scores.

from . import audit_render  # for version check
from . import audit_txt_report  # for version check
_RUBRIC_VERSION = audit_checks.RUBRIC.get("rubric_version", "?")
_VERSIONS = {
    "vendor_audit.py":      __version__,
    "audit.py":             audit.__version__,
    "audit_checks.py":      audit_checks.__version__,
    "audit_render.py":      audit_render.__version__,
    "audit_txt_report.py":  audit_txt_report.__version__,
    "scoring_rubric.json":  _RUBRIC_VERSION,
}
if len(set(_VERSIONS.values())) > 1:
    print("[!] Version mismatch across audit modules:")
    for name, ver in _VERSIONS.items():
        print(f"      {name:<24}  {ver}")
    print("\n  All five components must carry the same version. Refusing to run with mismatched components.")
    sys.exit(1)


# ── Bulk-mode defaults ────────────────────────────────────────────────────────

DOMAIN_WORKERS = 10  # domains audited concurrently; all checks are I/O-bound

# Score-percentage thresholds for colorizing the per-domain bulk progress
# line. Same thresholds the terminal report's score panel uses (lives in
# audit_render as _SCORE_GREEN/_SCORE_YELLOW). We read directly from the
# rubric here rather than importing the underscore-prefixed constants from
# audit_render — the rubric is the source of truth, audit_render is just
# another consumer.
_BULK_SCORE_GREEN  = audit_checks.RUBRIC["thresholds"]["score_color_green_pct"]
_BULK_SCORE_YELLOW = audit_checks.RUBRIC["thresholds"]["score_color_yellow_pct"]

# Sentinel used by argparse when --outcsv is passed without a value. Resolved
# by _resolve_outcsv() into a real filename.
_OUTCSV_AUTO_SENTINEL = "__AUTO__"

# Default output directory for auto-named CSV and TXT reports. Created on
# first auto-name; ignored when the user passes an explicit path. Keeping
# generated files out of the project root makes batch runs cleaner.
_DEFAULT_REPORTS_DIR = "reports"


def _ensure_reports_dir() -> str:
    """Create the default reports directory if it doesn't exist and return
    its path. Used by both auto-name helpers below."""
    os.makedirs(_DEFAULT_REPORTS_DIR, exist_ok=True)
    return _DEFAULT_REPORTS_DIR


def _auto_outcsv_name() -> str:
    """Generate a timestamped path for auto-named CSVs, inside ./reports/.

    Format: reports/vendor_audit_2026-04-26T13-42-09.csv (ISO 8601 date +
    'T' separator + dash-separated time; no colons since some filesystems
    and shells dislike them). Local time, since CSVs are typically reviewed
    by an operator on the same machine that produced them.
    """
    fname = datetime.now().strftime("vendor_audit_%Y-%m-%dT%H-%M-%S.csv")
    return os.path.join(_ensure_reports_dir(), fname)


def _resolve_outcsv(value):
    """Map an argparse --outcsv value to a final filename or None.

    value is one of:
      None                         → user did not pass --outcsv            → None
      _OUTCSV_AUTO_SENTINEL        → user passed bare --outcsv             → auto-named
      directory-shaped str         → existing dir, or trailing /\\         → auto-named inside it
      str (anything else)          → user passed an explicit path          → that path
    """
    if value is None:
        return None
    if value == _OUTCSV_AUTO_SENTINEL:
        return _auto_outcsv_name()
    # Directory case: trailing separator or pre-existing directory means
    # "put an auto-named file in here", not "use this literal string as a
    # filename" (which would fail on Windows with [Errno 22] Invalid argument).
    if value.endswith(("/", "\\")) or os.path.isdir(value):
        os.makedirs(value, exist_ok=True)
        # Just the bare filename — caller specified the directory, so we
        # do NOT use _auto_outcsv_name() here (it would prefix ./reports/).
        fname = datetime.now().strftime("vendor_audit_%Y-%m-%dT%H-%M-%S.csv")
        return os.path.join(value, fname)
    return value


# Same sentinel mechanism for --report (text technical report). Auto-name
# is "<domain>_<ISO-with-time>.txt" — domain-keyed rather than
# vendor_audit-prefixed because the report is single-domain by design,
# so the filename should lead with the domain it describes.
_REPORT_AUTO_SENTINEL = "__AUTO__"


def _auto_report_name(domain, in_default_dir: bool = True):
    """Return a default --report path (or filename) for the given domain.

    Uses the same ISO-with-time format as the CSV auto-naming so timestamps
    sort lexicographically and a CSV + TXT pair from the same scan sit next
    to each other in a directory listing.

    in_default_dir=True   → returns reports/<domain>_<ISO>.txt and creates
                            the dir. New auto-naming default.
    in_default_dir=False  → returns just <domain>_<ISO>.txt (bare filename) —
                            for callers that already have a destination
                            directory in hand: bulk mode with an explicit
                            --report DIR, or the directory-shaped path
                            branch in _resolve_report.
    """
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    fname = datetime.now().strftime(f"{safe_domain}_%Y-%m-%dT%H-%M-%S.txt")
    if in_default_dir:
        return os.path.join(_ensure_reports_dir(), fname)
    return fname


def _resolve_report(value, domain):
    """Map an argparse --report value to a final filename or None.
    Mirrors _resolve_outcsv but needs the domain for auto-naming.

    Directory-shaped values (existing directory, or string with a trailing
    / or \\) are treated as "auto-name a file inside this directory" —
    needed because os.fdopen on a path ending in a separator fails with
    [Errno 22] on Windows.
    """
    if value is None:
        return None
    if value == _REPORT_AUTO_SENTINEL:
        return _auto_report_name(domain)
    if value.endswith(("/", "\\")) or os.path.isdir(value):
        os.makedirs(value, exist_ok=True)
        return os.path.join(value, _auto_report_name(domain, in_default_dir=False))
    return value


# ── Thread-safe print + timestamp + logging bridge ────────────────────────────

_print_lock = threading.Lock()


class _CliLogHandler(logging.Handler):
    """Logging handler that mimics _tprint() output: timestamped, colored
    by severity, and thread-locked using the same lock as _tprint() so that
    log records and direct _tprint() calls never interleave.

    The audit module (vendor_audit.audit) emits its progress via
    logging.getLogger("vendor_audit.audit"); this handler is what makes
    those messages show up on the terminal in the same style as the rest
    of the CLI's output.
    """

    _LEVEL_COLOR = {
        logging.DEBUG:    GREY,
        logging.INFO:     "",      # default terminal color
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: RED,
    }

    def emit(self, record):
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            color = self._LEVEL_COLOR.get(record.levelno, "")
            msg = record.getMessage()
            line = f"{c(GREY, ts)}  {color}{msg}{RESET if color else ''}"
            with _print_lock:
                print(line, file=sys.stderr)
        except Exception:
            self.handleError(record)


def _install_audit_logging():
    """Wire the audit module's logger to the CLI's terminal output.

    Idempotent: safe to call more than once (won't add duplicate handlers).
    The web layer never calls this; logging stays unconfigured there and
    audit messages are silently dropped by Python's lastResort handler.
    """
    audit_log = logging.getLogger("vendor_audit.audit")
    if any(isinstance(h, _CliLogHandler) for h in audit_log.handlers):
        return
    audit_log.addHandler(_CliLogHandler())
    audit_log.setLevel(logging.INFO)
    audit_log.propagate = False  # don't double-print via root


def _tprint(*args, **kwargs):
    """Print with a lock so parallel domain output doesn't interleave.
    Prefixes each line with a HH:MM:SS timestamp for timing diagnostics.

    Used by the rest of the CLI (SSL Labs polling, bulk-mode progress,
    main()'s top-of-output banner). The audit module emits its own
    progress through logging, which the _CliLogHandler above merges into
    the same output stream using the same lock.
    """
    ts = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        if args and isinstance(args[0], str):
            print(f"{c(GREY, ts)}  {args[0]}", *args[1:], **kwargs)
        else:
            print(f"{c(GREY, ts)} ", *args, **kwargs)


# ── SSL Labs integration ──────────────────────────────────────────────────────

_SSLLABS_BASE     = "https://api.ssllabs.com/api/v4"
_SSL_BACKOFF_SECS = 60   # seconds to wait after a 429 before retrying


class SslLabsRateLimitError(RuntimeError):
    """Raised when SSL Labs returns HTTP 429 Too Many Requests."""


def _ssllabs_call(path, email=None, params=None, method="GET", json_body=None, timeout=60):
    """Make a request to the SSL Labs API v4.

    Per the API docs:
      - All calls use GET except /register, which must use POST.
      - The registered email is passed as an HTTP header (not a query param)
        and is mandatory for analyze and getEndpointData.
      - Content-Type: application/json is only sent on POST requests.

    timeout is intentionally 60 s rather than the configured per-op timeout —
    SSL Labs responses can be slow (the server queues assessments and may
    take many seconds to reply), so the tighter per-operation timeout used
    for domain checks would produce false 'API unreachable' errors here.

    Raises RuntimeError on known error codes (400, 429, 441, 500, 503, 529).
    Returns (data, response_headers).
    """
    url = f"{_SSLLABS_BASE}/{path}"

    if method == "POST":
        headers = {"Content-Type": "application/json"}
        if email:
            headers["email"] = email
        # httpx is API-compatible with requests for the simple-request
        # case used here: status_code, json(), text, headers, and
        # raise_for_status() all exist with the same shape.
        resp = httpx.post(url, headers=headers, json=json_body or {}, timeout=timeout)
    else:
        headers = {}
        if email:
            headers["email"] = email
        resp = httpx.get(url, headers=headers, params=params or {}, timeout=timeout)

    if resp.status_code == 400:
        try:
            errs = resp.json().get("errors", [])
            detail = "; ".join(f"{e.get('field','?')}: {e.get('message','?')}" for e in errs)
        except Exception:
            detail = resp.text
        raise RuntimeError(f"SSL Labs returned 400 Bad Request — {detail}")
    if resp.status_code == 429:
        raise SslLabsRateLimitError(
            "SSL Labs returned 429 Too Many Requests."
        )
    if resp.status_code == 441:
        raise RuntimeError(
            "SSL Labs returned 441 Unauthorized — register your email first with --sslregistration."
        )
    if resp.status_code == 500:
        raise RuntimeError(
            "SSL Labs returned 500 Internal Server Error — the assessment has been marked as flawed; "
            "you may retry, but if 500s persist, stop and try again later."
        )
    if resp.status_code == 503:
        raise RuntimeError(
            "SSL Labs returned 503 Service Unavailable (maintenance) — wait ~15 minutes then retry."
        )
    if resp.status_code == 529:
        raise RuntimeError(
            "SSL Labs returned 529 Overloaded — wait 15-30 minutes then retry."
        )

    resp.raise_for_status()
    return resp.json(), resp.headers


def cmd_sslregistration():
    """Interactive SSL Labs API registration flow.

    Prompts for first name, last name, email, and organisation, shows a
    confirmation, then POSTs to /register.
    """
    print(f"\n{c(BOLD+CYAN, '━'*56)}")
    print(c(BOLD, "  SSL Labs API Registration"))
    print(f"{c(BOLD+CYAN, '━'*56)}")
    print(c(GREY, "  One-time registration required before using --ssl."))
    print(c(GREY, "  Use a non-free-email-service address (no Gmail, Yahoo, etc.)."))
    print()

    def _prompt(label, required=True):
        while True:
            val = input(f"  {label}: ").strip()
            if val:
                return val
            if not required:
                return ""
            print(f"  {c(RED, '✘')} {label} is required.")

    first_name   = _prompt("First name")
    last_name    = _prompt("Last name")
    email        = _prompt("Email (organisation address)")
    organisation = _prompt("Organisation")

    print()
    print(c(BOLD, "  Confirm registration details:"))
    print(f"    Name:         {first_name} {last_name}")
    print(f"    Email:        {email}")
    print(f"    Organisation: {organisation}")
    print()

    confirm = input("  Submit? [y/N]: ").strip().lower()
    if confirm != "y":
        print(c(YELLOW, "\n  Registration cancelled."))
        return

    print()
    print(c(GREY, "  Submitting registration to SSL Labs…"))

    try:
        data, _ = _ssllabs_call(
            "register",
            method="POST",
            json_body={
                "firstName":    first_name,
                "lastName":     last_name,
                "email":        email,
                "organization": organisation,
            },
        )
        reg_status  = data.get("status", "")
        reg_message = data.get("message", "")

        if reg_status == "failure" or (reg_status and reg_status != "success"):
            print(c(RED, f"\n  ✘ Registration rejected by SSL Labs: {reg_message or reg_status}"))
            return

        print(c(GREEN, "\n  ✔ Registration accepted."))
        if reg_message:
            print(f"  {c(GREY, reg_message)}")
        print()
        print(c(BOLD, "  Next step:"))
        print(f"    python3 vendor_audit.py example.com {c(CYAN, f'--ssl {email}')}")
        print()
    except RuntimeError as exc:
        print(c(RED, f"\n  ✘ Registration failed: {exc}"))
    except Exception as exc:
        print(c(RED, f"\n  ✘ Unexpected error: {exc}"))


# ── SSL Labs response decoder ────────────────────────────────────────────────
# Single helper that walks the SSL Labs response and returns a list of
# observations: things SSL Labs measured that the user might want to address.
#
# Design choice: we do NOT try to classify which observations affect the grade
# and which don't. SSL Labs's grading rules are richer than the public Rating
# Guide documents (warnings, A→A- demotions, scoring nuances), and pretending
# to know which signals are grade-relevant would mislead readers. The grade
# itself is the verdict; this list reports the conditions SSL Labs saw.
#
# Field reference:   https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md
# Rating guide:      https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide

def _ssllabs_leaf_cert(host_data):
    """Find the leaf (server) certificate in the response's top-level certs[]
    array. The leaf is the one referenced by the endpoint's certChains.certIds
    in position 0 — but as a robust fallback we pick the first cert whose
    subject matches the assessed hostname. Returns None if not findable."""
    certs = host_data.get("certs") or []
    if not certs:
        return None

    # Fast path: certChains[0].certIds[0] points to the leaf.
    for ep in host_data.get("endpoints") or []:
        chains = (ep.get("details") or {}).get("certChains") or []
        for chain in chains:
            cert_ids = chain.get("certIds") or []
            if cert_ids:
                leaf_id = cert_ids[0]
                for c in certs:
                    if c.get("id") == leaf_id:
                        return c

    # Fallback: pick the first cert whose subject CN equals the host.
    host = (host_data.get("host") or "").lower()
    for c in certs:
        subj = (c.get("subject") or "").lower()
        if f"cn={host}" in subj:
            return c

    # Last resort: just return the first cert.
    return certs[0]


def _ssllabs_protocols_set(details):
    """Return a set of protocol-version strings, e.g. {'TLS 1.2', 'TLS 1.3'}.
    Empty set if no protocol info present."""
    out = set()
    for p in details.get("protocols") or []:
        ver = p.get("version")
        name = p.get("name") or "TLS"
        if ver:
            out.add(f"{name} {ver}")
    return out


def _extract_ssllabs_findings(host_data):
    """Decode SSL Labs response into a list of human-readable observations.

    Returns a deduped list of strings. Empty list = SSL Labs reported nothing
    we know how to surface. We do not interpret which observations affect the
    grade — the grade itself is the verdict; this list reports what SSL Labs
    saw. Wording is plain ("Vulnerable to Heartbleed (CVE-2014-0160)"), with
    no inference about grade impact.
    """
    findings = []
    seen     = set()

    def add(msg):
        if msg not in seen:
            seen.add(msg)
            findings.append(msg)

    LONG_MAX_AGE = 15552000   # 180 days; the SSL Labs threshold for A+

    for ep in host_data.get("endpoints") or []:
        details = ep.get("details") or {}

        # ── Protocol support ─────────────────────────────────────────────────
        protocols = _ssllabs_protocols_set(details)
        if protocols:
            for obsolete in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
                if obsolete in protocols:
                    add(f"Obsolete protocol supported: {obsolete}")
            if "TLS 1.2" not in protocols:
                add("TLS 1.2 not supported")
            if "TLS 1.3" not in protocols:
                add("TLS 1.3 not supported")

        # TLS 1.3 mandatory cipher suite.
        if details.get("implementsTLS13MandatoryCS") is False and "TLS 1.3" in protocols:
            add("TLS 1.3 mandatory cipher suite (TLS_AES_128_GCM_SHA256) not implemented")

        # ── Named vulnerabilities (boolean fields) ───────────────────────────
        bool_vulns = [
            ("vulnBeast",        "Vulnerable to BEAST"),
            ("heartbleed",       "Vulnerable to Heartbleed (CVE-2014-0160)"),
            ("poodle",           "Vulnerable to POODLE (SSLv3)"),
            ("freak",            "Vulnerable to FREAK"),
            ("logjam",           "Vulnerable to Logjam (weak DH parameters)"),
            ("drownVulnerable",  "Vulnerable to DROWN"),
        ]
        for field, message in bool_vulns:
            if details.get(field) is True:
                add(message)

        # ── Named vulnerabilities (status integers) ──────────────────────────
        # Convention: 1 = not vulnerable, 0 = unknown, -1 = test failed,
        # ≥2 = vulnerable in some form.
        status_vulns = [
            ("openSslCcs",              "Vulnerable to OpenSSL CCS injection (CVE-2014-0224)"),
            ("openSSLLuckyMinus20",     "Vulnerable to Lucky Minus 20 (CVE-2016-2107)"),
            ("ticketbleed",             "Vulnerable to Ticketbleed (CVE-2016-9244)"),
            ("bleichenbacher",          "Vulnerable to ROBOT (Bleichenbacher's oracle)"),
            ("zombiePoodle",            "Vulnerable to Zombie POODLE"),
            ("goldenDoodle",            "Vulnerable to GOLDENDOODLE"),
            ("zeroLengthPaddingOracle", "Vulnerable to 0-Length Padding Oracle (CVE-2019-1559)"),
            ("sleepingPoodle",          "Vulnerable to Sleeping POODLE"),
            ("poodleTls",               "Vulnerable to POODLE TLS"),
        ]
        for field, message in status_vulns:
            v = details.get(field)
            if isinstance(v, int) and v >= 2:
                add(message)

        # ── Cipher / key-exchange posture ────────────────────────────────────
        if details.get("supportsRc4") is True:
            add("RC4 cipher suites supported")
        if details.get("rc4Only") is True:
            add("Server supports ONLY RC4 cipher suites")
        if details.get("supportsAead") is False:
            add("AEAD cipher suites not supported")

        # forwardSecrecy is a bitfield. Bit 2 (4) = FS with all simulated
        # clients. 0 = no FS at all. 1-3 = partial FS.
        fs = details.get("forwardSecrecy")
        if isinstance(fs, int):
            if fs == 0:
                add("Forward secrecy not supported")
            elif not (fs & 4):
                add("Forward secrecy not achieved with all reference clients")

        # ── Renegotiation ────────────────────────────────────────────────────
        # bit 0 (1) = insecure client-initiated renegotiation supported.
        reneg = details.get("renegSupport")
        if isinstance(reneg, int) and (reneg & 1):
            add("Insecure client-initiated renegotiation supported")

        # ── DH parameters ────────────────────────────────────────────────────
        dh_known = details.get("dhUsesKnownPrimes")
        if dh_known == 2:
            add("Weak well-known DH primes in use")
        elif dh_known == 1:
            add("Common DH primes in use (potential Logjam exposure)")
        if details.get("dhYsReuse") is True:
            add("DH ephemeral server value reused across sessions")
        if details.get("ecdhParameterReuse") is True:
            add("ECDHE parameters reused across sessions")

        # ── 0-RTT (TLS 1.3 replay surface) ───────────────────────────────────
        if details.get("zeroRTTEnabled") == 1:
            add("TLS 1.3 0-RTT enabled (replay attack surface)")

        # ── Certificate chain issues ─────────────────────────────────────────
        # certChains[].issues bitfield: bit 1 (2) incomplete, bit 2 (4)
        # unrelated/duplicate, bit 3 (8) wrong order, bit 5 (32) couldn't
        # validate. We OR across all chains and decode bit-by-bit.
        chain_issues = 0
        for chain in details.get("certChains") or []:
            ci = chain.get("issues")
            if isinstance(ci, int):
                chain_issues |= ci
        if chain_issues & 2:
            add("Certificate chain incomplete")
        if chain_issues & 4:
            add("Certificate chain contains unrelated or duplicate certs")
        if chain_issues & 8:
            add("Certificate chain in incorrect order")
        if chain_issues & 32:
            add("Certificate chain could not be validated")

        # ── HSTS ─────────────────────────────────────────────────────────────
        hsts = details.get("hstsPolicy") or {}
        hsts_status = hsts.get("status")
        if hsts_status in ("absent", "missing", "disabled", "invalid"):
            add(f"HSTS not properly configured: {hsts_status}")
        elif hsts_status == "present":
            max_age = hsts.get("maxAge")
            if isinstance(max_age, int) and max_age < LONG_MAX_AGE:
                days = max_age // 86400
                add(f"HSTS max-age is {max_age} seconds ({days} days); 6 months (15552000) recommended")
            if hsts.get("includeSubDomains") is False:
                add("HSTS missing 'includeSubDomains' directive")
            if hsts.get("preload") is False:
                add("HSTS missing 'preload' directive")

        # ── HSTS preload list status ─────────────────────────────────────────
        # Site advertises preload in its HSTS header but isn't actually on
        # any browser's preload list. Common — preload submission is a
        # separate step at hstspreload.org.
        preloads = details.get("hstsPreloads") or []
        absent_sources = [p.get("source") for p in preloads
                          if p.get("status") in ("absent", "unknown")]
        if preloads and len(absent_sources) == len(preloads):
            if hsts.get("preload") is True:
                add("HSTS header claims 'preload' but host is not on any browser preload list")

        # ── OCSP stapling ────────────────────────────────────────────────────
        if details.get("ocspStapling") is False:
            add("OCSP stapling not enabled")

        # ── Session resumption / tickets ─────────────────────────────────────
        # 0 = not enabled, 1 = IDs returned but not resumed, 2 = working.
        sr = details.get("sessionResumption")
        if sr == 0:
            add("Session resumption not enabled")
        elif sr == 1:
            add("Session resumption: IDs returned but not resumed")
        if details.get("sessionTickets") == 0:
            add("TLS session tickets not enabled")

        # ── Weak cipher suites offered ───────────────────────────────────────
        # Each suite in the suites list has a 'q' flag — non-zero = weak per
        # SSL Labs' own classification (CBC mode, RSA key exchange without
        # forward secrecy, etc.).
        weak_suite_names = []
        for suite_grp in details.get("suites") or []:
            for s in suite_grp.get("list") or []:
                if s.get("q"):
                    name = s.get("name")
                    if name and name not in weak_suite_names:
                        weak_suite_names.append(name)
        if weak_suite_names:
            count = len(weak_suite_names)
            sample = ", ".join(weak_suite_names[:3])
            more = f" + {count - 3} more" if count > 3 else ""
            add(f"{count} weak cipher suite(s) offered: {sample}{more}")

    # ── Cert-level checks (run once on the leaf cert across endpoints) ──────
    leaf = _ssllabs_leaf_cert(host_data)
    if leaf:
        # Insecure signature algorithms.
        sig_alg = (leaf.get("sigAlg") or "").upper()
        if "MD5" in sig_alg or "MD2" in sig_alg:
            add(f"Insecure certificate signature algorithm: {sig_alg}")
        elif "SHA1" in sig_alg:
            add(f"Certificate signed with SHA1 ({sig_alg})")

        # Weak key sizes.
        key_alg  = leaf.get("keyAlg") or ""
        key_size = leaf.get("keySize")
        if isinstance(key_size, int):
            if key_alg == "RSA" and key_size < 2048:
                add(f"Weak certificate key: {key_alg} {key_size} bits")
            elif key_alg == "EC" and key_size < 256:
                add(f"Weak certificate key: {key_alg} {key_size} bits")

        # Cert.issues is a bitfield. Decode the documented bits.
        ci = leaf.get("issues")
        if isinstance(ci, int) and ci:
            if ci & 1:
                add("Certificate: no chain of trust")
            if ci & 2:
                add("Certificate: not before date is in the future")
            if ci & 4:
                add("Certificate: expired")
            if ci & 8:
                add("Certificate: hostname mismatch")
            if ci & 16:
                add("Certificate: revoked")
            if ci & 32:
                add("Certificate: bad common name")
            if ci & 64:
                add("Certificate: self-signed")
            if ci & 128:
                add("Certificate: blacklisted")
            if ci & 256:
                add("Certificate: insecure signature")
            if ci & 512:
                add("Certificate: insecure key")

        # CAA DNS record.
        if leaf.get("dnsCaa") is False:
            add("CAA DNS record not published")

        # Certificate transparency — no SCT in leaf cert.
        if leaf.get("sct") is False:
            add("Certificate transparency: no SCT embedded in leaf cert")

    return findings


def cmd_ssl_scan(domain, email, publish=False, from_cache=True, max_age=24):
    """Run a Qualys SSL Labs assessment for domain and return grade data.

    By default requests a cached report (fromCache=on, maxAge=24 h).
    SSL Labs starts a fresh assessment automatically when the cached result
    is older than maxAge — or when Qualys has already evicted it from
    their cache, which can happen well before maxAge.

    Per the API docs, fromCache and startNew are mutually exclusive.
    """
    # Track wall time and which path we took (cache hit vs fresh scan) so
    # we can emit a one-line diagnostic at the end. The original symptom
    # that motivated this — a weekend-old scan re-running a day later —
    # was invisible because the runner just said "querying example.com…"
    # regardless of which path the API took.
    scan_start_time = datetime.now()
    was_cache_hit   = None  # set after the first _ssllabs_call returns
    if from_cache:
        cache_note = f"accept cache up to {max_age}h"
    else:
        cache_note = "forcing new scan"
    _tprint(c(GREY, f"  SSL Labs: querying {domain}…  {c(GREY, f'[{cache_note}]')}"))
    if publish:
        _tprint(c(YELLOW, "  ⚠ SSL Labs results will be published to the public scoreboard."))

    if from_cache:
        init_params = {
            "host":      domain,
            "fromCache": "on",
            "maxAge":    str(max_age),
            "all":       "done",
            "publish":   "on" if publish else "off",
        }
    else:
        init_params = {
            "host":     domain,
            "startNew": "on",
            "all":      "done",
            "publish":  "on" if publish else "off",
        }

    while True:
        try:
            data, _resp_hdrs = _ssllabs_call("analyze", email=email, params=init_params)
            break
        except SslLabsRateLimitError:
            _tprint(c(YELLOW, f"  ⚠ SSL Labs rate limit hit — waiting {_SSL_BACKOFF_SECS}s before retrying…"))
            time.sleep(_SSL_BACKOFF_SECS)
        except RuntimeError as exc:
            _tprint(c(RED, f"  ✘ {exc}"))
            return
        except Exception as exc:
            _tprint(c(RED, f"  ✘ Could not reach SSL Labs API: {exc}"))
            return

    # Detect cache hit. fromCache=on with a usable cached result returns
    # status=READY on the first call; any other status (DNS, IN_PROGRESS)
    # means SSL Labs decided to start (or had already started) a fresh
    # assessment. With from_cache=False (--ssl-no-cache) we passed
    # startNew=on, so this is always a fresh scan.
    if not from_cache:
        was_cache_hit = False
    else:
        was_cache_hit = (data.get("status") == "READY")

    # ── Poll until terminal state ─────────────────────────────────────────────
    # Per the API spec:
    #   - startNew must NEVER be repeated in poll calls — doing so triggers a
    #     new assessment on every request, creating an assessment loop.
    #   - fromCache defaults to off, which also starts a new assessment.
    #   - Therefore, all poll calls must use fromCache=on regardless of how
    #     the initial request was made.
    #   - The v4 spec documents maxAge as "Maximum report age in hours if
    #     retrieving from cache (fromCache parameter)" — implying the two
    #     parameters travel together. The reference Go client always pairs
    #     them on every call. Match that here so the poll uses the same
    #     cache window as the initial request.
    poll_params = {
        "host":      domain,
        "fromCache": "on",
        "maxAge":    str(max_age),
        "all":       "done",
        "publish":   "on" if publish else "off",
    }

    last_eta = None

    while True:
        status     = data.get("status", "")
        status_msg = data.get("statusMessage", "")

        if status == "READY":
            break
        if status == "ERROR":
            _tprint(c(RED, f"  ✘ SSL Labs returned an error: {status_msg}"))
            return

        endpoints_in_progress = data.get("endpoints", [])
        etas = [ep.get("eta") for ep in endpoints_in_progress
                if ep.get("eta") is not None and ep.get("eta") > 0]
        current_eta = min(etas) if etas else None
        if current_eta is not None and (last_eta is None or current_eta <= last_eta):
            eta_str  = f"  (~{current_eta}s remaining)"
            last_eta = current_eta
        else:
            eta_str = ""
        progress_label = status_msg if status_msg and status_msg != "None" else status
        _tprint(c(GREY, f"  … {progress_label}{eta_str}"))

        for ep in endpoints_in_progress:
            ip      = ep.get("ipAddress", "?")
            detail  = ep.get("statusDetailsMessage") or ep.get("statusMessage") or ""
            ep_eta  = ep.get("eta")
            if detail and detail != "None":
                eta_part = f"  (~{ep_eta}s)" if ep_eta and ep_eta > 0 else ""
                _tprint(c(GREY, f"       · {ip} — {detail}{eta_part}"))

        # Per API docs: poll every 5s before IN_PROGRESS, every 10s after.
        poll_sleep = 10 if status == "IN_PROGRESS" else 5
        time.sleep(poll_sleep + random.uniform(0, 2))

        try:
            data, _resp_hdrs = _ssllabs_call(
                "analyze",
                email=email,
                params=poll_params,
            )
        except SslLabsRateLimitError:
            _tprint(c(YELLOW, f"  ⚠ SSL Labs rate limit hit — waiting {_SSL_BACKOFF_SECS}s before retrying…"))
            time.sleep(_SSL_BACKOFF_SECS)
        except RuntimeError as exc:
            _tprint(c(RED, f"\n  ✘ {exc}"))
            return
        except Exception as exc:
            _tprint(c(RED, f"\n  ✘ Poll failed: {exc}"))
            return

    # ── Extract grade ─────────────────────────────────────────────────────────
    endpoints = data.get("endpoints", [])
    if not endpoints:
        _tprint(c(YELLOW, "  ⚠ SSL Labs: no endpoints returned"))
        return None

    # Use the rubric's grade order so vendor_audit.py and audit_checks.py agree.
    grade_order = audit_checks.SSL_GRADE_ORDER
    all_grades  = []
    unknown_grades = []
    for ep in endpoints:
        grade = ep.get("grade") or ep.get("gradeTrust") or "?"
        if grade in grade_order:
            all_grades.append(grade)
        elif grade != "?":
            unknown_grades.append(grade)

    if unknown_grades:
        _tprint(c(YELLOW, f"  ⚠ SSL Labs returned unrecognised grade(s): {', '.join(unknown_grades)} — scoring may be incomplete"))

    worst_grade = None
    for g in grade_order:
        if g in all_grades:
            worst_grade = g
            break

    # Cache-hit vs fresh-scan diagnostic. data.testTime is "Assessment
    # completion time, in milliseconds since 1970" per the v4 spec — for
    # a cache hit it tells the reader how stale the cached result is; for
    # a fresh scan it just confirms we got one. The wall-clock elapsed
    # for a fresh scan is more useful in that case.
    if was_cache_hit:
        test_ms = data.get("testTime")
        if test_ms:
            try:
                age_secs = (datetime.now(timezone.utc) -
                            datetime.fromtimestamp(test_ms / 1000, tz=timezone.utc)
                            ).total_seconds()
                if age_secs < 3600:
                    age_str = f"{int(age_secs // 60)} minutes ago"
                elif age_secs < 86400:
                    age_str = f"{int(age_secs // 3600)} hours ago"
                else:
                    age_str = f"{int(age_secs // 86400)} days ago"
                _tprint(c(GREY, f"  SSL Labs: cache hit (assessed {age_str})"))
            except Exception:
                _tprint(c(GREY, "  SSL Labs: cache hit"))
        else:
            _tprint(c(GREY, "  SSL Labs: cache hit"))
    else:
        elapsed_s = (datetime.now() - scan_start_time).total_seconds()
        _tprint(c(GREY, f"  SSL Labs: fresh assessment ({int(elapsed_s)}s)"))

    _tprint(c(GREEN, f"  ✔ SSL Labs grade: {worst_grade}"))

    # Decode the SSL Labs response into a single deduped list of observations.
    # The extractor walks endpoints internally and merges results — multi-IP
    # setups usually have near-identical configuration.
    merged_findings = _extract_ssllabs_findings(data)

    return {
        "worst_grade":      worst_grade,
        "grades":           all_grades,
        "test_time_ms":     data.get("testTime"),
        "findings":         merged_findings,
        "criteria_version": data.get("criteriaVersion"),
    }


# ── Bulk runner ───────────────────────────────────────────────────────────────

def _bulk_progress_line(domain, row):
    """Format a per-domain progress line for bulk runs from a row dict.

    Pulls the score directly from the row that results_to_csv_row() has
    already produced, so this is bookkeeping only — no scoring is
    re-computed. Returns an empty string if the row has no score
    populated (errored audits, which take a different code path
    anyway).
    """
    earned = row.get("score_total_earned", "")
    possible = row.get("score_total_possible", "")
    pct_str = row.get("score_total_pct", "")
    if not (earned and possible and pct_str):
        return ""
    try:
        pct = int(pct_str)
    except (TypeError, ValueError):
        return ""
    color = (GREEN if pct >= _BULK_SCORE_GREEN
             else YELLOW if pct >= _BULK_SCORE_YELLOW
             else RED)
    # The whole line is color-coded by score band, so no [OK]/[FAIL] tag —
    # the color carries the verdict and a tag would be redundant (or
    # misleading at 15%, which technically "completed" but isn't OK).
    return f"  {c(color, '•')} {domain}: {c(BOLD, f'{earned}/{possible}')} ({c(color, f'{pct}%')})"


def run_bulk(domains, outcsv_path, ssl_args=None, concurrency=None, report_dir=None):
    """Audit multiple domains and write results to a CSV.

    Without --ssl: domains audited in parallel (concurrency workers).
    With --ssl:    one domain at a time, fully complete before the next starts.

    DNS server and HTTP timeout must be configured globally before calling.

    If report_dir is provided, a detailed plain-text report is written for
    each successfully-audited domain into that directory. The filename
    follows the same "<domain>_<ISO-with-time>.txt" pattern used for the
    single-domain auto-named report. Errored domains are skipped — the
    audit_txt_report module expects a populated results dict and would
    otherwise crash mid-bulk.
    """
    rows       = [None] * len(domains)
    bulk_start = time.time()
    reports_written = 0
    reports_failed  = 0

    def _write_per_domain_report(original, audit_domain, results, ts):
        """Write one report for a successfully-audited domain. Failures
        are counted but never re-raised — a single broken report should
        not abort the whole bulk run. Returns True on success."""
        nonlocal reports_written, reports_failed
        if not report_dir:
            return False
        try:
            filename = _auto_report_name(original, in_default_dir=False)
            path = os.path.join(report_dir, filename)
            audit_txt_report.write_txt_report(
                original_domain=original,
                audit_domain=audit_domain,
                results=results,
                timestamp=ts,
                out_path=path,
                report_version=audit_txt_report.__version__,
            )
            reports_written += 1
            return True
        except Exception as e:
            reports_failed += 1
            _tprint(f"{c(RED, '[REPORT-ERROR]')} {original}: {e}")
            return False

    if ssl_args:
        # Sequential when --ssl is on: each domain fully complete before the next.
        for idx, raw in enumerate(domains):
            try:
                _outcome = audit.run_audit(raw, ssl_active=True)
                original, audit_domain, results, ts = (
                    _outcome["domain"], _outcome["audit_domain"],
                    _outcome["results"], _outcome["timestamp"],
                )
                ssl_result = cmd_ssl_scan(
                    audit_domain,
                    email=ssl_args["email"],
                    publish=ssl_args.get("publish", False),
                    from_cache=ssl_args.get("from_cache", True),
                    max_age=ssl_args.get("max_age", 24),
                )
                if ssl_result:
                    results["ssl_labs"] = ssl_result
                rows[idx] = results_to_csv_row(original, audit_domain, results, ts)
                line = _bulk_progress_line(original, rows[idx])
                if line:
                    _tprint(line)
                _write_per_domain_report(original, audit_domain, results, ts)
            except Exception as e:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                rows[idx] = error_csv_row(raw, str(e), ts)
                _tprint(f"{c(RED, '[ERROR]')} {raw}: {e}")
    else:
        # Parallel: standard checks only.
        workers = concurrency if concurrency is not None else DOMAIN_WORKERS

        def _worker(idx, raw):
            try:
                _outcome = audit.run_audit(raw)
                original, audit_domain, results, ts = (
                    _outcome["domain"], _outcome["audit_domain"],
                    _outcome["results"], _outcome["timestamp"],
                )
                rows[idx] = results_to_csv_row(original, audit_domain, results, ts)
                line = _bulk_progress_line(original, rows[idx])
                if line:
                    _tprint(line)
                _write_per_domain_report(original, audit_domain, results, ts)
            except Exception as e:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                rows[idx] = error_csv_row(raw, str(e), ts)
                raise

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_worker, i, d): d for i, d in enumerate(domains)}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    _tprint(f"{c(RED, '[ERROR]')} {futures[future]}: {e}")

    written = sum(1 for r in rows if r is not None)
    errored = sum(1 for r in rows
                  if r is not None and str(r.get("verdict_spf", "")).startswith("audit_error:"))
    file_exists = os.path.isfile(outcsv_path)

    # Schema-compatibility guard: if the file exists, verify the header matches.
    # A mismatch means the file was produced by a different version of the
    # script — appending would silently misalign columns.
    if file_exists:
        try:
            with open(outcsv_path, newline="", encoding="utf-8") as _fh:
                existing_fields = next(csv.reader(_fh), [])
            if existing_fields != CSV_FIELDS:
                raise SystemExit(
                    f"[!] CSV schema mismatch: {outcsv_path!r} was created with a "
                    f"different version of vendor_audit.py.\n"
                    f"    Rename or remove the existing file before appending new results."
                )
        except (OSError, StopIteration):
            pass  # unreadable or empty — let the open() below surface real errors

    with open(outcsv_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        if not file_exists:
            writer.writeheader()
        for row in rows:
            if row is not None:
                writer.writerow(row)

    elapsed   = time.time() - bulk_start
    minutes   = int(elapsed // 60)
    seconds   = int(elapsed % 60)
    time_str  = f"{minutes} minute{'s' if minutes != 1 else ''} and {seconds} second{'s' if seconds != 1 else ''}"
    domain_str = f"{written} domain{'s' if written != 1 else ''} audited in {time_str}."

    summary = f"({written} / {len(domains)} domains"
    if errored:
        summary += f", {errored} errored"
    summary += ")"
    _tprint(
        f"\n{c(BOLD, domain_str)}"
        f"\n{c(GREEN, '✔')} Results written to {c(BOLD, outcsv_path)}  {summary}"
    )
    if report_dir:
        report_summary = f"({reports_written} report{'s' if reports_written != 1 else ''} written"
        if reports_failed:
            report_summary += f", {reports_failed} failed"
        report_summary += ")"
        _tprint(
            f"{c(GREEN, '✔')} Reports written to {c(BOLD, report_dir)}  {report_summary}"
        )


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Lightweight passive security health check for a domain or list of domains.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT IS CHECKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SPF            Sender Policy Framework record — presence, policy strength
                 (-all / ~all / +all), DNS lookup count (RFC limit: 10),
                 and redirect chain validity.

  DMARC          Domain-based Message Authentication record — presence,
                 policy level (none / quarantine / reject), pct= enforcement
                 percentage, and sp= subdomain policy.

  MX             Mail exchanger records — presence, null MX (RFC 7505),
                 and host list.

  IP / ASN       Resolves IPv4 and IPv6 addresses, looks up the BGP prefix
                 and originating ASN via RIPEstat, checks RPKI validity
                 (valid / invalid / not-found), and verifies IRR/RIS
                 route presence.

  DNSSEC         Checks whether the TLD is signed, whether the domain
                 publishes a DNSKEY, and whether a validating resolver
                 returns the AD (Authenticated Data) flag.

  TLS            Connects on port 443, records the negotiated TLS version,
                 certificate validity dates, lifetime, issuer, and whether
                 the certificate SANs match the domain.

  HTTP→HTTPS     Follows the full redirect chain from http:// and reports
                 whether plain HTTP is reachable or redirects to HTTPS.
                 Note: browser behaviour may differ (browsers auto-upgrade
                 to HTTPS). Use  curl -v http://domain  or  iwr http://domain
                 to verify the raw HTTP response.

  HSTS           Checks for the Strict-Transport-Security header, max-age,
                 includeSubDomains, preload directive, and whether the TLD
                 is on the HSTS preload list.

  Server         Inspects Server and X-Powered-By headers, infers OS from
                 IIS version strings, fingerprints the technology stack
                 (WordPress, Drupal, Next.js, Shopify, etc.), and checks
                 browser security headers: CSP, X-Frame-Options,
                 X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

  Redirect       Detects HTTP → HTTPS redirects at the domain level.
  (email split)  When a website redirects to a different domain, SPF,
                 DMARC, and MX are fully audited and scored for both the
                 source domain and the redirect target independently.
                 Both appear as separate sections in the report.

  SSL Labs       Optional deep TLS assessment via the Qualys SSL Labs API v4.
                 Requires a registered email (--sslregistration) and the
                 --ssl flag. Returns a grade (A+ through F, plus T and M)
                 worth up to 5 points, plus a Findings list of the specific
                 conditions affecting the grade (obsolete protocols, named
                 CVEs like Heartbleed/ROBOT/POODLE, RC4 support, partial
                 forward secrecy, certificate chain issues, etc.). Cached
                 reports are accepted up to 24 hours old; Qualys may evict
                 sooner.

  CAA            DNS Certification Authority Authorization records (RFC 8659):
                 which CAs may issue certificates for this domain. Missing
                 CAA = any public CA can issue. Walks up the label tree.

  Mail transport Hardening for inbound mail: MTA-STS DNS record (RFC 8461),
                 TLS-RPT reporting endpoint (RFC 8460), DANE/TLSA records
                 on each MX host (RFC 7672), and a probe of common DKIM
                 selectors. The DKIM probe is a partial check only — DKIM
                 selectors are arbitrary, so absence proves nothing.

  CSP detail     Google CSP Evaluator-style breakdown of any
                 Content-Security-Policy header: script-src safety
                 (strict / nonce-or-hash / host-allowlist / unsafe-inline /
                 wildcard-or-scheme), object-src, base-uri, frame-ancestors,
                 enforcement mode (Content-Security-Policy vs. Report-Only).

  Cross-origin   Cross-Origin-Opener-Policy (COOP), Cross-Origin-Resource-
                 Policy (CORP), Cross-Origin-Embedder-Policy (COEP),
                 Origin-Agent-Cluster.

  Misc hardening Server clock skew (Date: header vs. local UTC),
                 Redirect first-hop hygiene (Mozilla rule: first hop should
                 be HTTPS on the same host), Cert SAN coverage of www
                 variant, X-XSS-Protection deprecation warning, HSTS
                 max-age strength (≥6 months), Cookie name prefixes
                 (__Host- / __Secure-) validated per RFC 6265bis,
                 Nameserver count (RFC 1034 ≥2 recommended),
                 HTTPS response-time estimate from the redirect GET.

  Page-level     SRI on external scripts/stylesheets, in-page mixed
                 content (HTTP resources on HTTPS pages), third-party
                 origin inventory (Webbkoll-style), and indicative
                 accessibility signals (alt, label, lang — NOT a
                 substitute for WAVE/Axe/pa11y). Gated to --deep,
                 since bot-mitigation challenge pages produce unreliable
                 findings on a meaningful share of real domains and the
                 body capture costs ~1MB per domain.

  Versioned      Detects ~185 client-side JavaScript and CSS libraries from
  libraries      script src filenames, CDN paths, inline banner comments, and
                 generator meta tags (frameworks, UI kits, charts, editors,
                 utilities, CMS). Of these, 28 common libraries (jQuery,
                 Bootstrap, Angular, Vue, etc.) are checked against curated
                 EOL data in library_eol.json — old majors are flagged with
                 their last-release dates. The remaining ~150 are reported
                 with their detected version but no EOL judgment. Runs by
                 default.

  --deep checks  The slow / thorough additions that --deep enables:

                 DANE TLSA      DNS TLSA queries on each MX host (RFC
                                7672). 5s lifetime per host because
                                resolvers handle TLSA poorly when the
                                MX zone isn't DNSSEC-signed; the slowest
                                single host bounds the wall time.

                 STARTTLS-MX    Opens port 25 to each MX host,
                                EHLO/STARTTLS, inspects the cert. 10s
                                timeout per host. Port 25 egress is
                                blocked from many cloud providers and
                                residential ISPs — partial results are
                                normal in those environments.

                 Page Analysis  SRI, mixed content, third-party origins,
                                and a11y signals from a parse of the
                                page HTML. Gated to --deep because
                                bot-mitigation challenge pages produce
                                unreliable findings.

                 5MB body cap   Page-body capture is raised from 256KB
                                (default — enough for server/CMS finger-
                                printing and library version detection)
                                to 5MB so the page parser can see large
                                server-rendered CMS pages. Costs extra
                                bandwidth on big pages but gives accurate
                                <img> / <input> / SRI counts.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SWITCHES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  domain         Positional. The domain to audit. May be passed with or
                 without a scheme (https:// is stripped automatically).
                   python3 vendor_audit.py example.com

  --domain DOMAIN
                 Named alternative to the positional argument. Useful when
                 calling from scripts where positional args are awkward.
                   python3 vendor_audit.py --domain example.com

  --file FILE    Path to a plain-text file with one domain per line.
                 Lines starting with # are treated as comments and skipped.
                 Domains are audited concurrently (10 at a time).
                 Requires --outcsv.
                   python3 vendor_audit.py --file domains.txt --outcsv out.csv

  --outcsv CSV   Path to the CSV output file.
                 - Required when --file is used.
                 - Optional in single-domain mode (terminal output is shown
                   either way).
                 - If the file already exists, rows are appended and the
                   header is not repeated, so you can accumulate results
                   across multiple runs.
                   python3 vendor_audit.py example.com --outcsv results.csv

  --json         Print raw JSON to stdout instead of the formatted report.
                 Single-domain mode only. Useful for piping into jq or
                 other tooling. --outcsv can be combined with --json.
                   python3 vendor_audit.py example.com --json | jq .spf

  --dns-server IP
                 Use a specific DNS resolver for all queries instead of
                 the system default. Useful for testing against authoritative
                 nameservers or comparing results between resolvers.
                 Accepts any valid IPv4 address.
                   python3 vendor_audit.py example.com --dns-server 1.1.1.1
                   python3 vendor_audit.py example.com --dns-server 8.8.8.8

  --http-timeout SECONDS
                 Per-operation socket timeout in seconds (default: 5). Applies
                 to each connect/recv individually. A black-holed host that never
                 responds may still take 2-3x this value before the script moves
                 on, due to https->http fallback retries within each check.
                 Lower for faster bulk scans; raise for legitimately slow servers.
                   python3 vendor_audit.py example.com --http-timeout 5
                   python3 vendor_audit.py --file domains.txt --outcsv out.csv --http-timeout 5

  --sslregistration
                 Interactive one-time registration with the Qualys SSL Labs API.
                 Required before --ssl can be used. Prompts for name, email,
                 and organisation, then submits to the SSL Labs /register endpoint.
                 Use a non-free-email-service address (no Gmail, Yahoo, etc.).
                   python3 vendor_audit.py --sslregistration

  --ssl EMAIL    Run a Qualys SSL Labs assessment for the domain using the given
                 registered email address. The grade is incorporated into the
                 score (5 points), and the report includes a Findings list
                 explaining the conditions affecting the grade (vulnerable
                 protocols, missing forward secrecy, chain issues, etc.).
                 Cached reports up to 24 hours old are accepted by default;
                 Qualys may evict sooner.
                   python3 vendor_audit.py example.com --ssl you@yourorg.com

  --ssl-no-cache
                 Force a fresh SSL Labs assessment, switching from
                 fromCache=on to startNew=on (the two are mutually exclusive).
                 Note: a fresh scan can also be triggered automatically
                 without this flag if Qualys has evicted the cached result.
                   python3 vendor_audit.py example.com --ssl you@yourorg.com --ssl-no-cache

  --ssl-max-age HOURS
                 Client-side filter on cached SSL Labs reports — older than
                 this is treated as a miss (default: 24 hours, matching
                 the SSL Labs reference clients). Does not extend Qualys's
                 retention. Ignored when --ssl-no-cache.
                   python3 vendor_audit.py example.com --ssl you@yourorg.com --ssl-max-age 168

  --ssl-publish  Publish the SSL Labs results to the public scoreboard at
                 ssllabs.com. Default is private. Use with caution on sensitive
                 or internal domains.
                   python3 vendor_audit.py example.com --ssl you@yourorg.com --ssl-publish

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMMON RECIPES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Single domain, terminal output only:
    python3 vendor_audit.py example.com

  Single domain, save to CSV:
    python3 vendor_audit.py example.com --outcsv results.csv

  Single domain, raw JSON:
    python3 vendor_audit.py example.com --json

  Bulk audit from a file, results to CSV:
    python3 vendor_audit.py --file domains.txt --outcsv results.csv

  Bulk audit using Cloudflare DNS:
    python3 vendor_audit.py --file domains.txt --outcsv results.csv --dns-server 1.1.1.1

  Bulk audit with one plain-text report per domain (in cwd):
    python3 vendor_audit.py --file domains.txt --outcsv results.csv --report

  Bulk audit with reports written to a named directory:
    python3 vendor_audit.py --file domains.txt --outcsv results.csv --report reports/

  Single domain with SSL Labs assessment:
    python3 vendor_audit.py example.com --ssl you@yourorg.com

  Force a fresh SSL Labs scan (bypass cache):
    python3 vendor_audit.py example.com --ssl you@yourorg.com --ssl-no-cache

  Accumulate results across multiple runs (CSV is appended, not overwritten):
    python3 vendor_audit.py batch1.txt --outcsv master.csv
    python3 vendor_audit.py batch2.txt --outcsv master.csv

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXIT CODES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  0  Script ran successfully. Domain-level findings (missing SPF, bad
     DMARC policy, etc.) do not affect the exit code.
  1  Hard failure: bad arguments, missing --file path, or unrecoverable
     startup error.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROJECT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Source, issues, and contributions:
  https://github.com/chrono1313/Vendor-Audit
""",
    )

    # ── Input — mutually exclusive ───────────────────────────────────────────
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("domain", nargs="?",
                             help="Domain to audit, e.g. example.com")
    input_group.add_argument("--domain", dest="domain_flag", metavar="DOMAIN",
                             help="Domain to audit (named alternative to positional argument)")
    input_group.add_argument("--file", metavar="FILE",
                             help="Text file with one domain per line; lines starting with # are skipped")

    # ── Output ────────────────────────────────────────────────────────────────
    # --outcsv semantics:
    #   --outcsv path.csv   → explicit path (string)
    #   --outcsv            → AUTO sentinel; auto-generate timestamped name
    #   (omitted)           → None; do not write a CSV
    # The sentinel disambiguates "omitted" from "passed bare without a value":
    # without it, argparse would produce None for both and a bare --outcsv
    # would silently drop the CSV in single-domain mode.
    parser.add_argument("--outcsv", metavar="CSV", nargs="?", const="__AUTO__",
                        help="CSV output path. With --file, defaults to "
                             "vendor_audit_YYYY-MM-DDTHH-MM-SS.csv in the current "
                             "directory if --outcsv is given without a value. "
                             "Same auto-naming applies in single-domain mode: "
                             "bare --outcsv produces a timestamped CSV. Pass an "
                             "explicit path to override.")
    parser.add_argument("--concurrency", metavar="N", type=int, default=None,
                        help=f"Number of domains audited in parallel during --file bulk runs "
                             f"(default: {DOMAIN_WORKERS}). Ignored when --ssl is set: "
                             f"--ssl forces sequential execution (one domain at a time) "
                             f"because each domain's SSL Labs assessment must complete in "
                             f"full before the next starts.")
    parser.add_argument("--json", action="store_true",
                        help="Print raw JSON instead of the formatted report (single-domain mode only)")

    # Detailed plain-text report. Pre-resolves to an auto-named
    # "<domain>_<ISO-with-time>.txt" when the flag is given without a
    # value, mirroring --outcsv's pattern. In single-domain mode an
    # explicit value is treated as the output file path. In bulk mode
    # (with --file) an explicit value is treated as a destination
    # *directory* — one file per domain is written into it.
    parser.add_argument("--report", metavar="TXT_OR_DIR", nargs="?", const="__AUTO__",
                        help="Write a detailed plain-text technical report. "
                             "Single-domain: with no value, the report is written to "
                             "<domain>_<ISO-with-time>.txt in the current directory; "
                             "pass an explicit path to override. "
                             "Bulk (with --file): one report per successfully-audited "
                             "domain. With no value the reports are written to the "
                             "current directory; pass a directory path to override "
                             "(it will be created if it does not exist). The files are "
                             "UTF-8 encoded and 100 columns wide.")

    # ── DNS / network ─────────────────────────────────────────────────────────
    parser.add_argument("--dns-server", metavar="IP",
                        help="DNS resolver IP for all queries, e.g. 1.1.1.1 or 8.8.8.8 (default: system resolver)")
    parser.add_argument("--http-timeout", metavar="SECONDS", type=int, default=5,
                        help="Per-operation socket timeout in seconds (default: 5); a dead host may take 2-3x this value before moving on")

    # ── SSL Labs ──────────────────────────────────────────────────────────────
    parser.add_argument("--ssl", metavar="EMAIL",
                        help="Run a Qualys SSL Labs assessment for the domain using this registered email. "
                             "The email is sent to Qualys as an HTTP header on every API call (plaintext over TLS). "
                             "Example: python3 vendor_audit.py example.com --ssl you@yourorg.com")
    parser.add_argument("--sslregistration", action="store_true",
                        help="Interactively register an email address with the SSL Labs API (one-time). "
                             "Required before --ssl can be used.")
    parser.add_argument("--ssl-publish", action="store_true",
                        help="Publish SSL Labs results to the public scoreboard (default: private).")
    parser.add_argument("--ssl-no-cache", action="store_true",
                        help="Force a fresh SSL Labs assessment even if a cached result is available. "
                             "Note: Qualys may evict their own cache before maxAge — a fresh "
                             "assessment can be triggered automatically even without this flag.")
    parser.add_argument("--ssl-max-age", metavar="HOURS", type=int, default=24,
                        help="Client-side filter on cached SSL Labs reports — reports older than "
                             "this are treated as a miss, triggering a fresh scan "
                             "(default: 24 hours). Does not extend Qualys's retention. "
                             "Ignored when --ssl-no-cache is set.")

    # ── Deep mode ─────────────────────────────────────────────────────────────
    parser.add_argument("--deep", action="store_true",
                        help="Run a slower, more thorough scan. Adds four things on top of the "
                             "default: (1) DANE TLSA records on every MX host (5s DNS lifetime, "
                             "frequently slow when the MX zone isn't DNSSEC-signed); (2) the "
                             "STARTTLS-MX probe (10s timeout per MX host, often blocked outbound "
                             "from cloud and residential networks); (3) Page Analysis (SRI, "
                             "mixed content, third-party origins, a11y signals — gated to --deep "
                             "because bot-mitigation pages produce unreliable findings and the "
                             "body capture costs ~1MB per domain); (4) a 5MB page-body capture "
                             "cap (vs 256KB default), so the page parser sees the full HTML "
                             "even on large server-rendered CMS pages. Adds 5-30s to the scan.")

    # ── Versioning ────────────────────────────────────────────────────────────
    parser.add_argument("--version", action="store_true",
                        help="Print version info for all components and exit.")

    args = parser.parse_args()

    # Wire audit module log messages into the CLI's stderr output.
    # The audit module emits its progress via logging.getLogger("vendor_audit.audit");
    # without this call, those messages are silently dropped.
    _install_audit_logging()

    if args.version:
        for name, ver in _VERSIONS.items():
            print(f"  {name:<22}  {ver}")
        return

    # ── SSL Labs registration (standalone — no domain required) ───────────────
    if args.sslregistration:
        cmd_sslregistration()
        return

    flags = []
    if args.deep:
        flags.append("--deep")
    if args.ssl:
        flags.append("--ssl")
    flag_str = ("   [" + " ".join(flags) + "]") if flags else ""
    print(f"vendor_audit.py  v{__version__}{flag_str}")
    print(f"{c(GREY, 'Free software, GNU GPL v3 — no warranty. See LICENSE.')}")
    print(f"{c(GREY, 'https://github.com/chrono1313/Vendor-Audit')}")
    print()

    # ── One-time global configuration ────────────────────────────────────────
    # Set via the audit_checks setters (no cross-module global mutation).
    # Must happen BEFORE any worker thread starts.
    if args.http_timeout is not None:
        set_http_timeout(args.http_timeout)
    if args.dns_server:
        set_dns_server(args.dns_server)
    set_deep(args.deep)

    # ── Validation / dispatch ────────────────────────────────────────────────
    if args.file:
        # Bulk mode: always write a CSV. If --outcsv wasn't given (None) or
        # was given without a value (sentinel), auto-generate a timestamped
        # name in the cwd. _resolve_outcsv() returns None only for None
        # input, which we then convert to an auto name; for the sentinel and
        # explicit paths it returns the right thing directly.
        outcsv_path = _resolve_outcsv(args.outcsv) or _auto_outcsv_name()
        if args.outcsv in (None, _OUTCSV_AUTO_SENTINEL):
            print(c(GREY, f"  No --outcsv path given — writing to {c(BOLD, outcsv_path)}"))

        # In bulk mode --report (when given) means "one .txt per domain".
        # The argparse value is interpreted as a destination *directory*
        # rather than a single filename — a single path can't hold N
        # reports. Sentinel (bare flag) → ./reports/; explicit value → that
        # directory, created if it does not exist; None → reports off.
        report_dir = None
        if args.report is not None:
            if args.report == _REPORT_AUTO_SENTINEL:
                report_dir = _ensure_reports_dir()
            else:
                report_dir = args.report
                try:
                    os.makedirs(report_dir, exist_ok=True)
                except OSError as e:
                    parser.error(f"cannot create --report directory {report_dir!r}: {e}")
            print(c(GREY, f"  Reports will be written to {c(BOLD, report_dir)}"))

        try:
            with open(args.file, encoding="utf-8") as fh:
                domains = [
                    ln.strip() for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")
                ]
        except OSError as e:
            parser.error(f"cannot read --file: {e}")

        if not domains:
            parser.error(f"--file {args.file!r} contains no domains")

        ssl_args = None
        if args.ssl:
            ssl_args = {
                "email":      args.ssl,
                "publish":    getattr(args, "ssl_publish", False),
                "from_cache": not getattr(args, "ssl_no_cache", False),
                "max_age":    getattr(args, "ssl_max_age", 24),
            }

        concurrency = args.concurrency if args.concurrency is not None else DOMAIN_WORKERS

        if ssl_args:
            print(c(GREY, "  SSL Labs bulk mode: one domain at a time — backs off 60s if rate limited"))

        run_bulk(domains, outcsv_path, ssl_args=ssl_args, concurrency=concurrency, report_dir=report_dir)

    else:
        domain = args.domain_flag or args.domain
        if not domain:
            parser.error(
                "a domain is required — pass it positionally, via --domain, or use --file"
            )

        _outcome = audit.run_audit(domain, ssl_active=bool(args.ssl))
        original, audit_domain, results, timestamp = (
            _outcome["domain"], _outcome["audit_domain"],
            _outcome["results"], _outcome["timestamp"],
        )

        # SSL Labs runs before render so the grade feeds into the score.
        if args.ssl:
            ssl_result = cmd_ssl_scan(
                audit_domain,
                email=args.ssl,
                publish=getattr(args, "ssl_publish", False),
                from_cache=not getattr(args, "ssl_no_cache", False),
                max_age=getattr(args, "ssl_max_age", 24),
            )
            if ssl_result:
                results["ssl_labs"] = ssl_result

        if args.json:
            # Strip non-serialisable internals before dumping. We keep
            # _scan (timing + version metadata) since it's useful to
            # consumers, but rename it to drop the underscore prefix.
            scan_meta = results.get("_scan")
            results_clean = {k: v for k, v in results.items() if not k.startswith("_")}
            if scan_meta:
                results_clean["scan"] = scan_meta
            print(json.dumps({"timestamp": timestamp, **results_clean}, indent=2, default=str))
        else:
            render(original, audit_domain, results, dns_server=args.dns_server)

        # Resolve --outcsv: explicit path, AUTO sentinel (bare --outcsv),
        # or None (flag omitted). Sentinel becomes a timestamped filename;
        # None means "don't write a CSV".
        outcsv_path = _resolve_outcsv(args.outcsv)
        if outcsv_path:
            row = results_to_csv_row(original, audit_domain, results, timestamp)
            file_exists = os.path.isfile(outcsv_path)
            if file_exists:
                try:
                    with open(outcsv_path, newline="", encoding="utf-8") as _fh:
                        existing_fields = next(csv.reader(_fh), [])
                    if existing_fields != CSV_FIELDS:
                        raise SystemExit(
                            f"[!] CSV schema mismatch: {outcsv_path!r} was created with a "
                            f"different version of vendor_audit.py.\n"
                            f"    Rename or remove the existing file before appending new results."
                        )
                except (OSError, StopIteration):
                    pass
            with open(outcsv_path, "a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row)
            print(f"\n{c(GREEN, '✔')} Result written to {c(BOLD, outcsv_path)}")

        # ── Plain-text report (--report) ─────────────────────────────────────
        # In single-domain mode --report writes one detailed .txt at the
        # given path (or auto-named if the flag is bare). Bulk-mode
        # report writing is handled inside run_bulk(). Module is already
        # imported at module load (for the version-mismatch guard), so
        # this is just a function call.
        report_path = _resolve_report(args.report, original)
        if report_path:
            try:
                audit_txt_report.write_txt_report(
                    original_domain=original,
                    audit_domain=audit_domain,
                    results=results,
                    timestamp=timestamp,
                    out_path=report_path,
                    report_version=audit_txt_report.__version__,
                )
                print(f"{c(GREEN, '✔')} Report written to {c(BOLD, report_path)}")
            except OSError as e:
                print(f"{c(RED, '✘')} Failed to write report: {e}")

    # ── Footer ───────────────────────────────────────────────────────────────
    # Printed after every real audit run (not after --version or
    # --sslregistration, which return early before the banner).
    print()
    print(c(GREY, "https://github.com/chrono1313/Vendor-Audit"))


if __name__ == "__main__":
    main()
