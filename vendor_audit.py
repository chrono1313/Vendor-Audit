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

__version__ = "1.0"

import os
import sys
import csv
import json
import time
import random
import socket
import argparse
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
    import requests  # noqa: F401
    import urllib3   # noqa: F401
except ImportError:
    _MISSING.append("requests")

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
import audit_checks
from audit_checks import (
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
from audit_render import (
    render, results_to_csv_row, error_csv_row, CSV_FIELDS,
    BOLD, GREY, RED, GREEN, YELLOW, CYAN, RESET, c,
)

# ── Cross-module version sanity check ─────────────────────────────────────────
# All four files (this one, audit_checks, audit_render, scoring_rubric.json)
# carry their own version. If they're out of sync — usually because someone
# updated one file but not the others — fail loudly at startup rather than
# producing subtly wrong scores.

import audit_render  # for version check
import audit_txt_report  # for version check
_RUBRIC_VERSION = audit_checks.RUBRIC.get("rubric_version", "?")
_VERSIONS = {
    "vendor_audit.py":      __version__,
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


def _auto_outcsv_name() -> str:
    """Generate a timestamped filename for auto-named CSVs.

    Format: vendor_audit_2026-04-26T13-42-09.csv (ISO 8601 date + 'T' separator
    + dash-separated time; no colons since some filesystems and shells dislike
    them). Local time, since CSVs are typically reviewed by an operator on the
    same machine that produced them.
    """
    return datetime.now().strftime("vendor_audit_%Y-%m-%dT%H-%M-%S.csv")


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
        return os.path.join(value, _auto_outcsv_name())
    return value


# Same sentinel mechanism for --report (text technical report). Auto-name
# is "<domain>_<ISO-with-time>.txt" — domain-keyed rather than
# vendor_audit-prefixed because the report is single-domain by design,
# so the filename should lead with the domain it describes.
_REPORT_AUTO_SENTINEL = "__AUTO__"


def _auto_report_name(domain):
    """Return a default --report filename for the given domain. Uses
    the same ISO-with-time format as the CSV auto-naming so timestamps
    sort lexicographically and a CSV + TXT pair from the same scan
    sit next to each other in a directory listing."""
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    return datetime.now().strftime(f"{safe_domain}_%Y-%m-%dT%H-%M-%S.txt")


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
        return os.path.join(value, _auto_report_name(domain))
    return value


# ── Thread-safe print + timestamp ─────────────────────────────────────────────

_print_lock = threading.Lock()


def _tprint(*args, **kwargs):
    """Print with a lock so parallel domain output doesn't interleave.
    Prefixes each line with a HH:MM:SS timestamp for timing diagnostics.
    """
    ts = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        if args and isinstance(args[0], str):
            print(f"{c(GREY, ts)}  {args[0]}", *args[1:], **kwargs)
        else:
            print(f"{c(GREY, ts)} ", *args, **kwargs)


# ── Domain normalisation ──────────────────────────────────────────────────────

def normalize_domain(raw):
    """Convert a URL or messy input into a bare ASCII (Punycode) domain name.

    Examples:
      https://www.co.coos.or.us/foo/bar  →  co.coos.or.us
      https://例え.jp                    →  xn--r8jz45g.jp
      WWW.EXAMPLE.com.                   →  example.com

    IDNA encoding (RFC 5891): non-ASCII labels are converted to their A-label
    Punycode form. Domain checks (DNS, TLS handshake, HTTP) all need ASCII.
    Without this, dnspython raises and the user sees an inscrutable error.

    If IDNA encoding fails (a label contains characters that don't round-trip
    through Punycode — usually a paste with control chars or emoji), we fall
    back to the original lowercased string and let downstream checks surface
    the failure on their own terms; the script doesn't exit on a bad domain
    in bulk mode.
    """
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    domain = parsed.netloc.lower()
    domain = domain.split(":")[0]    # strip port
    if domain.startswith("www."):
        domain = domain[4:]
    domain = domain.rstrip(".")

    # Pure-ASCII fast path: skip IDNA work entirely (the common case).
    if domain.isascii():
        return domain

    # IDNA encoding for IDN domains. Use the `idna` package because Python's
    # stdlib .encode('idna') uses IDNA 2003 (deprecated) and rejects some
    # valid IDNA 2008 labels.
    try:
        return idna.encode(domain, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Bad label — return the lowercased original; downstream DNS lookup
        # will fail with a clearer error than the IDNA exception would give.
        return domain


# ── Single-domain audit ───────────────────────────────────────────────────────

def run_audit(domain):
    """Run all checks for a single domain. Thread-safe.

    Returns (original_domain, audit_domain, results, timestamp_utc).

    Global configuration (DNS server, HTTP timeout) must be set once before
    any worker thread starts via set_dns_server() and set_http_timeout().
    """
    domain = normalize_domain(domain)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deep = audit_checks.is_deep()

    _tprint(f"\n{c(GREY, 'Running checks for')} {c(BOLD, domain)}{c(GREY, '...')}"
            + (c(YELLOW, "  [--deep]") if deep else ""))

    # ── Per-check timing — used by render() for the "Scan info" footer and by
    # CSV output. A check-name -> seconds dict so we can spot which network
    # call is dominating the wall time.
    check_timings = {}
    scan_t0 = time.monotonic()

    # ── Redirect check first — determines which domain web checks run against
    # In --deep mode we ask for a 5MB body cap (vs 256KB default) so the page
    # parser, which only runs under --deep, can see large server-rendered CMS
    # pages. In default mode the body chunk is consumed by server/CMS finger-
    # printing (the _BODY_SIGNALS regex table) and versioned library detection
    # (check_versioned_libraries), both of which fit comfortably in 256KB.
    body_cap = audit_checks._DEEP_BODY_SNIFF_BYTES if deep else audit_checks._BODY_SNIFF_BYTES
    t = time.monotonic()
    redirect = check_redirect(domain, body_cap=body_cap)
    check_timings["redirect"] = round(time.monotonic() - t, 3)
    audit_domain = redirect["final"] if redirect["redirected"] else domain

    if redirect["redirected"]:
        _tprint(f"  {c(YELLOW, '⚠')} {domain} redirects to {c(BOLD, audit_domain)}"
                f" — email audited for both domains, web/TLS checks against redirect target")

    # Pop the cached response before storing redirect (live Response is not serialisable)
    cached_resp = redirect.pop("_response", None)

    results = {
        "redirect":     redirect,
        "_audit_domain": audit_domain,
        "_deep_mode":   deep,
    }

    # ── Check menu ───────────────────────────────────────────────────────────
    # Email: source domain (always). Web/TLS: audit_domain (after redirect).
    # Email infrastructure belongs to the source — that's the envelope domain
    # regardless of where the website resolves.
    email_checks = [
        ("spf",     lambda d: check_spf(d)),
        ("dmarc",   lambda d: check_dmarc(d)),
        ("mx",      lambda d: check_mx(d)),
        # 2.1.0: mail transport hardening checks (DNS-only)
        ("mta_sts", lambda d: check_mta_sts(d)),
        ("tls_rpt", lambda d: check_tls_rpt(d)),
        ("dkim",    lambda d: check_dkim_common(d)),
    ]

    web_checks = [
        ("ip_routing",    lambda d: check_ip_routing(d)),
        ("dnssec",        lambda d: check_dnssec(d)),
        ("tls",           lambda d: check_tls(d)),
        ("http_version",  lambda d: check_http_version(d)),
        ("hsts",          lambda d: check_hsts(d, _cached_response=cached_resp)),
        ("http_redirect", lambda d: check_http_redirect(d)),
        ("server_header", lambda d: check_server_header(d, _cached_response=cached_resp)),
        ("security_txt",  lambda d: check_security_txt(d)),
        # 2.1.0: DNS hygiene against the audit_domain
        ("caa",           lambda d: check_caa(d)),
        ("ns_soa",        lambda d: check_ns_soa(d)),
    ]

    redirect_email_checks = []
    if redirect["redirected"]:
        redirect_email_checks = [
            ("redirect_target_spf",     lambda d: check_spf(d)),
            ("redirect_target_dmarc",   lambda d: check_dmarc(d)),
            ("redirect_target_mx",      lambda d: check_mx(d)),
            ("redirect_target_mta_sts", lambda d: check_mta_sts(d)),
            ("redirect_target_tls_rpt", lambda d: check_tls_rpt(d)),
            ("redirect_target_dkim",    lambda d: check_dkim_common(d)),
        ]

    all_checks = (
        [(key, fn, domain)       for key, fn in email_checks] +
        [(key, fn, audit_domain) for key, fn in web_checks] +
        [(key, fn, audit_domain) for key, fn in redirect_email_checks]
    )

    # ── Run all checks in parallel ────────────────────────────────────────────
    # Each check is wrapped in a timer so we can attribute slow wall-time
    # to specific network calls (RIPEstat, hstspreload.org, security.txt
    # candidates, etc.). The wrapper returns (result, elapsed_s).
    def _timed(fn, target):
        t0 = time.monotonic()
        try:
            return fn(target), time.monotonic() - t0, None
        except Exception as e:
            return None, time.monotonic() - t0, e

    pool_t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(all_checks)) as ex:
        futures = {ex.submit(_timed, fn, target): key for key, fn, target in all_checks}
        for future in as_completed(futures):
            key = futures[future]
            res, elapsed, exc = future.result()
            check_timings[key] = round(elapsed, 3)
            if exc is not None:
                results[key] = {"error": str(exc)}
            else:
                results[key] = res
    check_timings["_pool_wall"] = round(time.monotonic() - pool_t0, 3)

    # ── Post-server-header derived analyses (synchronous, near-instant) ──────
    srv = results.get("server_header") or {}
    mx_entries = (results.get("mx") or {}).get("entries") or []

    # CSP analysis from the header we already have
    if not srv.get("error"):
        results["csp_analysis"] = analyze_csp(
            srv.get("csp"),
            csp_report_only=bool(srv.get("csp_report_only")),
        )

    # Server clock skew from the Date: header we already captured
    results["clock"] = check_clock_skew(srv.get("date"))

    # Cert covers redirect-source/target variant
    tls_r = results.get("tls") or {}
    sans = tls_r.get("cert_san_names") or []
    results["cert_variant"] = check_cert_covers_variant(audit_domain, domain, sans)

    # ── Mark unresolvable domains ─────────────────────────────────────────────
    ipr   = results.get("ip_routing", {})
    no_v4 = not ipr.get("v4", {}).get("address")
    no_v6 = not ipr.get("v6", {}).get("address")
    if no_v4 and no_v6:
        results["_unresolvable"] = True

    # ── Post-pool extras (run in parallel) ────────────────────────────────────
    # Default-mode jobs (always run):
    #   - versioned_libs: regex-scan the captured body for client-side library
    #     versions (jQuery, Bootstrap, Font Awesome, etc.) and cross-reference
    #     against library_eol.json. Pure local CPU on existing data; new in
    #     2.8.0.
    #   - MTA-STS policy fetch: one HTTPS GET to mta-sts.<domain>. Most
    #     domains have no such host, so this fast-fails on DNS resolution.
    #
    # --deep-only jobs (require explicit opt-in):
    #   - page-level analysis: pure local CPU on the body chunk, but the
    #     body chunk itself is expensive to capture (up to 5MB under --deep)
    #     and a meaningful share of pages are bot-mitigation challenges that
    #     produce unreliable findings — opt-in via --deep so default scans
    #     don't pay the bandwidth or get noisy results from challenge pages.
    #   - DANE TLSA on each MX host: TLSA queries to MX hosts that don't
    #     have DANE deployed routinely take 5+ seconds each because many
    #     recursive resolvers handle TLSA poorly when the zone isn't
    #     DNSSEC-signed. There's no way to make this fast without trading
    #     away accuracy.
    #   - STARTTLS-MX probe: opens port 25 to each MX host, EHLO/STARTTLS,
    #     inspects each cert. 10s timeout per host. Port-25 egress is
    #     blocked from many cloud providers and residential ISPs, in
    #     which case the wall time hits the timeout cap.
    #
    # All jobs in the batch run concurrently, so the wall-time addition
    # is bounded by the slowest single one.
    rt_mx_entries = []
    if redirect["redirected"]:
        rt_mx_entries = (results.get("redirect_target_mx") or {}).get("entries") or []

    if not results.get("_unresolvable"):
        page_url   = redirect.get("final") or audit_domain
        body_bytes = getattr(cached_resp, "_body_chunk", b"") if cached_resp is not None else b""
        body_html  = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

        post_pool_jobs = []

        # Default-mode jobs
        if body_html:
            post_pool_jobs.append((
                "versioned_libs",
                lambda: check_versioned_libraries(body_html),
            ))
        if mx_entries:
            post_pool_jobs.append(("mta_sts_policy", lambda: check_mta_sts_policy(domain)))
            if redirect["redirected"]:
                post_pool_jobs.append((
                    "redirect_target_mta_sts_policy",
                    lambda: check_mta_sts_policy(audit_domain),
                ))

        # --deep-only jobs
        if deep:
            if body_html:
                post_pool_jobs.append((
                    "page_signals",
                    lambda: check_page_security_signals(
                        body_html,
                        page_url=f"https://{page_url}/" if not page_url.startswith("http") else page_url,
                        audit_domain=audit_domain,
                    ),
                ))
            if mx_entries:
                post_pool_jobs.append(("dane", lambda: check_dane(domain, mx_entries)))
                post_pool_jobs.append(("starttls_mx", lambda: check_starttls_mx(mx_entries)))
            if rt_mx_entries:
                post_pool_jobs.append((
                    "redirect_target_dane",
                    lambda: check_dane(audit_domain, rt_mx_entries),
                ))

        if post_pool_jobs:
            # Use a zero-arg timed wrapper since these callables don't take a
            # target argument (we baked it into the lambda above).
            def _timed_call(fn):
                t0 = time.monotonic()
                try:
                    return fn(), time.monotonic() - t0, None
                except Exception as e:
                    return None, time.monotonic() - t0, e

            with ThreadPoolExecutor(max_workers=len(post_pool_jobs)) as pp_ex:
                pp_futs = {pp_ex.submit(_timed_call, fn): key for key, fn in post_pool_jobs}
                for fut in as_completed(pp_futs):
                    key = pp_futs[fut]
                    res, elapsed, exc = fut.result()
                    check_timings[key] = round(elapsed, 3)
                    if exc is not None:
                        if key == "page_signals":
                            results[key] = {"parsed": False, "error": str(exc)}
                        elif key == "versioned_libs":
                            results[key] = {"libraries": [], "any_eol": False, "error": str(exc)}
                        elif key in ("dane", "redirect_target_dane", "starttls_mx"):
                            results[key] = {"error": str(exc)}
                        else:
                            results[key] = {"fetched": False, "error": str(exc)}
                    else:
                        results[key] = res

    # ── OS EOL detection (2.9.0, default mode) ────────────────────────────────
    # Pure CPU on data already collected (Server header + TLS result), so we
    # run it synchronously after the post-pool join. No network I/O, no
    # thread pool needed. Robust against missing inputs: check_os_eol takes
    # an empty header and a None tls_result.
    server_hdr = (results.get("server_header") or {}).get("server") or ""
    tls_result = results.get("tls") or {}
    os_t0 = time.monotonic()
    try:
        results["os_eol"] = check_os_eol(server_hdr, tls_result)
    except Exception as exc:
        results["os_eol"] = {"os_findings": [], "any_eol": False,
                             "tls_old_stack": False, "tls_signals": [],
                             "error": str(exc)}
    check_timings["os_eol"] = round(time.monotonic() - os_t0, 3)

    # ── Record total scan wall time + per-check timings for the report ───────
    scan_elapsed = round(time.monotonic() - scan_t0, 3)
    results["_scan"] = {
        "elapsed_s":      scan_elapsed,
        "check_timings":  check_timings,
        "deep":           deep,
        "version":        __version__,
    }

    _tprint(f"  {c(GREEN, 'done')} {domain}  {c(GREY, f'({scan_elapsed:.1f}s)')}")
    return domain, audit_domain, results, timestamp


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
        resp = requests.post(url, headers=headers, json=json_body or {}, timeout=timeout)
    else:
        headers = {}
        if email:
            headers["email"] = email
        resp = requests.get(url, headers=headers, params=params or {}, timeout=timeout)

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


def _extract_ssllabs_findings(endpoint):
    """Decode a single SSL Labs endpoint's details into human-readable findings.

    SSL Labs does not return a flat 'warnings' list — the warnings shown in
    the web UI are derived by inspecting individual fields in the details
    object (booleans, status integers, bitfields). This function reproduces
    that decoding for the conditions most commonly responsible for grade
    caps and A→A- demotions.

    Returns a list of strings. Each string is one finding. Empty list means
    nothing wrong was detected — but absence of evidence isn't evidence of
    absence: SSL Labs's grading criteria evolve, and we only check the
    dozen-or-so most common conditions. The full report is always one click
    away on ssllabs.com.

    Conventions:
      - boolean True = problem (vulnBeast, heartbleed, freak, …)
      - status ints: 1 means "not vulnerable"; 0 = unknown, -1 = test failed,
        ≥2 = some flavour of vulnerable. We surface ≥2 only.
      - bitfields (renegSupport, forwardSecrecy, certChain.issues) are
        decoded bit-by-bit; only the problematic bits emit findings.

    Field reference: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md#endpointdetails
    """
    findings = []
    details  = endpoint.get("details") or {}

    # ── Protocols ─────────────────────────────────────────────────────────────
    # Each entry: {"name": "TLS", "version": "1.2", ...}.
    # Obsolete protocols cap the grade. Missing TLS 1.3 is not a grade cap
    # but is widely treated as a posture warning, and other parts of this
    # audit already check it locally — surfacing it here lets the SSL Labs
    # section tell a complete story.
    #
    # When the protocols list is missing entirely (failed assessment, no
    # details object) we emit no protocol findings — absence of data is
    # not evidence the protocol is missing.
    protocols = details.get("protocols")
    if protocols:
        proto_versions = {f"{p.get('name', 'TLS')} {p.get('version', '')}".strip()
                          for p in protocols if p.get("version")}
        for obsolete in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
            if obsolete in proto_versions:
                findings.append(f"Obsolete protocol supported: {obsolete}")
        if "TLS 1.3" not in proto_versions:
            findings.append("TLS 1.3 not supported")

    # ── Named vulnerability tests (boolean) ───────────────────────────────────
    bool_vulns = [
        ("vulnBeast",        "Vulnerable to BEAST"),
        ("heartbleed",       "Vulnerable to Heartbleed (CVE-2014-0160)"),
        ("poodle",           "Vulnerable to POODLE (SSLv3)"),
        ("freak",            "Vulnerable to FREAK (export-grade RSA)"),
        ("logjam",           "Vulnerable to Logjam (weak DH parameters <1024 bits)"),
        ("drownVulnerable",  "Vulnerable to DROWN"),
    ]
    for field, message in bool_vulns:
        if details.get(field) is True:
            findings.append(message)

    # ── Named vulnerability tests (status integers) ──────────────────────────
    # Per spec: 1 = not vulnerable, 0 = unknown, -1 = test failed,
    # higher values indicate degrees of vulnerability. We flag any value ≥2.
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
            findings.append(message)

    # ── Cipher / key exchange posture ────────────────────────────────────────
    if details.get("supportsRc4") is True:
        findings.append("RC4 cipher suites supported")
    # forwardSecrecy is a bitfield: bit 2 (4) = FS with all simulated clients.
    # Healthy value is 7 (1+2+4). Anything less is a warning condition.
    fs = details.get("forwardSecrecy")
    if isinstance(fs, int) and not (fs & 4):
        findings.append("Forward secrecy not achieved with all reference clients")

    # ── Renegotiation ────────────────────────────────────────────────────────
    # bit 0 (1) = insecure client-initiated renegotiation supported (bad).
    reneg = details.get("renegSupport")
    if isinstance(reneg, int) and (reneg & 1):
        findings.append("Insecure client-initiated renegotiation supported")

    # ── Session resumption ───────────────────────────────────────────────────
    # 0 = not enabled, 1 = IDs returned but not resumed, 2 = working.
    sr = details.get("sessionResumption")
    if sr == 0:
        findings.append("Session resumption not enabled")
    elif sr == 1:
        findings.append("Session resumption broken (IDs returned but not resumed)")

    # ── OCSP stapling ────────────────────────────────────────────────────────
    if details.get("ocspStapling") is False:
        findings.append("OCSP stapling not enabled")

    # ── DH parameter reuse / weak primes ─────────────────────────────────────
    if details.get("dhYsReuse") is True:
        findings.append("DH ephemeral server value reused")
    if details.get("ecdhParameterReuse") is True:
        findings.append("ECDHE parameters reused")
    dh_known = details.get("dhUsesKnownPrimes")
    if dh_known == 2:
        findings.append("Weak well-known DH primes in use")

    # ── 0-RTT (TLS 1.3 replay vector) ─────────────────────────────────────────
    if details.get("zeroRTTEnabled") == 1:
        findings.append("TLS 1.3 0-RTT enabled (replay attack vector)")

    # ── Certificate chain issues ─────────────────────────────────────────────
    # certChains[].issues bitfield: bit 1 (2) incomplete, bit 2 (4) unrelated/
    # duplicate certs, bit 3 (8) wrong order, bit 5 (32) couldn't validate.
    # We pick the worst across all chains.
    chain_issues = 0
    for chain in details.get("certChains") or []:
        ci = chain.get("issues")
        if isinstance(ci, int):
            chain_issues |= ci
    if chain_issues & 2:
        findings.append("Certificate chain incomplete")
    if chain_issues & 4:
        findings.append("Certificate chain contains unrelated or duplicate certs")
    if chain_issues & 8:
        findings.append("Certificate chain in incorrect order")
    if chain_issues & 32:
        findings.append("Certificate chain could not be validated")

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

    # Merge findings across endpoints. Most domains have one endpoint, but
    # multi-IP setups can have several — usually a load-balancer pool with
    # near-identical configuration, occasionally with drift between nodes.
    # Per design choice: merge into a single deduped list (order preserved)
    # rather than reporting per-IP, since the score reflects the worst
    # grade across endpoints anyway.
    merged_findings = []
    seen_findings   = set()
    for ep in endpoints:
        for f in _extract_ssllabs_findings(ep):
            if f not in seen_findings:
                seen_findings.add(f)
                merged_findings.append(f)

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

    def _write_per_domain_report(original, audit, results, ts):
        """Write one report for a successfully-audited domain. Failures
        are counted but never re-raised — a single broken report should
        not abort the whole bulk run. Returns True on success."""
        nonlocal reports_written, reports_failed
        if not report_dir:
            return False
        try:
            filename = _auto_report_name(original)
            path = os.path.join(report_dir, filename)
            audit_txt_report.write_txt_report(
                original_domain=original,
                audit_domain=audit,
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
                original, audit, results, ts = run_audit(raw)
                ssl_result = cmd_ssl_scan(
                    audit,
                    email=ssl_args["email"],
                    publish=ssl_args.get("publish", False),
                    from_cache=ssl_args.get("from_cache", True),
                    max_age=ssl_args.get("max_age", 24),
                )
                if ssl_result:
                    results["ssl_labs"] = ssl_result
                rows[idx] = results_to_csv_row(original, audit, results, ts)
                line = _bulk_progress_line(original, rows[idx])
                if line:
                    _tprint(line)
                _write_per_domain_report(original, audit, results, ts)
            except Exception as e:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                rows[idx] = error_csv_row(raw, str(e), ts)
                _tprint(f"{c(RED, '[ERROR]')} {raw}: {e}")
    else:
        # Parallel: standard checks only.
        workers = concurrency if concurrency is not None else DOMAIN_WORKERS

        def _worker(idx, raw):
            try:
                original, audit, results, ts = run_audit(raw)
                rows[idx] = results_to_csv_row(original, audit, results, ts)
                line = _bulk_progress_line(original, rows[idx])
                if line:
                    _tprint(line)
                _write_per_domain_report(original, audit, results, ts)
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
        # reports. Sentinel (bare flag) → cwd; explicit value → that
        # directory, created if it does not exist; None → reports off.
        report_dir = None
        if args.report is not None:
            if args.report == _REPORT_AUTO_SENTINEL:
                report_dir = "."
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

        original, audit_domain, results, timestamp = run_audit(domain)

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
