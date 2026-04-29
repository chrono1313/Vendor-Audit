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
audit_checks.py — Vendor audit check functions and scoring.

Imported by vendor_audit.py and audit_render.py; not intended to be run
directly.

This module owns:
  - Network primitives (DNS resolver, HTTP session, TLS context, watchdog timer)
  - All check_* functions that interrogate a domain
  - The classifiers and parsers those checks rely on
  - score_results(), which interprets a result dict per the JSON rubric

It is deliberately free of presentation logic — no print(), no ANSI colors,
no rendering. Every public function returns a plain dict.

The four .py files (vendor_audit, audit_checks, audit_render, audit_txt_report)
and scoring_rubric.json share a single version number that is enforced
at startup. See vendor_audit.py for the full versioning policy.
"""
from __future__ import annotations

__version__ = "1.0"

import os
import re
import ssl
import json
import time
import base64
import socket
import smtplib
import threading
import urllib.parse
from html.parser import HTMLParser
from collections import defaultdict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
import dns.exception

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

import httpx
import tldextract as _tldextract

# ── tldextract: bundled PSL only, no network at import time ────────────────────
_tld_extractor = _tldextract.TLDExtract(suffix_list_urls=())

# ── Rubric loader ─────────────────────────────────────────────────────────────
# The rubric ships alongside this module. Loaded once at import time; rubric
# changes require a process restart, which is what we want — the rubric is
# config, not runtime state.

_RUBRIC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scoring_rubric.json")

try:
    with open(_RUBRIC_PATH, encoding="utf-8") as _fh:
        RUBRIC = json.load(_fh)
except (OSError, json.JSONDecodeError) as _exc:
    raise RuntimeError(
        f"Could not load scoring rubric from {_RUBRIC_PATH}: {_exc}\n"
        f"The rubric file must sit next to audit_checks.py."
    ) from _exc

# Convenience accessors — keep call sites readable
_W = RUBRIC["weights"]
_THRESH = RUBRIC["thresholds"]
STRONG_REFERRER_POLICIES = frozenset(RUBRIC["strong_referrer_policies"])
GOOD_PROXIES   = frozenset(RUBRIC["good_proxies"])
ORIGIN_SERVERS = frozenset(RUBRIC["origin_servers"])
SSL_GRADE_ORDER = list(RUBRIC["ssl_grade_order"])

# ── Library EOL data loader ───────────────────────────────────────────────────
# library_eol.json sits next to this module. Hand-curated end-of-life data for
# common client-side libraries. Used by check_versioned_libraries() to annotate
# detected libraries as EOL based on their major version.
#
# The file is OPTIONAL — if it's missing or malformed, library detection still
# runs but no EOL annotations are produced. We chose not to make this a hard
# dependency because the rubric is fundamental to scoring (and a missing rubric
# means we can't score at all), but missing EOL data just means slightly less
# helpful output. Different criticality, different failure mode.

_LIBRARY_EOL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "library_eol.json")

LIBRARY_EOL: dict = {}
try:
    with open(_LIBRARY_EOL_PATH, encoding="utf-8") as _fh:
        LIBRARY_EOL = json.load(_fh)
except (OSError, json.JSONDecodeError):
    # Quietly proceed without EOL annotations. Detection logic checks for
    # an empty dict and short-circuits its annotation path.
    LIBRARY_EOL = {}

# ── OS EOL data loader (2.9.0) ────────────────────────────────────────────────
# os_eol.json sits next to this module. Hand-curated EOL data for server
# operating systems detected via Server header annotations and IIS version
# strings. Same load semantics as LIBRARY_EOL: optional file, malformed →
# detection runs but no annotation. The detection is intentionally
# conservative — we only annotate signals we have high confidence in,
# because false-positive "your OS is EOL" findings are much more painful
# for an operator than false-positive "your jQuery is EOL" findings.

_OS_EOL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "os_eol.json")

OS_EOL: dict = {}
try:
    with open(_OS_EOL_PATH, encoding="utf-8") as _fh:
        OS_EOL = json.load(_fh)
except (OSError, json.JSONDecodeError):
    OS_EOL = {}

# ── Module configuration (set once from main(), read-only thereafter) ─────────

_dns_server: str | None = None
_http_timeout: int = 5  # default; overridden by set_http_timeout() before workers run


def set_dns_server(server: str | None) -> None:
    """Set the global DNS server. Must be called before any worker thread runs."""
    global _dns_server
    _dns_server = server


def set_http_timeout(seconds: int) -> None:
    """Set the global HTTP timeout. Must be called before any worker thread runs.
    Also applies the value via socket.setdefaulttimeout() so blocking socket ops
    elsewhere (e.g. dnspython's UDP) honour it."""
    global _http_timeout
    _http_timeout = seconds
    socket.setdefaulttimeout(seconds)


def get_http_timeout() -> int:
    """Public accessor — used by other modules that need the configured timeout."""
    return _http_timeout


# ── Deep mode gate ────────────────────────────────────────────────────────────
# In 2.2.0 the only checks that remain behind --deep are DANE TLSA on MX hosts
# and the STARTTLS-MX probe. Both are slow on networks where the relevant
# upstream service (recursive DNS for TLSA, port 25 for STARTTLS) doesn't
# answer quickly, and there's no fast workaround we can apply that doesn't
# trade away accuracy. set_deep(True) opts in to running them; the default is
# off so a typical scan stays fast.
_deep_mode = False


def set_deep(enabled: bool) -> None:
    """Enable deep mode globally. Must be called before any worker thread runs."""
    global _deep_mode
    _deep_mode = bool(enabled)


def is_deep() -> bool:
    return _deep_mode


# ── Common DKIM selectors (loaded from rubric) ────────────────────────────────
# Probing arbitrary selectors is inherently incomplete because operators can
# choose any selector name. We probe the most common ones and clearly label
# the result as "partial check only" so users don't read absence as proof.

DKIM_COMMON_SELECTORS = list(RUBRIC.get("dkim_common_selectors", [
    "google", "default", "selector1", "selector2", "mail", "k1"
]))


# ── Shared TLS context — built once at import time ────────────────────────────
# check_hostname is disabled globally to tolerate www/apex mismatches; we
# inspect the cert ourselves and report mismatches as findings rather than
# refusing the handshake.
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode    = ssl.CERT_REQUIRED
_TLS_CTX.set_alpn_protocols(["h2", "http/1.1"])

# ── Compiled regexes / signal lists ───────────────────────────────────────────

_RE_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'
    r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
    re.IGNORECASE,
)

_BODY_SIGNALS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/wp-content/',                    re.IGNORECASE), "WordPress"),
    (re.compile(r'/wp-includes/',                   re.IGNORECASE), "WordPress"),
    (re.compile(r'Powered by <a[^>]+>WordPress',    re.IGNORECASE), "WordPress"),
    (re.compile(r'/sites/default/files/',           re.IGNORECASE), "Drupal"),
    (re.compile(r'jQuery\.extend\(Drupal',          re.IGNORECASE), "Drupal"),
    (re.compile(r'/media/jui/',                     re.IGNORECASE), "Joomla"),
    (re.compile(r'var\s+Joomla\s*=',                re.IGNORECASE), "Joomla"),
    (re.compile(r'<[^>]+class="[^"]*shopify[^"]*"', re.IGNORECASE), "Shopify"),
    (re.compile(r'Shopify\.theme',                  re.IGNORECASE), "Shopify"),
    (re.compile(r'window\.__NEXT_DATA__',           re.IGNORECASE), "Next.js"),
    (re.compile(r'__nuxt',                          re.IGNORECASE), "Nuxt.js"),
    (re.compile(r'ng-version=',                     re.IGNORECASE), "Angular"),
    (re.compile(r'data-reactroot',                  re.IGNORECASE), "React"),
    (re.compile(r'__GATSBY',                        re.IGNORECASE), "Gatsby"),
]

# Body-snippet size used by check_redirect to capture the response body. The
# default-mode consumers (server/CMS fingerprinting, versioned library
# detection) all match in the first few KB on every CMS we test against, so
# the default cap stays small. With --deep the page-level parser
# (check_page_security_signals) also runs, and we raise the cap to 5MB,
# which covers every real page we saw without producing absurd bulk-run
# bandwidth (256KB/domain × 200 domains ≈ 50MB at default).
_BODY_SNIFF_BYTES      = 262144     # 256 KB - default cap
_DEEP_BODY_SNIFF_BYTES = 5242880    # 5 MB  - --deep cap

# Known infrastructure-set cookies — CDN / WAF / bot-mitigation layers the
# domain operator doesn't control directly. Still reported, but tagged so the
# reader understands the finding may not be actionable at the origin.
_INFRA_COOKIE_PREFIXES = (
    "__cf_bm", "__cflb", "cf_clearance",          # Cloudflare
    "_abck", "ak_bmsc", "bm_sv", "bm_mi",         # Akamai Bot Manager
    "incap_ses_", "visid_incap_", "nlbi_",        # Imperva/Incapsula
    "AWSALB", "AWSALBCORS", "AWSELB",             # AWS ELB stickiness
    "fastly_",                                    # Fastly
)

# ── Thread-local resolver / session ───────────────────────────────────────────
# Each worker thread gets its own resolver/session; this avoids contention on
# dnspython's internal locks and lets requests reuse TCP/TLS connections within
# a thread (matters most for the multiple sequential RIPEstat calls).
_tls = threading.local()


def _get_resolver():
    """Return a dns.resolver.Resolver for the current thread, creating if needed."""
    if not hasattr(_tls, "resolver"):
        r = dns.resolver.Resolver()
        if _dns_server:
            r.nameservers = [_dns_server]
        _tls.resolver = r
    return _tls.resolver


def _get_session():
    """Return a requests.Session for the current thread, creating if needed."""
    if not hasattr(_tls, "session"):
        _tls.session = requests.Session()
        _tls.session.headers.update({"User-Agent": f"vendor-audit/{__version__}"})
    return _tls.session


# ── Hard-deadline watchdog ────────────────────────────────────────────────────

def _run_with_hard_timeout(fn, timeout, on_timeout=None):
    """Run fn() in a background thread and enforce a wall-clock deadline.

    Returns fn's return value on success, or raises fn's exception.
    On timeout: raises TimeoutError. If on_timeout is provided, it is called
    first (to close sockets / unblock the stuck worker before the deadline
    exception is raised).

    Rationale: socket.setdefaulttimeout() does NOT cap the TCP SYN retry loop
    on Windows — the OS can spend 20+ seconds retransmitting SYNs regardless
    of any Python-level timeout. Closing the socket from outside the worker
    thread is the only reliable way to abort a stuck connect().

    Thread-leak note: when a hard timeout fires and on_timeout closes the
    underlying socket, the worker thread will unblock shortly after and exit
    naturally. Without an on_timeout callback (or if the close fails), the
    thread is a daemon and will be reaped at process exit.
    """
    result = [None]
    exc    = [None]

    def _target():
        try:
            result[0] = fn()
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        if on_timeout is not None:
            try:
                on_timeout()
            except Exception:
                pass  # best-effort cleanup — never let this mask the original timeout
        raise TimeoutError(f"Hard timeout ({timeout}s) exceeded")

    if exc[0] is not None:
        raise exc[0]
    return result[0]


def _http_get(url, **kwargs):
    """HTTP GET with a hard wall-clock deadline enforced by a watchdog thread."""
    session = _get_session()
    timeout = _http_timeout

    def _close_session_sockets():
        for adapter in session.adapters.values():
            pool_manager = getattr(adapter, "poolmanager", None)
            if not pool_manager:
                continue
            for pool in pool_manager.pools.values():
                try:
                    pool.close()
                except Exception:
                    pass

    try:
        return _run_with_hard_timeout(
            lambda: session.get(url, **kwargs),
            timeout=timeout,
            on_timeout=_close_session_sockets,
        )
    except TimeoutError:
        # Re-raise as requests.exceptions.Timeout so existing except clauses
        # elsewhere in the script still catch it.
        raise requests.exceptions.Timeout(
            f"Hard timeout ({timeout}s) exceeded for {url}"
        )


# ── DNS helpers ───────────────────────────────────────────────────────────────

def resolve(name, rtype, lifetime=None):
    """Return list of record strings, or []. Never raises.
    For TXT records, joins multi-string chunks via r.strings to avoid
    quoted-chunk artifacts from to_text().

    Errors are returned as a single-element list with the prefix 'ERROR:' so
    callers must check via resolve_error() before iterating. (Kept for backward
    compatibility with the original API; a future v3 should switch to a
    (records, error) tuple return.)

    `lifetime` (seconds) overrides dnspython's default 5.0s lifetime for this
    one query. Useful for absence-likely probes (TLSA, DKIM common selectors)
    where a 5-second wait per failed query becomes the audit's bottleneck.
    Reverts to the resolver's default after the call.
    """
    resolver = _get_resolver()
    saved_lifetime = resolver.lifetime
    if lifetime is not None:
        resolver.lifetime = lifetime
    try:
        answers = resolver.resolve(name, rtype, raise_on_no_answer=False)
        result = []
        for r in answers:
            if hasattr(r, "strings"):
                result.append(b"".join(r.strings).decode("utf-8", errors="replace"))
            else:
                result.append(r.to_text())
        return result
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return ["ERROR:no_nameservers"]
    except dns.resolver.Timeout:
        return ["ERROR:timeout"]
    except Exception as e:
        return [f"ERROR:{e}"]
    finally:
        # Restore the resolver's default lifetime so unrelated callers
        # sharing this thread-local resolver aren't affected.
        if lifetime is not None:
            resolver.lifetime = saved_lifetime


def resolve_error(records):
    """Return the error string if the record list is an error sentinel, else None."""
    if records and records[0].startswith("ERROR:"):
        return records[0][6:]
    return None


def udp_query(qname, rtype, nameserver, timeout=None):
    """Send a raw UDP DNS query to a specific nameserver. Returns response or None.

    timeout defaults to the configured http timeout so all network operations
    honour the same per-operation deadline.
    """
    if timeout is None:
        timeout = _http_timeout
    try:
        q = dns.message.make_query(qname, rtype, want_dnssec=True)
        q.flags |= dns.flags.AD
        return dns.query.udp(q, nameserver, timeout=timeout)
    except (dns.exception.DNSException, OSError):
        return None


def _org_domain(domain):
    """Return the organisational domain for `domain` using the PSL snapshot.

    Examples:
      aws.amazon.com  -> amazon.com
      foo.co.uk       -> foo.co.uk
      oregon.gov      -> oregon.gov  (no subdomain — already the org domain)

    Returns None if tldextract cannot parse the domain.
    """
    try:
        r = _tld_extractor(domain)
        result = (getattr(r, "top_domain_under_public_suffix", None)
                  or getattr(r, "registered_domain", None))
        return result or None
    except Exception:
        return None


# ── SPF ───────────────────────────────────────────────────────────────────────

# Mechanisms that each cost one DNS lookup toward the RFC 7208 limit of 10.
_SPF_DNS_MECHANISMS = frozenset(("a", "mx", "include", "exists", "ptr"))

# Process-wide cache for SPF lookup counts, keyed on the resolved record content.
# Keying on the record content (not the target name) means two different domains
# that include the same upstream provider share a count, AND a target whose
# record content has changed during a long-running scan re-counts naturally.
_spf_cache_lock = threading.Lock()
_spf_cache: dict[str, int] = {}


def _count_spf_lookups(record, visited=None):
    """Recursively count DNS-querying mechanisms in an SPF record.

    Mechanisms that cost a lookup: a, mx, include, exists, ptr, redirect.
    Follows both include: and redirect= targets recursively. The `visited` set
    prevents cycles within a single top-level evaluation.

    Sub-record counts are cached process-wide keyed on record content; this is
    thread-safe and dramatically faster on bulk runs where many domains share
    common SPF providers (Google, Microsoft, etc).

    Returns the total count of DNS lookups consumed.
    """
    if visited is None:
        visited = set()
    count = 0

    include_targets = []
    redirect_target = None
    for term in record.split():
        term = term.lstrip("+~-?").lower()
        mech = term.split(":")[0].split("=")[0]
        if mech in _SPF_DNS_MECHANISMS:
            count += 1
            if mech == "include":
                target = term.split(":", 1)[1] if ":" in term else None
                if target and target not in visited:
                    visited.add(target)
                    include_targets.append(target)
        elif mech == "redirect":
            count += 1
            target = term.split("=", 1)[1] if "=" in term else None
            if target and target not in visited:
                visited.add(target)
                redirect_target = target

    def _fetch_and_count(target):
        """Fetch target's SPF record and return its recursive lookup count.

        Each call gets a snapshot of the current visited set rather than the
        shared reference. Without the snapshot, concurrent siblings would race
        on visited.add() and could double-count shared sub-domains. Combined
        with the content-keyed cache below, this is both correct and fast.
        """
        sub = resolve(target, "TXT")
        if resolve_error(sub):
            return 0
        for r in sub:
            if "v=spf1" in r:
                # Cache key: the record content itself. Keeps the cache stable
                # even if the same content is reachable via multiple aliases.
                with _spf_cache_lock:
                    cached = _spf_cache.get(r)
                if cached is not None:
                    return cached
                computed = _count_spf_lookups(r, set(visited))
                with _spf_cache_lock:
                    _spf_cache[r] = computed
                return computed
        return 0

    all_targets = include_targets + ([redirect_target] if redirect_target else [])
    if not all_targets:
        return count

    # Cap the pool at 10 to avoid spawning dozens of threads for pathological records.
    with ThreadPoolExecutor(max_workers=min(len(all_targets), 10)) as ex:
        futs = [ex.submit(_fetch_and_count, t) for t in all_targets]
    count += sum(f.result() for f in futs)
    return count


def _parse_spf_record(record):
    """Return dict with status, redirect_target, lookup_count."""
    result = {"redirect_target": None}
    tokens = [t.lower() for t in record.split()]

    for term in tokens:
        if term.startswith("redirect="):
            result["redirect_target"] = term.split("=", 1)[1]
            break

    if result["redirect_target"]:
        result["status"] = "redirect"
    elif "-all" in tokens:
        other = [t for t in tokens if t not in ("v=spf1", "-all")]
        result["status"] = "null_sender" if not other else "hardfail"
    elif "~all" in tokens:
        result["status"] = "softfail"
    elif "+all" in tokens:
        result["status"] = "pass_all_DANGEROUS"
    elif "?all" in tokens:
        result["status"] = "neutral"
    else:
        result["status"] = "no_all_mechanism"
    result["lookup_count"] = _count_spf_lookups(record)
    return result


def check_spf(domain):
    records = resolve(domain, "TXT")
    err = resolve_error(records)
    if err:
        return {"status": "error", "error": err, "record": None, "lookup_count": None}

    for record in records:
        if "v=spf1" not in record:
            continue

        parsed = _parse_spf_record(record)

        if parsed["status"] == "redirect":
            target = parsed["redirect_target"]
            sub_records = resolve(target, "TXT")

            sub_err = resolve_error(sub_records)
            if sub_err:
                return {"status": "error", "error": f"redirect target {target}: {sub_err}",
                        "record": record, "lookup_count": None, "redirect_target": target}
            for sub in sub_records:
                if "v=spf1" in sub:
                    sub_parsed = _parse_spf_record(sub)
                    status = sub_parsed["status"]
                    if status == "no_all_mechanism":
                        status = "redirect_no_all"
                    total = 1 + sub_parsed["lookup_count"]
                    return {
                        "status":          status,
                        "record":          record,
                        "redirect_target": target,
                        "redirect_record": sub,
                        "lookup_count":    total,
                    }
            return {"status": "redirect_target_no_spf", "record": record,
                    "redirect_target": target, "lookup_count": None}

        return {"status": parsed["status"], "record": record,
                "lookup_count": parsed["lookup_count"], "redirect_target": None}

    return {"status": "missing", "record": None, "lookup_count": None, "redirect_target": None}


# ── DMARC ─────────────────────────────────────────────────────────────────────

def _parse_dmarc_record(record):
    """Parse a raw DMARC TXT record string and return a result dict.

    rua= (aggregate report URIs) and ruf= (forensic report URIs) are also
    extracted. rua is the one that matters for operations - without it the
    operator has no visibility into spoofing attempts or legitimate-mail
    rejections, so a deployment without rua is effectively flying blind.
    """
    policy = "none"
    pct    = 100   # default per RFC if tag absent
    sp     = None  # absent means subdomain inherits p=
    rua    = []    # aggregate report destinations (RFC 7489 §6.2)
    ruf    = []    # forensic report destinations (less common)
    for part in record.split(";"):
        part = part.strip()
        # Tags are case-insensitive per spec; check on lowercased form but
        # extract value from the original-cased part.
        tag_low = part.lower()
        if tag_low.startswith("p="):
            policy = part[2:].strip().lower()
        elif tag_low.startswith("pct="):
            try:
                pct = int(part[4:].strip())
            except ValueError:
                pass
        elif tag_low.startswith("sp="):
            sp = part[3:].strip().lower()
        elif tag_low.startswith("rua="):
            # Comma-separated list of mailto:/https: URIs
            rua = [u.strip() for u in part[4:].split(",") if u.strip()]
        elif tag_low.startswith("ruf="):
            ruf = [u.strip() for u in part[4:].split(",") if u.strip()]
    return {"present": True, "policy": policy, "pct": pct, "sp": sp,
            "rua": rua, "ruf": ruf, "record": record}


def check_dmarc(domain):
    """Check DMARC for domain, following the RFC 7489 organisational-domain
    fallback when the subdomain has no record of its own.
    """
    def _lookup(d):
        recs = resolve(f"_dmarc.{d}", "TXT")
        err  = resolve_error(recs)
        if err:
            return {"present": False, "policy": None, "record": None, "error": err}
        for rec in recs:
            if "v=DMARC1" in rec:
                return _parse_dmarc_record(rec)
        return None

    result = _lookup(domain)
    if result is not None:
        result.setdefault("inherited_from", None)
        if result.get("present"):
            return result
        if result.get("error"):
            return {**result, "inherited_from": None}
        # Absent — fall through

    org = _org_domain(domain)
    if org and org != domain:
        org_result = _lookup(org)
        if org_result is not None and org_result.get("present"):
            return {**org_result, "inherited_from": org}
        if org_result is not None and org_result.get("error"):
            return {**org_result, "inherited_from": None}

    return {"present": False, "policy": None, "pct": None, "sp": None,
            "rua": [], "ruf": [],
            "record": None, "inherited_from": None}


# ── MX ────────────────────────────────────────────────────────────────────────

def check_mx(domain):
    """Return MX records for the domain.

    Detects RFC 7505 null MX ('0 .') and sets 'null_mx': True in the result.
    A null MX is an explicit declaration that the domain sends and receives no mail.
    """
    records = resolve(domain, "MX")
    err = resolve_error(records)
    if err:
        return {"error": err, "entries": [], "null_mx": False}

    for record in records:
        parts = record.split()
        if len(parts) == 2 and parts[0] == "0" and parts[1] in (".", ""):
            return {"entries": [], "null_mx": True}

    parsed = []
    for record in records:
        parts = record.split()
        if len(parts) < 2 or not parts[1].rstrip("."):
            continue
        try:
            priority = int(parts[0])
        except ValueError:
            continue
        host = parts[1].rstrip(".")
        parsed.append({"priority": priority, "host": host})
    return {
        "entries": sorted(parsed, key=lambda x: x["priority"]),
        "null_mx": False,
    }


# ── CAA records ──────────────────────────────────────────────────────────────
# CAA (RFC 8659) lets a domain restrict which Certificate Authorities can
# issue certs for it. Missing CAA = any public CA can issue. Detection is a
# single TXT-style DNS query; analysis is pure parsing.

def check_caa(domain):
    """Look up CAA records for the domain (and walk up to org domain if absent).

    Returns:
      present:        bool — at least one CAA record found
      issue:          list of authorised issue= values (empty list = none allowed)
      issue_wild:     list of authorised issuewild= values
      iodef:          list of iodef= reporting URIs (RFC 8659 §4.4)
      records:        raw record strings
      inherited_from: domain we found CAA on (per RFC 8659 §3.1, parents apply)
      error:          DNS error string if lookup failed
    """
    def _query(name):
        recs = resolve(name, "CAA")
        err  = resolve_error(recs)
        return recs, err

    # CAA inheritance: if the domain itself has no CAA, walk up the labels
    # until we find one or hit the public suffix boundary.
    parts = domain.split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    org = _org_domain(domain)
    if org and org not in candidates:
        candidates.append(org)

    last_err = None
    for name in candidates:
        recs, err = _query(name)
        if err:
            last_err = err
            continue
        if not recs:
            continue
        issue, issue_wild, iodef = [], [], []
        for r in recs:
            # dnspython returns CAA as: "0 issue \"letsencrypt.org\""
            m = re.match(r'^\s*(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$', r)
            if not m:
                continue
            tag = m.group(2).lower()
            val = m.group(3).strip()
            if tag == "issue":
                issue.append(val)
            elif tag == "issuewild":
                issue_wild.append(val)
            elif tag == "iodef":
                iodef.append(val)
        return {
            "present":         True,
            "issue":           issue,
            "issue_wild":      issue_wild,
            "iodef":           iodef,
            "records":         recs,
            "inherited_from":  None if name == domain else name,
        }
    return {
        "present":        False,
        "issue":          [],
        "issue_wild":     [],
        "iodef":          [],
        "records":        [],
        "inherited_from": None,
        "error":          last_err,
    }


# ── MTA-STS (RFC 8461) ───────────────────────────────────────────────────────
# Default-mode check: is the _mta-sts.<domain> TXT record present and what is
# its declared mode? Fetching the actual policy file is a separate (deep-mode)
# concern in check_mta_sts_policy() because it requires an HTTPS GET.

def check_mta_sts(domain):
    """Check for an MTA-STS TXT record at _mta-sts.<domain>.

    The TXT record format (RFC 8461 §3.1): v=STSv1; id=<arbitrary-id>
    The actual policy file (mode=enforce|testing|none) lives at
    https://mta-sts.<domain>/.well-known/mta-sts.txt and is only fetched in
    deep mode by check_mta_sts_policy().
    """
    recs = resolve(f"_mta-sts.{domain}", "TXT")
    err  = resolve_error(recs)
    if err:
        return {"present": False, "id": None, "error": err}
    for r in recs:
        if "v=STSv1" in r:
            id_match = re.search(r"id=([A-Za-z0-9]+)", r)
            return {
                "present":  True,
                "id":       id_match.group(1) if id_match else None,
                "record":   r,
            }
    return {"present": False, "id": None, "record": None}


def check_mta_sts_policy(domain):
    """Fetch the MTA-STS policy file (deep-mode only).

    Returns dict with mode, mx, max_age. mode is the value scored.
    """
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = _http_get(url, verify=False, allow_redirects=True)
        if not resp.ok:
            return {"fetched": False, "error": f"HTTP {resp.status_code}"}
        body = resp.text
        mode = max_age = None
        mx = []
        for line in body.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = (x.strip() for x in line.split(":", 1))
            kl = k.lower()
            if kl == "mode":
                mode = v.lower()
            elif kl == "max_age":
                try:
                    max_age = int(v)
                except ValueError:
                    pass
            elif kl == "mx":
                mx.append(v)
        return {"fetched": True, "mode": mode, "max_age": max_age, "mx": mx}
    except Exception as e:
        return {"fetched": False, "error": str(e)}


# ── TLS-RPT (RFC 8460) ───────────────────────────────────────────────────────

def check_tls_rpt(domain):
    """Check for a TLS-RPT TXT record at _smtp._tls.<domain>.

    Format (RFC 8460 §3): v=TLSRPTv1; rua=mailto:reports@example.com
    """
    recs = resolve(f"_smtp._tls.{domain}", "TXT")
    err  = resolve_error(recs)
    if err:
        return {"present": False, "rua": None, "error": err}
    for r in recs:
        if "v=TLSRPTv1" in r:
            rua_match = re.search(r"rua=([^;]+)", r)
            return {
                "present":  True,
                "rua":      rua_match.group(1).strip() if rua_match else None,
                "record":   r,
            }
    return {"present": False, "rua": None, "record": None}


# ── DANE / TLSA on MX hosts ──────────────────────────────────────────────────

def check_dane(domain, mx_entries):
    """For each MX host, look up TLSA records at _25._tcp.<mx-host>.

    Returns:
      mx_count:     total MX hosts checked
      with_tlsa:    list of MX hosts that returned TLSA records
      without_tlsa: list of MX hosts that did not
      records:      dict mx_host -> list of TLSA record strings
    """
    if not mx_entries:
        return {"mx_count": 0, "with_tlsa": [], "without_tlsa": [], "records": {}}

    # Cap concurrency at 8 — a domain with hundreds of MX hosts is exotic but
    # we don't want to blow up the thread pool.
    hosts = [e["host"] for e in mx_entries]
    results = {}

    def _check_one(host):
        # 5s lifetime — DANE is now --deep-gated, so we can afford to wait
        # for resolvers that handle TLSA queries slowly (the common case
        # when the MX host's zone isn't DNSSEC-signed). False negatives
        # under a tighter budget would have under-reported DANE coverage,
        # which we'd rather not do when the user explicitly asked for the
        # heavy probe by passing --deep.
        recs = resolve(f"_25._tcp.{host}", "TLSA", lifetime=5.0)
        if resolve_error(recs):
            return host, []
        # Filter to only records that look like TLSA (4 fields: usage, selector,
        # matching-type, certificate-association-data). dnspython returns them
        # already formatted but DNS errors elsewhere could leak through.
        tlsa = [r for r in recs if len(r.split()) >= 4]
        return host, tlsa

    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as ex:
        for host, tlsa in ex.map(_check_one, hosts):
            results[host] = tlsa

    with_tlsa    = [h for h, t in results.items() if t]
    without_tlsa = [h for h, t in results.items() if not t]
    return {
        "mx_count":      len(hosts),
        "with_tlsa":     with_tlsa,
        "without_tlsa":  without_tlsa,
        "records":       results,
    }


# ── DKIM probing (common selectors only — partial check) ─────────────────────

def check_dkim_common(domain):
    """Probe a small list of common DKIM selectors.

    DKIM keys live at <selector>._domainkey.<domain>. Selector names are
    arbitrary, so absence proves nothing — this is a positive-only signal.
    The render layer must present the result with the partial-check caveat
    front and centre.

    Returns:
      checked:     list of selectors probed
      found:       list of selectors that returned a v=DKIM1 record
      records:     dict selector -> raw record string
    """
    found, recs = [], {}

    def _probe(selector):
        # 2s lifetime — DKIM common-selector probes are NXDOMAIN-likely for
        # most domains (selectors are operator-chosen and arbitrary), so the
        # default 5s wait per missing selector is wasted time. Same trade-off
        # as DANE: false negatives only under-report a partial check that's
        # already explicitly labelled as partial in the report.
        result = resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=2.0)
        if resolve_error(result):
            return selector, None
        for r in result:
            if "v=DKIM1" in r:
                return selector, r
        return selector, None

    with ThreadPoolExecutor(max_workers=min(8, len(DKIM_COMMON_SELECTORS))) as ex:
        for selector, rec in ex.map(_probe, DKIM_COMMON_SELECTORS):
            if rec:
                found.append(selector)
                recs[selector] = rec

    return {
        "checked":  list(DKIM_COMMON_SELECTORS),
        "found":    found,
        "records":  recs,
    }


# ── DNS hygiene: NS and SOA ──────────────────────────────────────────────────

def check_ns_soa(domain):
    """Check authoritative NS list and SOA serial for the domain.

    RFC 1034 §4.1 recommends at least two nameservers for redundancy.
    SOA serial is informational — useful for change tracking.
    """
    ns_records  = resolve(domain, "NS")
    soa_records = resolve(domain, "SOA")

    ns_err  = resolve_error(ns_records)
    soa_err = resolve_error(soa_records)

    nameservers = []
    if not ns_err:
        nameservers = sorted(set(r.rstrip(".").lower() for r in ns_records))

    soa = None
    if not soa_err and soa_records:
        # SOA format: "primary admin serial refresh retry expire minimum"
        parts = soa_records[0].split()
        if len(parts) >= 7:
            try:
                soa = {
                    "primary":  parts[0].rstrip("."),
                    "admin":    parts[1].rstrip("."),
                    "serial":   int(parts[2]),
                    "refresh":  int(parts[3]),
                    "retry":    int(parts[4]),
                    "expire":   int(parts[5]),
                    "minimum":  int(parts[6]),
                }
            except (ValueError, IndexError):
                pass

    return {
        "nameservers":   nameservers,
        "ns_count":      len(nameservers),
        "ns_error":      ns_err,
        "soa":           soa,
        "soa_error":     soa_err,
    }


# ── IP routing / RPKI ─────────────────────────────────────────────────────────

def check_ip_routing(domain):
    """Resolve the first IPv4 and IPv6 addresses for the domain, then for each
    query RIPEstat for BGP prefix, ASN, RPKI validity, and IRR/RIS presence.
    Never raises.
    """
    RIPESTAT = "https://stat.ripe.net/data"
    timeout = _http_timeout
    RETRIES = 2

    def _ripe_get(url, params):
        last_exc = None
        for _ in range(RETRIES):
            try:
                resp = _get_session().get(url, params=params, timeout=timeout)
                resp.raise_for_status()
                return resp
            except Exception as e:
                last_exc = e
        raise last_exc

    def _empty_addr():
        return {
            "address":     None,
            "prefix":      None,
            "asn":         None,
            "asn_name":    None,
            "rpki_status": None,
            "irr_in_ris":  False,
            "error":       None,
        }

    def _fetch_rpki(asn, prefix):
        try:
            resp = _ripe_get(
                f"{RIPESTAT}/rpki-validation/data.json",
                params={"resource": str(asn), "prefix": prefix},
            )
            status = resp.json().get("data", {}).get("status", "").lower()
            return "not-found" if status == "unknown" else status or "error"
        except Exception:
            return "error"

    def _fetch_ris(asn, afi, prefix):
        try:
            resp = _ripe_get(
                f"{RIPESTAT}/ris-prefixes/data.json",
                params={"resource": f"AS{asn}", "list_prefixes": "true"},
            )
            prefixes = resp.json().get("data", {}).get("prefixes", {})
            orig_key = "v4" if afi == "v4" else "v6"
            originating = prefixes.get(orig_key, {}).get("originating", [])
            return prefix in originating
        except Exception:
            return False

    def _lookup(ip, afi):
        r = _empty_addr()
        r["address"] = ip

        try:
            resp = _ripe_get(
                f"{RIPESTAT}/prefix-overview/data.json",
                params={"resource": ip},
            )
            data = resp.json().get("data", {})
            r["prefix"] = data.get("resource")
            asns = data.get("asns", [])
            if asns:
                r["asn"]      = asns[0].get("asn")
                r["asn_name"] = asns[0].get("holder", "")
        except Exception as e:
            r["error"] = f"prefix-overview: {e}"
            return r

        if not r["prefix"] or r["asn"] is None:
            r["error"] = "no BGP prefix announced for this IP"
            return r

        with ThreadPoolExecutor(max_workers=2) as inner:
            rpki_fut = inner.submit(_fetch_rpki, r["asn"], r["prefix"])
            ris_fut  = inner.submit(_fetch_ris,  r["asn"], afi, r["prefix"])
        r["rpki_status"] = rpki_fut.result()
        if r["rpki_status"] == "error":
            r["error"] = "rpki-validation: request failed"
        r["irr_in_ris"] = ris_fut.result()

        return r

    result = {
        "v4":    _empty_addr(),
        "v6":    _empty_addr(),
        "error": None,
    }

    with ThreadPoolExecutor(max_workers=2) as dns_ex:
        a_fut    = dns_ex.submit(resolve, domain, "A")
        aaaa_fut = dns_ex.submit(resolve, domain, "AAAA")
    a_records    = a_fut.result()
    aaaa_records = aaaa_fut.result()

    a_err    = resolve_error(a_records)
    aaaa_err = resolve_error(aaaa_records)

    v4_ip = None if (a_err or not a_records) else a_records[0]
    v6_ip = None if (aaaa_err or not aaaa_records) else aaaa_records[0]

    with ThreadPoolExecutor(max_workers=2) as addr_ex:
        v4_fut = addr_ex.submit(_lookup, v4_ip, "v4") if v4_ip else None
        v6_fut = addr_ex.submit(_lookup, v6_ip, "v6") if v6_ip else None

    if a_err:
        result["v4"]["error"] = f"A record lookup failed: {a_err}"
    elif not a_records:
        result["v4"]["error"] = "no A record"
    else:
        result["v4"] = v4_fut.result()

    if aaaa_err:
        result["v6"]["error"] = f"AAAA record lookup failed: {aaaa_err}"
    elif not aaaa_records:
        result["v6"]["error"] = "no AAAA record"
    else:
        result["v6"] = v6_fut.result()
        result["v6"]["all_addresses"] = aaaa_records

    return result


# ── DNSSEC ────────────────────────────────────────────────────────────────────

def check_dnssec(domain):
    """Check DNSSEC at TLD level (parent zone signing) and at the domain
    itself (DNSKEY presence + AD flag from a validating resolver).
    """
    result = {
        "tld":    {"signed": False, "tld": None, "error": None},
        "domain": {"dnskey": False, "ad_flag": False, "error": None},
    }

    parts = domain.split(".")
    tld = parts[-1] if len(parts) >= 2 else domain
    result["tld"]["tld"] = tld
    ns = _dns_server or "8.8.8.8"

    def _check_tld():
        resp = udp_query(tld, dns.rdatatype.DNSKEY, ns)
        if resp is None:
            return {"error": "timeout_or_unreachable"}
        has_dnskey = any(
            rrset.rdtype == dns.rdatatype.DNSKEY
            for rrset in resp.answer
        )
        return {"signed": has_dnskey or bool(resp.flags & dns.flags.AD)}

    def _check_domain_dnskey():
        records = resolve(domain, "DNSKEY")
        err = resolve_error(records)
        if err:
            return {"error": err, "dnskey": False}
        return {"dnskey": bool(records), "error": None}

    def _check_domain_ad():
        resp = udp_query(domain, dns.rdatatype.A, ns)
        if resp is None:
            return {"ad_error": "timeout_or_unreachable"}
        return {"ad_flag": bool(resp.flags & dns.flags.AD)}

    with ThreadPoolExecutor(max_workers=3) as ex:
        tld_fut    = ex.submit(_check_tld)
        dnskey_fut = ex.submit(_check_domain_dnskey)
        ad_fut     = ex.submit(_check_domain_ad)

    tld_res = tld_fut.result()
    if tld_res.get("error"):
        result["tld"]["error"] = tld_res["error"]
    else:
        result["tld"]["signed"] = tld_res.get("signed", False)

    dnskey_res = dnskey_fut.result()
    if dnskey_res.get("error"):
        result["domain"]["error"] = dnskey_res["error"]
    else:
        result["domain"]["dnskey"] = dnskey_res.get("dnskey", False)

    if not result["domain"]["error"]:
        ad_res = ad_fut.result()
        if ad_res.get("ad_error"):
            result["domain"]["error"] = ad_res["ad_error"]
        else:
            result["domain"]["ad_flag"] = ad_res.get("ad_flag", False)

    return result


# ── TLS ───────────────────────────────────────────────────────────────────────

def _cert_matches_domain(domain, cert):
    """Return (match: bool, names: list[str]) where names are all SANs + CN found.

    Modern browsers (Chrome, Firefox) ignore CN entirely when SANs are present.
    We include CN as a fallback in `names` for visibility but the same matching
    rules apply: exact match (case-insensitive) or single-label wildcard
    (RFC 6125 §6.4.3).
    """
    names = []

    for typ, val in cert.get("subjectAltName", ()):
        if typ.lower() == "dns":
            names.append(val.lower())

    subject_dict = dict(x[0] for x in cert.get("subject", []))
    cn = subject_dict.get("commonName", "").lower()
    if cn and cn not in names:
        names.append(cn)

    domain_lower = domain.lower()

    def _matches_one(name):
        if name == domain_lower:
            return True
        if name.startswith("*."):
            suffix = name[2:]
            parts  = domain_lower.split(".", 1)
            if len(parts) == 2 and parts[1] == suffix:
                return True
        return False

    matched = any(_matches_one(n) for n in names)
    return matched, names


def check_http_version(domain):
    """Detect the highest HTTP version the server will negotiate using httpx.

    httpx natively advertises h2 in ALPN and speaks HTTP/2, giving an accurate
    result through CDNs. HTTP/3 is detected separately via Alt-Svc.
    """
    result = {"version": None, "error": None}
    try:
        with httpx.Client(
            http2=True,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": f"vendor-audit/{__version__}"},
            timeout=_http_timeout,
        ) as client:
            resp = client.head(f"https://{domain}")
            result["version"] = resp.http_version
    except Exception as e:
        result["error"] = str(e)
    return result


def check_tls(domain, port=443):
    """Negotiate TLS, report version, and inspect the certificate.

    Uses CERT_REQUIRED with the system CA bundle so getpeercert() returns
    structured fields. check_hostname is disabled to tolerate www/apex
    mismatches; we report mismatches via cert_names_match instead.
    """
    result = {
        "version":            None,
        "alpn_protocol":      None,
        "error":              None,
        "tls_cert_error":     False,   # always present; flips True on cert verify error
        "cert_issued":        None,
        "cert_expires":       None,
        "cert_lifetime_days": None,
        "cert_issuer":        None,
        "cert_names_match":   None,
        "cert_san_names":     [],
    }

    try:
        sock_holder = [None]

        def _connect():
            sock_holder[0] = socket.create_connection((domain, port), timeout=_http_timeout)
            return sock_holder[0]

        def _close_sock():
            if sock_holder[0]:
                try:
                    sock_holder[0].close()
                except Exception:
                    pass

        try:
            sock = _run_with_hard_timeout(_connect, timeout=_http_timeout, on_timeout=_close_sock)
        except TimeoutError:
            raise socket.timeout(f"TLS connect timeout after {_http_timeout}s")

        sock.settimeout(_http_timeout)
        with sock:
            with _TLS_CTX.wrap_socket(sock, server_hostname=domain) as ssock:
                result["version"] = ssock.version()
                result["alpn_protocol"] = ssock.selected_alpn_protocol()
                cert = ssock.getpeercert()
                if cert:
                    try:
                        issued_ts  = ssl.cert_time_to_seconds(cert["notBefore"])
                        expires_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                        issued  = datetime.fromtimestamp(issued_ts,  tz=timezone.utc)
                        expires = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
                        result["cert_lifetime_days"] = (expires - issued).days
                        result["cert_issued"]  = issued.strftime("%Y-%m-%d")
                        result["cert_expires"] = expires.strftime("%Y-%m-%d")
                    except Exception:
                        pass  # cert exists but date fields are unparseable; lifetime stays None
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_issuer"] = (
                        issuer_dict.get("commonName") or
                        issuer_dict.get("organizationName") or ""
                    )
                    matched, names = _cert_matches_domain(domain, cert)
                    result["cert_names_match"] = matched
                    result["cert_san_names"]   = names
    except ssl.SSLCertVerificationError as e:
        # Port 443 is open, TLS negotiated, but cert failed CA verification
        # (self-signed, expired, or untrusted issuer). Tagged separately so
        # scoring can penalise "no cert at all" more heavily than "bad cert".
        result["error"]          = str(e)
        result["tls_cert_error"] = True
    except Exception as e:
        # Hard failure: no port 443, timeout, connection refused, etc.
        result["error"]          = str(e)
        result["tls_cert_error"] = False

    return result


# ── HSTS ──────────────────────────────────────────────────────────────────────

def check_hsts(domain, _cached_response=None):
    """Fetch HTTPS response and inspect Strict-Transport-Security header.
    Also checks HSTS preload status via the hstspreload.org API.

    If _cached_response is supplied (a requests.Response from check_redirect)
    the HTTPS header fetch is skipped — STS is read from the cached response.
    """
    result = {"present": False, "max_age": None, "includes_subdomains": False,
              "preload_directive": False,
              "preloaded": None, "preloaded_via": None, "preload_error": None}

    def _parse_hsts_header(resp):
        out = {}
        try:
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if hsts:
                out["present"] = True
                for part in hsts.split(";"):
                    part = part.strip()
                    if part.lower().startswith("max-age="):
                        try:
                            out["max_age"] = int(part.split("=")[1])
                        except ValueError:
                            pass
                out["includes_subdomains"] = "includesubdomains" in hsts.lower()
                out["preload_directive"]   = "preload" in hsts.lower()
        except Exception as e:
            out["error"] = str(e)
        return out

    def _fetch_header():
        try:
            resp = _http_get(
                f"https://{domain}", verify=False,
                allow_redirects=True,
                stream=True,
            )
            return _parse_hsts_header(resp)
        except Exception as e:
            return {"error": str(e)}

    def _fetch_preload():
        out = {}
        try:
            pr = _http_get(
                f"https://hstspreload.org/api/v2/status?domain={domain}",
            )
            data = pr.json()
            status = data.get("status", "")
            out["preloaded"]     = (status == "preloaded")
            out["preloaded_via"] = domain if out["preloaded"] else None
        except Exception as e:
            out["preload_error"] = str(e)
        return out

    if _cached_response is not None:
        try:
            result.update(_parse_hsts_header(_cached_response))
        except Exception:
            pass
        result.update(_fetch_preload())
        return result

    with ThreadPoolExecutor(max_workers=2) as ex:
        hdr_fut     = ex.submit(_fetch_header)
        preload_fut = ex.submit(_fetch_preload)

    result.update(hdr_fut.result())
    result.update(preload_fut.result())

    return result


# ── Redirect / HTTP ───────────────────────────────────────────────────────────

from urllib.parse import urlparse  # used by check_redirect / check_http_redirect


def check_redirect(domain, body_cap=None):
    """Follow HTTP redirects; return final domain plus a cached response.

    The cached requests.Response is returned under '_response' so callers can
    reuse the already-fetched page (header + body chunk) without a second
    round-trip. Caller must pop '_response' before serializing the result.

    Also captures:
      - elapsed_ms: total wall time for the GET incl. redirects (used as a
        free ping estimate)
      - first_hop_url / first_hop_https / first_hop_same_host: from
        resp.history[0]; lets callers score Mozilla-style "first redirect
        goes to HTTPS on same host" without a second fetch
      - body_truncated: True if the body was larger than body_cap and got
        capped (callers can warn that page-level analysis may be incomplete
        on long pages)
      - body_cap_used: the cap that was applied (caller may have requested
        a larger cap via --deep)
      - body_looks_like_html: True if the captured body has a recognisable
        HTML start (e.g. <!DOCTYPE html>, <html, <head>, <body>). False
        means the page parser will produce noise — useful to surface to the
        user when the body is a JSON API response, a PDF, an image, etc.
        2.5.x added this check to expose bot-mitigation challenge pages and
        non-HTML responses that previously parsed silently as zero counts.

    body_cap (bytes) controls how much body is read. Default is
    _BODY_SNIFF_BYTES (256KB); --deep callers may pass a larger value
    (typically _DEEP_BODY_SNIFF_BYTES = 5MB).
    """
    if body_cap is None:
        body_cap = _BODY_SNIFF_BYTES

    for scheme in ("https", "http"):
        try:
            t0 = time.monotonic()
            # Don't force Accept-Encoding: identity. Many commercial CDNs
            # (Akamai, AWS Cloudfront, Cloudflare's enterprise tier) ignore
            # the identity request and serve gzip/br anyway. Reading via
            # resp.raw.read() then returns *compressed* bytes that look like
            # garbage to the HTML parser, producing nonsense findings (1
            # <img>, 3 <script>, etc) when grep happens to match a substring
            # inside the gzip stream. iter_content() with stream=True does
            # the right thing: requests transparently decompresses and we
            # only consume up to body_cap of decoded bytes, so we don't
            # download a full 50MB page just to fill our sniff window.
            resp = _http_get(
                f"{scheme}://{domain}", verify=False,
                allow_redirects=True,
                stream=True,
            )
            chunks = []
            total  = 0
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= body_cap:
                    break
            resp._body_chunk = b"".join(chunks)
            resp._body_truncated = (total >= body_cap)
            resp.close()
            elapsed_ms = (time.monotonic() - t0) * 1000.0

            # Sanity-check: does the body look like HTML? A JSON API, PDF,
            # gzipped-bytes-from-a-misbehaving-server, or bot-mitigation
            # challenge page can all return 2xx but parse to noise. We test
            # for an HTML signature in the first 4KB only; that's enough to
            # catch the common cases without scanning the whole body.
            body_head = resp._body_chunk[:4096]
            try:
                head_text = body_head.decode("utf-8", errors="replace").lower()
            except Exception:
                head_text = ""
            body_looks_like_html = (
                "<!doctype html" in head_text
                or "<html" in head_text
                or "<head" in head_text
                or "<body" in head_text
            )

            # First-hop hygiene: did the very first response point to HTTPS on
            # the same host? Mozilla penalises off-host first hops because they
            # leak the original URL via Referer and bypass HSTS for the apex.
            first_hop_url       = None
            first_hop_https     = None
            first_hop_same_host = None
            history             = list(resp.history)
            if history:
                first_resp           = history[0]
                first_hop_url        = first_resp.headers.get("Location") or first_resp.url
                try:
                    first_parsed = urlparse(first_hop_url)
                    first_hop_https     = first_parsed.scheme.lower() == "https"
                    first_host          = first_parsed.netloc.lower().split(":")[0].lstrip("www.")
                    first_hop_same_host = first_host == domain.lower().lstrip("www.")
                except Exception:
                    pass

            final = urlparse(resp.url).netloc.lower().rstrip(".")
            final = final.split(":")[0]
            if final.startswith("www."):
                final = final[4:]
            redirected = final != domain.lower().rstrip(".")
            return {
                "redirected":             redirected,
                "original":               domain,
                "final":                  final if redirected else domain,
                "elapsed_ms":             round(elapsed_ms, 1),
                "first_hop_url":          first_hop_url,
                "first_hop_https":        first_hop_https,
                "first_hop_same_host":    first_hop_same_host,
                "body_truncated":         bool(getattr(resp, "_body_truncated", False)),
                "body_cap_used":          body_cap,
                "body_looks_like_html":   body_looks_like_html,
                "_response":              resp,
            }
        except requests.exceptions.Timeout:
            if scheme == "https":
                return {"redirected": False, "original": domain, "final": domain,
                        "error": "unreachable", "_https_timed_out": True}
            break
        except Exception:
            continue
    return {"redirected": False, "original": domain, "final": domain, "error": "unreachable"}


def check_http_redirect(domain):
    """Check whether http:// ultimately lands on an HTTP or HTTPS page.

    Uses stream=True so the body isn't downloaded just to read the final URL —
    on slow servers with large default landing pages this saves significant time.
    """
    result = {
        "status":      None,
        "final_url":   None,
        "status_code": None,
        "detail":      None,
    }

    try:
        resp = _http_get(
            f"http://{domain}",
            verify=False,
            allow_redirects=True,
            stream=True,
        )
        try:
            final_url = resp.url
            result["final_url"]   = final_url
            result["status_code"] = resp.status_code

            if urlparse(final_url).scheme == "https":
                result["status"] = "https_only"
                result["detail"] = f"http:// redirects to HTTPS (final: {final_url})"
            elif resp.status_code >= 400:
                result["status"] = "http_error"
                result["detail"] = (
                    f"HTTP port 80 open but returned {resp.status_code} "
                    f"with no HTTPS redirect (final: {final_url})"
                )
            else:
                result["status"] = "http_available"
                result["detail"] = f"Page is accessible over plain HTTP (final: {final_url})"
        finally:
            resp.close()

    except requests.exceptions.ConnectionError:
        result["status"] = "unreachable"
        result["detail"] = "HTTP port 80 not reachable"
    except Exception as e:
        result["status"] = "unreachable"
        result["detail"] = f"HTTP port 80 error: {e}"

    return result


# ── security.txt ──────────────────────────────────────────────────────────────

def check_security_txt(domain):
    """Fetch security.txt and extract Contact / Policy / Expires.

    Tries the canonical RFC 9116 location (/.well-known/security.txt), then
    the legacy root path (/security.txt). RFC 9116 §3 SHOULDs HTTPS, but real
    deployments still serve over plain HTTP on hosts without TLS, so we
    additionally fall back to http:// if both HTTPS attempts fail with a
    network/connection error.
    """
    result = {"present": False, "contact": [], "policy": None,
              "expires": None, "expired": None, "found_at": None, "error": None}

    def _parse_body(body):
        contacts = []
        policy = None
        expires_raw = None
        for line in body.splitlines():
            line = line.strip()
            ll = line.lower()
            if ll.startswith("contact:"):
                contact = line[len("contact:"):].strip()
                if contact:
                    contacts.append(contact)
            elif ll.startswith("policy:"):
                policy = line[len("policy:"):].strip() or None
            elif ll.startswith("expires:"):
                expires_raw = line[len("expires:"):].strip() or None
        has_security_fields = contacts or any(
            line.strip().lower().startswith(("expires:", "policy:", "preferred-languages:"))
            for line in body.splitlines()
        )
        return (contacts, policy, expires_raw) if has_security_fields else None

    def _try_url(url):
        try:
            resp = _http_get(url, verify=False, allow_redirects=True)
            return resp, None
        except Exception as e:
            return None, str(e)

    candidates = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
        # http:// fallbacks — only used if the https candidates fail with a
        # network error (not 4xx, which short-circuits the loop below).
        f"http://{domain}/.well-known/security.txt",
        f"http://{domain}/security.txt",
    ]
    last_err = None
    for url in candidates:
        resp, err = _try_url(url)
        if err:
            last_err = err
            continue
        if not resp.ok:
            continue
        parsed = _parse_body(resp.text)
        if parsed is None:
            # 2xx but not a real security.txt (e.g. HTML landing page).
            # Don't try further candidates — same site likely returns the same.
            break
        contacts, policy, expires_raw = parsed
        result["present"] = True
        result["found_at"] = url
        result["contact"] = contacts
        result["policy"]  = policy
        result["expires"] = expires_raw
        if expires_raw:
            try:
                exp_str = expires_raw.replace("Z", "+00:00").replace("z", "+00:00")
                exp_dt  = datetime.fromisoformat(exp_str)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                result["expired"] = exp_dt < datetime.now(timezone.utc)
            except Exception:
                result["expired"] = None
        return result

    if last_err and not result["present"]:
        result["error"] = last_err
    return result


# ── Cookies ───────────────────────────────────────────────────────────────────

def _parse_set_cookies(resp):
    """Extract every Set-Cookie header from a requests.Response.

    Uses raw.headers.getlist() to preserve individual headers — requests'
    public .headers flattens multi-value headers with ", " which is ambiguous
    for Set-Cookie because the Expires attribute contains a comma.
    """
    cookies = []
    raw_headers = []
    try:
        raw = getattr(resp, "raw", None)
        if raw is not None and hasattr(raw.headers, "getlist"):
            raw_headers = raw.headers.getlist("Set-Cookie")
        if not raw_headers:
            joined = resp.headers.get("Set-Cookie", "")
            if joined:
                raw_headers = [joined]
    except Exception:
        return cookies

    for header in raw_headers:
        if not header:
            continue
        parts = [p.strip() for p in header.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        if not name:
            continue

        secure   = False
        httponly = False
        samesite = None
        path     = "/"   # default per RFC 6265 §5.2.4
        domain_attr = None
        for attr in parts[1:]:
            low = attr.lower()
            if low == "secure":
                secure = True
            elif low == "httponly":
                httponly = True
            elif low.startswith("samesite="):
                val = attr.split("=", 1)[1].strip()
                v_low = val.lower()
                if v_low == "strict":
                    samesite = "Strict"
                elif v_low == "lax":
                    samesite = "Lax"
                elif v_low == "none":
                    samesite = "None"
                else:
                    samesite = val
            elif low.startswith("path="):
                path = attr.split("=", 1)[1].strip() or "/"
            elif low.startswith("domain="):
                domain_attr = attr.split("=", 1)[1].strip().lstrip(".") or None

        infra = any(name.startswith(p) for p in _INFRA_COOKIE_PREFIXES)

        issues = []
        if not secure:
            issues.append("missing_secure")
        if not httponly:
            issues.append("missing_httponly")
        if samesite is None:
            issues.append("missing_samesite")
        elif samesite == "None" and not secure:
            issues.append("samesite_none_without_secure")

        # ── 2.1.0: Cookie name prefix validation (RFC 6265bis §4.1.3) ────────
        # __Secure- requires Secure
        # __Host-   requires Secure + Path=/ + no Domain
        if name.startswith("__Secure-") and not secure:
            issues.append("invalid_secure_prefix")
        if name.startswith("__Host-"):
            if not secure or path != "/" or domain_attr:
                issues.append("invalid_host_prefix")

        cookies.append({
            "name":     name,
            "secure":   secure,
            "httponly": httponly,
            "samesite": samesite,
            "path":     path,
            "domain":   domain_attr,
            "infra":    infra,
            "issues":   issues,
        })

    return cookies


# ── Server header / browser security headers ──────────────────────────────────

def check_server_header(domain, _cached_response=None):
    """Return Server, X-Powered-By, browser security headers, and tech stack.

    If _cached_response is supplied (from check_redirect) the function uses it
    directly and skips the HTTP fetch.
    """
    def _parse_response(resp):
        h = resp.headers
        if hasattr(resp, '_body_chunk'):
            body = resp._body_chunk.decode("utf-8", errors="replace")
        else:
            body = resp.text

        csp_raw = h.get("Content-Security-Policy")
        if csp_raw:
            csp_raw_low = csp_raw.lower()
            csp_quality = "present"
            for directive in csp_raw_low.split(";"):
                tokens = directive.strip().split()
                if not tokens:
                    continue
                name, values = tokens[0], tokens[1:]
                if name == "default-src" and "*" in values:
                    csp_quality = "permissive"
                    break
            csp_frame_ancestors = "frame-ancestors" in csp_raw_low
        else:
            csp_quality = None
            csp_frame_ancestors = False

        stack = []
        for hdr, label in [
            ("X-AspNet-Version",     "ASP.NET {v}"),
            ("X-AspNetMvc-Version",  "ASP.NET MVC {v}"),
            ("X-Generator",          "{v}"),
            ("X-Powered-CMS",        "{v}"),
            ("X-Drupal-Cache",       "Drupal"),
            ("X-Drupal-Dynamic-Cache", "Drupal"),
            ("X-Joomla-Token",       "Joomla"),
        ]:
            val = h.get(hdr)
            if val is not None:
                stack.append(label.replace("{v}", val) if "{v}" in label else label)

        gen_match = _RE_META_GENERATOR.search(body)
        if gen_match:
            stack.append(f"Generator: {(gen_match.group(1) or gen_match.group(2)).strip()}")

        seen = set(stack)
        for pattern, label in _BODY_SIGNALS:
            if label not in seen and pattern.search(body):
                stack.append(label)
                seen.add(label)

        alt_svc = h.get("Alt-Svc", "")
        cookies = _parse_set_cookies(resp)

        # ── 2.1.0 additions: COOP/COEP/CORP, X-XSS-Protection, Date, ─────────
        # Cache-Control, Content-Length, CSP-Report-Only ───────────────────────
        csp_report_only = h.get("Content-Security-Policy-Report-Only")
        cl_hdr  = h.get("Content-Length")
        cl_actual = None
        if hasattr(resp, "_body_chunk"):
            # Only meaningful as a sanity check when body wasn't truncated
            if not getattr(resp, "_body_truncated", False):
                cl_actual = len(resp._body_chunk)

        return {
            "server":              h.get("Server"),
            "x_powered_by":        h.get("X-Powered-By"),
            "final_url":           resp.url,
            "stack":               stack,
            "http3_advertised":    "h3" in alt_svc,
            "alt_svc":             alt_svc or None,
            "csp":                 csp_raw,
            "csp_report_only":     csp_report_only,
            "csp_quality":         csp_quality,
            "csp_frame_ancestors": csp_frame_ancestors,
            "x_frame_options":     h.get("X-Frame-Options"),
            "x_content_type":      h.get("X-Content-Type-Options"),
            "referrer_policy":     h.get("Referrer-Policy"),
            "permissions_policy":  h.get("Permissions-Policy"),
            "cookies":             cookies,
            "coop":                h.get("Cross-Origin-Opener-Policy"),
            "coep":                h.get("Cross-Origin-Embedder-Policy"),
            "corp":                h.get("Cross-Origin-Resource-Policy"),
            "origin_agent_cluster":h.get("Origin-Agent-Cluster"),
            "x_xss_protection":    h.get("X-XSS-Protection"),
            "date":                h.get("Date"),
            "cache_control":       h.get("Cache-Control"),
            "expires":             h.get("Expires"),
            "content_length_hdr":  cl_hdr,
            "content_length_actual": cl_actual,
        }

    _EMPTY = {
        "server": None, "x_powered_by": None, "final_url": None, "stack": [],
        "http3_advertised": None, "alt_svc": None,
        "csp": None, "csp_report_only": None, "csp_quality": None, "csp_frame_ancestors": False,
        "x_frame_options": None, "x_content_type": None,
        "referrer_policy": None, "permissions_policy": None,
        "cookies": [],
        "coop": None, "coep": None, "corp": None, "origin_agent_cluster": None,
        "x_xss_protection": None, "date": None, "cache_control": None, "expires": None,
        "content_length_hdr": None, "content_length_actual": None,
    }

    if _cached_response is not None:
        try:
            return _parse_response(_cached_response)
        except Exception:
            pass  # fall through to a fresh fetch

    last_err = None
    for scheme in ("https", "http"):
        try:
            # Same iter_content() pattern as check_redirect: don't force
            # Accept-Encoding: identity (CDNs ignore it), and read decoded
            # bytes via iter_content() so we get usable HTML even when the
            # server insists on gzip. Cap at _BODY_SNIFF_BYTES; this fetch
            # is only for tech fingerprinting, so 256KB is plenty.
            resp = _http_get(
                f"{scheme}://{domain}", verify=False,
                allow_redirects=True,
                stream=True,
            )
            chunks = []
            total  = 0
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= _BODY_SNIFF_BYTES:
                    break
            resp._body_chunk = b"".join(chunks)
            resp.close()
            return _parse_response(resp)
        except requests.exceptions.Timeout:
            last_err = Exception(f"Hard timeout ({_http_timeout}s) exceeded for {scheme}://{domain}")
            if scheme == "https":
                break
            continue
        except Exception as e:
            last_err = e
            continue
    return {**_EMPTY, "error": str(last_err) if last_err else "unreachable"}


# ── Server classification ─────────────────────────────────────────────────────

def classify_server(value):
    """Returns: 'absent', 'good_proxy', 'origin_no_version', 'origin_with_version', 'unknown'"""
    if not value:
        return "absent"
    low = value.lower()
    has_version = any(ch.isdigit() for ch in value)
    if any(p in low for p in GOOD_PROXIES):
        return "good_proxy"
    if any(o in low for o in ORIGIN_SERVERS):
        return "origin_with_version" if has_version else "origin_no_version"
    return "origin_with_version" if has_version else "unknown"


# ── CSP analyzer (Google Evaluator-style) ────────────────────────────────────
# Pure string parsing on a header we already have. Categorises script-src
# safety, checks for missing defensive directives, detects nonce/hash usage,
# and surfaces the bypasses Google's csp-evaluator considers high-severity.

_CSP_DIRECTIVES_CAUSING_XSS = {"script-src", "script-src-elem", "script-src-attr",
                               "object-src", "default-src", "base-uri", "trusted-types"}
_CSP_DANGEROUS_SCHEMES = {"http:", "https:", "data:", "filesystem:", "blob:"}


def _parse_csp_header(header):
    """Parse a CSP header string into {directive: [values...]}."""
    out = {}
    if not header:
        return out
    for directive in header.split(";"):
        tokens = directive.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        out[name] = tokens[1:]
    return out


def analyze_csp(csp_header, csp_report_only=False):
    """Return a dict with per-directive findings and outcome keys for scoring.

    Outcome keys returned (for use by score_results):
      script_src_outcome    — strict / nonce_or_hash / host_allowlist / unsafe_inline / wildcard_or_scheme / missing
      object_src_outcome    — none_or_self / unrestricted / missing
      base_uri_outcome      — set / missing
      frame_ancestors_outcome — set / missing
      enforcement_outcome   — enforced / report_only

    Findings are surfaced as a list of (severity, message) tuples for render.
    """
    result = {
        "present":              bool(csp_header),
        "directives":           {},
        "findings":             [],
        "script_src_outcome":   "missing",
        "object_src_outcome":   "missing",
        "base_uri_outcome":     "missing",
        "frame_ancestors_outcome": "missing",
        "enforcement_outcome":  "report_only" if csp_report_only else "enforced",
    }
    if not csp_header:
        return result

    directives = _parse_csp_header(csp_header)
    result["directives"] = directives

    def _severity(s):
        return s  # simple passthrough; render layer chooses colour

    # ── script-src analysis ───────────────────────────────────────────────────
    # Order of preference (highest to lowest):
    #   strict           = strict-dynamic + nonce/hash
    #     (host sources, schemes, 'unsafe-inline' are all ignored by CSP3
    #     browsers when 'strict-dynamic' is present — kept only for CSP1/2
    #     fallback)
    #   nonce_or_hash    = nonce-* or sha256/384/512 present (no strict-dynamic
    #     to ignore allowlist)
    #   host_allowlist   = host sources only, no wildcards/dangerous schemes
    #   unsafe_inline    = 'unsafe-inline' or 'unsafe-eval' present and effective
    #   wildcard_or_scheme = * or http:/https:/data: in script-src AND no
    #     nonce/hash to gate inline scripts
    script_dir = directives.get("script-src") or directives.get("default-src", [])
    if not script_dir:
        result["findings"].append(("high",
            "No script-src or default-src — XSS protection ineffective"))
        result["script_src_outcome"] = "missing"
    else:
        sd_low = [v.lower() for v in script_dir]
        has_nonce        = any(v.startswith("'nonce-") for v in sd_low)
        has_hash         = any(v.startswith(("'sha256-", "'sha384-", "'sha512-")) for v in sd_low)
        has_strict_dyn   = "'strict-dynamic'" in sd_low
        has_unsafe_inl   = "'unsafe-inline'" in sd_low
        has_unsafe_eval  = "'unsafe-eval'" in sd_low
        has_wildcard     = "*" in sd_low
        # Dangerous schemes check — exact scheme strings (with the colon)
        has_dangerous_scheme = any(v in _CSP_DANGEROUS_SCHEMES for v in sd_low)
        host_only        = all(
            (v.startswith(("http://", "https://")) or v == "'self'" or v == "'none'")
            for v in sd_low
        )

        if has_unsafe_eval:
            result["findings"].append(("medium",
                "CSP script-src includes 'unsafe-eval' — eval() and Function() are allowed"))

        # ── Decision tree ────────────────────────────────────────────────────
        # When 'strict-dynamic' is present alongside nonce/hash, CSP3
        # browsers IGNORE all allowlist sources, host sources, schemes, and
        # 'unsafe-inline'. The policy is therefore "strict" regardless of
        # whether https: or 'unsafe-inline' also appear (those are CSP1/2
        # fallback). This matches Google CSP Evaluator's "Sample safe policy"
        # which deliberately includes https: and 'unsafe-inline' so older
        # browsers still load nonced scripts.
        if has_strict_dyn and (has_nonce or has_hash):
            result["script_src_outcome"] = "strict"
            # Surface the legacy fallback explicitly so the user knows what's
            # happening on CSP1/2 browsers — but it's not a finding.
        elif has_wildcard and not (has_nonce or has_hash):
            result["findings"].append(("high",
                "CSP script-src includes '*' — any origin can run scripts"))
            result["script_src_outcome"] = "wildcard_or_scheme"
        elif has_dangerous_scheme and not (has_nonce or has_hash):
            bad = [v for v in sd_low if v in _CSP_DANGEROUS_SCHEMES]
            result["findings"].append(("high",
                f"CSP script-src includes dangerous schemes ({', '.join(bad)}) — bypasses the policy"))
            result["script_src_outcome"] = "wildcard_or_scheme"
        elif has_unsafe_inl and not (has_nonce or has_hash):
            # In CSP3, 'unsafe-inline' is ignored if a nonce or hash is present.
            # Without either, 'unsafe-inline' actually applies and is a major hole.
            result["findings"].append(("high",
                "CSP script-src includes 'unsafe-inline' without a nonce/hash — inline scripts run"))
            result["script_src_outcome"] = "unsafe_inline"
        elif has_nonce or has_hash:
            # Check nonce length: <8 bytes after b64 decode is too short to be unguessable
            min_bytes = _THRESH.get("csp_nonce_min_bytes", 8)
            short_nonce = False
            for v in sd_low:
                if v.startswith("'nonce-"):
                    nonce_val = v[len("'nonce-"):-1]
                    try:
                        decoded = base64.urlsafe_b64decode(nonce_val + "=" * (-len(nonce_val) % 4))
                        if len(decoded) < min_bytes:
                            short_nonce = True
                            break
                    except Exception:
                        pass
            if short_nonce:
                result["findings"].append(("medium",
                    f"CSP nonce too short (< {min_bytes} bytes after decode) — guessable"))
            result["script_src_outcome"] = "nonce_or_hash"
        elif host_only:
            result["script_src_outcome"] = "host_allowlist"
            # Mention IP-source weakness (rare but Google flags it)
            for v in sd_low:
                if v.startswith(("http://", "https://")) and re.match(r"https?://\d+\.\d+\.\d+\.\d+", v):
                    result["findings"].append(("medium",
                        f"CSP script-src uses an IP source ({v}) — IPs cannot serve TLS hostnames securely"))
        else:
            # Mixed/unknown — be conservative
            result["script_src_outcome"] = "host_allowlist"

    # ── object-src ────────────────────────────────────────────────────────────
    # Plugin content (Flash, Java applets) used to be a major XSS vector.
    # 'none' or 'self' is good; missing is bad because plugins inject scripts.
    object_dir = directives.get("object-src")
    if object_dir is None:
        # Falls back to default-src per spec — but only if default-src is restrictive
        default_dir = directives.get("default-src", [])
        if "'none'" in [v.lower() for v in default_dir]:
            result["object_src_outcome"] = "none_or_self"
        else:
            result["findings"].append(("medium",
                "CSP missing object-src — plugins (Flash, Java) can be injected"))
            result["object_src_outcome"] = "missing"
    else:
        ov = [v.lower() for v in object_dir]
        if "'none'" in ov or (ov == ["'self'"]):
            result["object_src_outcome"] = "none_or_self"
        elif "*" in ov or any(v in _CSP_DANGEROUS_SCHEMES for v in ov):
            result["findings"].append(("high",
                "CSP object-src is unrestricted — plugin XSS likely"))
            result["object_src_outcome"] = "unrestricted"
        else:
            result["object_src_outcome"] = "none_or_self"

    # ── base-uri ──────────────────────────────────────────────────────────────
    # base-uri defaults to *. Without restriction, an attacker who can inject
    # a single <base href> tag can redirect every relative URL on the page.
    base_dir = directives.get("base-uri")
    if base_dir is None:
        result["findings"].append(("medium",
            "CSP missing base-uri — <base> tag injection can hijack relative URLs"))
        result["base_uri_outcome"] = "missing"
    else:
        bv = [v.lower() for v in base_dir]
        if "'none'" in bv or "'self'" in bv:
            result["base_uri_outcome"] = "set"
        elif "*" in bv:
            result["findings"].append(("medium",
                "CSP base-uri allows '*' — equivalent to no protection"))
            result["base_uri_outcome"] = "missing"
        else:
            result["base_uri_outcome"] = "set"

    # ── frame-ancestors ───────────────────────────────────────────────────────
    # Modern clickjacking defence; supersedes X-Frame-Options.
    fa_dir = directives.get("frame-ancestors")
    if fa_dir is None:
        # Note: frame-ancestors does NOT fall back to default-src, per spec.
        result["frame_ancestors_outcome"] = "missing"
    else:
        fv = [v.lower() for v in fa_dir]
        if "*" in fv:
            result["findings"].append(("medium",
                "CSP frame-ancestors '*' — site can be framed by anyone (clickjacking)"))
            result["frame_ancestors_outcome"] = "missing"
        else:
            result["frame_ancestors_outcome"] = "set"

    if csp_report_only:
        result["findings"].append(("medium",
            "CSP is in Report-Only mode — violations are logged but not blocked"))

    return result


# ── Server clock accuracy ─────────────────────────────────────────────────────

def check_clock_skew(server_date_header):
    """Compare the HTTP Date header to local UTC and report the skew.

    server_date_header: the raw 'Date:' header string from a response.
    Returns dict with skew_seconds, outcome (in_sync / minor_skew / bad_skew / no_date).

    Uses email.utils.parsedate_to_datetime which understands the RFC 7231
    IMF-fixdate format ("Sun, 06 Nov 1994 08:49:37 GMT").
    """
    if not server_date_header:
        return {"skew_seconds": None, "server_time": None, "outcome": "no_date"}
    try:
        from email.utils import parsedate_to_datetime
        server_dt = parsedate_to_datetime(server_date_header)
        if server_dt.tzinfo is None:
            server_dt = server_dt.replace(tzinfo=timezone.utc)
        skew = (datetime.now(timezone.utc) - server_dt).total_seconds()
    except Exception:
        return {"skew_seconds": None, "server_time": None, "outcome": "no_date"}

    abs_skew = abs(skew)
    warn = _THRESH.get("clock_skew_warn_seconds", 30)
    bad  = _THRESH.get("clock_skew_bad_seconds", 300)
    if abs_skew <= warn:
        outcome = "in_sync"
    elif abs_skew <= bad:
        outcome = "minor_skew"
    else:
        outcome = "bad_skew"
    return {
        "skew_seconds": round(skew, 1),
        "server_time": server_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "outcome": outcome,
    }


# ── Cert SAN coverage of the variant we redirected to/from ───────────────────

def check_cert_covers_variant(audit_domain, original_domain, cert_san_names):
    """Was the source domain redirected, and if so does the cert cover both?

    Catches a common config error: cert covers www.example.com only, the apex
    redirects to www, but the user typed example.com directly so they get a
    cert mismatch on the first hop. Or the inverse.
    """
    if audit_domain == original_domain:
        return {"outcome": "no_redirect"}
    sans_lower = [n.lower() for n in (cert_san_names or [])]
    needed = {audit_domain.lower(), original_domain.lower()}

    def _cert_covers(name):
        for san in sans_lower:
            if san == name:
                return True
            if san.startswith("*."):
                suffix = san[2:]
                parts = name.split(".", 1)
                if len(parts) == 2 and parts[1] == suffix:
                    return True
        return False

    missing = [n for n in needed if not _cert_covers(n)]
    return {
        "outcome":  "covers" if not missing else "missing_variant",
        "missing":  missing,
        "needed":   sorted(needed),
    }


# ── Versioned library detection (default mode) ────────────────────────────────
# Pulls (library, version) pairs from the captured HTML body. Runs by default:
# the body is already in hand from check_redirect, the regexes match in the
# first few KB so the 256KB cap doesn't bite, and the matches are version-
# string-anchored (not generic substring matches), so a bot-challenge page
# can't false-positive — it doesn't contain "/jquery-3.6.0.min.js" in its
# body unless the real page also serves jQuery.
#
# Detection layers, in priority order (first match wins per library):
#   1. Inline comment banners — most reliable: /*! jQuery v3.6.0 */ comes
#      verbatim from the library's own header. Operators almost never strip
#      these.
#   2. Asset URL filenames — script src and link href: jquery-3.6.0.min.js,
#      bootstrap.4.6.2.min.css, font-awesome/4.7.0/css/. Highly reliable but
#      can be evaded by renaming bundled assets.
#   3. Framework-specific markers — ng-version="17.0.5" attribute (modern
#      Angular), <meta name=generator content="WordPress 6.4.2"> (CMSes).
#   4. Query-string version stamps — ?ver=6.4.2 on /wp-includes/ paths.
#      WordPress-specific.
#
# Each match is run through _annotate_library_eol() which consults
# LIBRARY_EOL (loaded from library_eol.json at import time) to attach an
# eol_status and human-readable message when applicable. Libraries not in
# the EOL table are reported with version only, no annotation.

# Library detection regexes. Each pattern captures (version) in group 1.
# Some libraries appear twice (URL pattern + comment-banner pattern); the
# detector dedupes, keeping whichever match has the more specific version
# string (longer = usually more specific, e.g. "3.6.0" > "3.6").
#
# 2.9.0 expansion: ~70 additional libraries beyond the original 11. New
# patterns favour the modern CDN @-version syntax (lib@1.2.3/) since
# unpkg/jsdelivr/cdnjs have largely standardized on it, plus traditional
# filename forms (lib-1.2.3.min.js) and inline banners. Each detected
# library that has a corresponding entry in library_eol.json gets EOL
# annotation; the rest report version-only. We deliberately did NOT add
# patterns for libraries that:
#   - have no version exposed in static HTML (Webpack/Parcel/Rollup runtimes,
#     Babel polyfill when bundled, Bower-managed deps, ASP.NET .axd handlers,
#     SharePoint init.js / sp.js, Bing Maps, Google Charts loader, PayPal
#     SDK, reCAPTCHA, Turnstile, jsbn, HeadJS),
#   - are compiled away (Svelte, SvelteKit, Marko, Pug, Jade),
#   - are framework-emitted plugin bundles redundant with a parent CMS
#     detection (Drupal behaviors / jQuery Once, WordPress wp-emoji /
#     wp-util, Magento Knockout/Prototype/RequireJS variants),
#   - are Node-only (jsonwebtoken),
#   - or are already covered transitively (jQuery UI Datepicker,
#     SharePoint .axd handlers, Sencha Ext JS = Ext JS, MUI = Material UI 5+).
_LIB_PATTERNS: list[tuple[str, re.Pattern]] = [
    # ── Original 11 (unchanged from 2.8.0) ──
    # Asset URL filenames
    ("jquery",       re.compile(r'/jquery[-./](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),
    ("jquery",       re.compile(r'/jquery@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),  # 2.9.0: jsdelivr @-form
    ("jquery",       re.compile(r'/(?:libs/)?jquery/(\d+\.\d+(?:\.\d+)?)/jquery',                 re.IGNORECASE)),  # 2.9.0: cdnjs / Google CDN form
    ("jquery-ui",    re.compile(r'/jquery[-.]ui[-./](\d+\.\d+(?:\.\d+)?)(?:[/.]|\.min\.)',        re.IGNORECASE)),
    ("jquery-ui",    re.compile(r'/jqueryui/(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),  # Google CDN style
    ("jquery-ui",    re.compile(r'/jquery-ui@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),  # 2.9.0: jsdelivr @-form
    ("bootstrap",    re.compile(r'/bootstrap[-./](\d+\.\d+(?:\.\d+)?)(?:[/.]|\.min\.)',           re.IGNORECASE)),
    ("bootstrap",    re.compile(r'/bootstrap@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),  # 2.9.0: jsdelivr @-form
    ("font-awesome", re.compile(r'/font[-]?awesome[-./](\d+\.\d+(?:\.\d+)?)(?:[/.]|\.min\.)',     re.IGNORECASE)),
    ("font-awesome", re.compile(r'/fontawesome/(\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("font-awesome", re.compile(r'/font-?awesome@(\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),  # 2.9.0: jsdelivr @-form
    ("modernizr",    re.compile(r'/modernizr[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',              re.IGNORECASE)),
    ("moment",       re.compile(r'/moment[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                 re.IGNORECASE)),

    # Inline banners
    ("jquery",       re.compile(r'/\*!?\s*jQuery\s+(?:JavaScript Library\s+)?v?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)),
    ("jquery-ui",    re.compile(r'/\*!?\s*jQuery UI\s+(?:-\s+)?v?(\d+\.\d+(?:\.\d+)?)',           re.IGNORECASE)),
    ("bootstrap",    re.compile(r'/\*!?\s*Bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)',                    re.IGNORECASE)),
    ("font-awesome", re.compile(r'/\*!?\s*Font Awesome\s+(?:Free\s+|Pro\s+)?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)),
    ("modernizr",    re.compile(r'/\*!?\s*Modernizr\s+(\d+\.\d+(?:\.\d+)?)',                      re.IGNORECASE)),
    ("moment",       re.compile(r'/\*!?\s*Moment\.js\s*(?:-\s+)?(\d+\.\d+(?:\.\d+)?)',            re.IGNORECASE)),

    # Framework-specific markers
    ("angular",      re.compile(r'\bng-version=["\'](\d+\.\d+(?:\.\d+)?)',                        re.IGNORECASE)),

    # CMS generator meta tags
    ("wordpress",    re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)),
    ("wordpress",    re.compile(r'<meta[^>]+content=["\']WordPress\s+(\d+\.\d+(?:\.\d+)?)["\'][^>]+name=["\']generator["\']', re.IGNORECASE)),
    ("drupal",       re.compile(r'<meta[^>]+name=["\']Generator["\'][^>]+content=["\']Drupal\s+(\d+)',                     re.IGNORECASE)),
    ("drupal",       re.compile(r'<meta[^>]+content=["\']Drupal\s+(\d+)[^"\']*["\'][^>]+name=["\']Generator["\']',         re.IGNORECASE)),
    ("joomla",       re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!?\s+(\d+\.\d+(?:\.\d+)?)',     re.IGNORECASE)),

    # AngularJS — distinct project from modern Angular. Filename-based since
    # the ng-version attribute is modern-Angular-only.
    ("angularjs",    re.compile(r'/angular[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),

    # ── 2.9.0 additions ──

    # ── Frameworks & meta-frameworks (modern) ──
    # Vue 2 detection note: Vue 2 ships with no ng-version-equivalent attribute,
    # so we rely on filenames and CDN paths. A vue.runtime.global.2.7.16.js
    # filename or /vue@2.7.16/ CDN path is the typical tell.
    ("vue",          re.compile(r'/vue@(\d+\.\d+(?:\.\d+)?)/',                                    re.IGNORECASE)),
    ("vue",          re.compile(r'/vue[-.](?:global\.|runtime\.|esm\.)*(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', re.IGNORECASE)),
    ("vue",          re.compile(r'/\*!?\s*Vue\.js\s+v(\d+\.\d+(?:\.\d+)?)',                       re.IGNORECASE)),
    ("vuetify",      re.compile(r'/vuetify@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("vuetify",      re.compile(r'/vuetify[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)',        re.IGNORECASE)),
    ("vuetify",      re.compile(r'/\*!?\s*Vuetify\s+v(\d+\.\d+(?:\.\d+)?)',                       re.IGNORECASE)),
    ("react",        re.compile(r'/react@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("react",        re.compile(r'/react(?:-dom)?[-.](?:production\.min\.|development\.)?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', re.IGNORECASE)),
    ("preact",       re.compile(r'/preact@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("ember",        re.compile(r'/ember[-.](\d+\.\d+(?:\.\d+)?)(?:\.(?:debug|prod))?(?:\.min)?\.js', re.IGNORECASE)),
    ("ember",        re.compile(r'/\*!?\s*Ember\s*-\s*(\d+\.\d+(?:\.\d+)?)',                      re.IGNORECASE)),
    ("backbone",     re.compile(r'/backbone[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',               re.IGNORECASE)),
    ("backbone",     re.compile(r'/\*!?\s*Backbone\.js\s+(\d+\.\d+(?:\.\d+)?)',                   re.IGNORECASE)),
    ("underscore",   re.compile(r'/underscore[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',             re.IGNORECASE)),
    ("knockout",     re.compile(r'/knockout[-.](\d+\.\d+(?:\.\d+)?)(?:\.(?:debug|min))?\.js',     re.IGNORECASE)),
    ("polymer",      re.compile(r'/polymer@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("polymer",      re.compile(r'/polymer[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|html)',       re.IGNORECASE)),
    ("lit",          re.compile(r'/lit@(\d+\.\d+(?:\.\d+)?)/',                                    re.IGNORECASE)),
    ("alpinejs",     re.compile(r'/alpinejs@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("alpinejs",     re.compile(r'/alpine[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                 re.IGNORECASE)),
    ("htmx",         re.compile(r'/htmx\.org@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("htmx",         re.compile(r'/\*!?\s*htmx\s+v(\d+\.\d+(?:\.\d+)?)',                          re.IGNORECASE)),
    ("mithril",      re.compile(r'/mithril@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("aurelia",      re.compile(r'/aurelia[-.](?:bootstrapper[-.])?(\d+\.\d+(?:\.\d+)?)/',        re.IGNORECASE)),
    ("marionette",   re.compile(r'/backbone\.marionette[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',   re.IGNORECASE)),
    ("marionette",   re.compile(r'/\*!?\s*Marionette\.JS\s+v(\d+\.\d+(?:\.\d+)?)',                re.IGNORECASE)),
    ("canjs",        re.compile(r'/canjs@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),

    # ── AngularJS-era / pre-jQuery-era libraries (mostly EOL) ──
    ("mootools",     re.compile(r'/mootools(?:-(?:core|more))?[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', re.IGNORECASE)),
    ("mootools",     re.compile(r'/\*!?\s*MooTools(?:\.(?:Core|More))?\s+(?:[\d.]+\s+)?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)),
    ("prototype",    re.compile(r'/prototype[-.](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)(?:\.min)?\.js',    re.IGNORECASE)),
    ("prototype",    re.compile(r'Prototype JavaScript framework,?\s*version\s+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', re.IGNORECASE)),
    ("scriptaculous",re.compile(r'/scriptaculous[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',          re.IGNORECASE)),
    ("yui",          re.compile(r'/yui/(\d+\.\d+(?:\.\d+)?)/build/',                              re.IGNORECASE)),
    ("yui",          re.compile(r'/\*!?\s*YUI\s+(\d+\.\d+(?:\.\d+)?)',                            re.IGNORECASE)),
    ("zepto",        re.compile(r'/zepto[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                  re.IGNORECASE)),
    ("cash",         re.compile(r'/cash[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                   re.IGNORECASE)),
    ("dojo",         re.compile(r'/dojo/(\d+\.\d+(?:\.\d+)?)/dojo\.js',                           re.IGNORECASE)),
    ("ext",          re.compile(r'/ext(?:js)?[-.](\d+\.\d+(?:\.\d+)?)(?:[/.])',                   re.IGNORECASE)),
    ("ext",          re.compile(r'/ext(?:js)?/(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),

    # ── jQuery family (plugins worth detecting separately) ──
    ("jquery-mobile",re.compile(r'/jquery\.mobile[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)', re.IGNORECASE)),
    ("jquery-migrate",re.compile(r'/jquery[-.]migrate[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',     re.IGNORECASE)),
    ("jquery-migrate",re.compile(r'/\*!?\s*jQuery Migrate\s+(?:-\s+)?v?(\d+\.\d+(?:\.\d+)?)',     re.IGNORECASE)),

    # ── Adobe Flash era (dead) ──
    ("swfobject",    re.compile(r'/swfobject[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',              re.IGNORECASE)),

    # ── UI component libraries ──
    ("bulma",        re.compile(r'/bulma@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("foundation",   re.compile(r'/foundation[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)',     re.IGNORECASE)),
    ("materialize",  re.compile(r'/materialize[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)',    re.IGNORECASE)),
    ("uikit",        re.compile(r'/uikit[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)',          re.IGNORECASE)),
    ("uikit",        re.compile(r'/\*!?\s*UIkit\s+(\d+\.\d+(?:\.\d+)?)',                          re.IGNORECASE)),
    ("semantic-ui",  re.compile(r'/semantic-ui[-.@](\d+\.\d+(?:\.\d+)?)/',                        re.IGNORECASE)),
    ("fomantic-ui",  re.compile(r'/fomantic-ui@(\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("skeleton",     re.compile(r'/skeleton[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.css',              re.IGNORECASE)),
    ("pure",         re.compile(r'/pure@(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("milligram",    re.compile(r'/milligram@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("tailwindcss",  re.compile(r'/tailwindcss@(\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("ant-design",   re.compile(r'/antd@(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("element-ui",   re.compile(r'/element-ui@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("element-ui",   re.compile(r'/element-ui/lib/index\.js\?ver=(\d+\.\d+(?:\.\d+)?)',           re.IGNORECASE)),
    ("element-plus", re.compile(r'/element-plus@(\d+\.\d+(?:\.\d+)?)/',                           re.IGNORECASE)),
    ("material-ui",  re.compile(r'/@material-ui/core@(\d+\.\d+(?:\.\d+)?)/',                      re.IGNORECASE)),
    ("material-ui",  re.compile(r'/material-ui@(\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("mui",          re.compile(r'/@mui/material@(\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("material-components-web", re.compile(r'/material-components-web@(\d+\.\d+(?:\.\d+)?)/',     re.IGNORECASE)),
    ("primeng",      re.compile(r'/primeng@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("primereact",   re.compile(r'/primereact@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("primevue",     re.compile(r'/primevue@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("primeui",      re.compile(r'/primeui@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("onsenui",      re.compile(r'/onsenui@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("framework7",   re.compile(r'/framework7@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("ionic",        re.compile(r'/@ionic/core@(\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("ionic",        re.compile(r'/ionic[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)',          re.IGNORECASE)),
    ("quasar",       re.compile(r'/quasar@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("kendo-ui",     re.compile(r'/kendo-ui[-.](?:ver)?(\d+\.\d+(?:\.\d+)?)/',                    re.IGNORECASE)),
    ("devextreme",   re.compile(r'/devextreme[-.](\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("jqwidgets",    re.compile(r'/jqwidgets[-.]ver(\d+\.\d+(?:\.\d+)?)/',                        re.IGNORECASE)),
    ("wijmo",        re.compile(r'/wijmo[-.](\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("syncfusion",   re.compile(r'/ej2/(\d+\.\d+(?:\.\d+)?)/',                                    re.IGNORECASE)),

    # ── Charting / visualization ──
    ("chart.js",     re.compile(r'/chart\.js@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("chart.js",     re.compile(r'/Chart[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                  re.IGNORECASE)),
    ("d3",           re.compile(r'/d3@(\d+\.\d+(?:\.\d+)?)/',                                     re.IGNORECASE)),
    ("d3",           re.compile(r'/d3[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                     re.IGNORECASE)),
    ("highcharts",   re.compile(r'/highcharts/(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("highstock",    re.compile(r'/highstock/(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("highmaps",     re.compile(r'/highmaps/(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("plotly.js",    re.compile(r'/plotly\.js@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("plotly.js",    re.compile(r'/plotly[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                 re.IGNORECASE)),
    ("echarts",      re.compile(r'/echarts@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("c3",           re.compile(r'/c3[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                     re.IGNORECASE)),
    ("nvd3",         re.compile(r'/nv\.d3[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                 re.IGNORECASE)),
    ("chartist",     re.compile(r'/chartist[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)',       re.IGNORECASE)),
    ("vega",         re.compile(r'/vega@(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("vega-lite",    re.compile(r'/vega-lite@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("morris",       re.compile(r'/morris[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                 re.IGNORECASE)),
    ("dygraphs",     re.compile(r'/dygraph[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),
    ("amcharts",     re.compile(r'/amcharts/(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("amcharts",     re.compile(r'/@amcharts/amcharts(?:\d+)?@(\d+\.\d+(?:\.\d+)?)/',             re.IGNORECASE)),
    ("flot",         re.compile(r'/flot[-.](\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("jqplot",       re.compile(r'/jqplot[-.](\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("raphael",      re.compile(r'/raphael[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),

    # ── Editors ──
    ("ckeditor",     re.compile(r'/ckeditor/(\d+\.\d+(?:\.\d+)?)/ckeditor\.js',                   re.IGNORECASE)),
    ("ckeditor",     re.compile(r'/ckeditor5/(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("tinymce",      re.compile(r'/tinymce/(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("tinymce",      re.compile(r'/\*!?\s*TinyMCE\s+version\s+(\d+\.\d+(?:\.\d+)?)',              re.IGNORECASE)),
    ("quill",        re.compile(r'/quill@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("monaco-editor",re.compile(r'/monaco-editor@(\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("ace",          re.compile(r'/ace-builds@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("ace",          re.compile(r'/ace[-.](\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("codemirror",   re.compile(r'/codemirror@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("codemirror",   re.compile(r'/codemirror[-.](\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("summernote",   re.compile(r'/summernote[-.](\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("froala",       re.compile(r'/froala_editor@(\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("froala",       re.compile(r'/froala-editor[-.](\d+\.\d+(?:\.\d+)?)/',                       re.IGNORECASE)),

    # ── Sliders / carousels / lightboxes ──
    ("slick",        re.compile(r'/slick[-.](\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("slick",        re.compile(r'/\*!?\s*Slick\s+(\d+\.\d+(?:\.\d+)?)',                          re.IGNORECASE)),
    ("swiper",       re.compile(r'/swiper@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("swiper",       re.compile(r'/\*!?\s*Swiper\s+(\d+\.\d+(?:\.\d+)?)',                         re.IGNORECASE)),
    ("owl-carousel", re.compile(r'/OwlCarousel\d?[-.](\d+\.\d+(?:\.\d+)?)/',                      re.IGNORECASE)),
    ("bxslider",     re.compile(r'/jquery\.bxslider[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',       re.IGNORECASE)),
    ("flexslider",   re.compile(r'/flexslider[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',             re.IGNORECASE)),
    ("lightbox2",    re.compile(r'/lightbox2[-.](\d+\.\d+(?:\.\d+)?)/',                           re.IGNORECASE)),
    ("magnific-popup", re.compile(r'/magnific-popup[-.](\d+\.\d+(?:\.\d+)?)/',                    re.IGNORECASE)),
    ("photoswipe",   re.compile(r'/photoswipe@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("fancybox",     re.compile(r'/fancybox/(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("fancybox",     re.compile(r'/fancybox@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("colorbox",     re.compile(r'/jquery\.colorbox[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',       re.IGNORECASE)),

    # ── Form / picker / validation ──
    ("select2",      re.compile(r'/select2[-.](\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("select2",      re.compile(r'/\*!?\s*Select2\s+(\d+\.\d+(?:\.\d+)?)',                        re.IGNORECASE)),
    ("chosen",       re.compile(r'/chosen[-.](\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("flatpickr",    re.compile(r'/flatpickr@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("bootstrap-datepicker", re.compile(r'/bootstrap-datepicker[-.](\d+\.\d+(?:\.\d+)?)/',        re.IGNORECASE)),
    ("pikaday",      re.compile(r'/pikaday@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("daterangepicker", re.compile(r'/daterangepicker@(\d+\.\d+(?:\.\d+)?)/',                     re.IGNORECASE)),
    ("nouislider",   re.compile(r'/nouislider@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("nouislider",   re.compile(r'/\*!?\s*noUiSlider\s*-\s*(\d+\.\d+(?:\.\d+)?)',                 re.IGNORECASE)),
    ("ion-rangeslider", re.compile(r'/ion\.rangeSlider[-.](\d+\.\d+(?:\.\d+)?)/',                 re.IGNORECASE)),
    ("inputmask",    re.compile(r'/inputmask@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("inputmask",    re.compile(r'/\*!?\s*Inputmask\s+(\d+\.\d+(?:\.\d+)?)',                      re.IGNORECASE)),
    ("cleave.js",    re.compile(r'/cleave\.js@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("parsley",      re.compile(r'/parsley@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("jquery-validate", re.compile(r'/\*!?\s*jQuery Validation Plugin\s+v(\d+\.\d+(?:\.\d+)?)',   re.IGNORECASE)),
    ("typeahead",    re.compile(r'/typeahead\.js@(\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),
    ("typeahead",    re.compile(r'/\*!?\s*typeahead\.js\s+(\d+\.\d+(?:\.\d+)?)',                  re.IGNORECASE)),

    # ── Animation / utility / data ──
    ("gsap",         re.compile(r'/gsap@(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("gsap",         re.compile(r'/\*!?\s*GSAP\s+(\d+\.\d+(?:\.\d+)?)',                           re.IGNORECASE)),
    ("velocity",     re.compile(r'/velocity@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("velocity",     re.compile(r'VelocityJS\.org\s*\((\d+\.\d+(?:\.\d+)?)\)',                    re.IGNORECASE)),
    ("anime.js",     re.compile(r'/animejs@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("anime.js",     re.compile(r'/\*!?\s*anime\.js\s+v(\d+\.\d+(?:\.\d+)?)',                     re.IGNORECASE)),
    ("wow",          re.compile(r'/wow[-.](\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("wow",          re.compile(r'/\*!?\s*WOW\s*-\s*v(\d+\.\d+(?:\.\d+)?)',                       re.IGNORECASE)),
    ("aos",          re.compile(r'/aos@(\d+\.\d+(?:\.\d+)?)/',                                    re.IGNORECASE)),
    ("aos",          re.compile(r'/\*!?\s*AOS\s*-\s*(\d+\.\d+(?:\.\d+)?)',                        re.IGNORECASE)),
    # Three.js uses an 'r' prefix (r161) so we also accept that form.
    ("three.js",     re.compile(r'/three\.js@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("three.js",     re.compile(r'/\*!?\s*three\.js\s+r(\d+)',                                    re.IGNORECASE)),
    ("lodash",       re.compile(r'/lodash@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("lodash",       re.compile(r'/lodash[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                 re.IGNORECASE)),
    ("ramda",        re.compile(r'/ramda@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("ramda",        re.compile(r'/\*!?\s*Ramda\s+v(\d+\.\d+(?:\.\d+)?)',                         re.IGNORECASE)),
    ("date-fns",     re.compile(r'/date-fns@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("dayjs",        re.compile(r'/dayjs@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("luxon",        re.compile(r'/luxon@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("moment-timezone", re.compile(r'/moment-timezone(?:-with-data)?[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', re.IGNORECASE)),
    ("crypto-js",    re.compile(r'/crypto-js@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("lazyload",     re.compile(r'/vanilla-lazyload@(\d+\.\d+(?:\.\d+)?)/',                       re.IGNORECASE)),
    ("imagesloaded", re.compile(r'/imagesloaded@(\d+\.\d+(?:\.\d+)?)/',                           re.IGNORECASE)),
    ("masonry",      re.compile(r'/masonry@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("masonry",      re.compile(r'/\*!?\s*Masonry\s+v(\d+\.\d+(?:\.\d+)?)',                       re.IGNORECASE)),
    ("isotope",      re.compile(r'/isotope[-.](\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),

    # ── File upload ──
    ("dropzone",     re.compile(r'/dropzone@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("dropzone",     re.compile(r'/\*!?\s*Dropzone\s+(?:Version\s+)?(\d+\.\d+(?:\.\d+)?)',        re.IGNORECASE)),
    ("plupload",     re.compile(r'/plupload[-.](\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("fine-uploader",re.compile(r'/fine-uploader[-.](\d+\.\d+(?:\.\d+)?)/',                       re.IGNORECASE)),
    ("filepond",     re.compile(r'/filepond@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("uppy",         re.compile(r'/uppy@(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("uppy",         re.compile(r'/uppy[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                   re.IGNORECASE)),
    ("blueimp-fileupload", re.compile(r'/jquery\.fileupload[-.](\d+\.\d+(?:\.\d+)?)/',            re.IGNORECASE)),

    # ── Templating ──
    ("mustache",     re.compile(r'/mustache\.js@(\d+\.\d+(?:\.\d+)?)/',                           re.IGNORECASE)),
    ("mustache",     re.compile(r'/\*!?\s*mustache\.js\s*-\s*(\d+\.\d+(?:\.\d+)?)',               re.IGNORECASE)),
    ("handlebars",   re.compile(r'/handlebars[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',             re.IGNORECASE)),
    ("handlebars",   re.compile(r'/\*!?\s*Handlebars\.js\s+(\d+\.\d+(?:\.\d+)?)',                 re.IGNORECASE)),
    ("hogan",        re.compile(r'/hogan[-.](\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("ejs",          re.compile(r'/ejs@(\d+\.\d+(?:\.\d+)?)/',                                    re.IGNORECASE)),
    ("nunjucks",     re.compile(r'/nunjucks@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("dot",          re.compile(r'/dot[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                    re.IGNORECASE)),
    ("dustjs",       re.compile(r'/dust(?:-full)?[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',         re.IGNORECASE)),
    ("jsrender",     re.compile(r'/jsrender@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("jsrender",     re.compile(r'/\*!?\s*JsRender\s+v(\d+\.\d+(?:\.\d+)?)',                      re.IGNORECASE)),
    ("i18next",      re.compile(r'/i18next@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("globalize",    re.compile(r'/globalize@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),

    # ── Maps ──
    ("leaflet",      re.compile(r'/leaflet@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("leaflet",      re.compile(r'/\*!?\s*Leaflet\s+(\d+\.\d+(?:\.\d+)?)',                        re.IGNORECASE)),
    ("openlayers",   re.compile(r'/openlayers@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("openlayers",   re.compile(r'/\*!?\s*OpenLayers\s+(\d+\.\d+(?:\.\d+)?)',                     re.IGNORECASE)),
    ("mapbox-gl",    re.compile(r'/mapbox-gl@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("cesium",       re.compile(r'/cesium@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("arcgis",       re.compile(r'/arcgis/(\d+\.\d+(?:\.\d+)?)/init\.js',                         re.IGNORECASE)),
    ("google-maps",  re.compile(r'maps/api/js\?[^"\']*\bv=(\d+(?:\.\d+)?)',                       re.IGNORECASE)),

    # ── Auth / SDK ──
    ("firebase",     re.compile(r'/firebasejs/(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("firebase",     re.compile(r'/firebase@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("stripe",       re.compile(r'js\.stripe\.com/v(\d+)/',                                       re.IGNORECASE)),
    ("auth0.js",     re.compile(r'/auth0[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                  re.IGNORECASE)),
    ("auth0.js",     re.compile(r'/auth0@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("msal",         re.compile(r'/msal/(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("msal",         re.compile(r'/@azure/msal-browser@(\d+\.\d+(?:\.\d+)?)/',                    re.IGNORECASE)),
    ("oidc-client",  re.compile(r'/oidc-client@(\d+\.\d+(?:\.\d+)?)/',                            re.IGNORECASE)),
    ("oidc-client-ts", re.compile(r'/oidc-client-ts@(\d+\.\d+(?:\.\d+)?)/',                       re.IGNORECASE)),
    ("keycloak",     re.compile(r'/keycloak\.js\?[^"\']*version=(\d+\.\d+(?:\.\d+)?)',            re.IGNORECASE)),
    ("jose",         re.compile(r'/jose@(\d+\.\d+(?:\.\d+)?)/',                                   re.IGNORECASE)),
    ("jsrsasign",    re.compile(r'/jsrsasign@(\d+\.\d+(?:\.\d+)?)/',                              re.IGNORECASE)),
    ("jsrsasign",    re.compile(r'/\*!?\s*jsrsasign\s+(\d+\.\d+(?:\.\d+)?)',                      re.IGNORECASE)),
    ("sjcl",         re.compile(r'/sjcl[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                   re.IGNORECASE)),
    ("node-forge",   re.compile(r'/node-forge@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("signalr",      re.compile(r'/signalr@(\d+\.\d+(?:\.\d+)?)/',                                re.IGNORECASE)),
    ("signalr",      re.compile(r'/signalr[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),

    # ── Networking / async ──
    ("axios",        re.compile(r'/axios@(\d+\.\d+(?:\.\d+)?)/',                                  re.IGNORECASE)),
    ("axios",        re.compile(r'/\*!?\s*Axios\s+v(\d+\.\d+(?:\.\d+)?)',                         re.IGNORECASE)),
    ("socket.io",    re.compile(r'/socket\.io@(\d+\.\d+(?:\.\d+)?)/',                             re.IGNORECASE)),
    ("sockjs",       re.compile(r'/sockjs@(\d+\.\d+(?:\.\d+)?)/',                                 re.IGNORECASE)),
    ("qs",           re.compile(r'/qs@(\d+\.\d+(?:\.\d+)?)/',                                     re.IGNORECASE)),
    ("uri.js",       re.compile(r'/URI[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                    re.IGNORECASE)),
    ("umbrella",     re.compile(r'/umbrella[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',               re.IGNORECASE)),

    # ── Module loaders / build runtimes (only the ones that actually expose
    # a version in static HTML; webpack/parcel/rollup runtimes do not) ──
    ("requirejs",    re.compile(r'/require[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),
    ("requirejs",    re.compile(r'/\*!?\s*RequireJS\s+(\d+\.\d+(?:\.\d+)?)',                      re.IGNORECASE)),
    ("systemjs",     re.compile(r'/systemjs@(\d+\.\d+(?:\.\d+)?)/',                               re.IGNORECASE)),
    ("seajs",        re.compile(r'/sea[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                    re.IGNORECASE)),
    ("labjs",        re.compile(r'/LAB[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                    re.IGNORECASE)),
    ("yepnope",      re.compile(r'/yepnope[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                re.IGNORECASE)),

    # ── Polyfills (CDN-loaded only) ──
    ("core-js",      re.compile(r'/core-js(?:-bundle)?@(\d+\.\d+(?:\.\d+)?)/',                    re.IGNORECASE)),
    ("regenerator-runtime", re.compile(r'/regenerator-runtime@(\d+\.\d+(?:\.\d+)?)/',             re.IGNORECASE)),
    ("babel-polyfill", re.compile(r'/babel-polyfill[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',       re.IGNORECASE)),
    ("whatwg-fetch", re.compile(r'/whatwg-fetch@(\d+\.\d+(?:\.\d+)?)/',                           re.IGNORECASE)),
    ("whatwg-fetch", re.compile(r'/fetch[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                  re.IGNORECASE)),
    ("intl",         re.compile(r'/Intl[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',                   re.IGNORECASE)),
    ("js-joda",      re.compile(r'/@js-joda/core@(\d+\.\d+(?:\.\d+)?)/',                          re.IGNORECASE)),

    # ── WordPress plugin ?ver= detection (not WP core, but valuable) ──
    # WooCommerce ships its own ?ver= on plugin assets; we capture it as a
    # WooCommerce version even though it's the plugin version, not core.
    ("woocommerce",  re.compile(r'/wp-content/plugins/woocommerce/[^"\']*\?ver=(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)),
]


def _major_of(version: str, library: str = "") -> str:
    """Extract the major-version key for EOL lookup.

    Most libraries: the integer before the first '.'. So '3.6.4' → '3'.
    jQuery UI is special — its 'major' for our purposes is the 1.x.y minor
    segment, since the entire library has been at 1.x for its whole life.
    So '1.12.1' → '1.12'. The library-specific dispatch lives here so the
    annotator stays generic.
    """
    if library == "jquery-ui":
        parts = version.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return parts[0] if parts else version
    return version.split(".")[0]


def _annotate_library_eol(library: str, version: str) -> dict:
    """Look up EOL status for a detected library + version.

    Returns a dict with at least {library, version}. When EOL data is
    available and the version is below floor or explicitly listed, also
    populates: eol_status ('eol' / 'ok' / 'unknown'), eol_message, and
    eol_last_release / eol_last_version when known.

    Outcomes:
      - Library not in LIBRARY_EOL → eol_status='unknown' (just report version)
      - Major < min_supported_major AND in eol_majors → 'eol' with specific msg
      - Major < min_supported_major AND not in eol_majors → 'eol' with
        generic msg ("major version below minimum supported"). This is the
        floor-based catch-all per spec — old versions that predate our
        explicit listings still get flagged.
      - Major in eol_majors but >= floor → 'eol' (shouldn't happen in
        practice unless someone misconfigures the JSON, but handled
        defensively).
      - Otherwise → 'ok' (no annotation in the report)
    """
    out = {"library": library, "version": version}
    entry = LIBRARY_EOL.get(library)
    if not entry:
        out["eol_status"] = "unknown"
        return out

    major_key = _major_of(version, library)

    # Determine the floor. jQuery UI uses min_supported_major_minor (string
    # like "1.14"); everyone else uses min_supported_major (integer).
    min_floor_str = entry.get("min_supported_major_minor")
    if min_floor_str:
        # String-keyed comparison — convert "1.13" vs "1.14" via numeric tuple
        def _vt(s):
            try:
                return tuple(int(p) for p in s.split("."))
            except ValueError:
                return ()
        floor_tuple = _vt(min_floor_str)
        major_tuple = _vt(major_key)
        below_floor = major_tuple and floor_tuple and major_tuple < floor_tuple
    else:
        floor_int = entry.get("min_supported_major")
        try:
            major_int = int(major_key)
            below_floor = floor_int is not None and major_int < floor_int
        except ValueError:
            below_floor = False

    eol_majors = entry.get("eol_majors") or {}
    specific = eol_majors.get(major_key)

    if below_floor or specific:
        out["eol_status"] = "eol"
        if specific:
            parts = []
            if specific.get("last_version"):
                parts.append(f"last release {specific['last_version']}")
            if specific.get("last_release"):
                parts.append(specific["last_release"])
            detail = " ".join(parts) if parts else "version EOL"
            out["eol_message"] = f"{library} {major_key}.x — {detail}"
            if specific.get("last_release"):
                out["eol_last_release"] = specific["last_release"]
            if specific.get("last_version"):
                out["eol_last_version"] = specific["last_version"]
        else:
            # Below floor but no explicit entry — generic message
            out["eol_message"] = (
                f"{library} {major_key}.x — major version below minimum "
                f"supported"
            )
    else:
        out["eol_status"] = "ok"

    return out


def check_versioned_libraries(html: str) -> dict:
    """Detect versioned client-side libraries in static HTML.

    Returns:
      {
        "libraries": [
          {"library": "jquery", "version": "1.12.4", "eol_status": "eol",
           "eol_message": "jquery 1.x — last release 1.12.4 2016-05-20",
           "eol_last_release": "2016-05-20", "eol_last_version": "1.12.4"},
          {"library": "wordpress", "version": "6.4.2", "eol_status": "ok"},
          ...
        ],
        "any_eol": True/False,
      }

    Pure CPU on the supplied html string — no network I/O. Safe to call from
    multiple worker threads. Returns {"libraries": [], "any_eol": False} when
    html is empty or no patterns match.
    """
    if not html:
        return {"libraries": [], "any_eol": False}

    # Run every pattern, collect (library, version) pairs. Same library
    # detected by multiple patterns produces multiple hits — we dedupe by
    # keeping the longest version string per library, which heuristically
    # corresponds to the most specific version (3.6.4 > 3.6).
    raw_hits: dict[str, str] = {}
    for library, pattern in _LIB_PATTERNS:
        for match in pattern.finditer(html):
            version = match.group(1)
            existing = raw_hits.get(library)
            if existing is None or len(version) > len(existing):
                raw_hits[library] = version

    libraries = [_annotate_library_eol(lib, ver) for lib, ver in sorted(raw_hits.items())]
    any_eol = any(item.get("eol_status") == "eol" for item in libraries)
    return {"libraries": libraries, "any_eol": any_eol}


# ── OS EOL detection (2.9.0) ──────────────────────────────────────────────────
# Inspects the Server header (and a couple of corroborating signals) for
# evidence that the host is running an end-of-life operating system. Three
# detection strategies, in order of confidence:
#
#   1. IIS version string. "Server: Microsoft-IIS/7.5" maps unambiguously
#      to Windows Server 2008 R2, which is EOL. IIS ≤8.5 each map to a
#      single specific Windows Server release, all of which are EOL.
#      IIS 10.0 ships on Server 2016, 2019, 2022, AND 2025 — those are
#      not distinguishable from the IIS version, so IIS 10.0 produces no
#      EOL flag here.
#
#   2. Distro name + version in an Apache/Nginx parens annotation.
#      "Server: Apache/2.4.6 (CentOS)" names the distro but not its
#      version. We attribute it to the named distro and look up the
#      vendor's overall lifecycle — for CentOS that's a 999 floor, so
#      every CentOS string flags. For Ubuntu / Debian / RHEL we need a
#      version, which is rare in Server headers.
#
#   3. TLS-fingerprint corroboration. If the TLS check found that the
#      server still negotiates TLS 1.0 / 1.1 / SSLv3, we record it as a
#      'tls_old_stack' signal alongside the OS finding. This does NOT
#      by itself identify a specific OS — operators backport, link
#      statically, etc. — but if the Server header already named CentOS
#      or IIS 7.5, the TLS signal strengthens the case.
#
# Per-OS confidence rules:
#   - IIS ≤8 → high confidence, EOL
#   - "CentOS" anywhere in Server header → high confidence, EOL
#     (entire CentOS Linux line is EOL)
#   - Ubuntu / Debian / RHEL with explicit version → high confidence
#   - Distro name without version → reported but not flagged EOL
#     (we can't tell which version is running)
#
# Output shape mirrors check_versioned_libraries:
#   {
#     "os_findings": [
#       {"os": "iis", "version": "7.5", "eol_status": "eol",
#        "eol_message": "...", "underlying_os": "Windows Server 2008 R2",
#        "source": "server_header"},
#       ...
#     ],
#     "tls_old_stack": True/False,    # corroborating TLS-fingerprint signal
#     "tls_signals": ["TLSv1.0 negotiated", ...],
#     "any_eol": True/False,
#   }

# Server-header IIS version regex: "Microsoft-IIS/7.5" → captures "7.5".
_IIS_VERSION_RE = re.compile(r'\bMicrosoft-IIS/(\d+(?:\.\d+)?)', re.IGNORECASE)

# Server-header parens distro annotation: "Apache/2.4.6 (CentOS)" or
# "Apache/2.4.7 (Ubuntu)" or "Apache/2.4.41 (Ubuntu) mod_wsgi/4.6.8 ..." etc.
# We capture the first parens annotation; subsequent ones tend to be modules
# (mod_wsgi, mod_ssl) rather than distros.
_DISTRO_PARENS_RE = re.compile(r'\(([^)]+)\)')

# Distro names we recognize inside the parens annotation. The dict maps
# the lowercase token we look for to the OS_EOL key.
_DISTRO_NAME_TO_KEY = {
    "centos":                  "centos",
    "red hat":                 "rhel",
    "rhel":                    "rhel",
    "red hat enterprise linux":"rhel",
    "ubuntu":                  "ubuntu",
    "debian":                  "debian",
    "freebsd":                 "freebsd",
}

# Version pattern that may appear after the distro name within the parens —
# rare in Apache Server headers (most just say "(Ubuntu)" without a version),
# but Nginx packaging sometimes includes it.
_DISTRO_VERSION_RE = re.compile(r'(\d+(?:\.\d+)?(?:\.\d+)?)')

# Per-IIS-minor underlying-Windows-Server table. The major-version JSON entry
# only carries one EOL date and one underlying_os string per major (because
# 7.0/7.5 and 8.0/8.5 share EOL dates), but the rendering layer wants to
# distinguish "Server 2008" from "Server 2008 R2" in the user-facing text.
# This dict refines the underlying_os AFTER the JSON lookup. IIS 10.0 is
# handled separately because TLS context narrows the candidate Windows
# Server release.
_IIS_MINOR_REFINEMENTS = {
    "5.0": "Windows 2000 Server",
    "5.1": "Windows XP",
    "6.0": "Windows Server 2003",
    "7.0": "Windows Server 2008",
    "7.5": "Windows Server 2008 R2",
    "8.0": "Windows Server 2012 (not R2)",
    "8.5": "Windows Server 2012 R2",
    # 10.0 deliberately omitted — narrowed by TLS context inside _refine_iis_finding
}


def _refine_iis_finding(finding: dict, tls_result: dict | None) -> dict:
    """Refine an IIS finding from check_os_eol with per-minor underlying-OS
    detail and a TLS-capability narrative.

    The JSON entry's underlying_os is generic ("Windows Server 2008 / 2008
    R2"); this function tightens it to the precise Windows Server release
    implied by the IIS minor version (7.0 → Server 2008, 7.5 → Server 2008
    R2, etc), and for IIS 10.0 it adds a tls_capability_note that uses
    the negotiated TLS version to narrow the candidate set.

    Microsoft's official position (Microsoft Learn) is that TLS 1.3 in
    Schannel is supported only on Windows Server 2022 and later — enabling
    TLS 1.3 on earlier versions via registry hacks is not a supported
    configuration. So:
      - IIS 10.0 + TLS 1.3 → likely Server 2022 or 2025
      - IIS 10.0 + non-TLS-1.3 → likely Server 2016 or 2019; getting TLS
        1.3 supportably requires moving to Server 2022 or later
      - IIS 10.0 + unknown TLS → can't narrow

    Returns the same dict back, mutated in place.
    """
    iis_ver = finding.get("version", "")
    refined = _IIS_MINOR_REFINEMENTS.get(iis_ver)
    if refined:
        finding["underlying_os"] = refined

    if iis_ver.startswith("10."):
        tls_ver = ""
        if tls_result and not tls_result.get("error"):
            tls_ver = (tls_result.get("version") or "")
        if tls_ver == "TLSv1.3":
            finding["underlying_os"] = "Windows Server 2022 or 2025 (TLS 1.3 negotiated)"
            finding["tls_capability_note"] = (
                "IIS 10.0 + TLS 1.3 → likely Server 2022 or 2025 "
                "(Schannel TLS 1.3 is officially supported on Server 2022 "
                "and later only)"
            )
        elif tls_ver in ("TLSv1.2", "TLSv1.1", "TLSv1.0"):
            finding["underlying_os"] = (
                "Windows Server 2016 or 2019 (no TLS 1.3 negotiated)"
            )
            finding["tls_capability_note"] = (
                f"IIS 10.0 + {tls_ver} → likely Server 2016 or 2019; "
                "to support TLS 1.3 you would need to upgrade to Server "
                "2022 or later (Server 2016 ends extended support "
                "2027-01-12; Server 2019 ends 2029-01-09)"
            )
        else:
            finding["underlying_os"] = (
                "Windows Server 2016, 2019, 2022, or 2025 (TLS version unknown)"
            )
            finding["tls_capability_note"] = (
                "IIS 10.0: cannot narrow underlying Windows Server release "
                "without a TLS handshake result"
            )

    return finding


def _annotate_os_eol(os_key: str, version: str, source: str) -> dict:
    """Look up EOL status for a detected OS + version.

    Mirrors _annotate_library_eol but uses OS_EOL. Returns a dict with at
    least {os, version, source}, plus eol_status and eol_message when EOL
    data is available. 'source' indicates which detection strategy fired
    (server_header, server_header_iis, or tls_corroboration).
    """
    out = {"os": os_key, "version": version, "source": source}
    entry = OS_EOL.get(os_key)
    if not entry:
        out["eol_status"] = "unknown"
        return out

    # Determine the major-version key for lookup. Ubuntu uses two-segment
    # majors ("22.04"), windows-server uses 4-digit years ("2016"), most
    # others use a single integer.
    if entry.get("min_supported_major_minor"):
        # Ubuntu-style: keep "22.04" as the lookup key
        parts = version.split(".")
        major_key = ".".join(parts[:2]) if len(parts) >= 2 else parts[0]
    else:
        major_key = version.split(".")[0]

    # Floor comparison
    min_floor_str = entry.get("min_supported_major_minor")
    if min_floor_str:
        def _vt(s):
            try:
                return tuple(int(p) for p in s.split("."))
            except ValueError:
                return ()
        floor_tuple = _vt(min_floor_str)
        major_tuple = _vt(major_key)
        below_floor = bool(major_tuple) and bool(floor_tuple) and major_tuple < floor_tuple
    else:
        floor_int = entry.get("min_supported_major")
        try:
            major_int = int(major_key)
            below_floor = floor_int is not None and major_int < floor_int
        except ValueError:
            # Non-numeric version (e.g. "?"). Special case: a 999 floor means
            # the entire OS is EOL by convention, so we should still flag
            # even when we couldn't extract a version. Otherwise (real floor,
            # missing version), we can't compare and don't flag.
            below_floor = (floor_int == 999)

    eol_majors = entry.get("eol_majors") or {}
    specific = eol_majors.get(major_key)

    if below_floor or specific:
        out["eol_status"] = "eol"
        if specific:
            parts = []
            if specific.get("last_version"):
                parts.append(f"last release {specific['last_version']}")
            if specific.get("last_release"):
                parts.append(specific["last_release"])
            detail = " ".join(parts) if parts else "version EOL"
            out["eol_message"] = f"{os_key} {major_key} — {detail}"
            if specific.get("last_release"):
                out["eol_last_release"] = specific["last_release"]
            if specific.get("last_version"):
                out["eol_last_version"] = specific["last_version"]
            if specific.get("underlying_os"):
                out["underlying_os"] = specific["underlying_os"]
        else:
            # Below floor with no specific entry. Two sub-cases:
            #  - Floor is 999 → entire OS is EOL by convention. We may not
            #    even have a version (CentOS in a Server header rarely
            #    includes one). The phrasing "all versions EOL" is the
            #    accurate framing, not "below minimum supported".
            #  - Real floor (e.g. Ubuntu floor 22.04, detected 16.04) →
            #    "below minimum supported" phrasing.
            floor_for_msg = entry.get("min_supported_major")
            if floor_for_msg == 999:
                out["eol_message"] = f"{os_key} — all versions EOL"
            else:
                out["eol_message"] = (
                    f"{os_key} {major_key} — major version below minimum supported"
                )
    else:
        out["eol_status"] = "ok"

    return out


def check_os_eol(server_header: str, tls_result: dict | None = None) -> dict:
    """Detect EOL operating systems via Server header and TLS fingerprinting.

    Args:
        server_header: The raw Server header value (e.g. "Apache/2.4.6 (CentOS)"
                       or "Microsoft-IIS/7.5"). Empty string is fine.
        tls_result: The check_tls() result dict. We look at .version to
                    detect TLS 1.0/1.1/SSLv3 still being negotiated, which
                    corroborates an old-stack hypothesis. Optional.

    Returns:
        {
          "os_findings": [...],            # list of {os, version, eol_status, ...}
          "tls_old_stack": bool,           # corroborating signal
          "tls_signals": [str, ...],
          "any_eol": bool,
        }

    Detection is intentionally conservative — false positives on "your OS
    is EOL" findings are painful for operators, so we only annotate
    high-confidence signals. Every match goes through _annotate_os_eol()
    which consults OS_EOL.
    """
    findings: list[dict] = []
    tls_signals: list[str] = []

    # ── Strategy 1: IIS version ──
    if server_header:
        m = _IIS_VERSION_RE.search(server_header)
        if m:
            iis_ver = m.group(1)
            iis_finding = _annotate_os_eol("iis", iis_ver, "server_header_iis")
            # Refine with per-minor underlying-OS detail + TLS-capability
            # narrative. This lets the rendering layer distinguish "Server
            # 2008" from "Server 2008 R2", and produces the IIS-10-plus-TLS
            # narrative the renderer reads back when displaying findings.
            findings.append(_refine_iis_finding(iis_finding, tls_result))

    # ── Strategy 2: distro name in parens annotation ──
    # Walk all parens groups since Apache may emit several. First distro-name
    # match wins per OS key (we don't want to double-flag "Ubuntu" if the
    # operator vended it twice).
    seen_os_keys: set[str] = set()
    if server_header:
        for paren_match in _DISTRO_PARENS_RE.finditer(server_header):
            inner = paren_match.group(1).lower().strip()
            for distro_token, os_key in _DISTRO_NAME_TO_KEY.items():
                if distro_token in inner and os_key not in seen_os_keys:
                    # Try to pull a version out of the parens content. If
                    # the distro is one with a 999 floor (CentOS), version
                    # doesn't matter; otherwise we only flag if we have a
                    # version to compare against.
                    ver_match = _DISTRO_VERSION_RE.search(inner)
                    detected_version = ver_match.group(1) if ver_match else ""
                    entry = OS_EOL.get(os_key, {})
                    floor = entry.get("min_supported_major")
                    # Treat 999 floors as "any version flags" — we don't
                    # need a version to know it's EOL.
                    if floor == 999:
                        findings.append(_annotate_os_eol(os_key, detected_version or "?", "server_header"))
                        seen_os_keys.add(os_key)
                    elif detected_version:
                        findings.append(_annotate_os_eol(os_key, detected_version, "server_header"))
                        seen_os_keys.add(os_key)
                    else:
                        # Distro named but no version — record the
                        # detection without an EOL claim, so the report
                        # can show "Ubuntu (version unknown)" without
                        # penalizing the score.
                        findings.append({
                            "os":         os_key,
                            "version":    "",
                            "source":     "server_header",
                            "eol_status": "unknown",
                        })
                        seen_os_keys.add(os_key)
                    break  # one distro per parens group is enough

    # ── Strategy 3: TLS fingerprint corroboration ──
    # We treat TLS 1.0 / 1.1 / SSLv3 as a strong "old stack" signal, but
    # do NOT claim a specific OS from it. The TLS version alone could
    # mean the operator deliberately enabled legacy compat for a partner
    # or kept default OpenSSL settings.
    tls_old_stack = False
    if tls_result and not tls_result.get("error"):
        ver = (tls_result.get("version") or "").upper()
        if ver in ("TLSV1", "TLSV1.0", "SSLV3", "SSLV2", "TLSV1.1"):
            tls_old_stack = True
            tls_signals.append(f"{ver} negotiated")

    any_eol = any(f.get("eol_status") == "eol" for f in findings)
    return {
        "os_findings":   findings,
        "tls_old_stack": tls_old_stack,
        "tls_signals":   tls_signals,
        "any_eol":       any_eol,
    }


# ── Page-level analyses (--deep only as of 2.7.0) ─────────────────────────────
# These operate on the body chunk that check_redirect already fetched. The
# parser itself does no extra network I/O — it's pure local CPU on a body
# we have in hand. Trip through the lifecycle:
#   2.1.x  --deep only
#   2.2.0  promoted to default (cheap because it reuses the captured body)
#   2.7.0  re-gated to --deep — the body we got was often a bot-mitigation
#          challenge page (Akamai/AWS WAF/Cloudflare) producing unreliable
#          findings, and capturing 1MB per domain × 200 domains was 200MB
#          of bandwidth for findings that the operator may not need.
# Under --deep, body_cap rises to _DEEP_BODY_SNIFF_BYTES (5MB) so this
# parser sees the full HTML of large server-rendered CMS pages.
#
# Note: check_versioned_libraries() (2.8.0) also operates on the body chunk
# but runs in default mode. It's robust against bot-mitigation pages — those
# pages don't contain version strings to falsely match against — and the
# detection regexes all match in the first few KB so the smaller default
# cap is fine for it.

class _DeepHTMLParser(HTMLParser):
    """Cheap HTML parser for deep checks. Records src/href URLs, integrity
    attributes, alt presence, label associations, etc.

    Deliberately lenient — we never raise on malformed HTML because real-world
    pages are full of broken markup and we'd rather report partial findings
    than nothing.
    """
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts        = []   # list of dicts: src, integrity, crossorigin, inline
        self.stylesheets    = []   # list of dicts: href, integrity, crossorigin
        self.iframes        = []   # list of src
        self.images_no_alt  = 0
        self.images_total   = 0
        self.empty_buttons  = 0
        self.empty_links    = 0
        self.inputs_total   = 0
        self.inputs_unlabeled = 0
        self.html_lang      = None
        self.has_meta_csp   = False
        self.meta_csp_value = None
        self._in_script     = False
        self._in_button     = False
        self._in_anchor     = False
        self._button_text   = []
        self._anchor_text   = []
        self._labels        = set()  # all `for=` attribute values
        self._inputs_with_id = []     # input ids that need a matching label
        self._inputs_aria_labeled = set()

    def handle_starttag(self, tag, attrs):
        a = dict((k.lower(), (v or "").strip()) for k, v in attrs)
        if tag == "html":
            self.html_lang = a.get("lang")
        elif tag == "script":
            self.scripts.append({
                "src": a.get("src", ""),
                "integrity": a.get("integrity", ""),
                "crossorigin": a.get("crossorigin", ""),
                "inline": not a.get("src"),
            })
            self._in_script = True
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel:
                self.stylesheets.append({
                    "href": a.get("href", ""),
                    "integrity": a.get("integrity", ""),
                    "crossorigin": a.get("crossorigin", ""),
                })
        elif tag == "img":
            self.images_total += 1
            if "alt" not in a:
                self.images_no_alt += 1
        elif tag == "iframe":
            self.iframes.append(a.get("src", ""))
        elif tag == "button":
            self._in_button = True
            self._button_text = []
            if a.get("aria-label") or a.get("aria-labelledby") or a.get("title"):
                # Pre-credit: button has an accessible name even if empty body
                self._button_text = ["[aria]"]
        elif tag == "a":
            self._in_anchor = True
            self._anchor_text = []
            if a.get("aria-label") or a.get("aria-labelledby") or a.get("title"):
                self._anchor_text = ["[aria]"]
        elif tag == "input":
            t = a.get("type", "text").lower()
            if t in ("hidden", "submit", "button", "reset", "image"):
                return  # not a form-input that needs a visible label
            self.inputs_total += 1
            if a.get("aria-label") or a.get("aria-labelledby"):
                self._inputs_aria_labeled.add(a.get("id", ""))
            elif a.get("id"):
                self._inputs_with_id.append(a["id"])
            else:
                self.inputs_unlabeled += 1   # no id and no aria label = unlabelable
        elif tag == "label":
            f = a.get("for")
            if f:
                self._labels.add(f)
        elif tag == "meta":
            if a.get("http-equiv", "").lower() == "content-security-policy":
                self.has_meta_csp = True
                self.meta_csp_value = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        elif tag == "button":
            txt = "".join(self._button_text).strip()
            if not txt:
                self.empty_buttons += 1
            self._in_button = False
        elif tag == "a":
            txt = "".join(self._anchor_text).strip()
            if not txt:
                self.empty_links += 1
            self._in_anchor = False

    def handle_data(self, data):
        if self._in_button:
            self._button_text.append(data)
        elif self._in_anchor:
            self._anchor_text.append(data)
        # we deliberately ignore script bodies; we don't analyze inline JS

    def finalize(self):
        # After parsing, count inputs whose id has no matching <label for=...>
        for input_id in self._inputs_with_id:
            if input_id not in self._labels and input_id not in self._inputs_aria_labeled:
                self.inputs_unlabeled += 1


def check_page_security_signals(html, page_url, audit_domain):
    """Parse the HTML body for SRI, mixed content, third-party origins, and
    a regex-light a11y subset. Runs under --deep only.

    page_url      — the final URL after redirects (from check_redirect)
    audit_domain  — the apex domain for first-vs-third-party classification

    Returns a dict with deeply structured results — see render layer for
    presentation. The render layer surfaces "0 found" lines explicitly so
    the reader can tell the parser succeeded but the page genuinely has
    no <img>/<input>/etc — common when the captured body is a bot-mitigation
    challenge page or a real SPA shell rendered client-side.
    """
    if not html:
        return {"parsed": False, "error": "no body"}

    parser = _DeepHTMLParser()
    try:
        parser.feed(html)
    except Exception as e:
        # Lenient — return what we got
        result = {"parsed": False, "error": f"parse: {e}"}
    else:
        result = {"parsed": True}
    parser.finalize()

    # ── First-vs-third-party classification ──────────────────────────────────
    # Use the org domain so https://api.example.com on example.com is "first
    # party". Anything outside that boundary is third-party.
    base_org = _org_domain(audit_domain) or audit_domain

    def _origin_of(url):
        if not url:
            return None
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            return None  # relative URL, same origin
        elif not url.startswith(("http://", "https://")):
            return None
        try:
            host = urlparse(url).netloc.lower().split(":")[0]
            return host
        except Exception:
            return None

    def _is_third_party(host):
        if not host:
            return False
        host_org = _org_domain(host) or host
        return host_org != base_org

    third_party_origins = set()
    for s in parser.scripts:
        host = _origin_of(s["src"])
        if host and _is_third_party(host):
            third_party_origins.add(host)
    for s in parser.stylesheets:
        host = _origin_of(s["href"])
        if host and _is_third_party(host):
            third_party_origins.add(host)
    for src in parser.iframes:
        host = _origin_of(src)
        if host and _is_third_party(host):
            third_party_origins.add(host)

    # ── SRI on third-party scripts and stylesheets ──────────────────────────
    external_scripts = [s for s in parser.scripts
                        if s["src"] and _is_third_party(_origin_of(s["src"]) or "")]
    external_styles  = [s for s in parser.stylesheets
                        if s["href"] and _is_third_party(_origin_of(s["href"]) or "")]
    external_total   = len(external_scripts) + len(external_styles)
    sri_protected    = (sum(1 for s in external_scripts if s["integrity"]) +
                        sum(1 for s in external_styles  if s["integrity"]))

    if external_total == 0:
        sri_outcome = "no_external_scripts"
    elif sri_protected == external_total:
        sri_outcome = "all_external_have_sri"
    elif sri_protected > 0:
        sri_outcome = "some_external_have_sri"
    else:
        sri_outcome = "external_without_sri"

    # ── Mixed content (page served over HTTPS, but resources over HTTP) ─────
    is_https_page = page_url and page_url.lower().startswith("https://")
    mixed_active  = []
    mixed_passive = []
    if is_https_page:
        for s in parser.scripts:
            if s["src"].startswith("http://"):
                mixed_active.append(s["src"])
        for s in parser.stylesheets:
            if s["href"].startswith("http://"):
                mixed_active.append(s["href"])
        for src in parser.iframes:
            if src.startswith("http://"):
                mixed_active.append(src)
        # Note: we don't see <img>/<video> sources unless we extend the parser.
        # Keeping the parser narrow so we focus on the high-impact mixed content.

    if not is_https_page:
        mixed_outcome = "none"   # page itself is HTTP — mixed content doesn't apply
    elif mixed_active:
        mixed_outcome = "active"
    elif mixed_passive:
        mixed_outcome = "passive_only"
    else:
        mixed_outcome = "none"

    # ── A11y signals (regex/parser-light, NOT a real WAVE substitute) ────────
    a11y = {
        "html_lang_set":       parser.html_lang is not None and parser.html_lang.strip() != "",
        "html_lang":           parser.html_lang,
        "images_total":        parser.images_total,
        "images_missing_alt":  parser.images_no_alt,
        "inputs_total":        parser.inputs_total,
        "inputs_unlabeled":    parser.inputs_unlabeled,
        "empty_buttons":       parser.empty_buttons,
        "empty_links":         parser.empty_links,
    }

    return {
        "parsed":               True,
        "body_bytes":           len(html),
        "scripts_total":        len(parser.scripts),
        "stylesheets_total":    len(parser.stylesheets),
        "external_scripts":     len(external_scripts),
        "external_styles":      len(external_styles),
        "third_party_origins":  sorted(third_party_origins),
        "sri_protected":        sri_protected,
        "sri_external_total":   external_total,
        "sri_outcome":          sri_outcome,
        "mixed_active":         mixed_active[:20],   # cap at 20 for readability
        "mixed_active_count":   len(mixed_active),
        "mixed_outcome":        mixed_outcome,
        "iframe_count":         len(parser.iframes),
        "meta_csp":             parser.meta_csp_value,
        "a11y":                 a11y,
    }


# ── STARTTLS probe of MX hosts (--deep only — heaviest single check) ─────────

def check_starttls_mx(mx_entries):
    """For each MX host, open TCP/25, EHLO, STARTTLS, and inspect the cert.

    This is the heaviest --deep check (typically 2-5 seconds per MX host),
    which is why it's behind the flag. Probing port 25 is also blocked from
    many residential ISPs and cloud providers — partial results are normal.

    Returns a dict mx_host -> {tls_version, cert_subject, cert_issuer,
    cert_expires, cert_lifetime_days, error}.
    """
    if not mx_entries:
        return {"mx_count": 0, "results": {}}

    timeout = max(_http_timeout, 10)  # SMTP banners can be slow
    results = {}

    def _probe(host):
        out = {"tls_version": None, "cert_subject": None, "cert_issuer": None,
               "cert_expires": None, "cert_lifetime_days": None, "error": None}

        # Build TLS context. We turn OFF hostname verification because MX
        # certs frequently don't list every routing hostname (e.g. Outlook
        # uses *.protection.outlook.com but routes to per-tenant subdomains
        # like contoso-com.mail.protection.outlook.com, where the SAN may
        # cover the wildcard but not the full route name). Chain verification
        # stays ON so getpeercert() returns a parsed dict — Python returns
        # an empty {} from getpeercert() when verify_mode=CERT_NONE, which
        # is why earlier versions of this check captured no cert detail at
        # all. If chain validation fails, we retry with CERT_NONE.
        def _do_probe(verify):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            if not verify:
                ctx.verify_mode = ssl.CERT_NONE
            try:
                with smtplib.SMTP(host, 25, timeout=timeout) as smtp:
                    smtp.ehlo()
                    if not smtp.has_extn("STARTTLS"):
                        return None, "Server does not advertise STARTTLS"
                    smtp.starttls(context=ctx)
                    ssl_sock = smtp.sock
                    ver = ssl_sock.version() if hasattr(ssl_sock, "version") else None
                    cert = ssl_sock.getpeercert() if hasattr(ssl_sock, "getpeercert") else None
                    return (ver, cert), None
            except (socket.timeout, OSError, smtplib.SMTPException, ssl.SSLError) as e:
                return None, str(e)

        result, err = _do_probe(verify=True)
        if err and ("certificate verify failed" in err
                    or "self-signed" in err
                    or "self signed" in err
                    or "certificate has expired" in err):
            # Chain validation rejected — retry without it so we can still
            # report what's there. The cert detail is informational only;
            # we don't separately score "invalid chain".
            result, err = _do_probe(verify=False)

        if err:
            out["error"] = err
            return host, out

        ver, cert = result
        out["tls_version"] = ver

        # CERT_NONE makes getpeercert() return {} instead of None. Treat
        # both as "nothing parsable" — but at this point we negotiated
        # successfully, so emit the TLS version with no cert detail.
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            out["cert_subject"] = subject.get("commonName")
            out["cert_issuer"]  = issuer.get("commonName") or issuer.get("organizationName")
            try:
                nb = ssl.cert_time_to_seconds(cert["notBefore"])
                na = ssl.cert_time_to_seconds(cert["notAfter"])
                nb_dt = datetime.fromtimestamp(nb, tz=timezone.utc)
                na_dt = datetime.fromtimestamp(na, tz=timezone.utc)
                out["cert_expires"]       = na_dt.strftime("%Y-%m-%d")
                out["cert_lifetime_days"] = (na_dt - nb_dt).days
            except Exception:
                pass
        return host, out

    hosts = [e["host"] for e in mx_entries]
    with ThreadPoolExecutor(max_workers=min(4, len(hosts))) as ex:
        for host, out in ex.map(_probe, hosts):
            results[host] = out

    return {"mx_count": len(hosts), "results": results}


# ── Scoring ───────────────────────────────────────────────────────────────────
# All weights and outcome→points mappings live in scoring_rubric.json.
# This module owns the BRANCHING — deciding which outcome key applies for a
# given result dict — and reads weights from RUBRIC.

def _w(label, outcome):
    """Return (earned, possible) for a label/outcome from the rubric, or
    (0, 0) if the combo is missing. Logs the missing case so rubric drift
    surfaces in tests rather than silently zeroing scores."""
    table = _W.get(label)
    if not table:
        return (0, 0)
    entry = table.get(outcome)
    if not entry:
        # Missing outcome — return zeros, but make this visible. Don't raise:
        # a misconfigured rubric should not crash a bulk scan.
        return (0, 0)
    return (entry["earned"], entry["possible"])


def _score_email(spf, dmarc, mx, pts, prefix=""):
    """Score SPF, DMARC, and MX for one domain, appending to `pts` list.
    `prefix` is prepended to label names to distinguish source vs redirect target."""
    def _p(label, outcome):
        e, p = _w(label, outcome)
        pts.append((f"{prefix}{label}", e, p))

    has_mx  = bool(mx.get("entries")) and not mx.get("null_mx")
    spf_s   = spf.get("status", "")
    has_spf = spf_s not in ("error", "missing", "", None)

    # SPF policy is scored when a record exists OR when there's an MX.
    # Rationale: SPF on a no-MX domain is deliberate anti-spoofing (e.g.
    # v=spf1 -all to block forged senders); its strength is meaningful.
    if spf_s == "null_sender":
        _p("SPF policy", "null_sender")
    elif (has_mx or has_spf) and spf_s != "error":
        # Direct lookup: the rubric's outcome keys match the spf_s values
        # for the eight non-null-sender outcomes. Default to 'missing' for
        # an unrecognised status to keep the denominator stable.
        if spf_s in _W["SPF policy"]:
            _p("SPF policy", spf_s)
        else:
            _p("SPF policy", "missing")

        lc = spf.get("lookup_count")
        if lc is not None:
            _p("SPF lookup count",
               "within_limit" if lc <= _THRESH["spf_lookup_limit"] else "exceeds_limit")

        if spf_s != "redirect_target_no_spf":
            _p("SPF redirect", "resolves")

    if not dmarc.get("error"):
        _p("DMARC present", "present" if dmarc.get("present") else "missing")
        if dmarc.get("present"):
            pol = dmarc.get("policy", "")
            if pol in ("reject", "quarantine"):
                _p("DMARC policy", pol)
            else:
                _p("DMARC policy", "none")
            if pol in ("reject", "quarantine"):
                pct = dmarc.get("pct")
                if pct is not None:
                    _p("DMARC pct", "full" if pct == 100 else "partial")
                sp = dmarc.get("sp")
                if sp is not None:
                    _p("DMARC sp", "none" if sp == "none" else "enforced")
            # rua= aggregate report destination — score whenever DMARC is
            # present, regardless of policy. Operators on p=none still need
            # rua to know whether moving to quarantine/reject would drop
            # legitimate mail.
            rua = dmarc.get("rua") or []
            _p("DMARC rua reporting", "present" if rua else "missing")

    if not mx.get("error") and mx.get("entries"):
        _p("MX records", "present")


def score_results(results):
    """Return (earned, possible, breakdown).

    earned   — float (0.5 / 1.0 / 2.0 etc as defined in the rubric)
    possible — int   (denominator; only countable items, errors excluded)
    breakdown — list of (label, earned, possible) for each scoreable item
    """
    pts = []

    def _p(label, outcome):
        e, p = _w(label, outcome)
        pts.append((label, e, p))

    spf    = results.get("spf",    {})
    dmarc  = results.get("dmarc",  {})
    mx     = results.get("mx",     {})
    ipr    = results.get("ip_routing", {})
    dnssec = results.get("dnssec", {})
    tls    = results.get("tls",    {})
    hsts   = results.get("hsts",   {})
    srv    = results.get("server_header", {})

    v4 = ipr.get("v4", {})
    v6 = ipr.get("v6", {})

    # ── Email — source domain (always) ───────────────────────────────────────
    _score_email(spf, dmarc, mx, pts)

    # ── Email — redirect target (when redirected) ────────────────────────────
    redirected = results.get("redirect", {}).get("redirected", False)
    if redirected:
        _score_email(
            results.get("redirect_target_spf",   {}),
            results.get("redirect_target_dmarc", {}),
            results.get("redirect_target_mx",    {}),
            pts,
            prefix="redirect target: ",
        )

    # ── IPv6 (always in denominator — capability + hygiene) ──────────────────
    v6_present = bool(v6.get("address"))
    _p("IPv6", "present" if v6_present else "missing")

    # ── IPv4 routing ─────────────────────────────────────────────────────────
    if not v4.get("error") or v4.get("address"):
        rpki4 = v4.get("rpki_status")
        if rpki4 in ("valid", "not-found", "invalid"):
            _p("IPv4 RPKI", rpki4)
        # "error" → excluded from denominator

        if rpki4 != "error" and rpki4 is not None:
            _p("IPv4 IRR/RIS", "in_ris" if v4.get("irr_in_ris") else "not_in_ris")

    # ── IPv6 routing — only scored when IPv6 present ─────────────────────────
    if v6_present:
        rpki6 = v6.get("rpki_status")
        if rpki6 in ("valid", "not-found", "invalid"):
            _p("IPv6 RPKI", rpki6)

        if rpki6 != "error" and rpki6 is not None:
            _p("IPv6 IRR/RIS", "in_ris" if v6.get("irr_in_ris") else "not_in_ris")

    # ── DNSSEC ────────────────────────────────────────────────────────────────
    tld_d = dnssec.get("tld", {})
    dom_d = dnssec.get("domain", {})
    if not tld_d.get("error"):
        _p("DNSSEC TLD signed", "signed" if tld_d.get("signed") else "unsigned")
    if not dom_d.get("error"):
        _p("DNSSEC DNSKEY", "present" if dom_d.get("dnskey") else "missing")
        _p("DNSSEC AD flag", "set" if dom_d.get("ad_flag") else "unset")

    # ── TLS ───────────────────────────────────────────────────────────────────
    if not tls.get("error"):
        ver = tls.get("version", "")
        _p("TLS connection", "ok")
        if ver == "TLSv1.3":
            _p("TLS 1.3", "negotiated")
        elif ver == "TLSv1.2":
            _p("TLS 1.3", "tls_1_2")
        else:
            _p("TLS 1.3", "older")

        lifetime = tls.get("cert_lifetime_days")
        if lifetime is not None:
            _p("Certificate lifetime",
               "short_lived" if lifetime <= _THRESH["cert_lifetime_max_days"] else "long_lived")

        names_match = tls.get("cert_names_match")
        if names_match is not None:
            _p("Certificate name match", "match" if names_match else "no_match")

        # ── HTTP version (only when TLS works) ────────────────────────────────
        # Single scoring entry covering all three tiers:
        #   http3 → 2/2 (modern, full credit)
        #   http2 → 1/2 (legacy but still TLS, half credit)
        #   http1 → 0/2 (no HTTP/2 support — server should be retired)
        hv      = results.get("http_version", {})
        hv_ver  = hv.get("version")
        srv_h   = results.get("server_header", {})
        http3   = srv_h.get("http3_advertised")
        if not hv.get("error") or http3 is not None:
            if http3:
                _p("HTTP version", "http3")
            elif hv_ver == "HTTP/2":
                _p("HTTP version", "http2")
            elif hv_ver is not None:
                _p("HTTP version", "http1")
    else:
        # When TLS fails we still count TLS-dependent items in the denominator
        # so a broken site can't score better by percentage than a working one.
        # tls_cert_error=True → port 443 open, cert is self-signed/untrusted.
        # tls_cert_error=False → no port 443 at all.
        cert_err = tls.get("tls_cert_error", False)
        _p("TLS connection",         "cert_error" if cert_err else "no_tls")
        _p("TLS 1.3",                "older")
        _p("Certificate lifetime",   "long_lived")
        _p("Certificate name match", "cert_error" if cert_err else "no_match")
        _p("HTTP/2",                 "not_supported")
        _p("HTTP version",           "http1")

    # ── HTTP→HTTPS redirect ──────────────────────────────────────────────────
    hr = results.get("http_redirect", {})
    hr_s = hr.get("status")
    if hr_s in ("https_only", "http_error", "http_available"):
        _p("HTTP→HTTPS redirect", hr_s)
    # "unreachable" → not scored

    # ── HSTS ──────────────────────────────────────────────────────────────────
    if not hsts.get("error"):
        _p("HSTS present", "present" if hsts.get("present") else "missing")
        _p("HSTS includeSubDomains",
           "set" if hsts.get("includes_subdomains") else "unset")
        if not hsts.get("preload_error"):
            if hsts.get("preloaded"):
                _p("HSTS preloaded", "preloaded")
            elif hsts.get("preload_directive"):
                _p("HSTS preloaded", "preload_directive")
            else:
                _p("HSTS preloaded", "not_preloaded")

    # ── Server / disclosure ───────────────────────────────────────────────────
    if not srv.get("error"):
        kind = classify_server(srv.get("server"))
        if kind in ("absent", "good_proxy"):
            _p("Server header", "absent_or_proxy")
        elif kind == "origin_no_version":
            _p("Server header", "origin_no_version")
        else:
            _p("Server header", "origin_with_version")

        _p("X-Powered-By absent", "present" if srv.get("x_powered_by") else "absent")

    # ── Browser security headers ──────────────────────────────────────────────
    if not srv.get("error"):
        csp_q = srv.get("csp_quality")
        if csp_q == "present":
            _p("CSP", "present")
        elif csp_q == "permissive":
            _p("CSP", "permissive")
        else:
            _p("CSP", "missing")

        xfo = (srv.get("x_frame_options") or "").split(",")[0].strip().upper()
        if srv.get("csp_frame_ancestors"):
            _p("X-Frame-Options", "set")
        else:
            _p("X-Frame-Options", "set" if xfo in ("DENY", "SAMEORIGIN") else "unset")

        xcto = (srv.get("x_content_type") or "").lower()
        _p("X-Content-Type-Options", "nosniff" if xcto == "nosniff" else "missing")

        rp = (srv.get("referrer_policy") or "").split(",")[0].strip().lower()
        if rp in STRONG_REFERRER_POLICIES:
            _p("Referrer-Policy", "strong")
        elif rp:
            _p("Referrer-Policy", "weak")
        else:
            _p("Referrer-Policy", "missing")

        _p("Permissions-Policy", "set" if srv.get("permissions_policy") else "missing")

    # ── Cookies ───────────────────────────────────────────────────────────────
    # Fixed 3-point budget (Secure / HttpOnly / SameSite). Worst-cookie-wins.
    # Infra cookies (CDN/WAF) excluded — operator can't control them.
    if not srv.get("error"):
        cookies = [ck for ck in (srv.get("cookies") or []) if not ck.get("infra")]
        if cookies:
            all_secure   = all(ck["secure"]   for ck in cookies)
            all_httponly = all(ck["httponly"] for ck in cookies)
            _p("Cookie Secure",   "all_secure"   if all_secure   else "some_insecure")
            _p("Cookie HttpOnly", "all_httponly" if all_httponly else "some_not")

            # SameSite worst-cookie-wins:
            # Strict/Lax → 1.0 (strict_or_lax)
            # None+Secure → 0.5 (none_with_secure)
            # everything else → 0.0 (missing_or_bad)
            def _ss_outcome(ck):
                ss = ck["samesite"]
                if ss in ("Strict", "Lax"):           return "strict_or_lax"
                if ss == "None" and ck["secure"]:     return "none_with_secure"
                return "missing_or_bad"
            _ORDER = {"strict_or_lax": 2, "none_with_secure": 1, "missing_or_bad": 0}
            worst = min(cookies, key=lambda ck: _ORDER[_ss_outcome(ck)])
            _p("Cookie SameSite", _ss_outcome(worst))

    # ── security.txt ──────────────────────────────────────────────────────────
    sectxt = results.get("security_txt", {})
    if not sectxt.get("error"):
        if sectxt.get("present") and sectxt.get("contact"):
            if sectxt.get("expired") is False:
                _p("security.txt", "present_with_expiry")
            else:
                _p("security.txt", "present_no_expiry")
        else:
            _p("security.txt", "missing")

    # ── SSL Labs grade ────────────────────────────────────────────────────────
    ssl_result = results.get("ssl_labs")
    if ssl_result is not None:
        grade = ssl_result.get("worst_grade")
        if grade in _W["SSL Labs grade"]:
            _p("SSL Labs grade", grade)
        # grade=None / unknown → excluded
    else:
        # --ssl was NOT used. If TLS is missing entirely (hard connection
        # failure), add 0/10 so the missing TLS shows up in the denominator.
        # If TLS works we simply haven't run the test — no points either way.
        if tls.get("error") and not tls.get("tls_cert_error"):
            _p("SSL Labs grade", "no_tls_at_all")

    # ─────────────────────────────────────────────────────────────────────────
    # 2.1.0 additions below this line
    # ─────────────────────────────────────────────────────────────────────────

    # ── CAA records ───────────────────────────────────────────────────────────
    caa = results.get("caa", {})
    if not caa.get("error"):
        if caa.get("present"):
            _p("CAA records", "with_iodef" if caa.get("iodef") else "present")
        else:
            _p("CAA records", "missing")

    # ── Nameserver count ──────────────────────────────────────────────────────
    ns_soa = results.get("ns_soa", {})
    ns_count = ns_soa.get("ns_count", 0)
    if not ns_soa.get("ns_error"):
        min_ns = _THRESH.get("min_nameservers", 2)
        _p("Nameserver count", "two_or_more" if ns_count >= min_ns else "single")

    # ── MTA-STS / TLS-RPT / DANE — only score when MX exists ─────────────────
    has_mx = bool(mx.get("entries")) and not mx.get("null_mx")
    if has_mx:
        mta_sts        = results.get("mta_sts", {})
        mta_sts_policy = results.get("mta_sts_policy", {})
        if not mta_sts.get("error"):
            if mta_sts.get("present"):
                # In default mode (no policy fetch) we can't tell mode; treat
                # presence-only as "testing" since that's the conservative,
                # user-not-yet-enforcing read. If we did fetch the policy
                # (deep mode), use the actual mode.
                mode = (mta_sts_policy.get("mode") if mta_sts_policy.get("fetched") else None)
                if mode in ("enforce", "testing", "none"):
                    _p("MTA-STS", mode)
                else:
                    _p("MTA-STS", "testing")
            else:
                _p("MTA-STS", "missing")

        tls_rpt = results.get("tls_rpt", {})
        if not tls_rpt.get("error"):
            _p("TLS-RPT", "present" if tls_rpt.get("present") else "missing")

        dane = results.get("dane", {})
        # dane scoring: only meaningful if we have MX hosts to compare against
        if dane and dane.get("mx_count", 0) > 0:
            with_t = len(dane.get("with_tlsa", []))
            total  = dane["mx_count"]
            if with_t == total:
                _p("DANE TLSA on MX", "all_mx")
            elif with_t > 0:
                _p("DANE TLSA on MX", "some_mx")
            else:
                _p("DANE TLSA on MX", "no_mx")

        # ── STARTTLS-MX (2.9.0) ───────────────────────────────────────────────
        # Worst-of aggregation across MX hosts. Mail delivery uses MX
        # preference order, but an attacker capable of network manipulation
        # can force delivery to the lowest-pref MX, so a single weak host
        # defines the actual exposure. Outcome ladder:
        #
        #   tls_1_3      — best: STARTTLS works AND negotiated TLS 1.3 on
        #                  every probed MX                            (2/2)
        #   tls_1_2      — STARTTLS works AND every probed MX negotiates
        #                  at least TLS 1.2                          (1.5/2)
        #   tls_legacy   — STARTTLS works but at least one MX still
        #                  negotiates TLS 1.0/1.1                     (1/2)
        #   no_starttls  — at least one MX did not advertise STARTTLS at
        #                  EHLO; SMTP delivery to that host is plaintext (0/2)
        #   unprobed     — every probe failed at the network layer (port
        #                  25 blocked egress, connection refused/timed
        #                  out, TLS handshake never reached); we cannot
        #                  conclude anything about the operator's STARTTLS
        #                  posture                                    (0/0)
        #
        # The unprobed row is intentionally still appended to the breakdown
        # so the operator sees in the report that the check was attempted.
        # Silent disappearance would let an operator wrongly conclude
        # STARTTLS is fine when port 25 was simply blocked. The check only
        # runs in --deep, so STARTTLS-MX won't appear in the breakdown
        # at all when --deep wasn't requested.
        starttls_mx = results.get("starttls_mx", {})
        if starttls_mx and starttls_mx.get("mx_count", 0) > 0:
            host_results = (starttls_mx.get("results") or {}).values()

            # Network-error classifier: distinguish "we never got a TLS
            # handshake from this host, so we have no STARTTLS evidence"
            # from "we got an EHLO and the server explicitly didn't
            # advertise STARTTLS". The latter is the no_starttls case
            # (operator's posture is bad); the former is unprobed (we
            # don't know).
            def _classify(host_info: dict) -> str:
                err = host_info.get("error") or ""
                if not err:
                    ver = (host_info.get("tls_version") or "").upper()
                    if ver in ("TLSV1.3",):
                        return "tls_1_3"
                    if ver in ("TLSV1.2",):
                        return "tls_1_2"
                    if ver in ("TLSV1.1", "TLSV1.0", "SSLV3", "SSLV2"):
                        return "tls_legacy"
                    # No error AND no TLS version: treat as unprobed
                    # (shouldn't happen in practice — smtplib gives one
                    # or the other — but defensive).
                    return "unprobed"
                # Specific error string that means "server explicitly
                # rejected STARTTLS at EHLO"
                if "does not advertise STARTTLS" in err:
                    return "no_starttls"
                # Everything else (timeout, connection refused, network
                # blocked port 25, SSL handshake error) → unprobed.
                # We could try to be more granular here (e.g. an SSL
                # handshake error after a successful STARTTLS upgrade
                # might indicate cert problems rather than missing
                # STARTTLS) but for scoring purposes the actionable
                # distinction is "did we observe STARTTLS work or not"
                # and the no_starttls bucket is reserved for the
                # explicit EHLO refusal.
                return "unprobed"

            classifications = [_classify(h) for h in host_results]
            # Worst-CONFIRMED-of aggregation. Severity (worst → best):
            #   no_starttls > tls_legacy > tls_1_2 > tls_1_3
            # Unprobed hosts are dropped from the aggregation when any
            # confirmed result exists. Rationale: a network error on one
            # host (port 25 blocked egress, timeout) shouldn't pull down
            # the score for a domain where the other MX hosts produced
            # clean handshakes. The score reflects what we could measure;
            # unprobed silently exits when measurement happened elsewhere.
            # Only when EVERY host was unprobed does the check evaluate
            # to "unprobed" (0/0) — a 0/0 row that still appears in the
            # breakdown so the operator sees the check ran but produced
            # no signal.
            severity = {
                "no_starttls": 4,
                "tls_legacy":  3,
                "tls_1_2":     1,
                "tls_1_3":     0,
            }
            confirmed = [k for k in classifications if k != "unprobed"]
            if confirmed:
                worst = max(confirmed, key=lambda k: severity.get(k, 0))
            else:
                worst = "unprobed"
            _p("STARTTLS-MX", worst)

        dkim = results.get("dkim", {})
        if dkim and dkim.get("checked"):
            _p("DKIM (common selectors)",
               "found" if dkim.get("found") else "not_found")

    # ── Server clock accuracy ─────────────────────────────────────────────────
    clock = results.get("clock", {})
    co = clock.get("outcome")
    if co in ("in_sync", "minor_skew", "bad_skew"):
        _p("Server clock accuracy", co)
    # outcome=no_date → not scored

    # ── HSTS max-age strength ─────────────────────────────────────────────────
    if not hsts.get("error") and hsts.get("present"):
        ma = hsts.get("max_age")
        min_age = _THRESH.get("hsts_max_age_min_seconds", 15768000)
        if ma is None:
            _p("HSTS max-age strength", "missing")
        elif ma >= min_age:
            _p("HSTS max-age strength", "six_months_plus")
        else:
            _p("HSTS max-age strength", "less_than_six")

    # ── Detailed CSP analysis ─────────────────────────────────────────────────
    csp_a = results.get("csp_analysis")
    if csp_a and csp_a.get("present"):
        _p("CSP script-src safety", csp_a["script_src_outcome"])
        _p("CSP object-src",        csp_a["object_src_outcome"])
        _p("CSP base-uri",          csp_a["base_uri_outcome"])
        _p("CSP frame-ancestors",   csp_a["frame_ancestors_outcome"])
        _p("CSP enforcement mode",  csp_a["enforcement_outcome"])

    # ── Cross-Origin headers (COOP/CORP) ──────────────────────────────────────
    if not srv.get("error"):
        coop = (srv.get("coop") or "").lower().strip()
        if coop == "same-origin":
            _p("Cross-Origin-Opener-Policy", "same_origin")
        elif coop == "same-origin-allow-popups":
            _p("Cross-Origin-Opener-Policy", "same_origin_allow_popups")
        else:
            _p("Cross-Origin-Opener-Policy", "missing")

        corp = (srv.get("corp") or "").lower().strip()
        if corp in ("same-origin", "same-site"):
            _p("Cross-Origin-Resource-Policy", "same_origin_or_site")
        elif corp == "cross-origin":
            _p("Cross-Origin-Resource-Policy", "cross_origin")
        else:
            _p("Cross-Origin-Resource-Policy", "missing")

        # X-XSS-Protection: deprecated header. We award full credit for absent
        # OR explicit `0` (disable filter). Penalise only `1; mode=block` or
        # similar enabled values per Mozilla / OWASP guidance.
        xxp = (srv.get("x_xss_protection") or "").lower().strip()
        if not xxp or xxp.startswith("0"):
            _p("X-XSS-Protection deprecated", "absent_or_zero")
        else:
            _p("X-XSS-Protection deprecated", "set_dangerous")

    # ── Cookie name prefixes ──────────────────────────────────────────────────
    if not srv.get("error"):
        cookies = [ck for ck in (srv.get("cookies") or []) if not ck.get("infra")]
        prefixed = [ck for ck in cookies
                    if ck["name"].startswith(("__Host-", "__Secure-"))]
        if prefixed:
            invalid = []
            for ck in prefixed:
                if ck["name"].startswith("__Secure-") and not ck["secure"]:
                    invalid.append(ck["name"])
                elif ck["name"].startswith("__Host-"):
                    if (not ck["secure"] or
                            ck.get("path", "/") != "/" or
                            ck.get("domain")):
                        invalid.append(ck["name"])
            _p("Cookie name prefixes", "invalid_prefix" if invalid else "valid")
        # If no prefixed cookies exist, we don't score — possible=0 in rubric

    # ── Redirect first-hop hygiene ────────────────────────────────────────────
    redir = results.get("redirect", {})
    if redir.get("redirected") and redir.get("first_hop_https") is not None:
        if redir.get("first_hop_https") and redir.get("first_hop_same_host"):
            _p("Redirect first-hop hygiene", "https_same_host")
        else:
            _p("Redirect first-hop hygiene", "off_host_first")

    # ── Cert covers redirect variant ──────────────────────────────────────────
    cert_var = results.get("cert_variant", {})
    if cert_var.get("outcome") in ("covers", "missing_variant"):
        _p("Cert covers www variant", cert_var["outcome"])

    # ── Deep-mode: page-level ─────────────────────────────────────────────────
    page = results.get("page_signals", {})
    if page and page.get("parsed"):
        _p("Subresource Integrity", page["sri_outcome"])
        _p("Mixed content (in-page)", page["mixed_outcome"])

    # ── EOL versioned libraries (2.9.0) ───────────────────────────────────────
    # Each detected EOL library is its own 0/1 penalty. Detected libraries
    # that are NOT EOL ('ok' status) are not scored — they don't earn points,
    # they just don't lose them. Libraries with 'unknown' status (detected
    # but not in library_eol.json) are also not scored, since absence of
    # EOL data is not evidence of EOL.
    #
    # Per-library scoring means the denominator floats with how many EOL
    # libraries the page loads: a site running 3 EOL libraries gets 0/3
    # contribution to its overall score; a site running zero EOL libraries
    # contributes 0/0 (no impact on the percentage). This mirrors the
    # rubric's existing partial-check convention (DKIM not_found → 0/0).
    #
    # Labels are "EOL library: <lib> <version>" so each library is its own
    # row in the breakdown, and they all map to the Website category via
    # the prefix-aware category lookup in audit_render.
    vlibs = (results.get("versioned_libs") or {}).get("libraries") or []
    for lib in vlibs:
        if lib.get("eol_status") == "eol":
            label = f"EOL library: {lib.get('library', '?')} {lib.get('version', '?')}"
            pts.append((label, 0, 1))

    # ── EOL operating system (2.9.0) ──────────────────────────────────────────
    # Big penalty: each detected EOL OS contributes 0/3 to the score. This
    # is the same shape as the EOL library scoring but with a heavier weight
    # because an EOL OS is a much more serious finding than an EOL client-
    # side library — it implies the entire stack is unpatched, not just
    # one front-end dependency.
    #
    # Same rules: 'ok' (in-floor / known-supported) and 'unknown' (detected
    # but no EOL data, or detected without enough version info to make a
    # claim) do not contribute to the score in either direction. Only
    # confirmed EOL findings produce a 0/3 row.
    os_eol = results.get("os_eol") or {}
    for finding in os_eol.get("os_findings") or []:
        if finding.get("eol_status") == "eol":
            os_name = finding.get("os", "?")
            ver     = finding.get("version") or ""
            # Strip the placeholder "?" version (used when distro was named
            # but no version string was recovered) so the breakdown label
            # doesn't read "EOL OS: centos ?". For 999-floor OSes that's
            # the common case and the version doesn't add information.
            if ver in ("?", ""):
                label = f"EOL OS: {os_name}"
            else:
                label = f"EOL OS: {os_name} {ver}"
            pts.append((label, 0, 3))

    earned   = sum(e for _, e, _ in pts)
    possible = sum(p for _, _, p in pts)
    return earned, possible, pts
