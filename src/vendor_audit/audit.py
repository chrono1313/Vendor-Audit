"""vendor_audit.audit — single-domain orchestrator.

Imported by both the CLI and the web layer. Has no opinion on output format,
no terminal colors, and no print() calls. Status messages are emitted via
stdlib `logging`; the caller installs whatever handler it likes (or none at
all). The CLI installs a thread-locked colored handler that mimics the
historic _tprint() output. The web layer leaves logging unconfigured, so
messages are silently dropped by Python's lastResort handler.

Two public entry points:

  run_audit(domain, *, ssl_active=False) -> dict
      Runs all checks for one domain. Returns a dict with keys:
      domain, audit_domain, results, timestamp. Raises on configuration
      errors and on hard failures inside checks (individual check failures
      are absorbed into results[<check>] = {"error": str(exc)} as before).

  safe_run_audit(domain, *, deep=False, http_timeout=15, dns_server=None,
                 ssl_active=False) -> dict
      Wraps run_audit() with exception handling and ALWAYS returns a
      uniform {ok, error, ...} envelope. This is the function the web
      layer should call. It also handles per-call configuration setters
      (set_deep, set_http_timeout, set_dns_server) so a fresh process-pool
      worker picks up the right settings on the first invocation.

VERSIONING
----------
This file participates in the cross-module version sanity check enforced
by cli.py at startup. __version__ here must equal __version__ in cli.py,
audit_checks.py, audit_render.py, and audit_txt_report.py, and must equal
rubric_version in scoring_rubric.json. See the docstring in cli.py for the
versioning policy.
"""
from __future__ import annotations

import logging
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import idna

from . import audit_checks
from .audit_checks import (
    analyze_csp,
    check_caa,
    check_cert_covers_variant,
    check_clock_skew,
    check_dane,
    check_dkim_common,
    check_dmarc,
    check_dnssec,
    check_hsts,
    check_http_redirect,
    check_http_version,
    check_ip_routing,
    check_mta_sts,
    check_mta_sts_policy,
    check_mx,
    check_ns_soa,
    check_os_eol,
    check_page_security_signals,
    check_redirect,
    check_security_txt,
    check_server_header,
    check_spf,
    check_starttls_mx,
    check_tls,
    check_tls_rpt,
    check_versioned_libraries,
)

__version__ = "1.0"

log = logging.getLogger(__name__)


# ── Domain normalisation ─────────────────────────────────────────────────────

def normalize_domain(raw: str) -> str:
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
    the failure on their own terms; this function never raises so callers in
    bulk mode can keep going on a per-domain basis.
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


# ── Single-domain audit ──────────────────────────────────────────────────────

def run_audit(domain: str, *, ssl_active: bool = False) -> dict:
    """Run all checks for a single domain. Thread-safe.

    Returns a dict:
        {
            "domain":       str,   # the normalized input domain
            "audit_domain": str,   # post-redirect (may equal `domain`)
            "results":      dict,  # full results map (unchanged shape)
            "timestamp":    str,   # ISO 8601 UTC, scan start time
        }

    Status messages are emitted via the module logger ("vendor_audit.audit"):
      - INFO  at scan start ("Running checks for example.com…")
      - INFO  on completion ("done example.com (1.4s)")
      - WARNING when the input domain redirects to a different domain

    Configure DNS server, HTTP timeout, and deep mode before calling, via
    audit_checks.set_dns_server() / set_http_timeout() / set_deep(). When
    running under a process pool, those setters must be invoked inside the
    worker process (module state does not cross process boundaries).
    safe_run_audit() handles this.

    `ssl_active` is informational only — used to label the start-of-scan log
    line so the operator can see at a glance which flags are in effect. The
    actual SSL Labs assessment is run separately by the CLI; it has its own
    rate-limit / sequencing rules that don't fit the per-domain check
    pipeline.
    """
    domain = normalize_domain(domain)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deep = audit_checks.is_deep()

    # Build the same flag list the CLI banner builds (--deep, --ssl), so the
    # per-domain progress line agrees with the top-of-output banner.
    active_flags = []
    if deep:
        active_flags.append("--deep")
    if ssl_active:
        active_flags.append("--ssl")
    flag_suffix = f"  [{' '.join(active_flags)}]" if active_flags else ""

    log.info("Running checks for %s...%s", domain, flag_suffix)

    # ── Per-check timing — used by render() for the "Scan info" footer and
    # by CSV output. A check-name -> seconds dict so we can spot which
    # network call is dominating wall time.
    check_timings: dict = {}
    scan_t0 = time.monotonic()

    # ── Redirect check first — determines which domain web checks run
    # against. In --deep mode we ask for a 5MB body cap (vs 256KB default)
    # so the page parser, which only runs under --deep, can see large
    # server-rendered CMS pages. In default mode the body chunk is consumed
    # by server/CMS fingerprinting (the _BODY_SIGNALS regex table) and
    # versioned library detection (check_versioned_libraries), both of
    # which fit comfortably in 256KB.
    body_cap = (
        audit_checks._DEEP_BODY_SNIFF_BYTES if deep else audit_checks._BODY_SNIFF_BYTES
    )
    t = time.monotonic()
    redirect = check_redirect(domain, body_cap=body_cap)
    check_timings["redirect"] = round(time.monotonic() - t, 3)
    audit_domain = redirect["final"] if redirect["redirected"] else domain

    if redirect["redirected"]:
        log.warning(
            "%s redirects to %s — email audited for both domains, "
            "web/TLS checks against redirect target",
            domain, audit_domain,
        )

    # Pop the cached response before storing redirect (live Response is not
    # serialisable through pickle / process-pool boundaries).
    cached_resp = redirect.pop("_response", None)

    results: dict = {
        "redirect":      redirect,
        "_audit_domain": audit_domain,
        "_deep_mode":    deep,
    }

    # ── Check menu ───────────────────────────────────────────────────────
    # Email checks run against the source domain (always). Web/TLS checks
    # run against audit_domain (after redirect resolution). Email
    # infrastructure belongs to the source — that's the envelope domain
    # regardless of where the website itself resolves.
    email_checks = [
        ("spf",     lambda d: check_spf(d)),
        ("dmarc",   lambda d: check_dmarc(d)),
        ("mx",      lambda d: check_mx(d)),
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
        ("caa",           lambda d: check_caa(d)),
        ("ns_soa",        lambda d: check_ns_soa(d)),
    ]

    redirect_email_checks: list = []
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

    # ── Run all checks in parallel ───────────────────────────────────────
    # Each check is wrapped in a timer so we can attribute slow wall-time
    # to specific network calls (RIPEstat, hstspreload.org, security.txt
    # candidates, etc.). The wrapper returns (result, elapsed_s, exc).
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

    # ── Post-server-header derived analyses (synchronous, near-instant) ──
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

    # ── Mark unresolvable domains ────────────────────────────────────────
    ipr = results.get("ip_routing", {})
    no_v4 = not ipr.get("v4", {}).get("address")
    no_v6 = not ipr.get("v6", {}).get("address")
    if no_v4 and no_v6:
        results["_unresolvable"] = True

    # ── Post-pool extras (run in parallel) ───────────────────────────────
    # Default-mode jobs (always run):
    #   - versioned_libs: regex-scan the captured body for client-side
    #     library versions (jQuery, Bootstrap, Font Awesome, etc.) and
    #     cross-reference against library_eol.json. Pure local CPU on
    #     existing data.
    #   - MTA-STS policy fetch: one HTTPS GET to mta-sts.<domain>. Most
    #     domains have no such host, so this fast-fails on DNS resolution.
    #
    # --deep-only jobs (require explicit opt-in):
    #   - page-level analysis: pure local CPU on the body chunk, but the
    #     body chunk itself is expensive to capture (up to 5MB under
    #     --deep) and a meaningful share of pages are bot-mitigation
    #     challenges that produce unreliable findings — opt-in via --deep
    #     so default scans don't pay the bandwidth or get noisy results
    #     from challenge pages.
    #   - DANE TLSA on each MX host: TLSA queries to MX hosts that don't
    #     have DANE deployed routinely take 5+ seconds each because many
    #     recursive resolvers handle TLSA poorly when the zone isn't
    #     DNSSEC-signed.
    #   - STARTTLS-MX probe: opens port 25 to each MX host, EHLO/STARTTLS,
    #     inspects each cert. 10s timeout per host. Port-25 egress is
    #     blocked from many cloud providers and residential ISPs, in
    #     which case the wall time hits the timeout cap.
    #
    # All jobs in the batch run concurrently, so the wall-time addition
    # is bounded by the slowest single one.
    rt_mx_entries: list = []
    if redirect["redirected"]:
        rt_mx_entries = (results.get("redirect_target_mx") or {}).get("entries") or []

    if not results.get("_unresolvable"):
        page_url   = redirect.get("final") or audit_domain
        body_bytes = getattr(cached_resp, "_body_chunk", b"") if cached_resp is not None else b""
        body_html  = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

        post_pool_jobs: list = []

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
            # Use a zero-arg timed wrapper since these callables don't take
            # a target argument (we baked it into the lambda above).
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

    # ── OS EOL detection (default mode) ──────────────────────────────────
    # Pure CPU on data already collected (Server header + TLS result), so
    # we run it synchronously after the post-pool join. No network I/O, no
    # thread pool needed. Robust against missing inputs: check_os_eol takes
    # an empty header and a None tls_result.
    server_hdr = (results.get("server_header") or {}).get("server") or ""
    tls_result = results.get("tls") or {}
    os_t0 = time.monotonic()
    try:
        results["os_eol"] = check_os_eol(server_hdr, tls_result)
    except Exception as exc:
        results["os_eol"] = {
            "os_findings":   [],
            "any_eol":       False,
            "tls_old_stack": False,
            "tls_signals":   [],
            "error":         str(exc),
        }
    check_timings["os_eol"] = round(time.monotonic() - os_t0, 3)

    # ── Record total scan wall time + per-check timings for the report ───
    scan_elapsed = round(time.monotonic() - scan_t0, 3)
    results["_scan"] = {
        "elapsed_s":     scan_elapsed,
        "check_timings": check_timings,
        "deep":          deep,
        "version":       __version__,
    }

    log.info("done %s (%.1fs)", domain, scan_elapsed)

    return {
        "domain":       domain,
        "audit_domain": audit_domain,
        "results":      results,
        "timestamp":    timestamp,
    }


# ── Safe wrapper: classifies failures into the unified error envelope ────────

class _ValidationError(Exception):
    """Internal marker — input failed normalization or basic shape checks."""


class _ResolutionError(Exception):
    """Internal marker — domain doesn't resolve to anything."""


def safe_run_audit(
    domain: str,
    *,
    deep: bool = False,
    http_timeout: int = 15,
    dns_server: Optional[str] = None,
    ssl_active: bool = False,
) -> dict:
    """Run an audit and ALWAYS return the {ok, error, ...} envelope.

    Every exception is caught and classified. This is the function the web
    layer (and CI / automation users of the library) should call; the CLI's
    main loop calls run_audit() directly because it has its own
    print-the-traceback behaviour for hard failures.

    Configuration setters are invoked here, INSIDE the wrapper. This is the
    correct place for them when running under a process pool: the setters
    mutate module state in audit_checks, and module state lives per-process,
    not per-call. Putting the setters in safe_run_audit means a fresh
    worker process picks up the right config on the first call without any
    further dance.

    Return shape (always):

        {
            "ok":             bool,
            "domain":         str | None,   # normalized; None on validation failure
            "original_input": str,          # the raw input from the caller
            "timestamp":      str,          # ISO 8601 UTC, scan start
            "duration_ms":    int,
            "results":        dict | None,  # populated when ok=True
            "audit_domain":   str | None,   # populated when ok=True
            "error":          dict | None,  # populated when ok=False
        }

    When ok=False, error is:

        {"kind": str, "message": str, "detail": str | None}

    where kind is one of:
      "validation"  — input failed normalization or basic shape checks
                      (no audit was attempted)
      "resolution"  — the domain does not resolve to any IP address
      "timeout"     — reserved for a future wall-clock guard (currently
                      unreachable; safe_run_audit itself does not impose a
                      timeout)
      "internal"    — anything else; `detail` carries the traceback for logs
    """
    started_mono = time.monotonic()
    started_iso  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    original_input = domain

    try:
        # 1. Normalize and basic shape validation
        try:
            normalized = normalize_domain(domain)
        except Exception as exc:
            raise _ValidationError(f"Could not parse input: {exc}") from exc
        if not normalized or "." not in normalized:
            raise _ValidationError("Input does not look like a domain name.")

        # 2. Configure module state (per-worker)
        audit_checks.set_deep(deep)
        audit_checks.set_http_timeout(http_timeout)
        if dns_server is not None:
            audit_checks.set_dns_server(dns_server)

        # 3. Run the audit
        outcome = run_audit(normalized, ssl_active=ssl_active)

        # 4. Detect "domain doesn't resolve" — distinct from internal
        # errors because it's a normal user-facing outcome, not a bug.
        if outcome["results"].get("_unresolvable"):
            raise _ResolutionError(
                f"{normalized} did not resolve to any IPv4 or IPv6 address."
            )

        return {
            "ok":             True,
            "domain":         normalized,
            "original_input": original_input,
            "timestamp":      outcome["timestamp"],
            "duration_ms":    int((time.monotonic() - started_mono) * 1000),
            "results":        outcome["results"],
            "audit_domain":   outcome["audit_domain"],
            "error":          None,
        }

    except _ValidationError as exc:
        return _err_envelope(
            original_input, started_iso, started_mono,
            kind="validation", message=str(exc), detail=None,
        )
    except _ResolutionError as exc:
        return _err_envelope(
            original_input, started_iso, started_mono,
            kind="resolution", message=str(exc), detail=None,
        )
    except TimeoutError as exc:
        # Currently unreachable — run_audit doesn't raise TimeoutError today.
        # Reserved for the wall-clock guard the web layer will add (a
        # subprocess-level deadline that interrupts a runaway audit).
        return _err_envelope(
            original_input, started_iso, started_mono,
            kind="timeout",
            message="The audit took longer than the allowed time and was stopped.",
            detail=str(exc),
        )
    except Exception:
        return _err_envelope(
            original_input, started_iso, started_mono,
            kind="internal",
            message="An unexpected error occurred while running the audit.",
            detail=traceback.format_exc(),
        )


def _err_envelope(original, started_iso, started_mono, *, kind, message, detail):
    return {
        "ok":             False,
        "domain":         None,
        "original_input": original,
        "timestamp":      started_iso,
        "duration_ms":    int((time.monotonic() - started_mono) * 1000),
        "results":        None,
        "audit_domain":   None,
        "error":          {"kind": kind, "message": message, "detail": detail},
    }
