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
audit_render.py — Terminal rendering and CSV output for vendor_audit.

Imported by vendor_audit.py; reads results produced by audit_checks.py
and turns them into either a human-readable terminal report (`render`)
or a flat dict for csv.DictWriter (`results_to_csv_row`).

This module never makes network calls and never mutates results; it only
reads them. All score weights, label maps, and grade colors come from
audit_checks.RUBRIC.

The four .py files (vendor_audit, audit_checks, audit_render, audit_txt_report)
and rubric.json share a single version number that is enforced
at startup. See vendor_audit.py for the full versioning policy.
"""
from __future__ import annotations

__version__ = "3.5.15"

import sys
from datetime import datetime, timezone

from .audit_checks import (
    RUBRIC, classify_server, assess_results, severity_counts,
)

# ── ANSI colors (disabled when stdout is not a TTY) ───────────────────────────

if sys.stdout.isatty():
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    GREY   = "\033[90m"
else:
    RESET = BOLD = RED = YELLOW = GREEN = CYAN = GREY = ""



def c(color, text):
    return f"{color}{text}{RESET}"


# ── Category order ────────────────────────────────────────────────────────────

_CATEGORY_ORDER = ["Email", "DNS", "Routing", "TLS", "HTTP", "Website"]


# ── OS inference (used by the CSV) ───────────────────────

def _infer_os(server_val, tls_ver):
    """Return a short OS identification/inference string based on IIS+TLS, or ''."""
    if not server_val or "microsoft-iis" not in server_val.lower():
        return ""
    iis_ver = server_val.lower().replace("microsoft-iis/", "").strip()
    if iis_ver.startswith("8.0"):
        return "Windows Server 2012 — EOL Oct 2023"
    if iis_ver.startswith("8.5"):
        return "Windows Server 2012 R2 — EOL Oct 2023"
    if iis_ver.startswith("10."):
        if tls_ver == "TLSv1.3":
            return "Windows Server 2022 or 2025 (inferred)"
        if tls_ver in ("TLSv1.2", "TLSv1.1", "TLSv1.0"):
            return "Windows Server 2016 or 2019 (inferred) — 2016 EOL Jan 2027"
        return "Windows Server 2016/2019/2022/2025 (inconclusive)"
    return ""


# ── Main render entry point ───────────────────────────────────────────────────

def render(original_domain, audit_domain, r, dns_server):
    redirect = r.get("redirect", {})
    redirected = redirect.get("redirected", False)
    www_fallback = redirect.get("www_fallback", False)

    print(f"\n{c(BOLD+CYAN, '━'*56)}")
    print(f"{c(BOLD+CYAN, f'  Vendor Audit — {original_domain}')}")
    if www_fallback:
        # The user typed the apex but the apex has no A/AAAA, so web/TLS
        # checks were routed at www. This is NOT a real HTTP redirect —
        # there's nothing to redirect FROM at the apex. Communicate that
        # accurately so the report doesn't read as "apex redirects to www".
        fb_host = redirect.get("www_fallback_host", audit_domain)
        print(c(YELLOW, f"  Apex {original_domain} has no DNS records \u2014 auditing {fb_host} for web/TLS"))
        print(f"{c(YELLOW, f'  Email still audited against {original_domain}')}")
    elif redirected:
        print(f"{c(YELLOW, f'  Website redirects to: {audit_domain}')}")
        print(f"{c(YELLOW, f'  Email audited for both: {original_domain} and {audit_domain}')}")
        print(f"{c(YELLOW, f'  Web/TLS checks against: {audit_domain}')}")
    if dns_server:
        print(f"{c(GREY, f'  DNS server: {dns_server}')}")
    print(f"{c(BOLD+CYAN, '━'*56)}\n")

    # ── Unresolvable domain — bail out early ──────────────────────────────────
    if r.get("_unresolvable"):
        print(f"  {c(RED, '✘')} Domain did not resolve to any IP address — check the domain name is correct")
        print(f"\n{c(BOLD+CYAN, '━'*56)}\n")
        return

    # ── Detail sections ──────────────────────────────────────────────────────
    # The same sections as the text report: each check is worded once, in
    # audit_txt_report, and printed here in colour without the What / Why /
    # Fix paragraphs. See "Line kinds" in audit_txt_report.
    from .audit_txt_report import _ReportData as _RD, render_detail_sections
    _print_detail_sections(render_detail_sections(
        _RD(original_domain, audit_domain, r, "", (r.get("_scan") or {}).get("version", "?"))))

    # ── Summary ───────────────────────────────────────────────────────────────
    summary_domain = audit_domain if redirected else original_domain
    print(f"\n{c(BOLD+CYAN, '━'*56)}")
    print(c(BOLD, f"  Summary of {summary_domain}"))
    print(f"{c(BOLD+CYAN, '━'*56)}\n")
    if redirected:
        print(f"  {c(GREY, '→')} {original_domain} redirects to {audit_domain} — email audited for both domains; web/TLS reflects {audit_domain}\n")

    # ── Summary: findings by severity ────────────────────────────────────────
    # Built from the same finding rows the text and HTML reports use, so all
    # three agree. There are no points: each finding has a severity, and the
    # totals line counts them.
    from .audit_txt_report import (_ReportData, ISSUE_SEVERITIES,
                                   SEVERITY_TITLES, severity_summary)
    data = _ReportData(original_domain, audit_domain, r, "",
                       (r.get("_scan") or {}).get("version", "?"))
    sev_color = {"critical": RED, "high": RED, "medium": YELLOW, "low": YELLOW}

    passes = [x for x in data.finding_rows if x["severity"] == "pass"]
    if passes:
        print(c(BOLD, "  Passing checks"))
        for cat in _CATEGORY_ORDER:
            for x in passes:
                if x["category"] == cat:
                    print(f"  {c(GREEN, '✔')} {c(GREY, cat + ':')}  {x['display']}")

    infos = [x for x in data.finding_rows if x["severity"] == "info"]
    if infos:
        print(c(BOLD, "\n  Informational"))
        for x in infos:
            print(f"  {c(GREY, '·')} {c(GREY, x['category'] + ':')}  {c(GREY, x['display'])}")

    ranked = data.issues_ranked()
    if ranked:
        for sev in ISSUE_SEVERITIES:
            rows = [x for x in ranked if x["severity"] == sev]
            if not rows:
                continue
            sym = '✘' if sev in ("critical", "high") else '⚠'
            print(c(BOLD, f"\n  {SEVERITY_TITLES[sev].capitalize()} ({len(rows)})"))
            for x in rows:
                print(f"  {c(sev_color[sev], sym)} {c(GREY, x['category'] + ':')}  {x['display']}")
    elif not redirected:
        print(f"\n  {c(GREEN, '✔')} No issues found")

    head_color = sev_color.get(data.worst_severity, GREEN)
    print(f"\n  {c(BOLD, 'Findings:')}  "
          f"{c(head_color+BOLD, severity_summary(data.counts))}  "
          f"{c(GREY, '(' + data.verdict + ')')}")
    print()
    for row in data.category_rows:
        cc = sev_color.get(row["worst"], GREEN)
        print(f"    {row['category']:<8}  {c(cc, severity_summary(row['counts']))}  "
              f"{c(GREY, str(row['passed']) + ' passed')}")

    scan = r.get("_scan") or {}
    if scan:
        opts = []
        if scan.get("deep"):
            opts.append("--deep")
        if r.get("ssl_labs"):
            opts.append("--ssl")
        opts_str = ", ".join(opts) if opts else "default"
        elapsed = scan.get("elapsed_s", 0)
        scan_ver = scan.get("version", "?")

        # Identify the dominant check, if any. We threshold at 1.0s and at
        # 30% of the total scan time to avoid noisy callouts on fast scans.
        timings = scan.get("check_timings") or {}
        per_check = {k: v for k, v in timings.items() if not k.startswith("_")}
        slow = ""
        if per_check and elapsed >= 2.0:
            slowest_name, slowest_t = max(per_check.items(), key=lambda kv: kv[1])
            if slowest_t >= 1.0 and slowest_t >= elapsed * 0.30:
                slow = c(GREY, f"  (slowest: {slowest_name} {slowest_t:.1f}s)")

        print(f"\n  {c(GREY, 'Scan')}  v{scan_ver}  ·  options: {opts_str}  ·  "
              f"completed in {c(BOLD, f'{elapsed:.1f}s')}{slow}")

    print(f"\n{c(BOLD+CYAN, '━'*56)}\n")



# ── Detail sections (shared with the text report) ────────────────────────────

# Colour of a status line's word (see "Status-line words" in
# audit_txt_report). NOTE stays uncoloured: observed, not rated.
_STATUS_COLOR = {
    "pass": GREEN, "info": GREY,
    "medium": YELLOW, "low": YELLOW,
    "high": RED, "critical": RED,
}
_TERM_WIDTH = 56


def _print_detail_sections(tagged):
    """Print the text report's detail sections for a terminal.

    Reads the line-kind tags (audit_txt_report, "Line kinds"): headings are
    coloured, a status line's word takes its severity's colour, the
    What / Why / Fix paragraphs are left out, and runs of blank lines
    become one. Everything else prints as the plain form has it.
    """
    from .audit_txt_report import split_tag
    blank = True                       # no blank line before the first heading
    for line in tagged.split("\n"):
        kind, text = split_tag(line)
        if kind in ("E", "R"):
            continue
        if not text.strip():
            if not blank:
                print()
                blank = True
            continue
        if kind == "H":
            title = text.strip()
            if not blank:
                print()
            print(c(BOLD + CYAN, f"── {title} " + "─" * max(3, _TERM_WIDTH - len(title) - 4)))
        elif kind == "h":
            print(c(BOLD, text.strip()))
        elif kind.startswith("S:"):
            colour = _STATUS_COLOR.get(kind[2:], "")
            lead = len(text) - len(text.lstrip())
            word, _, rest = text[lead:].partition(" ")
            print(f"{text[:lead]}{c(colour, word)} {rest}" if colour and rest else
                  f"{text[:lead]}{c(colour, word)}" if colour else text)
        else:
            print(text)
        blank = False

# ── CSV serialization ─────────────────────────────────────────────────────────
# Schema design notes:
#   - Columns are grouped by category (email_/dns_/routing_/tls_/http_/web_/
#     score_/meta_) matching the six top-level categories used in the report.
#   - Booleans are uniformly 'yes' / 'no' / '' (empty for "data unavailable").
#   - Verdict-style summary columns are consolidated under each section's
#     `_status` field rather than per-section verdict_* columns.
#   - DKIM has no 'status' field because the not-found result is scored 0/0
#     (partial check); dkim_found_selectors carries the same information.
#   - Per-category subscore columns are exposed (score_email_pct, ...) so the
#     spreadsheet can pivot/filter by category without recomputing.
#
# The schema is versioned independently (_SCHEMA_VERSION) and bumped on any
# breaking change to the column list or value semantics. The schema-version
# guard in vendor_audit.py refuses to append rows from a different schema to
# an existing CSV; users see a clear error asking them to start a fresh file.

_SCHEMA_VERSION = "2.0"


def _yn(v):
    """Canonicalise Python truthy/falsy values to 'yes' / 'no' / '' for CSV.

    None becomes '' (data unavailable, distinct from a definite no). True/
    'true'/'True'/'yes' all collapse to 'yes'. False/'false'/'False'/'no'
    collapse to 'no'. Numeric 0/1 collapse appropriately. Anything else
    becomes ''.
    """
    if v is None or v == "":
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (int, float)):
        return "yes" if v else "no"
    s = str(v).strip().lower()
    if s in ("true", "yes", "1"):
        return "yes"
    if s in ("false", "no", "0"):
        return "no"
    return ""


def _str_or_blank(v):
    """str() that turns None into '' rather than 'None', for CSV cleanliness."""
    return "" if v is None else str(v)


def findings_sort_key(counts):
    """One number that orders domains from best to worst when sorted
    ascending, without pretending severities trade off against each other.

    It is the four counts written side by side, three digits each:
    critical, high, medium, low. 2 critical, 4 high, 11 medium, 10 low
    → 2004011010. Because each severity has its own block of digits, no
    number of lower findings can outweigh a single higher one: 50 mediums
    (50000) still sorts ahead of 1 high (1000000). Counts cap at 999.

    It is a sort key, not a score — the gaps between values mean nothing.
    """
    key = 0
    for sev in ("critical", "high", "medium", "low"):
        key = key * 1000 + min(int(counts.get(sev, 0) or 0), 999)
    return key


def _score_csv(results):
    """Findings columns for the CSV row.

    Sorting columns first, for lists of hundreds of domains:
      findings_sort_key      ascending = best first (see findings_sort_key)
      findings_issues        critical + high + medium + low
      findings_critical_high critical + high
      findings_passed        checks met
      findings_passed_pct    passed / (passed + issues); informational rows
                             are left out of both
    then the four severity counts, info, the verdict, and for each category
    the number of issues and its worst severity."""
    from .audit_txt_report import ISSUE_SEVERITIES, verdict_for
    findings = assess_results(results)
    counts = severity_counts(findings)
    issues = sum(counts[s] for s in ISSUE_SEVERITIES)
    assessed = issues + counts["pass"]
    out = {
        "findings_sort_key":      _str_or_blank(findings_sort_key(counts)),
        "findings_issues":        _str_or_blank(issues),
        "findings_critical_high": _str_or_blank(counts["critical"] + counts["high"]),
        "findings_passed_pct":    _str_or_blank(round(100 * counts["pass"] / assessed)) if assessed else "",
        "findings_critical": _str_or_blank(counts["critical"]),
        "findings_high":     _str_or_blank(counts["high"]),
        "findings_medium":   _str_or_blank(counts["medium"]),
        "findings_low":      _str_or_blank(counts["low"]),
        "findings_info":     _str_or_blank(counts["info"]),
        "findings_passed":   _str_or_blank(counts["pass"]),
        "findings_verdict":  verdict_for(counts),
    }
    for cat in _CATEGORY_ORDER:
        in_cat = [f["severity"] for f in findings if f["category"] == cat]
        issues = [s for s in in_cat if s in ISSUE_SEVERITIES]
        worst = next((s for s in ISSUE_SEVERITIES if s in issues), "")
        prefix = f"findings_{cat.lower()}"
        out[f"{prefix}_issues"] = _str_or_blank(len(issues)) if in_cat else ""
        out[f"{prefix}_worst"]  = worst
    return out


def results_to_csv_row(original_domain, audit_domain, results, timestamp):
    """Flatten an audit result dict into an ordered dict for CSV writing.

    See module-level CSV section comment for schema overview.
    """
    spf    = results.get("spf",    {})
    dmarc  = results.get("dmarc",  {})
    mx     = results.get("mx",     {})
    ipr    = results.get("ip_routing", {})
    dnssec = results.get("dnssec", {})
    tls    = results.get("tls",    {})
    hsts   = results.get("hsts",   {})
    srv    = results.get("server_header", {})
    redir  = results.get("redirect", {})
    sectxt = results.get("security_txt", {})
    sslr   = results.get("ssl_labs", {}) or {}
    httpr  = results.get("http_redirect", {})
    httpv  = results.get("http_version", {})

    rt_spf   = results.get("redirect_target_spf",   {})
    rt_dmarc = results.get("redirect_target_dmarc", {})
    rt_mx    = results.get("redirect_target_mx",    {})

    caa     = results.get("caa", {}) or {}
    ns_soa  = results.get("ns_soa", {}) or {}
    ns_health = results.get("ns_health", {}) or {}
    mta_sts = results.get("mta_sts", {}) or {}
    mta_sts_policy = results.get("mta_sts_policy", {}) or {}
    tls_rpt = results.get("tls_rpt", {}) or {}
    dane    = results.get("dane", {}) or {}
    dkim    = results.get("dkim", {}) or {}
    rt_mta  = results.get("redirect_target_mta_sts", {}) or {}
    rt_mta_policy = results.get("redirect_target_mta_sts_policy", {}) or {}
    rt_tls_rpt  = results.get("redirect_target_tls_rpt", {}) or {}
    rt_dane = results.get("redirect_target_dane", {}) or {}
    csp_a   = results.get("csp_analysis", {}) or {}
    clock   = results.get("clock", {}) or {}
    cert_v  = results.get("cert_variant", {}) or {}
    page    = results.get("page_signals", {}) or {}
    starttls = results.get("starttls_mx", {}) or {}
    error_page = results.get("error_page", {}) or {}
    cors      = results.get("cors", {}) or {}
    wau     = results.get("www_apex_unified", {}) or {}

    # ── Email rollup statuses ─────────────────────────────────────────────────
    if mx.get("error"):
        mx_status = "error"
    elif mx.get("null_mx"):
        mx_status = "null_mx"
    elif not mx.get("entries"):
        mx_status = "missing"
    else:
        mx_status = "present"

    if dmarc.get("error"):
        dmarc_status = "error"
    elif dmarc.get("present"):
        dmarc_status = dmarc.get("policy") or "present"
    else:
        dmarc_status = "missing"

    # ── DNS rollup ────────────────────────────────────────────────────────────
    dnssec_tld    = dnssec.get("tld",    {})
    dnssec_domain = dnssec.get("domain", {})
    if dnssec_tld.get("error") or dnssec_domain.get("error"):
        dnssec_status = "error"
    elif dnssec_domain.get("dnskey") and dnssec_domain.get("ad_flag"):
        dnssec_status = "validated"
    elif dnssec_domain.get("dnskey"):
        dnssec_status = "dnskey_no_chain"
    else:
        dnssec_status = "unconfigured"

    # ── Routing rollup ────────────────────────────────────────────────────────
    v4 = ipr.get("v4", {})
    v6 = ipr.get("v6", {})
    rpki_v4 = v4.get("rpki_status") or ("error" if v4.get("error") else "")

    v6_err = v6.get("error") or ""
    if v6.get("rpki_status"):
        rpki_v6 = v6["rpki_status"]
    elif "no AAAA" in v6_err:
        rpki_v6 = "no_aaaa"
    elif v6_err:
        rpki_v6 = "error"
    else:
        rpki_v6 = ""

    def _rpki_severity(s):
        return {"invalid": 3, "error": 2, "not-found": 1, "valid": 0}.get(s, -1)
    rpki_worst = (rpki_v4 if _rpki_severity(rpki_v4) >= _rpki_severity(rpki_v6)
                  else rpki_v6) or ""

    if v6.get("address"):
        ipv6_status = "present"
    elif "no AAAA" in v6_err:
        ipv6_status = "missing"
    elif v6_err:
        ipv6_status = "error"
    else:
        ipv6_status = "missing"

    v6_addrs = v6.get("all_addresses") or ([v6["address"]] if v6.get("address") else [])

    # ── TLS rollup ────────────────────────────────────────────────────────────
    tls_ver = tls.get("version", "")
    if tls.get("error"):
        tls_status = "cert_error" if tls.get("tls_cert_error") else "no_tls"
    elif tls_ver == "TLSv1.3":
        tls_status = "tls13"
    elif tls_ver == "TLSv1.2":
        tls_status = "tls12"
    else:
        tls_status = "older"

    if hsts.get("error"):
        hsts_status = "error"
    elif hsts.get("preloaded"):
        hsts_status = "preloaded"
    elif hsts.get("present"):
        hsts_status = "present"
    else:
        hsts_status = "missing"

    # ── HTTP redirect rollup (combines first-hop hygiene into one column) ─────
    if redir.get("redirected"):
        if redir.get("first_hop_https") and redir.get("first_hop_same_host"):
            first_hop_status = "https_same_host"
        elif redir.get("first_hop_https"):
            first_hop_status = "https_off_host"
        else:
            first_hop_status = "http"
    else:
        first_hop_status = ""

    # ── Server / Web rollup ───────────────────────────────────────────────────
    server_val  = srv.get("server") or ""
    server_kind = classify_server(server_val) if server_val else "absent"

    # ── SSL Labs ──────────────────────────────────────────────────────────────
    ssl_assessed_utc = ""
    if sslr.get("test_time_ms"):
        try:
            ssl_assessed_utc = datetime.fromtimestamp(
                sslr["test_time_ms"] / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # ── Cookies ───────────────────────────────────────────────────────────────
    cookies = (srv.get("cookies") or []) if not srv.get("error") else []
    cookie_detail = "; ".join(
        f"{ck['name']}[{'S' if ck['secure'] else '-'}"
        f"{'H' if ck['httponly'] else '-'}"
        f"{'s' if ck['samesite'] else '-'}]"
        + ("(infra)" if ck["infra"] else "")
        for ck in cookies)
    valid_pref = sum(1 for ck in cookies
                     if ck["name"].startswith(("__Host-", "__Secure-"))
                     and "invalid_secure_prefix" not in ck["issues"]
                     and "invalid_host_prefix" not in ck["issues"])
    invalid_pref = sum(1 for ck in cookies
                       if "invalid_secure_prefix" in ck["issues"]
                       or "invalid_host_prefix" in ck["issues"])

    # ── MX STARTTLS results ──────────────────────────────────────────────────
    starttls_results = starttls.get("results", {})
    st_tls13 = sum(1 for v in starttls_results.values() if v.get("tls_version") == "TLSv1.3")
    st_tls12 = sum(1 for v in starttls_results.values() if v.get("tls_version") == "TLSv1.2")
    st_err   = sum(1 for v in starttls_results.values() if v.get("error"))

    # MTA-STS mode is known once the policy file is fetched, so this field
    # is populated whenever the policy file actually loaded.
    mta_mode = mta_sts_policy.get("mode") if mta_sts_policy.get("fetched") else ""
    rt_mta_mode = rt_mta_policy.get("mode") if rt_mta_policy.get("fetched") else ""

    a11y = page.get("a11y", {}) if page.get("parsed") else {}

    # ── Scan options ────────────────────────────────────────────────────────
    # Speed/timing fields are intentionally not in the CSV — they are noisy
    # in spreadsheets, vary with network conditions rather than vendor
    # posture, and aren't the point of the audit. The console output still
    # shows them ("completed in 3.9s", optional slowest-check callout), and
    # --json output still includes the full scan.check_timings map for
    # anyone debugging scanner performance.
    scan = results.get("_scan") or {}

    # The full row, ordered to match CSV_FIELDS below.
    row = {
        # ── Meta / identity ───────────────────────────────────────────────────
        "meta_timestamp":              timestamp,
        "meta_rubric_version":         RUBRIC.get("rubric_version", ""),
        "meta_schema_version":         _SCHEMA_VERSION,
        "meta_scan_version":           scan.get("version", ""),
        "meta_deep_mode":              _yn(results.get("_deep_mode")),
        "meta_domain_input":           original_domain,
        "meta_domain_audited":         audit_domain,
        "meta_redirected":             _yn(redir.get("redirected", False)),

        # ── Email — SPF (source domain) ───────────────────────────────────────
        "email_spf_status":            spf.get("status") or "error",
        "email_spf_lookup_count":      _str_or_blank(spf.get("lookup_count")),
        "email_spf_redirect_target":   spf.get("redirect_target") or "",
        "email_spf_record":            spf.get("record") or "",

        # ── Email — DMARC (source domain) ─────────────────────────────────────
        "email_dmarc_status":          dmarc_status,
        "email_dmarc_policy":          dmarc.get("policy") or "",
        "email_dmarc_pct":             _str_or_blank(dmarc.get("pct")),
        "email_dmarc_subdomain_policy":dmarc.get("sp") or "",
        "email_dmarc_rua_count":       _str_or_blank(len(dmarc.get("rua") or [])),
        "email_dmarc_rua_destinations":"; ".join(dmarc.get("rua") or []),
        "email_dmarc_inherited_from":  dmarc.get("inherited_from") or "",
        "email_dmarc_record":          dmarc.get("record") or "",

        # ── Email — MX (source domain) ────────────────────────────────────────
        "email_mx_status":             mx_status,
        "email_mx_is_null_mx":         _yn(mx.get("null_mx")),
        "email_mx_hosts":              "; ".join(e["host"] for e in mx.get("entries", []))
                                       if not mx.get("error") else "",
        "email_mx_targets_ip":         "; ".join(mx.get("mx_targets_ip") or []),
        "email_mx_targets_cname":      "; ".join(mx.get("mx_targets_cname") or []),

        # ── Email — Mail transport hardening (source domain) ──────────────────
        "email_mta_sts_present":       _yn(mta_sts.get("present")),
        "email_mta_sts_mode":          mta_mode or "",
        "email_mta_sts_id":            mta_sts.get("id") or "",
        "email_tls_rpt_present":       _yn(tls_rpt.get("present")),
        "email_tls_rpt_rua":           tls_rpt.get("rua") or "",
        "email_dane_mx_total":         _str_or_blank(dane.get("mx_count")),
        "email_dane_mx_with_tlsa":     _str_or_blank(len(dane.get("with_tlsa", []))) if dane else "",
        "email_dkim_selectors_checked":"; ".join(dkim.get("checked", [])),
        "email_dkim_selectors_found":  "; ".join(dkim.get("found", [])),
        "email_dkim_worst_strength":   dkim.get("worst_strength") or "",

        # ── Email — Redirect target equivalents (only populated on redirect) ──
        "email_redirect_target_spf_status":   rt_spf.get("status") or "",
        "email_redirect_target_spf_record":   rt_spf.get("record") or "",
        "email_redirect_target_dmarc_policy": rt_dmarc.get("policy") or "",
        "email_redirect_target_dmarc_record": rt_dmarc.get("record") or "",
        "email_redirect_target_dmarc_rua_count": (
            _str_or_blank(len(rt_dmarc.get("rua") or [])) if rt_dmarc else ""),
        "email_redirect_target_mx_hosts": "; ".join(e["host"] for e in rt_mx.get("entries", []))
                                          if not rt_mx.get("error") else "",
        "email_redirect_target_mx_is_null_mx": _yn(rt_mx.get("null_mx")) if rt_mx else "",
        "email_redirect_target_mta_sts_present": _yn(rt_mta.get("present")) if rt_mta else "",
        "email_redirect_target_mta_sts_mode": rt_mta_mode or "",
        "email_redirect_target_tls_rpt_present": _yn(rt_tls_rpt.get("present")) if rt_tls_rpt else "",
        "email_redirect_target_dane_mx_with_tlsa":
            _str_or_blank(len(rt_dane.get("with_tlsa", []))) if rt_dane else "",

        # ── Email — STARTTLS-MX probe ───────────────────────────────────────
        "email_starttls_mx_count":     _str_or_blank(starttls.get("mx_count")),
        "email_starttls_mx_tls13":     _str_or_blank(st_tls13) if starttls else "",
        "email_starttls_mx_tls12":     _str_or_blank(st_tls12) if starttls else "",
        "email_starttls_mx_errors":    _str_or_blank(st_err) if starttls else "",

        # ── DNS — DNSSEC + CAA + nameservers ──────────────────────────────────
        "dns_dnssec_status":           dnssec_status,
        "dns_dnssec_tld_signed":       _yn(dnssec_tld.get("signed")),
        "dns_dnssec_dnskey_present":   _yn(dnssec_domain.get("dnskey")),
        "dns_dnssec_chain_validated":  _yn(dnssec_domain.get("ad_flag")),
        "dns_caa_present":             _yn(caa.get("present")),
        "dns_caa_authorised_cas":      "; ".join(caa.get("issue", [])),
        "dns_caa_iodef_contacts":      "; ".join(caa.get("iodef", [])),
        "dns_caa_inherited_from":      caa.get("inherited_from") or "",
        "dns_nameserver_count":        _str_or_blank(ns_soa.get("ns_count")),
        "dns_nameservers":             "; ".join(ns_soa.get("nameservers") or []),
        "dns_soa_serial":              _str_or_blank((ns_soa.get("soa") or {}).get("serial")),
        "dns_soa_primary":             (ns_soa.get("soa") or {}).get("primary", ""),
        "dns_lame_ns":                 "; ".join(ns_health.get("lame_ns") or []),
        "dns_open_resolver_ns":        "; ".join(ns_health.get("open_resolver_ns") or []),
        "dns_ns_health_probed":        _str_or_blank(ns_health.get("probed")),

        # ── Routing — IPv4 / IPv6 / RPKI / IRR ────────────────────────────────
        "routing_ipv4_address":        v4.get("address") or "",
        "routing_ipv4_asn":            _str_or_blank(v4.get("asn")),
        "routing_ipv4_asn_name":       v4.get("asn_name") or "",
        "routing_ipv4_prefix":         v4.get("prefix") or "",
        "routing_ipv4_rpki_status":    rpki_v4,
        "routing_ipv4_in_irr":         _yn(v4.get("irr_in_ris")),
        "routing_ipv6_status":         ipv6_status,
        "routing_ipv6_addresses":      "; ".join(v6_addrs),
        "routing_ipv6_asn":            _str_or_blank(v6.get("asn")),
        "routing_ipv6_asn_name":       v6.get("asn_name") or "",
        "routing_ipv6_prefix":         v6.get("prefix") or "",
        "routing_ipv6_rpki_status":    rpki_v6,
        "routing_ipv6_in_irr":         _yn(v6.get("irr_in_ris")),
        "routing_rpki_worst":          rpki_worst,

        # ── TLS — handshake + certificate + HSTS + SSL Labs ───────────────────
        "tls_status":                  tls_status,
        "tls_version":                 tls_ver,
        "tls_cert_issuer":             tls.get("cert_issuer") or "",
        "tls_cert_issued":             tls.get("cert_issued") or "",
        "tls_cert_expires":            tls.get("cert_expires") or "",
        "tls_cert_lifetime_days":      _str_or_blank(tls.get("cert_lifetime_days")),
        "tls_cert_name_match":         _yn(tls.get("cert_names_match")),
        "tls_cert_san_names":          "; ".join(tls.get("cert_san_names", [])),
        "tls_cert_covers_variant":     cert_v.get("outcome", ""),
        "tls_chain_status":            tls.get("chain_status") or "",
        "tls_chain_sent_count":        _str_or_blank(tls.get("chain_sent_count")),
        "tls_chain_verified_count":    _str_or_blank(tls.get("chain_verified_count")),
        "tls_hsts_status":             hsts_status,
        "tls_hsts_max_age_seconds":    _str_or_blank(hsts.get("max_age")),
        "tls_hsts_includes_subdomains":_yn(hsts.get("includes_subdomains")),
        "tls_hsts_preload_directive":  _yn(hsts.get("preload_directive")),
        "tls_hsts_preloaded":          _yn(hsts.get("preloaded")),
        "tls_hsts_preload_status":     hsts.get("preload_status") or "",
        "tls_ssl_labs_grade":          sslr.get("worst_grade") or "",
        "tls_ssl_labs_assessed_utc":   ssl_assessed_utc,

        # ── HTTP — version + redirect ─────────────────────────────────────────
        "http_version":                httpv.get("version") or "",
        "http_h3_advertised":          _yn(srv.get("http3_advertised")),
        "http_alt_svc":                srv.get("alt_svc") or "",
        "http_redirect_status":        httpr.get("status") or "",
        "http_redirect_detail":        httpr.get("detail") or "",
        "http_first_hop_status":       first_hop_status,
        "http_first_hop_url":          redir.get("first_hop_url") or "",
        "http_response_elapsed_ms":    _str_or_blank(redir.get("elapsed_ms")),
        "http_www_apex_outcome":       wau.get("outcome") or "",
        "http_www_apex_missing_side":  wau.get("missing_side") or "",
        "http_www_fallback":           _yn(redir.get("www_fallback") or False),

        # ── Website — server / headers / cookies / clock / page signals ───────
        "web_server_header_kind":      server_kind if not srv.get("error") else "unreachable",
        "web_server_header":           "unreachable" if srv.get("error") else server_val,
        "web_x_powered_by":            "unreachable" if srv.get("error") else (srv.get("x_powered_by") or ""),
        "web_inferred_os":             "" if srv.get("error") else _infer_os(server_val, tls_ver),
        "web_tech_stack":              "unreachable" if srv.get("error") else "; ".join(dict.fromkeys(srv.get("stack", []))),

        "web_csp_quality":             ("unreachable" if srv.get("error") else
                                        srv.get("csp_quality") or "missing"),
        "web_csp_enforcement":         "report_only" if srv.get("csp_report_only") else "enforced" if srv.get("csp") else "",
        "web_csp_script_src_outcome":  csp_a.get("script_src_outcome", ""),
        "web_csp_object_src_outcome":  csp_a.get("object_src_outcome", ""),
        "web_csp_base_uri_outcome":    csp_a.get("base_uri_outcome", ""),
        "web_csp_frame_ancestors_outcome": csp_a.get("frame_ancestors_outcome", ""),
        "web_csp_findings_count":      _str_or_blank(len(csp_a.get("findings", []))),

        "web_x_frame_options":         "unreachable" if srv.get("error") else (srv.get("x_frame_options") or "missing"),
        "web_x_content_type_options":  "unreachable" if srv.get("error") else (srv.get("x_content_type") or "missing"),
        "web_referrer_policy":         "unreachable" if srv.get("error") else (srv.get("referrer_policy") or "missing"),
        "web_permissions_policy_set":  "" if srv.get("error") else _yn(bool(srv.get("permissions_policy"))),
        "web_coop":                    srv.get("coop") or "",
        "web_coep":                    srv.get("coep") or "",
        "web_corp":                    srv.get("corp") or "",
        "web_origin_agent_cluster":    srv.get("origin_agent_cluster") or "",
        "web_x_xss_protection":        srv.get("x_xss_protection") or "",
        "web_cache_control":           srv.get("cache_control") or "",
        "web_expires_header":          srv.get("expires") or "",

        "web_cookie_count":            "" if srv.get("error") else _str_or_blank(len(cookies)),
        "web_cookies_missing_secure":  "" if srv.get("error") else _str_or_blank(sum(1 for ck in cookies if not ck["secure"])),
        "web_cookies_missing_httponly":"" if srv.get("error") else _str_or_blank(sum(1 for ck in cookies if not ck["httponly"])),
        "web_cookies_missing_samesite":"" if srv.get("error") else _str_or_blank(sum(1 for ck in cookies if ck["samesite"] is None)),
        "web_cookies_with_valid_prefix":   _str_or_blank(valid_pref),
        "web_cookies_with_invalid_prefix": _str_or_blank(invalid_pref),
        "web_cookie_detail":           "" if srv.get("error") else cookie_detail,

        "web_security_txt_present":    _yn(sectxt.get("present")),
        "web_security_txt_contacts":   "; ".join(sectxt.get("contact", [])),
        "web_security_txt_policy":     sectxt.get("policy") or "",
        "web_security_txt_expires":    sectxt.get("expires") or "",
        "web_security_txt_expired":    _yn(sectxt.get("expired")),

        # Default error page disclosure (3.0.0)
        "web_error_page_outcome":      error_page.get("outcome") or "",
        "web_error_page_detected":     error_page.get("detected") or "",
        "web_error_page_version":      error_page.get("version") or "",
        "web_error_page_status":       _str_or_blank(error_page.get("status")),

        # CORS configuration (3.0.0)
        "web_cors_outcome":            cors.get("outcome") or "",

        "web_clock_skew_seconds":      _str_or_blank(clock.get("skew_seconds")),
        "web_clock_outcome":           clock.get("outcome", ""),

        # Page-level signals (SRI, mixed content, third-party, a11y)
        "web_page_parsed":             _yn(page.get("parsed")),
        "web_page_third_party_origins":"; ".join(page.get("third_party_origins") or []),
        "web_page_third_party_count":  _str_or_blank(len(page.get("third_party_origins", []))),
        "web_page_external_resources": _str_or_blank(page.get("sri_external_total")),
        "web_page_sri_protected":      _str_or_blank(page.get("sri_protected")),
        "web_page_sri_outcome":        page.get("sri_outcome", ""),
        "web_page_mixed_active_count": _str_or_blank(page.get("mixed_active_count")),
        "web_page_mixed_outcome":      page.get("mixed_outcome", ""),
        "web_page_iframe_count":       _str_or_blank(page.get("iframe_count")),
        "web_page_meta_csp":           _yn(bool(page.get("meta_csp"))),
        "web_page_a11y_html_lang":     a11y.get("html_lang") or "",
        "web_page_a11y_images_total":  _str_or_blank(a11y.get("images_total")),
        "web_page_a11y_images_missing_alt": _str_or_blank(a11y.get("images_missing_alt")),
        "web_page_a11y_inputs_total":  _str_or_blank(a11y.get("inputs_total")),
        "web_page_a11y_inputs_unlabeled": _str_or_blank(a11y.get("inputs_unlabeled")),
        "web_page_a11y_empty_buttons": _str_or_blank(a11y.get("empty_buttons")),
        "web_page_a11y_empty_links":   _str_or_blank(a11y.get("empty_links")),

        # ── Versioned libraries (2.8.0) ───────────────────────────────────────
        # Build "name version" tokens, semicolon-separated for in-cell read.
        # The 'detected' column lists every library found; 'eol' lists only
        # those flagged EOL by library_eol.json. Both come from the same
        # results['versioned_libs']['libraries'] list.
        **_versioned_libs_csv(results),

        # 2.9.0: same shape for OS detection — every detected OS in one
        # column, just the EOL ones in another, and a flag for whether
        # legacy TLS was negotiated as a corroborating signal.
        **_os_eol_csv(results),

        # ── Score ─────────────────────────────────────────────────────────────
        **_score_csv(results),
    }
    return row


def _versioned_libs_csv(results):
    """Return the three tech_libs_* CSV cells as a dict.

    Empty result-dict in default-mode-with-no-detection / unresolvable /
    bot-blocked cases — same shape, just empty strings (and 0 for the count).
    """
    vl = (results.get("versioned_libs") or {}).get("libraries") or []
    detected_tokens = [f"{lib['library']} {lib['version']}" for lib in vl]
    eol_tokens      = [
        f"{lib['library']} {lib['version']}"
        for lib in vl if lib.get("eol_status") == "eol"
    ]
    return {
        "tech_libs_detected":  ";".join(detected_tokens),
        "tech_libs_eol":       ";".join(eol_tokens),
        "tech_libs_eol_count": _str_or_blank(len(eol_tokens)),
    }


def _os_eol_csv(results):
    """Return the os_eol_* CSV cells as a dict (2.9.0).

    Mirrors _versioned_libs_csv shape: a semicolon-separated list of
    detected OSes, a semicolon-separated list of just the EOL ones, an
    EOL count, and a flag for whether legacy TLS was detected as a
    corroborating signal.
    """
    oe = results.get("os_eol") or {}
    findings = oe.get("os_findings") or []
    detected = []
    eol = []
    for f in findings:
        ver = f.get("version") or ""
        # Strip the internal "?" placeholder used when a distro was
        # detected without an extractable version number — for CSV
        # output we want a clean cell like "centos" instead of
        # "centos ?". Same convention as the breakdown labels in
        # score_results / the rendering side.
        if ver in ("?", ""):
            token = f["os"]
        else:
            token = f"{f['os']} {ver}"
        detected.append(token)
        if f.get("eol_status") == "eol":
            eol.append(token)
    return {
        "tech_os_detected":      ";".join(detected),
        "tech_os_eol":           ";".join(eol),
        "tech_os_eol_count":     _str_or_blank(len(eol)),
        "tech_os_tls_old_stack": "yes" if oe.get("tls_old_stack") else "no",
    }


# ── CSV schema (v2.2.0) ───────────────────────────────────────────────────────
# Columns are listed in the same logical order they appear in the report:
# meta -> email -> dns -> routing -> tls -> http -> web -> score. New columns
# go in the same group so the spreadsheet stays scan-friendly.

CSV_FIELDS = [
    # Meta / identity
    "meta_timestamp", "meta_rubric_version", "meta_schema_version",
    "meta_scan_version",
    "meta_deep_mode", "meta_domain_input", "meta_domain_audited", "meta_redirected",

    # Email — SPF
    "email_spf_status", "email_spf_lookup_count",
    "email_spf_redirect_target", "email_spf_record",
    # Email — DMARC
    "email_dmarc_status", "email_dmarc_policy", "email_dmarc_pct",
    "email_dmarc_subdomain_policy",
    "email_dmarc_rua_count", "email_dmarc_rua_destinations",
    "email_dmarc_inherited_from", "email_dmarc_record",
    # Email — MX
    "email_mx_status", "email_mx_is_null_mx", "email_mx_hosts",
    "email_mx_targets_ip", "email_mx_targets_cname",
    # Email — Mail transport hardening
    "email_mta_sts_present", "email_mta_sts_mode", "email_mta_sts_id",
    "email_tls_rpt_present", "email_tls_rpt_rua",
    "email_dane_mx_total", "email_dane_mx_with_tlsa",
    "email_dkim_selectors_checked", "email_dkim_selectors_found",
    "email_dkim_worst_strength",
    # Email — Redirect target equivalents
    "email_redirect_target_spf_status", "email_redirect_target_spf_record",
    "email_redirect_target_dmarc_policy", "email_redirect_target_dmarc_record",
    "email_redirect_target_dmarc_rua_count",
    "email_redirect_target_mx_hosts", "email_redirect_target_mx_is_null_mx",
    "email_redirect_target_mta_sts_present", "email_redirect_target_mta_sts_mode",
    "email_redirect_target_tls_rpt_present",
    "email_redirect_target_dane_mx_with_tlsa",
    # Email — STARTTLS-MX probe
    "email_starttls_mx_count", "email_starttls_mx_tls13",
    "email_starttls_mx_tls12", "email_starttls_mx_errors",

    # DNS
    "dns_dnssec_status", "dns_dnssec_tld_signed",
    "dns_dnssec_dnskey_present", "dns_dnssec_chain_validated",
    "dns_caa_present", "dns_caa_authorised_cas",
    "dns_caa_iodef_contacts", "dns_caa_inherited_from",
    "dns_nameserver_count", "dns_nameservers",
    "dns_soa_serial", "dns_soa_primary",
    "dns_lame_ns", "dns_open_resolver_ns", "dns_ns_health_probed",

    # Routing
    "routing_ipv4_address", "routing_ipv4_asn", "routing_ipv4_asn_name",
    "routing_ipv4_prefix", "routing_ipv4_rpki_status", "routing_ipv4_in_irr",
    "routing_ipv6_status", "routing_ipv6_addresses",
    "routing_ipv6_asn", "routing_ipv6_asn_name",
    "routing_ipv6_prefix", "routing_ipv6_rpki_status", "routing_ipv6_in_irr",
    "routing_rpki_worst",

    # TLS
    "tls_status", "tls_version",
    "tls_cert_issuer", "tls_cert_issued", "tls_cert_expires",
    "tls_cert_lifetime_days", "tls_cert_name_match",
    "tls_cert_san_names", "tls_cert_covers_variant",
    "tls_chain_status", "tls_chain_sent_count", "tls_chain_verified_count",
    "tls_hsts_status", "tls_hsts_max_age_seconds",
    "tls_hsts_includes_subdomains", "tls_hsts_preload_directive", "tls_hsts_preloaded",
    "tls_hsts_preload_status",
    "tls_ssl_labs_grade", "tls_ssl_labs_assessed_utc",

    # HTTP
    "http_version", "http_h3_advertised", "http_alt_svc",
    "http_redirect_status", "http_redirect_detail",
    "http_first_hop_status", "http_first_hop_url",
    "http_response_elapsed_ms",
    "http_www_apex_outcome", "http_www_apex_missing_side",
    "http_www_fallback",

    # Website — server / headers / cookies / security.txt / clock / page (deep)
    "web_server_header_kind", "web_server_header", "web_x_powered_by",
    "web_inferred_os", "web_tech_stack",
    "web_csp_quality", "web_csp_enforcement",
    "web_csp_script_src_outcome", "web_csp_object_src_outcome",
    "web_csp_base_uri_outcome", "web_csp_frame_ancestors_outcome",
    "web_csp_findings_count",
    "web_x_frame_options", "web_x_content_type_options",
    "web_referrer_policy", "web_permissions_policy_set",
    "web_coop", "web_coep", "web_corp",
    "web_origin_agent_cluster", "web_x_xss_protection",
    "web_cache_control", "web_expires_header",
    "web_cookie_count", "web_cookies_missing_secure",
    "web_cookies_missing_httponly", "web_cookies_missing_samesite",
    "web_cookies_with_valid_prefix", "web_cookies_with_invalid_prefix",
    "web_cookie_detail",
    "web_security_txt_present", "web_security_txt_contacts",
    "web_security_txt_policy", "web_security_txt_expires", "web_security_txt_expired",
    "web_error_page_outcome", "web_error_page_detected",
    "web_error_page_version", "web_error_page_status",
    "web_cors_outcome",
    "web_clock_skew_seconds", "web_clock_outcome",
    "web_page_parsed",
    "web_page_third_party_origins", "web_page_third_party_count",
    "web_page_external_resources", "web_page_sri_protected", "web_page_sri_outcome",
    "web_page_mixed_active_count", "web_page_mixed_outcome",
    "web_page_iframe_count", "web_page_meta_csp",
    "web_page_a11y_html_lang", "web_page_a11y_images_total",
    "web_page_a11y_images_missing_alt", "web_page_a11y_inputs_total",
    "web_page_a11y_inputs_unlabeled", "web_page_a11y_empty_buttons",
    "web_page_a11y_empty_links",
    # 2.8.0: versioned library detection. Both columns are semicolon-
    # separated for in-cell readability ("jquery 1.12.4;bootstrap 4.6.2").
    # tech_libs_detected is every match; tech_libs_eol is the subset that
    # was flagged EOL (i.e. retired, below a curated floor, or
    # past its end-of-life date). tech_libs_eol_count gives a numeric
    # column for spreadsheet sorting / filtering.
    "tech_libs_detected", "tech_libs_eol", "tech_libs_eol_count",
    # 2.9.0: same shape for server OS detection. tech_os_detected lists
    # every detected OS as "<key> <version>" (semicolon-separated);
    # tech_os_eol lists only those flagged EOL (i.e.
    # past its end-of-life date); tech_os_eol_count is a numeric for filtering;
    # tech_os_tls_old_stack is "yes"/"no" for whether TLS 1.0/1.1/SSLv3
    # was still negotiated, which corroborates the OS finding but is
    # recorded separately so it can be reasoned about on its own.
    "tech_os_detected", "tech_os_eol", "tech_os_eol_count",
    "tech_os_tls_old_stack",

    # Score — overall + per-category breakdown
    "findings_sort_key", "findings_issues", "findings_critical_high",
    "findings_passed", "findings_passed_pct",
    "findings_critical", "findings_high", "findings_medium", "findings_low",
    "findings_info", "findings_verdict",
    "findings_email_issues", "findings_email_worst",
    "findings_dns_issues", "findings_dns_worst",
    "findings_routing_issues", "findings_routing_worst",
    "findings_tls_issues", "findings_tls_worst",
    "findings_http_issues", "findings_http_worst",
    "findings_website_issues", "findings_website_worst",
]


def error_csv_row(domain, error_message, timestamp):
    """Build a CSV row for a domain that failed during audit.
    All check fields are blank; identity + the error message are populated.
    """
    row = {field: "" for field in CSV_FIELDS}
    row["meta_timestamp"]       = timestamp
    row["meta_rubric_version"]  = RUBRIC.get("rubric_version", "")
    row["meta_schema_version"]  = _SCHEMA_VERSION
    row["meta_scan_version"]    = RUBRIC.get("rubric_version", "")
    row["meta_domain_input"]    = domain
    row["meta_domain_audited"]  = domain
    row["email_spf_status"]     = f"audit_error: {error_message}"
    return row
