#!/usr/bin/env python3
"""Findings tests — severity map, one-cause-one-finding merges, page budget.

Vendor Audit has no score. Every check ends in an outcome, rubric.json gives
each outcome a severity, and reports count findings by severity. These tests
pin:

  - rubric integrity: every outcome the code can emit is either rated in
    rubric.json or on the short list of outcomes that deliberately produce
    no finding
  - a full sample domain produces the expected counts
  - SPF is assessed on every domain, mail-sending or not
  - one cause is one finding (HSTS, DNSSEC, clickjacking, failed TLS)
  - certificate lifetime and renewal thresholds
  - the HTML page stays one self-contained response with one script
  - every check has a record with an explanation, a standard and a detail
    panel on the page
  - a bot-challenge response is recorded and the reports say so
  - the .html download is a saved copy that works from disk

Run:  python3 tests/test_findings.py
Exits non-zero on failure.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vendor_audit import audit_checks as ac          # noqa: E402
from vendor_audit import audit_txt_report as atr     # noqa: E402

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def sample():
    """A domain with a bit of everything wrong: end-of-life Windows and
    jQuery, no DMARC, SPF ~all, an expiring year-long certificate, no
    security headers. Deep-mode shaped."""
    d = {
        "ip_routing": {"v4": {"address": "192.0.2.16", "rpki_status": "not-found", "irr_in_ris": True}, "v6": {}},
        "spf": {"status": "softfail", "record": "v=spf1 include:_spf.example.net ~all", "lookup_count": 4},
        "dmarc": {"present": False, "policy": None},
        "mx": {"entries": [{"priority": 1, "host": "mx.example.net"}], "null_mx": False},
        "mta_sts": {"present": False}, "tls_rpt": {"present": False}, "bimi": {"present": False},
        "dane": {"mx_count": 1, "with_tlsa": []},
        "dkim": {"checked": ["google"], "found": ["google"], "worst_strength": "good"},
        "dnssec": {"tld": {"tld": "com", "signed": True}, "domain": {"dnskey": False, "ad_flag": False}},
        "caa": {"present": False},
        "ns_soa": {"ns_count": 2}, "ns_health": {"probed": 2, "lame_ns": [], "open_resolver_ns": []},
        "tls": {"error": None, "version": "TLSv1.2", "cert_names_match": True,
                "cert_issued": "2025-11-19", "cert_expires": "2026-11-20", "cert_lifetime_days": 366,
                "cert_remaining_pct": 0.5, "cert_remaining_seconds": 43 * 3600, "chain_status": "complete"},
        "http_version": {"version": "HTTP/1.1"}, "http_redirect": {"status": "http_error"},
        "www_apex_unified": {"outcome": "unified"},
        "hsts": {"present": False},
        "server_header": {"server": "Microsoft-IIS/8.0", "x_powered_by": "ASP.NET", "http3_advertised": False,
                          "x_content_type": None, "x_frame_options": None, "referrer_policy": None,
                          "permissions_policy": None, "coop": None, "corp": None, "cookies": [], "stack": []},
        "csp_analysis": {"present": False, "script_src_outcome": "missing", "frame_ancestors_outcome": "missing"},
        "security_txt": {"present": False}, "error_page": {"outcome": "custom_404"},
        "cors": {"outcome": "no_cors"}, "clock": {"outcome": "in_sync", "skew_seconds": 1.1, "server_time": "2026-11-19 04:55:33 UTC"},
        "page_signals": {"parsed": True, "sri_outcome": "external_without_sri", "mixed_outcome": "active"},
    }
    d["os_eol"] = ac.check_os_eol("Microsoft-IIS/8.0", d["tls"], today="2026-11-18")
    d["tech_eol"] = ac.check_tech_eol(d["server_header"], d["error_page"], today="2026-11-18")
    d["versioned_libs"] = ac.check_versioned_libraries('<script src="/js/jquery-1.9.1.min.js"></script>')
    return d


def by_label(results):
    return {f["label"]: f for f in ac.assess_results(results)}


def sev(results, label):
    f = by_label(results).get(label)
    return f["severity"] if f else None


# Outcomes the code emits on purpose with no rubric entry: nothing to report.
_NO_FINDING = {
    ("MX target hygiene", "no_mx"), ("Cert covers www variant", "no_redirect"),
    ("Cert chain completeness", "unsupported"), ("Cookie name prefixes", "no_prefixed"),
    ("Redirect first-hop hygiene", "no_redirect"), ("www and apex unified", "not_scored"),
    ("Server clock accuracy", "no_date"), ("DKIM key strength", "not_found"),
    ("Authoritative delegation", "unprobed"), ("NS not open resolver", "unprobed"),
    ("DNSSEC TLD signed", "signed"),
    # Raw checks folded into one finding by _merge_outcomes.
    ("HSTS present", "present"), ("HSTS present", "missing"),
    ("HSTS includeSubDomains", "set"), ("HSTS includeSubDomains", "unset"),
    ("HSTS preloaded", "preloaded"), ("HSTS preloaded", "pending"),
    ("HSTS preloaded", "preload_directive"), ("HSTS preloaded", "not_preloaded"),
    ("HSTS max-age strength", "missing"), ("HSTS max-age strength", "six_months_plus"),
    ("HSTS max-age strength", "less_than_six"),
    ("DNSSEC DNSKEY", "present"), ("DNSSEC DNSKEY", "missing"),
    ("DNSSEC AD flag", "set"), ("DNSSEC AD flag", "unset"),
    ("X-Frame-Options", "set"), ("X-Frame-Options", "unset"),
}


def test_rubric_integrity():
    rubric = ac.RUBRIC
    findings = rubric["findings"]
    valid = set(rubric["severities"])
    for label, outcomes in findings.items():
        for outcome, entry in outcomes.items():
            check(entry[0] in valid, f"{label}/{outcome}: unknown severity {entry[0]!r}")
            check(bool(entry[1].strip()), f"{label}/{outcome}: empty text")
    in_cats = [l for labels in rubric["categories"].values() for l in labels]
    check(sorted(in_cats) == sorted(findings), "categories and findings list different labels")

    # Every literal _p("label", "outcome") in the code is rated or exempt.
    src = open(os.path.join(os.path.dirname(ac.__file__), "audit_checks.py"), encoding="utf-8").read()
    for label, outcome in set(re.findall(r'_p\("([^"]+)",\s*"([^"]+)"\)', src)):
        if (label, outcome) in _NO_FINDING:
            continue
        check(outcome in findings.get(label, {}),
              f'code emits ("{label}", "{outcome}") but rubric.json does not rate it')


def test_sample_counts():
    counts = ac.severity_counts(ac.assess_results(sample()))
    want = {"critical": 2, "high": 4, "medium": 11, "low": 10, "info": 2}
    for s, n in want.items():
        check(counts[s] == n, f"sample domain: {counts[s]} {s}, want {n}")
    f = by_label(sample())
    check(f["DMARC policy"]["severity"] == "critical", "missing DMARC should be critical")
    check(f["EOL OS: iis 8.0"]["severity"] == "critical", "end-of-life OS should be critical")
    check(f["EOL library: jquery 1.9.1"]["severity"] == "high", "end-of-life library should be high")
    check(f["BIMI"]["severity"] == "info" and f["DANE TLSA on MX"]["severity"] == "info",
          "BIMI and DANE are optional: info, never counted")
    check(atr.verdict_for(counts) == "Critical issues found", "verdict follows the worst severity")
    check(atr.verdict_for({"low": 3}) == "Minor issues only", "low-only verdict")
    check(atr.verdict_for({}) == "No issues found", "clean verdict")

    # CSV sorting columns.
    from vendor_audit import audit_render
    key = audit_render.findings_sort_key
    check(key(counts) == 2004011010, f"sort key for 2/4/11/10 should be 2004011010, got {key(counts)}")
    check(key({"medium": 50}) < key({"high": 1}), "fifty mediums must still sort ahead of one high")
    check(key({"high": 900, "medium": 900, "low": 900}) < key({"critical": 1}), "nothing below outweighs a critical")
    check(key({}) == 0 and key({"low": 5000}) == 999, "clean is 0; counts cap at 999")
    row = audit_render._score_csv(sample())
    check(row["findings_issues"] == "27" and row["findings_critical_high"] == "6",
          f"issues / critical+high columns wrong: {row['findings_issues']}, {row['findings_critical_high']}")
    check(row["findings_passed_pct"] == str(round(100 * counts["pass"] / (counts["pass"] + 27))),
          "passed_pct should be passed / (passed + issues)")
    check(set(row) <= set(__import__("vendor_audit.cli", fromlist=["CSV_FIELDS"]).CSV_FIELDS),
          "every findings column must be in the CSV field list")


def test_spf_everywhere():
    d = sample(); d["mx"] = {"entries": [], "null_mx": False}; d["spf"] = {"status": "missing"}
    check(sev(d, "SPF policy") == "critical", "no MX + no SPF record must be a critical finding")
    d["spf"] = {"status": "null_sender", "record": "v=spf1 -all"}
    check(sev(d, "SPF policy") == "pass", "no MX + v=spf1 -all is the recommended posture")
    for spf in ({"status": "error", "error": "SERVFAIL"}, {"error": "Skipped: audit deadline exceeded"}):
        d = sample(); d["spf"] = spf
        check(not any(l.startswith("SPF") for l in by_label(d)),
              f"a failed SPF lookup is missing data, not a finding ({spf})")
    d = sample(); d["spf"] = {"status": "pass_all_DANGEROUS"}
    check(sev(d, "SPF policy") == "critical", "+all should be critical")
    d["spf"] = {"status": "hardfail", "lookup_count": 12}
    check(sev(d, "SPF lookup count") == "high", "over 10 lookups should be high")


def test_one_cause_one_finding():
    f = by_label(sample())
    check("HSTS" in f and f["HSTS"]["severity"] == "high", "missing HSTS is one high finding")
    for gone in ("HSTS present", "HSTS includeSubDomains", "HSTS preloaded", "HSTS max-age strength",
                 "HSTS preload", "DNSSEC DNSKEY", "DNSSEC AD flag", "X-Frame-Options",
                 "CSP frame-ancestors", "SPF redirect", "MX records"):
        check(gone not in f, f"'{gone}' should not appear as its own finding")
    check(f["DNSSEC"]["outcome"] == "not_enabled", "DNSSEC is one finding")
    check(f["Clickjacking protection"]["severity"] == "medium", "no XFO and no frame-ancestors: medium")

    d = sample(); d["hsts"] = {"present": True, "includes_subdomains": False, "preloaded": False, "max_age": 3600}
    f = by_label(d)
    check(f["HSTS"]["outcome"] == "weak_both" and f["HSTS"]["severity"] == "low", "weak HSTS is one low finding")
    d["hsts"] = {"present": True, "includes_subdomains": True, "preloaded": False, "max_age": 63072000}
    f = by_label(d)
    check(f["HSTS"]["severity"] == "pass" and f.get("HSTS preload", {}).get("severity") == "info",
          "good HSTS passes; not being preloaded is info only")

    d = sample(); d["server_header"]["x_frame_options"] = "DENY"
    check(sev(d, "Clickjacking protection") == "pass", "X-Frame-Options alone is enough")

    d = sample(); d["tls"] = {"error": "connection refused", "tls_cert_error": False}
    f = by_label(d)
    check(f["TLS connection"]["severity"] == "critical", "no HTTPS is critical")
    for gone in ("TLS 1.3", "Certificate lifetime", "Certificate renewal", "Certificate name match", "HTTP version"):
        check(gone not in f, f"with no TLS, '{gone}' has nothing to judge")


def test_certificate_thresholds():
    for days, want in ((6, "pass"), (90, "pass"), (91, "pass"), (92, "medium"), (199, "medium")):
        d = sample(); d["tls"]["cert_lifetime_days"] = days
        check(sev(d, "Certificate lifetime") == want, f"lifetime {days}d should be {want}")
    for pct, want in ((60.0, "pass"), (10.0, "pass"), (9.9, "medium"), (-2.0, "medium")):
        d = sample(); d["tls"]["cert_remaining_pct"] = pct
        check(sev(d, "Certificate renewal") == want, f"{pct}% of lifetime left should be {want}")
    d = sample(); d["tls"].pop("cert_remaining_pct")
    check(sev(d, "Certificate renewal") is None, "no remaining-life figure: no finding")
    th = ac.RUBRIC["thresholds"]
    check(atr._CERT_LIFETIME_MAX_DAYS == th["cert_lifetime_max_days"], "txt lifetime threshold drifted from rubric")
    check(atr._CERT_RENEWAL_MIN_PCT == th["cert_renewal_min_remaining_pct"], "txt renewal threshold drifted from rubric")


def test_mta_sts_default_mode():
    d = sample(); d["mta_sts"] = {"present": True}
    f = by_label(d)["MTA-STS"]
    check(f["outcome"] == "published" and f["severity"] == "pass",
          "a published MTA-STS record whose policy was not fetched must not be reported as 'testing'")


def test_page_budget():
    """The report page is one response: no stylesheet, image or font to
    fetch, and exactly one first-party script."""
    try:
        from vendor_audit.web import render_html
    except Exception as exc:                     # web extras not installed
        print(f"       (skipped page budget: {exc})")
        return
    d = sample(); d["_scan"] = {"deep": True, "version": "3.0.0"}
    page = render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                      "results": d, "timestamp": "2026-11-19T04:55:32Z", "duration_ms": 1200})
    scripts = re.findall(r"<script\b[^>]*>", page)
    check(len(scripts) == 1 and 'src="/static/result.js' in scripts[0], f"expected one first-party script, got {scripts}")
    check(not re.search(r'<link[^>]+rel="stylesheet"', page), "page must not load a stylesheet")
    check("<img" not in page and "@font-face" not in page and "@import" not in page, "page must not load images or fonts")
    check(not re.search(r'\b(?:src|href)="https?://(?!github\.com|www\.ssllabs\.com|vendoraudit\.org)[^"]*\.(?:js|css|woff2?|png|svg)"', page),
          "page must not reference third-party assets")
    import gzip
    raw = page.encode("utf-8")
    kb, wire = len(raw) / 1024, len(gzip.compress(raw)) / 1024
    check(kb < 250, f"page is {kb:.0f} KB; budget is 250 KB")
    check(wire < 45, f"page is {wire:.0f} KB compressed; budget is 45 KB on the wire")
    check("2 critical and 4 high findings" in page, "headline should state the two worst severities")
    check("<!--AGO-->" in page, "scan-age placeholder must survive for the cache layer")
    check('class="ring"' in page and "passed of" in page, "pass-rate ring should be on the page")
    rows = re.findall(r'<tr data-sev="(\w+)" data-cat="[^"]*" data-id="([\w-]+)">', page)
    check(len(rows) == len(ac.assess_results(sample())), f"one table row per check, got {len(rows)}")
    for _sev, rid in rows:
        check(f'id="check-{rid}"' in page, f"check {rid} has no detail panel")
    for target in set(re.findall(r'href="#([\w-]+)"', page)):
        check(f'id="{target}"' in page, f"link to #{target} has no target on the page")


def test_saved_copy():
    """The .html download works from disk: script inlined, no site-relative
    links, no request to make, and the site-only parts gone."""
    try:
        from vendor_audit.web import render_html
    except Exception as exc:                     # web extras not installed
        print(f"       (skipped saved copy: {exc})")
        return
    d = sample(); d["_scan"] = {"deep": True, "version": "3.0.0"}
    page = render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                      "results": d, "timestamp": "2026-11-19T04:55:32Z", "duration_ms": 1200})
    check('href="/audit/example.com.html?deep=1"' in page, "site page should link the .html download")
    check('class="banner banner-saved" hidden' in page, "saved-copy note should be hidden on the site")
    check("</script" not in render_html._RESULT_JS, "the script must not contain </script, or inlining breaks")
    saved = render_html.to_standalone(page, "https://vendoraudit.org", "<svg></svg>")
    scripts = re.findall(r"<script\b[^>]*>", saved)
    check(scripts == ["<script>"], f"saved copy should have one inline script, got {scripts}")
    check("openDrawer" in saved, "the inlined script should be the page script")
    left = re.findall(r'(?:href|src|action)="/[^"]*"', saved)
    check(not left, f"saved copy should have no site-relative links, found {left[:3]}")
    check(not re.findall(r'<link rel="stylesheet"|<img\b|<iframe\b', saved), "saved copy should fetch nothing")
    check('class="inline-audit-form"' not in saved and "<!--site-->" not in saved, "site-only parts should be gone")
    check("<!--AGO-->" not in saved, "age placeholder should be gone")
    check('class="banner banner-saved">' in saved, "saved-copy note should show")
    check('href="https://vendoraudit.org/audit/result?domain=example.com&amp;deep=1"' in saved,
          "audit-again link should point at the service")
    for target in set(re.findall(r'href="#([\w-]+)"', saved)):
        check(f'id="{target}"' in saved, f"link to #{target} has no target in the saved copy")


def test_bot_challenge():
    """A response Cloudflare marks as a challenge is recorded as one, and the
    reports say so. A plain 403 is not a challenge."""
    import httpx
    def resp(status, headers):
        return httpx.Response(status, headers=headers, content=b"<html><body>x</body></html>",
                              request=httpx.Request("GET", "https://example.com/"))
    hit = ac.check_server_header("example.com", _cached_response=resp(403, {"cf-mitigated": "challenge"}))
    miss = ac.check_server_header("example.com", _cached_response=resp(403, {"Server": "cloudflare"}))
    check(hit.get("bot_challenge") is True and hit.get("status_code") == 403, "challenge response should be recorded")
    check(miss.get("bot_challenge") is False, "a plain 403 is not a challenge")
    d = sample(); d["_scan"] = {"deep": True, "version": "3.0.0"}
    d["server_header"] = dict(d["server_header"], bot_challenge=True, status_code=403)
    data = atr._ReportData("example.com", "example.com", d, "2026-11-19T04:55:32Z", "2.1.0")
    check("Bot challenge:" in atr._render_text(data), "text report should carry the challenge note")
    try:
        from vendor_audit.web import render_html
    except Exception:
        return
    page = render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                      "results": d, "timestamp": "2026-11-19T04:55:32Z", "duration_ms": 1200})
    check("Bot challenge:" in page, "page should carry the challenge note")


def test_records():
    """Every check becomes one record with something to say about it."""
    from vendor_audit import audit_records as ar
    d = sample(); d["_scan"] = {"deep": True, "version": "3.0.0"}
    data = atr._ReportData("example.com", "example.com", d, "2026-11-19T04:55:32Z", "2.1.0")
    recs = ar.build_records(data)
    check(len(recs) == len(data.finding_rows), "one record per finding row")
    check(len({r["id"] for r in recs}) == len(recs), "record ids must be unique")
    order = [atr.SEVERITY_ORDER.index(r["severity"]) for r in recs]
    check(order == sorted(order), "records run from critical to passing")
    for r in recs:
        for field in ("topic", "standard", "what", "why"):
            check(bool(r[field]), f'record "{r["label"]}" has no {field}')
    # Every label the rubric can produce has a topic and a standard, and the
    # topic has its explanation.
    for label in ac.RUBRIC["findings"]:
        check(ar.topic_for(label) in atr.EXPLANATIONS, f'no explanation topic for "{label}"')
        check(bool(ar.standard_for(label)), f'no standard for "{label}"')
        check(all(ar.explanation_for(label)), f'incomplete explanation for "{label}"')
    for label in ar._CHECK_TEXT:
        check(label in ac.RUBRIC["findings"], f'_CHECK_TEXT names an unknown check "{label}"')
    # A builder that meets a shape it does not expect yields nothing.
    check(ar.evidence_for("DMARC policy", {"dmarc": "not a dict"}) == [], "evidence must not raise")
    check(ar.evidence_for("SPF policy", {}) == [], "no result, no evidence")
    # The share passed leaves informational rows out of both sides.
    check(atr.passed_pct({"pass": 17, "critical": 2, "high": 4, "medium": 10, "low": 10, "info": 2}) == 40,
          "17 of 43 assessed checks is 40%")
    check(atr.passed_pct({"pass": 0, "info": 3}) is None, "nothing assessed, no percentage")


def run():
    for fn in (test_rubric_integrity, test_sample_counts, test_spf_everywhere, test_one_cause_one_finding,
               test_certificate_thresholds, test_mta_sts_default_mode, test_page_budget, test_saved_copy, test_bot_challenge, test_records):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nFINDINGS FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll findings checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
