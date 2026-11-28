"""vendor_audit.web.example — the example report at /learn/example-report.

A made-up vendor, sample-vendor.example (RFC 2606 reserves .example, so it
can never be a real site), with a typical mix: mostly sound, a handful of
gaps, one end-of-life runtime.

WHY IT STAYS CURRENT
--------------------
This module holds only raw check results: the same dict a real audit
returns. Ratings, wording, explanations and layout are never stored here;
every request runs these results through assess_results(), the rubric and
the renderers, exactly as for a live audit. A change to the rubric or the
report text shows up here on the next page load.

Dates are worked out from the time of the request (certificate 30 days
into a 90-day life, security.txt expiring in 200 days), so nothing ages.
The end-of-life runtime is PHP 7.4, which will never return to support.

tests/test_example.py fails the build when a check in rubric.json is
neither rated from these results nor listed in NOT_RATED with a reason,
and when a check in NOT_RATED is in fact rated. Adding or reshaping a
check therefore means adding its data here, or saying why it can't apply.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .. import audit_checks as ac
from .. import audit_txt_report

DOMAIN = "sample-vendor.example"
PATH = "/learn/example-report"
FILENAME = "vendor-audit-example-report"

# Checks that only apply when something this vendor doesn't have is in
# place. Every other check in rubric.json must be rated from results().
NOT_RATED = {
    "CSP base-uri": "only rated when a Content-Security-Policy is published; this vendor has none",
    "CSP object-src": "only rated when a Content-Security-Policy is published; this vendor has none",
    "DMARC external reports": "only rated when DMARC reports go to another organisation's domain",
    "DNSSEC TLD signed": "only listed when the TLD is unsigned",
    "DNSSEC algorithm": "only rated when the domain is DNSSEC signed",
    "DNSSEC DS digest": "only rated when the domain is DNSSEC signed",
    "MTA-STS max_age": "only rated when MTA-STS is published",
    "MTA-STS policy MX match": "only rated when MTA-STS is published",
    "Null MX on no-mail domain": "only rated for a domain that receives no mail",
    "Redirect first-hop hygiene": "only rated when the site redirects",
    "SSL Labs grade": "only rated when the SSL Labs option is chosen",
}

_MX = {"mx1.mailhost.example": ("198.51.100.25", "2001:db8:25::1"),
       "mx2.mailhost.example": ("198.51.100.26", "2001:db8:25::2")}
_NS = ["ns1.dnshost.example", "ns2.dnshost.example", "ns3.dnshost.example"]


def _day(dt):
    return dt.strftime("%Y-%m-%d")


def results(now: datetime | None = None) -> dict:
    """The raw audit results for the example vendor, dated relative to `now`."""
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    d = DOMAIN
    issued, expires = now - timedelta(days=30), now + timedelta(days=60)
    serial = int((now - timedelta(days=12)).strftime("%Y%m%d") + "01")
    sh = {
        "server": "Apache", "x_powered_by": "PHP/7.4.33", "http3_advertised": False,
        "x_content_type": "nosniff", "x_frame_options": "SAMEORIGIN", "referrer_policy": None,
        "permissions_policy": None, "coop": None, "corp": None,
        "cookies": [{"name": "PHPSESSID", "secure": True, "httponly": True, "samesite": None, "path": "/",
                     "domain": None, "infra": False, "issues": ["missing_samesite"]},
                    {"name": "__Host-csrf", "secure": True, "httponly": True, "samesite": "Lax", "path": "/",
                     "domain": None, "infra": False, "issues": []}],
        "stack": ["PHP", "WordPress"], "csp": None, "csp_report_only": None, "csp_quality": "missing",
        "public_key_pins": None, "expect_ct": None,
        "cache_control": "no-store, no-cache, must-revalidate", "expires": "Thu, 19 Nov 1981 08:52:00 GMT",
    }
    tls = {
        "error": None, "version": "TLSv1.3", "cert_names_match": True,
        "cert_issued": _day(issued), "cert_expires": _day(expires), "cert_lifetime_days": 90,
        "cert_remaining_pct": 66.7, "cert_remaining_seconds": 60 * 86400, "chain_status": "complete",
        "cert_key_type": "EC", "cert_key_bits": 256, "cert_sig_alg": "ecdsa-with-SHA384",
        "cert_issuer": "R12", "cert_sans": [d, f"www.{d}"],
        "cert_aki": "00B529F22D8E6F31E89B4CAD783EFADCE90CD1D2",      # Let's Encrypt R12 (CCADB)
        "cipher": "TLS_AES_256_GCM_SHA384", "forward_secrecy": True,
    }
    error_page = {"outcome": "custom_404"}
    today = _day(now)
    r = {
        # ── Email ──
        "spf": {"status": "softfail",
                "record": "v=spf1 include:_spf.mailhost.example include:send.newsletter.example ~all",
                "lookup_count": 6, "record_count": 1, "void_lookups": 0, "uses_ptr": False,
                "missing_includes": []},
        "dmarc": {"present": True, "policy": "quarantine", "pct": 100, "sp": "none", "ruf": [],
                  "rua": [f"mailto:dmarc@{d}"], "record_count": 1, "inherited_from": None,
                  "record": f"v=DMARC1; p=quarantine; sp=none; rua=mailto:dmarc@{d}", "rua_external": [],
                  "adkim": "r", "aspf": "r"},
        "dkim": {"checked": ["selector1", "selector2", "google", "default"], "found": ["selector1"],
                 "worst_strength": "good"},
        "mx": {"entries": [{"priority": 10, "host": h} for h in _MX], "null_mx": False,
               "mx_targets_ip": [], "mx_targets_cname": [],
               "mx_hosts": {h: {"v4": [a4], "v6": [a6], "resolves": True,
                                "ptr": [{"address": a4, "name": h, "confirmed": True}]}
                            for h, (a4, a6) in _MX.items()}},
        "mta_sts": {"present": False},
        "tls_rpt": {"present": False},
        "bimi": {"present": False},
        "dane": {"mx_count": 2, "with_tlsa": []},
        "starttls_mx": {"mx_count": 2, "results": {
            h: {"error": None, "tls_version": "TLSv1.3", "cert_subject": h, "cert_issuer": "Example CA R3",
                "cert_expires": _day(now + timedelta(days=41)), "cert_lifetime_days": 90,
                "cert_verified": True, "cert_verify_reason": None, "cert_remaining_pct": 45.6}
            for h in _MX}},
        # ── DNS ──
        "dnssec": {"tld": {"signed": True, "tld": "example"}, "domain": {"dnskey": False, "ad_flag": False}},
        "caa": {"present": True, "records": ['0 issue "letsencrypt.org"'], "issue": ["letsencrypt.org"],
                "issuewild": [], "iodef": []},
        "ns_soa": {"nameservers": _NS, "ns_count": 3,
                   "soa": {"primary": _NS[0], "admin": f"hostmaster.{d}", "serial": serial, "refresh": 7200,
                           "retry": 3600, "expire": 1209600, "minimum": 3600}},
        "ns_health": {"probed": 3, "lame_ns": [], "open_resolver_ns": [], "unprobed": [], "ns_list": _NS,
                      "versions": {}, "ns_sets": {h: _NS for h in _NS}, "serials": {h: serial for h in _NS},
                      "parent": {"zone": "example", "server": "a.nic.example", "ns": _NS}, "error": None},
        "dangling_cname": {"names": {d: {"chain": [], "end": "ok"}, f"www.{d}": {"chain": [], "end": "ok"}},
                           "dangling": []},
        "infra_routing": {
            "ns": {"hosts": {h: {"v4": [f"203.0.113.{i + 1}"], "v6": [f"2001:db8:53::{i + 1}"]}
                             for i, h in enumerate(_NS)},
                   "lookups": [{"host": h, "address": f"203.0.113.{i + 1}", "prefix": "203.0.113.0/24",
                                "asn": 64500 + i, "rpki_status": "valid", "error": None}
                               for i, h in enumerate(_NS)],
                   "error": None},
            "mx": {"hosts": {h: {"v4": [a4], "v6": [a6]} for h, (a4, a6) in _MX.items()},
                   "lookups": [{"host": h, "address": a4, "prefix": "198.51.100.0/24", "asn": 64510,
                                "rpki_status": "valid", "error": None} for h, (a4, _a6) in _MX.items()],
                   "error": None}},
        # ── Routing ──
        "ip_routing": {
            "v4": {"address": "192.0.2.80", "prefix": "192.0.2.0/24", "asn": 64496, "asn_name": "SAMPLE-HOSTING",
                   "rpki_status": "valid", "irr_in_ris": True, "error": None},
            "v6": {"address": "2001:db8:80::10", "prefix": "2001:db8::/32", "asn": 64496,
                   "asn_name": "SAMPLE-HOSTING", "rpki_status": "not-found", "irr_in_ris": True, "error": None}},
        # ── TLS ──
        "tls": tls,
        "tls_legacy": {"tls1_0": "refused", "tls1_1": "refused", "static_rsa": "refused", "null_cipher": "refused",
                       "rc4": "refused", "des3": "refused", "cbc": "accepted",
                       "cbc_suite": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "pq": "not_offered"},
        "cert_variant": {"outcome": "covers"},
        "hsts": {"present": True, "header": "max-age=31536000", "max_age": 31536000, "includes_subdomains": False,
                 "preload_directive": False, "preloaded": False},
        # ── HTTP ──
        "http_redirect": {"status": "https_only"},
        "redirect": {"redirected": False, "original": d, "final": d, "first_hop_url": f"https://{d}/",
                     "first_hop_https": True, "first_hop_same_host": True},
        "www_apex_unified": {"outcome": "unified", "apex_host": d, "www_host": f"www.{d}",
                             "apex_resolves": True, "www_resolves": True},
        "http_version": {"version": "HTTP/2"},
        "https_rr": {"present": False, "records": [], "alpn": [], "ech": False, "error": None},
        "wildcard_dns": {"wildcard": False, "name": f"va-3f9c2a71b0d4.{d}", "addresses": [], "error": None},
        # ── Website ──
        "server_header": sh,
        "csp_analysis": {"present": False, "script_src_outcome": "missing", "frame_ancestors_outcome": "missing"},
        "security_txt": {"present": True, "contact": [f"mailto:security@{d}"], "policy": None, "error": None,
                         "expires": (now + timedelta(days=200)).strftime("%Y-%m-%dT00:00:00Z"), "expired": False,
                         "found_at": f"https://{d}/.well-known/security.txt",
                         "final_url": f"https://{d}/.well-known/security.txt",
                         "canonical": [f"https://{d}/.well-known/security.txt"]},
        "error_page": error_page,
        "cors": {"outcome": "no_cors"},
        "clock": {"outcome": "in_sync", "skew_seconds": 0.4, "server_time": now.strftime("%Y-%m-%d %H:%M:%S UTC")},
        "page_signals": {"parsed": True, "sri_outcome": "external_without_sri", "mixed_outcome": "none",
                         "third_party_script_origins": ["cdn.jsdelivr.net", "www.googletagmanager.com"],
                         "a11y": {"html_lang_set": True, "html_lang": "en", "images_total": 12,
                                  "images_missing_alt": 2, "inputs_total": 3, "inputs_unlabeled": 0}},
        # End-of-life: judged live against the bundled end-of-life data.
        "os_eol": ac.check_os_eol("Apache", tls, today=today),
        "tech_eol": ac.check_tech_eol(sh, error_page, today=today),
        "versioned_libs": ac.check_versioned_libraries(
            '<script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script>'),
        "_scan": {"deep": True, "version": ac.__version__},
    }
    return r


def envelope(now: datetime | None = None) -> dict:
    """The audit envelope render_html.render_result() takes."""
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    return {"ok": True, "domain": DOMAIN, "audit_domain": DOMAIN, "results": results(now),
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "duration_ms": 8240, "example": True}


MARKDOWN_NOTE = (f"> **Example report:** {DOMAIN} is a fictional vendor and these results are made up. "
                 "The ratings and wording are the live ones, produced by the same code as a real audit.")


def markdown(now: datetime | None = None) -> str:
    """The text report (.md) for the example, with a note under the title."""
    env = envelope(now)
    md = audit_txt_report.markdown_report(DOMAIN, DOMAIN, env["results"], env["timestamp"])
    head, sep, rest = md.partition("\n\n")
    first, sep2, rest2 = rest.partition("\n\n")
    return f"{head}{sep}{first}\n\n{MARKDOWN_NOTE}{sep2}{rest2}"
