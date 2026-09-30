#!/usr/bin/env python3
"""Scoring regression tests — guards against the 'denominator vanish' bug class.

Background
----------
Several checks score a "quality" row (e.g. DMARC policy, CSP directives) only
when the feature is present. If that row is gated on the feature's *presence*
rather than on *data availability*, then a domain that LACKS the feature has
the row omitted from the denominator entirely — instead of scoring 0. The
effect is that lacking a feature can score BETTER (by percentage) than having
it weakly configured, because the penalty rows disappear.

This bit us twice:
  - DMARC policy (18 pts) vanished when no DMARC record existed.
  - CSP directives (30 pts) vanished when no CSP header existed.

These tests assert that removing a feature that SHOULD always be scored (given
the domain is a web/mail domain) does NOT shrink the denominator — the rows
must still be present, scored 0.

Deliberately NOT tested (these correctly score only when present):
  - Cookie flags       — no cookies means nothing to secure
  - DANE / STARTTLS-MX — only relevant with MX
  - DMARC pct / sp / rua — only meaningful with an enforcing policy

Run:  python3 tests/test_scoring_denominator.py
Exits non-zero on failure.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vendor_audit import audit_checks  # noqa: E402


def _full_domain():
    """A domain with every scored feature present and healthy."""
    return {
        "ip_routing": {"v4": {"address": "1.2.3.4"}, "v6": {"address": "::1"}},
        "spf": {"status": "hardfail", "record": "v=spf1 -all",
                "all_qualifier": "-", "lookup_count": 3},
        "dmarc": {"present": True, "policy": "reject", "pct": 100,
                  "sp": "reject", "rua": ["mailto:x@ex.com"]},
        "mx": {"entries": [{"priority": 10, "host": "mx.ex.com"}], "null_mx": False},
        "tls": {"error": None, "version": "TLSv1.3", "cert_names_match": True,
                "cert_lifetime_days": 80, "chain_status": "complete"},
        "http_version": {"version": "HTTP/3"},
        "http_redirect": {"status": "https_only"},
        "server_header": {"server": "nginx", "csp_quality": "present",
                          "x_content_type": "nosniff",
                          "cookies": [{"name": "s", "secure": True,
                                       "httponly": True, "samesite": "Strict",
                                       "infra": False}],
                          "coop": "same-origin", "corp": "same-origin",
                          "referrer_policy": "no-referrer",
                          "permissions_policy": "geolocation=()", "stack": []},
        "csp_analysis": {"present": True, "script_src_outcome": "strict",
                         "object_src_outcome": "none_or_self",
                         "base_uri_outcome": "set",
                         "frame_ancestors_outcome": "set",
                         "enforcement_outcome": "enforced"},
        "hsts": {"present": True, "includes_subdomains": True,
                 "preloaded": True, "max_age": 99999999},
        "tech_eol": {"techs": []}, "os_eol": {"os_findings": []},
        "mta_sts": {"present": True}, "tls_rpt": {"present": True},
        "caa": {"present": True, "iodef": True},
        "security_txt": {"present": True, "contact": "x", "expired": False},
        "dkim": {"checked": True, "found": True, "key_bits": 2048, "key_type": "rsa"},
    }


# Each case: a mutation that REMOVES a feature which must still be scored (0),
# so the denominator must NOT shrink.
_MUST_NOT_SHRINK = [
    ("DMARC absent",
     {"dmarc": {"present": False, "policy": None}},
     # DMARC present (4) + policy (18) must remain; pct/sp/rua correctly drop (16)
     16),  # allowed shrink: pct+sp+rua only-apply-when-enforcing
    ("CSP absent",
     {"csp_analysis": {"present": False, "script_src_outcome": "missing",
                       "object_src_outcome": "missing", "base_uri_outcome": "missing",
                       "frame_ancestors_outcome": "missing",
                       "enforcement_outcome": "enforced"},
      "server_header_csp": "missing"},
     0),  # nothing should drop — all CSP rows score 0
    ("security.txt absent",
     {"security_txt": {"present": False}}, 0),
    ("CAA absent",
     {"caa": {"present": False}}, 0),
    ("MTA-STS absent",
     {"mta_sts": {"present": False}}, 0),
    ("HSTS absent",
     {"hsts": {"present": False}},
     # HSTS present (6) + includeSubDomains (2) + preloaded (2) must remain;
     # max-age strength (2) correctly drops — it's a refinement that only
     # applies when HSTS exists, same principle as DMARC pct/sp.
     2),
]


def run():
    base = _full_domain()
    _, base_denom, _ = audit_checks.score_results(base)
    failures = []

    for name, mut, allowed_shrink in _MUST_NOT_SHRINK:
        d = _full_domain()
        # Special handling for the CSP csp_quality nested field.
        if "server_header_csp" in mut:
            d["server_header"]["csp_quality"] = mut.pop("server_header_csp")
        d.update(mut)
        _, denom, _ = audit_checks.score_results(d)
        shrink = base_denom - denom
        if shrink > allowed_shrink:
            failures.append(
                f"  FAIL {name}: denominator shrank by {shrink} "
                f"(allowed {allowed_shrink}). Rows vanished instead of scoring 0."
            )
        else:
            print(f"  ok   {name}: shrink {shrink} (allowed {allowed_shrink})")

    if failures:
        print("\nSCORING DENOMINATOR REGRESSIONS:\n" + "\n".join(failures))
        return 1
    print(f"\nAll denominator checks passed (baseline denom {base_denom}).")
    return 0


if __name__ == "__main__":
    sys.exit(run())
