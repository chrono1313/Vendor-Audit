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

Also covered: SPF is scored on every domain (a no-MX domain with no SPF
record scores 0/18 instead of dropping the row), and the certificate
lifetime / renewal thresholds.

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
                "cert_lifetime_days": 80, "cert_remaining_pct": 60.0,
                "cert_remaining_seconds": 48 * 86400, "chain_status": "complete"},
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


def _rows(results):
    _, _, pts = audit_checks.score_results(results)
    return {label: (earned, possible) for label, earned, possible in pts}


def _spf_and_cert_cases():
    """Targeted row-level assertions. Returns a list of failure strings."""
    fails = []

    # SPF is scored on every domain. No MX + no SPF record must score 0/18,
    # not vanish (the bug: the row was gated on 'has MX or has SPF').
    d = _full_domain()
    d["mx"] = {"entries": [], "null_mx": False}
    d["spf"] = {"status": "missing", "record": None, "lookup_count": None}
    rows = _rows(d)
    if rows.get("SPF policy") != (0, 18):
        fails.append(f"  FAIL no MX + no SPF: SPF policy row is {rows.get('SPF policy')}, want (0, 18)")

    # A missing record has no redirect and no lookup count to judge.
    d = _full_domain()
    d["spf"] = {"status": "missing", "record": None, "lookup_count": None}
    rows = _rows(d)
    for label in ("SPF redirect", "SPF lookup count"):
        if label in rows:
            fails.append(f"  FAIL MX + no SPF: '{label}' scored {rows[label]} with no SPF record")
    if rows.get("SPF policy") != (0, 18):
        fails.append(f"  FAIL MX + no SPF: SPF policy row is {rows.get('SPF policy')}, want (0, 18)")

    # No MX + "v=spf1 -all" is the recommended posture: full marks.
    d = _full_domain()
    d["mx"] = {"entries": [], "null_mx": False}
    d["spf"] = {"status": "null_sender", "record": "v=spf1 -all", "lookup_count": 0}
    if _rows(d).get("SPF policy") != (18, 18):
        fails.append("  FAIL no MX + v=spf1 -all: SPF policy should be 18/18")

    # A failed or deadline-skipped SPF lookup is missing data, not a missing
    # record: no SPF rows at all.
    for spf in ({"status": "error", "error": "SERVFAIL"},
                {"error": "Skipped: audit deadline exceeded"}):
        d = _full_domain()
        d["spf"] = spf
        if any(k.startswith("SPF") for k in _rows(d)):
            fails.append(f"  FAIL SPF lookup failed ({spf}): SPF rows were scored")

    # Certificate lifetime: 91 days or less reads as automated issuance.
    for days, want in ((90, (10, 10)), (91, (10, 10)), (92, (0, 10)), (199, (0, 10)), (6, (10, 10))):
        d = _full_domain()
        d["tls"]["cert_lifetime_days"] = days
        got = _rows(d).get("Certificate lifetime")
        if got != want:
            fails.append(f"  FAIL cert lifetime {days}d: got {got}, want {want}")

    # Certificate renewal: under 10% of lifetime left is overdue. Percent of
    # lifetime, so a ~160-hour certificate is judged the same way.
    for pct, want in ((60.0, (4, 4)), (10.0, (4, 4)), (9.9, (0, 4)), (-3.0, (0, 4))):
        d = _full_domain()
        d["tls"]["cert_remaining_pct"] = pct
        got = _rows(d).get("Certificate renewal")
        if got != want:
            fails.append(f"  FAIL cert renewal at {pct}% left: got {got}, want {want}")

    # The text report keeps its own copy of the two certificate thresholds
    # for wording; they must not drift from the rubric.
    from vendor_audit import audit_txt_report as atr
    th = audit_checks.RUBRIC["thresholds"]
    if atr._CERT_LIFETIME_MAX_DAYS != th["cert_lifetime_max_days"]:
        fails.append("  FAIL audit_txt_report._CERT_LIFETIME_MAX_DAYS differs from the rubric")
    if atr._CERT_RENEWAL_MIN_PCT != th["cert_renewal_min_remaining_pct"]:
        fails.append("  FAIL audit_txt_report._CERT_RENEWAL_MIN_PCT differs from the rubric")

    # No remaining-life figure (older cached result) → row not scored.
    d = _full_domain()
    d["tls"].pop("cert_remaining_pct")
    if "Certificate renewal" in _rows(d):
        fails.append("  FAIL cert renewal scored without a remaining-life figure")
    return fails


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

    row_failures = _spf_and_cert_cases()
    if not row_failures:
        print("  ok   SPF scored on every domain; certificate lifetime and renewal thresholds")
    failures.extend(row_failures)

    if failures:
        print("\nSCORING DENOMINATOR REGRESSIONS:\n" + "\n".join(failures))
        return 1
    print(f"\nAll denominator checks passed (baseline denom {base_denom}).")
    return 0


if __name__ == "__main__":
    sys.exit(run())
