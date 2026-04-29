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
and scoring_rubric.json share a single version number that is enforced
at startup. See vendor_audit.py for the full versioning policy.
"""
from __future__ import annotations

__version__ = "1.0"

import sys
from collections import defaultdict
from datetime import datetime, timezone

from audit_checks import (
    RUBRIC, classify_server, score_results,
    _org_domain, STRONG_REFERRER_POLICIES,
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

_COLOR_BY_NAME = {
    "RED": RED, "YELLOW": YELLOW, "GREEN": GREEN,
    "CYAN": CYAN, "GREY": GREY, "BOLD": BOLD, "RESET": RESET,
}


def c(color, text):
    return f"{color}{text}{RESET}"


# ── Rubric-driven label tables ────────────────────────────────────────────────

_SCORE_LABEL_DISPLAY = RUBRIC["score_label_display"]
_PARTIAL_LABEL       = RUBRIC["partial_label"]

# 2.9.0: pretty display names for the OS keys used in os_eol.json. Like the
# library equivalent, missing entries fall back to the raw key.
_OS_DISPLAY_NAMES = {
    "centos":         "CentOS Linux",
    "rhel":           "Red Hat Enterprise Linux",
    "ubuntu":         "Ubuntu",
    "debian":         "Debian",
    "windows-server": "Windows Server",
    "iis":            "Microsoft IIS",
    "freebsd":        "FreeBSD",
}
_GRADE_COLOR_NAMES   = RUBRIC["ssl_grade_colors"]
_GRADE_COLOR = {g: _COLOR_BY_NAME.get(name, GREY) for g, name in _GRADE_COLOR_NAMES.items()}
_SSL_GRADE_PTS = {g: entry["earned"]
                  for g, entry in RUBRIC["weights"]["SSL Labs grade"].items()
                  if g not in ("no_tls_at_all",)}
# The "possible" weight is the same across every grade entry in the rubric
# (we just want one number for the /N denominator). Pull it once at module
# load so the displayed denominator follows the rubric automatically and
# never goes stale when a weight is changed in scoring_rubric.json.
_SSL_GRADE_POSSIBLE = next(
    iter(RUBRIC["weights"]["SSL Labs grade"].values())
)["possible"]

_SCORE_GREEN = RUBRIC["thresholds"]["score_color_green_pct"]
_SCORE_YELLOW = RUBRIC["thresholds"]["score_color_yellow_pct"]

# ── Categories ────────────────────────────────────────────────────────────────
# The rubric defines six top-level categories used in both the detailed
# sections and the summary. Build a reverse lookup score_label -> category
# so we can prepend a category prefix to each finding/passing line in the
# summary section.

_CATEGORIES = RUBRIC.get("categories", {})
_CATEGORY_ORDER = ["Email", "DNS", "Routing", "TLS", "HTTP", "Website"]
_LABEL_TO_CATEGORY = {}
for _cat, _labels in _CATEGORIES.items():
    for _lbl in _labels:
        _LABEL_TO_CATEGORY[_lbl] = _cat


def _category_for_score_label(score_label):
    """Map a rubric score label (e.g. 'SPF policy') to its top-level category.
    Returns 'Website' as the catch-all if the label is not registered in the
    rubric's `categories` map - that way new checks that haven't been wired
    into the categories yet still appear in the summary instead of being lost.
    """
    if not score_label:
        return "Website"
    return _LABEL_TO_CATEGORY.get(score_label, "Website")


def _category_for_finding_label(finding_label):
    """Map a free-form finding label (the human-readable description we
    appended to the findings list) to a category. Used for findings that
    weren't paired with an explicit score_label - mostly DNS errors and
    informational notes. Falls back to keyword sniffing.
    """
    if not finding_label:
        return "Website"
    l = finding_label.lower()
    # Strip a trailing '(domain)' annotation if present
    if l.endswith(")") and " (" in l:
        l = l[:l.rfind(" (")]
    if (l.startswith("spf") or l.startswith("dmarc") or l.startswith("mx") or
            l.startswith("pct=") or l.startswith("sp=") or
            l.startswith("mta-sts") or l.startswith("tls-rpt") or
            l.startswith("dane") or l.startswith("dkim")):
        return "Email"
    if (l.startswith("dnssec") or l.startswith("caa") or
            l.startswith("certification authority authorization") or
            l.startswith("security reporting contact") or
            l.startswith("nameserver")):
        return "DNS"
    if (l.startswith("rpki") or l.startswith("ip routing") or
            l.startswith("ipv6") or l.startswith("ipv4")):
        return "Routing"
    if (l.startswith("tls") or l.startswith("certificate") or
            l.startswith("hsts") or l.startswith("ssl labs")):
        return "TLS"
    if l.startswith("http") or l.startswith("redirect"):
        return "HTTP"
    return "Website"


# ── Findings helpers ──────────────────────────────────────────────────────────
# Findings are collected during render() and reported in the summary section.
# Each finding carries an explicit score_label (or None) so the score
# annotation in the summary doesn't depend on fragile keyword matching of
# the user-facing message text. This is the v2 fix for the brittle
# _finding_score_label keyword map in v1.

def ok(msg, label=None):
    return f"  {c(GREEN,  '✔')} {msg}"


def info(msg):
    return f"  {c(CYAN,   'ℹ')} {msg}"


def _make_warn_bad_err(findings):
    """Return warn/bad/err helpers that append into the given findings list.

    Each helper accepts an optional `label` (display text) and `score_label`
    (the matching key in the scoring rubric, used for score annotation in
    the summary). The score_label is plumbed explicitly rather than reverse-
    engineered from the message text.
    """
    def warn(msg, label=None, score_label=None):
        if label:
            findings.append(("warn", label, score_label))
        return f"  {c(YELLOW, '⚠')} {msg}"

    def bad(msg, label=None, score_label=None):
        if label:
            findings.append(("bad", label, score_label))
        return f"  {c(RED,    '✘')} {msg}"

    def err(msg, label=None, score_label=None):
        if label:
            findings.append(("err", label, score_label))
        return f"  {c(GREY,   '?')} {msg}"

    return warn, bad, err


def _finding_category(label, score_label=None):
    """Map a finding to a top-level category for the summary.

    Prefers the score_label-driven mapping (rubric-defined categories),
    falling back to keyword sniffing on the human-readable finding label
    when no score label is attached (DNS errors, info-only notes, etc.).
    """
    if score_label:
        return _category_for_score_label(score_label)
    return _category_for_finding_label(label)


# ── Email section (used for source domain and redirect target) ────────────────

def _render_email_section(domain_label, spf, dmarc, mx, warn, bad, err, ok):
    """Render SPF, DMARC, and MX for one domain."""
    # Wrap warn/bad/err so every finding label is prefixed with the domain name.
    _warn, _bad, _err = warn, bad, err

    def warn(msg, label=None, score_label=None):
        return _warn(msg,
                     f"{label} ({domain_label})" if label else None,
                     score_label)

    def bad(msg, label=None, score_label=None):
        return _bad(msg,
                    f"{label} ({domain_label})" if label else None,
                    score_label)

    def err(msg, label=None, score_label=None):
        return _err(msg,
                    f"{label} ({domain_label})" if label else None,
                    score_label)

    # ── SPF ──────────────────────────────────────────────────────────────────
    print(c(BOLD, f"SPF  {c(GREY, f'({domain_label})')}"))
    has_mx = bool(mx.get("entries")) and not mx.get("null_mx")
    s = spf.get("status", "missing")
    rec = c(GREY, f"  ({spf['record']})") if spf.get("record") else ""
    if s == "error":
        print(err(f"DNS query failed: {spf['error']}", "SPF — DNS error"))
    elif s == "null_sender":
        print(ok(f"Null sender (v=spf1 -all) — domain explicitly declares it sends no mail{rec}"))
    elif s == "hardfail":
        print(ok(f"Hard fail (-all){rec}"))
    elif s == "softfail":
        print(warn(f"Soft fail (~all){rec}", "SPF — soft fail (~all)", "SPF policy"))
    elif s == "pass_all_DANGEROUS":
        print(bad("+all — anyone on the internet can spoof this domain!",
                  "SPF — +all (dangerous)", "SPF policy"))
    elif s == "neutral":
        print(warn(f"Neutral (?all){rec}", "SPF — neutral (?all)", "SPF policy"))
    elif s == "no_all_mechanism":
        print(warn(f"SPF record present but missing 'all' mechanism{rec}",
                   "SPF — missing enforcement mechanism", "SPF policy"))
    elif s == "redirect_no_all":
        print(warn(f"SPF via redirect — no explicit 'all' mechanism in target{rec}",
                   "SPF — redirect target missing enforcement", "SPF policy"))
    elif s == "redirect_target_no_spf":
        print(bad("SPF redirect target has no SPF record",
                  "SPF — broken redirect", "SPF redirect"))
    else:
        if has_mx:
            print(bad("No SPF record — domain receives mail (MX present) but has no sending policy; spoofing trivially easy",
                      "SPF — missing with MX present (critical)", "SPF policy"))
        else:
            print(f"  {c(GREY, '–')} No SPF record — no MX present, not scored")

    if spf.get("redirect_target"):
        rr = c(GREY, f"  ({spf['redirect_record']})") if spf.get("redirect_record") else ""
        print(f"  {c(GREY,'→')} Redirected to: {c(GREY, spf['redirect_target'])}{rr}")

    lc = spf.get("lookup_count")
    if lc is not None and s != "null_sender":
        if lc > RUBRIC["thresholds"]["spf_lookup_limit"]:
            print(bad(f"SPF lookup count: {lc} — exceeds 10-lookup limit (silent failures likely)",
                      "SPF — lookup limit exceeded", "SPF lookup count"))
        elif lc >= 9:
            print(info(f"SPF lookup count: {lc} — approaching 10-lookup limit"))
        else:
            print(ok(f"SPF lookup count: {lc}"))

    # ── DMARC ────────────────────────────────────────────────────────────────
    print(c(BOLD, f"\nDMARC  {c(GREY, f'({domain_label})')}"))
    inherited = dmarc.get("inherited_from")
    org       = _org_domain(domain_label) or domain_label
    is_sub    = org != domain_label
    if dmarc.get("error"):
        print(err(f"DNS query failed: {dmarc['error']}", "DMARC — DNS error"))
    elif not dmarc.get("present"):
        if is_sub:
            # Finding points at the org domain — that's where DMARC must be published.
            # Call _bad directly (bypass the wrapper) so the summary shows the
            # org domain rather than the subdomain being audited.
            print(_bad(f"No DMARC record on {domain_label} or {org}",
                       f"DMARC — missing ({org})", "DMARC present"))
        else:
            print(bad("No DMARC record", "DMARC — missing", "DMARC present"))
    else:
        if inherited:
            print(info(f"No DMARC on {domain_label} — inherits from {c(GREY, inherited)}"))
        pol = dmarc["policy"]
        if pol == "reject":
            print(ok(f"Policy: {c(GREEN, 'reject')}"))
        elif pol == "quarantine":
            print(warn(f"Policy: {c(YELLOW, 'quarantine')}",
                       "DMARC — policy: quarantine", "DMARC policy"))
        else:
            print(bad(f"Policy: {c(RED, 'none')} — monitoring only, no enforcement",
                      "DMARC — policy: none", "DMARC policy"))

        if pol in ("reject", "quarantine"):
            pct = dmarc.get("pct")
            if pct is not None and pct < 100:
                print(bad(f"pct={pct} — policy only applies to {pct}% of mail; full enforcement requires pct=100",
                          f"DMARC — pct={pct} (partial enforcement)", "DMARC pct"))
            elif pct == 100 or pct is None:
                print(ok("pct=100 — policy applies to all mail"))
            sp = dmarc.get("sp")
            if sp == "none":
                print(bad("sp=none — subdomain policy explicitly set to none; subdomains are unprotected "
                          "even if apex domain has reject/quarantine",
                          "DMARC — sp=none (subdomains unprotected)", "DMARC sp"))
            elif sp in ("reject", "quarantine"):
                print(ok(f"sp={sp} — subdomain policy explicitly enforced"))

        # ── rua= aggregate reporting destination (RFC 7489 §6.2) ─────────────
        # Without rua, the operator has no visibility into spoofing attempts
        # or legitimate mail being rejected. Score regardless of policy.
        rua = dmarc.get("rua") or []
        if rua:
            if len(rua) == 1:
                print(ok(f"rua={c(GREY, rua[0])} — aggregate reports collected"))
            else:
                print(ok(f"rua= aggregate reports collected at {len(rua)} destinations"))
                for dest in rua:
                    print(f"      {c(GREY, '·')} {c(GREY, dest)}")
        else:
            print(warn(
                "No rua= tag — no aggregate reporting destination set; "
                "operator cannot see spoofing attempts or legit-mail rejections",
                "DMARC — no rua= reporting destination",
                "DMARC rua reporting"))

    # ── MX ───────────────────────────────────────────────────────────────────
    print(c(BOLD, f"\nMX Records  {c(GREY, f'({domain_label})')}"))
    if mx.get("error"):
        print(err(f"DNS query failed: {mx['error']}", "MX — DNS error"))
    elif mx.get("null_mx"):
        print(ok("Null MX (RFC 7505) — domain explicitly does not send or receive mail"))
    elif not mx.get("entries"):
        print(f"  {c(GREY, '–')} No MX records — domain does not receive email")
    for entry in mx.get("entries", []):
        pri = f"{entry['priority']:>4}"
        print(f"  {c(GREEN,'✔')} {c(GREY, pri)}  {entry['host']}")


def _render_mail_transport(domain_label, results, warn, bad, err, ok, prefix=""):
    """Render MTA-STS / TLS-RPT / DANE / DKIM. Only meaningful when MX present.

    `prefix` is used to namespace the result keys for the redirect-target case.
    For example: prefix='redirect_target_' uses results['redirect_target_mta_sts']
    instead of results['mta_sts'].

    For domains without MX (or with a null MX per RFC 7505), we skip this
    section entirely — these checks are about inbound mail transport
    hardening, which is irrelevant when the domain doesn't receive mail.
    """
    mx = results.get(f"{prefix}mx", {}) or {}
    has_mx = bool(mx.get("entries")) and not mx.get("null_mx")
    if not has_mx:
        # Domain doesn't receive mail; mail transport hardening N/A.
        return

    mta_sts        = results.get(f"{prefix}mta_sts", {}) or {}
    mta_sts_policy = results.get(f"{prefix}mta_sts_policy", {}) or {}
    tls_rpt        = results.get(f"{prefix}tls_rpt", {}) or {}
    dane           = results.get(f"{prefix}dane", {}) or {}
    dkim           = results.get(f"{prefix}dkim", {}) or {}

    # Don't print the section header at all if every check is empty
    nothing = (not mta_sts and not tls_rpt and not dane and not dkim)
    if nothing:
        return

    _warn, _bad, _err = warn, bad, err

    def warn(msg, label=None, score_label=None):
        return _warn(msg,
                     f"{label} ({domain_label})" if label else None,
                     score_label)

    def bad(msg, label=None, score_label=None):
        return _bad(msg,
                    f"{label} ({domain_label})" if label else None,
                    score_label)

    def err(msg, label=None, score_label=None):
        return _err(msg,
                    f"{label} ({domain_label})" if label else None,
                    score_label)

    print(c(BOLD, f"\nMail Transport Hardening  {c(GREY, f'({domain_label})')}"))

    # ── MTA-STS ──────────────────────────────────────────────────────────────
    if mta_sts:
        if mta_sts.get("error"):
            print(err(f"MTA-STS DNS lookup failed: {mta_sts['error']}",
                      "MTA-STS — DNS error"))
        elif mta_sts.get("present"):
            id_str = c(GREY, f"  (id={mta_sts.get('id')})") if mta_sts.get("id") else ""
            mode = mta_sts_policy.get("mode") if mta_sts_policy.get("fetched") else None
            if mode == "enforce":
                print(ok(f"MTA-STS published — mode=enforce{id_str}"))
            elif mode == "testing":
                print(warn(f"MTA-STS in testing mode — failures are reported but not enforced{id_str}",
                           "MTA-STS — testing mode (not enforced)", "MTA-STS"))
            elif mode == "none":
                print(warn(f"MTA-STS mode=none — explicit opt-out{id_str}",
                           "MTA-STS — mode=none (opt-out)", "MTA-STS"))
            elif mta_sts_policy.get("fetched") is False:
                print(warn(f"MTA-STS DNS record present but policy file missing or unreachable{id_str}",
                           "MTA-STS — policy file unreachable", "MTA-STS"))
            else:
                # Policy fetch did not run or returned no mode (rare; the
                # default flow always tries to fetch). Show a neutral OK
                # since we did at least confirm the DNS record exists.
                print(ok(f"MTA-STS DNS record published{id_str}"))
        else:
            print(warn("No MTA-STS — receiving servers may accept downgrades to plaintext",
                       "MTA-STS — missing", "MTA-STS"))

    # ── TLS-RPT ──────────────────────────────────────────────────────────────
    if tls_rpt:
        if tls_rpt.get("error"):
            print(err(f"TLS-RPT DNS lookup failed: {tls_rpt['error']}",
                      "TLS-RPT — DNS error"))
        elif tls_rpt.get("present"):
            rua = tls_rpt.get("rua") or ""
            print(ok(f"TLS-RPT reporting enabled  {c(GREY, rua) if rua else ''}"))
        else:
            print(warn("No TLS-RPT — no failure reporting for inbound mail TLS",
                       "TLS-RPT — missing", "TLS-RPT"))

    # ── DANE ─────────────────────────────────────────────────────────────────
    if dane and dane.get("mx_count", 0) > 0:
        with_t = dane.get("with_tlsa", []) or []
        without_t = dane.get("without_tlsa", []) or []
        total = dane["mx_count"]
        if len(with_t) == total:
            print(ok(f"DANE/TLSA published on all {total} MX host{'s' if total != 1 else ''}"))
        elif with_t:
            print(warn(f"DANE/TLSA on {len(with_t)}/{total} MX hosts — incomplete",
                       "DANE/TLSA — partial coverage on MX", "DANE TLSA on MX"))
            for h in with_t:
                print(f"    {c(GREEN,'✔')} {c(GREY, h)}")
            for h in without_t:
                print(f"    {c(RED,  '✘')} {c(GREY, h)}")
        else:
            print(warn(f"No DANE/TLSA on any MX host — STARTTLS downgrade not detected",
                       "DANE/TLSA — missing on MX", "DANE TLSA on MX"))

    # ── DKIM (common selectors only — partial check) ─────────────────────────
    if dkim and dkim.get("checked"):
        found = dkim.get("found", [])
        checked = dkim.get("checked", [])
        # Always emit the partial-check caveat so users don't read absence as
        # proof. DKIM selectors are operator-chosen and arbitrary.
        if found:
            sels = ", ".join(found)
            print(ok(f"DKIM key found at common selector(s): {c(GREEN, sels)}  "
                     f"{c(GREY, '(checked: ' + ', '.join(checked) + ')')}"))
        else:
            # Headline first, then the partial-check explanation on its own
            # indented lines for readability. The summary scores this as 0/0
            # (rubric: not_found has possible=0) because absence proves
            # nothing - DKIM selectors are arbitrary operator-chosen names.
            print(warn(
                f"No DKIM at common selectors ({', '.join(checked)})",
                "DKIM — not found at common selectors (partial check)",
                "DKIM (common selectors)"))
            print(f"      {c(GREY, 'PARTIAL CHECK ONLY — DKIM uses arbitrary selector names.')}")
            print(f"      {c(GREY, 'Absence at the common names proves nothing.')}")
            print(f"      {c(GREY, 'Use the rua= reports from your DMARC to discover')}")
            print(f"      {c(GREY, 'the actual selectors in use.')}")


# ── DNS hygiene (CAA + NS/SOA) ───────────────────────────────────────────────

def _render_dns_hygiene(results, warn, bad, err, ok):
    caa    = results.get("caa", {}) or {}
    ns_soa = results.get("ns_soa", {}) or {}

    if not caa and not ns_soa:
        return

    print(c(BOLD, "\nDNS Hygiene"))

    # ── Nameserver count ────────────────────────────────────────────────────
    if ns_soa:
        if ns_soa.get("ns_error"):
            print(err(f"NS lookup failed: {ns_soa['ns_error']}",
                      "Nameserver count — DNS error"))
        else:
            ns = ns_soa.get("nameservers", [])
            ns_count = ns_soa.get("ns_count", 0)
            # Detailed section: never truncate. Show count on the headline,
            # then list every nameserver on its own indented line so even a
            # domain with 8+ nameservers stays readable.
            if ns_count >= 2:
                print(ok(f"Nameservers: {ns_count}"))
            elif ns_count == 1:
                print(bad(f"Single nameserver — RFC 1034 recommends ≥2 for redundancy",
                          "Nameservers — only one", "Nameserver count"))
            else:
                print(err("No nameservers found", "Nameservers — none", "Nameserver count"))
            for ns_host in ns:
                print(f"      {c(GREY, '·')} {c(GREY, ns_host)}")

        soa = ns_soa.get("soa")
        if soa:
            serial_str = f"{soa['serial']:>10}"
            print(f"  {c(GREY, '·')} SOA primary: {c(GREY, soa['primary'])}, serial {c(GREY, serial_str)}")

    # ── CAA records ─────────────────────────────────────────────────────────
    if caa:
        if caa.get("error"):
            print(err(f"Certification Authority Authorization lookup failed: {caa['error']}",
                      "Certification Authority Authorization — DNS error"))
        elif caa.get("present"):
            inh = c(GREY, f"  (inherited from {caa['inherited_from']})") if caa.get("inherited_from") else ""
            issuers = caa.get("issue", [])
            if not issuers or issuers == [";"]:
                print(ok(f"Certification Authority Authorization records published — issuance disallowed by default{inh}"))
            else:
                # Show the full authorised-CA list. With ≤3 entries we keep
                # them inline; otherwise we move them to indented bullets so
                # the headline stays scannable.
                if len(issuers) <= 3:
                    preview = ", ".join(issuers)
                    print(ok(f"Certification Authority Authorization records published — authorised CAs: {c(GREY, preview)}{inh}"))
                else:
                    print(ok(f"Certification Authority Authorization records published — {len(issuers)} authorised CAs{inh}"))
                    for ca in issuers:
                        print(f"      {c(GREY, '·')} {c(GREY, ca)}")
            if caa.get("iodef"):
                print(ok(f"Security reporting contact (iodef) set"))
            else:
                print(warn(
                    "Certification Authority Authorization records published but no security reporting contact (iodef) "
                    "— CAs cannot notify you of policy violations",
                    "Security reporting contact (iodef) — not set", "CAA records"))
        else:
            print(warn("No Certification Authority Authorization records — any public CA can issue certificates for this domain",
                       "Certification Authority Authorization — missing", "CAA records"))


# ── OS inference (used by both terminal render and CSV) ───────────────────────

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
    findings = []   # list of (level, label, score_label) — local, thread-safe
    warn, bad, err = _make_warn_bad_err(findings)

    redirect = r.get("redirect", {})
    redirected = redirect.get("redirected", False)

    print(f"\n{c(BOLD+CYAN, '━'*56)}")
    print(f"{c(BOLD+CYAN, f'  Security Health Check — {original_domain}')}")
    if redirected:
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

    # ── Email checks — source domain (always) ────────────────────────────────
    _render_email_section(
        original_domain,
        r["spf"], r["dmarc"], r["mx"],
        warn, bad, err, ok,
    )

    # ── Mail transport hardening (MTA-STS / TLS-RPT / DANE / DKIM) ───────────
    _render_mail_transport(original_domain, r, warn, bad, err, ok)

    # ── Email checks — redirect target (when redirected) ──────────────────────
    if redirected:
        print(f"\n{c(BOLD+CYAN, '─'*56)}")
        print(c(BOLD+CYAN, f"  Redirect Target Email — {audit_domain}"))
        print(f"{c(BOLD+CYAN, '─'*56)}")
        _render_email_section(
            audit_domain,
            r.get("redirect_target_spf",   {}),
            r.get("redirect_target_dmarc", {}),
            r.get("redirect_target_mx",    {}),
            warn, bad, err, ok,
        )
        _render_mail_transport(
            audit_domain, r, warn, bad, err, ok,
            prefix="redirect_target_",
        )

    # ── DNS hygiene (CAA + NS/SOA) ───────────────────────────────────────────
    _render_dns_hygiene(r, warn, bad, err, ok)

    # ── IP / ASN / RPKI ──────────────────────────────────────────────────────
    ipr = r["ip_routing"]
    print(c(BOLD, "\nIP / ASN / RPKI"))

    def _render_addr(af_label, af):
        addr     = af.get("address")
        af_err   = af.get("error")
        prefix   = af.get("prefix")
        asn      = af.get("asn")
        asn_name = af.get("asn_name", "")
        rpki     = af.get("rpki_status")

        if not addr and af_err:
            if af_label == "IPv4":
                print(err(f"{af_label} — {af_err}", f"IP routing — {af_label} failed"))
            else:
                if "no AAAA" in af_err:
                    print(warn(f"{af_label} — {af_err}", "IPv6 — not configured", "IPv6"))
                else:
                    print(err(f"{af_label} — {af_err}", f"IP routing — {af_label} failed"))
            return

        asn_str  = f"AS{asn}" if asn is not None else "ASN unknown"
        name_str = c(GREY, asn_name) if asn_name else ""
        pfx_str  = c(GREY, prefix)   if prefix   else ""

        all_addrs = af.get("all_addresses")
        # Detailed section: never truncate. With many addresses, show the
        # first on the headline (so the routing/RPKI summary stays readable)
        # and list every address on its own indented line below.
        if all_addrs and len(all_addrs) > 1:
            if len(all_addrs) <= 3:
                addr_display = ", ".join(all_addrs)
                extra_addrs = []
            else:
                addr_display = f"{all_addrs[0]}  (+{len(all_addrs)-1} more)"
                extra_addrs = all_addrs[1:]
        else:
            addr_display = addr
            extra_addrs = []

        print(ok(f"{af_label}  {c(CYAN, addr_display)}  →  {c(CYAN, asn_str)}  {name_str}"))
        for extra in extra_addrs:
            print(f"      {c(GREY, '·')} {c(CYAN, extra)}")
        if pfx_str:
            print(f"  {c(GREY,'·')} Prefix: {pfx_str}")

        if af_err and not rpki:
            print(err(f"Routing lookup failed: {af_err}", f"IP routing — {af_label} error"))
            return

        if rpki == "valid":
            print(ok(f"RPKI {c(GREEN, 'valid')}"))
        elif rpki == "invalid":
            print(bad(f"RPKI {c(RED, 'invalid')}  — ROA exists but origin AS mismatch (possible route hijack)",
                      f"RPKI {af_label} — invalid", f"{af_label} RPKI"))
        elif rpki == "not-found":
            print(warn(f"RPKI not-found  — no route origin authorization published for this prefix",
                       f"RPKI {af_label} — no route origin authorization", f"{af_label} RPKI"))
        elif rpki == "error":
            print(err(f"RPKI check failed{': ' + af_err if af_err else ''}",
                      f"RPKI {af_label} — check error"))

        if af.get("irr_in_ris"):
            print(ok(f"IRR  — prefix seen in RIS routing table"))
        elif prefix:
            print(f"  {c(GREY,'·')} IRR  — prefix not seen in RIS snapshot (may be filtered or new)")

    _render_addr("IPv4", ipr["v4"])

    v6_addr = ipr["v6"].get("address")
    v6_err  = ipr["v6"].get("error", "")
    if v6_addr or v6_err:
        print()
    _render_addr("IPv6", ipr["v6"])

    dnssec = r["dnssec"]
    tld_d  = dnssec["tld"]
    dom_d  = dnssec["domain"]
    print(c(BOLD, "\nDNSSEC"))

    tld_label = tld_d["tld"].upper() if tld_d["tld"] else "TLD"
    if tld_d.get("error"):
        print(err(f".{tld_label} — DNS query failed: {tld_d['error']}",
                  f"DNSSEC — .{tld_label} query error"))
    elif tld_d["signed"]:
        print(ok(f".{tld_label} is signed — DNSSEC chain possible"))
    else:
        print(warn(f".{tld_label} does not appear to be signed — DNSSEC chain cannot be established",
                   f"DNSSEC — .{tld_label} unsigned", "DNSSEC TLD signed"))

    if dom_d.get("error"):
        print(err(f"Domain — DNS query failed: {dom_d['error']}", "DNSSEC — domain query error"))
    elif dom_d["dnskey"] and dom_d["ad_flag"]:
        print(ok("Domain enabled and validated (DNSKEY present, AD flag confirmed)"))
    elif dom_d["dnskey"]:
        print(warn("Domain DNSKEY found but AD flag not set (chain may be incomplete)",
                   "DNSSEC — AD flag not set", "DNSSEC AD flag"))
    else:
        print(warn("Domain DNSSEC not detected", "DNSSEC — not enabled", "DNSSEC DNSKEY"))
        print(warn("DNSSEC chain not validated (AD flag not set)",
                   "DNSSEC — AD flag not set", "DNSSEC AD flag"))

    # ── TLS ──────────────────────────────────────────────────────────────────
    tls = r["tls"]
    print(c(BOLD, "\nTLS"))
    if tls.get("error"):
        print(bad(f"Could not connect on port 443: {tls['error']}",
                  "TLS — connection failed", "TLS connection"))
    else:
        ver = tls.get("version", "unknown")
        if ver == "TLSv1.3":
            print(ok(f"Negotiated: {c(GREEN, ver)}"))
            print(ok("TLS 1.3"))
        elif ver == "TLSv1.2":
            print(f"  {c(GREY, '–')} Negotiated: {c(YELLOW, ver)}")
            print(warn("TLS 1.3 not supported", "TLS 1.3 — not negotiated", "TLS 1.3"))
        else:
            print(bad(f"Negotiated: {c(RED, ver)} — upgrade required",
                      f"TLS — {ver} negotiated", "TLS 1.3"))
            print(bad("TLS 1.3 not supported", "TLS 1.3 — not negotiated", "TLS 1.3"))

        # ── Certificate name match ───────────────────────────────────────────
        names_match = tls.get("cert_names_match")
        san_names   = tls.get("cert_san_names", [])
        if names_match is True:
            covering = [n for n in san_names
                        if n == audit_domain.lower()
                        or (n.startswith("*.") and audit_domain.lower().endswith("." + n[2:]))]
            cover_str = c(GREY, f"  ({', '.join(covering)})") if covering else ""
            print(ok(f"Certificate name matches domain{cover_str}"))
        elif names_match is False:
            # Detailed section: never truncate the SAN list. With ≤5 names
            # we keep them inline; otherwise we put the count on the headline
            # and list every name indented underneath.
            if len(san_names) <= 5:
                names_str = c(GREY, f"  (cert covers: {', '.join(san_names)})")
                print(bad(f"Certificate name mismatch — cert does not cover {audit_domain}{names_str}",
                          "TLS — certificate does not cover this domain", "Certificate name match"))
            else:
                print(bad(f"Certificate name mismatch — cert does not cover {audit_domain}  "
                          f"{c(GREY, f'(cert covers {len(san_names)} names)')}",
                          "TLS — certificate does not cover this domain", "Certificate name match"))
                for n in san_names:
                    print(f"      {c(GREY, '·')} {c(GREY, n)}")

        # ── Certificate lifetime ──────────────────────────────────────────────
        lifetime = tls.get("cert_lifetime_days")
        issued   = tls.get("cert_issued",  "")
        expires  = tls.get("cert_expires", "")
        issuer   = tls.get("cert_issuer",  "")
        if lifetime is not None:
            date_str = c(GREY, f"  ({issued} → {expires})")
            if lifetime <= RUBRIC["thresholds"]["cert_lifetime_max_days"]:
                print(ok(f"Certificate lifetime: {lifetime} days {date_str}  ← automated issuance likely"))
            else:
                print(warn(f"Certificate lifetime: {lifetime} days {date_str}  ← indicates manual certificate management",
                           f"TLS — manual certificate management likely ({lifetime} days)", "Certificate lifetime"))
            if issuer:
                print(f"  {c(GREY,'·')} Issuer: {c(GREY, issuer)}")

        # ── Cert covers redirect-target variant ──────────────────────────────
        # When the user types example.com but the site redirects to
        # www.example.com, both names need cert coverage so the first hop
        # doesn't fail TLS verification in the browser.
        cert_var = r.get("cert_variant", {})
        cv_outcome = cert_var.get("outcome")
        if cv_outcome == "covers":
            print(ok("Certificate also covers the redirect source/target variant"))
        elif cv_outcome == "missing_variant":
            missing = cert_var.get("missing", [])
            print(warn(
                f"Certificate missing coverage for: {', '.join(missing)} "
                f"— users typing the uncovered name see a TLS error before the redirect",
                f"TLS — cert missing variant ({', '.join(missing)})",
                "Cert covers www variant",
            ))

    # ── HTTP ─────────────────────────────────────────────────────────────────
    http_redir  = r.get("http_redirect", {})
    hv          = r.get("http_version", {})
    hv_ver      = hv.get("version")
    http3       = r.get("server_header", {}).get("http3_advertised")
    alt_svc_val = r.get("server_header", {}).get("alt_svc")
    print(c(BOLD, "\nHTTP"))

    # ── Response time (free ping estimate from the redirect GET) ─────────────
    # We have one HTTPS GET wall-clock measurement from check_redirect. Display
    # it as a single value since we don't have multiple data points; a future
    # version could fire two GETs and report a min/max range.
    elapsed = redirect.get("elapsed_ms")
    if elapsed is not None:
        slow_ms = RUBRIC["thresholds"].get("response_slow_ms", 1000)
        fast_ms = RUBRIC["thresholds"].get("response_fast_ms", 200)
        if elapsed <= fast_ms:
            ec = GREEN
        elif elapsed <= slow_ms:
            ec = YELLOW
        else:
            ec = RED
        # Note: this includes DNS + TLS handshake + TCP, since we time the full
        # GET. Browsers caching DNS / reusing connections will see less.
        print(f"  {c(GREY, '·')} Response time: {c(ec, f'{elapsed:.0f} ms')}  "
              f"{c(GREY, '(includes DNS + TCP + TLS, not a pure HTTP RTT)')}")

    # ── First-hop hygiene (Mozilla Observatory rule) ─────────────────────────
    if redirect.get("redirected"):
        if redirect.get("first_hop_https") and redirect.get("first_hop_same_host"):
            print(ok("First redirect hop is HTTPS on the same host"))
        elif redirect.get("first_hop_url"):
            first_hop = redirect.get("first_hop_url")
            if not redirect.get("first_hop_https"):
                print(warn(
                    f"First redirect hop is plain HTTP ({first_hop}) — bypasses HSTS",
                    "Redirect — first hop is HTTP",
                    "Redirect first-hop hygiene",
                ))
            else:
                print(warn(
                    f"First redirect hop is off-host ({first_hop}) — leaks Referer and prevents HSTS for the apex",
                    "Redirect — first hop is off-host",
                    "Redirect first-hop hygiene",
                ))

    # HTTP version (single scoring row, three tiers — see audit_checks
    # score_results for the rubric mapping). Inline rendering follows
    # the same tiering: HTTP/3 → ok line (no finding emitted; passing
    # row comes from the breakdown); HTTP/2-only → warn line tied to
    # the 'HTTP version' rubric label so the partial 1/2 annotation
    # flows into the summary; HTTP/1.1 → bad line at the same label.
    if http3:
        print(ok(f"HTTP/3 advertised  {c(GREY, f'(Alt-Svc: {alt_svc_val})')}"))
    elif hv_ver == "HTTP/2":
        print(warn("HTTP/2 supported, HTTP/3 not advertised",
                   "HTTP/3 not supported (HTTP/2 only)", "HTTP version"))
    elif hv_ver == "HTTP/1.1":
        print(bad("HTTP/1.1 detected — server does not support HTTP/2 or HTTP/3 (https://http1mustdie.com)",
                  "HTTP/1.1 detected (https://http1mustdie.com)", "HTTP version"))
    elif hv.get("error"):
        print(err(f"HTTP version check failed: {hv['error']}", "HTTP — version check error"))

    hr_status = http_redir.get("status")
    hr_detail = c(GREY, f"  ({http_redir.get('detail', '')})")
    if hr_status == "https_only":
        print(ok(f"http:// redirects to HTTPS{hr_detail}"))
    elif hr_status == "http_available":
        print(bad(
            f"Page is accessible over plain HTTP{hr_detail}",
            "HTTP — plain HTTP accessible (no HTTPS redirect)",
            "HTTP→HTTPS redirect",
        ))
        print(c(GREY, f"  verify with: curl -v http://{audit_domain}"))
        print(c(GREY, f"           or: iwr http://{audit_domain}"))
    elif hr_status == "http_error":
        sc = http_redir.get("status_code", "")
        hsts_preloaded = r.get("hsts", {}).get("preloaded")
        preload_note = (
            c(GREY, "  (browser behaviour may differ — domain is HSTS preloaded)")
            if hsts_preloaded else
            c(GREY, "  (browser behaviour may differ)")
        )
        print(warn(
            f"HTTP port 80 open but no HTTPS redirect (got {sc}){hr_detail}",
            "HTTP — port 80 open, no redirect",
            "HTTP→HTTPS redirect",
        ))
        print(preload_note)
        print(c(GREY, f"  verify with: curl -v http://{audit_domain}"))
        print(c(GREY, f"           or: iwr http://{audit_domain}"))
    elif hr_status == "unreachable":
        print(f"  {c(GREY, '–')} HTTP port 80 not reachable{hr_detail}")

    # ── HSTS ─────────────────────────────────────────────────────────────────
    hsts = r["hsts"]
    print(c(BOLD, "\nHSTS"))

    if hsts.get("error"):
        print(err(f"Could not fetch HTTPS response: {hsts['error']}", "HSTS — fetch error"))
    elif not hsts.get("present"):
        print(bad("Strict-Transport-Security header not set", "HSTS — missing", "HSTS present"))
    else:
        print(ok("Strict-Transport-Security header present"))

        # ── max-age strength (Mozilla Observatory: 6 months minimum) ─────────
        ma = hsts.get("max_age")
        min_age = RUBRIC["thresholds"].get("hsts_max_age_min_seconds", 15768000)
        if ma is None:
            print(warn("max-age missing — header has no expiry directive",
                       "HSTS — max-age missing", "HSTS max-age strength"))
        elif ma >= min_age:
            days = ma // 86400
            print(ok(f"max-age: {ma} ({days} days)"))
        else:
            days = ma // 86400
            min_days = min_age // 86400
            print(warn(f"max-age: {ma} ({days} days) — below the {min_days}-day minimum recommended by Mozilla",
                       f"HSTS — max-age too short ({days} days)", "HSTS max-age strength"))

        if hsts.get("includes_subdomains"):
            print(ok("includeSubDomains set"))
        else:
            print(warn("includeSubDomains not set",
                       "HSTS — includeSubDomains missing", "HSTS includeSubDomains"))

    if hsts.get("preload_error") and hsts.get("preloaded") is None:
        print(err(f"Preload list check failed: {hsts['preload_error']}",
                  "HSTS — preload check error"))
    elif hsts.get("preloaded"):
        print(ok("Domain is on the HSTS preload list"))
    elif hsts.get("present") and hsts.get("preload_directive"):
        print(warn("preload directive present but domain not yet in preload list",
                   "HSTS — preload pending", "HSTS preloaded"))
    elif hsts.get("present") and hsts.get("preloaded") is False:
        # Only report "not preloaded" when HSTS IS present — if it's missing
        # entirely, that finding already covers it; double-reporting is noise.
        print(warn("Not in HSTS preload list", "HSTS — not preloaded", "HSTS preloaded"))

    # ── Server header ─────────────────────────────────────────────────────────
    srv = r["server_header"]
    print(c(BOLD, "\nServer / Technology Disclosure"))
    val = None
    if srv.get("error"):
        print(f"  {c(GREY, '–')} Site unreachable — server and security headers cannot be evaluated")
        print(f"  {c(GREY, str(srv['error']))}")
    else:
        val  = srv.get("server")
        kind = classify_server(val)
        if kind == "absent":
            print(ok("Server header not present"))
        elif kind == "good_proxy":
            print(ok(f"Server: {c(GREEN, val)}  ← reverse proxy / CDN"))
        elif kind == "origin_with_version":
            print(bad(f"Server: {c(RED, val)}  ← origin server with version disclosed",
                      f"Server — version disclosed ({val})", "Server header"))
        elif kind == "origin_no_version":
            print(warn(f"Server: {c(YELLOW, val)}  ← origin server exposed (no version)",
                       f"Server — origin exposed ({val})", "Server header"))
        else:
            print(warn(f"Server: {c(YELLOW, val)}  ← server technology disclosed",
                       f"Server — technology disclosed ({val})", "Server header"))

        if srv.get("x_powered_by"):
            print(bad(f"X-Powered-By: {c(RED, srv['x_powered_by'])}  ← technology disclosed",
                      f"X-Powered-By — disclosed ({srv['x_powered_by']})", "X-Powered-By absent"))
        else:
            print(ok("X-Powered-By header not present"))

        # ── Server clock accuracy (RedBot-style) ────────────────────────────
        clock = r.get("clock", {})
        skew = clock.get("skew_seconds")
        if clock.get("outcome") == "in_sync":
            print(ok(f"Server clock in sync with UTC  {c(GREY, f'(skew: {skew:+.0f}s)')}"))
        elif clock.get("outcome") == "minor_skew":
            print(warn(f"Server clock skew: {skew:+.0f}s — small but noticeable",
                       f"Clock — minor skew ({skew:+.0f}s)", "Server clock accuracy"))
        elif clock.get("outcome") == "bad_skew":
            print(bad(
                f"Server clock skew: {skew:+.0f}s — large skew can break HSTS, OAuth, "
                f"and certificate validation",
                f"Clock — bad skew ({skew:+.0f}s)", "Server clock accuracy"))

    # ── OS detection (2.9.0; consolidated 2.9.1) ─────────────────────────────
    # Surfaces results from check_os_eol() inline, beneath the Server header
    # that revealed the OS. EOL findings emit warn() so they appear in the
    # summary with the right score_label (drives the 0/3 row in the
    # breakdown). Non-EOL findings render as info-only `→` lines that
    # don't enter the findings list. OS attribution lives here, adjacent
    # to the Server header that's its source of truth, rather than in a
    # separate standalone section.
    os_eol = r.get("os_eol") or {}
    os_findings = os_eol.get("os_findings") or []
    if os_eol.get("error"):
        print(f"  {c(GREY, '?')} OS detection error: {os_eol['error']}")
    for finding in os_findings:
        os_name    = finding.get("os", "?")
        ver        = finding.get("version") or ""
        # Internal "?" placeholder is used when a distro was named in a
        # parens annotation but no version number could be extracted.
        # Don't surface it to the user — the stack label should just
        # read "CentOS Linux", not "CentOS Linux ?".
        ver_display = "" if ver in ("", "?") else ver
        display    = _OS_DISPLAY_NAMES.get(os_name, os_name)
        stack_label = f"{display} {ver_display}".rstrip()
        underlying = finding.get("underlying_os")
        tls_note   = finding.get("tls_capability_note")
        eol_status = finding.get("eol_status")

        # Build the "via X" framing. For IIS findings, the lead-in is
        # "IIS 8.0 → Windows Server 2012". For distro findings (CentOS,
        # Ubuntu, etc.), there's no separate web-server stack to mention,
        # so we just lead with the OS name itself. The `via` framing is
        # what tells the reader "we figured this out from the IIS
        # version" — it's only appropriate when there IS a stack
        # distinguishable from the OS.
        if finding.get("source") == "server_header_iis":
            # "IIS 8.0 → <underlying or stack_label>"
            iis_ver  = ver
            os_text  = underlying or stack_label
            head_line = f"IIS {iis_ver} → {os_text}"
        else:
            # Distro detection from parens annotation. underlying_os is
            # generally None for distros (we don't carry a separate
            # "underlying" — the distro IS the OS), so we use the
            # display name. For unknown-version detections, stack_label
            # has no version suffix.
            head_line = stack_label

        if eol_status == "eol":
            # EOL → warn(), with the underlying-OS-led label so the
            # Findings summary line reads "EOL OS — Windows Server 2012"
            # rather than "EOL OS — Microsoft IIS 8.0".
            headline = underlying or stack_label
            date     = finding.get("eol_last_release", "")
            via_stack = bool(underlying and stack_label != underlying)
            # Inline parenthetical: just the EOL date. The "via X" part
            # is omitted inline because for IIS findings the visible line
            # already starts with "IIS 8.0 →" — adding ", via Microsoft
            # IIS 8.0" at the end would be redundant. The summary
            # findings list (which doesn't have the inline lead-in)
            # still gets "via X" via finding_label below.
            inline_paren_bits = []
            if date:
                inline_paren_bits.append(f"EOL {date}")
            inline_paren = (
                f"  {c(GREY, '(' + ', '.join(inline_paren_bits) + ')')}"
                if inline_paren_bits else ""
            )
            # Findings-summary label keeps the "via X" suffix because
            # the summary doesn't show the "IIS 8.0 →" lead-in.
            finding_label = f"EOL OS — {headline}"
            if via_stack:
                finding_label = f"{finding_label} (via {stack_label})"
            # score_label matches the breakdown key in score_results so
            # the 0/3 score annotation renders next to the finding.
            if not ver or ver == "?":
                score_label = f"EOL OS: {os_name}"
            else:
                score_label = f"EOL OS: {os_name} {ver}"
            # Use the IIS lead-in form for the visible line when the
            # finding came from server_header_iis, since "IIS 8.0 →
            # Windows Server 2012" reads more naturally inline than
            # just "Windows Server 2012". For distro detections the
            # head_line already IS the OS name.
            if finding.get("source") == "server_header_iis":
                visible = f"IIS {ver} → {c(RED, headline)}{inline_paren}"
            else:
                visible = f"{c(RED, headline)}{inline_paren}"
            print(warn(visible, finding_label, score_label))
        elif eol_status == "unknown":
            # Detected but we couldn't determine EOL status (no version,
            # or OS not in os_eol.json). Plain info line, no finding.
            hint = " (version not exposed in Server header)" if not ver else ""
            print(f"  {c(CYAN, '→')} {head_line}{c(GREY, hint)}")
        else:
            # 'ok' — known-supported / IIS 10.0 ambiguous case. Plain
            # info line, no finding. The underlying_os narrative still
            # surfaces because it's actionable (e.g. "could be Server
            # 2016/19/22/25" or "Server 2016 or 2019, no TLS 1.3").
            print(f"  {c(CYAN, '→')} {head_line}")
        # tls_capability_note (IIS 10.0 + TLS-version narrative) renders
        # as a continuation line under the headline. Always shown when
        # present, regardless of EOL status, since it's actionable
        # detail (e.g. "supported TLS 1.3 requires upgrading to Server
        # 2022 or later").
        if tls_note:
            print(f"      {c(GREY, '↳ ' + tls_note)}")

    # Legacy-TLS corroboration sits at the end of the inline OS block.
    # Info-only — by itself a TLS 1.0/1.1/SSLv3 negotiation doesn't
    # attribute a specific OS, so it doesn't enter the findings list, but
    # it does strengthen any EOL OS finding above it (which the reader
    # can see right above this line).
    if os_eol.get("tls_old_stack"):
        sigs = ", ".join(os_eol.get("tls_signals") or [])
        print(f"  {c(YELLOW, '⚠')} Legacy TLS still negotiated: {sigs}  "
              f"{c(GREY, '(corroborates old-stack hypothesis)')}")

    # ── Technology stack ──────────────────────────────────────────────────────
    stack = srv.get("stack", [])
    if not srv.get("error") and stack:
        print(c(BOLD, "\nTechnology Stack"))
        seen_stack = set()
        for item in stack:
            key = item.split(" ")[0].lower()
            if key not in seen_stack:
                seen_stack.add(key)
                print(f"  {c(GREY, '·')} {item}")

    # ── Versioned libraries (2.8.0) ──────────────────────────────────────────
    # Lists each detected client-side library with its version. EOL entries
    # render through warn() so they hit the findings summary; non-EOL entries
    # print as plain info lines (with their version, but no annotation).
    # Entirely omitted when nothing was detected. Driven by results.versioned_libs
    # (populated by check_versioned_libraries in audit_checks).
    vlibs = (r.get("versioned_libs") or {}).get("libraries") or []
    if vlibs:
        print(c(BOLD, "\nVersioned Libraries"))
        # Pretty-print library names (jquery-ui → jQuery UI, etc). Library
        # keys are kebab/lowercase by convention in the detection table; we
        # keep the case-corrected names purely for display. Libraries not
        # in this map render with their raw kebab-case key, which is fine
        # for less common entries.
        _LIB_DISPLAY_NAMES = {
            # Original 2.8.0 set
            "jquery":       "jQuery",
            "jquery-ui":    "jQuery UI",
            "bootstrap":    "Bootstrap",
            "font-awesome": "Font Awesome",
            "modernizr":    "Modernizr",
            "moment":       "Moment.js",
            "angular":      "Angular",
            "angularjs":    "AngularJS",
            "wordpress":    "WordPress",
            "drupal":       "Drupal",
            "joomla":       "Joomla",
            # 2.9.0 additions — focus on libraries with EOL data plus the
            # most common detect-only entries where the kebab form is
            # noticeably uglier than the conventional name.
            "vue":           "Vue.js",
            "vuetify":       "Vuetify",
            "react":         "React",
            "preact":        "Preact",
            "ember":         "Ember.js",
            "backbone":      "Backbone.js",
            "underscore":    "Underscore.js",
            "knockout":      "Knockout.js",
            "polymer":       "Polymer",
            "lit":           "Lit",
            "alpinejs":      "Alpine.js",
            "htmx":          "htmx",
            "mithril":       "Mithril",
            "aurelia":       "Aurelia",
            "marionette":    "Marionette.js",
            "canjs":         "CanJS",
            "mootools":      "MooTools",
            "prototype":     "Prototype.js",
            "scriptaculous": "script.aculo.us",
            "yui":           "YUI",
            "zepto":         "Zepto.js",
            "cash":          "Cash",
            "dojo":          "Dojo Toolkit",
            "ext":           "Sencha Ext JS",
            "jquery-mobile": "jQuery Mobile",
            "jquery-migrate":"jQuery Migrate",
            "swfobject":     "SWFObject",
            "bulma":         "Bulma",
            "foundation":    "Foundation",
            "materialize":   "Materialize CSS",
            "uikit":         "UIkit",
            "semantic-ui":   "Semantic UI",
            "fomantic-ui":   "Fomantic UI",
            "skeleton":      "Skeleton",
            "pure":          "Pure.css",
            "milligram":     "Milligram",
            "tailwindcss":   "Tailwind CSS",
            "ant-design":    "Ant Design",
            "element-ui":    "Element UI",
            "element-plus":  "Element Plus",
            "material-ui":   "Material UI (legacy)",
            "mui":           "MUI",
            "material-components-web": "Material Components Web",
            "primeng":       "PrimeNG",
            "primereact":    "PrimeReact",
            "primevue":      "PrimeVue",
            "primeui":       "PrimeUI",
            "onsenui":       "Onsen UI",
            "framework7":    "Framework7",
            "ionic":         "Ionic",
            "quasar":        "Quasar",
            "kendo-ui":      "Kendo UI",
            "devextreme":    "DevExtreme",
            "jqwidgets":     "jQWidgets",
            "wijmo":         "Wijmo",
            "syncfusion":    "Syncfusion",
            "chart.js":      "Chart.js",
            "d3":            "D3.js",
            "highcharts":    "Highcharts",
            "highstock":     "Highstock",
            "highmaps":      "Highmaps",
            "plotly.js":     "Plotly.js",
            "echarts":       "Apache ECharts",
            "c3":            "C3.js",
            "nvd3":          "NVD3",
            "chartist":      "Chartist",
            "vega":          "Vega",
            "vega-lite":     "Vega-Lite",
            "morris":        "Morris.js",
            "dygraphs":      "dygraphs",
            "amcharts":      "amCharts",
            "flot":          "Flot",
            "jqplot":        "jqPlot",
            "raphael":       "Raphael",
            "ckeditor":      "CKEditor",
            "tinymce":       "TinyMCE",
            "quill":         "Quill",
            "monaco-editor": "Monaco Editor",
            "ace":           "Ace Editor",
            "codemirror":    "CodeMirror",
            "summernote":    "Summernote",
            "froala":        "Froala Editor",
            "slick":         "Slick",
            "swiper":        "Swiper",
            "owl-carousel":  "Owl Carousel",
            "bxslider":      "bxSlider",
            "flexslider":    "FlexSlider",
            "lightbox2":     "Lightbox2",
            "magnific-popup":"Magnific Popup",
            "photoswipe":    "PhotoSwipe",
            "fancybox":      "Fancybox",
            "colorbox":      "Colorbox",
            "select2":       "Select2",
            "chosen":        "Chosen",
            "flatpickr":     "Flatpickr",
            "bootstrap-datepicker": "Bootstrap Datepicker",
            "pikaday":       "Pikaday",
            "daterangepicker":"Date Range Picker",
            "nouislider":    "noUiSlider",
            "ion-rangeslider":"Ion.RangeSlider",
            "inputmask":     "Inputmask",
            "cleave.js":     "Cleave.js",
            "parsley":       "Parsley.js",
            "jquery-validate":"jQuery Validate",
            "typeahead":     "typeahead.js",
            "gsap":          "GSAP",
            "velocity":      "Velocity.js",
            "anime.js":      "Anime.js",
            "wow":           "WOW.js",
            "aos":           "AOS",
            "three.js":      "Three.js",
            "lodash":        "Lodash",
            "ramda":         "Ramda",
            "date-fns":      "date-fns",
            "dayjs":         "Day.js",
            "luxon":         "Luxon",
            "moment-timezone":"moment-timezone",
            "crypto-js":     "CryptoJS",
            "lazyload":      "Vanilla LazyLoad",
            "imagesloaded":  "imagesLoaded",
            "masonry":       "Masonry",
            "isotope":       "Isotope",
            "dropzone":      "Dropzone.js",
            "plupload":      "Plupload",
            "fine-uploader": "Fine Uploader",
            "filepond":      "FilePond",
            "uppy":          "Uppy",
            "blueimp-fileupload": "Blueimp jQuery File Upload",
            "mustache":      "Mustache",
            "handlebars":    "Handlebars",
            "hogan":         "Hogan.js",
            "ejs":           "EJS",
            "nunjucks":      "Nunjucks",
            "dot":           "doT.js",
            "dustjs":        "Dust.js",
            "jsrender":      "JsRender",
            "i18next":       "i18next",
            "globalize":     "Globalize",
            "leaflet":       "Leaflet",
            "openlayers":    "OpenLayers",
            "mapbox-gl":     "Mapbox GL JS",
            "cesium":        "CesiumJS",
            "arcgis":        "Esri ArcGIS API",
            "google-maps":   "Google Maps API",
            "firebase":      "Firebase JS SDK",
            "stripe":        "Stripe.js",
            "auth0.js":      "auth0.js",
            "msal":          "MSAL.js",
            "oidc-client":   "oidc-client",
            "oidc-client-ts":"oidc-client-ts",
            "keycloak":      "Keycloak adapter",
            "jose":          "jose",
            "jsrsasign":     "jsrsasign",
            "sjcl":          "SJCL",
            "node-forge":    "node-forge",
            "signalr":       "SignalR client",
            "axios":         "Axios",
            "socket.io":     "socket.io-client",
            "sockjs":        "SockJS",
            "qs":             "qs",
            "uri.js":        "URI.js",
            "umbrella":      "Umbrella JS",
            "requirejs":     "RequireJS",
            "systemjs":      "SystemJS",
            "seajs":         "SeaJS",
            "labjs":         "LABjs",
            "yepnope":       "YepNope",
            "core-js":       "core-js",
            "regenerator-runtime": "regenerator-runtime",
            "babel-polyfill":"Babel polyfill",
            "whatwg-fetch":  "whatwg-fetch",
            "intl":          "Intl.js",
            "js-joda":       "js-joda",
            "woocommerce":   "WooCommerce",
        }
        for lib in vlibs:
            name = _LIB_DISPLAY_NAMES.get(lib["library"], lib["library"])
            ver  = lib.get("version", "?")
            label = f"{name} {ver}"
            if lib.get("eol_status") == "eol":
                msg = lib.get("eol_message") or "version is end-of-life"
                # Surfaces in the findings summary at warn severity. The
                # finding label uses just "<library> <version>" so it
                # de-dupes cleanly across domains in a bulk run.
                # The score_label is the per-library breakdown key
                # (matches what score_results() appends to pts), so the
                # 0/1 score annotation renders next to the finding line.
                score_label = f"EOL library: {lib['library']} {ver}"
                print(warn(
                    f"{label}  {c(GREY, '← EOL: ' + msg)}",
                    f"EOL library — {label}",
                    score_label,
                ))
            else:
                # 'ok' (in-floor / not in EOL list) and 'unknown' (no entry
                # in library_eol.json) both render as plain info lines.
                print(f"  {c(GREY, '·')} {label}")

    # ── Browser security headers ──────────────────────────────────────────────
    print(c(BOLD, "\nBrowser Security Headers"))
    if srv.get("error"):
        print(f"  {c(GREY, '–')} Skipped — site unreachable, headers cannot be evaluated")
    else:
        # ── CSP — driven by audit_checks.analyze_csp output ─────────────────
        # The simple "present/permissive/missing" check is kept for back-compat
        # scoring under the "CSP" rubric label; the deeper breakdown drives
        # CSP script-src safety / object-src / base-uri / frame-ancestors /
        # enforcement-mode rubric labels.
        csp_q = srv.get("csp_quality")
        csp_a = r.get("csp_analysis", {}) or {}
        if csp_q == "present":
            print(ok("Content-Security-Policy set"))
        elif csp_q == "permissive":
            print(warn("Content-Security-Policy present but appears permissive (wildcard src detected)",
                       "Content Security Policy — policy too permissive", "CSP"))
        else:
            print(warn("Content-Security-Policy not set",
                       "Content Security Policy — missing", "CSP"))

        if csp_a.get("present"):
            # Per-directive breakdown lines + findings list
            sso = csp_a.get("script_src_outcome")
            if sso == "strict":
                print(ok("CSP script-src: strict (nonce/hash + strict-dynamic)"))
            elif sso == "nonce_or_hash":
                print(ok("CSP script-src: nonce/hash present"))
            elif sso == "host_allowlist":
                print(warn("CSP script-src: host-allowlist (weaker than nonce/hash)",
                           "CSP — script-src is host-allowlist", "CSP script-src safety"))
            elif sso == "unsafe_inline":
                print(bad("CSP script-src: 'unsafe-inline' without nonce/hash — inline scripts run",
                          "CSP — unsafe-inline in script-src", "CSP script-src safety"))
            elif sso == "wildcard_or_scheme":
                print(bad("CSP script-src: wildcard or dangerous scheme — policy bypass possible",
                          "CSP — wildcard/scheme in script-src", "CSP script-src safety"))

            oso = csp_a.get("object_src_outcome")
            if oso == "none_or_self":
                print(ok("CSP object-src restricted ('none' or 'self')"))
            elif oso == "unrestricted":
                print(bad("CSP object-src unrestricted — plugin XSS likely",
                          "CSP — object-src unrestricted", "CSP object-src"))
            else:
                print(warn("CSP object-src missing — plugins (Flash, Java) can be injected",
                           "CSP — object-src missing", "CSP object-src"))

            buo = csp_a.get("base_uri_outcome")
            if buo == "set":
                print(ok("CSP base-uri restricted (prevents <base> hijack)"))
            else:
                print(warn("CSP base-uri missing — <base> tag injection can hijack relative URLs",
                           "CSP — base-uri missing", "CSP base-uri"))

            # frame-ancestors: only emit a finding if X-Frame-Options ALSO not set,
            # otherwise the next block already covers clickjacking defence.
            fao = csp_a.get("frame_ancestors_outcome")
            xfo_now = srv.get("x_frame_options")
            if fao == "set":
                print(ok("CSP frame-ancestors restricted"))
            elif not xfo_now:
                print(warn("CSP frame-ancestors missing — and no X-Frame-Options either",
                           "CSP — frame-ancestors missing", "CSP frame-ancestors"))

            if csp_a.get("enforcement_outcome") == "report_only":
                print(warn("CSP is in Report-Only mode — violations logged but not blocked",
                           "CSP — Report-Only (not enforced)", "CSP enforcement mode"))

            # Surface any high-severity findings the analyzer flagged that
            # didn't already become a per-directive line above.
            for sev, msg in csp_a.get("findings", []):
                # Skip findings already represented by per-directive lines
                low = msg.lower()
                if any(s in low for s in (
                    "missing object-src", "missing base-uri",
                    "report-only", "wildcard '*'", "dangerous schemes",
                    "'unsafe-inline' without",
                )):
                    continue
                if sev == "high":
                    print(bad(f"CSP: {msg}", "CSP — issue", "CSP script-src safety"))
                else:
                    print(warn(f"CSP: {msg}", "CSP — issue", "CSP script-src safety"))

        xfo = srv.get("x_frame_options")
        csp_fa = srv.get("csp_frame_ancestors", False)
        if csp_fa:
            if xfo:
                xfo_first = xfo.split(",")[0].strip().upper()
                dupe_note = c(GREY, "  ← header sent multiple times") if "," in xfo else ""
                print(ok(f"X-Frame-Options: {c(GREEN, xfo_first)}{dupe_note}  {c(GREY, '(CSP frame-ancestors also set)')}"))
            else:
                print(ok(f"X-Frame-Options: covered by {c(GREEN, 'CSP frame-ancestors')}"))
        elif xfo:
            xfo_first = xfo.split(",")[0].strip().upper()
            if xfo_first in ("DENY", "SAMEORIGIN"):
                dupe_note = c(GREY, "  ← header sent multiple times") if "," in xfo else ""
                print(ok(f"X-Frame-Options: {c(GREEN, xfo_first)}{dupe_note}"))
            else:
                print(warn(f"X-Frame-Options: {c(YELLOW, xfo)}  ← unrecognised value",
                           f"X-Frame-Options — unrecognised value ({xfo_first})", "X-Frame-Options"))
        else:
            print(warn("X-Frame-Options not set", "X-Frame-Options — missing", "X-Frame-Options"))

        xcto = srv.get("x_content_type")
        if xcto and xcto.lower() == "nosniff":
            print(ok("X-Content-Type-Options: nosniff"))
        elif xcto:
            print(warn(f"X-Content-Type-Options: {c(YELLOW, xcto)}  ← expected 'nosniff'",
                       "X-Content-Type-Options — unexpected value", "X-Content-Type-Options"))
        else:
            print(warn("X-Content-Type-Options not set",
                       "X-Content-Type-Options — missing", "X-Content-Type-Options"))

        rp = srv.get("referrer_policy")
        if rp:
            rp_first = rp.split(",")[0].strip().lower()
            dupe_note = c(GREY, "  ← header sent multiple times") if "," in rp else ""
            if rp_first in STRONG_REFERRER_POLICIES:
                print(ok(f"Referrer-Policy: {c(GREEN, rp_first)}{dupe_note}"))
            else:
                print(warn(f"Referrer-Policy: {c(YELLOW, rp_first)}{dupe_note}  ← consider a stricter policy",
                           f"Referrer-Policy — weak ({rp_first})", "Referrer-Policy"))
        else:
            print(warn("Referrer-Policy not set", "Referrer-Policy — missing", "Referrer-Policy"))

        pp = srv.get("permissions_policy")
        if pp:
            print(ok("Permissions-Policy set"))
        else:
            print(warn("Permissions-Policy not set",
                       "Permissions-Policy — missing", "Permissions-Policy"))

        # ── 2.1.0 additions: Cross-Origin-Opener-Policy / Cross-Origin-
        # Resource-Policy / COEP / X-XSS-Protection ─────────────────────────
        coop = (srv.get("coop") or "").strip()
        coop_low = coop.lower()
        if coop_low == "same-origin":
            print(ok(f"Cross-Origin-Opener-Policy: {c(GREEN, coop)}"))
        elif coop_low == "same-origin-allow-popups":
            print(warn(f"Cross-Origin-Opener-Policy: {c(YELLOW, coop)} — partial isolation",
                       "Cross-Origin-Opener-Policy — same-origin-allow-popups (partial)",
                       "Cross-Origin-Opener-Policy"))
        elif coop:
            print(warn(f"Cross-Origin-Opener-Policy: {c(YELLOW, coop)} — weak value",
                       f"Cross-Origin-Opener-Policy — weak value ({coop})",
                       "Cross-Origin-Opener-Policy"))
        else:
            print(warn("Cross-Origin-Opener-Policy not set",
                       "Cross-Origin-Opener-Policy — missing", "Cross-Origin-Opener-Policy"))

        corp = (srv.get("corp") or "").strip()
        corp_low = corp.lower()
        if corp_low in ("same-origin", "same-site"):
            print(ok(f"Cross-Origin-Resource-Policy: {c(GREEN, corp)}"))
        elif corp_low == "cross-origin":
            print(warn(f"Cross-Origin-Resource-Policy: {c(YELLOW, corp)} — explicit cross-origin",
                       "Cross-Origin-Resource-Policy — cross-origin",
                       "Cross-Origin-Resource-Policy"))
        elif corp:
            print(warn(f"Cross-Origin-Resource-Policy: {c(YELLOW, corp)}",
                       f"Cross-Origin-Resource-Policy — unrecognised ({corp})",
                       "Cross-Origin-Resource-Policy"))
        else:
            print(warn("Cross-Origin-Resource-Policy not set",
                       "Cross-Origin-Resource-Policy — missing",
                       "Cross-Origin-Resource-Policy"))

        coep = (srv.get("coep") or "").strip()
        if coep:
            # COEP is informational — only meaningful with COOP and is rarely
            # appropriate for non-isolated sites. Don't score it.
            print(f"  {c(GREY, '·')} Cross-Origin-Embedder-Policy: {c(GREY, coep)}")

        # X-XSS-Protection — modern browsers have removed it. Setting it
        # ('1; mode=block') can introduce vulnerabilities in older browsers.
        # Mozilla / OWASP / Chrome team all say: don't set it (or set to 0).
        xxp = (srv.get("x_xss_protection") or "").strip()
        if not xxp:
            # Absent is correct — full credit, silent
            pass
        elif xxp.startswith("0"):
            print(ok(f"X-XSS-Protection: {c(GREEN, '0')} — explicitly disabled (correct)"))
        else:
            print(warn(
                f"X-XSS-Protection: {c(YELLOW, xxp)} — header is deprecated; "
                f"setting it can introduce XSS in older browsers. Recommended: remove or set to 0",
                f"X-XSS-Protection — deprecated header set ({xxp})",
                "X-XSS-Protection deprecated"))

        # ── Cookies ──────────────────────────────────────────────────────
        cookies = srv.get("cookies") or []
        print(c(BOLD, "\nCookies") + c(GREY, "  (on homepage response)"))
        _cookie_issues: dict[str, list[tuple[str, str]]] = defaultdict(list)
        if not cookies:
            print(info("No Set-Cookie headers on this response — "
                       "cookies set after login or by JavaScript are not visible here"))
        else:
            for ck in cookies:
                name = ck["name"]
                tag_infra = c(GREY, " (CDN/WAF)") if ck["infra"] else ""

                def _mark(present, label):
                    return c(GREEN, f"✔ {label}") if present else c(RED, f"✘ {label}")

                secure_m   = _mark(ck["secure"],   "Secure")
                httponly_m = _mark(ck["httponly"], "HttpOnly")

                if ck["samesite"]:
                    ss_val = ck["samesite"]
                    if ss_val == "None" and not ck["secure"]:
                        ss_m = c(RED, f"✘ SameSite=None (no Secure — browser will reject)")
                    elif ss_val in ("Strict", "Lax"):
                        ss_m = c(GREEN, f"✔ SameSite={ss_val}")
                    else:
                        ss_m = c(YELLOW, f"? SameSite={ss_val}")
                else:
                    ss_m = c(RED, "✘ SameSite missing")

                print(f"  {c(CYAN, '·')} {c(BOLD, name)}{tag_infra}")
                print(f"    {secure_m}   {httponly_m}   {ss_m}")

                src = " (infra)" if ck["infra"] else ""
                for issue in ck["issues"]:
                    _cookie_issues[issue].append((name, src))

        # Emit one consolidated finding per issue type. Non-infra cookies are
        # scored; infra cookies (CDN/WAF-set) are not — emit them on separate
        # lines so the score annotation on the non-infra line isn't suppressed.
        _ISSUE_META = [
            ("missing_secure",              "bad",  "Cookie missing Secure",    "Cookie Secure"),
            ("missing_httponly",            "bad",  "Cookie missing HttpOnly",  "Cookie HttpOnly"),
            ("missing_samesite",            "warn", "Cookie missing SameSite",  "Cookie SameSite"),
            ("samesite_none_without_secure","bad",  "Cookie SameSite=None without Secure", "Cookie Secure"),
            # 2.1.0: prefix-violation findings tied to the prefix rubric label
            ("invalid_secure_prefix",       "bad",
             "Cookie has __Secure- prefix without Secure flag", "Cookie name prefixes"),
            ("invalid_host_prefix",         "bad",
             "Cookie has __Host- prefix but lacks Secure / Path=/ / has Domain",
             "Cookie name prefixes"),
        ]
        for issue_key, level, label, score_label in _ISSUE_META:
            affected = _cookie_issues.get(issue_key, [])
            if not affected:
                continue
            scored  = [name for name, src in affected if not src]
            infra   = [name for name, src in affected if src]
            if scored:
                findings.append((level, f"{label} ({', '.join(scored)})", score_label))
            if infra:
                # Infra cookies are not scored — pass score_label=None to suppress annotation
                findings.append((level, f"{label} ({', '.join(f'{n} (infra)' for n in infra)})", None))

        # Note successful prefix usage (positive score signal — silent, no finding)
        _good_prefixed = [ck for ck in cookies
                          if ck["name"].startswith(("__Host-", "__Secure-"))
                          and "invalid_secure_prefix" not in ck["issues"]
                          and "invalid_host_prefix"   not in ck["issues"]]
        if _good_prefixed:
            names = ", ".join(ck["name"] for ck in _good_prefixed)
            print(ok(f"Cookies use __Host-/__Secure- prefixes correctly  {c(GREY, '(' + names + ')')}"))

    # ── Security.txt ──────────────────────────────────────────────────────────
    sectxt = r.get("security_txt", {})
    print(c(BOLD, "\nSecurity Contact") + c(GREY, "  (RFC 9116 — security.txt)"))
    if sectxt.get("error"):
        print(err(f"Could not fetch security.txt: {sectxt['error']}",
                  "security.txt (RFC 9116) — fetch error"))
    elif sectxt.get("present") and sectxt.get("contact"):
        found_at = sectxt.get("found_at", "")
        if found_at and "/security.txt" in found_at and "/.well-known/" not in found_at:
            print(f"  {c(GREY, '·')} Found at legacy path: {c(GREY, found_at)} (consider moving to /.well-known/security.txt)")
        for contact in sectxt["contact"]:
            print(ok(f"security.txt contact: {c(GREEN, contact)}"))
        if sectxt.get("policy"):
            print(f"  {c(GREY, '·')} Policy: {c(GREY, sectxt['policy'])}")
        expires = sectxt.get("expires")
        expired = sectxt.get("expired")
        if expires and expired is False:
            print(ok(f"Expires: {c(GREEN, expires)}"))
        elif expires and expired is True:
            print(bad(f"Expires: {c(RED, expires)}  ← security.txt has expired",
                      "security.txt (RFC 9116) — expired", "security.txt"))
        elif expires is None:
            print(warn("Expires: field missing — required by RFC 9116",
                       "security.txt (RFC 9116) — no expiry", "security.txt"))
    elif sectxt.get("present"):
        print(warn("security.txt present but no Contact: field found",
                   "security.txt (RFC 9116) — no contact", "security.txt"))
    else:
        print(warn("security.txt not found", "security.txt (RFC 9116) — missing", "security.txt"))

    # ── SSL Labs ──────────────────────────────────────────────────────────────
    ssl_result = r.get("ssl_labs")
    if ssl_result is not None:
        worst = ssl_result.get("worst_grade")
        all_g = ssl_result.get("grades", [])
        print(c(BOLD, "\nSSL Labs") + c(GREY, "  (Qualys SSL Labs API)"))

        test_time_ms = ssl_result.get("test_time_ms")
        if test_time_ms:
            try:
                test_dt  = datetime.fromtimestamp(test_time_ms / 1000, tz=timezone.utc)
                age_secs = (datetime.now(timezone.utc) - test_dt).total_seconds()
                if age_secs < 3600:
                    age_str = f"{int(age_secs // 60)} minutes ago"
                elif age_secs < 86400:
                    age_str = f"{int(age_secs // 3600)} hours ago"
                else:
                    age_str = f"{int(age_secs // 86400)} days ago"
                print(f"  {c(GREY, '·')} Assessed: {c(GREY, test_dt.strftime('%Y-%m-%d %H:%M UTC'))}  {c(GREY, f'({age_str})')}")
            except Exception:
                pass
        if worst is None:
            print(err("No grade returned from SSL Labs", "SSL Labs — no grade"))
        else:
            pts     = _SSL_GRADE_PTS.get(worst)
            gcol    = _GRADE_COLOR.get(worst, GREY)
            pts_str = c(GREY, f"  ({pts}/{_SSL_GRADE_POSSIBLE})") if pts is not None else ""
            unique_grades = list(dict.fromkeys(all_g))
            ep_str  = c(GREY, f"  (endpoints: {', '.join(all_g)})") if len(unique_grades) > 1 else ""
            grade_line = f"Grade: {c(gcol+BOLD, worst)}{pts_str}{ep_str}"
            if worst in ("A+", "A", "A-"):
                print(ok(grade_line))
            elif worst in ("B", "C", "M"):
                print(warn(grade_line, f"SSL Labs — grade {worst}", "SSL Labs grade"))
            else:
                print(bad(grade_line, f"SSL Labs — grade {worst}", "SSL Labs grade"))

            # Conditions reported by SSL Labs. We do not classify which ones
            # affect the grade and which don't — the grade itself is the
            # verdict, this list reports the observations.
            #
            # Local name is ssl_findings (not findings) to avoid shadowing
            # the outer findings list of (level, label, score_label) tuples
            # used by the summary panel. Lines are printed without a label=
            # argument so they don't register individually as findings —
            # the SSL Labs grade is already a finding.
            ssl_findings = ssl_result.get("findings") or []
            if ssl_findings:
                print(f"  {c(GREY, '·')} Conditions reported by SSL Labs ({len(ssl_findings)}):")
                for f in ssl_findings:
                    print(warn(f))

    # ── Page Analysis (SRI, mixed content, third-party, a11y) ──────────────
    page = r.get("page_signals")
    if page is not None and page.get("parsed"):
        print(c(BOLD, "\nPage Analysis"))

        # ── Body truncation / non-HTML caveats ────────────────────────────────
        # Shown FIRST so the reader knows up front whether the counts below
        # reflect the whole page, only the first N MB, or a non-HTML payload.
        # Three distinct warnings can fire:
        #   (a) body_truncated — page exceeded the cap; counts undercount
        #   (b) body_looks_like_html=False — server returned bytes that aren't
        #       HTML. Common cases: bot-mitigation challenge, JSON API root,
        #       PDF/binary, gzipped bytes from a misbehaving CDN.
        #   (c) Both can fire together; show both.
        cap_used    = redirect.get("body_cap_used") or 262144
        cap_str     = f"{cap_used // (1024 * 1024)}MB" if cap_used >= 1048576 else f"{cap_used // 1024}KB"
        looks_html  = redirect.get("body_looks_like_html", True)  # default True for back-compat

        if redirect.get("body_truncated"):
            print(c(YELLOW, f"  ⚠ Page body exceeded {cap_str} capture limit — "
                            f"counts below are conservative"
                            + ("" if cap_used >= 5242880 else "  (use --deep for a 5MB cap)")))
        if not looks_html and (page.get("body_bytes") or 0) > 0:
            print(c(YELLOW, "  ⚠ Response body does not look like HTML — "
                            "page-level counts below are unreliable. Common causes: "
                            "bot-mitigation challenge page (Akamai / AWS WAF), "
                            "non-HTML payload (JSON API, PDF), or a CDN that ignored "
                            "Accept-Encoding."))

        # ── Parser inventory ─────────────────────────────────────────────────
        # Tells the reader what the parser actually saw. Useful for diagnosing
        # SPA shells (where the static HTML has almost no content because the
        # body is rendered client-side) — without this line the user can't
        # tell whether "0 images" means "no images" or "parser failed".
        body_bytes  = page.get("body_bytes", 0)
        scripts     = page.get("scripts_total", 0)
        stylesheets = page.get("stylesheets_total", 0)
        a = page.get("a11y") or {}
        img_total   = a.get("images_total", 0)
        inp_total   = a.get("inputs_total", 0)
        iframe_n    = page.get("iframe_count", 0)
        size_str = f"{body_bytes/1024:.0f} KB" if body_bytes < 1024*1024 else f"{body_bytes/(1024*1024):.1f} MB"
        print(f"  {c(GREY, '·')} Parser inspected {c(BOLD, size_str)} of HTML: "
              f"{scripts} <script>, {stylesheets} <link rel=stylesheet>, "
              f"{img_total} <img>, {inp_total} <input>, {iframe_n} <iframe>")
        # Hint when a likely SPA shell or bot-challenge page is detected.
        # The two are indistinguishable to a static parser — both yield a
        # body with a few <script> tags and no real content — but in
        # practice the bot-challenge page is the more common explanation,
        # so we flag it first. Suppress this hint when the body doesn't
        # look like HTML at all, since the more important warning above
        # already explains why we found nothing.
        if (looks_html and scripts > 0 and img_total == 0 and inp_total == 0
                and not redirect.get("body_truncated")):
            print(c(GREY, "    (most likely a bot-protection or captcha "
                          "challenge page (Cloudflare / Akamai / AWS WAF) — "
                          "could also be a real SPA shell rendered client-side; "
                          "either way the static HTML has no <img>/<input>)"))

        # ── Subresource Integrity ────────────────────────────────────────────
        sri_outcome = page.get("sri_outcome")
        protected = page.get("sri_protected", 0)
        ext_total = page.get("sri_external_total", 0)
        if sri_outcome == "no_external_scripts":
            print(ok("No external scripts/stylesheets — SRI not needed"))
        elif sri_outcome == "all_external_have_sri":
            print(ok(f"Subresource Integrity on all {ext_total} external resources"))
        elif sri_outcome == "some_external_have_sri":
            print(warn(
                f"Subresource Integrity on {protected}/{ext_total} external resources",
                "SRI — partial coverage", "Subresource Integrity"))
        elif sri_outcome == "external_without_sri":
            print(bad(
                f"No Subresource Integrity on any of {ext_total} external resources — "
                f"a CDN compromise could inject arbitrary code",
                "SRI — none on external resources", "Subresource Integrity"))

        # ── Mixed content ────────────────────────────────────────────────────
        mc_outcome = page.get("mixed_outcome")
        mc_count = page.get("mixed_active_count", 0)
        if mc_outcome == "active":
            mixed_list = page.get("mixed_active", []) or []
            # Detailed section: never truncate. With ≤3 entries inline,
            # otherwise full list indented.
            if len(mixed_list) <= 3:
                sample = ", ".join(mixed_list)
                print(bad(
                    f"Mixed content (active): {mc_count} HTTP resource(s) on HTTPS page  "
                    f"{c(GREY, '(' + sample + ')')}",
                    f"Mixed content — {mc_count} HTTP resources on HTTPS page",
                    "Mixed content (in-page)"))
            else:
                print(bad(
                    f"Mixed content (active): {mc_count} HTTP resource(s) on HTTPS page",
                    f"Mixed content — {mc_count} HTTP resources on HTTPS page",
                    "Mixed content (in-page)"))
                for url in mixed_list:
                    print(f"      {c(GREY, '·')} {c(GREY, url)}")
        elif mc_outcome == "passive_only":
            print(warn("Mixed content (passive only) — images/media loaded over HTTP",
                       "Mixed content — passive", "Mixed content (in-page)"))
        elif mc_outcome == "none":
            print(ok("No mixed content detected"))

        # ── Third-party origins ──────────────────────────────────────────────
        third = page.get("third_party_origins", [])
        if third:
            # Detailed section: never truncate. ≤5 inline, otherwise full
            # list indented.
            if len(third) <= 5:
                preview = ", ".join(third)
                print(info(f"Third-party origins: {len(third)}  {c(GREY, '(' + preview + ')')}"))
            else:
                print(info(f"Third-party origins: {len(third)}"))
                for origin in third:
                    print(f"      {c(GREY, '·')} {c(GREY, origin)}")
        else:
            print(ok("No third-party origins detected on the homepage"))

        # ── Iframes ──────────────────────────────────────────────────────────
        if page.get("iframe_count", 0) > 0:
            print(info(f"Iframes on page: {page['iframe_count']}"))

        # ── meta http-equiv=Content-Security-Policy ──────────────────────────
        meta_csp = page.get("meta_csp")
        if meta_csp and not srv.get("csp"):
            # Show the full CSP rather than truncating at 80 chars. Long
            # policies wrap to a separate indented line so the headline
            # stays readable.
            if len(meta_csp) <= 80:
                print(info(f"CSP delivered via <meta> tag (HTTP header preferred): "
                           f"{c(GREY, meta_csp)}"))
            else:
                print(info(f"CSP delivered via <meta> tag (HTTP header preferred):"))
                print(f"      {c(GREY, meta_csp)}")

        # ── Accessibility signals ──────────────────────────────────────────
        # We emit a line for every check we ran, including zero counts ("we
        # found 0 <img> tags"), so the reader can tell the parser succeeded
        # but found nothing — an important distinction on SPA shells, redirect
        # landing pages, and low-content sites where silent omission would
        # look like the audit had failed.
        a = page.get("a11y", {})
        if a:
            print(c(BOLD, "\n  Accessibility Signals  ") +
                  c(GREY, "(indicative only — not a WAVE/Axe substitute)"))

            # html lang
            if not a.get("html_lang_set"):
                print(warn("<html> has no lang attribute", None, None))
            else:
                print(ok(f"<html lang=\"{a.get('html_lang') or '?'}\">"))

            # alt text — always emit a line so 0-image pages aren't silent
            total = a.get("images_total", 0)
            no_alt = a.get("images_missing_alt", 0)
            if total == 0:
                print(f"  {c(GREY, '·')} {c(GREY, 'No <img> tags found in static HTML')}")
            elif no_alt == 0:
                print(ok(f"All {total} <img> tag(s) have an alt attribute"))
            else:
                _alt_hint = '(decorative images should still have alt="")'
                print(warn(
                    f"{no_alt}/{total} <img> tag(s) missing alt attribute  "
                    f"{c(GREY, _alt_hint)}",
                    None, None))

            # form labels — always emit a line so no-form pages aren't silent
            inp_total = a.get("inputs_total", 0)
            unl = a.get("inputs_unlabeled", 0)
            if inp_total == 0:
                print(f"  {c(GREY, '·')} {c(GREY, 'No labelable form <input> tags found')}")
            elif unl == 0:
                print(ok(f"All {inp_total} form input(s) have a label"))
            else:
                print(warn(
                    f"{unl}/{inp_total} form input(s) without an associated label or aria-label",
                    None, None))

            # empty buttons - show count when present, OK line when none
            empty_b = a.get("empty_buttons", 0)
            if empty_b == 0:
                print(f"  {c(GREY, '·')} {c(GREY, 'No empty <button> elements')}")
            else:
                print(warn(f"{empty_b} empty <button> element(s)  "
                           f"{c(GREY, '(no text and no aria-label/title)')}",
                           None, None))

            # empty anchors - show count when present, OK line when none
            empty_a = a.get("empty_links", 0)
            if empty_a == 0:
                print(f"  {c(GREY, '·')} {c(GREY, 'No empty <a> elements')}")
            else:
                print(warn(f"{empty_a} empty <a> element(s)  "
                           f"{c(GREY, '(no text and no aria-label/title)')}",
                           None, None))

            print(c(GREY, "  · A11y signals are not scored — they are reported for awareness only."))
            print(c(GREY, "    For a full audit use WebAIM WAVE, Axe DevTools, or pa11y."))

    # ── STARTTLS / DANE on MX hosts (--deep only) ────────────────────────────
    starttls = r.get("starttls_mx")
    if starttls is not None and starttls.get("mx_count", 0) > 0:
        print(c(BOLD, "\nMX STARTTLS Probe  ") + c(GREY, "(--deep)"))
        print(c(GREY, "  Probing port 25 → EHLO → STARTTLS on each MX host. "
                       "Many networks block port 25 egress; partial results are normal."))
        # Per-host diagnostic lines. These are info-only (label=None, score_label=None
        # on the warn/bad calls) — the scoring finding is emitted once below
        # via the worst-of aggregation. That keeps the breakdown to one
        # STARTTLS-MX row regardless of MX count.
        #
        # Annotate the negotiated TLS version with what it implies, so the
        # reader can see how each host's version corresponds to the
        # summary finding. Our context offers TLS 1.3 by default; if the
        # server came back with 1.2, it's because 1.3 wasn't offered
        # server-side.
        for host, info_d in (starttls.get("results") or {}).items():
            if info_d.get("error"):
                print(f"  {c(GREY, '?')} {host}: {c(GREY, info_d['error'])}")
            else:
                ver = info_d.get("tls_version") or "?"
                issuer = info_d.get("cert_issuer") or ""
                expires = info_d.get("cert_expires") or ""
                # Build parenthetical only from fields that have values, so
                # "(, expires )" doesn't render when both are missing — some
                # Outlook / Exchange Online MX endpoints complete the TLS
                # handshake but don't expose parseable cert details.
                bits = []
                if issuer:
                    bits.append(issuer)
                if expires:
                    bits.append(f"expires {expires}")
                detail = c(GREY, f"({', '.join(bits)})") if bits else ""
                # Two-space gap only when there's something to show.
                gap = "  " if detail else ""
                if ver == "TLSv1.3":
                    annot = c(GREY, "  ← strong")
                    print(ok(f"{host}: {c(GREEN, ver)}{annot}{gap}{detail}"))
                elif ver == "TLSv1.2":
                    annot = c(GREY, "  ← TLS 1.3 not offered")
                    print(warn(f"{host}: {c(YELLOW, ver)}{annot}{gap}{detail}",
                               None, None))
                else:
                    annot = c(GREY, "  ← legacy TLS, vulnerable") if ver in ("TLSv1", "TLSv1.0", "TLSv1.1") else ""
                    print(bad(f"{host}: {c(RED, ver)}{annot}{gap}{detail}",
                              None, None))

        # ── STARTTLS-MX scoring finding (one per scan, worst-of) ─────────
        # Same classification + worst-of aggregation logic as score_results
        # in audit_checks. The two MUST stay in sync — if you change the
        # outcome ladder there, change it here. The per-host classifier
        # is duplicated rather than imported because the rendering layer
        # historically does not pull logic out of audit_checks (cleaner
        # one-way dependency: render imports from checks, never the other
        # way around).
        def _classify_starttls_host(host_info):
            err = host_info.get("error") or ""
            if not err:
                ver_u = (host_info.get("tls_version") or "").upper()
                if ver_u == "TLSV1.3":
                    return "tls_1_3"
                if ver_u == "TLSV1.2":
                    return "tls_1_2"
                if ver_u in ("TLSV1.1", "TLSV1.0", "SSLV3", "SSLV2"):
                    return "tls_legacy"
                return "unprobed"
            if "does not advertise STARTTLS" in err:
                return "no_starttls"
            return "unprobed"

        host_results = list((starttls.get("results") or {}).values())
        classifications = [_classify_starttls_host(h) for h in host_results]
        # Worst-CONFIRMED-of aggregation — must match audit_checks
        # score_results. Unprobed hosts drop out when any confirmed
        # result exists. Only when EVERY host was unprobed does the
        # whole check evaluate to "unprobed" (0/0).
        severity = {
            "no_starttls": 4, "tls_legacy": 3,
            "tls_1_2": 1, "tls_1_3": 0,
        }
        confirmed = [k for k in classifications if k != "unprobed"]
        if confirmed:
            worst = max(confirmed, key=lambda k: severity.get(k, 0))
        elif classifications:
            worst = "unprobed"
        else:
            worst = "unprobed"

        # Render the section-level summary line for the worst result. We
        # always emit a finding (even on tls_1_3) so the row appears in
        # the breakdown — that's the user-requested behavior of "in all
        # cases it should be in the results, the 0/0 in the findings as
        # a possible issue". For passing cases (tls_1_3 / tls_1_2) we
        # use ok() so they appear in the Passing checks section, not
        # the Findings section.
        if worst == "tls_1_3":
            print(ok("STARTTLS negotiated TLS 1.3 on every probed MX host  "
                     + c(GREY, "← strong"),
                     "STARTTLS-MX — TLS 1.3 on all probed MX hosts"))
        elif worst == "tls_1_2":
            # 1.5/2 — partial. Goes through warn() so it lands in Findings.
            print(warn("STARTTLS works but at least one MX negotiated only TLS 1.2  "
                       + c(GREY, "← TLS 1.3 not offered"),
                       "STARTTLS-MX — TLS 1.2 negotiated (TLS 1.3 not offered)",
                       "STARTTLS-MX"))
        elif worst == "tls_legacy":
            print(bad("STARTTLS works but at least one MX negotiated TLS 1.0/1.1  "
                      + c(GREY, "← legacy TLS, vulnerable"),
                      "STARTTLS-MX — legacy TLS (1.0/1.1) on at least one MX",
                      "STARTTLS-MX"))
        elif worst == "no_starttls":
            print(bad("At least one MX did not advertise STARTTLS  "
                      + c(GREY, "← SMTP delivery to that host is plaintext"),
                      "STARTTLS-MX — STARTTLS not advertised on at least one MX",
                      "STARTTLS-MX"))
        else:  # unprobed
            # 0/0 — but still emitted so the operator sees the check ran
            # and produced no signal. Goes through err() (the '?' marker)
            # since that's the visual we already use for inconclusive
            # checks (DKIM not_found, etc.).
            print(err("STARTTLS-MX could not be probed on any MX host  "
                      + c(GREY, "← port 25 likely blocked egress; STARTTLS posture unknown"),
                      "STARTTLS-MX — unprobed (port 25 blocked or network error)",
                      "STARTTLS-MX"))

    # ── Summary ───────────────────────────────────────────────────────────────
    summary_domain = audit_domain if redirected else original_domain
    print(f"\n{c(BOLD+CYAN, '━'*56)}")
    print(c(BOLD, f"  Summary of {summary_domain}"))
    print(f"{c(BOLD+CYAN, '━'*56)}\n")
    if redirected:
        print(f"  {c(GREY, '→')} {original_domain} redirects to {audit_domain} — email audited for both domains; web/TLS reflects {audit_domain}\n")

    earned, possible, breakdown = score_results(r)
    passing = [(label, e, p) for label, e, p in breakdown if e == p and p > 0]
    partial = [(label, e, p) for label, e, p in breakdown if 0 < e < p]
    score_lookup = {label: (e, p) for label, e, p in breakdown}

    def _fmt_score(e, p):
        e_disp = int(e) if e == int(e) else e
        return c(GREY, f"{e_disp}/{p}")

    # ── Passing checks ────────────────────────────────────────────────────────
    # Each line is prefixed with its category (Email:/DNS:/Routing:/TLS:/HTTP:
    # /Website:) so a reader can scan for what passed in their area of concern
    # without re-reading the detailed sections above.
    if passing:
        print(c(BOLD, "  Passing checks"))
        # Group by category, then print in the canonical order so all Email
        # items appear together, all DNS items together, etc.
        passing_by_cat = defaultdict(list)
        for label, e, p in passing:
            cat = _category_for_score_label(label)
            passing_by_cat[cat].append((label, e, p))
        for cat in _CATEGORY_ORDER:
            for label, e, p in passing_by_cat.get(cat, []):
                if label == "SSL Labs grade":
                    ssl_r = r.get("ssl_labs", {})
                    worst = ssl_r.get("worst_grade", "?")
                    gcol  = _GRADE_COLOR.get(worst, GREEN)
                    print(f"  {c(GREEN, '✔')} {c(GREY, cat + ':')}  "
                          f"SSL Labs grade: {c(gcol+BOLD, worst)}  {_fmt_score(e, p)}")
                    continue
                display = _SCORE_LABEL_DISPLAY.get(label, label)
                print(f"  {c(GREEN, '✔')} {c(GREY, cat + ':')}  {display}  {_fmt_score(e, p)}")

    # ── SSL Labs zero-score grades → findings ─────────────────────────────────
    ssl_r = r.get("ssl_labs")
    if ssl_r is not None:
        worst = ssl_r.get("worst_grade")
        if worst is not None:
            e_ssl, p_ssl = score_lookup.get("SSL Labs grade", (None, None))
            if e_ssl is not None and e_ssl == 0:
                findings.append(("bad",
                                 f"SSL Labs — grade {worst}  → https://www.ssllabs.com/ssltest/analyze.html?d={audit_domain}",
                                 "SSL Labs grade"))

    # ── Partial findings ──────────────────────────────────────────────────────
    already_in_findings = set()
    for level, msg, sl in findings:
        if sl:
            already_in_findings.add(sl)

    partial_findings = []
    for label, e, p in partial:
        if label in already_in_findings:
            continue
        if label == "SSL Labs grade":
            ssl_r = r.get("ssl_labs", {})
            worst = ssl_r.get("worst_grade", "?")
            desc = f"SSL Labs grade: {worst}  → https://www.ssllabs.com/ssltest/analyze.html?d={audit_domain}"
        else:
            desc = _PARTIAL_LABEL.get(label, f"{_SCORE_LABEL_DISPLAY.get(label, label)} — partial")
        partial_findings.append((label, desc, e, p))

    # ── Findings ──────────────────────────────────────────────────────────────
    # Each finding line is prefixed with its category so the reader can scan
    # the same way as the passing-checks list. We resolve the category from
    # the score_label when one is attached (rubric-driven, exact match);
    # otherwise we fall back to keyword sniffing on the finding label.
    grouped = defaultdict(list)
    for level, msg, score_label in findings:
        if score_label is None:
            score_ann = f"  {c(GREY, '0/0')}"
        else:
            se, sp = score_lookup.get(score_label, (None, None))
            if se is not None and sp:
                score_ann = f"  {_fmt_score(se, sp)}"
            else:
                # Either the label isn't in score_lookup (informational
                # finding) or it has possible=0 (DKIM not-found, etc.).
                # Either way render as 0/0 so the no-penalty status is clear.
                score_ann = f"  {c(GREY, '0/0')}"
        cat = _finding_category(msg, score_label)
        grouped[cat].append((level, cat, f"{msg}{score_ann}"))

    for label, desc, e, p in partial_findings:
        cat = _category_for_score_label(label)
        grouped[cat].append(("partial", cat, f"{desc}  {_fmt_score(e, p)}"))

    has_findings = bool(grouped)
    if has_findings:
        print(c(BOLD, f"\n  Findings"))
        for cat in _CATEGORY_ORDER:
            if cat not in grouped:
                continue
            for level, line_cat, msg in grouped[cat]:
                sym = c(RED, '✘') if level == "bad" else c(YELLOW, '⚠') if level in ("warn", "partial") else c(GREY, '?')
                # Indent any continuation lines (multi-line finding text such
                # as the DKIM partial-check explanation) so they line up under
                # the body, not under the symbol/category prefix.
                lines = msg.split("\n")
                first = lines[0]
                print(f"  {sym} {c(GREY, line_cat + ':')}  {first}")
                for cont in lines[1:]:
                    print(f"        {cont}")
    elif not redirected:
        print(f"\n  {c(GREEN, '✔')} No issues found")

    # ── Score + category bar chart ────────────────────────────────────────────
    earned_disp = int(earned) if earned == int(earned) else earned
    pct = round((earned / possible * 100)) if possible else 0
    score_color = GREEN if pct >= _SCORE_GREEN else YELLOW if pct >= _SCORE_YELLOW else RED
    print(f"\n  {c(BOLD, 'Score:')}  {c(score_color+BOLD, f'{earned_disp}/{possible}')}  {c(score_color+BOLD, f'({pct}%)')}")
    print()

    # Per-category subscores driven directly off the rubric's `categories`
    # map. New checks added to the rubric automatically appear here without
    # touching this code.
    by_cat_pts = defaultdict(list)
    for label, e, p in breakdown:
        by_cat_pts[_category_for_score_label(label)].append((e, p))
    for cat in _CATEGORY_ORDER:
        cat_pts = by_cat_pts.get(cat, [])
        if not cat_pts:
            continue
        ce = sum(e for e, p in cat_pts)
        cp = sum(p for e, p in cat_pts)
        if cp == 0:
            continue
        cpct = round(ce / cp * 100)
        ce_disp = int(ce) if ce == int(ce) else ce
        cc = GREEN if cpct >= _SCORE_GREEN else YELLOW if cpct >= _SCORE_YELLOW else RED
        bar_filled = round(cpct / 10)
        bar = c(cc, "█" * bar_filled) + c(GREY, "░" * (10 - bar_filled))
        print(f"    {cat:<8}  {bar}  {c(cc, f'{ce_disp}/{cp}')}  {c(GREY, f'({cpct}%)')}")

    # ── Scan info footer ──────────────────────────────────────────────────────
    # Shows version, which options the run used, and total wall time. If one
    # individual check accounted for most of the wall time we name it — that
    # makes slowdowns from network operations (RIPEstat, DANE TLSA, STARTTLS,
    # etc.) immediately diagnosable instead of mysteriously vanishing into the
    # parallel pool.
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

_SCHEMA_VERSION = "1.0"


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


def _score_csv(results):
    """Per-category subscores plus the overall score, ready to merge into a row."""
    earned, possible, breakdown = score_results(results)
    earned_disp = int(earned) if earned == int(earned) else earned
    pct = round(earned / possible * 100) if possible else 0

    # Per-category subscores using the rubric-driven category mapping.
    by_cat = defaultdict(lambda: [0, 0])
    for label, e, p in breakdown:
        cat = _category_for_score_label(label)
        by_cat[cat][0] += e
        by_cat[cat][1] += p

    out = {
        "score_total_earned":   _str_or_blank(earned_disp),
        "score_total_possible": _str_or_blank(possible),
        "score_total_pct":      _str_or_blank(pct),
    }
    for cat in _CATEGORY_ORDER:
        ce, cp = by_cat.get(cat, [0, 0])
        ce_disp = int(ce) if ce == int(ce) else ce
        cpct = round(ce / cp * 100) if cp else ""
        prefix = f"score_{cat.lower()}"
        out[f"{prefix}_earned"]   = _str_or_blank(ce_disp) if cp else ""
        out[f"{prefix}_possible"] = _str_or_blank(cp) if cp else ""
        out[f"{prefix}_pct"]      = _str_or_blank(cpct)
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
        "tls_hsts_status":             hsts_status,
        "tls_hsts_max_age_seconds":    _str_or_blank(hsts.get("max_age")),
        "tls_hsts_includes_subdomains":_yn(hsts.get("includes_subdomains")),
        "tls_hsts_preload_directive":  _yn(hsts.get("preload_directive")),
        "tls_hsts_preloaded":          _yn(hsts.get("preloaded")),
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
    # Email — Mail transport hardening
    "email_mta_sts_present", "email_mta_sts_mode", "email_mta_sts_id",
    "email_tls_rpt_present", "email_tls_rpt_rua",
    "email_dane_mx_total", "email_dane_mx_with_tlsa",
    "email_dkim_selectors_checked", "email_dkim_selectors_found",
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
    "tls_hsts_status", "tls_hsts_max_age_seconds",
    "tls_hsts_includes_subdomains", "tls_hsts_preload_directive", "tls_hsts_preloaded",
    "tls_ssl_labs_grade", "tls_ssl_labs_assessed_utc",

    # HTTP
    "http_version", "http_h3_advertised", "http_alt_svc",
    "http_redirect_status", "http_redirect_detail",
    "http_first_hop_status", "http_first_hop_url",
    "http_response_elapsed_ms",

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
    # was flagged EOL (i.e. major below library_eol.json's floor or
    # explicitly listed in eol_majors). tech_libs_eol_count gives a numeric
    # column for spreadsheet sorting / filtering.
    "tech_libs_detected", "tech_libs_eol", "tech_libs_eol_count",
    # 2.9.0: same shape for server OS detection. tech_os_detected lists
    # every detected OS as "<key> <version>" (semicolon-separated);
    # tech_os_eol lists only those flagged EOL (below floor or in
    # eol_majors); tech_os_eol_count is a numeric for filtering;
    # tech_os_tls_old_stack is "yes"/"no" for whether TLS 1.0/1.1/SSLv3
    # was still negotiated, which corroborates the OS finding but is
    # recorded separately so it can be reasoned about on its own.
    "tech_os_detected", "tech_os_eol", "tech_os_eol_count",
    "tech_os_tls_old_stack",

    # Score — overall + per-category breakdown
    "score_total_earned", "score_total_possible", "score_total_pct",
    "score_email_earned", "score_email_possible", "score_email_pct",
    "score_dns_earned", "score_dns_possible", "score_dns_pct",
    "score_routing_earned", "score_routing_possible", "score_routing_pct",
    "score_tls_earned", "score_tls_possible", "score_tls_pct",
    "score_http_earned", "score_http_possible", "score_http_pct",
    "score_website_earned", "score_website_possible", "score_website_pct",
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
