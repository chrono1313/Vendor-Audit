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
audit_txt_report.py — the text report, written in Markdown.

Produces a self-contained .md file from a results dict (the same dict
audit_render.render() consumes). Designed for the technical owner of a
system: contains the evidence and raw values the terminal report shows,
organized by category, severity-prioritized at the top.

The file reads as plain text in any editor and renders as a formatted
page wherever Markdown is shown. It stays simple and greppable: one
finding per line, no hard wrapping, every status line starting with its
severity word (- **HIGH** …).

Single public entry point:

    write_md_report(original_domain, audit_domain, results, timestamp,
                    out_path, report_version)

Returns None on success; raises OSError on filesystem errors.

The detail sections are written once and printed two ways: as Markdown
for this file, and as plain tagged text for the terminal report
(audit_render). See "Output modes" below.

The four .py files (vendor_audit, audit_checks, audit_render, audit_txt_report)
and rubric.json share a single version number that is enforced
at startup. See vendor_audit.py for the full versioning policy.

Layout
======
1.  Header — domain, timestamp, version, links.
2.  Findings — severity counts, verdict, per-category table.
3.  Executive summary — the findings grouped by severity, then the
    informational rows. Passing checks are not repeated here; each one
    is in its section below.
4.  Detailed sections — Email, DNS, Routing, TLS, HTTP, HSTS, Server &
    Technology, Versioned Libraries, Browser Security Headers,
    security.txt, SSL Labs, Page Analysis, STARTTLS-MX. Each section
    suppressed when its source data isn't present.
5.  Scan footer — version and options.
"""

from __future__ import annotations

import contextvars
import re
from datetime import datetime, timezone
from collections import defaultdict


__version__ = "3.5.10"


# ── Layout constants ─────────────────────────────────────────────────────────

WIDTH = 100
RULE_LIGHT = "─" * WIDTH


# ── Line kinds ───────────────────────────────────────────────────────────────
# The detail sections are written once and printed two ways: as the
# Markdown text report, and by the terminal report (audit_render), which
# colours them and leaves out the explanation paragraphs. So the terminal
# can tell the lines apart, the plain form of the line builders below
# starts each line they make with a short tag naming its kind:
#
#   R          rule line above / below a section heading
#   H          section heading title
#   h          subsection heading
#   E          explanation paragraph (What / Why / Fix)
#   S:<sev>    first line of a status line; <sev> is a _STATUS_WORDS key, or none
#
# A tag is \x1e + kind + \x1f, added after word-wrapping so it never counts
# toward a line's width. Lines without a tag (tables, notes, records) are
# printed as they are. The Markdown form makes no tags, and _md_tidy
# removes any that remain; tests/test_reports.py checks that none survive.

_TAG_OPEN, _TAG_CLOSE = "\x1e", "\x1f"
_TAG_RE = re.compile("\x1e[^\x1f]*\x1f")


def _tag(kind):
    return f"{_TAG_OPEN}{kind}{_TAG_CLOSE}"


def strip_tags(text):
    """The text with every line-kind tag removed."""
    return _TAG_RE.sub("", text)


def split_tag(line):
    """(kind, text) for one line; kind is "" for an untagged line."""
    if line.startswith(_TAG_OPEN):
        end = line.find(_TAG_CLOSE)
        if end != -1:
            return line[1:end], line[end + 1:]
    return "", line


# ── Output modes ─────────────────────────────────────────────────────────────
# The line builders below (_heading, _status, _kv, _para, …) write one of
# two forms:
#
#   plain     tagged, word-wrapped text for the terminal report. This is
#             the default, and its output is unchanged since 3.0.
#   Markdown  for the .md text report: set by render_markdown. Headings
#             are ## / ###, a status line is "- **HIGH** body" with its
#             notes as nested "    - " items, key/value pairs are
#             "- Key: value", records are fenced code blocks, and nothing
#             is wrapped, so each finding stays on one greppable line.
#
# _md_tidy then evens out the blank lines between blocks, so a section
# renderer can keep the spacing it uses for the plain form.

_MARKDOWN = contextvars.ContextVar("vendor_audit_markdown", default=False)


def _md():
    """True while the Markdown text report is being rendered."""
    return _MARKDOWN.get()


_MD_HTML_RE = re.compile(r"<[A-Za-z/!][^<>]*>")


def _md_inline(text):
    """Text made safe to show as Markdown, changing as little as possible.

    HTML tag names (<img>, <html lang="en">) go in code spans, so they
    show instead of being read as markup; a * that could start emphasis
    (a wildcard like *.example.com) is escaped. Text that already has a
    code span is left as it is."""
    s = re.sub(r"(?<=\S) {2,}", " ", str(text))   # alignment padding
    if "`" in s:
        return s
    s = _MD_HTML_RE.sub(lambda m: f"`{m.group(0)}`", s)
    pieces = s.split("`")
    for i in range(0, len(pieces), 2):          # outside code spans only
        pieces[i] = re.sub(r"\*(?=\S)", r"\\*", pieces[i])
    return "`".join(pieces)


def _md_cell(text):
    """One Markdown table cell."""
    return _md_inline(text).replace("|", "\\|")


def _md_table(headers, rows):
    """A Markdown table, as a list of lines."""
    out = ["| " + " | ".join(_md_cell(h) for h in headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
    return out


class _OneNote(tuple):
    """Note fragments that make one note.

    A few notes are written as several short lines, which the plain form
    prints one per line. Markdown keeps each note on one line, so these
    become a single list item."""


def _md_kind(line):
    if line.startswith("    - "):
        return "nested"
    if line.startswith("- "):
        return "list"
    if line.startswith("|"):
        return "table"
    if line.startswith("```"):
        return "fence"
    return "text"


def _md_tidy(text):
    """The Markdown document with its spacing evened out.

    Exactly one blank line between blocks; none between the items of a
    list or the rows of a table, or before a nested item. A nested item
    with no list item above it moves out to the top level. Lines outside
    lists and code blocks lose their leading spaces (four would make a
    code block)."""
    out = []
    prev = None
    in_fence = False
    for raw in strip_tags(text).split("\n"):
        if in_fence:
            out.append(raw.rstrip())
            if raw.strip() == "```":
                in_fence = False
            continue
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line.startswith("    - "):
            line = line.lstrip()
        kind = _md_kind(line)
        if kind == "nested" and prev not in ("list", "nested"):
            line, kind = line[4:], "list"
        together = ((prev in ("list", "nested") and kind in ("list", "nested"))
                    or (prev == "table" and kind == "table"))
        if prev is not None and not together:
            out.append("")
        out.append(line)
        if kind == "fence":
            in_fence = True
        prev = kind
    return "\n".join(out).rstrip() + "\n"


# ── Severity classification ──────────────────────────────────────────────────


# Severity order and display labels for findings.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "pass")
ISSUE_SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_TITLES = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
    "info": "INFORMATIONAL", "pass": "PASSING",
}


# DNSKEY algorithm numbers (IANA registry), for the DNSSEC detail line.
_DNSSEC_ALG_NAMES = {
    1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256", 10: "RSASHA512", 12: "ECC-GOST", 13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448",
}


def severity_summary(counts, sep=" · "):
    """'2 critical · 4 high · 11 medium · 10 low' — zero counts left out."""
    bits = [f"{counts.get(s, 0)} {s}" for s in ISSUE_SEVERITIES if counts.get(s, 0)]
    return sep.join(bits) if bits else "no issues"


def passed_pct(counts):
    """Share of assessed checks that passed, as a whole percent, or None
    when nothing was assessed. Informational rows are not assessed, so they
    are in neither the numerator nor the denominator."""
    assessed = counts.get("pass", 0) + sum(counts.get(s, 0) for s in ISSUE_SEVERITIES)
    return round(100 * counts.get("pass", 0) / assessed) if assessed else None


def verdict_for(counts):
    """One-line verdict. A rule on the counts, not arithmetic."""
    if counts.get("critical"):
        return "Critical issues found"
    if counts.get("high"):
        return "High-severity issues found"
    if counts.get("medium"):
        return "Medium-severity issues found"
    if counts.get("low"):
        return "Minor issues only"
    return "No issues found"


# Address-family subheading labels with RFC citations. Used in the
# IP / ASN / RPKI section. The base RFC 6480 (RPKI) is on the parent
# section heading; these add the per-protocol IP standards.
_AF_LABEL_WITH_RFC = {
    "IPv4": "IPv4 (legacy IP, RFC 791)",
    "IPv6": "IPv6 (RFC 8200)",
}


# ── OS pretty names — mirror the terminal/HTML renderer ──────────────────────

_OS_DISPLAY_NAMES = {
    "centos":         "CentOS Linux",
    "rhel":           "Red Hat Enterprise Linux",
    "ubuntu":         "Ubuntu",
    "debian":         "Debian",
    "windows-server": "Windows Server",
    "iis":            "Microsoft IIS",
    "freebsd":        "FreeBSD",
}


# ── Library pretty names — abridged from audit_render._LIB_DISPLAY_NAMES ─────

_LIB_DISPLAY_NAMES = {
    "jquery":          "jQuery",
    "jquery-ui":       "jQuery UI",
    "jquery-mobile":   "jQuery Mobile",
    "jquery-migrate":  "jQuery Migrate",
    "bootstrap":       "Bootstrap",
    "font-awesome":    "Font Awesome",
    "modernizr":       "Modernizr",
    "moment":          "Moment.js",
    "moment-timezone": "moment-timezone",
    "angular":         "Angular",
    "angularjs":       "AngularJS",
    "wordpress":       "WordPress",
    "drupal":          "Drupal",
    "joomla":          "Joomla",
    "vue":             "Vue.js",
    "vuetify":         "Vuetify",
    "react":           "React",
    "preact":          "Preact",
    "ember":           "Ember.js",
    "backbone":        "Backbone.js",
    "underscore":      "Underscore.js",
    "knockout":        "Knockout.js",
    "polymer":         "Polymer",
    "lit":             "Lit",
    "alpinejs":        "Alpine.js",
    "htmx":            "htmx",
    "mithril":         "Mithril",
    "mootools":        "MooTools",
    "prototype":       "Prototype.js",
    "scriptaculous":   "script.aculo.us",
    "yui":             "YUI",
    "zepto":           "Zepto.js",
    "dojo":            "Dojo Toolkit",
    "ext":             "Sencha Ext JS",
    "swfobject":       "SWFObject",
    "tailwindcss":     "Tailwind CSS",
    "ant-design":      "Ant Design",
    "element-ui":      "Element UI",
    "element-plus":    "Element Plus",
    "material-ui":     "Material UI (legacy)",
    "mui":             "MUI",
    "ionic":           "Ionic",
    "ckeditor":        "CKEditor",
    "tinymce":         "TinyMCE",
    "lodash":          "Lodash",
    "axios":           "Axios",
    "three.js":        "Three.js",
    "d3":              "D3.js",
    "chart.js":        "Chart.js",
    "leaflet":         "Leaflet",
    "stripe":          "Stripe.js",
    "gsap":            "GSAP",
    "firebase":        "Firebase JS SDK",
    "core-js":         "core-js",
    "swiper":          "Swiper",
    "select2":         "Select2",
    "fancybox":        "Fancybox",
    "highcharts":      "Highcharts",
    "monaco-editor":   "Monaco Editor",
    "ace":             "Ace Editor",
    "codemirror":      "CodeMirror",
}


# Server-side tech display names — mirror of the keys in tech_eol.json.
_TECH_DISPLAY_NAMES = {
    "php":      "PHP",
    "asp.net":  "ASP.NET",
}


# Strong Referrer-Policy values — mirror of audit_checks.STRONG_REFERRER_POLICIES
_STRONG_REFERRER_POLICIES = {
    "no-referrer", "no-referrer-when-downgrade", "same-origin",
    "strict-origin", "strict-origin-when-cross-origin",
}


# Cert issuer expansions — short cryptic CNs that benefit from naming
# the issuing organisation alongside.
_CERT_ISSUER_EXPANSIONS = {
    "WE1": "WE1 (Google Trust Services)",
    "WE2": "WE2 (Google Trust Services)",
    "WR1": "WR1 (Google Trust Services)",
    "WR2": "WR2 (Google Trust Services)",
    "WR3": "WR3 (Google Trust Services)",
    "WR4": "WR4 (Google Trust Services)",
    "WR5": "WR5 (Google Trust Services)",
    "E1":  "E1 (Let's Encrypt)",
    "E2":  "E2 (Let's Encrypt)",
    "E5":  "E5 (Let's Encrypt)",
    "E6":  "E6 (Let's Encrypt)",
    "R3":  "R3 (Let's Encrypt)",
    "R10": "R10 (Let's Encrypt)",
    "R11": "R11 (Let's Encrypt)",
}


# ── Criticality ranking for the executive summary ─────────────────────────────
#
# The Possible Issues block in the executive summary is a flat priority list:
# the most consequential findings first, regardless of category. Items not in
# this map fall back to a default rank (placed after all named items, in their
# original rubric order). EOL OS and EOL libraries don't appear here as fixed
# labels because their actual labels include the OS/library name (e.g.
# "EOL OS: centos 7"); they're handled by a label-prefix check in the sort
# key — see _criticality_rank() below.
#
# Lower number = higher priority. Spread out so future inserts have room.
_CRITICALITY_RANK_TABLE = {
    # Every finding label in rubric.json has a rank here, and nothing else
    # (3.5.5; tests/test_reports.py checks both). Raw checks that are
    # merged into one finding (HSTS present → HSTS) are ranked under the
    # finding's label. Ranks need not be unique: equal ranks keep the
    # order the checks run in.

    # ── Tier 1: domain takeover / direct compromise ─────────────────────
    # EOL OS is handled separately (rank 5) by the prefix check in
    # _criticality_rank, since the label embeds the OS name.
    "SPF policy":                   10,   # +all = anyone can spoof
    "SPF single record":            11,   # two records = SPF ignored (permerror)
    "Dangling CNAME":               12,   # subdomain takeover
    "DMARC policy":                 13,   # p=none = no enforcement
    "DMARC single record":          14,   # two records = DMARC ignored
    "TLS connection":               15,   # TLS broken = users can't reach site safely
    "Certificate name match":       16,

    # ── Tier 2: enables phishing / MITM / takeover ──────────────────────
    "Legacy TLS disabled":          20,   # TLS 1.0 / 1.1 still accepted
    "DMARC pct":                    25,
    "DMARC sp":                     26,
    "DMARC rua reporting":          27,
    "DMARC external reports":       27,
    "SPF lookup count":             28,
    "SPF mechanisms":               28,
    "HSTS":                         30,
    "HSTS includeSubDomains":       31,
    "HSTS max-age":                 32,
    "HSTS preload":                 34,
    "MTA-STS":                      36,
    "MTA-STS policy MX match":      36,
    "MTA-STS max_age":              37,
    "TLS-RPT":                      37,
    "DANE TLSA on MX":              38,
    "STARTTLS-MX":                  39,
    "Forward secrecy":              40,
    "CAA records":                  42,   # any CA can issue for the domain
    "DNSSEC TLD signed":            43,
    "DNSSEC":                       44,
    "DNSSEC algorithm":             44,
    "Cert chain completeness":      45,
    "Certificate key size":         45,
    "Certificate signature":        45,
    "Cert covers www variant":      46,
    "Certificate lifetime":         47,
    "Certificate renewal":          47,   # about to lapse — same tier as lifetime
    "DKIM key strength":            48,
    "DKIM (common selectors)":      48,
    "Authoritative delegation":     49,   # lame NS = some users get NODATA/SERVFAIL
    "NS not open resolver":         50,   # DDoS-amp risk; not a takeover but real
    "MX targets not CNAMEs":        51,   # RFC 2181 violation; sending MTAs vary
    "MX targets are hostnames":     51,   # RFC 5321 violation
    "MX hosts resolve":             51,
    "MX reverse DNS":               52,
    "MX reverse DNS matches":       52,
    "Null MX on no-mail domain":    53,

    # ── Tier 3: defence-in-depth / hardening ────────────────────────────
    "SSL Labs grade":               54,
    "TLS 1.3":                      55,
    "HTTP→HTTPS redirect":          56,
    "www and apex resolve":         57,
    "www and apex unified":         57,
    "CSP script-src safety":        59,
    "CSP object-src":               60,
    "CSP base-uri":                 61,
    "Clickjacking protection":      62,
    "X-Content-Type-Options":       66,
    "Subresource Integrity":        67,
    "Mixed content (in-page)":      68,
    "CORS configuration":           70,
    "Default error page":           71,
    "Server header":                72,
    "X-Powered-By absent":          73,
    "Server clock accuracy":        74,
    "Cookie Secure":                75,
    "Cookie HttpOnly":              76,
    "Cookie SameSite":              77,
    "Cookie name prefixes":         78,

    # ── Tier 4: routing / availability ──────────────────────────────────
    # 3.5.5: above the optional headers (was the last tier), so a missing
    # IPv6 or a single nameserver comes before Referrer-Policy.
    "IPv4 RPKI":                    80,
    "IPv6 RPKI":                    81,
    "Nameserver RPKI":              81,
    "Mail server RPKI":             81,
    "IPv4 IRR/RIS":                 82,
    "IPv6 IRR/RIS":                 83,
    "IPv6":                         84,
    "Nameservers on IPv6":          85,
    "Mail servers on IPv6":         85,
    "Nameserver count":             86,
    "Nameserver networks":          86,
    "SOA timers":                   88,
    "HTTP version":                 89,
    "Redirect first-hop hygiene":   90,

    # ── Tier 5: optional headers and best-practice signals ──────────────
    "Referrer-Policy":             100,
    "Permissions-Policy":          101,
    "Cross-Origin-Opener-Policy":  102,
    "Cross-Origin-Resource-Policy": 103,
    "X-XSS-Protection deprecated": 104,
    "HPKP absent":                 104,
    "Expect-CT absent":            104,
    "security.txt":                106,
    "security.txt location":       106,
    "security.txt Canonical":      106,
    "HTTPS DNS record":            108,
    "BIMI":                        109,
    "Page language declared":      110,
}

# Default rank for a label not in the table — sorts after everything named.
# Every rubric label has a rank (tests/test_reports.py), so this only
# applies to a label added without one.
_CRITICALITY_DEFAULT_RANK = 500


def _criticality_rank(label):
    """Return the criticality rank for a finding label.

    EOL OS and EOL libraries both sort to the very top — both signal
    "running unpatched software" and are usually the most consequential
    issues a vendor has, ahead of email or TLS configuration. EOL OS
    edges ahead (rank 5) because a kernel-level CVE on an EOL OS is
    typically more urgent than a client-side library bug; EOL server-side
    tech (PHP / ASP.NET) sits at rank 6 — a whole unpatched runtime, more
    serious than a front-end library but narrower than the OS; EOL
    libraries sit at rank 8. All three rank above the most-critical Tier 1
    entries (SPF policy, DMARC, TLS connection) so EOL findings always
    lead the Possible Issues list when present.
    """
    if not label:
        return _CRITICALITY_DEFAULT_RANK
    # 3.5.5: a redirect target's email checks rank like the domain's own.
    if label.startswith("redirect target: "):
        label = label[len("redirect target: "):]
    if label.startswith("EOL OS:"):
        return 5
    if label.startswith("EOL tech:"):
        return 6
    if label.startswith("EOL library:"):
        return 8
    return _CRITICALITY_RANK_TABLE.get(label, _CRITICALITY_DEFAULT_RANK)


# ── Subsection explanations (shown in detail sections) ────────────────────────
#
# Internet.nl-style "what / why / fix" copy attached to each subsection. Read
# by the txt renderer (injected after the _subheading line) and by the HTML
# renderer (rendered as a small explanation panel under the section summary).
#
# Keys are stable identifiers used by the renderers. Each entry has:
#   what  — one sentence: what this control is.
#   why   — one sentence: why a vendor should care.
#   fix   — one sentence: what to do if it's missing or weak.
# Keep each line under ~140 characters so they wrap cleanly in the
# terminal and don't require a second wrap on a typical browser width.
EXPLANATIONS = {
    "spf": {
        "what": "SPF is a DNS record that lists which mail servers are allowed to send email using your domain.",
        "why":  "Without enforcement, anyone can spoof your domain in phishing emails — recipients can't tell a forgery from a real message.",
        # 3.5.1: the no-mail case on a line of its own (the page shows the
        # line break; the text report gives it its own line).
        "fix":  "Publish a v=spf1 record that lists your senders and ends with -all.\nA domain that sends no mail needs \"v=spf1 -all\".",
        "details": [
            "Sender Policy Framework (SPF, RFC 7208) is published as a DNS TXT record on your domain. When a receiving mail server gets a message claiming to be from your domain, it can read the SPF record and check whether the sending IP appears on your authorised list. If it doesn't, the receiver applies whatever policy your record's qualifier specifies.",
            "The qualifier — the symbol before all in the record — is what determines what receivers actually do. -all means hard fail (reject). ~all means soft fail (accept but mark, often spam-folder). ?all is neutral (no opinion). +all is permissive (anyone can send, almost certainly a misconfiguration). Only -all and a properly-published null sender (v=spf1 -all) on a non-sending domain are considered fully enforcing.",
            # 3.4.6: a (heading, text) pair renders as a short titled paragraph.
            ("Domains that don't send email.",
             "A domain that never sends email still needs SPF. Parked, redirect-only and brand-protection domains look legitimate to recipients, and attackers pick them because nobody watches them. Publish three records: v=spf1 -all as SPF (no server may send for the domain), a null MX of 0 . (RFC 7505: the domain accepts no mail), and a DMARC record of v=DMARC1; p=reject (receivers reject anything claiming to come from it). Together they tell every receiver that mail from this domain is always forged."),
            "SPF has a well-known limitation: each include= or redirect= mechanism counts toward a hard cap of 10 DNS lookups per evaluation (RFC 7208 §4.6.4). Exceeding the cap causes receivers to treat the result as PermError and silently fail mail. If you use several SaaS providers (marketing, transactional, helpdesk) you can hit this quickly — flatten or consolidate via a SPF management service if you do.",
            "SPF alone does not survive forwarding. When a mailing list or auto-forward rewrites the message, the original sender's SPF check fails for the new envelope sender. This is why DKIM and DMARC together cover what SPF can't — they sign the message itself, not just authorise the IP. A modern email-authentication setup uses all three.",
        ],
    },
    "dmarc": {
        "what": "DMARC tells receiving mail servers what to do when an email claiming to be from your domain fails SPF or DKIM checks.",
        "why":  "Without DMARC at p=reject, receivers cannot reliably reject spoofed mail claiming to be from your domain — exactly the foothold phishing campaigns rely on.",
        "fix":  "Publish a DMARC record with p=reject, pct=100, and a rua= reporting address so you also get visibility into spoofing attempts.",
        "details": [
            "Domain-based Message Authentication, Reporting, and Conformance (DMARC, RFC 7489) is published as a DNS TXT record at _dmarc.<domain>. It binds together SPF and DKIM and tells receivers what to do when a message fails both — reject it, quarantine it, or just observe (none).",
            "Deployment is typically a progression. Operators start at p=none with rua= reporting enabled to gather data on what's sending mail under their domain (legitimate or otherwise). After a few weeks of reports, they identify and authorise legitimate senders, then move to p=quarantine (spam-folder) and finally p=reject (drop). Jumping straight to p=reject without observation usually breaks something legitimate — newsletters, ticketing systems, payroll mail.",
            "A few directives matter beyond the policy itself. pct= sets the percentage of failing mail the policy applies to (anything less than 100 is partial enforcement). sp= sets the policy for subdomains; without it, attackers can spoof random.<your-domain> and your main policy doesn't apply. rua= names the address(es) to receive aggregate XML reports — without it you have no visibility into what's hitting your domain.",
            "DMARC enforces alignment, not just authentication. SPF must pass for the envelope-from domain that aligns with the From: header domain (relaxed alignment is the common default). DKIM must pass on a signature whose d= domain aligns with the From: header. A message can pass SPF for some other domain and still fail DMARC because the domains don't align — this is the property that actually stops spoofing.",
        ],
    },
    "dkim": {
        "what": "DKIM adds a cryptographic signature to outgoing mail so receivers can verify the message was authorised by your domain.",
        "why":  "DKIM is one of the two pillars (with SPF) that DMARC relies on; without it, legitimate forwarded mail tends to fail authentication and bounce.",
        "fix":  "Generate a DKIM key with your mail provider and publish the public key as a DNS TXT record at <selector>._domainkey.<domain>.",
        "details": [
            "DomainKeys Identified Mail (DKIM, RFC 6376) signs outgoing mail with a private key held by your mail-sending infrastructure. The public key is published in DNS, so any receiving server can verify the signature without contacting you. The signature covers the message body and selected headers — if either is altered in transit, verification fails.",
            "Each signing key is identified by a selector, a short label your mail provider chooses. The DNS record lives at <selector>._domainkey.<domain>. Most providers choose semi-arbitrary selector names (google, default, mail, k1, selector1, etc.), so detection by external tools is heuristic — Vendor Audit probes the most common selectors and reports what it finds.",
            "Key strength matters. NIST SP 800-131A has disallowed RSA keys under 2048 bits for new signatures since 2014, and RFC 8301 (2018) recommends 2048 bits for DKIM while still accepting 1024 as the minimum. Modern best practice is RSA-2048 or higher, or the more efficient Ed25519. M3AAWG's DKIM Key Rotation Best Common Practices recommends rotating keys roughly every six months, which the selector mechanism makes easy: publish a new key under a new selector, switch your signer to it, retire the old selector after a propagation window.",
            "DKIM survives forwarding because the signature travels with the message. SPF doesn't, because the envelope changes. This is why DMARC requires either SPF or DKIM to pass with alignment — DKIM is the one that holds up when a mailing list or corporate gateway rewrites the path.",
        ],
    },
    "mta_sts": {
        "what": "MTA-STS publishes a policy telling sending mail servers they must use TLS when delivering mail to your domain.",
        "why":  "Without it, an attacker between mail servers can downgrade the connection to plaintext (STARTTLS stripping) and read or alter messages.",
        "fix":  "Publish a TXT record at _mta-sts.<domain> and host an MTA-STS policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode=enforce.",
        "details": [
            "Mail Transfer Agent Strict Transport Security (MTA-STS, RFC 8461) is the SMTP equivalent of HSTS for the web. It tells sending mail servers that mail to your domain must be delivered over a TLS-encrypted connection to a host whose certificate matches one of your declared MX hostnames.",
            "Deployment has two parts. First, a DNS TXT record at _mta-sts.<domain> with v=STSv1; id=<unique-id> tells senders a policy exists and gives an identifier they can cache against. Second, an HTTPS-served policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt declares the actual MX hostnames and the mode (none / testing / enforce). The HTTPS host itself must be reachable and present a valid publicly-trusted certificate — that's how senders verify the policy is authentic.",
            "The mode= directive controls behaviour. mode=none disables the policy temporarily. mode=testing means senders should report failures via TLS-RPT but still deliver. mode=enforce means senders should refuse to deliver if the TLS or hostname checks fail. Most operators start in testing for several weeks while observing reports, then promote to enforce.",
            "MTA-STS is best paired with TLS-RPT (RFC 8460). MTA-STS without reporting means downgrade attacks happen silently — the policy fires, mail is rejected, and you learn about it from a customer ticket two days later. With TLS-RPT you get aggregate reports of every TLS failure, including which sender saw it and what error code came back.",
        ],
    },
    "tls_rpt": {
        "what": "TLS-RPT (SMTP TLS Reporting) gives your domain visibility into mail-delivery TLS failures observed by receiving servers.",
        "why":  "Without TLS-RPT, you can't tell if MTA-STS is being honoured or if downgrade attacks are happening — you're operating blind.",
        "fix":  "Publish a TXT record at _smtp._tls.<domain> with v=TLSRPTv1; rua=mailto:<reporting-address>.",
        "details": [
            "SMTP TLS Reporting (TLS-RPT, RFC 8460) is the feedback channel for mail-transport security. It lets sending mail servers tell you, after the fact, when TLS or MTA-STS failed for messages bound for your domain. Reports are sent as JSON, typically once a day per sender, and are aggregated rather than per-message.",
            "The DNS record is small: a TXT record at _smtp._tls.<domain> with v=TLSRPTv1; rua=mailto:<address> (or rua=https://<endpoint> if you have a webhook receiver). Most operators point rua at an inbox they monitor or at a TLS-RPT processing service that aggregates and surfaces patterns.",
            "TLS-RPT is most valuable when paired with MTA-STS. The combination gives you both a policy senders should follow and a feedback loop telling you when they don't. Running MTA-STS without TLS-RPT means you've published a policy whose violations are invisible to you — exactly the state of operating blind that the policy was meant to fix.",
        ],
    },
    "bimi": {
        "what": "BIMI (Brand Indicators for Message Identification) lets mailbox providers display your brand's logo beside your authenticated messages in the inbox.",
        "why":  "BIMI improves brand recognition and trust in the inbox, but only renders if DMARC is at enforcement (p=quarantine or p=reject) — publishing BIMI without enforcing DMARC does nothing.",
        "fix":  "Publish a TXT record at default._bimi.<domain> with v=BIMI1; l=<https logo URL>; a=<https VMC URL>, and ensure your DMARC policy is at quarantine or reject.",
        "details": [
            "BIMI is a standard for showing a verified brand logo next to messages that pass authentication. It's published as a TXT record at default._bimi.<domain> in the form v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem. The l= tag points at the logo — an SVG in the restrictive 'Tiny PS' profile (no scripts, no external references, square aspect). The a= tag points at a Verified Mark Certificate (VMC) or Common Mark Certificate (CMC), a cryptographic proof that the brand owns the trademark on the logo.",
            "BIMI's single hard prerequisite is DMARC at enforcement. Mailbox providers will not display a BIMI logo for a domain whose DMARC policy is p=none — the whole point is that the logo only appears on mail that's provably authentic, and p=none means the domain isn't yet asking receivers to act on authentication failures. A BIMI record on a p=none domain is published but inert: it will never render. This is the most common BIMI misconfiguration, and Vendor Audit flags it specifically by cross-referencing your DMARC policy.",
            "The VMC is where BIMI gets expensive and slow. Gmail and Apple Mail both require a VMC (issued by a handful of CAs after a trademark-verification process that can take weeks and costs on the order of a thousand dollars a year) before they'll show the logo. Some other providers display the logo from the l= SVG alone. So there are three tiers: no BIMI, BIMI with logo only (renders in some clients), and BIMI with logo + VMC (renders in Gmail and Apple Mail). The audit reports which tier you're in.",
            "BIMI is optional, so a domain with no BIMI record gets an informational note, never a finding. A domain that has published a logo but has not reached DMARC enforcement gets a Low finding: the BIMI work is done, the logo will not display, and the remaining fix is on the DMARC side.",
        ],
    },
    "mx": {
        "what": "MX (Mail Exchanger) records in DNS list the servers that receive mail for your domain.",
        "why":  "Every domain should publish an MX record — receiving mail if it does, or a Null MX (RFC 7505) if it doesn't, so attackers can't claim mail authority for it through the absence of a policy.",
        "fix":  "Publish MX records pointing to your mail provider, or — if the domain sends/receives no mail — publish a Null MX (a single MX record with priority 0 and target \".\") per RFC 7505.",
        "details": [
            "MX records are the directory entry that tells the world which servers receive mail for your domain. They're consulted before any SMTP delivery: a sender looks up MX <your-domain>, picks the lowest-priority record, and connects to that host. Each MX entry is a (priority, hostname) pair; lower priority is preferred, with secondaries used as fallback.",
            "A domain that sends or receives mail must publish MX records. A domain that does neither — many marketing domains, redirect-only domains, brand-protection registrations — should publish a Null MX (RFC 7505): a single MX record with priority 0 and the target \".\" (a literal period). This tells the world authoritatively that the domain refuses all mail and lets receivers reject delivery attempts immediately rather than timing out.",
            "Without an MX record, sending servers fall back to the A or AAAA record of the apex domain (RFC 5321 §5.1) — meaning your web server suddenly fields SMTP traffic. That's never desirable: at best it's wasted load, at worst it accepts mail you can't see. A Null MX prevents that fallback path entirely.",
            "Multiple MX records with different priorities give you geographic and provider redundancy. Two records at priority 10 and 20 mean senders prefer the priority-10 host but fall back to priority-20 if it's unreachable — useful for split between primary and secondary mail providers, or between regions of the same provider.",
        ],
    },
    "mail_transport": {
        "what": "Mail-transport hardening (MTA-STS, TLS-RPT, DKIM, DANE, STARTTLS) protects email in transit between mail servers.",
        "why":  "Without these, mail can be intercepted in plaintext, signatures can be stripped, and downgrade attacks are undetectable.",
        "fix":  "Publish MTA-STS in enforce mode, a TLS-RPT reporting endpoint, and a DKIM signing key; use a mail provider that supports DANE if possible.",
        "details": [
            "Email's transport story has improved a lot in the past decade, but the underlying SMTP protocol is still optimistic about encryption: STARTTLS upgrades a plaintext connection only if both ends opt in, and a network attacker can strip the STARTTLS advertisement from the server response and force fallback to plaintext. Mail-transport hardening is the layered set of standards that closes that gap.",
            "MTA-STS (RFC 8461) and DANE (RFC 7672) both make the TLS expectation explicit. MTA-STS publishes a policy via HTTPS that senders fetch and cache; DANE publishes TLSA records in DNSSEC-signed DNS that senders verify directly against the certificate. DANE is stronger (no caching window, cryptographic provenance) but requires DNSSEC. Most operators start with MTA-STS because it's deployable without DNSSEC.",
            "TLS-RPT (RFC 8460) sits alongside both as the feedback channel. DKIM (RFC 6376) is the message-signing layer that survives forwarding. Together: STARTTLS + MTA-STS or DANE + TLS-RPT + DKIM gives you an in-transit story where downgrades are detectable, message tampering is detectable, and impersonation requires breaking cryptography rather than just spoofing an IP.",
        ],
    },
    "dnssec": {
        "what": "DNSSEC cryptographically signs your DNS records so resolvers can verify they haven't been tampered with in transit.",
        "why":  "Without DNSSEC, an attacker on the network path can poison DNS responses and redirect users to attacker-controlled servers.",
        "fix":  "Enable DNSSEC at your registrar and DNS provider; both must support it and the chain must be published to the parent zone.",
        "details": [
            "DNS Security Extensions (DNSSEC, RFC 4033 and successors) add cryptographic signatures to DNS records. A resolver that supports DNSSEC validation can verify that the answer it received came from the authoritative nameserver and wasn't modified along the way. Without DNSSEC, any on-path attacker — a hostile WiFi gateway, a compromised ISP router, or a state actor — can substitute their own IP for yours and the user's browser has no way to tell.",
            "The validation chain has three pieces. The TLD must be signed (most are now — .com, .org, .gov, .net, .uk, .de, the IETF-managed ones). Your domain must publish a DNSKEY record. And a Delegation Signer (DS) record must be published in the parent zone, linking the parent's signing chain to your DNSKEY. If any link is broken, the chain doesn't validate and resolvers fall back to unauthenticated DNS — defeating the protection entirely.",
            "Vendor Audit checks the chain by querying for the AD (Authenticated Data) flag on the response. The AD flag is set by a validating resolver when every signature in the chain checks out. A missing AD flag with a present DNSKEY usually means the DS record at the parent is missing or stale — a common mistake when a domain is migrated to a new DNS provider but the registrar's DS record points at the old provider's keys.",
            "Enabling DNSSEC is usually a one-click operation at modern registrars and DNS hosts; the registrar publishes the DS at the TLD when you turn it on. The harder part is keeping it healthy: key rollovers must be coordinated between DNS provider and registrar, and an expired or mismatched DS record makes the domain unresolvable for validating users.",
        ],
    },
    "caa": {
        "what": "CAA records tell certificate authorities which CAs are allowed to issue certificates for your domain.",
        "why":  "Without CAA, any of hundreds of trusted public CAs can issue a certificate for your domain — a single compromised CA is enough.",
        "fix":  "Publish a CAA record listing your authorised CA(s), e.g. 0 issue \"letsencrypt.org\" and 0 issuewild \"letsencrypt.org\".",
        "details": [
            "Certification Authority Authorization (CAA, RFC 8659) is a DNS record that constrains which CAs are allowed to issue TLS certificates for your domain. Public CAs are required by the CA/Browser Forum Baseline Requirements to check CAA before issuing — if a non-authorised CA tries, the issuance must be refused.",
            "A typical record set has issue tags listing CAs that may issue any certificate, and issuewild tags listing CAs that may issue wildcards. For example: 0 issue \"letsencrypt.org\" and 0 issuewild \"letsencrypt.org\". An issue \";\" record (with a single semicolon target) explicitly forbids issuance entirely — useful for parked domains.",
            "When using ACME, you can tighten further with the validationmethods and accounturi parameters. validationmethods=http-01 restricts the CA to a specific challenge type; accounturi=<url> binds issuance to a specific ACME account. This prevents an attacker who briefly controls DNS or a webroot from issuing under your domain via a different account.",
            "A few extra tags are worth including. issuemail \";\" and issuevmc \";\" forbid S/MIME and BIMI certificate issuance respectively if you don't use them — without these, the absence of issue-tag fallback rules in the spec means any CA can still issue those certificate types. iodef can name a contact (mailto: or https://) where CAs send notifications about policy violations they observed.",
        ],
    },
    "nameservers": {
        "what": "Authoritative nameservers should answer authoritatively, should not also serve recursion, and there should be more than one of them.",
        "why":  "DNS is the gate to every other service — a single nameserver is a single point of failure for the whole domain, a lame nameserver returns errors for some users, and an open recursive nameserver is abusable for DNS amplification DDoS.",
        "fix":  "Use a managed DNS provider, or run authoritative-only nameserver software (refuse recursion from clients outside your network). Have at least two nameservers.",
        "details": [
            "RFC 1034 (1987) requires every domain to have more than one authoritative nameserver. The reason hasn't changed: a single point of failure for DNS is a single point of failure for the whole domain — mail, web, APIs all stop working if name resolution fails.",
            "Each nameserver listed at the parent registry must actually answer authoritatively for the zone (RFC 1034 §4.2). A nameserver that's listed in delegation but doesn't serve the zone is \"lame\" — a common artefact of moving DNS providers and forgetting to update the registrar's NS records. Users routed to a lame nameserver (which one depends on their resolver) get SERVFAIL or NODATA instead of the real answer.",
            "Authoritative nameservers should not also serve recursion to arbitrary clients (RFC 5358 / BCP 140). An authoritative-recursive nameserver is usable as a reflector in DNS amplification DDoS attacks — the attacker spoofs the victim's source IP, sends a small query, and the nameserver sends a much larger response to the victim. Authoritative-only software (or recursion restricted to internal clients) closes the reflector.",
            "While not checked by Vendor Audit, nameserver diversity matters for the redundancy requirement to actually deliver redundancy. Two nameservers in the same datacentre or same AS give resilience against process crashes but not against network outages at that provider; RFC 2182 has specific guidance on geographic, network, and ISP diversity for self-hosted secondaries. Modern managed DNS services (Cloudflare, Route 53, Google Cloud DNS, NS1) handle this automatically with anycast across global infrastructure.",
        ],
    },
    "tls": {
        "what": "Modern TLS (1.3 preferred, 1.2 acceptable) protects all HTTPS traffic between visitors and your server.",
        "why":  "Older TLS versions and weak ciphers leave traffic vulnerable to interception and tampering by anyone on the network path.",
        "fix":  "Enable TLS 1.3 in your web server; disable TLS 1.0/1.1 and any cipher suites flagged by SSL Labs as weak.",
        "details": [
            "Transport Layer Security (TLS) is the encryption layer underneath HTTPS. TLS 1.3 (RFC 8446, 2018) is the current standard — it removed every cipher suite the older versions had cryptographic weaknesses in, simplified the handshake to a single round-trip, and made forward secrecy mandatory. TLS 1.2 (RFC 5246) is still widely deployed and acceptable; TLS 1.0 and 1.1 are formally deprecated by RFC 8996 and should be disabled.",
            "Vendor Audit verifies the TLS version negotiated during the handshake, the certificate's name match against the requested host, the certificate lifetime, and chain completeness. Specific cipher-suite probing (which suites the server accepts, key-exchange parameters, named-CVE conditions like POODLE or ROBOT) is not part of this audit by design — that's what the Qualys SSL Labs assessment is for.",
            "If you want a comprehensive TLS configuration review, run the SSL Labs assessment at https://ssllabs.com/ssltest/. It probes every cipher suite the server accepts, reports forward-secrecy support, flags named vulnerabilities, and gives a letter grade. Modern stacks (recent nginx, Apache, Cloudflare, Caddy, AWS ALB) configured with the Mozilla Intermediate or Modern profile typically score A or A+ without further tuning.",
            "Certificate lifetime is now an enforcement point in its own right. Under the CA/Browser Forum's Ballot SC081v3, the maximum lifetime stepped down from 398 days to 200 days on March 15, 2026; it drops to 100 days on March 15, 2027 and to 47 days on March 15, 2029. Short-lived certificates with automated renewal (ACME / Let's Encrypt) are the only path that scales at the 47-day endpoint; manually-renewed certificates are already strained at 200 days and won't be viable at 100. Vendor Audit reads a lifetime of 91 days or less as automated issuance — ACME certificates run 90 days or shorter, down to about six days — and anything longer as a sign of manual renewal. It also checks renewal headroom: a certificate with under 10% of its lifetime left should already have been replaced, whatever its length, because automated clients renew with a third to a half of the lifetime remaining.",
        ],
    },
    "hsts": {
        "what": "HTTP Strict Transport Security tells browsers to only ever connect to your site over HTTPS, even if the user types http://.",
        "why":  "Without HSTS, attackers can intercept the first plain-HTTP request and downgrade the user to an unencrypted session (SSL stripping).",
        "fix":  "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload and submit your domain to hstspreload.org.",
        "details": [
            "HTTP Strict Transport Security (HSTS, RFC 6797) closes a small but important gap: the first plain-HTTP request from a user who types example.com instead of https://example.com. Without HSTS, that request goes out unencrypted; an attacker on the network path can intercept the redirect to HTTPS, strip it, and serve the site over HTTP indefinitely. HSTS tells the browser to remember a domain as HTTPS-only for a configurable period, so subsequent visits skip the plaintext step entirely.",
            "Deployment has three components. max-age sets how long the browser remembers (in seconds; 63072000 = two years is the modern recommendation). includeSubDomains extends the policy to every subdomain — important, but only safe to enable if every subdomain genuinely supports HTTPS. preload requests inclusion in the HSTS Preload List, which ships with Chrome, Firefox, Safari, and Edge — meaning even the very first visit to your domain gets HSTS protection without ever having visited.",
            "Preload is one-way: once your domain is on the list, removing it is slow (months) and reaching every browser version is impossible. Before submitting to hstspreload.org, make absolutely sure every subdomain works over HTTPS, your renewal process is solid, and you don't plan to ever revert. For most production domains this is fine; for development or experimental subdomains it can be a footgun.",
            "A common HSTS configuration error is sending the header only after a redirect from http://. Browsers respect HSTS only when received over HTTPS — so the header on the post-redirect HTTPS response works, but if the user's plain-HTTP request hits a server that doesn't redirect (or that serves the header on the HTTP response and not the HTTPS response), the policy never lands. Verify with curl -I https://<domain> that the header appears on the HTTPS response itself.",
        ],
    },
    "http_redirect": {
        "what": "Plain HTTP requests should redirect to HTTPS so users are never served content over an unencrypted channel.",
        "why":  "Without redirect, content served over HTTP can be read or modified by anyone on the network — including injected malicious scripts.",
        "fix":  "Configure your web server to 301-redirect all http:// URLs to their https:// equivalents.",
        "details": [
            "Every modern HTTPS deployment should redirect plain-HTTP requests to HTTPS. Without the redirect, anyone on the network path between the user and your server can read or alter the response — and in practice this means injecting tracking, ads, or hostile JavaScript into pages that should have been encrypted. Public WiFi, hotel networks, and (historically) some ISPs have all done this at scale.",
            "The redirect should happen on the same hostname before any cross-host redirect. http://example.com should go to https://example.com, not directly to https://www.example.com. Why? Because HSTS is set on the host the browser landed on first — if you skip the same-host hop, the browser never sees an HSTS header for the apex domain and the next plain-HTTP request to example.com is again unprotected.",
            "Use 301 (Moved Permanently) rather than 302 — browsers cache 301s aggressively, which means subsequent visits skip the plaintext request entirely even before HSTS kicks in. Some bot-mitigation layers and CDNs return non-redirect responses on port 80 (a 404 or a connection reset) which technically means there's no plain-HTTP exposure, but most automated audits flag it as a missed redirect because the standard expectation is a 301.",
        ],
    },
    "http": {
        "what": "This section covers HTTP transport: HTTP/2 and HTTP/3 support, plain-HTTP→HTTPS redirect, first-hop redirect hygiene, and apex/www unification.",
        "why":  "Modern protocols are faster and more reliable; missing HTTPS redirects let attackers serve content unencrypted; off-host first hops leak Referer and bypass HSTS; split apex/www forms leave users with DNS errors or split-brain sites.",
        "fix":  "Enable HTTP/2 and HTTP/3 in your server or CDN; ensure http://<domain> 301-redirects directly to https://<domain> on the same host; publish A/AAAA records for both the apex and www and 301-redirect one form to the other.",
        "details": [
            "The HTTP transport layer has evolved significantly since HTTP/1.1 was standardised in 1997. HTTP/2 (RFC 7540 in 2015, updated by RFC 9113 in 2022) introduced multiplexing — many requests over a single TCP connection — which fixed head-of-line blocking and dramatically reduced page load times for resource-heavy sites. HTTP/3 (RFC 9114, 2022) replaced TCP with QUIC over UDP, fixing head-of-line blocking at the transport layer too and reducing handshake latency on lossy networks like mobile and satellite.",
            "Enabling these is essentially free for most operators: nginx, Apache, Caddy, IIS and every major CDN support HTTP/2 with a one-line config change. HTTP/3 needs UDP allowed through your firewall but otherwise drops in the same way. There's no compatibility downside — clients fall back to HTTP/1.1 transparently if the newer versions aren't advertised.",
            "First-hop redirect hygiene is the small but important detail of redirecting users to HTTPS on the same host before redirecting anywhere else. http://example.com should land on https://example.com, which can then redirect to https://www.example.com. Skipping that step (going straight to the www variant) means the apex domain never gets an HSTS header for the user's browser, leaving the next plain-HTTP visit to example.com unprotected.",
            "The apex (example.com) and www (www.example.com) forms of your domain should resolve to one canonical site. Mozilla's web-deployment guidance is that a domain picks one canonical hostname (either form is fine) and the other variant redirects to it. When the two forms aren't unified, users who type the variant you didn't plan for get either a DNS error (if one form has no A/AAAA records) or a separate split-brain site (if both serve content but neither redirects). If your registrar doesn't support apex-level aliasing (ALIAS / ANAME / CNAME-flattening), a free static redirector pointing the apex at the www site is the usual fix.",
        ],
    },
    "http_version": {
        "what": "The HTTP versions the site offers: HTTP/1.1, HTTP/2 or HTTP/3.",
        "why":  "HTTP/1.1 marks where a request ends in two ambiguous ways, so when a proxy or CDN and the server behind it disagree, an attacker can smuggle a hidden request through (request smuggling, or desync) to hijack other visitors' responses, poison caches or slip past security controls. HTTP/2 and HTTP/3 frame every request exactly; HTTP/3 is also faster on mobile and high-latency links.",
        "fix":  "Enable HTTP/2 and HTTP/3 at the web server or CDN, and use HTTP/2 between any proxy or CDN and the origin server as well.",
        "details": [
            "HTTP/2 (originally RFC 7540 in 2015, current revision RFC 9113 in 2022) and HTTP/3 (RFC 9114, 2022) are the modern HTTP transports. HTTP/2 multiplexes many requests over a single TCP connection, eliminating the connection-pool overhead of HTTP/1.1 and the artificial sharding workarounds (multiple subdomains, sprite sheets) sites used to need. HTTP/3 takes the same idea to UDP via QUIC, improving handshake latency and resilience to packet loss.",
            "PortSwigger's 2025 research \"HTTP/1.1 must die: the desync endgame\" (http1mustdie.com) showed request-smuggling attacks still working against major CDNs and sites, and concluded that the only reliable fix is to stop using HTTP/1.1 between proxies and servers. This audit sees only the connection visitors make, so a site offering HTTP/2 here may still use HTTP/1.1 behind its CDN; a site offering only HTTP/1.1 almost certainly does.",
            "Vendor Audit detects HTTP/2 by the negotiated ALPN protocol on the TLS handshake, and HTTP/3 by the presence of an Alt-Svc header on the response advertising h3. Some servers support HTTP/3 but don't advertise it via Alt-Svc — in those cases the audit will report HTTP/3 as not advertised even though it works.",
            "Enabling them in your server stack is usually trivial: nginx 1.25+ ships HTTP/3 behind a flag; Apache via mod_http2 and mod_http3; Caddy enables both by default; and every major CDN (Cloudflare, Fastly, Akamai, AWS CloudFront) supports both transparently. There's no compatibility risk: clients negotiate down to HTTP/1.1 if needed.",
        ],
    },
    "server_disclosure": {
        "what": "The Server and X-Powered-By headers can reveal the exact software and version running on your server.",
        "why":  "Disclosure helps attackers match your server to known vulnerabilities and saves them time when targeting your stack specifically.",
        "fix":  "Configure your web server to suppress or genericise these headers (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
        "details": [
            "The Server response header was originally meant to identify the web server software for diagnostic purposes. In practice it's now a fingerprint that helps attackers narrow their tooling — a Server: Apache/2.4.41 (Ubuntu) header tells anyone scanning the internet exactly which CVE list applies and what default paths to probe. The OWASP information leakage guidance recommends suppressing or genericising it.",
            "X-Powered-By is the same problem one layer up: a header advertising PHP/7.4.3 or ASP.NET/4.8 invites application-level attacks. Most application frameworks emit it by default and most operators forget to disable it. Removing it costs nothing and tells you nothing useful about your own deployment that isn't already in the logs.",
            "A reasonable middle ground is to keep a generic Server: nginx without the version, or to suppress entirely. Some load balancers and CDNs override the header to identify themselves (Server: cloudflare); that's defensible because the CDN is the attack surface anyway and has its own hardening, but the origin should still suppress its own identification.",
            "Vendor Audit also reports detected technology stacks (Drupal, WordPress, etc.) inferred from response headers and HTML markers. These detections aren't scored — they're informational, useful when correlating with known vulnerabilities or with the EOL library check.",
        ],
    },
    "csp": {
        "what": "Content Security Policy is a header telling the browser which sources of scripts, styles, and other resources are allowed to load.",
        "why":  "If any other vulnerability allows script injection on your site, a strong CSP is what limits the damage.",
        "fix":  "Start with Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none' and tighten further; avoid 'unsafe-inline'.",
        "details": [
            "Content Security Policy (CSP, W3C standard) is a defence-in-depth layer for cross-site scripting (XSS). It doesn't prevent XSS bugs from existing in your code — that's input validation's job — but it constrains what an injected script can actually do. A well-configured CSP can downgrade a remote-code-execution XSS to a no-op because the browser refuses to load the attacker's payload.",
            "The most important directives are script-src, object-src, base-uri, frame-ancestors, and form-action. script-src controls where JavaScript can come from — the strongest configurations use a per-request nonce or content hash with 'strict-dynamic'. object-src 'none' blocks legacy plugin content (Flash, Java applets) which has been a perennial source of CSP bypasses. base-uri restricts the <base> tag, which can otherwise rewrite all relative URLs in a page. frame-ancestors is the modern replacement for X-Frame-Options.",
            "Common pitfalls: 'unsafe-inline' in script-src defeats most of CSP's value (it permits inline <script> blocks, which is exactly what most XSS injects). data: URLs in script-src or object-src likewise allow attacker-controlled inline payloads. Wildcard sources (*) or scheme-only sources (https:) are too permissive for production. The Google CSP Evaluator at https://csp-evaluator.withgoogle.com/ is excellent for catching these.",
            "Roll out incrementally with Content-Security-Policy-Report-Only, which logs violations to a reporting endpoint without blocking. Watch the reports for a few weeks, identify legitimate sources you missed, refine the policy, then switch to enforcing Content-Security-Policy. Don't try to write a perfect policy on the first attempt — incremental is the only way that doesn't break the site.",
        ],
    },
    "security_headers": {
        "what": "X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy harden the browser against common attack patterns.",
        "why":  "Each closes a specific class of vulnerability: clickjacking, MIME sniffing, referrer leakage, and unauthorised feature access.",
        "fix":  "Add all four headers in your web server config; sensible defaults are DENY, nosniff, strict-origin-when-cross-origin, and an empty Permissions-Policy.",
        "details": [
            "X-Frame-Options: DENY (or SAMEORIGIN) prevents your pages from being embedded in <frame>, <iframe>, <object>, or <embed> on other sites. This blocks clickjacking, where an attacker frames your login page transparently over their own UI and tricks the user into clicking on your form. CSP's frame-ancestors directive supersedes X-Frame-Options for modern browsers, but X-Frame-Options is still a defence for users on older browsers.",
            "X-Content-Type-Options: nosniff disables MIME-type sniffing. Browsers historically tried to guess the content type of a response when the Content-Type header was missing or generic — useful for legacy sites, but exploitable when an attacker can upload a file that gets served with a permissive content type. nosniff turns the guessing off; the browser uses the declared Content-Type or refuses to interpret the file.",
            "Referrer-Policy controls what's sent in the Referer header when a user clicks a link from your site. The default browser behaviour (strict-origin-when-cross-origin) sends only the origin to cross-origin destinations and the full URL to same-origin destinations. Stricter values like no-referrer or same-origin reduce information leakage further; weaker values like unsafe-url leak full URLs over HTTP and should never be used.",
            "Permissions-Policy (formerly Feature-Policy) controls which browser APIs your site can use — camera, microphone, geolocation, payment, USB, etc. An empty allowlist for sensitive features (geolocation=(), camera=()) means even an XSS injection can't trigger a permission prompt. This is mostly useful as a defence in depth: most sites don't need most APIs, and turning them off costs nothing.",
            "Two more headers worth setting: Cross-Origin-Opener-Policy: same-origin isolates your tab's browsing context from cross-origin pages, defending against tab-nabbing and Spectre-class attacks. Cross-Origin-Resource-Policy: same-origin (or same-site) prevents your resources from being loaded by cross-origin pages, blocking some categories of resource-timing side channels.",
        ],
    },
    "cookies": {
        "what": "Cookies should be marked Secure, HttpOnly, and SameSite, and ideally use the __Host- or __Secure- prefix.",
        "why":  "Missing flags leak session cookies over HTTP, expose them to JavaScript-based theft, or allow cross-site request forgery (CSRF).",
        "fix":  "When setting cookies, always include Secure; HttpOnly; SameSite=Lax (or Strict) and use the __Host- prefix for session cookies.",
        "details": [
            "The cookie attribute set has expanded significantly over the past decade. Secure prevents the cookie from ever being sent over a plain-HTTP connection, closing the leakage path even if HSTS hasn't yet been seen by the browser. HttpOnly prevents JavaScript from reading the cookie via document.cookie, blocking the most common XSS-to-session-theft chain. SameSite controls cross-site request inclusion, mitigating CSRF.",
            "SameSite has three values. Strict means the cookie is sent only on requests originating from the same site; this is the safest but breaks some cross-site flows like an OAuth callback. Lax sends the cookie on top-level cross-site GET navigations but not on POST or sub-resource requests; this is the modern default and balances security with usability. None requires the cookie to opt explicitly into cross-site contexts and forces Secure to be set.",
            "The __Host- and __Secure- name prefixes are commitments enforced by the browser. A cookie named __Host-session must have Secure, no Domain attribute, and Path=/ — the browser refuses to set the cookie if any of those are violated. This protects against subtle attacks where an attacker sets a same-named cookie from a sibling subdomain and the browser sends both to your application. For session cookies specifically, __Host- is the modern best practice.",
            "Vendor Audit observes only the cookies set on the homepage response. Cookies set after authentication or by JavaScript don't appear in this view. A clean homepage cookie audit doesn't guarantee all of your cookies are well-configured — but a flagged homepage cookie is a clear sign the application has at least one misconfigured cookie path.",
        ],
    },
    "security_txt": {
        "what": "A security.txt file at /.well-known/security.txt tells researchers how to report vulnerabilities they find on your site (RFC 9116).",
        "why":  "Without one, well-meaning researchers struggle to find a contact and may give up — the issue stays unreported and unfixed.",
        "fix":  "Publish a security.txt file with at least Contact: and Expires: fields; see securitytxt.org for a generator.",
        "details": [
            "security.txt (RFC 9116) is a small text file at /.well-known/security.txt that tells security researchers who to contact and how. It's the equivalent of robots.txt for vulnerability reporting — machine- and human-readable, with a small set of standardised fields. Researchers who find a bug in your site or systems can find a contact in seconds rather than rummaging through your website hoping to spot a security@ link.",
            "Required fields are Contact: (an email address, phone number, or URL — multiple are allowed) and Expires: (an ISO 8601 timestamp after which the file should not be trusted). Optional fields include Encryption: (a PGP key URL for encrypted reports), Policy: (a URL to your coordinated-disclosure policy), Acknowledgments: (a hall-of-fame URL), and Canonical: (the URL of the file itself, useful when redirected).",
            "Best practice: keep Expires: less than a year out and rotate it on a recurring basis (so a stale file doesn't go unnoticed indefinitely). Sign the file with PGP (the signature is inline, just the file contents wrapped in a PGP signature block). Place it at /.well-known/security.txt — the legacy /security.txt path still works but is deprecated.",
            "Generator at https://securitytxt.org/ produces a syntactically valid file with sensible defaults. The whole effort is typically 10 minutes of work, including PGP signing, and meaningfully shortens the time-to-fix for issues researchers report.",
        ],
    },
    "eol_os": {
        "what": "An end-of-life operating system no longer receives security patches from its vendor.",
        "why":  "Newly-discovered vulnerabilities — including remote code execution and privilege escalation — will never be fixed on this system.",
        "fix":  "Upgrade to a supported OS version. If business constraints require staying on this version, isolate it heavily and document the risk.",
        "details": [
            "Operating systems have defined support lifecycles after which their vendors stop releasing security updates. Once an OS is end-of-life, every newly-discovered kernel, library, or service vulnerability is permanent — no patch will ever be issued, and any exploit becomes a zero-day for the lifetime of the deployment.",
            "Vendor Audit infers the OS from what the web server volunteers. An IIS version maps to one Windows Server release. A distro named in the Server header (\"Apache/2.4.29 (Ubuntu)\") is resolved to a release from the package version, because distributions freeze the upstream version for the life of a release: Apache 2.4.29 shipped in Ubuntu 18.04 and nowhere else. A distro-packaged PHP version (\"PHP/7.3.31-1~deb10u5\") names the release outright. The release is then compared with its end-of-support date; those dates come from endoflife.date and are checked against today's date on every audit, so a release is flagged from the day its support ends.",
            "Detection is best-effort. Sites behind Cloudflare, Akamai, or AWS CloudFront usually return the CDN's Server header, masking the origin entirely — the audit can't see what's running underneath. Some operators set the Server header to a custom string for the same reason. A clean EOL OS check on a CDN-fronted site means the audit couldn't determine the origin OS, not that the origin is supported.",
            "The date used is the end of free security support: Ubuntu standard support, Debian LTS, RHEL maintenance support, Windows extended support. Paid extensions (Ubuntu Pro / ESM, RHEL ELS, Debian ELTS, Windows ESU) keep patches flowing for a few more years, and the audit cannot see from outside whether a server has one. Where one is still on sale the finding says so. If this server is covered, the finding does not apply; a paid extension is a bridge while migrating, not a permanent position.",
        ],
    },
    "eol_libraries": {
        "what": "An end-of-life client-side library (jQuery, Bootstrap, Angular, etc.) no longer receives security or compatibility updates.",
        "why":  "Browser environments evolve constantly; an unmaintained library is increasingly likely to break or harbour known XSS vulnerabilities.",
        "fix":  "Upgrade to the current major version of the library, or migrate to a supported alternative.",
        "details": [
            "Client-side JavaScript libraries have their own support lifecycles — usually shorter than operating systems, often 18-36 months from a major release. jQuery, Bootstrap, Angular, Vue, Ember, the WordPress / Drupal / Joomla CMSes, and many smaller libraries publish a support policy that names which majors still receive security fixes.",
            "Vendor Audit recognises about 185 client-side libraries and CMSes via static HTML inspection — script src attributes, inline version markers, generator tags. About 50 of them have end-of-life data: release dates from endoflife.date where the project publishes a support policy (jQuery UI, Bootstrap, Angular, Vue, Ember, Drupal, Joomla, TYPO3, MediaWiki and others), and projects whose own maintainers have declared them discontinued (Moment.js, AngularJS, CryptoJS, oidc-client-js and others). Dates are checked against today's date on every audit. The remaining libraries are reported with their version but not judged — an end-of-life claim needs a source to cite.",
            "Upgrading client-side libraries is sometimes a small change (a single CDN URL update) and sometimes a months-long migration. AngularJS to Angular is the canonical hard case: different framework, complete rewrite. jQuery 1.x to 3.x is mostly mechanical but breaks in subtle ways with custom plugins. Regardless, an EOL library is a known-fragile dependency and the cost of replacement only goes up over time.",
            "If immediate upgrade is impossible, the next-best step is to add Subresource Integrity (SRI) attributes to the library's <script> tag and pin the version — at least preventing a CDN compromise from substituting a malicious version. But SRI doesn't fix vulnerabilities in the library itself; it just keeps the library you have from being silently swapped out.",
        ],
    },
    "eol_tech": {
        "what": "End-of-life server software (web server, runtime, TLS library, application platform) disclosed in your HTTP headers no longer receives security patches.",
        "why":  "Fixes for newly found flaws are no longer released for this version, and the headers state exactly which version is running.",
        "fix":  "Upgrade to a release that is still supported, then stop advertising versions (ServerTokens Prod, server_tokens off, expose_php = Off).",
        "details": [
            "Server software has a fixed support lifecycle just like an operating system. PHP releases get two years of active support and two of security fixes. Apache httpd maintains only the 2.4 branch. OpenSSL, Tomcat, Python, Ruby and Perl each publish end-of-life dates per release. Past that date no fixes are issued.",
            "This finding is distinct from plain version disclosure. Revealing \"PHP\" is a minor leak; revealing \"PHP/8.1.34\" after 8.1 has reached end of life tells a reader both what is running and that it is no longer maintained.",
            "Vendor Audit reads versions the server already volunteers: the Server and X-Powered-By headers (Apache, nginx, OpenSSL, PHP, Python, Ruby, Perl, Jetty), X-AspNet-Version and X-AspNetMvc-Version, the MicrosoftSharePointTeamServices, X-OWA-Version and X-Jenkins headers, the build in an Outlook Web App sign-in page, the version tag on Confluence and Jira pages, and the footer of a default error page (Apache, nginx, Tomcat). Each is compared with its end-of-life date from endoflife.date, checked against today's date. Linux distributions keep patching the versions they ship long after upstream stops, so for software distributions backport (nginx, OpenSSL, Tomcat, Jetty, Python, Ruby, Perl) only versions old enough that every distribution that shipped them is itself unsupported are flagged, and a PHP version carrying an Ubuntu or Debian package suffix is judged by that distro release instead of by php.net. If a CDN or reverse proxy strips these headers the check sees nothing and flags nothing.",
            "The fix has two halves. First, upgrade to a supported release. Second, stop advertising versions: ServerTokens Prod and ServerSignature Off for Apache, server_tokens off for nginx, expose_php = Off for PHP, and remove X-AspNet-Version / X-AspNetMvc-Version in web.config. Hiding the version patches nothing, so do it after the upgrade, not instead of it.",
        ],
    },
    # 3.5.9: DNS server software named in a version.bind answer.
    "eol_dns": {
        "what": "End-of-life DNS server software, named by the domain's own nameservers when asked for version.bind, no longer receives security patches.",
        "why":  "A nameserver answers anyone on the internet, and an unpatched one can be crashed (taking the domain offline) or, with some flaws, made to serve forged answers.",
        "fix":  "Upgrade BIND to a supported release, or to the version your distribution still patches, then set version \"none\"; (or any text) in named.conf options so it stops giving its version.",
        "details": [
            "BIND answers a query for version.bind in the CHAOS class with its version unless told otherwise. Vendor Audit sends that one query to each nameserver, alongside the lame-delegation and open-resolver checks; most DNS providers refuse it or answer with a placeholder, and only a real BIND version string is judged.",
            "Linux distributions keep patching the BIND they ship (9.11 on RHEL 8, 9.16 on RHEL 9, 9.18 on Debian 12 and Ubuntu 22.04 and 24.04), so only versions older than any of those (below 9.11) are flagged.",
        ],
    },
    # 3.5.4: mail server software named in the SMTP greeting (deep scans).
    "eol_mail": {
        "what": "End-of-life mail server software, named in the greeting the domain's mail servers send to every connecting server, no longer receives security patches.",
        "why":  "Mail servers face the whole internet, and the greeting states exactly which version is running. Exim has had remotely exploitable flaws, such as CVE-2019-10149, that were attacked at scale soon after they were published.",
        "fix":  "Upgrade to a supported release, or to the version your distribution still patches, then set smtp_banner so the greeting no longer names the version.",
        "details": [
            "Every mail server greets a connecting server with a line starting 220. Exim's default names its version (\"ESMTP Exim 4.94.2\"). The deep scan already connects to each mail server to test STARTTLS, so it reads that line at no extra cost.",
            "Exim's developers support only the newest release, but Debian and Ubuntu patch the version they ship for the life of the distribution. So only versions older than any supported distribution ships (below 4.95) are flagged: those are unpatched everywhere.",
            "The fix has two halves. First, upgrade. Second, set smtp_banner in the Exim configuration to leave out $version_number. Hiding the version patches nothing, so do it after the upgrade, not instead of it.",
        ],
    },
    "error_page": {
        "what": "Default error pages (the built-in 404 / 500 pages from Apache, Nginx, IIS, Tomcat, etc.) reveal the server software and often its exact version.",
        "why":  "An attacker probing your domain learns which CVE list applies and which exploits to try — for free, without ever having to send a real attack.",
        "fix":  "Configure a custom error page in your web server. nginx: error_page 404 /custom_404.html; Apache: ErrorDocument 404 /custom_404.html; IIS: customErrors mode='On' in web.config.",
        "details": [
            "Web servers ship with built-in error pages so that a fresh install responds to a 404 or 500 with something rather than a blank screen. Those defaults are the immediate giveaway — Apache's footer reads 'Apache/2.4.41 (Ubuntu) Server at example.com Port 443', nginx's reads 'nginx/1.18.0 (Ubuntu)', IIS shows the version and a link to support.microsoft.com, Tomcat shows the full stack trace and version. Vendor Audit probes a randomized non-existent URL to trigger the 404 and looks for these fingerprints in the response body.",
            "The risk isn't theoretical. Once an attacker knows you're running Apache 2.4.41 on Ubuntu, the fingerprint matches a specific package version with a public CVE list. CVE-2021-44790 (mod_lua buffer overflow), CVE-2021-44224 (request smuggling), and dozens of others are tied to specific minor versions — a default error page reveals exactly which ones apply. The same goes for nginx version-tied CVEs, IIS-specific bugs, and version-tagged Tomcat advisories.",
            "The fix is to override the default. Every major server has a custom-error-page configuration (nginx error_page directive, Apache ErrorDocument, IIS httpErrors, Tomcat <error-page>). Pair it with suppression of the Server header (server_tokens off in nginx, ServerTokens Prod in Apache) so your custom 404 doesn't reintroduce the disclosure via headers. CDNs (Cloudflare, Fastly, Akamai) override error pages automatically when their proxies handle the response — but the origin should still be hardened in case requests bypass the CDN.",
            "Vendor Audit distinguishes between 'default page, no version' (the operator hid the version but left the default template) and 'default page with version' (full disclosure). The former is much better than the latter, but neither is as good as a custom page. A clean check means the audit's probe got either a fully customised response or a generic 404 with no recognizable fingerprint.",
        ],
    },
    "cors": {
        "what": "Cross-Origin Resource Sharing (CORS) headers tell the browser which other origins are allowed to read responses from your site.",
        "why":  "A misconfigured CORS policy can let a malicious site read your authenticated API responses — turning a same-origin protection into a cross-origin information leak.",
        "fix":  "Use Access-Control-Allow-Origin: <specific origin>, never *, especially when Allow-Credentials: true is set. Avoid reflective ACAO that echoes the request's Origin header.",
        "details": [
            "The Same-Origin Policy (SOP) is one of the foundational web security boundaries: a script on attacker.example can't read responses from victim.example, even if the user is logged in. CORS is the explicit relaxation of that boundary — your server can send Access-Control-Allow-Origin (ACAO) headers to authorise specific other origins to read its responses. Misconfigurations turn a protection into a leak.",
            "The dangerous patterns are well-known. ACAO: * allows any origin to read responses, which is fine for genuinely public APIs but disastrous for anything authenticated. ACAO: * combined with Access-Control-Allow-Credentials: true is so dangerous that browsers reject it at runtime — but a server that emits the combination indicates the operator believes credentialed cross-origin reads are acceptable, which they almost never are. ACAO: null trusts sandboxed iframes and other null-origin contexts, which an attacker can trigger from a page they control. Reflective ACAO (echoing whatever Origin: the client sends) is effectively the same as allowing all origins, just slower.",
            "The right configuration is to allowlist specific origins. ACAO: https://app.example.com (one origin per response, varied per request based on a server-side allowlist). If you support multiple origins, the server inspects the request's Origin: header, checks it against an explicit allowlist, and echoes it back only on match. Add Vary: Origin so caches don't serve one origin's response to another. For credentialed cross-origin reads, also set Allow-Credentials: true — but only on responses to specific allowlisted origins, never with ACAO: *.",
            "Vendor Audit makes a single GET against the homepage with an Origin: header and inspects the response. Findings cover the four high-risk patterns (wildcard with credentials, null, reflective, broad wildcard) and the safe baseline (no CORS headers — meaning the browser refuses cross-origin reads, which is the secure default). Sites that legitimately need CORS for their own subdomains or partners will still pass this check as long as they enumerate allowed origins rather than wildcard them.",
        ],
    },
    "rpki": {
        "what": "RPKI (Route Origin Authorization) lets you cryptographically declare which Autonomous Systems are allowed to announce your IP prefixes.",
        "why":  "Without ROAs, anyone can hijack your IP space via BGP — sending your traffic through their network and impersonating your services.",
        "fix":  "Ask your hosting provider or RIR (ARIN/RIPE/APNIC/etc) to create ROAs covering each prefix you announce.",
        "details": [
            "Resource Public Key Infrastructure (RPKI, RFC 6480 and follow-ons) is the routing-layer counterpart to DNSSEC. The Border Gateway Protocol (BGP) that connects the world's networks has historically been an honour system: any ISP can announce any prefix, and other ISPs simply trust the announcement. Misconfigurations and deliberate hijacks have repeatedly redirected major services to the wrong networks — sometimes for hours.",
            "A Route Origin Authorization (ROA) is a cryptographically signed statement, published by the legitimate holder of a prefix, declaring which Autonomous System (AS) numbers are authorised to originate that prefix. Networks that do RPKI validation reject announcements that don't match a published ROA — closing off the hijack path for any prefix with a ROA in place.",
            "Adoption has accelerated significantly. Most major transits (Cloudflare, Telia, NTT, Cogent, AT&T) drop RPKI-Invalid routes today, meaning a hijack of a properly-ROA'd prefix is rejected globally within seconds. Publishing ROAs is a quick conversation with whoever holds your IP allocation: AWS, GCP, and Azure publish ROAs for their customer prefixes by default; smaller hosters often need an explicit request to the RIR (ARIN, RIPE, APNIC, AFRINIC, LACNIC).",
            "Vendor Audit checks the validation state via RIPEstat for each prefix the audit's IPs fall into. Valid means a ROA exists and matches the announcement. NotFound means no ROA covers the prefix — the announcement is technically still routed, but the prefix is unprotected against hijacks. Invalid means a ROA exists and doesn't match — usually a misconfiguration that should be fixed urgently.",
        ],
    },
    "routing": {
        "what": "This section covers IP-level reachability and routing security: IPv6 connectivity and RPKI Route Origin Authorizations for both IP families.",
        "why":  "IPv6-only users can't reach sites that are IPv4 (legacy IP) only, and prefixes without ROAs are vulnerable to BGP hijacks that redirect traffic to attackers.",
        "fix":  "Add AAAA records to enable IPv6, and ask your hosting provider or RIR to publish ROAs for every prefix your AS announces.",
        "details": [
            "Routing-layer security and reachability are usually invisible — until they aren't. The two checks in this section cover the cases where they aren't: a domain that's unreachable for users on IPv6-only networks, and a prefix that's vulnerable to BGP hijacking because no Route Origin Authorisation has been published.",
            "Both checks rely on RIPEstat's public BGP and IRR data. The IRR / RIS check confirms the prefix appears in real-world routing tables — a sanity check that the announcement is actually visible from RIPE's collectors. The RPKI check pulls the validated ROA payloads and compares them to the observed origin AS.",
        ],
    },
    "ipv6": {
        "what": "IPv6 connectivity makes your site reachable for the growing share of users on IPv6-only networks (mobile, enterprise, some ISPs).",
        "why":  "IPv4 (legacy IP) address exhaustion means more networks are deploying IPv6-only access; IPv4-only domains are simply unreachable for those users.",
        "fix":  "Add AAAA records pointing to IPv6 addresses on your hosting; most CDNs and cloud providers offer this with a single config flag.",
        "details": [
            "IPv6 is now the majority. Cisco's 6lab measurement puts the internet core at 88% IPv6, global content at 64%, and user-side deployment at 57%. IPv4 is the legacy protocol on the way out — addresses cost real money (AWS bills per public IPv4 per hour) and a growing fraction of users sit behind carrier-grade NAT or NAT64, where an IPv4-only domain looks slow at best and unreachable at worst. If you haven't enabled IPv6 yet, now is the time.",
            "Enabling IPv6 is usually trivial. Every major cloud provider (AWS, GCP, Azure, Cloudflare, Fastly, Akamai) offers IPv6 with a config-flag toggle. The DNS record is an AAAA pointing to the IPv6 address; that's the entire DNS-side change. Server-side, every modern web server (nginx, Apache, IIS) listens on IPv6 by default; if you're running them on a VPS, the provider has likely already assigned you a /64.",
            "The check looks for an AAAA record on the apex domain. A common deployment mistake is to enable IPv6 on www but not on the apex (or vice versa) — both should resolve to IPv6 addresses. If the audit reports IPv6 not configured on a site you know has IPv6, double-check that AAAA exists for the exact hostname in the report (apex vs. www).",
        ],
    },
    "page_analysis": {
        "what": "A passive read of the homepage HTML for Subresource Integrity, mixed content, third-party origins, and basic accessibility signals.",
        "why":  "Missing SRI on third-party scripts means a CDN compromise injects code into your site; mixed content allows tampering with HTTPS pages.",
        "fix":  "Add integrity= attributes to all <script> and <link> tags loading from third-party origins; never include http:// resources in HTTPS pages.",
        "details": [
            "Page analysis is a single GET of the homepage with the response body parsed for a small set of signals. It's gated behind --deep because it's slower (the body has to be fetched and parsed) and noisier (sites behind bot-mitigation challenges produce unreliable findings). The output is a parser inventory and a handful of derived findings.",
            "Subresource Integrity (SRI, W3C standard) is a hash attribute on <script> and <link> tags that lets the browser verify the resource's bytes match an expected hash before executing it. Without SRI, a third-party CDN compromise injects code into every page that loads from it — the 2018 British Airways, Newegg, and Ticketmaster compromises all chained through the same Magecart pattern. With SRI on every external resource, the same compromise causes scripts to fail to load instead of executing attacker code.",
            "Mixed content is HTTP resources loaded by an HTTPS page. Browsers block it by default for scripts and stylesheets (active mixed content) but allow it for images and audio with a console warning (passive mixed content). Either way, a network attacker can substitute the unencrypted resource — for a script that's RCE on every page view; for an image it's smaller but still a tracking and tampering vector.",
            "The accessibility signals are not a substitute for a proper a11y audit: empty buttons, missing alt= attributes, missing form labels, missing <html lang=>. They're the kind of thing a quick visual scan catches that automated WAVE/Axe/pa11y tooling would catch in much more depth. A clean signal here means nothing structural is obviously broken; it doesn't mean the site is fully accessible.",
        ],
    },
    "dangling_dns": {
        "what": "A CNAME record points one name at another. A dangling CNAME points at a name that no longer exists, usually a cloud bucket, app or CDN endpoint that was deleted.",
        "why":  "At many providers anyone can create a resource with the freed name. Whoever does then serves their own content on this domain, with a valid certificate (subdomain takeover).",
        "fix":  "Delete CNAME records for services that are no longer used, or re-create the resource at the provider before the name is claimed.",
        "details": [
            "This audit follows the CNAME chain of the domain as entered and of its www form, and reports a chain whose last name returns NXDOMAIN (does not exist). A timeout or server error is not counted, since it does not show that the name is free.",
            "Only these two names are checked. A takeover can happen on any subdomain, so an inventory of the zone's CNAME records, checked when a cloud resource is removed, is the lasting fix.",
        ],
    },
    "infra_routing": {
        "what": "The addresses of the domain's nameservers and mail servers: whether they are on IPv6, which networks they sit in, and whether their routes are protected by RPKI.",
        "why":  "A route hijack of the nameservers or mail servers redirects the whole domain's DNS or mail, not just its website. Nameservers on one network share every outage of that network, and servers without IPv6 cannot be reached by IPv6-only clients.",
        "fix":  "Ask the DNS and mail providers to publish ROAs for their prefixes and to offer IPv6, or move to providers that do. Spread nameservers over more than one network.",
        "details": [
            "For up to four nameservers and three mail servers, one IPv4 and one IPv6 address each are looked up in RIPEstat (at most eight lookups per audit): the announcing network (ASN) and the RPKI origin validation of the route.",
            "RPKI \"not-found\" means no Route Origin Authorization covers the prefix, so nothing stops another network announcing it. \"invalid\" means the route contradicts the published ROA, which is either a misconfiguration or a hijack in progress.",
            "Large anycast DNS providers often run all of a domain's nameservers from one network. That is reported as Informational: RFC 2182 asks for network diversity, but a well-run anycast network is resilient in practice.",
        ],
    },
}


def _explanation_lines_txt(key, indent="  "):
    """Render an explanation block as a list of indented txt lines.

    Returns [] if `key` isn't in EXPLANATIONS so callers can append
    unconditionally without an existence check on every site.
    """
    entry = EXPLANATIONS.get(key)
    if not entry:
        return []
    if _md():
        # One paragraph each, so What / Why / Fix stay apart when rendered.
        out = []
        for label in ("What", "Why", "Fix"):
            if entry[label.lower()]:
                out += [f"**{label}:** {_md_inline(entry[label.lower()])}", ""]
        return out[:-1]
    out = []
    body_w = WIDTH - len(indent) - 6  # leave room for the "What:" label
    for label, text in (("What", entry["what"]),
                        ("Why",  entry["why"]),
                        ("Fix",  entry["fix"])):
        wrapped = _wrap_at_words(text, body_w)
        # First line gets the label; continuations align under the body text.
        if not wrapped:
            continue
        out.append(f"{_tag('E')}{indent}{label}: {wrapped[0]}")
        cont_indent = indent + " " * (len(label) + 2)
        for cont in wrapped[1:]:
            out.append(f"{_tag('E')}{cont_indent}{cont}")
    return out


def _subheading_with_explanation(title, explanation_key):
    """Shorthand: subheading line, blank, explanation block, blank.

    Used by the section renderers to produce a subsection heading
    followed immediately by the Internet.nl-style "What / Why / Fix"
    explanation paragraph. Returns a list of strings ready to be
    appended to the section's `parts` or `out` list.

    If `explanation_key` is unknown, falls back to a bare subheading
    + blank line so existing behaviour is preserved for sections we
    haven't yet authored explanations for.
    """
    lines = [_subheading(title), ""]
    expl = _explanation_lines_txt(explanation_key)
    if expl:
        lines.extend(expl)
        lines.append("")
    return lines


def _section_explanation_lines(explanation_key):
    """Render an explanation block for use right after a top-level
    `_heading(...)` line. Returns a list of strings (the explanation
    body and a trailing blank), or [] if the key isn't known.

    Used by sections whose first subsection's explanation also serves
    as the natural top-of-section context (e.g. Routing, where we
    explain RPKI/IPv6 once at the top rather than twice — once per
    address family).
    """
    expl = _explanation_lines_txt(explanation_key)
    if not expl:
        return []
    return expl + [""]


# ── Generic helpers ──────────────────────────────────────────────────────────

def _fmt_int_or_float(v):
    """Render a points value as int when integer-valued, else as-is."""
    try:
        if v == int(v):
            return int(v)
    except (TypeError, ValueError):
        pass
    return v


def _fmt_kb_or_mb(n):
    if n is None:
        return ""
    if n < 1024 * 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _expand_cert_issuer(issuer):
    """Expand short cryptic issuer CNs (like 'WE1') with the issuing
    organisation in parens. Returns the issuer unchanged if not in the
    expansion table."""
    if not issuer:
        return issuer
    issuer_str = str(issuer).strip()
    return _CERT_ISSUER_EXPANSIONS.get(issuer_str, issuer_str)


# Builders for the line shapes used throughout the report. Each returns a
# string (no trailing newline) so the caller can join with "\n" and decide
# its own paragraph spacing.

def _heading(title):
    """Section heading — light rule above and below the title line."""
    if _md():
        return f"## {_md_title(title)}"
    return f"{_tag('R')}{RULE_LIGHT}\n{_tag('H')}  {title}\n{_tag('R')}{RULE_LIGHT}"


def _subheading(title):
    """Subsection heading — just the title, indented two spaces.
    Surrounding paragraphs are responsible for blank lines."""
    if _md():
        return f"### {_md_inline(title.replace('(--deep)', '(deep scan)'))}"
    return f"{_tag('h')}  {title}"


# Words kept in capitals when a section title is put in sentence case.
_MD_TITLE_KEEP = {"DNS", "IP", "ASN", "RPKI", "TLS", "HTTP", "HSTS", "CORS",
                  "SSL", "MX", "STARTTLS", "OWASP", "W3C", "RFC"}


def _md_title(title):
    """A section title in sentence case: "BROWSER SECURITY HEADERS (W3C /
    OWASP secure-headers)" → "Browser security headers (W3C / OWASP
    secure-headers)". The part in brackets is already in normal case."""
    title = title.replace("(--deep)", "(deep scan)")
    head, sep, rest = title.partition(" (")
    words = []
    for i, w in enumerate(head.split(" ")):
        if w in _MD_TITLE_KEEP or not w.isupper():
            words.append(w)
        elif w == "LABS":
            words.append("Labs")
        else:
            words.append(w.capitalize() if i == 0 else w.lower())
    return _md_inline(" ".join(words) + sep + rest)


def _para(text, indent=2):
    """A paragraph of prose: word-wrapped and indented in the plain form,
    one line in Markdown."""
    if _md():
        return _md_inline(text)
    return "\n".join(f"{' ' * indent}{ln}" for ln in _wrap_at_words(text, WIDTH - indent))


def _items(values, indent=7, nested=True):
    """A bare list of values (nameservers, technologies): one per line
    in the plain form; Markdown list items, nested under the status line
    above them unless `nested` is False."""
    if _md():
        lead = "    - " if nested else "- "
        return "\n".join(f"{lead}{_md_inline(v)}" for v in values)
    return "\n".join(f"{' ' * indent}{v}" for v in values)


def _code_list(label, values, indent=7):
    """A labelled list of raw values (certificate names): the plain form
    indents them under the label; Markdown puts them in a code block."""
    if _md():
        return "\n".join([_md_inline(label), "", "```", *map(str, values), "```"])
    return "\n".join([f"{' ' * indent}{label}",
                      *(f"{' ' * (indent + 2)}{v}" for v in values)])


def _wrap_at_words(text, width):
    """Soft-wrap `text` to a list of lines no wider than `width`, breaking
    only at whitespace. Single tokens longer than `width` (e.g. a URL) are
    left intact on their own line — they'll exceed the budget but stay
    readable, and Notepad's word-wrap handles them on screen."""
    words = str(text).split()
    if not words:
        return [""]
    out = []
    buf = ""
    for w in words:
        if buf and len(buf) + 1 + len(w) > width:
            out.append(buf)
            buf = w
        elif not buf:
            buf = w
        else:
            buf = buf + " " + w
    if buf:
        out.append(buf)
    return out


# Certificate lifetime at or under this many days reads as automated issuance.
# Mirrors thresholds.cert_lifetime_max_days in rubric.json.
_CERT_LIFETIME_MAX_DAYS = 91
# Under this share of its lifetime left, a certificate's renewal is overdue.
# Mirrors thresholds.cert_renewal_min_remaining_pct.
_CERT_RENEWAL_MIN_PCT = 10


def _humanize_seconds(seconds):
    """'16 hours', '9 days' — hours under three days, so short-lived
    certificates read sensibly."""
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return ""
    if seconds < 0:
        return "already expired"
    if seconds < 3 * 86400:
        hours = max(1, round(seconds / 3600))
        return f"{hours} hour{'s' if hours != 1 else ''}"
    days = round(seconds / 86400)
    return f"{days} days"


def _cert_renewal_text(tls):
    """(severity, text) for the certificate-renewal line, or None when the
    audit has no remaining-lifetime figure."""
    pct = (tls or {}).get("cert_remaining_pct")
    if pct is None:
        return None
    left = _humanize_seconds((tls or {}).get("cert_remaining_seconds"))
    pct_txt = f"{max(pct, 0):.0f}%"
    if pct >= _CERT_RENEWAL_MIN_PCT:
        return ("pass", f"Certificate renewal on schedule — {pct_txt} of its lifetime left"
                        + (f" (expires in {left})" if left else ""))
    return ("fail", f"Certificate renewal overdue — {pct_txt} of its lifetime left"
                    + (f" (expires in {left})" if left else "")
                    + "; automated renewal replaces a certificate well before this point")


# ── Status-line words ────────────────────────────────────────────────────────
# A detail line starts with a word saying how the audit rates what it
# describes. The word comes from the check the line reports on (the
# `check=` argument, a label in rubric.json), so the detail sections, the
# summary, the web page and the CSV can never disagree:
#
#   the line says                tied to a check           not tied to one
#   ───────────────────────────  ────────────────────────  ───────────────
#   this part is fine            PASS                      (no word)
#   something is missing/wrong   the check's severity      NOTE
#   information                  INFO if the check could   (no word)
#                                not run or is optional
#
# A check can span several lines (HSTS: max-age, includeSubDomains,
# preload), so a passing detail of a check with a finding still reads PASS.
# NOTE marks something observed that the rubric does not rate, such as the
# accessibility signals. The section's own judgement (`severity`: pass /
# info / warn / fail) only decides which row of the table applies.

_STATUS_WORDS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                 "low": "LOW", "info": "INFO", "pass": "PASS", "note": "NOTE"}
_STATUS_WORD_W = 8

# label -> severity for the report being rendered; set by
# render_detail_sections. A context variable, so concurrent renders in
# threads or tasks each see their own report.
_CHECK_SEVERITIES = contextvars.ContextVar("vendor_audit_check_severities", default={})


def _status_word(severity, check):
    """'' or a key of _STATUS_WORDS for one status line."""
    found = _CHECK_SEVERITIES.get().get(check) if check else None
    if severity == "pass":
        return "pass" if check else ""
    if severity == "info":
        return "info" if check and found in (None, "info") else ""
    # warn / fail: the section flags a problem
    if not check:
        return "note"
    return found or "note"


def _status(severity, body, sub_lines=None, note_lines=None, check=None):
    """Status line: '    PASS      Body text', plus optional indented
    sub-lines (typically raw values like a record string) and note lines
    (typically explanation continuations).

    `severity` is the section's own reading (pass / info / warn / fail);
    `check` names the rubric check the line reports on, if any. The word
    printed is worked out from both — see "Status-line words" above.

    The body is word-wrapped, with continuations indented to align under
    the body text (col 14). sub_lines and note_lines are iterables of
    strings; each is indented further under the body."""
    word = _status_word(severity, check)
    if _md():
        label = _STATUS_WORDS.get(word, "")
        body = _md_inline(body)
        first = (f"- **{label}** {body}" if body else f"- **{label}**") if label else f"- {body}"
        out = [first.rstrip()]
        notes = [" ".join(note_lines)] if isinstance(note_lines, _OneNote) else (note_lines or [])
        out += [f"    - {_md_inline(n)}" for n in notes]
        out += [f"    - {_md_inline(s)}" for s in (sub_lines or [])]
        return "\n".join(out)
    LEAD = "    "                                # 4 spaces before the word
    BODY_INDENT = " " * (len(LEAD) + _STATUS_WORD_W + 2)   # col 14
    BODY_W = WIDTH - len(BODY_INDENT)           # col budget for body text

    body_lines = _wrap_at_words(body, BODY_W)
    label = _STATUS_WORDS.get(word, "")
    out = [f"{_tag('S:' + (word or 'none'))}{LEAD}{label.ljust(_STATUS_WORD_W)}  {body_lines[0]}".rstrip()
           if body_lines[0] else f"{_tag('S:' + (word or 'none'))}{LEAD}{label}".rstrip()]
    for cont in body_lines[1:]:
        out.append(f"{BODY_INDENT}{cont}")

    if note_lines:
        # Note lines get a "· " bullet prefix so they read as distinct
        # remarks, apart from body word-wrap continuations (which share
        # the same indent but continue the sentence).
        for ln in note_lines:
            wrapped_lines = _wrap_at_words(f"· {ln}", BODY_W)
            for wi, wrapped in enumerate(wrapped_lines):
                # Continuation of a long note keeps the bullet column aligned
                # (2-space hanging indent) but only the first line carries "·".
                if wi == 0:
                    out.append(f"{BODY_INDENT}{wrapped}")
                else:
                    out.append(f"{BODY_INDENT}  {wrapped}")
    if sub_lines:
        sub_indent = BODY_INDENT + "  "
        sub_w = WIDTH - len(sub_indent)
        for ln in sub_lines:
            # Sub-lines are typically raw values (URLs, hostnames, records).
            # Don't word-wrap a single token that exceeds the budget — keep
            # it on one line so the user can copy-paste cleanly. Only wrap
            # multi-word sub-lines.
            ln_str = str(ln)
            if " " in ln_str.strip() and len(ln_str) > sub_w:
                for wrapped in _wrap_at_words(ln_str, sub_w):
                    out.append(f"{sub_indent}{wrapped}")
            else:
                out.append(f"{sub_indent}{ln_str}")
    return "\n".join(out)


def _kv(pairs, indent=7, gap=4):
    """Aligned key/value block. `pairs` is a list of (key, value) tuples.
    Keys are left-padded to the longest-key width. `indent` is total left
    margin in spaces (default 7 — aligns under status-line bodies);
    `gap` is the column gap between key and value."""
    if not pairs:
        return ""
    if _md():
        return "\n".join(f"- {_md_inline(k)}: {_md_inline(v)}" for k, v in pairs)
    max_key = max(len(k) for k, _ in pairs)
    out = []
    for k, v in pairs:
        out.append(f"{' ' * indent}{k.ljust(max_key + gap)}{v}")
    return "\n".join(out)


def _raw_value(label, value, indent=4):
    """Long verbatim record (SPF, DMARC, CSP, etc). Emitted as a label
    line followed by the value on its own line, unindented past the
    leading margin so Notepad's word-wrap does the right thing."""
    if _md():
        block = f"```\n{value}\n```"
        return f"{_md_inline(label)}\n\n{block}" if label else block
    pad = " " * indent
    if label:
        return f"{pad}{label}\n{pad}{value}"
    return f"{pad}{value}"


# ── Data model (small, internal) ──────────────────────────────────────────────

class _ReportData:
    """Aggregate everything the renderer needs in one place. Computed once
    from the results dict + assessed findings so the rendering can be a
    straight transformation."""

    def __init__(self, original_domain, audit_domain, results, timestamp,
                 report_version):
        self.original_domain = original_domain
        self.audit_domain    = audit_domain
        self.timestamp       = timestamp
        self.report_version  = report_version
        self.results         = results

        # Defer import to runtime to avoid a circular dependency at module
        # load time. audit_checks imports nothing from this file, so this
        # cycle exists only because the report needs the score function.
        from .audit_checks import assess_results, severity_counts, RUBRIC

        self.rubric   = RUBRIC
        self.findings = assess_results(results)
        self.counts   = severity_counts(self.findings)
        self.issue_count = sum(self.counts[s] for s in ISSUE_SEVERITIES)
        self.verdict  = verdict_for(self.counts)
        # Colour class for the headline: the worst severity present.
        self.worst_severity = next(
            (s for s in ISSUE_SEVERITIES if self.counts[s]), "pass")

        self._build_finding_rows()
        self._build_category_rows()

    def _build_category_rows(self):
        """Per-category severity counts, in report order."""
        from .audit_checks import auditor_cannot_reach
        order = ["Email", "DNS", "Routing", "TLS", "HTTP", "Website"]
        # 3.4.4: when the site couldn't be reached at all (IPv6-only site,
        # audit host without IPv6), say "not checked" rather than leaving a
        # row that reads "no issues, 0 passed".
        unreached = {"TLS", "HTTP", "Website"} if auditor_cannot_reach(self.results) else set()
        rows = []
        for cat in order:
            in_cat = [r for r in self.finding_rows if r["category"] == cat]
            if not in_cat and cat not in unreached:
                continue
            counts = {s: 0 for s in SEVERITY_ORDER}
            for r in in_cat:
                counts[r["severity"]] += 1
            rows.append({
                "category": cat,
                "counts":   counts,
                "issues":   sum(counts[s] for s in ISSUE_SEVERITIES),
                "passed":   counts["pass"],
                "total":    len(in_cat),
                "worst":    next((s for s in ISSUE_SEVERITIES if counts[s]), "pass"),
                "not_checked": cat in unreached,
            })
        self.category_rows = rows

    def _build_finding_rows(self):
        """One row per finding, with the sentence shown in reports.

        The sentence comes from rubric.json. It is refined here only where it
        carries live values: end-of-life names and dates, and the time left
        on the certificate."""
        eol_lookup = {}
        eol_lookup.update(self._build_eol_os_lookup())
        eol_lookup.update(self._build_eol_lib_lookup())
        eol_lookup.update(self._build_eol_tech_lookup())

        rows = []
        for f in self.findings:
            label, display = f["label"], f["text"]
            if label in eol_lookup:
                display = eol_lookup[label]
            elif label == "Certificate renewal":
                live = _cert_renewal_text(self.results.get("tls") or {})
                if live:
                    display = live[1]
            if label.startswith("redirect target: "):
                display = f"{display} (redirect target)"
            rows.append({
                "label":    label,
                "outcome":  f["outcome"],
                "display":  display,
                "category": f["category"],
                "severity": f["severity"],
            })
        self.finding_rows = rows

    def issues_ranked(self):
        """Critical → low, and within a severity by how much the practice
        matters (_CRITICALITY_RANK_TABLE)."""
        order = {s: i for i, s in enumerate(ISSUE_SEVERITIES)}
        return sorted(
            (r for r in self.finding_rows if r["severity"] in order),
            key=lambda r: (order[r["severity"]], _criticality_rank(r["label"])),
        )

    def _build_eol_os_lookup(self):
        """Map EOL OS breakdown labels → vendor-friendly display strings."""
        out = {}
        os_eol = self.results.get("os_eol") or {}
        for finding in (os_eol.get("os_findings") or []):
            if finding.get("eol_status") != "eol":
                continue
            os_key = finding.get("os", "?")
            ver    = finding.get("version") or ""
            if not ver or ver == "?":
                key = f"EOL OS: {os_key}"
            else:
                key = f"EOL OS: {os_key} {ver}"
            display    = finding.get("name") or _OS_DISPLAY_NAMES.get(os_key, os_key)
            ver_disp   = "" if ver in ("", "?") else ver
            stack_label = f"{display} {ver_disp}".rstrip()
            underlying = finding.get("underlying_os")
            headline   = underlying or stack_label
            date       = finding.get("eol_last_release", "")
            paren_bits = []
            if date:
                paren_bits.append(f"EOL {date}")
            if underlying and stack_label != underlying:
                paren_bits.append(f"via {stack_label}")
            paren = f" ({', '.join(paren_bits)})" if paren_bits else ""
            out[key] = f"End-of-life OS: {headline}{paren}"
        return out

    def _build_eol_lib_lookup(self):
        """Map EOL library breakdown labels → vendor-friendly display."""
        out = {}
        vlibs = (self.results.get("versioned_libs") or {}).get("libraries") or []
        for lib in vlibs:
            if lib.get("eol_status") != "eol":
                continue
            name = lib.get("library", "?")
            ver  = lib.get("version", "?")
            key  = f"EOL library: {name} {ver}"
            msg  = lib.get("eol_message") or "version is end-of-life"
            display_name = _LIB_DISPLAY_NAMES.get(name) or lib.get("name") or name
            out[key] = f"End-of-life library: {display_name} {ver} ({msg})"
        return out

    def _build_eol_tech_lookup(self):
        """Map EOL server-side tech breakdown labels → vendor-friendly display."""
        out = {}
        tech_eol = self.results.get("tech_eol") or {}
        for t in (tech_eol.get("techs") or []):
            if t.get("eol_status") not in ("eol", "undetermined"):
                continue
            tech = t.get("tech", "?")
            ver  = t.get("version", "?")
            key  = f"EOL tech: {tech} {ver}".rstrip()
            disp = t.get("name") or _TECH_DISPLAY_NAMES.get(tech, tech.upper())
            msg  = t.get("eol_message") or "version is end-of-life"
            if t.get("eol_status") == "undetermined":
                out[key] = f"Support status undetermined: {disp} {ver} ({msg})"
                continue
            # eol_message already includes the tech name + version; use it
            # directly for the parenthetical detail but lead with a clear
            # "End-of-life runtime:" framing.
            kind = {"smtp_banner": "mail server software",
                    "version_bind": "DNS server software"}.get(t.get("source"), "server software")
            out[key] = f"End-of-life {kind}: {disp} {ver} ({msg})"
        return out


_SITE_LINKS = ("[vendoraudit.org](https://vendoraudit.org) · "
               "[GitHub](https://github.com/chrono1313/Vendor-Audit)")


def _render_header(data):
    """Title, then one line with the time, version and links."""
    try:
        ts_dt = datetime.fromisoformat(data.timestamp.replace("Z", "+00:00"))
        ts_human = ts_dt.strftime("%B %d, %Y at %H:%M:%S %Z").strip()
    except (ValueError, AttributeError):
        ts_human = data.timestamp
    return "\n".join([
        f"# Vendor Audit — {data.original_domain}",
        "",
        f"{ts_human} · v{data.report_version} · {_SITE_LINKS}",
    ])


def _render_score_panel(data):
    """Findings headline + per-category table.

      ## Findings

      **2 critical · 4 high · 11 medium** — Critical issues found

      | Category | Findings | Passed |
      | --- | --- | --- |
      | Email | 1 critical · 1 medium | 8 |
    """
    out = ["## Findings", "",
           f"**{severity_summary(data.counts)}** — {data.verdict}"]
    cat_rows = data.category_rows or []
    if cat_rows:
        rows = []
        for r in cat_rows:
            if r.get("not_checked"):
                rows.append((r["category"], "not checked (site unreachable from this audit server)", "—"))
            else:
                rows.append((r["category"], severity_summary(r["counts"]), str(r["passed"])))
        out += [""] + _md_table(("Category", "Findings", "Passed"), rows)
    return "\n".join(out)


def _render_findings_group(title, rows):
    """One severity group in the Executive Summary:

      ### High (2)

      - **HIGH** Website — No Content-Security-Policy restricting scripts
    """
    if not rows:
        return ""
    out = [f"### {title.capitalize()} ({len(rows)})", ""]
    for r in rows:
        word = _STATUS_WORDS.get(r["severity"], r["severity"].upper())
        out.append(f"- **{word}** {r['category']} — {_md_inline(r['display'])}")
    return "\n".join(out)


def _render_executive_summary(data):
    """Executive summary: one block per severity, most serious first.

    Within a severity, findings are ordered by how much the practice
    matters (_CRITICALITY_RANK_TABLE), regardless of category.
    Informational rows (optional practices, or checks that could not be
    determined) follow in their own block. Passing checks are not listed
    here: the category table counts them, and each one is in its section.
    """
    infos  = [r for r in data.finding_rows if r["severity"] == "info"]
    ranked = data.issues_ranked()

    blocks = []
    for sev in ISSUE_SEVERITIES:
        rows = [r for r in ranked if r["severity"] == sev]
        if rows:
            blocks.append(_render_findings_group(SEVERITY_TITLES[sev], rows))
    if infos:
        blocks.append(_render_findings_group(SEVERITY_TITLES["info"], infos))
    if not ranked:
        blocks.insert(0, "No issues found.")
    return "\n\n".join(["## Executive summary"] + blocks)


# ── Detailed sections: Email ─────────────────────────────────────────────────

def _render_email_block(domain_label, spf, dmarc, mx, results, prefix=""):
    """SPF + DMARC + MX + mail-transport hardening for one domain.

    `prefix` picks the results keys ("redirect_target_" for the domain a
    site redirects to); `chk` is the matching prefix of the finding labels
    the status lines report on ("redirect target: SPF policy")."""
    from .audit_checks import _mx_pattern_match, _spf_covered_by_dmarc
    chk = "redirect target: " if prefix else ""
    out = []

    # ── SPF ──────────────────────────────────────────────────────────────
    out.extend(_subheading_with_explanation(
        f"SPF — {domain_label} (RFC 7208)", "spf"))
    if spf:
        s = spf.get("status", "missing")
        record = spf.get("record")
        has_mx = bool(mx.get("entries")) and not mx.get("null_mx")

        if s == "error":
            out.append(_status("info",
                f"DNS query failed: {spf.get('error')}", check=chk + "SPF policy"))
        elif s == "null_sender":
            out.append(_status("pass",
                "Null sender (v=spf1 -all) — domain explicitly declares it sends no mail", check=chk + "SPF policy"))
        elif s == "hardfail":
            out.append(_status("pass",
                "Hard fail (-all) — strict policy", check=chk + "SPF policy"))
        elif s == "softfail":
            out.append(_status("warn",
                "Soft fail (~all) — receivers will accept-and-mark, not reject", check=chk + "SPF policy"))
        elif s == "pass_all_DANGEROUS":
            out.append(_status("fail",
                "+all — anyone on the internet can spoof this domain", check=chk + "SPF policy"))
        elif s == "neutral":
            out.append(_status("warn",
                "Neutral (?all) — no enforcement", check=chk + "SPF policy"))
        elif s == "no_all_mechanism":
            out.append(_status("warn",
                "SPF record present but missing 'all' mechanism", check=chk + "SPF policy"))
        elif s == "redirect_no_all":
            out.append(_status("warn",
                "SPF via redirect= — no explicit 'all' in target", check=chk + "SPF policy"))
        elif s == "redirect_target_no_spf":
            out.append(_status("fail",
                "SPF redirect target has no SPF record (broken redirect)", check=chk + "SPF policy"))
        elif _spf_covered_by_dmarc(spf, dmarc, mx):
            # 3.4.10: a subdomain that sends no mail, under an enforcing DMARC policy.
            source, tag = _spf_covered_by_dmarc(spf, dmarc, mx)
            whose = "its own" if source == (spf.get("domain") or "").lower() else f"{source}'s"
            out.append(_status("info",
                f"No SPF record on this subdomain — spoofing is covered by {whose} DMARC policy ({tag})",
                note_lines=["SPF is checked only on the exact name, so subdomains that send no mail "
                            "rarely have their own record. DMARC applies to them, and forged mail "
                            "from this name fails it. Publishing \"v=spf1 -all\" here as well would "
                            "make that explicit."], check=chk + "SPF policy"))
        else:
            if has_mx:
                out.append(_status("fail",
                    "No SPF record — domain receives mail (MX present); spoofing trivially easy", check=chk + "SPF policy"))
            else:
                out.append(_status("fail",
                    "No SPF record — any server can send mail as this domain",
                    note_lines=["No MX records, so the domain appears to send no mail. "
                                "Publish \"v=spf1 -all\" to say so; receivers will then "
                                "reject mail claiming to come from it."], check=chk + "SPF policy"))

        lc = spf.get("lookup_count")
        if lc is not None and s != "null_sender":
            if lc > 10:
                out.append(_status("fail",
                    f"SPF lookup count: {lc} — exceeds 10-lookup limit (silent failures likely)",
                    note_lines=["The limit counts the lookups inside included records too: an include: "
                                "whose record includes other domains in turn uses a lookup for each of them."],
                    check=chk + "SPF lookup count"))
            elif lc >= 9:
                out.append(_status("pass",
                    f"SPF lookup count: {lc} of 10 — close to the limit", check=chk + "SPF lookup count"))
            else:
                out.append(_status("pass",
                    f"SPF lookup count: {lc}", check=chk + "SPF lookup count"))
            # 3.5.8: which term costs what, so a record over the limit
            # points at the include: to trim.
            tree_lines = spf_lookup_lines(spf.get("lookup_tree"))
            if tree_lines:
                out.append("")
                out.append(_code_list(f"Lookups by term ({lc} of 10 allowed):", tree_lines))

        # 3.4: one record only, and no lookups that fail or are deprecated.
        n_spf = spf.get("record_count")
        if n_spf and n_spf > 1:
            out.append(_status("fail",
                f"{n_spf} SPF records published — receivers treat SPF as broken (RFC 7208 §3.2)",
                check=chk + "SPF single record"))
        elif n_spf == 1:
            out.append(_status("pass", "One SPF record published", check=chk + "SPF single record"))
        if "void_lookups" in spf:
            missing_inc = spf.get("missing_includes") or []
            voids = spf.get("void_lookups") or 0
            if missing_inc:
                out.append(_status("fail",
                    "SPF includes a domain with no SPF record — receivers treat SPF as broken",
                    sub_lines=[f"include:{t}" for t in missing_inc], check=chk + "SPF mechanisms"))
            elif voids > 2:
                out.append(_status("fail",
                    f"{voids} SPF lookups return nothing — more than the 2 allowed (RFC 7208 §4.6.4)",
                    check=chk + "SPF mechanisms"))
            elif spf.get("uses_ptr"):
                out.append(_status("warn",
                    "SPF uses the ptr mechanism — deprecated (RFC 7208 §5.5)", check=chk + "SPF mechanisms"))
            else:
                out.append(_status("pass",
                    "SPF lookups all resolve; no deprecated mechanisms" if not voids
                    else f"SPF has {voids} lookup(s) that return nothing — within the limit of 2",
                    check=chk + "SPF mechanisms"))

        if spf.get("redirect_target"):
            rec = spf.get("redirect_record") or ""
            out.append(_status("info",
                f"Redirected to {spf['redirect_target']}"))
            if rec:
                out.append("")
                out.append(_raw_value("SPF redirect target record:", rec))

        if record:
            out.append("")
            out.append(_raw_value("Record published:", record))
    else:
        out.append(_para("No SPF data collected.", 4))

    out.append("")
    out.append("")

    # ── DMARC ────────────────────────────────────────────────────────────
    out.extend(_subheading_with_explanation(
        f"DMARC — {domain_label} (RFC 7489)", "dmarc"))
    if dmarc:
        if dmarc.get("error"):
            out.append(_status("info",
                f"DNS query failed: {dmarc['error']}", check=chk + "DMARC policy"))
        elif not dmarc.get("present"):
            out.append(_status("fail", "No DMARC record", check=chk + "DMARC policy"))
        else:
            inherited = dmarc.get("inherited_from")
            if inherited:
                out.append(_status("info",
                    f"DMARC inherited from organisational domain {inherited}", check=chk + "DMARC policy"))
            pol = dmarc.get("policy")
            if pol == "reject":
                out.append(_status("pass",
                    "Policy: reject — strongest enforcement", check=chk + "DMARC policy"))
            elif pol == "quarantine":
                out.append(_status("warn",
                    "Policy: quarantine — partial enforcement", check=chk + "DMARC policy"))
            elif pol == "none":
                out.append(_status("fail",
                    "Policy: none — monitoring only, no enforcement", check=chk + "DMARC policy"))

            if pol in ("reject", "quarantine"):
                pct = dmarc.get("pct")
                if pct is not None and pct < 100:
                    out.append(_status("fail",
                        f"pct={pct} — policy applies to only {pct}% of mail; full enforcement requires pct=100", check=chk + "DMARC pct"))
                else:
                    out.append(_status("pass",
                        "pct=100 — policy applies to all mail", check=chk + "DMARC pct"))
                sp = dmarc.get("sp")
                if sp == "none":
                    out.append(_status("fail",
                        "sp=none — subdomain policy explicitly set to none; subdomains are unprotected even with apex reject/quarantine", check=chk + "DMARC sp"))
                elif sp in ("reject", "quarantine"):
                    out.append(_status("pass",
                        f"sp={sp} — subdomain policy explicitly enforced", check=chk + "DMARC sp"))

            rua = dmarc.get("rua") or []
            if rua:
                if len(rua) == 1:
                    out.append(_status("pass",
                        f"rua= aggregate reports collected at {rua[0]}", check=chk + "DMARC rua reporting"))
                else:
                    out.append(_status("pass",
                        f"rua= aggregate reports collected at {len(rua)} destinations",
                        sub_lines=rua, check=chk + "DMARC rua reporting"))
            else:
                out.append(_status("warn",
                    "No rua= tag — no aggregate reporting destination set; operator cannot see spoofing attempts or legit-mail rejections", check=chk + "DMARC rua reporting"))

            # 3.4: one record only; reports to other organisations authorized.
            n_dmarc = dmarc.get("record_count")
            if n_dmarc and n_dmarc > 1:
                out.append(_status("fail",
                    f"{n_dmarc} DMARC records published — receivers ignore DMARC entirely (RFC 7489 §6.6.3)",
                    check=chk + "DMARC single record"))
            elif n_dmarc == 1:
                out.append(_status("pass", "One DMARC record published", check=chk + "DMARC single record"))
            policy_domain = dmarc.get("inherited_from") or domain_label
            for ext in dmarc.get("rua_external") or []:
                if ext.get("authorized") is True:
                    out.append(_status("pass",
                        f"Reports to {ext['domain']} are authorized by that domain", check=chk + "DMARC external reports"))
                elif ext.get("authorized") is False:
                    out.append(_status("warn",
                        f"Reports to {ext['domain']} are not authorized — no record at "
                        f"{policy_domain}._report._dmarc.{ext['domain']}, so they are not sent",
                        check=chk + "DMARC external reports"))

        if dmarc.get("record"):
            out.append("")
            out.append(_raw_value("Record published:", dmarc["record"]))
    else:
        out.append(_para("No DMARC data collected.", 4))

    out.append("")
    out.append("")

    # ── MX ───────────────────────────────────────────────────────────────
    out.extend(_subheading_with_explanation(
        f"MX records — {domain_label} (RFC 5321, 7505)", "mx"))
    if mx:
        if mx.get("error"):
            out.append(_status("info",
                f"DNS query failed: {mx['error']}", check=chk + "MX targets not CNAMEs"))
        elif mx.get("null_mx"):
            out.append(_status("pass",
                "Null MX (RFC 7505) — domain explicitly does not send or receive mail", check=chk + "Null MX on no-mail domain"))
        elif not mx.get("entries"):
            ipr = results.get("ip_routing") or {}
            has_address = bool((ipr.get("v4") or {}).get("address") or (ipr.get("v6") or {}).get("address"))
            if not prefix and has_address:
                # 3.5.8: a subdomain gets the parent-wide option too (M3AAWG).
                from .audit_checks import _org_domain
                org = _org_domain(domain_label)
                fix = ["Publish MX 0 . (RFC 7505) if the domain receives no mail"]
                if org and org != domain_label.lower().rstrip("."):
                    fix = [f"Publish MX 0 . (RFC 7505) on {domain_label} if it receives no mail, or "
                           f"*.{org} MX 0 . to cover every subdomain of {org} without an MX of its own "
                           f"(M3AAWG, Protecting Parked Domains)"]
                out.append(_status("fail",
                    "No MX records and no null MX — senders fall back to the domain's web address",
                    sub_lines=fix,
                    check=chk + "Null MX on no-mail domain"))
            else:
                out.append(_para("No MX records — domain does not receive email.", 4))
        else:
            # Plain table, two columns: Priority + Host. Lower priority
            # = preferred — note this once for users who don't know.
            if _md():
                out.extend(_md_table(("Priority", "Host"),
                    [(str(e.get("priority", "")), e.get("host", "")) for e in mx.get("entries", [])]))
                out.append("")
                out.append("Lower priority value = preferred.")
            else:
                out.append("    Priority   Host")
                out.append("    ────────   " + "─" * 60)
                for entry in mx.get("entries", []):
                    pri = str(entry.get("priority", ""))
                    host = entry.get("host", "")
                    out.append(f"    {pri:>5}      {host}")
                out.append("")
                out.append("    (lower priority value = preferred)")

            # MX target hygiene findings (RFC 2181 §10.3 / RFC 5321 §5.1)
            mx_targets_ip    = mx.get("mx_targets_ip") or []
            mx_targets_cname = mx.get("mx_targets_cname") or []
            if mx_targets_ip or mx_targets_cname:
                out.append("")
            for tgt in mx_targets_ip:
                out.append(_status("fail",
                    f"MX target is an IP literal: {tgt} \u2014 violates RFC 5321 \u00a75.1; "
                    f"sending MTAs may refuse or skip hostname-keyed checks", check=chk + "MX targets are hostnames"))
            for tgt in mx_targets_cname:
                out.append(_status("fail",
                    f"MX target is a CNAME: {tgt} \u2014 violates RFC 2181 \u00a710.3; "
                    f"some receivers may bounce", check=chk + "MX targets not CNAMEs"))

            # 3.4: every MX host has an address, with reverse DNS that maps back.
            hosts = mx.get("mx_hosts") or {}
            if hosts:
                out.append("")
                missing = [h for h, i in hosts.items() if i.get("resolves") is False]
                for h in missing:
                    out.append(_status("fail",
                        f"MX host {h} has no A or AAAA record — mail routed to it bounces",
                        check=chk + "MX hosts resolve"))
                if not missing and all(i.get("resolves") for i in hosts.values()):
                    out.append(_status("pass", "Every MX host has an address", check=chk + "MX hosts resolve"))
                # 3.5.10: no PTR and a PTR that doesn't map back are two checks.
                no_ptr, no_match, good = [], [], 0
                for h, i in hosts.items():
                    for p in i.get("ptr") or []:
                        if p.get("confirmed") is True:
                            good += 1
                        elif p.get("confirmed") is False and p.get("name"):
                            no_match.append(f"{p['address']} ({h}): reverse name {p['name']} does not resolve back")
                        elif p.get("confirmed") is False:
                            no_ptr.append(f"{p['address']} ({h})")
                if no_ptr:
                    out.append(_status("warn", "Mail server address with no reverse DNS",
                                       sub_lines=no_ptr, check=chk + "MX reverse DNS"))
                if no_match:
                    out.append(_status("warn", "Mail server reverse DNS does not map back",
                                       sub_lines=no_match, check=chk + "MX reverse DNS matches"))
                if good and not no_ptr and not no_match:
                    out.append(_status("pass",
                        f"Reverse DNS confirmed for {good} mail server address{'es' if good > 1 else ''}",
                        check=chk + "MX reverse DNS matches"))
    else:
        out.append(_para("No MX data collected.", 4))

    # ── Mail transport hardening ─────────────────────────────────────────
    has_mx = bool(mx.get("entries")) and not mx.get("null_mx")
    if has_mx:
        mta_sts        = results.get(f"{prefix}mta_sts", {}) or {}
        mta_sts_policy = results.get(f"{prefix}mta_sts_policy", {}) or {}
        tls_rpt        = results.get(f"{prefix}tls_rpt", {}) or {}
        dane           = results.get(f"{prefix}dane", {}) or {}
        dkim           = results.get(f"{prefix}dkim", {}) or {}

        items = []

        if mta_sts:
            if mta_sts.get("error"):
                items.append(_status("info",
                    f"MTA-STS DNS lookup failed: {mta_sts['error']}", check=chk + "MTA-STS"))
            elif mta_sts.get("present"):
                id_str = (f" (id={mta_sts.get('id')})"
                          if mta_sts.get("id") else "")
                mode = (mta_sts_policy.get("mode")
                        if mta_sts_policy.get("fetched") else None)
                failure = mta_sts_policy.get("failure")
                if mta_sts_policy.get("problems"):
                    items.append(_status("fail",
                        f"MTA-STS policy file is not a usable policy{id_str}",
                        sub_lines=["; ".join(mta_sts_policy["problems"])
                                   + " — sending servers ignore it"], check=chk + "MTA-STS"))
                elif failure in ("no_host", "http_error", "bad_cert"):
                    why = {"no_host": "the mta-sts host has no address",
                           "http_error": f"the server answered {mta_sts_policy.get('error')}",
                           "bad_cert": "its certificate does not validate"}[failure]
                    items.append(_status("fail",
                        f"MTA-STS record published but the policy can't be fetched: {why}{id_str}",
                        sub_lines=["Sending servers ignore the record without a policy file"],
                        check=chk + "MTA-STS"))
                elif failure in ("unreachable", "blocked"):
                    items.append(_status("pass",
                        f"MTA-STS DNS record published{id_str}",
                        sub_lines=[f"Policy file not reachable from this audit ({mta_sts_policy.get('error')});",
                                   "taken as published"], check=chk + "MTA-STS"))
                elif mode in ("enforce", "testing"):
                    if mode == "enforce":
                        items.append(_status("pass",
                            f"MTA-STS published — mode=enforce{id_str}", check=chk + "MTA-STS"))
                    else:
                        items.append(_status("warn",
                            f"MTA-STS in mode=testing — failures reported, not enforced{id_str}", check=chk + "MTA-STS"))
                    # 3.4: the policy must name every MX host, and be cached for weeks.
                    patterns = mta_sts_policy.get("mx") or []
                    uncovered = [e["host"] for e in mx.get("entries") or []
                                 if not any(_mx_pattern_match(p, e["host"]) for p in patterns)]
                    if uncovered:
                        items.append(_status("fail",
                            "MTA-STS policy does not name every MX host"
                            + (" — senders refuse to deliver to them" if mode == "enforce"
                               else " — mail to them fails once enforced"),
                            sub_lines=[f"Not covered: {', '.join(uncovered)}",
                                       f"Policy mx: {', '.join(patterns) or 'none'}"],
                            check=chk + "MTA-STS policy MX match"))
                    else:
                        items.append(_status("pass", "MTA-STS policy names every MX host",
                                             check=chk + "MTA-STS policy MX match"))
                    max_age = mta_sts_policy.get("max_age")
                    if isinstance(max_age, int):
                        days = max_age / 86400
                        if max_age < 604800:
                            items.append(_status("warn",
                                f"MTA-STS max_age {max_age} ({days:.1f} days) — under a week",
                                check=chk + "MTA-STS max_age"))
                        else:
                            items.append(_status("pass", f"MTA-STS max_age {max_age} ({days:.0f} days)",
                                                 check=chk + "MTA-STS max_age"))
                elif mode == "none":
                    items.append(_status("warn",
                        f"MTA-STS mode=none — explicit opt-out{id_str}", check=chk + "MTA-STS"))
                elif mta_sts_policy.get("fetched") is False:
                    items.append(_status("warn",
                        f"MTA-STS DNS record present but policy file missing or unreachable{id_str}", check=chk + "MTA-STS"))
                else:
                    items.append(_status("pass",
                        f"MTA-STS DNS record published{id_str}", check=chk + "MTA-STS"))
            else:
                # Wording fix (3.1.0): senders fall back, not receivers.
                items.append(_status("warn",
                    "No MTA-STS — sending servers have no policy preventing fallback to plaintext SMTP", check=chk + "MTA-STS"))

        if tls_rpt:
            if tls_rpt.get("error"):
                items.append(_status("info",
                    f"TLS-RPT DNS lookup failed: {tls_rpt['error']}", check=chk + "TLS-RPT"))
            elif tls_rpt.get("present"):
                rua_v = tls_rpt.get("rua") or ""
                rua_s = f" — {rua_v}" if rua_v else ""
                items.append(_status("pass",
                    f"TLS-RPT reporting enabled{rua_s}", check=chk + "TLS-RPT"))
            else:
                items.append(_status("warn",
                    "No TLS-RPT — no failure reporting for inbound mail TLS", check=chk + "TLS-RPT"))

        if dane and dane.get("mx_count", 0) > 0:
            with_t    = dane.get("with_tlsa", []) or []
            without_t = dane.get("without_tlsa", []) or []
            total = dane["mx_count"]
            if len(with_t) == total:
                items.append(_status("pass",
                    f"DANE/TLSA published on all {total} MX host{'s' if total != 1 else ''}", check=chk + "DANE TLSA on MX"))
            elif with_t:
                detail = []
                for h in with_t:
                    detail.append(f"✓ {h}")
                for h in without_t:
                    detail.append(f"✗ {h}")
                items.append(_status("warn",
                    f"DANE/TLSA on {len(with_t)}/{total} MX hosts — incomplete",
                    sub_lines=detail, check=chk + "DANE TLSA on MX"))
            else:
                # Wording fix (3.1.0): the old line "STARTTLS downgrade
                # not detected" read like a clean assessment.
                items.append(_status("fail",
                    f"No DANE/TLSA on any MX host — vulnerable to STARTTLS downgrade attacks", check=chk + "DANE TLSA on MX"))

        if dkim and dkim.get("checked"):
            found   = dkim.get("found", []) or []
            checked = dkim.get("checked", []) or []
            keys    = dkim.get("keys", {}) or {}
            if found:
                items.append(_status("pass",
                    f"DKIM key found at common selector(s): {', '.join(found)}",
                    note_lines=[f"Checked: {', '.join(checked)}"], check=chk + "DKIM (common selectors)"))
                # Key strength — independent rubric line
                ws = dkim.get("worst_strength")
                def _keydesc(sel, k):
                    algo = k.get("algorithm", "?")
                    bits = k.get("bits")
                    if algo == "rsa" and bits:
                        return f"{sel}: RSA-{bits}"
                    if algo == "ed25519":
                        return f"{sel}: Ed25519"
                    if k.get("strength") == "revoked":
                        return f"{sel}: revoked (p= empty)"
                    return f"{sel}: {algo}/{k.get('strength','?')}"
                desc = "; ".join(_keydesc(s, keys.get(s, {})) for s in found)
                if ws == "good":
                    items.append(_status("pass",
                        f"DKIM key strength acceptable: {desc}", check=chk + "DKIM key strength"))
                elif ws == "weak" and any((k or {}).get("strength") == "good" for k in keys.values()):
                    # 3.4.6: rotation leftover — see _collect_outcomes.
                    items.append(_status("warn",
                        f"DKIM key strength: {desc} — an RSA-1024 key is still published beside a stronger one",
                        note_lines=["Usually left over from a key rotation (Microsoft 365, for example, alternates "
                                    "selector1 and selector2). Receivers still verify mail against it, and NIST has "
                                    "disallowed RSA-1024 for new signatures since 2014, so rotate again or remove it "
                                    "until every published key is 2048-bit or Ed25519."],
                        check=chk + "DKIM key strength"))
                elif ws == "weak":
                    items.append(_status("warn",
                        f"DKIM key strength: {desc} — RSA-1024 has been disallowed for new signatures by "
                        f"NIST SP 800-131A since 2014",
                        note_lines=["RFC 8301 recommends at least 2048 bits. Upgrade to RSA-2048+ or Ed25519."],
                        check=chk + "DKIM key strength"))
                elif ws == "broken":
                    items.append(_status("fail",
                        f"DKIM key strength: {desc} — RSA <1024 is broken", check=chk + "DKIM key strength"))
                elif ws == "unparseable":
                    items.append(_status("info",
                        f"DKIM key strength: could not parse key ({desc})", check=chk + "DKIM key strength"))
                elif ws == "revoked":
                    items.append(_status("info",
                        f"DKIM key strength: revoked ({desc}) — operator deliberately disabled", check=chk + "DKIM key strength"))
            else:
                items.append(_status("warn",
                    f"No DKIM at common selectors ({', '.join(checked)})",
                    note_lines=_OneNote([
                        "Partial check only — DKIM uses arbitrary selector names; absence at",
                        "common names proves nothing. Use rua= reports from DMARC to discover",
                        "the actual selectors in use.",
                    ]), check=chk + "DKIM (common selectors)"))

        if items:
            out.append("")
            out.append("")
            out.extend(_subheading_with_explanation(
                f"Mail transport hardening — {domain_label} (RFC 8461, 8460, 6376, 7672)",
                "mail_transport"))
            out.extend(items)

        # ── BIMI (brand logo, informational) ─────────────────────────────────
        # Only shown for the source domain (no prefix). BIMI is now a scored
        # email check (0/1..1/1), so we render the subsection whenever the
        # domain has MX — including the missing case (a fail). The DMARC
        # cross-reference calls out the "published but won't render"
        # misconfiguration explicitly.
        bimi = results.get(f"{prefix}bimi", {}) or {}
        if not prefix and not bimi.get("error"):
            dmarc_pol = (dmarc.get("policy") or "").lower()
            enforcing = dmarc_pol in ("quarantine", "reject")
            bimi_items = []
            if not bimi.get("present"):
                bimi_items.append(_status("fail",
                    "No BIMI record — no brand logo will display beside your mail",
                    note_lines=["Publish default._bimi.<domain> with v=BIMI1; l=<logo URL>; "
                                "requires DMARC at quarantine or reject to render."], check=chk + "BIMI"))
            elif not bimi.get("has_logo"):
                if bimi.get("selfassert"):
                    bimi_items.append(_status("fail",
                        "BIMI record present but self-asserting (empty l=) — no logo published",
                        note_lines=["A self-asserting record declares participation but "
                                    "publishes no mark, so no logo can display."], check=chk + "BIMI"))
                else:
                    bimi_items.append(_status("fail",
                        "BIMI record present but malformed — no logo (l=) URL", check=chk + "BIMI"))
            else:
                logo = bimi.get("logo_url") or ""
                if not enforcing:
                    pol = dmarc_pol or "none"
                    bimi_items.append(_status("warn",
                        f"BIMI logo published but DMARC is p={pol} — the logo will "
                        f"NOT display until DMARC is at quarantine or reject",
                        note_lines=[f"Logo: {logo}"] if logo else None, check=chk + "BIMI"))
                elif bimi.get("has_vmc"):
                    bimi_items.append(_status("pass",
                        "BIMI published with logo and VMC — eligible for logo display "
                        "in Gmail, Apple Mail, and other supporting clients",
                        note_lines=[f"Logo: {logo}"] if logo else None, check=chk + "BIMI"))
                else:
                    bimi_items.append(_status("pass",
                        "BIMI published with logo (VMC not present) — renders in clients "
                        "that don't require a Verified Mark Certificate; Gmail and Apple "
                        "Mail additionally require a VMC",
                        note_lines=[f"Logo: {logo}"] if logo else None, check=chk + "BIMI"))
            if bimi_items:
                out.append("")
                out.append("")
                out.extend(_subheading_with_explanation(
                    f"BIMI brand indicator — {domain_label}",
                    "bimi"))
                out.extend(bimi_items)

    return "\n".join(out)


def _render_email_section(data):
    r = data.results
    redirect = r.get("redirect", {}) or {}
    redirected = redirect.get("redirected", False)

    parts = ["", _heading("EMAIL"), ""]
    parts.append(_render_email_block(
        data.original_domain,
        r.get("spf", {}) or {},
        r.get("dmarc", {}) or {},
        r.get("mx", {}) or {},
        r,
    ))

    if redirected and data.audit_domain != data.original_domain:
        parts.append("")
        parts.append("")
        if _md():
            parts.append(f"### Redirect target: {data.audit_domain}")
        else:
            parts.append("  " + "─" * (WIDTH - 2))
            parts.append(f"  Redirect target: {data.audit_domain}")
            parts.append("  " + "─" * (WIDTH - 2))
        parts.append("")
        parts.append(_para("Email is also audited for the redirect target, since "
                           "users may receive mail at either domain."))
        parts.append("")
        parts.append(_render_email_block(
            data.audit_domain,
            r.get("redirect_target_spf", {}) or {},
            r.get("redirect_target_dmarc", {}) or {},
            r.get("redirect_target_mx", {}) or {},
            r,
            prefix="redirect_target_",
        ))

    return "\n".join(parts)


# ── Detailed sections: DNS ───────────────────────────────────────────────────

def _render_dns_section(data):
    r = data.results
    dnssec = r.get("dnssec", {}) or {}
    caa    = r.get("caa", {}) or {}
    ns_soa = r.get("ns_soa", {}) or {}

    if not dnssec and not caa and not ns_soa:
        return ""

    parts = ["", _heading("DNS"), ""]

    # DNSSEC
    if dnssec:
        parts.extend(_subheading_with_explanation("DNSSEC (RFC 4033)", "dnssec"))
        tld_d = dnssec.get("tld", {}) or {}
        dom_d = dnssec.get("domain", {}) or {}

        tld_label = (tld_d.get("tld") or "").upper() or "TLD"
        if tld_d.get("error"):
            parts.append(_status("info",
                f".{tld_label} — DNS query failed: {tld_d['error']}"))
        elif tld_d.get("signed"):
            parts.append(_status("pass",
                f".{tld_label} is signed — DNSSEC chain possible"))
        else:
            parts.append(_status("warn",
                f".{tld_label} does not appear to be signed — DNSSEC chain cannot be established"))

        if dom_d.get("error"):
            parts.append(_status("info",
                f"Domain — DNS query failed: {dom_d['error']}", check="DNSSEC"))
        elif dom_d.get("dnskey") and dom_d.get("ad_flag"):
            parts.append(_status("pass",
                "Domain DNSSEC enabled and validated (DNSKEY present, AD flag confirmed)", check="DNSSEC"))
        elif dom_d.get("dnskey"):
            parts.append(_status("warn",
                "Domain DNSKEY found but AD flag not set (chain may be incomplete)", check="DNSSEC"))
        else:
            parts.append(_status("warn", "Domain DNSSEC not detected (no DNSKEY)", check="DNSSEC"))
            parts.append(_status("warn",
                "DNSSEC chain not validated (AD flag not set)", check="DNSSEC"))
        algs = dom_d.get("algorithms") or []
        if dom_d.get("dnskey") and algs:
            from .audit_checks import _DNSSEC_MODERN_ALGS
            names = ", ".join(f"{a} ({_DNSSEC_ALG_NAMES.get(a, 'unknown')})" for a in algs)
            if set(algs) & _DNSSEC_MODERN_ALGS:
                parts.append(_status("pass", f"Signing algorithm: {names}", check="DNSSEC algorithm"))
            elif 10 in algs:
                parts.append(_status("warn", f"Signing algorithm: {names} — not recommended (RFC 8624)",
                                     check="DNSSEC algorithm"))
            else:
                parts.append(_status("fail",
                    f"Signing algorithm: {names} — must not be used (RFC 8624, RFC 9905)",
                    sub_lines=["Validating resolvers treat a zone signed only with it as unsigned"],
                    check="DNSSEC algorithm"))
        parts.append("")
        parts.append("")

    # Nameservers / SOA
    if ns_soa:
        parts.extend(_subheading_with_explanation(
            "Nameservers (RFC 1034)", "nameservers"))
        if ns_soa.get("ns_error"):
            parts.append(_status("info",
                f"NS lookup failed: {ns_soa['ns_error']}", check="Nameserver count"))
        else:
            ns_count = ns_soa.get("ns_count", 0)
            if ns_count >= 2:
                parts.append(_status("pass",
                    f"{ns_count} authoritative nameservers", check="Nameserver count"))
            elif ns_count == 1:
                parts.append(_status("fail",
                    "Single nameserver — RFC 1034 recommends ≥2 for redundancy", check="Nameserver count"))
            else:
                parts.append(_status("info", "No nameservers found", check="Nameserver count"))

        ns_list = ns_soa.get("nameservers", []) or []
        if ns_list:
            parts.append("")
            parts.append(_items(ns_list))

        soa = ns_soa.get("soa")
        if soa:
            parts.append("")
            parts.append(_kv([
                ("SOA primary", soa.get("primary", "")),
                ("SOA serial",  soa.get("serial",  "")),
                ("SOA timers",  f"refresh {soa.get('refresh')} · retry {soa.get('retry')} · "
                                f"expire {soa.get('expire')} · minimum {soa.get('minimum')}"),
            ]))
            from .audit_checks import _soa_issues
            issues = _soa_issues(soa)
            parts.append("")
            if issues:
                parts.append(_status("info", "SOA timers outside RFC 1912 / RFC 2308 guidance",
                                     sub_lines=issues, check="SOA timers"))
            else:
                parts.append(_status("pass", "SOA timers within RFC 1912 / RFC 2308 guidance", check="SOA timers"))

        # ── NS health: lame delegation + open recursive resolver (1.2) ──
        ns_health = r.get("ns_health", {}) or {}
        if ns_health and not ns_health.get("error") and ns_health.get("ns_list"):
            parts.append("")
            if ns_health.get("probed", 0) > 0:
                lame = ns_health.get("lame_ns") or []
                if lame:
                    if len(lame) == 1:
                        parts.append(_status("fail",
                            f"Lame nameserver: {lame[0]} \u2014 listed in delegation but "
                            f"does not answer authoritatively for this zone (RFC 1034)", check="Authoritative delegation"))
                    else:
                        parts.append(_status("fail",
                            f"{len(lame)} lame nameservers: {', '.join(lame)} \u2014 "
                            f"listed in delegation but do not answer authoritatively (RFC 1034)", check="Authoritative delegation"))
                else:
                    parts.append(_status("pass",
                        "All authoritative nameservers respond authoritatively", check="Authoritative delegation"))

                opens = ns_health.get("open_resolver_ns") or []
                if opens:
                    if len(opens) == 1:
                        parts.append(_status("fail",
                            f"Open recursive resolver: {opens[0]} \u2014 answers "
                            f"recursion for arbitrary clients; abusable for DNS "
                            f"amplification attacks (RFC 5358 / BCP 140)", check="NS not open resolver"))
                    else:
                        parts.append(_status("fail",
                            f"{len(opens)} open recursive resolvers: {', '.join(opens)} \u2014 "
                            f"abusable for DNS amplification attacks (RFC 5358 / BCP 140)", check="NS not open resolver"))
                else:
                    parts.append(_status("pass",
                        "Nameservers do not serve open recursion", check="NS not open resolver"))

                unprobed = ns_health.get("unprobed") or []
                for ns_host, reason in unprobed:
                    parts.append(_status("info",
                        f"Could not probe {ns_host}: {reason}"))

        # 3.4: the nameservers' own addresses — IPv6 and network spread.
        ns_i = ((r.get("infra_routing") or {}).get("ns")) or {}
        if ns_i.get("hosts") and not ns_i.get("error"):
            parts.append("")
            hosts = ns_i["hosts"]
            with_v6 = [h for h, i in hosts.items() if i.get("v6")]
            if len(with_v6) >= 2:
                parts.append(_status("pass", f"{len(with_v6)} of {len(hosts)} nameservers reachable over IPv6",
                                     check="Nameservers on IPv6"))
            else:
                parts.append(_status("warn",
                    f"{len(with_v6)} of {len(hosts)} nameservers reachable over IPv6 — at least two should be",
                    check="Nameservers on IPv6"))
            by_asn = {}
            for l in ns_i.get("lookups") or []:
                if l.get("asn") is not None:
                    by_asn.setdefault(l["asn"], set()).add(l["host"])
            if len(by_asn) >= 2:
                parts.append(_status("pass", f"Nameservers spread over {len(by_asn)} networks",
                                     sub_lines=[f"AS{a}: {', '.join(sorted(h))}" for a, h in sorted(by_asn.items())],
                                     check="Nameserver networks"))
            elif by_asn:
                a = next(iter(by_asn))
                parts.append(_status("info", f"All nameservers checked are in one network (AS{a})",
                                     sub_lines=["One network outage or misrouting affects all of them (RFC 2182)"],
                                     check="Nameserver networks"))

        parts.append("")
        parts.append("")

    # CAA
    if caa:
        parts.extend(_subheading_with_explanation(
            "Certification Authority Authorization (CAA) (RFC 8659)", "caa"))
        if caa.get("error"):
            parts.append(_status("info",
                f"CAA lookup failed: {caa['error']}", check="CAA records"))
        elif caa.get("present"):
            inh = caa.get("inherited_from")
            inh_str = f" (inherited from {inh})" if inh else ""
            issuers = caa.get("issue", []) or []
            if not issuers or issuers == [";"]:
                parts.append(_status("pass",
                    f"CAA records published — issuance disallowed by default{inh_str}", check="CAA records"))
            else:
                parts.append(_status("pass",
                    f"CAA records published — {len(issuers)} authorised CA{'s' if len(issuers) != 1 else ''}{inh_str}",
                    sub_lines=issuers, check="CAA records"))
            if caa.get("iodef"):
                parts.append(_status("pass",
                    "Security reporting contact (iodef=) set"))
            else:
                parts.append(_status("warn",
                    "No security reporting contact (iodef=) — CAs cannot notify you of policy violations"))
        else:
            # Wording / consistency fix (3.1.0): old HTML used a warn
            # marker for this 0/2 fail row. The TXT render uses fail.
            parts.append(_status("fail",
                "No CAA records — any public CA can issue certificates for this domain", check="CAA records"))

    # 3.4: CNAMEs pointing at names that no longer exist.
    dangling = r.get("dangling_cname") or {}
    named = {n: i for n, i in (dangling.get("names") or {}).items() if i.get("end") != "error"}
    if named:
        parts.append("")
        parts.append("")
        parts.extend(_subheading_with_explanation("Dangling CNAMEs", "dangling_dns"))
        for n, i in sorted(named.items()):
            chain = " → ".join([n] + i.get("chain", []))
            if i.get("end") == "nxdomain":
                parts.append(_status("fail", f"{chain} — the target does not exist",
                                     sub_lines=["Whoever registers that name at the provider can serve content here"],
                                     check="Dangling CNAME"))
            elif i.get("chain"):
                parts.append(_status("pass", f"{chain} — target exists", check="Dangling CNAME"))
        if not any(i.get("chain") for i in named.values()):
            parts.append(_status("pass", "No CNAMEs on the domain or its www form", check="Dangling CNAME"))

    # 3.5.9: end-of-life BIND named in a version.bind answer.
    tech_eol = r.get("tech_eol") or {}
    parts.extend(_eol_tech_block(
        [t for t in (tech_eol.get("techs") or []) if t.get("source") == "version_bind"],
        "End-of-life DNS server software", "DNS server software support", key="eol_dns"))

    return "\n".join(parts)


# ── Detailed sections: Routing (IP / ASN / RPKI) ─────────────────────────────

def _render_routing_section(data):
    ipr = data.results.get("ip_routing")
    if not ipr:
        return ""

    parts = ["", _heading("IP / ASN / RPKI (RFC 6480)"), ""]
    parts.extend(_section_explanation_lines("routing"))

    # 3.4.3: the routing check was cut off by the audit deadline. Say so,
    # rather than printing two empty address-family blocks.
    if str(ipr.get("error") or "").startswith("Skipped"):
        parts.append(_status("info",
            "Routing lookup did not finish in time — IPv6 and RPKI for the website are not rated",
            sub_lines=["Usually RIPEstat answering slowly; running the audit again normally succeeds"],
            check="IPv6"))
        ipr = {}

    def _af_block(af_label, af):
        addr   = af.get("address")
        af_err = af.get("error")
        prefix = af.get("prefix")
        asn    = af.get("asn")
        asn_name = af.get("asn_name", "")
        rpki   = af.get("rpki_status")

        # Display label for messages — "IPv4 (legacy IP)" for v4 to
        # reinforce the messaging that IPv4 is the deprecated protocol;
        # plain "IPv6" for v6.
        af_display = "IPv4 (legacy IP)" if af_label == "IPv4" else af_label

        sub = [_subheading(_AF_LABEL_WITH_RFC.get(af_label, af_label)), ""]

        if addr and af_err == "no BGP prefix announced for this IP":
            # 3.4.3: published, but nothing routes to it.
            sub.append(_kv([("Address", addr)]))
            sub.append("")
            sub.append(_status("fail" if af_label == "IPv6" else "info",
                f"{af_display} address is not announced in BGP — unreachable from the internet",
                sub_lines=["Usually a stale record after a move, or a prefix the provider stopped announcing"],
                check="IPv6" if af_label == "IPv6" else None))
            return sub

        if not addr and af_err:
            sev = "warn" if (af_label == "IPv6" and "no AAAA" in (af_err or "")) else "info"
            sub.append(_status(sev, f"{af_display} — {af_err}", check="IPv6" if af_label == "IPv6" else None))
            return sub

        all_addrs = af.get("all_addresses") or ([addr] if addr else [])

        # Layout: write the address(es) first, then a kv block of ASN+Prefix.
        # If multiple addresses, the first goes on the "Addresses (N)" line
        # and the rest are listed immediately under it.
        if all_addrs:
            if len(all_addrs) == 1:
                addr_pairs = [("Address", all_addrs[0])]
                sub.append(_kv(addr_pairs))
            else:
                addr_pairs = [(f"Addresses ({len(all_addrs)})",
                               ", ".join(all_addrs) if _md() else all_addrs[0])]
                sub.append(_kv(addr_pairs))
                # Continuation indent matches _kv's value column. _kv pads
                # keys to max-key-width + 4 (gap). For just one pair, the
                # value column starts at indent + len(key) + 4.
                key_w = len(addr_pairs[0][0])
                value_col = 7 + key_w + 4
                for extra in ([] if _md() else all_addrs[1:]):
                    sub.append(f"{' ' * value_col}{extra}")

        meta_pairs = []
        if asn is not None:
            asn_disp = f"AS{asn}" + (f" — {asn_name}" if asn_name else "")
            meta_pairs.append(("ASN", asn_disp))
        if prefix:
            meta_pairs.append(("Prefix", prefix))
        if meta_pairs:
            sub.append(_kv(meta_pairs))
        sub.append("")

        if rpki == "valid":
            sub.append(_status("pass",
                "RPKI: valid — origin AS authorised by ROA", check=af_label + " RPKI"))
        elif rpki == "invalid":
            sub.append(_status("fail",
                "RPKI: invalid — ROA exists but origin AS mismatch (possible route hijack)", check=af_label + " RPKI"))
        elif rpki == "not-found":
            sub.append(_status("warn",
                "RPKI: not-found — no Route Origin Authorization published for this prefix", check=af_label + " RPKI"))
        elif rpki == "error" or (rpki is None and af_err):
            err_str = f": {af_err}" if af_err else ""
            sub.append(_status("info", f"RPKI check failed{err_str}", check=af_label + " RPKI"))

        if af.get("irr_in_ris"):
            sub.append(_status("pass", "IRR: prefix seen in RIS routing table", check=af_label + " IRR/RIS"))
        elif prefix:
            sub.append(_status("info",
                "IRR: prefix not seen in RIS snapshot (may be filtered or new)", check=af_label + " IRR/RIS"))

        return sub

    parts.extend(_af_block("IPv4", ipr.get("v4", {}) or {}))
    parts.append("")
    parts.append("")
    parts.extend(_af_block("IPv6", ipr.get("v6", {}) or {}))

    # 3.4: nameserver and mail server addresses — RPKI, and mail on IPv6.
    infra = data.results.get("infra_routing") or {}
    rows = []
    for kind, label in (("ns", "Nameserver"), ("mx", "Mail server")):
        block = infra.get(kind) or {}
        lookups = block.get("lookups") or []
        if kind == "mx" and block.get("hosts") and not block.get("error"):
            hosts = block["hosts"]
            n6 = [h for h, i in hosts.items() if i.get("v6")]
            # 3.4.5: say when only the first few mail servers were checked.
            total = max(block.get("total") or 0, len(hosts))
            checked = "" if total == len(hosts) else " checked"
            sampled = ([f"Checked the first {len(hosts)} of {total} mail servers, by MX priority"]
                       if checked else None)
            noun = "mail server" if len(hosts) == 1 else "mail servers"
            if len(n6) == len(hosts):
                head = ("The mail server is reachable over IPv6" if len(hosts) == 1
                        else f"All {len(hosts)} mail servers{checked} reachable over IPv6")
                rows.append(_status("pass", head, note_lines=sampled, check="Mail servers on IPv6"))
            else:
                rows.append(_status("warn", f"{len(n6)} of {len(hosts)} {noun}{checked} reachable over IPv6",
                                    note_lines=sampled,
                                    sub_lines=[f"No IPv6: {', '.join(sorted(h for h in hosts if h not in n6))}"],
                                    check="Mail servers on IPv6"))
        for l in lookups:
            st = l.get("rpki_status")
            where = f"{l['host']} {l['address']}" + (f" ({l['prefix']}, AS{l['asn']})" if l.get("prefix") else "")
            if st == "valid":
                rows.append(_status("pass", f"{label} RPKI valid: {where}", check=f"{label} RPKI"))
            elif st == "invalid":
                rows.append(_status("fail", f"{label} RPKI invalid: {where} — the route contradicts its ROA",
                                    check=f"{label} RPKI"))
            elif st == "not-found":
                rows.append(_status("warn", f"{label} RPKI not-found: {where} — no ROA published",
                                    check=f"{label} RPKI"))
            else:
                rows.append(_status("info", f"{label} RPKI check failed: {l['host']} {l['address']}"
                                    + (f" ({l['error']})" if l.get("error") else ""), check=f"{label} RPKI"))
        # 3.4.5: RIPEstat lookups are capped per scan; say what was left out.
        if block.get("unchecked"):
            n = block["unchecked"]
            rows.append(_status("info", f"{n} more {label.lower()} address{'es' if n != 1 else ''} not looked up"
                                f" (the scan makes at most {infra.get('max_lookups') or _infra_max_lookups()} routing lookups)"))
    if rows:
        parts.append("")
        parts.append("")
        parts.extend(_subheading_with_explanation("Nameserver and mail server addresses", "infra_routing"))
        parts.extend(rows)

    return "\n".join(parts)


def _landing_host(results, domain):
    """The host the site ends up on when it isn't `domain` itself (e.g. the
    bare name redirects to www), else None."""
    wau = results.get("www_apex_unified") or {}
    for final in (wau.get("www_final"), wau.get("apex_final")):
        if final and final.lower().rstrip(".") != (domain or "").lower():
            return final
    return None


def _mismatch_notes(data, san_names):
    """3.4.6: when the bare name's certificate is wrong but the site lives on
    another host, say why a browser may still seem fine."""
    landing = _landing_host(data.results, data.audit_domain)
    if not landing:
        return None
    names = ", ".join(san_names[:3]) if san_names else "other names"
    notes = [f"https://{data.audit_domain} presents a certificate for {names}, so a browser that goes there "
             f"over HTTPS stops at a certificate warning.",
             f"The site itself is at {landing}."]
    # 3.4.7: only explain why a browser looks fine when http:// redirects.
    if (data.results.get("http_redirect") or {}).get("status") == "https_only":
        notes[1] += (" Visitors who type the bare name usually start on http://, follow the redirect and never "
                     f"see the problem; links and bookmarks to https://{data.audit_domain} do.")
    return notes


def _infra_max_lookups():
    from .audit_checks import _INFRA_MAX_LOOKUPS
    return _INFRA_MAX_LOOKUPS


# ── Detailed sections: TLS ───────────────────────────────────────────────────

def _render_tls_section(data):
    r = data.results
    tls = r.get("tls", {}) or {}
    cert_var = r.get("cert_variant", {}) or {}

    if not tls and not cert_var:
        return ""

    parts = ["", _heading("TLS (RFC 8446)"), ""]
    parts.extend(_section_explanation_lines("tls"))

    if tls.get("error") and tls.get("tls_cert_error"):
        # 3.4.2: name the cause, and what the (untrusted) certificate says.
        reason = tls.get("cert_error_reason")
        c = tls.get("cert_failed_details") or {}
        head = {"expired": "Certificate has expired", "not_yet_valid": "Certificate is not valid yet",
                "self_signed": "Certificate is self-signed",
                "untrusted": "Certificate does not chain to a trusted authority"}.get(reason, "Certificate failed verification")
        if reason == "expired" and c.get("not_after"):
            head += f" (on {c['not_after'][:10]})"
        elif reason == "not_yet_valid" and c.get("not_before"):
            head += f" (valid from {c['not_before'][:10]})"
        sub = [s for s in (
            f"Issued to {c['subject_cn']}" if c.get("subject_cn") else None,
            f"Issued by {c['issuer_cn']}" if c.get("issuer_cn") else None,
            f"OpenSSL: {tls['error']}",
        ) if s]
        parts.append(_status("fail", head + " — browsers block the site", sub_lines=sub, check="TLS connection"))
    elif tls.get("error"):
        parts.append(_status("fail",
            f"Could not connect on port 443: {tls['error']}", check="TLS connection"))
    else:
        ver = tls.get("version", "unknown")
        if ver == "TLSv1.3":
            parts.append(_status("pass", f"Negotiated {ver}", check="TLS 1.3"))
        elif ver == "TLSv1.2":
            parts.append(_status("warn",
                f"Negotiated {ver} — TLS 1.3 not supported", check="TLS 1.3"))
        else:
            parts.append(_status("fail",
                f"Negotiated {ver} — upgrade required", check="TLS 1.3"))

        # 3.4: what else the server accepts when asked for it.
        from .audit_checks import (_legacy_tls_outcome, _forward_secrecy_outcome, _cert_key_outcome,
                                   _cert_sig_outcome)
        legacy = r.get("tls_legacy") or {}
        lo = _legacy_tls_outcome(legacy) if legacy else None
        if lo in ("tls1_0_accepted", "tls1_1_accepted"):
            accepted = [v for k, v in (("tls1_0", "TLS 1.0"), ("tls1_1", "TLS 1.1")) if legacy.get(k) == "accepted"]
            parts.append(_status("fail", f"{' and '.join(accepted)} still accepted — deprecated by RFC 8996",
                                 check="Legacy TLS disabled"))
        elif lo == "disabled":
            parts.append(_status("pass", "TLS 1.0 and 1.1 refused", check="Legacy TLS disabled"))
        elif lo == "unprobed":
            parts.append(_status("info", "TLS 1.0 / 1.1 not tested — this system's OpenSSL cannot offer them",
                                 check="Legacy TLS disabled"))
        elif legacy:
            parts.append(_status("info", "TLS 1.0 / 1.1 not determined — the probe got no answer",
                                 check="Legacy TLS disabled"))
        fo = _forward_secrecy_outcome(legacy) if legacy else None
        if fo == "null_cipher":
            parts.append(_status("fail", "NULL cipher accepted — traffic can be sent unencrypted",
                                 check="Forward secrecy"))
        elif fo == "static_rsa":
            parts.append(_status("fail", "Static RSA key exchange accepted — no forward secrecy for those connections",
                                 sub_lines=["A stolen server key decrypts recorded traffic"], check="Forward secrecy"))
        elif fo == "required":
            parts.append(_status("pass", "Forward secrecy required (static RSA and NULL ciphers refused)",
                                 check="Forward secrecy"))
        elif fo == "unprobed":
            parts.append(_status("info", "Key exchange not tested — this system's OpenSSL cannot offer it",
                                 check="Forward secrecy"))

        ko, so = _cert_key_outcome(tls), _cert_sig_outcome(tls)
        kind, bits, sig = tls.get("cert_key_type"), tls.get("cert_key_bits"), tls.get("cert_sig_alg") or "?"
        key = f"{kind} {bits}-bit" if bits else str(kind)
        if ko == "weak_key":
            parts.append(_status("fail", f"Certificate key {key} — below 2048-bit RSA / 256-bit EC",
                                 check="Certificate key size"))
        elif ko:
            parts.append(_status("pass", f"Certificate key {key}", check="Certificate key size"))
        if so == "weak_signature":
            parts.append(_status("fail", f"Certificate signed with {sig} — SHA-1/MD5 signatures are broken",
                                 check="Certificate signature"))
        elif so:
            parts.append(_status("pass", f"Certificate signed with {sig}", check="Certificate signature"))

        names_match = tls.get("cert_names_match")
        san_names   = tls.get("cert_san_names", []) or []
        audit_domain_lc = (data.audit_domain or "").lower()

        if names_match is True:
            covering = [n for n in san_names
                        if n == audit_domain_lc
                        or (n.startswith("*.") and audit_domain_lc.endswith("." + n[2:]))]
            note = ([f"Matched by: {', '.join(covering)}"]
                    if covering else None)
            parts.append(_status("pass", "Certificate name matches domain",
                                 note_lines=note, check="Certificate name match"))
        elif names_match is False:
            parts.append(_status("fail",
                f"Certificate name mismatch — cert does not cover {data.audit_domain}",
                note_lines=_mismatch_notes(data, san_names), check="Certificate name match"))

        lifetime = tls.get("cert_lifetime_days")
        issued   = tls.get("cert_issued",  "")
        expires  = tls.get("cert_expires", "")
        if lifetime is not None:
            date_note = [f"Issued:  {issued}", f"Expires: {expires}"]
            if lifetime <= _CERT_LIFETIME_MAX_DAYS:
                parts.append(_status("pass",
                    f"Certificate lifetime: {lifetime} days — automated issuance likely",
                    note_lines=date_note, check="Certificate lifetime"))
            else:
                parts.append(_status("warn",
                    f"Certificate lifetime: {lifetime} days — may indicate manual renewal",
                    note_lines=date_note, check="Certificate lifetime"))

        renewal = _cert_renewal_text(tls)
        if renewal:
            parts.append(_status(renewal[0], renewal[1], check="Certificate renewal"))

        cv_outcome = cert_var.get("outcome")
        if cv_outcome == "covers":
            parts.append(_status("pass",
                "Certificate covers the redirect source/target variant", check="Cert covers www variant"))
        elif cv_outcome == "missing_variant":
            missing = cert_var.get("missing", []) or []
            parts.append(_status("warn",
                f"Certificate missing coverage for: {', '.join(missing)} — users typing the uncovered name see a TLS error before the redirect", check="Cert covers www variant"))

        # Chain completeness — only emit a row when chain inspection actually
        # ran (Python 3.13+). On older Pythons (chain_status='unsupported')
        # stay silent rather than adding a confusing "we couldn't check" line.
        cs = tls.get("chain_status")
        sent = tls.get("chain_sent_count")
        ver_n = tls.get("chain_verified_count")
        if cs == "complete":
            parts.append(_status("pass",
                f"Server sends complete certificate chain (sent {sent}, verified {ver_n})", check="Cert chain completeness"))
        elif cs == "incomplete":
            parts.append(_status("warn",
                f"Incomplete chain: server sent {sent} cert(s) but {ver_n} were needed",
                note_lines=_OneNote([
                    "Clients fall back to AIA fetching (some clients don't",
                    "AIA-fetch; captive portals break it; latency suffers).",
                    "Server should send leaf + every needed intermediate.",
                ]), check="Cert chain completeness"))

    if not tls.get("error"):
        kv_pairs = []
        if tls.get("cert_issuer"):
            kv_pairs.append(("Issuer", _expand_cert_issuer(tls["cert_issuer"])))
        if tls.get("cert_issued"):
            kv_pairs.append(("Issued", tls["cert_issued"]))
        if tls.get("cert_expires"):
            kv_pairs.append(("Expires", tls["cert_expires"]))
        if tls.get("cert_lifetime_days") is not None:
            kv_pairs.append(("Lifetime", f"{tls['cert_lifetime_days']} days"))
        if kv_pairs:
            parts.append("")
            parts.append("")
            parts.append(_subheading("Certificate (CA/Browser Forum Baseline Requirements)"))
            parts.append("")
            parts.append(_kv(kv_pairs))

        san = tls.get("cert_san_names") or []
        if san:
            parts.append("")
            parts.append(_code_list(f"SAN names ({len(san)}):", san))

    return "\n".join(parts)


# ── Detailed sections: HTTP ──────────────────────────────────────────────────

def _render_http_section(data):
    r = data.results
    redirect    = r.get("redirect", {}) or {}
    http_redir  = r.get("http_redirect", {}) or {}
    hv          = r.get("http_version", {}) or {}
    server      = r.get("server_header", {}) or {}

    if not redirect and not http_redir and not hv:
        return ""

    parts = ["", _heading("HTTP (RFC 9113, 9114)"), ""]
    parts.extend(_section_explanation_lines("http"))

    elapsed = redirect.get("elapsed_ms")
    if elapsed is not None:
        if elapsed <= 200:
            sev = "pass"
        elif elapsed <= 1000:
            sev = "warn"
        else:
            sev = "fail"
        parts.append(_status(sev,
            f"Response time: {round(elapsed):,} ms",
            note_lines=["Includes DNS + TCP + TLS handshake — not a pure HTTP RTT"]))

    if redirect.get("redirected"):
        if redirect.get("first_hop_https") and redirect.get("first_hop_same_host"):
            parts.append(_status("pass", "First redirect hop is HTTPS on the same host", check="Redirect first-hop hygiene"))
        elif redirect.get("first_hop_url"):
            first_hop = redirect.get("first_hop_url")
            if not redirect.get("first_hop_https"):
                parts.append(_status("warn",
                    f"First redirect hop is plain HTTP ({first_hop}) — bypasses HSTS", check="Redirect first-hop hygiene"))
            else:
                parts.append(_status("warn",
                    f"First redirect hop is off-host ({first_hop}) — leaks Referer and prevents HSTS for the apex", check="Redirect first-hop hygiene"))

    # ── www and apex unified (1.1) ───────────────────────────────────────────
    wau = r.get("www_apex_unified", {}) or {}
    wau_outcome = wau.get("outcome")
    if wau_outcome in ("unified", "canonical", "split"):
        # 3.5.10: its own check; "unified" below is only rated when this passes.
        parts.append(_status("pass",
            f"{wau.get('apex_host') or 'Apex'} and {wau.get('www_host') or 'www'} both have DNS records",
            check="www and apex resolve"))
    if wau_outcome == "unified":
        apex_h = wau.get("apex_host", "")
        www_h  = wau.get("www_host", "")
        final = wau.get("apex_final") or wau.get("www_final")
        where = f"both land on {final}" if final else f"{apex_h} \u2194 {www_h}"
        parts.append(_status("pass",
            f"Apex and www unified ({where})", check="www and apex unified"))
    elif wau_outcome == "canonical":
        apex_h = wau.get("apex_host", "")
        www_h  = wau.get("www_host", "")
        parts.append(_status("pass",
            f"Apex and www both serve the site; both pages name {wau.get('canonical_host')} as canonical",
            note_lines=["MDN accepts this as well as a redirect: <link rel=\"canonical\"> on "
                        f"{apex_h} and {www_h} points at the same address"],
            check="www and apex unified"))
    elif wau_outcome == "split":
        apex_h = wau.get("apex_host", "")
        www_h  = wau.get("www_host", "")
        canon = [f"{h} names {c}" for h, c in ((apex_h, wau.get("apex_canonical")),
                                                (www_h, wau.get("www_canonical"))) if c]
        parts.append(_status("fail",
            f"Apex and www serve separate pages \u2014 neither {apex_h} nor {www_h} "
            f"redirects to the other", check="www and apex unified",
            note_lines=[("rel=canonical: " + "; ".join(canon) + " (both pages must name the same one)")
                        if canon else "Neither page names a canonical address (rel=canonical)"]))
    elif wau_outcome == "half_missing":
        missing = wau.get("missing_side")
        if missing == "apex":
            apex_h = wau.get("apex_host", "")
            www_h  = wau.get("www_host", "")
            parts.append(_status("fail",
                f"Apex {apex_h} has no A/AAAA records \u2014 users typing the bare "
                f"domain get a DNS error (web/TLS audited at {www_h} via fallback)", check="www and apex resolve"))
        else:  # "www"
            apex_h = wau.get("apex_host", "")
            www_h  = wau.get("www_host", "")
            parts.append(_status("fail",
                f"www variant {www_h} has no A/AAAA records \u2014 users typing the "
                f"www form get a DNS error", check="www and apex resolve"))
    # wau_outcome == "not_scored" or missing: no row emitted

    http3       = server.get("http3_advertised")
    alt_svc_val = server.get("alt_svc")
    hv_ver      = hv.get("version")
    if http3:
        alt_note = [f"Alt-Svc: {alt_svc_val}"] if alt_svc_val else None
        parts.append(_status("pass", "HTTP/3 advertised", note_lines=alt_note, check="HTTP version"))
    elif hv_ver == "HTTP/2":
        parts.append(_status("warn", "HTTP/2 supported, HTTP/3 not advertised", check="HTTP version"))
    elif hv_ver == "HTTP/1.1":
        parts.append(_status("fail",
            "HTTP/1.1 detected — server does not support HTTP/2 or HTTP/3 (http1mustdie.com)", check="HTTP version"))
    elif hv.get("error"):
        parts.append(_status("info",
            f"HTTP version check failed: {hv['error']}", check="HTTP version"))

    # 3.4: HTTPS (SVCB) DNS record, RFC 9460.
    https_rr = r.get("https_rr") or {}
    if https_rr.get("present"):
        extra = []
        if https_rr.get("alpn"):
            extra.append("alpn " + ",".join(https_rr["alpn"]))
        if https_rr.get("ech"):
            extra.append("Encrypted ClientHello key")
        parts.append(_status("pass", "HTTPS DNS record published" + (f" ({'; '.join(extra)})" if extra else ""),
                             check="HTTPS DNS record"))
    elif https_rr.get("present") is False:
        parts.append(_status("info", "No HTTPS DNS record (RFC 9460) — optional", check="HTTPS DNS record"))

    hr_status = http_redir.get("status")
    hr_detail = http_redir.get("detail", "")
    # http_redir.detail starts with the same phrase as the body (e.g.
    # "http:// redirects to HTTPS (final: ...)") because it's also
    # consumed by the terminal renderer where the duplication isn't
    # visible. For the report, slice off any leading prefix that
    # duplicates the body so the note shows only its supplemental info.
    def _trim_redundant_prefix(detail, *prefixes):
        for p in prefixes:
            if detail.startswith(p):
                rest = detail[len(p):].lstrip(" -—:(")
                rest = rest.rstrip(")")
                return rest if rest else None
        return detail or None

    if hr_status == "https_only":
        trimmed = _trim_redundant_prefix(hr_detail, "http:// redirects to HTTPS")
        notes = [trimmed] if trimmed else None
        parts.append(_status("pass", "http:// redirects to HTTPS",
                             note_lines=notes, check="HTTP→HTTPS redirect"))
    elif hr_status == "http_available":
        verify = f"Verify with: curl -v http://{data.audit_domain}"
        trimmed = _trim_redundant_prefix(hr_detail, "Page is accessible over plain HTTP")
        notes = []
        if trimmed:
            notes.append(trimmed)
        notes.append(verify)
        parts.append(_status("fail",
            "Page is accessible over plain HTTP",
            note_lines=notes, check="HTTP→HTTPS redirect"))
    elif hr_status == "http_error":
        sc = http_redir.get("status_code", "")
        verify = f"Verify with: curl -v http://{data.audit_domain}"
        # Port 80 returned 4xx/5xx without redirecting. Treated as a pass
        # because the security outcome (no plaintext content) is achieved.
        parts.append(_status("pass",
            f"HTTP port 80 refuses plaintext (status {sc} from http://{data.audit_domain})",
            note_lines=[verify], check="HTTP→HTTPS redirect"))
    elif hr_status == "unreachable":
        # 3.4.5: the detail often repeats the headline word for word.
        same = (hr_detail or "").strip().rstrip(".").lower() == "http port 80 not reachable"
        notes = [hr_detail] if hr_detail and not same else None
        parts.append(_status("info",
            "HTTP port 80 not reachable",
            note_lines=notes, check="HTTP→HTTPS redirect"))

    return "\n".join(parts)


# ── Detailed sections: HSTS ──────────────────────────────────────────────────

def _render_hsts_section(data):
    hsts = data.results.get("hsts", {}) or {}
    if not hsts:
        return ""

    parts = ["", _heading("HSTS (RFC 6797)"), ""]
    parts.extend(_section_explanation_lines("hsts"))

    if hsts.get("error"):
        parts.append(_status("info",
            f"Could not fetch HTTPS response: {hsts['error']}", check="HSTS"))
    elif not hsts.get("present"):
        parts.append(_status("fail", "Strict-Transport-Security header not set", check="HSTS"))
    else:
        parts.append(_status("pass", "Strict-Transport-Security header present", check="HSTS"))

        ma = hsts.get("max_age")
        min_age = 15552000  # 180 days — OWASP/Qualys minimum
        if ma is None:
            parts.append(_status("warn",
                "max-age missing — header has no expiry directive", check="HSTS max-age"))
        elif ma >= min_age:
            days = ma // 86400
            parts.append(_status("pass",
                f"max-age={int(ma):,} ({days} days)", check="HSTS max-age"))
        else:
            days = ma // 86400
            min_days = min_age // 86400
            parts.append(_status("warn",
                f"max-age={int(ma):,} ({days} days) — below the {min_days}-day minimum (OWASP/Qualys)", check="HSTS max-age"))

        if hsts.get("includes_subdomains"):
            parts.append(_status("pass", "includeSubDomains set", check="HSTS includeSubDomains"))
        else:
            parts.append(_status("warn", "includeSubDomains not set", check="HSTS includeSubDomains"))

    if hsts.get("preload_error") and hsts.get("preloaded") is None:
        parts.append(_status("info",
            f"Preload list check failed: {hsts['preload_error']}", check="HSTS preload"))
    elif hsts.get("preloaded"):
        parts.append(_status("pass", "Domain is on the HSTS preload list", check="HSTS preload"))
    elif hsts.get("preload_status") == "pending":
        # Submitted to hstspreload.org AND accepted, waiting for next Chrome
        # rollup. Distinct from the bare preload-directive case below.
        parts.append(_status("warn",
            "HSTS preload submission pending \u2014 accepted by hstspreload.org, "
            "waiting for the next Chrome release rollup (typically 2\u20133 months)", check="HSTS preload"))
    elif hsts.get("present") and hsts.get("preload_directive") and not _hsts_preload_ready(hsts):
        parts.append(_status("info",
            "preload directive present, but the header does not qualify for the preload list yet",
            note_lines=["hstspreload.org needs max-age of at least 31536000 (one year) and includeSubDomains"],
            check="HSTS preload"))
    elif hsts.get("present") and hsts.get("preloaded") is False and not _hsts_preload_ready(hsts):
        parts.append(_status("info", "Not in HSTS preload list (fix the HSTS header first)",
                             check="HSTS preload"))
    elif hsts.get("present") and hsts.get("preload_directive"):
        parts.append(_status("warn",
            "preload directive present in header but domain not submitted to "
            "hstspreload.org", check="HSTS preload", note_lines=_HSTS_PRELOAD_STEPS))
    elif hsts.get("present") and hsts.get("preloaded") is False:
        parts.append(_status("warn", "Not in HSTS preload list", check="HSTS preload",
                             note_lines=_HSTS_PRELOAD_STEPS))

    if hsts.get("present") and hsts.get("raw"):
        parts.append("")
        parts.append(_raw_value("Raw header:", hsts["raw"]))

    return "\n".join(parts)


# ── Detailed sections: Server / Technology Disclosure ───────────────────────

def _render_server_disclosure_section(data):
    r = data.results
    srv = r.get("server_header", {}) or {}
    os_eol = r.get("os_eol") or {}

    if not srv and not os_eol:
        return ""

    parts = ["", _heading("SERVER & TECHNOLOGY DISCLOSURE (OWASP information leakage)"), ""]
    parts.extend(_section_explanation_lines("server_disclosure"))

    if srv.get("error"):
        parts.append(_para("Site unreachable. Server and security headers cannot be evaluated.", 4))
        parts.append(_para(str(srv['error']), 4))
        return "\n".join(parts)

    val = srv.get("server")
    try:
        from .audit_checks import classify_server
        kind = classify_server(val)
    except Exception:
        kind = "unknown"

    if kind == "absent":
        parts.append(_status("pass", "Server header not present", check="Server header"))
    elif kind == "good_proxy":
        parts.append(_status("pass",
            f"Server: {val} — reverse proxy / CDN", check="Server header"))
    elif kind == "origin_with_version":
        parts.append(_status("fail",
            f"Server: {val} — software version disclosed", check="Server header"))
    elif kind == "origin_no_version":
        parts.append(_status("warn",
            f"Server: {val} — origin server exposed (no version)", check="Server header"))
    else:
        if val:
            parts.append(_status("warn",
                f"Server: {val} — server technology disclosed", check="Server header"))

    if srv.get("x_powered_by"):
        parts.append(_status("fail",
            f"X-Powered-By: {srv['x_powered_by']} — technology disclosed", check="X-Powered-By absent"))
    else:
        parts.append(_status("pass", "X-Powered-By header not present", check="X-Powered-By absent"))

    # Server clock
    clock = r.get("clock", {}) or {}
    skew = clock.get("skew_seconds")
    if clock.get("outcome") == "in_sync":
        parts.append(_status("pass",
            f"Server clock in sync with UTC (skew: {skew:+.0f}s)", check="Server clock accuracy"))
    elif clock.get("outcome") == "minor_skew":
        parts.append(_status("warn",
            f"Server clock skew: {skew:+.0f}s — small but noticeable", check="Server clock accuracy"))
    elif clock.get("outcome") == "bad_skew":
        parts.append(_status("fail",
            f"Server clock skew: {skew:+.0f}s — large skew can break HSTS, OAuth, and certificate validation", check="Server clock accuracy"))

    # OS detection
    os_findings   = (os_eol or {}).get("os_findings") or []
    tls_old_stack = (os_eol or {}).get("tls_old_stack")
    tls_signals   = (os_eol or {}).get("tls_signals") or []
    if os_findings or tls_old_stack or os_eol.get("error"):
        parts.append("")
        parts.append("")
        parts.extend(_subheading_with_explanation(
            "Operating system inference", "eol_os"))
        if os_eol.get("error"):
            parts.append(_status("info",
                f"OS detection error: {os_eol['error']}"))

        for finding in os_findings:
            os_name = finding.get("os", "?")
            ver     = finding.get("version") or ""
            ver_display = "" if ver in ("", "?") else ver
            display     = finding.get("name") or _OS_DISPLAY_NAMES.get(os_name, os_name)
            stack_label = f"{display} {ver_display}".rstrip()
            underlying  = finding.get("underlying_os")
            tls_note    = finding.get("tls_capability_note")
            eol_status  = finding.get("eol_status")

            if finding.get("source") == "server_header_iis":
                head = f"IIS {ver} → {underlying or stack_label}"
            else:
                head = stack_label

            # Notes carried on the finding: how the release was inferred, and
            # whether paid extended support is still on sale.
            extra_notes = list(finding.get("notes") or [])
            if tls_note:
                extra_notes.append(tls_note)
            if eol_status == "eol":
                date     = finding.get("eol_last_release", "")
                date_str = f" — EOL {date}" if date else " — end of life"
                via_str  = ""
                if underlying and stack_label != underlying:
                    via_str = f" (detected via {stack_label})"
                parts.append(_status("fail", f"{head}{date_str}{via_str}",
                                     note_lines=extra_notes or None, check=("EOL OS: " + os_name + ("" if ver in ("", "?") else " " + ver))))
            elif eol_status == "unknown":
                cands = finding.get("candidates") or []
                if cands:
                    hint = f" — release not determined (could be {' or '.join(cands)})"
                else:
                    hint = " — version not exposed in Server header" if not ver else ""
                parts.append(_status("info", f"{head}{hint}",
                                     note_lines=extra_notes or None, check=("EOL OS: " + os_name + ("" if ver in ("", "?") else " " + ver))))
            else:
                parts.append(_status("info", head,
                                     note_lines=extra_notes or None))

        if tls_old_stack and tls_signals:
            parts.append(_status("warn",
                f"Legacy TLS still negotiated: {', '.join(tls_signals)}",
                note_lines=["Corroborates old-stack hypothesis"]))

    # ── EOL server-side runtime (PHP / ASP.NET) ──────────────────────────────
    # Cross-references the disclosed X-Powered-By / Server / X-AspNet-Version
    # version against tech_eol.json. Only rendered when there's something to
    # say (an EOL runtime detected). The plain disclosure lines above already
    # cover the "version is revealed" finding; this subsection adds the
    # "and that version is end-of-life" dimension.
    tech_eol = r.get("tech_eol") or {}
    parts.extend(_eol_tech_block(
        [t for t in (tech_eol.get("techs") or []) if t.get("source") not in ("smtp_banner", "version_bind")],
        "End-of-life server software", "Server software support"))

    # Technology stack
    stack = srv.get("stack", []) or []
    if stack:
        seen = set()
        unique = []
        for item in stack:
            key = item.split(" ")[0].lower()
            if key not in seen:
                seen.add(key)
                unique.append(item)
        if unique:
            parts.append("")
            parts.append("")
            parts.append(_subheading("Technology stack"))
            parts.append("")
            parts.append(_items(unique, nested=False))

    return "\n".join(parts)


# ── Detailed sections: Versioned libraries ──────────────────────────────────

def _render_versioned_libraries_section(data):
    vlibs = (data.results.get("versioned_libs") or {}).get("libraries") or []
    if not vlibs:
        return ""

    parts = ["", _heading("VERSIONED LIBRARIES (OWASP A06:2021 — vulnerable & outdated components)"), ""]
    parts.extend(_section_explanation_lines("eol_libraries"))
    parts.append(_para(
        f"{len(vlibs)} client-side librar"
        f"{'y' if len(vlibs)==1 else 'ies'} detected in static HTML."
    ))
    parts.append("")

    # Compute column widths from the data.
    name_w = max(len(_LIB_DISPLAY_NAMES.get(l.get("library", ""))
                     or l.get("name") or l.get("library", ""))
                 for l in vlibs)
    ver_w = max(len(str(l.get("version", "?"))) for l in vlibs)
    name_w = max(name_w, len("Library"))
    ver_w  = max(ver_w,  len("Version"))

    if _md():
        rows = []
        for lib in vlibs:
            name = (_LIB_DISPLAY_NAMES.get(lib.get("library", ""))
                    or lib.get("name") or lib.get("library", ""))
            ver = str(lib.get("version", "?"))
            if lib.get("eol_status") == "eol":
                rows.append((name, ver, "EOL", lib.get("eol_message") or "version is end-of-life"))
            elif lib.get("eol_status") == "unknown":
                rows.append((name, ver, "no data", "Library not in EOL database"))
            else:
                rows.append((name, ver, "in support", ""))
        parts.extend(_md_table(("Library", "Version", "Status", "Notes"), rows))
        return "\n".join(parts)

    parts.append(f"    {'Library'.ljust(name_w)}   {'Version'.ljust(ver_w)}   Status     Notes")
    parts.append(f"    {'─' * name_w}   {'─' * ver_w}   ──────     ─────")
    for lib in vlibs:
        name = (_LIB_DISPLAY_NAMES.get(lib.get("library", ""))
                or lib.get("name") or lib.get("library", ""))
        ver  = str(lib.get("version", "?"))
        if lib.get("eol_status") == "eol":
            msg = lib.get("eol_message") or "version is end-of-life"
            parts.append(f"    {name.ljust(name_w)}   {ver.ljust(ver_w)}   EOL        {msg}")
        elif lib.get("eol_status") == "unknown":
            parts.append(f"    {name.ljust(name_w)}   {ver.ljust(ver_w)}   no data    Library not in EOL database")
        else:
            parts.append(f"    {name.ljust(name_w)}   {ver.ljust(ver_w)}   in support")

    return "\n".join(parts)


# ── Detailed sections: Browser security headers ──────────────────────────────

def _render_browser_security_headers_section(data):
    r = data.results
    srv = r.get("server_header", {}) or {}

    if srv.get("error") or not srv:
        return ""

    parts = ["", _heading("BROWSER SECURITY HEADERS (W3C / OWASP secure-headers)"), ""]
    parts.extend(_section_explanation_lines("security_headers"))

    csp_q      = srv.get("csp_quality")
    csp_a      = r.get("csp_analysis", {}) or {}
    csp_header = srv.get("csp")

    if csp_q == "present":
        parts.append(_status("pass", "Content-Security-Policy set", check="CSP script-src safety"))
    elif csp_q == "permissive":
        parts.append(_status("warn",
            "Content-Security-Policy present but appears permissive (wildcard src detected)"))
    elif srv.get("csp_report_only"):
        parts.append(_status("fail",
            "Content-Security-Policy is only sent as Report-Only — violations are logged, nothing is blocked",
            check="CSP script-src safety"))
    else:
        parts.append(_status("warn", "Content-Security-Policy not set", check="CSP script-src safety"))

    if csp_a.get("present"):
        sso = csp_a.get("script_src_outcome")
        if sso == "strict":
            parts.append(_status("pass",
                "CSP script-src: strict (nonce/hash + 'strict-dynamic')", check="CSP script-src safety"))
        elif sso == "nonce_or_hash":
            parts.append(_status("pass",
                "CSP script-src: nonce/hash present", check="CSP script-src safety"))
        elif sso == "host_allowlist":
            parts.append(_status("warn",
                "CSP script-src: host-allowlist (weaker than nonce/hash)", check="CSP script-src safety"))
        elif sso == "unsafe_inline":
            parts.append(_status("fail",
                "CSP script-src: 'unsafe-inline' without nonce/hash — inline scripts run", check="CSP script-src safety"))
        elif sso == "wildcard_or_scheme":
            parts.append(_status("fail",
                "CSP script-src: wildcard or dangerous scheme — policy bypass possible", check="CSP script-src safety"))

        oso = csp_a.get("object_src_outcome")
        if oso == "none_or_self":
            parts.append(_status("pass",
                "CSP object-src restricted ('none' or 'self')", check="CSP object-src"))
        elif oso == "unrestricted":
            parts.append(_status("fail",
                "CSP object-src unrestricted — <object> and <embed> can load scripts from anywhere",
                check="CSP object-src"))
        else:
            parts.append(_status("warn",
                "CSP object-src not restricted — <object> and <embed> can load content (set object-src 'none')",
                check="CSP object-src"))

        buo = csp_a.get("base_uri_outcome")
        if buo == "set":
            parts.append(_status("pass",
                "CSP base-uri restricted (prevents <base> hijack)", check="CSP base-uri"))
        else:
            parts.append(_status("warn",
                "CSP base-uri missing — <base> tag injection can hijack relative URLs", check="CSP base-uri"))

        fao     = csp_a.get("frame_ancestors_outcome")
        xfo_now = srv.get("x_frame_options")
        if fao == "set":
            parts.append(_status("pass", "CSP frame-ancestors restricted", check="Clickjacking protection"))
        elif not xfo_now:
            parts.append(_status("warn",
                "CSP frame-ancestors missing — and no X-Frame-Options either", check="Clickjacking protection"))

        if csp_a.get("enforcement_outcome") == "report_only":
            parts.append(_status("warn",
                "CSP is in Report-Only mode — violations logged but not blocked", check="CSP script-src safety"))

        for sev_csp, msg in csp_a.get("findings", []) or []:
            low = msg.lower()
            if any(s in low for s in (
                "missing object-src", "missing base-uri",
                "report-only", "wildcard '*'", "dangerous schemes",
                "'unsafe-inline' without",
            )):
                continue
            sev_t = "fail" if sev_csp == "high" else "warn"
            parts.append(_status(sev_t, f"CSP: {msg}"))

    # X-Frame-Options
    xfo    = srv.get("x_frame_options")
    csp_fa = srv.get("csp_frame_ancestors", False)
    if csp_fa and xfo:
        xfo_first = xfo.split(",")[0].strip().upper()
        dupe = " — header sent multiple times" if "," in xfo else ""
        parts.append(_status("pass",
            f"X-Frame-Options: {xfo_first}{dupe}",
            note_lines=["frame-ancestors also set in CSP"], check="Clickjacking protection"))
    elif csp_fa:
        parts.append(_status("pass",
            "X-Frame-Options covered by CSP frame-ancestors", check="Clickjacking protection"))
    elif xfo:
        xfo_first = xfo.split(",")[0].strip().upper()
        if xfo_first in ("DENY", "SAMEORIGIN"):
            dupe = " — header sent multiple times" if "," in xfo else ""
            parts.append(_status("pass",
                f"X-Frame-Options: {xfo_first}{dupe}", check="Clickjacking protection"))
        else:
            parts.append(_status("warn",
                f"X-Frame-Options: {xfo} — unrecognised value", check="Clickjacking protection"))
    else:
        parts.append(_status("warn", "X-Frame-Options not set", check="Clickjacking protection"))

    # X-Content-Type-Options
    xcto = srv.get("x_content_type")
    if xcto and xcto.lower() == "nosniff":
        parts.append(_status("pass", "X-Content-Type-Options: nosniff", check="X-Content-Type-Options"))
    elif xcto:
        parts.append(_status("warn",
            f"X-Content-Type-Options: {xcto} — expected nosniff", check="X-Content-Type-Options"))
    else:
        parts.append(_status("warn", "X-Content-Type-Options not set", check="X-Content-Type-Options"))

    # Referrer-Policy
    rp = srv.get("referrer_policy")
    if rp:
        rp_first = rp.split(",")[0].strip().lower()
        dupe = " — header sent multiple times" if "," in rp else ""
        if rp_first in _STRONG_REFERRER_POLICIES:
            parts.append(_status("pass",
                f"Referrer-Policy: {rp_first}{dupe}", check="Referrer-Policy"))
        else:
            parts.append(_status("warn",
                f"Referrer-Policy: {rp_first}{dupe} — consider a stricter policy", check="Referrer-Policy"))
    else:
        parts.append(_status("warn", "Referrer-Policy not set", check="Referrer-Policy"))

    # Permissions-Policy
    pp = srv.get("permissions_policy")
    if pp:
        parts.append(_status("pass", "Permissions-Policy set", check="Permissions-Policy"))
    else:
        parts.append(_status("warn", "Permissions-Policy not set", check="Permissions-Policy"))

    # COOP
    coop     = (srv.get("coop") or "").strip()
    coop_low = coop.lower()
    if coop_low == "same-origin":
        parts.append(_status("pass", f"Cross-Origin-Opener-Policy: {coop}", check="Cross-Origin-Opener-Policy"))
    elif coop_low == "same-origin-allow-popups":
        parts.append(_status("warn",
            f"Cross-Origin-Opener-Policy: {coop} — partial isolation", check="Cross-Origin-Opener-Policy"))
    elif coop:
        parts.append(_status("warn",
            f"Cross-Origin-Opener-Policy: {coop} — weak value", check="Cross-Origin-Opener-Policy"))
    else:
        parts.append(_status("warn", "Cross-Origin-Opener-Policy not set", check="Cross-Origin-Opener-Policy"))

    # CORP
    corp     = (srv.get("corp") or "").strip()
    corp_low = corp.lower()
    if corp_low in ("same-origin", "same-site"):
        parts.append(_status("pass", f"Cross-Origin-Resource-Policy: {corp}", check="Cross-Origin-Resource-Policy"))
    elif corp_low == "cross-origin":
        parts.append(_status("warn",
            f"Cross-Origin-Resource-Policy: {corp} — explicit cross-origin", check="Cross-Origin-Resource-Policy"))
    elif corp:
        parts.append(_status("warn",
            f"Cross-Origin-Resource-Policy: {corp}", check="Cross-Origin-Resource-Policy"))
    else:
        parts.append(_status("warn", "Cross-Origin-Resource-Policy not set", check="Cross-Origin-Resource-Policy"))

    # COEP — informational
    coep = (srv.get("coep") or "").strip()
    if coep:
        parts.append(_status("info", f"Cross-Origin-Embedder-Policy: {coep}"))

    # X-XSS-Protection — deprecated. Wording fix (3.1.0): "correctly absent"
    # phrasing instead of "not enabled" which sounded like a problem.
    xxp = (srv.get("x_xss_protection") or "").strip()
    if xxp.startswith("0"):
        parts.append(_status("pass",
            "X-XSS-Protection: 0 — explicitly disabled (correct, header is deprecated)", check="X-XSS-Protection deprecated"))
    elif xxp:
        parts.append(_status("warn",
            f"X-XSS-Protection: {xxp} — header is deprecated; setting it can introduce XSS in older browsers. Recommended: remove or set to 0", check="X-XSS-Protection deprecated"))

    # 3.4: HPKP and Expect-CT — deprecated headers to remove.
    if "public_key_pins" in srv:
        if srv.get("public_key_pins"):
            parts.append(_status("warn",
                "Public-Key-Pins (HPKP) set — browsers dropped it, and lost pinned keys lock visitors out",
                sub_lines=[f"Public-Key-Pins: {srv['public_key_pins'][:120]}"],
                check="HPKP absent"))
        if srv.get("expect_ct"):
            parts.append(_status("info", f"Expect-CT: {srv['expect_ct'][:80]} — deprecated, has no effect; remove it",
                                 check="Expect-CT absent"))
        if not srv.get("public_key_pins") and not srv.get("expect_ct"):
            parts.append(_status("pass", "No deprecated HPKP or Expect-CT headers",
                                 check="HPKP absent"))

    # Raw CSP value(s)
    if csp_header:
        parts.append("")
        parts.append(_raw_value("Raw Content-Security-Policy:", csp_header))
    csp_ro = srv.get("csp_report_only")
    if csp_ro:
        parts.append("")
        parts.append(_raw_value("Raw Content-Security-Policy-Report-Only:", csp_ro))

    # Cookies
    cookies = srv.get("cookies") or []
    parts.append("")
    parts.append("")
    parts.append(_subheading("Cookies (on homepage response) (RFC 6265)"))
    parts.append("")
    if not cookies:
        parts.append(_para("No Set-Cookie headers on this response (cookies set after "
                           "login or by JavaScript are not visible here).", 4))
    else:
        for ck in cookies:
            name = ck.get("name", "")
            infra = ck.get("infra")
            issues = ck.get("issues", []) or []

            flags = []
            flags.append("✓ Secure"   if ck.get("secure")   else "✗ Secure")
            flags.append("✓ HttpOnly" if ck.get("httponly") else "✗ HttpOnly")
            ss = ck.get("samesite")
            if ss in ("Strict", "Lax"):
                flags.append(f"✓ SameSite={ss}")
            elif ss == "None" and not ck.get("secure"):
                flags.append("✗ SameSite=None (no Secure — browser rejects)")
            elif ss:
                flags.append(f"? SameSite={ss}")
            else:
                flags.append("✗ SameSite missing")

            if _md():
                parts.append(f"- `{name}` — {' · '.join(flags)}")
                if infra:
                    parts.append("    - CDN/WAF cookie")
                if issues:
                    parts.append(f"    - Issues: {_md_inline(', '.join(issues))}")
                continue
            parts.append(f"       {name}")
            parts.append(f"         {' · '.join(flags)}")
            if infra:
                parts.append(f"         (CDN/WAF cookie)")
            if issues:
                parts.append(f"         Issues: {', '.join(issues)}")
            parts.append("")

    return "\n".join(parts).rstrip()


# ── Detailed sections: security.txt ──────────────────────────────────────────

def _render_security_txt_section(data):
    sectxt = data.results.get("security_txt", {}) or {}
    if not sectxt:
        return ""

    parts = ["", _heading("SECURITY CONTACT (RFC 9116)"), ""]
    parts.extend(_section_explanation_lines("security_txt"))

    if sectxt.get("error"):
        parts.append(_status("info",
            f"Could not fetch security.txt: {sectxt['error']}", check="security.txt"))
    elif sectxt.get("present") and sectxt.get("contact"):
        found_at = sectxt.get("found_at", "")
        if found_at and "/security.txt" in found_at and "/.well-known/" not in found_at:
            parts.append(_status("info",
                f"Found at legacy path: {found_at} (RFC 9116 places it at /.well-known/security.txt)",
                check="security.txt location"))
        else:
            parts.append(_status("pass", f"Found at {found_at}", check="security.txt location"))
        for contact in sectxt.get("contact", []) or []:
            parts.append(_status("pass", f"Contact: {contact}", check="security.txt"))
        if sectxt.get("policy"):
            parts.append(_status("info", f"Policy: {sectxt['policy']}"))
        expires = sectxt.get("expires")
        expired = sectxt.get("expired")
        if expires and expired is False:
            parts.append(_status("pass", f"Expires: {expires}", check="security.txt"))
        elif expires and expired is True:
            parts.append(_status("fail",
                f"Expires: {expires} — security.txt has expired", check="security.txt"))
        elif expires is None:
            parts.append(_status("warn",
                "Expires field missing — required by RFC 9116", check="security.txt"))
        canon = sectxt.get("canonical") or []
        if canon:
            here = {found_at, sectxt.get("final_url") or found_at}
            if here & set(canon):
                parts.append(_status("pass", "Canonical: matches where the file was found",
                                     check="security.txt Canonical"))
            else:
                parts.append(_status("warn", "Canonical: does not list where the file was found",
                                     sub_lines=[f"Found at {found_at}"] + [f"Canonical: {c}" for c in canon],
                                     check="security.txt Canonical"))
    elif sectxt.get("present"):
        parts.append(_status("warn",
            "security.txt present but no Contact: field found", check="security.txt"))
    else:
        parts.append(_status("warn", "security.txt not found", check="security.txt"))

    return "\n".join(parts)


# ── Detailed sections: Default error page / CORS ────────────────────────────

def _render_error_page_section(data):
    epr = data.results.get("error_page", {}) or {}
    if not epr.get("outcome"):
        return ""

    parts = ["", _heading("DEFAULT ERROR PAGE"), ""]

    epo      = epr.get("outcome")
    detected = epr.get("detected")
    version  = epr.get("version")
    status   = epr.get("status")

    if epo == "custom_404":
        parts.append(_status("pass",
            f"Custom error page (status {status}) — no default-server fingerprint matched", check="Default error page"))
    elif epo == "default_no_version":
        parts.append(_status("warn",
            f"Default {detected} error page detected (status {status}) — no version disclosed",
            note_lines=_OneNote([
                "Operator has not customised the default 404. Strip or override",
                "to avoid disclosing server software in error responses.",
            ]), check="Default error page"))
    elif epo == "default_with_version":
        parts.append(_status("fail",
            f"Default {detected}/{version} error page (status {status})",
            note_lines=_OneNote([
                f"Default 404 reveals {detected} version {version}.",
                "Strip the default error page or replace it with a custom template.",
            ]), check="Default error page"))
    elif epo == "spa_or_2xx":
        parts.append(_status("info",
            f"Probe path returned {status} (SPA shell or wildcard route) — no 404 to inspect", check="Default error page"))
    elif epo == "error":
        parts.append(_status("info",
            f"Could not probe error page: {epr.get('error', '?')}", check="Default error page"))

    return "\n".join(parts)


def _render_cors_section(data):
    cors = data.results.get("cors", {}) or {}
    if not cors.get("outcome"):
        return ""

    parts = ["", _heading("CORS CONFIGURATION"), ""]

    co_outcome = cors.get("outcome")
    details = cors.get("details") or {}
    if co_outcome == "no_cors":
        parts.append(_status("pass",
            "No CORS headers — secure default (browsers refuse cross-origin reads)", check="CORS configuration"))
    elif co_outcome == "public_wildcard":
        parts.append(_status("pass",
            "ACAO=* without credentials — any site can read these responses, but only",
            sub_lines=["what an anonymous visitor could fetch anyway (no cookies are sent)"],
            check="CORS configuration"))
    elif co_outcome == "allow_listed":
        parts.append(_status("pass",
            f"CORS allows one fixed origin ({details.get('acao_same_origin_probe') or '?'}) and "
            "did not echo a foreign one", check="CORS configuration"))
    elif co_outcome == "weak_wildcard_with_credentials":
        parts.append(_status("fail",
            "ACAO=* combined with Allow-Credentials=true — spec-forbidden pairing",
            note_lines=_OneNote([
                "Browsers refuse this combination at runtime, but a server emitting",
                "it indicates the operator believes credentials flow cross-origin",
                "from any origin — a real misconfiguration.",
            ]), check="CORS configuration"))
    elif co_outcome == "weak_null_origin":
        parts.append(_status("fail",
            "ACAO=null — trusts sandboxed iframes and other null-origin contexts", check="CORS configuration"))
    elif co_outcome == "weak_reflective":
        parts.append(_status("fail",
            "Reflective ACAO — server echoes whatever Origin: the client sends",
            note_lines=_OneNote([
                "Verified by sending Origin: https://vendor-audit-cors-probe.example",
                "and observing the same value returned in Access-Control-Allow-Origin.",
                "Any origin is effectively trusted; equivalent to ACAO=*.",
            ]), check="CORS configuration"))
    elif co_outcome == "error":
        parts.append(_status("info",
            f"Could not probe CORS: {cors.get('error', '?')}", check="CORS configuration"))

    return "\n".join(parts)


# ── Detailed sections: SSL Labs ──────────────────────────────────────────────

def _render_ssl_labs_section(data):
    ssl_result = data.results.get("ssl_labs")
    if ssl_result is None:
        return ""

    parts = ["", _heading("SSL LABS (Qualys SSL Labs API · --ssl) (RFC 8446 + CA/Browser BR)"), ""]

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
            parts.append(_status("info",
                f"Assessed: {test_dt.strftime('%Y-%m-%d %H:%M UTC')} ({age_str})"))
        except Exception:
            pass

    worst = ssl_result.get("worst_grade")
    all_g = ssl_result.get("grades", []) or []
    if worst is None:
        parts.append(_status("info", "No grade returned from SSL Labs", check="SSL Labs grade"))
    else:
        unique_grades = list(dict.fromkeys(all_g))
        ep_str = (f" — endpoints: {', '.join(all_g)}"
                  if len(unique_grades) > 1 else "")
        if worst in ("A+", "A", "A-"):
            sev = "pass"
        elif worst in ("B", "C", "M"):
            sev = "warn"
        else:
            sev = "fail"

        # Wording fix (3.1.0): include the grade in the label so the
        # reader sees the verdict without scrolling to find a fraction.
        parts.append(_status(sev,
            f"Grade: {worst}{ep_str}",
            note_lines=[
                f"Re-run anytime: https://www.ssllabs.com/ssltest/analyze.html?d={data.audit_domain}",
            ], check="SSL Labs grade"))

        # Conditions reported by SSL Labs. We do not classify which ones
        # affect the grade and which don't — the grade itself is the verdict,
        # this list reports the observations.
        findings = ssl_result.get("findings") or []
        if findings:
            parts.append("")
            parts.append(_status("info",
                f"Conditions reported by SSL Labs ({len(findings)}):"))
            for f in findings:
                parts.append(_status("warn", f))

    return "\n".join(parts)


# ── Detailed sections: Page Analysis (--deep) ────────────────────────────────

def _render_page_analysis_section(data):
    r = data.results
    page = r.get("page_signals")
    if page is None or not page.get("parsed"):
        return ""

    redirect = r.get("redirect", {}) or {}
    parts = ["", _heading("PAGE ANALYSIS (--deep) (W3C SRI, W3C Mixed Content, WCAG 2.1)"), ""]
    parts.extend(_section_explanation_lines("page_analysis"))

    cap_used = redirect.get("body_cap_used") or 262144
    cap_str  = (f"{cap_used // (1024 * 1024)}MB" if cap_used >= 1048576
                else f"{cap_used // 1024}KB")
    looks_html = redirect.get("body_looks_like_html", True)
    if redirect.get("body_truncated"):
        deep_hint = (" Use --deep for a 5MB cap."
                     if cap_used < 5242880 else "")
        para = (f"Body truncated. Page body exceeded {cap_str} capture "
                f"limit — counts below are conservative.{deep_hint}")
        parts.append(_para(para))
        parts.append("")
    if not looks_html and (page.get("body_bytes") or 0) > 0:
        para = ("Response body does not look like HTML. Page-level counts "
                "below are unreliable. Common causes: bot-mitigation "
                "challenge page (Akamai / AWS WAF), non-HTML payload "
                "(JSON API, PDF), or a CDN that ignored Accept-Encoding.")
        parts.append(_para(para))
        parts.append("")

    a = page.get("a11y") or {}
    body_bytes  = page.get("body_bytes", 0)
    scripts     = page.get("scripts_total", 0)
    stylesheets = page.get("stylesheets_total", 0)
    img_total   = a.get("images_total", 0)
    inp_total   = a.get("inputs_total", 0)
    iframe_n    = page.get("iframe_count", 0)

    parts.append(_subheading("Parser inventory"))
    parts.append("")
    inventory = [
        ("HTML inspected",        _fmt_kb_or_mb(body_bytes)),
        ("<script>",              str(scripts)),
        ("<link rel=stylesheet>", str(stylesheets)),
        ("<img>",                 str(img_total)),
        ("<input>",               str(inp_total)),
        ("<iframe>",              str(iframe_n)),
    ]
    if _md():
        parts.extend(_md_table(("Item", "Count"), inventory))
    else:
        parts.append(_kv(inventory))
    parts.append("")

    if (looks_html and scripts > 0 and img_total == 0 and inp_total == 0
            and not redirect.get("body_truncated")):
        para = ("Most likely a bot-protection or captcha challenge page "
                "(Cloudflare / Akamai / AWS WAF) — could also be a real "
                "SPA shell rendered client-side. Either way the static "
                "HTML has no <img>/<input>.")
        parts.append(_para(para))
        parts.append("")

    sri_outcome = page.get("sri_outcome")
    protected   = page.get("sri_protected", 0)
    ext_total   = page.get("sri_external_total", 0)
    if sri_outcome == "no_external_scripts":
        parts.append(_status("pass", "No external scripts/stylesheets — SRI not needed", check="Subresource Integrity"))
    elif sri_outcome == "all_external_have_sri":
        parts.append(_status("pass",
            f"Subresource Integrity on all {ext_total} external resources", check="Subresource Integrity"))
    elif sri_outcome == "some_external_have_sri":
        parts.append(_status("warn",
            f"Subresource Integrity on {protected}/{ext_total} external resources", check="Subresource Integrity"))
    elif sri_outcome == "external_without_sri":
        # Wording fix (3.1.0): "any of 1" was awkward.
        if ext_total == 1:
            parts.append(_status("fail",
                "No Subresource Integrity on the only external resource — a CDN compromise could inject arbitrary code", check="Subresource Integrity"))
        else:
            parts.append(_status("fail",
                f"No Subresource Integrity on any of the {ext_total} external resources — a CDN compromise could inject arbitrary code", check="Subresource Integrity"))

    mc_outcome = page.get("mixed_outcome")
    mc_count   = page.get("mixed_active_count", 0)
    mc_list    = page.get("mixed_active", []) or []
    if mc_outcome == "active":
        parts.append(_status("fail",
            f"Mixed content (active): {mc_count} HTTP resource(s) on HTTPS page",
            sub_lines=mc_list if mc_list else None, check="Mixed content (in-page)"))
    elif mc_outcome == "passive_only":
        parts.append(_status("warn",
            "Mixed content (passive only) — images/media loaded over HTTP", check="Mixed content (in-page)"))
    elif mc_outcome == "none":
        parts.append(_status("pass", "No mixed content detected", check="Mixed content (in-page)"))

    third = page.get("third_party_origins", []) or []
    if third:
        parts.append(_status("info",
            f"Third-party origins: {len(third)}",
            sub_lines=third))
    else:
        parts.append(_status("pass", "No third-party origins detected on the homepage"))

    if iframe_n > 0:
        parts.append(_status("info", f"Iframes on page: {iframe_n}"))

    meta_csp = page.get("meta_csp")
    if meta_csp and not (r.get("server_header", {}) or {}).get("csp"):
        parts.append("")
        parts.append(_raw_value(
            "CSP delivered via <meta> tag (HTTP header preferred):",
            meta_csp,
        ))

    # Accessibility signals
    if a:
        parts.append("")
        parts.append("")
        parts.append(_subheading("Accessibility signals (indicative — not a WAVE/Axe substitute)"))
        parts.append("")
        if not a.get("html_lang_set"):
            parts.append(_status("warn",
                "<html> has no lang attribute — screen readers can't pick the language",
                check="Page language declared"))
        else:
            parts.append(_status("pass",
                f'<html lang="{a.get("html_lang") or "?"}">', check="Page language declared"))

        total  = a.get("images_total", 0)
        no_alt = a.get("images_missing_alt", 0)
        if total == 0:
            parts.append(_status("info",
                "No <img> tags found in static HTML"))
        elif no_alt == 0:
            parts.append(_status("pass",
                f"All {total} <img> tag(s) have an alt attribute"))
        else:
            parts.append(_status("warn",
                f"{no_alt}/{total} <img> tag(s) missing alt attribute (decorative images should still have alt=\"\")"))

        inp_total = a.get("inputs_total", 0)
        unl       = a.get("inputs_unlabeled", 0)
        if inp_total == 0:
            parts.append(_status("info",
                "No labelable form <input> tags found"))
        elif unl == 0:
            parts.append(_status("pass",
                f"All {inp_total} form input(s) have a label"))
        else:
            parts.append(_status("warn",
                f"{unl}/{inp_total} form input(s) without an associated label or aria-label"))

        empty_b = a.get("empty_buttons", 0)
        if empty_b > 0:
            parts.append(_status("warn",
                f"{empty_b} empty <button> element(s) (no text and no aria-label/title)"))
        else:
            parts.append(_status("pass",
                "No empty <button> elements"))

        empty_a = a.get("empty_links", 0)
        if empty_a > 0:
            parts.append(_status("warn",
                f"{empty_a} empty <a> element(s) (no text and no aria-label/title)"))
        else:
            parts.append(_status("pass",
                "No empty <a> elements"))

        parts.append("")
        para = ("A11y signals are not rated as findings — they are reported for "
                "awareness only. For a full audit use WebAIM WAVE, "
                "Axe DevTools, or pa11y.")
        parts.append(_para(para))

    return "\n".join(parts)


# ── Detailed sections: STARTTLS-MX probe (--deep) ───────────────────────────

# 3.5.8: what hstspreload.org requires, and why to check before submitting.
_HSTS_PRELOAD_STEPS = [
    "Before submitting at hstspreload.org: serve every subdomain over HTTPS, "
    "including internal and legacy names, because preloading applies to all of them",
    "Send max-age of at least 31536000 (one year) with includeSubDomains and preload, "
    "and redirect http:// to https:// on the same host first",
    "Leaving the list takes months to reach every browser, so be sure no subdomain needs plain HTTP",
]


def _hsts_preload_ready(hsts):
    """Whether the HSTS header itself is good enough that not being on the
    preload list is rated (Low): includeSubDomains and a max-age at least
    the scoring minimum. Mirrors audit_checks._merge_outcomes."""
    try:
        ma = int(hsts.get("max_age") or 0)
    except (TypeError, ValueError):
        ma = 0
    return bool(hsts.get("includes_subdomains")) and ma >= 15552000


def spf_lookup_lines(tree):
    """The SPF lookup tree (audit_checks._spf_stats) as aligned lines: each
    term, indented under the include: or redirect= it came from, with the
    lookups it costs (its own and every nested one) and any note.

        include:_spf.google.com              4
          include:_netblocks.google.com      1
          include:_netblocks2.google.com     1
          include:_netblocks3.google.com     1
        include:old.example.com              1  no SPF record at this name
    """
    rows = []

    def walk(nodes, depth):
        for n in nodes:
            rows.append(("  " * depth + str(n.get("term", "")), n.get("lookups", 0), n.get("note")))
            walk(n.get("children") or [], depth + 1)
    walk(tree or [], 0)
    if not rows:
        return []
    width = max(len(t) for t, _, _ in rows)
    return [f"{t.ljust(width)}  {c:>2}" + (f"  {note}" if note else "") for t, c, note in rows]


def _eol_tech_block(techs, eol_title, neutral_title, key="eol_tech"):
    """The end-of-life lines for some of tech_eol's software, under their
    own subheading; [] when none of it is end of life or undetermined.
    "End-of-life" heads it only when something is; an undetermined
    version alone (ASP.NET 2.0.50727) gets the neutral heading."""
    techs = [t for t in techs if t.get("eol_status") in ("eol", "undetermined")]
    if not techs:
        return []
    any_eol = any(t.get("eol_status") == "eol" for t in techs)
    parts = ["", ""]
    parts.extend(_subheading_with_explanation(eol_title if any_eol else neutral_title, key))
    for t in techs:
        disp = t.get("name") or _TECH_DISPLAY_NAMES.get(t.get("tech", ""), (t.get("tech") or "?").upper())
        ver  = t.get("version", "?")
        msg  = t.get("eol_message") or ""
        date = t.get("eol_last_release", "")
        detail = f" — EOL {date}" if date else " — end of life"
        src_label = {"error_page": "seen on the default error page",
                     "server_header": "disclosed in the Server header",
                     "x_powered_by": "disclosed in X-Powered-By",
                     "x_aspnet_version": "disclosed in X-AspNet-Version",
                     "x_aspnetmvc_version": "disclosed in X-AspNetMvc-Version",
                     "sharepoint_header": "from the MicrosoftSharePointTeamServices header",
                     "owa_header": f"build {t.get('detail')}, disclosed in the X-OWA-Version header",
                     "owa_page": f"build {t.get('detail')}, seen in the Outlook Web App sign-in page",
                     "jenkins_header": "disclosed in the X-Jenkins header",
                     "atlassian_page": "named in the page's ajs-version-number tag",
                     "smtp_banner": f"named in the mail server greeting from {t.get('detail')}",
                     "version_bind": f"given for version.bind by {t.get('detail')}",
                     "via_header": "disclosed in the Via header",
                     "kibana_header": "disclosed in the kbn-version header",
                     "grafana_page": "named in the Grafana sign-in page's startup data",
                     "roundcube_page": "named in the Roundcube page's rcversion setting",
                     }.get(t.get("source") or "")
        check = f"EOL tech: {t.get('tech', '?')} {t.get('version') or ''}".rstrip()
        notes = [src_label[0].upper() + src_label[1:]] if src_label else None
        if t.get("eol_status") == "undetermined":
            parts.append(_status("info", f"{disp} {ver} — support undetermined: {msg}",
                                 note_lines=notes, check=check))
            continue
        parts.append(_status("fail", f"{disp} {ver}{detail} — no longer receives security patches",
                             note_lines=notes, check=check))
    return parts


def _render_starttls_section(data):
    """The STARTTLS probe's hosts, then (3.5.4) any end-of-life mail
    server software their greetings named."""
    body = _render_starttls_hosts(data)
    if not body:
        return body
    tech_eol = data.results.get("tech_eol") or {}
    extra = _eol_tech_block(
        [t for t in (tech_eol.get("techs") or []) if t.get("source") == "smtp_banner"],
        "End-of-life mail server software", "Mail server software support", key="eol_mail")
    return "\n".join([body, *extra]) if extra else body


def _render_starttls_hosts(data):
    starttls = data.results.get("starttls_mx")
    if starttls is None or starttls.get("mx_count", 0) == 0:
        return ""

    parts = ["", _heading("MX STARTTLS PROBE (--deep) (RFC 3207)"), ""]
    para = ("Probing port 25 → EHLO → STARTTLS on each MX host. Many "
            "networks block port 25 egress; partial results are normal.")
    parts.append(_para(para))
    parts.append("")

    rows = starttls.get("results") or {}
    if not rows:
        parts.append(_para("No probe results.", 4))
        return "\n".join(parts)

    # Per-host vertical block — three lines per host (MX Host / TLS /
    # Detail), separated by a blank line. Aligns with the rest of the
    # report's key-value style and avoids the column-rule awkwardness
    # of a horizontal table when the Detail field is long.
    #
    # Annotate the negotiated TLS version with what it implies, so the
    # reader can see how the version corresponds to a finding in the
    # summary. Our context offers TLS 1.3 by default; if the server
    # came back with 1.2 it's because 1.3 wasn't offered server-side.
    def _tls_annotation(ver):
        if not ver:
            return ""
        v = ver.upper()
        if v in ("TLSV1.3",):
            return "  ← strong"
        if v in ("TLSV1.2",):
            return "  ← TLS 1.3 not offered"
        if v in ("TLSV1", "TLSV1.0", "TLSV1.1"):
            return "  ← legacy TLS, vulnerable"
        return ""

    if _md():
        table = []
        for host, info_d in rows.items():
            if info_d.get("error"):
                table.append((host, f"unprobed — {info_d['error']}", "", ""))
                continue
            ver_raw = info_d.get("tls_version") or "?"
            note = _tls_annotation(ver_raw).replace("←", "").strip()
            table.append((host, f"{ver_raw} ({note})" if note else ver_raw,
                          _expand_cert_issuer(info_d.get("cert_issuer")) or "",
                          info_d.get("cert_expires") or ""))
        parts.extend(_md_table(("MX host", "TLS", "Issuer", "Expires"), table))
        return "\n".join(parts)

    host_list = list(rows.items())
    for i, (host, info_d) in enumerate(host_list):
        if info_d.get("error"):
            tls_val    = "unprobed"
            detail_val = info_d["error"]
        else:
            ver_raw  = info_d.get("tls_version") or "?"
            tls_val  = f"{ver_raw}{_tls_annotation(ver_raw)}"
            issuer  = _expand_cert_issuer(info_d.get("cert_issuer")) or ""
            expires = info_d.get("cert_expires") or ""
            bits = []
            if issuer:
                bits.append(f"Issuer: {issuer}")
            if expires:
                bits.append(f"Expires: {expires}")
            detail_val = "  ·  ".join(bits) or "(no certificate detail captured)"

        parts.append(_kv([
            ("MX Host", host),
            ("TLS",     tls_val),
            ("Detail",  detail_val),
        ], indent=4, gap=2))
        if i < len(host_list) - 1:
            parts.append("")

    return "\n".join(parts)


# ── Scan footer ──────────────────────────────────────────────────────────────

def _render_scan_footer(data):
    """Scan version, options, elapsed wall time, slowest individual check
    (when significant). Mirrors the terminal's footer line."""
    scan = data.results.get("_scan") or {}
    if not scan:
        return ""

    opts = []
    if scan.get("deep"):
        opts.append("--deep")
    if data.results.get("ssl_labs"):
        opts.append("--ssl")
    opts_str = ", ".join(opts) if opts else "default"
    scan_ver = scan.get("version", "?")

    # The SCAN section intentionally omits speed/timing entries — the
    # report describes vendor posture, and wall-time metrics depend on the
    # auditor's network rather than anything about the audited domain. The
    # console still shows the elapsed time and an optional slowest-check
    # callout for interactive runs.
    pairs = [
        ("Version",      f"v{scan_ver}"),
        ("Options",      opts_str),
    ]

    parts = ["", _heading("SCAN"), ""]
    parts.append(_kv(pairs))
    return "\n".join(parts)


# ── Top-level renderer ───────────────────────────────────────────────────────

def ipv6_only_note(results):
    """(heading, lines) when the site is IPv6-only and the audit host has no
    IPv6, so the website checks could not connect; else None."""
    from .audit_checks import auditor_cannot_reach
    if not auditor_cannot_reach(results):
        return None
    return "IPv6-only site", [
        "this site has only IPv6 addresses, and the server running this",
        "audit has no IPv6 connectivity, so the TLS, HTTP and website checks",
        "could not connect. They are not rated. DNS, email and routing",
        "checks are not affected.",
    ]


def bot_challenge_note(server_header):
    """(heading, lines) for the notice shown when a bot defence answered the
    audit instead of the site, or None. Shared by the text report and the page."""
    sh = server_header or {}
    if not sh.get("bot_challenge"):
        return None
    status = f" (HTTP {sh['status_code']})" if sh.get("status_code") else ""
    if sh.get("bot_challenge_kind") == "block":
        head, first = "Blocked", f"Cloudflare answered this audit with its block page{status}."
    else:
        head, first = "Bot challenge", f"the site answered this audit with a challenge page{status}."
    return head, [
        first,
        "The Website and HSTS checks read that page, not the site, so failing",
        "ones are shown as Informational. Email, DNS, routing and certificate",
        "checks are not affected.",
    ]


def render_markdown(data):
    """The whole text report, as Markdown, from the prepared _ReportData."""
    token = _MARKDOWN.set(True)
    try:
        return _md_tidy(_render_markdown(data))
    finally:
        _MARKDOWN.reset(token)


def _render_markdown(data):
    redirected = (data.results.get("redirect") or {}).get("redirected")

    out = [_render_header(data), ""]

    # Partial-audit banner. Mirrors the web result page's banner so the
    # downloadable report is also clearly marked as incomplete when the
    # audit hit its wall-clock deadline.
    if data.results.get("_partial"):
        reason = data.results.get("_partial_reason") or \
            "Some checks did not complete."
        out += [f"**⚠ Partial audit:** {_md_inline(reason)}", ""]

    for note in (bot_challenge_note(data.results.get("server_header")),
                 ipv6_only_note(data.results)):
        if note:
            head, lines = note
            out += [f"**{head}:** {_md_inline(' '.join(lines))}", ""]

    if redirected and data.audit_domain != data.original_domain:
        out += [f"**Redirect:** {data.original_domain} redirects to {data.audit_domain}. "
                "Email is audited for both domains; web / TLS reflects the destination.", ""]

    out += [_render_score_panel(data), "",
            _render_executive_summary(data), "",
            render_detail_sections(data), "",
            _render_scan_footer(data), "",
            "---", "",
            f"Generated by vendor_audit {data.report_version} · {_SITE_LINKS}"]
    return "\n".join(out)


def render_detail_sections(data):
    """The detail sections, one after another.

    Shared by the terminal report, which reads the line-kind tags of the
    plain form, and the Markdown text report (render_markdown sets the
    mode). Each section returns "" when its source data is absent.
    """
    token = _CHECK_SEVERITIES.set({r["label"]: r["severity"] for r in data.finding_rows})
    try:
        return _render_detail_sections(data)
    finally:
        _CHECK_SEVERITIES.reset(token)


def _render_detail_sections(data):
    out = []
    for renderer in (
        _render_email_section,
        _render_dns_section,
        _render_routing_section,
        _render_tls_section,
        _render_http_section,
        _render_hsts_section,
        _render_server_disclosure_section,
        _render_versioned_libraries_section,
        _render_browser_security_headers_section,
        _render_security_txt_section,
        _render_error_page_section,
        _render_cors_section,
        _render_ssl_labs_section,
        _render_page_analysis_section,
        _render_starttls_section,
    ):
        block = renderer(data)
        if block:
            out.append(block)
    return "\n".join(out)


# ── Public entry point ───────────────────────────────────────────────────────

def write_md_report(original_domain, audit_domain, results, timestamp,
                    out_path, report_version=None):
    """Build the Markdown text report and write it to disk.

    Args:
        original_domain: Domain the user supplied on the CLI.
        audit_domain: Domain that was actually scanned (may differ if the
            site redirected, e.g. apex → www).
        results: The full results dict — same shape that audit_render.render
            consumes. Must include _scan metadata.
        timestamp: ISO-ish timestamp string.
        out_path: Destination filename.
        report_version: Optional override of the report module version
            string in the output footer; defaults to this module's
            __version__.

    File is written UTF-8 (no BOM), which Notepad on Windows 11 and every
    Markdown viewer read without being told.

    Raises:
        OSError: filesystem write failures bubble up unchanged.
    """
    text = markdown_report(original_domain, audit_domain, results, timestamp,
                           report_version)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def markdown_report(original_domain, audit_domain, results, timestamp,
                    report_version=None):
    """The Markdown text report as a string (the web app serves it)."""
    return render_markdown(_ReportData(
        original_domain=original_domain,
        audit_domain=audit_domain,
        results=results,
        timestamp=timestamp,
        report_version=report_version or __version__,
    ))
