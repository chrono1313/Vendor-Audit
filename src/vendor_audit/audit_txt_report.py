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
audit_txt_report.py — Plain-text technical report.

Produces a self-contained .txt file from a results dict (the same dict
audit_render.render() consumes). Designed for the technical owner of a
system: contains the evidence and raw values the terminal report shows,
organized by category, severity-prioritized at the top.

Output is 100 columns wide, UTF-8 encoded, using Unicode box-drawing
characters (═ ─ █ ░ ✓ ! ✗ ·). Long values (SPF records, etc)
are emitted on their own unindented continuation lines so the text editor
can wrap them naturally without breaking the report's structure.

Single public entry point:

    write_txt_report(original_domain, audit_domain, results, timestamp,
                     out_path, report_version)

Returns None on success; raises OSError on filesystem errors.

The four .py files (vendor_audit, audit_checks, audit_render, audit_txt_report)
and scoring_rubric.json share a single version number that is enforced
at startup. See vendor_audit.py for the full versioning policy.

Layout
======
1.  Header — domain, timestamp, version (heavy ═ rule).
2.  Score panel — overall score bar + per-category bars.
3.  Executive summary — severity-grouped findings (Failing / Partial /
    Passing) with category prefix and score fraction.
4.  Detailed sections — Email, DNS, Routing, TLS, HTTP, HSTS, Server &
    Technology, Versioned Libraries, Browser Security Headers,
    security.txt, SSL Labs, Page Analysis, STARTTLS-MX. Each section
    suppressed when its source data isn't present.
5.  Scan footer — version and options.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from collections import defaultdict


__version__ = "1.0"


# ── Layout constants ─────────────────────────────────────────────────────────

WIDTH = 100
RULE_HEAVY = "═" * WIDTH
RULE_LIGHT = "─" * WIDTH


# ── Severity classification ──────────────────────────────────────────────────

_SCORE_GREEN_PCT  = 80
_SCORE_YELLOW_PCT = 60

# Status markers — one symbol per severity. The plain-text report relies
# on these instead of color, which doesn't survive copy-paste or email.
_MARKERS = {
    "pass": "✓",
    "warn": "!",
    "fail": "✗",
    "info": "·",
}


# Address-family subheading labels with RFC citations. Used in the
# IP / ASN / RPKI section. The base RFC 6480 (RPKI) is on the parent
# section heading; these add the per-protocol IP standards.
_AF_LABEL_WITH_RFC = {
    "IPv4": "IPv4 (RFC 791)",
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
    # ── Tier 1: domain takeover / direct compromise ─────────────────────
    # EOL OS is handled separately (rank 5) by the prefix check in
    # _criticality_rank, since the label embeds the OS name.
    "SPF policy":                   10,   # +all = anyone can spoof
    "DMARC present":                12,   # no DMARC = no enforcement
    "DMARC policy":                 13,   # p=none = no enforcement
    "TLS connection":               15,   # TLS broken = users can't reach site safely
    "Certificate name match":       16,
    "DNSSEC AD flag":               18,   # validation chain broken

    # ── Tier 2: enables phishing / MITM / takeover ──────────────────────
    "DMARC pct":                    25,
    "DMARC sp":                     26,
    "DMARC rua reporting":          27,
    "SPF lookup count":             28,
    "SPF redirect":                 29,
    "HSTS present":                 30,
    "HSTS includeSubDomains":       32,
    "HSTS max-age strength":        33,
    "HSTS preloaded":               34,
    "MTA-STS":                      36,
    "TLS-RPT":                      37,
    "DANE TLSA on MX":              38,
    "STARTTLS-MX":                  39,
    "CAA records":                  42,   # any CA can issue for the domain
    "DNSSEC TLD signed":            43,
    "DNSSEC DNSKEY":                44,
    "Cert chain completeness":      45,
    "Cert covers www variant":      46,
    "Certificate lifetime":         47,
    "DKIM key strength":            48,

    # ── Tier 3: defence-in-depth / hardening ────────────────────────────
    "TLS 1.3":                      55,
    "HTTP→HTTPS redirect":          56,
    "CSP":                          58,
    "CSP script-src safety":        59,
    "CSP object-src":               60,
    "CSP base-uri":                 61,
    "CSP frame-ancestors":          62,
    "CSP enforcement mode":         63,
    "X-Frame-Options":              65,
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

    # ── Tier 4: best-practice / informational signals ───────────────────
    "Referrer-Policy":              85,
    "Permissions-Policy":           86,
    "Cross-Origin-Opener-Policy":   87,
    "Cross-Origin-Resource-Policy": 88,
    "X-XSS-Protection deprecated":  89,
    "Reporting endpoints":          90,
    "security.txt":                 92,

    # ── Tier 5: routing / availability — important but rarely a vendor's
    # most pressing issue when other things are also wrong ──────────────
    "IPv4 RPKI":                    95,
    "IPv6 RPKI":                    96,
    "IPv4 IRR/RIS":                 97,
    "IPv6 IRR/RIS":                 98,
    "IPv6":                        100,
    "Nameserver count":            102,
    "MX records":                  103,
    "HTTP version":                105,
    "Redirect first-hop hygiene":  106,
}

# Default rank for any label not in the table — sorts after everything named.
_CRITICALITY_DEFAULT_RANK = 500


def _criticality_rank(label):
    """Return the criticality rank for a finding label.

    EOL OS is given a top-tier rank (5) by prefix match, since its labels
    embed the OS name (e.g. "EOL OS: centos 7"). EOL libraries get a
    second-tier rank (50) — significant but rarely as urgent as an
    EOL operating system.
    """
    if not label:
        return _CRITICALITY_DEFAULT_RANK
    if label.startswith("EOL OS:"):
        return 5
    if label.startswith("EOL library:"):
        return 50
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
# Keep each line under ~140 characters so they wrap cleanly in the 100-col
# txt report and don't require a second wrap on a typical browser width.
EXPLANATIONS = {
    "spf": {
        "what": "SPF is a DNS record that lists which mail servers are allowed to send email using your domain.",
        "why":  "Without enforcement, anyone can spoof your domain in phishing emails — recipients can't tell a forgery from a real message.",
        "fix":  "Publish a v=spf1 record listing your senders and end with -all (hard fail) so receivers reject unauthorised mail.",
    },
    "dmarc": {
        "what": "DMARC tells receiving mail servers what to do when an email claiming to be from your domain fails SPF or DKIM checks.",
        "why":  "Without DMARC at p=reject, attackers can spoof your domain in phishing campaigns — DMARC is the only control that actually stops it.",
        "fix":  "Publish a DMARC record with p=reject, pct=100, and a rua= reporting address so you also get visibility into spoofing attempts.",
    },
    "dkim": {
        "what": "DKIM adds a cryptographic signature to outgoing mail so receivers can verify the message was authorised by your domain.",
        "why":  "DKIM is one of the two pillars (with SPF) that DMARC relies on — without it, legitimate forwarded mail tends to fail authentication.",
        "fix":  "Generate a DKIM key with your mail provider and publish the public key as a DNS TXT record at <selector>._domainkey.<domain>.",
    },
    "mta_sts": {
        "what": "MTA-STS publishes a policy telling sending mail servers they must use TLS when delivering mail to your domain.",
        "why":  "Without it, an attacker between mail servers can downgrade the connection to plaintext (STARTTLS stripping) and read or alter messages.",
        "fix":  "Publish a TXT record at _mta-sts.<domain> and host an MTA-STS policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode=enforce.",
    },
    "tls_rpt": {
        "what": "TLS-RPT (SMTP TLS Reporting) gives your domain visibility into mail-delivery TLS failures observed by receiving servers.",
        "why":  "Without TLS-RPT, you can't tell if MTA-STS is being honoured or if downgrade attacks are happening — you're operating blind.",
        "fix":  "Publish a TXT record at _smtp._tls.<domain> with v=TLSRPTv1; rua=mailto:<reporting-address>.",
    },
    "mail_transport": {
        "what": "Mail-transport hardening (MTA-STS, TLS-RPT, DKIM, DANE, STARTTLS) protects email in transit between mail servers.",
        "why":  "Without these, mail can be intercepted in plaintext, signatures can be stripped, and downgrade attacks are undetectable.",
        "fix":  "Publish MTA-STS in enforce mode, a TLS-RPT reporting endpoint, and a DKIM signing key; use a mail provider that supports DANE if possible.",
    },
    "dnssec": {
        "what": "DNSSEC cryptographically signs your DNS records so resolvers can verify they haven't been tampered with in transit.",
        "why":  "Without DNSSEC, an attacker on the network path can poison DNS responses and redirect users to attacker-controlled servers.",
        "fix":  "Enable DNSSEC at your registrar and DNS provider; both must support it and the chain must be published to the parent zone.",
    },
    "caa": {
        "what": "CAA records tell certificate authorities which CAs are allowed to issue certificates for your domain.",
        "why":  "Without CAA, any of hundreds of trusted public CAs can issue a certificate for your domain — a single compromised CA is enough.",
        "fix":  "Publish a CAA record listing your authorised CA(s), e.g. 0 issue \"letsencrypt.org\" and 0 issuewild \"letsencrypt.org\".",
    },
    "nameservers": {
        "what": "RFC 1034 requires every domain to have at least two authoritative nameservers for redundancy.",
        "why":  "A single nameserver is a single point of failure — if it goes down, your domain effectively disappears from the internet.",
        "fix":  "Configure at least two nameservers, ideally on different networks; most DNS providers do this automatically.",
    },
    "tls": {
        "what": "Modern TLS (1.3 preferred, 1.2 acceptable) protects all HTTPS traffic between visitors and your server.",
        "why":  "Older TLS versions and weak ciphers leave traffic vulnerable to interception and tampering by anyone on the network path.",
        "fix":  "Enable TLS 1.3 in your web server; disable TLS 1.0/1.1 and any cipher suites flagged by SSL Labs as weak.",
    },
    "hsts": {
        "what": "HTTP Strict Transport Security tells browsers to only ever connect to your site over HTTPS, even if the user types http://.",
        "why":  "Without HSTS, attackers can intercept the first plain-HTTP request and downgrade the user to an unencrypted session (SSL stripping).",
        "fix":  "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload and submit your domain to hstspreload.org.",
    },
    "http_redirect": {
        "what": "Plain HTTP requests should redirect to HTTPS so users are never served content over an unencrypted channel.",
        "why":  "Without redirect, content served over HTTP can be read or modified by anyone on the network — including injected malicious scripts.",
        "fix":  "Configure your web server to 301-redirect all http:// URLs to their https:// equivalents.",
    },
    "http": {
        "what": "This section covers HTTP transport: HTTP/2 and HTTP/3 support, plain-HTTP→HTTPS redirect, and first-hop redirect hygiene.",
        "why":  "Modern protocols are faster and more reliable; missing HTTPS redirects let attackers serve content unencrypted; off-host first hops leak Referer and bypass HSTS.",
        "fix":  "Enable HTTP/2 and HTTP/3 in your server or CDN, ensure http://<domain> 301-redirects directly to https://<domain> on the same host.",
    },
    "http_version": {
        "what": "HTTP/2 and HTTP/3 are modern transport protocols that are faster and more efficient than HTTP/1.1.",
        "why":  "HTTP/3 in particular improves performance on mobile networks and high-latency links; both fix head-of-line blocking from HTTP/1.1.",
        "fix":  "Enable HTTP/2 and HTTP/3 in your web server or CDN; most modern stacks support both with a single config flag.",
    },
    "server_disclosure": {
        "what": "The Server and X-Powered-By headers can reveal the exact software and version running on your server.",
        "why":  "Disclosure helps attackers match your server to known vulnerabilities and saves them time when targeting your stack specifically.",
        "fix":  "Configure your web server to suppress or genericise these headers (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
    },
    "csp": {
        "what": "Content Security Policy is a header telling the browser which sources of scripts, styles, and other resources are allowed to load.",
        "why":  "A strong CSP is the most effective defence against cross-site scripting (XSS) — without one, an injected script can do anything.",
        "fix":  "Start with Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none' and tighten further; avoid 'unsafe-inline'.",
    },
    "security_headers": {
        "what": "X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy harden the browser against common attack patterns.",
        "why":  "Each closes a specific class of vulnerability: clickjacking, MIME sniffing, referrer leakage, and unauthorised feature access.",
        "fix":  "Add all four headers in your web server config; sensible defaults are DENY, nosniff, strict-origin-when-cross-origin, and an empty Permissions-Policy.",
    },
    "cookies": {
        "what": "Cookies should be marked Secure, HttpOnly, and SameSite, and ideally use the __Host- or __Secure- prefix.",
        "why":  "Missing flags leak session cookies over HTTP, expose them to JavaScript-based theft, or allow cross-site request forgery (CSRF).",
        "fix":  "When setting cookies, always include Secure; HttpOnly; SameSite=Lax (or Strict) and use the __Host- prefix for session cookies.",
    },
    "security_txt": {
        "what": "A security.txt file at /.well-known/security.txt tells researchers how to report vulnerabilities they find on your site (RFC 9116).",
        "why":  "Without one, well-meaning researchers struggle to find a contact and may give up — the issue stays unreported and unfixed.",
        "fix":  "Publish a security.txt file with at least Contact: and Expires: fields; see securitytxt.org for a generator.",
    },
    "eol_os": {
        "what": "An end-of-life operating system no longer receives security patches from its vendor.",
        "why":  "Newly-discovered vulnerabilities — including remote code execution and privilege escalation — will never be fixed on this system.",
        "fix":  "Upgrade to a supported OS version. If business constraints require staying on this version, isolate it heavily and document the risk.",
    },
    "eol_libraries": {
        "what": "An end-of-life client-side library (jQuery, Bootstrap, Angular, etc.) no longer receives security or compatibility updates.",
        "why":  "Browser environments evolve constantly; an unmaintained library is increasingly likely to break or harbour known XSS vulnerabilities.",
        "fix":  "Upgrade to the current major version of the library, or migrate to a supported alternative.",
    },
    "rpki": {
        "what": "RPKI (Route Origin Authorization) lets you cryptographically declare which Autonomous Systems are allowed to announce your IP prefixes.",
        "why":  "Without ROAs, anyone can hijack your IP space via BGP — sending your traffic through their network and impersonating your services.",
        "fix":  "Ask your hosting provider or RIR (ARIN/RIPE/APNIC/etc) to create ROAs covering each prefix you announce.",
    },
    "routing": {
        "what": "This section covers IP-level reachability and routing security: IPv6 connectivity and RPKI Route Origin Authorizations for both IP families.",
        "why":  "IPv6-only users can't reach IPv4-only sites, and prefixes without ROAs are vulnerable to BGP hijacks that redirect traffic to attackers.",
        "fix":  "Add AAAA records to enable IPv6, and ask your hosting provider or RIR to publish ROAs for every prefix your AS announces.",
    },
    "ipv6": {
        "what": "IPv6 connectivity makes your site reachable for the growing share of users on IPv6-only networks (mobile, enterprise, some ISPs).",
        "why":  "IPv4 address exhaustion means more networks are deploying IPv6-only access; IPv4-only domains are simply unreachable for those users.",
        "fix":  "Add AAAA records pointing to IPv6 addresses on your hosting; most CDNs and cloud providers offer this with a single config flag.",
    },
    "page_analysis": {
        "what": "A passive read of the homepage HTML for Subresource Integrity, mixed content, third-party origins, and basic accessibility signals.",
        "why":  "Missing SRI on third-party scripts means a CDN compromise injects code into your site; mixed content allows tampering with HTTPS pages.",
        "fix":  "Add integrity= attributes to all <script> and <link> tags loading from third-party origins; never include http:// resources in HTTPS pages.",
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
    out = []
    body_w = WIDTH - len(indent) - 6  # leave room for the "What:" label
    for label, text in (("What", entry["what"]),
                        ("Why",  entry["why"]),
                        ("Fix",  entry["fix"])):
        wrapped = _wrap_at_words(text, body_w)
        # First line gets the label; continuations align under the body text.
        if not wrapped:
            continue
        out.append(f"{indent}{label}: {wrapped[0]}")
        cont_indent = indent + " " * (len(label) + 2)
        for cont in wrapped[1:]:
            out.append(f"{cont_indent}{cont}")
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

def _severity_for_score(earned, possible):
    """Map (earned, possible) → 'pass' / 'warn' / 'fail' / 'info'."""
    if possible == 0:
        return "info"
    if earned == possible:
        return "pass"
    if earned == 0:
        return "fail"
    return "warn"


def _strip_ansi(s):
    """Strip ANSI escape codes from a string. Belt-and-braces — the report
    builder consumes structured data, not the rendered terminal output."""
    if not s:
        return s
    return re.sub(r"\x1b\[[0-9;]*m", "", str(s))


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


def _bar(pct, width=20):
    """Render a horizontal bar of width chars, filled to pct percent.
    Uses U+2588 (full block) for filled and U+2591 (light shade) for
    empty — both render correctly in Notepad on Windows 11 with the
    default Consolas font."""
    pct = max(0, min(100, int(pct)))
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


# Builders for the line shapes used throughout the report. Each returns a
# string (no trailing newline) so the caller can join with "\n" and decide
# its own paragraph spacing.

def _heading(title):
    """Section heading — light rule above and below the title line."""
    return f"{RULE_LIGHT}\n  {title}\n{RULE_LIGHT}"


def _subheading(title):
    """Subsection heading — just the title, indented two spaces.
    Surrounding paragraphs are responsible for blank lines."""
    return f"  {title}"


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


def _status(severity, body, sub_lines=None, note_lines=None):
    """Status line: '    ✓  Body text', plus optional indented sub-lines
    (typically raw values like a record string) and note lines (typically
    explanation continuations).

    The body is word-wrapped at 80 cols, with continuations indented to
    align under the body text (col 7). sub_lines and note_lines are
    iterables of strings; each is indented further under the body."""
    marker = _MARKERS.get(severity, "·")
    LEAD = "    "                                # 4 spaces before marker
    BODY_INDENT = " " * 7                        # alignment for continuations
    BODY_W = WIDTH - 7                           # col budget for body text

    body_lines = _wrap_at_words(body, BODY_W)
    out = [f"{LEAD}{marker}  {body_lines[0]}"]
    for cont in body_lines[1:]:
        out.append(f"{BODY_INDENT}{cont}")

    if note_lines:
        for ln in note_lines:
            for wrapped in _wrap_at_words(ln, BODY_W):
                out.append(f"{BODY_INDENT}{wrapped}")
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
    max_key = max(len(k) for k, _ in pairs)
    out = []
    for k, v in pairs:
        out.append(f"{' ' * indent}{k.ljust(max_key + gap)}{v}")
    return "\n".join(out)


def _raw_value(label, value, indent=4):
    """Long verbatim record (SPF, DMARC, CSP, etc). Emitted as a label
    line followed by the value on its own line, unindented past the
    leading margin so Notepad's word-wrap does the right thing."""
    pad = " " * indent
    if label:
        return f"{pad}{label}\n{pad}{value}"
    return f"{pad}{value}"


# ── Data model (small, internal) ──────────────────────────────────────────────

class _ReportData:
    """Aggregate everything the renderer needs in one place. Computed once
    from the results dict + score breakdown so the rendering can be a
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
        from .audit_checks import score_results, RUBRIC

        earned, possible, breakdown = score_results(results)
        self.earned        = earned
        self.possible      = possible
        self.breakdown     = breakdown
        self.rubric        = RUBRIC
        self.pct           = round((earned / possible * 100)) if possible else 0
        self.score_severity = (
            "pass" if self.pct >= _SCORE_GREEN_PCT
            else "warn" if self.pct >= _SCORE_YELLOW_PCT
            else "fail"
        )

        self._build_category_subscores()
        self._build_finding_rows()

    def _category_for(self, score_label):
        """Mirror audit_render._category_for_score_label."""
        if not score_label:
            return "Website"
        cat_map = self.rubric.get("categories", {}) or {}
        for cat, labels in cat_map.items():
            if score_label in labels:
                return cat
        return "Website"

    def _build_category_subscores(self):
        """Group breakdown rows by category, sum earned/possible per cat."""
        by_cat_pts = defaultdict(list)
        for label, e, p in self.breakdown:
            by_cat_pts[self._category_for(label)].append((e, p))

        order = ["Email", "DNS", "Routing", "TLS", "HTTP", "Website"]
        rows = []
        for cat in order:
            pts = by_cat_pts.get(cat, [])
            if not pts:
                continue
            ce = sum(e for e, _ in pts)
            cp = sum(p for _, p in pts)
            if cp == 0:
                continue
            cpct = round(ce / cp * 100)
            sev = (
                "pass" if cpct >= _SCORE_GREEN_PCT
                else "warn" if cpct >= _SCORE_YELLOW_PCT
                else "fail"
            )
            rows.append({
                "category": cat,
                "earned":   ce,
                "possible": cp,
                "pct":      cpct,
                "severity": sev,
            })
        self.category_rows = rows

    def _build_finding_rows(self):
        """Convert breakdown into a list of finding dicts grouped by
        severity. Order shown in report is fail → warn → info → pass."""
        score_label_display = self.rubric.get("score_label_display", {}) or {}
        partial_label       = self.rubric.get("partial_label", {}) or {}

        eol_os_lookup  = self._build_eol_os_lookup()
        eol_lib_lookup = self._build_eol_lib_lookup()

        # SSL Labs grade gets a dynamic label — the actual letter grade is
        # informative on every severity, not just on a fail. The rubric's
        # static labels for this row are too bare ("SSL Labs grade") to be
        # useful in the executive summary.
        ssl_grade = None
        ssl_result = self.results.get("ssl_labs") or {}
        if ssl_result:
            ssl_grade = ssl_result.get("worst_grade")

        rows = []
        for label, e, p in self.breakdown:
            sev = _severity_for_score(e, p)
            cat = self._category_for(label)

            if label in eol_os_lookup:
                display = eol_os_lookup[label]
            elif label in eol_lib_lookup:
                display = eol_lib_lookup[label]
            elif label == "SSL Labs grade" and ssl_grade:
                display = f"SSL Labs grade: {ssl_grade}"
            elif sev == "pass":
                display = score_label_display.get(label, label)
            elif sev == "warn":
                display = (
                    self._resolve_partial_label(partial_label.get(label), label)
                    or f"{score_label_display.get(label, label)} — partial"
                )
            elif sev == "fail":
                base = score_label_display.get(label, label)
                display = self._failure_phrasing(label, base)
            else:  # info / 0/0
                display = self._info_phrasing(
                    label, self._resolve_partial_label(partial_label.get(label), label))

            rows.append({
                "label":     label,
                "display":   display,
                "category":  cat,
                "earned":    e,
                "possible":  p,
                "severity":  sev,
            })
        self.finding_rows = rows

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
            display    = _OS_DISPLAY_NAMES.get(os_key, os_key)
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
            display_name = _LIB_DISPLAY_NAMES.get(name, name)
            out[key] = f"End-of-life library: {display_name} {ver} ({msg})"
        return out

    def _failure_phrasing(self, label, base_display):
        """Synthesised phrasing for a fail row when the rubric's labels.fail
        map doesn't have a more specific entry."""
        per_label = {
            "DMARC present":           "DMARC record not published",
            "DMARC policy":            "DMARC policy not enforced",
            "DMARC pct":               "DMARC pct= not at 100%",
            "DMARC sp":                "DMARC sp= not aligned with main policy",
            "DMARC rua reporting":     "DMARC rua= aggregate reporting not configured",
            "MX records":              "No MX records published",
            # MTA-STS — clarified that the SENDER falls back, not the receiver.
            "MTA-STS":                 "MTA-STS policy not published — sending servers have no policy preventing fallback to plaintext",
            "TLS-RPT":                 "TLS-RPT reporting endpoint not published",
            # DANE — fixed: the old wording read like a clean assessment.
            "DANE TLSA on MX":         "No DANE/TLSA records on any MX host — vulnerable to STARTTLS downgrade attacks",
            "STARTTLS-MX":             "STARTTLS not negotiated successfully on at least one MX host",
            "CAA records":             "No Certification Authority Authorization (CAA) records",
            "DNSSEC TLD signed":       "TLD is not DNSSEC signed",
            "DNSSEC DNSKEY":           "DNSKEY missing on this zone",
            "DNSSEC AD flag":          "DNSSEC validation chain not authenticated (AD flag unset)",
            "Nameserver count":        "Fewer than two authoritative nameservers (RFC 1034)",
            "IPv6":                    "IPv6 not configured",
            "IPv4 RPKI":               "IPv4 prefix has no Route Origin Authorization (RPKI)",
            "IPv6 RPKI":               "IPv6 prefix has no Route Origin Authorization (RPKI)",
            "IPv4 IRR/RIS":            "IPv4 route not registered in IRR / RIS",
            "IPv6 IRR/RIS":            "IPv6 route not registered in IRR / RIS",
            "TLS connection":          "TLS connection failed",
            "TLS 1.3":                 "TLS 1.3 not supported",
            "Certificate name match":  "TLS certificate does not match domain",
            "Certificate lifetime":    "TLS certificate lifetime exceeds 199 days — may indicate manual renewal",
            "HSTS present":            "HTTP Strict Transport Security (HSTS) not set",
            "HSTS includeSubDomains":  "HSTS missing includeSubDomains directive",
            "HSTS preloaded":          "HSTS not on the preload list",
            "HSTS max-age strength":   "HSTS max-age below 180 days",
            "HTTP version":            {
                "http1":     "HTTP/1.1 only \u2014 server does not support HTTP/2 or HTTP/3 (http1mustdie.com)",
                "http2":     "HTTP/3 not supported (HTTP/2 only)",
                "_default":  "HTTP/3 not supported"
            },
            "HTTP\u2192HTTPS redirect": "Plain HTTP does not redirect to HTTPS",
            "Server header":           "Server header discloses software / version",
            "X-Powered-By absent":     "X-Powered-By header reveals technology",
            "CSP":                     "Content Security Policy not set",
            "CSP script-src safety":   "CSP script-src is missing, wildcard, or allows inline scripts",
            "CSP object-src":          "CSP object-src not restricted — plugin XSS possible",
            "CSP base-uri":            "CSP base-uri not restricted — <base> tag injection possible",
            "CSP frame-ancestors":     "CSP frame-ancestors not restricted — clickjacking possible",
            "CSP enforcement mode":    "CSP in Report-Only mode — violations logged but not blocked",
            "X-Frame-Options":         "X-Frame-Options not set",
            "X-Content-Type-Options":  "X-Content-Type-Options not set",
            "Referrer-Policy":         "Referrer-Policy not set",
            "Permissions-Policy":      "Permissions-Policy not set",
            "Cross-Origin-Opener-Policy":   "Cross-Origin-Opener-Policy not set",
            "Cross-Origin-Resource-Policy": "Cross-Origin-Resource-Policy not set",
            "X-XSS-Protection deprecated":  "X-XSS-Protection set to a dangerous value",
            "security.txt":            "security.txt not published (RFC 9116)",
            "Subresource Integrity":   "External scripts have no Subresource Integrity (SRI)",
            "Mixed content (in-page)": "Mixed content detected on HTTPS page",
            "Cookie name prefixes":    "Cookies use __Host-/__Secure- prefix incorrectly",
            "Redirect first-hop hygiene":  "First redirect hop is off-host or HTTP",
            "Cert covers www variant": "TLS certificate doesn't cover www / apex variant",
            "Server clock accuracy":   "Server clock is significantly skewed from UTC",
            "SSL Labs grade":          "SSL Labs grade indicates serious TLS issues",
            "Cert chain completeness": "Server sends incomplete certificate chain — clients fall back to AIA fetching",
            "DKIM key strength":       "DKIM key uses RSA <1024 (broken)",
            "Default error page":      {
                "_default":             "Default error page detected",
                "default_with_version": "Default error page detected with version disclosure",
                "default_no_version":   "Default error page detected (server software disclosed, no version)"
            },
            "CORS configuration":      {
                "_default":                       "CORS configuration is unsafe",
                "weak_wildcard_with_credentials": "CORS — wildcard ACAO combined with Allow-Credentials=true",
                "weak_null_origin":               "CORS — Allow-Origin set to 'null' (sandboxed origins trusted)",
                "weak_reflective":                "CORS — server reflects arbitrary Origin: header (any origin trusted)"
            },
        }
        if label in per_label:
            entry = per_label[label]
            # Most entries are plain strings. A few (HTTP version) are
            # dicts keyed by outcome — same shape as the rubric's
            # partial_label entries — to differentiate fail-cases like
            # "HTTP/1.1 only" from partial-cases like "HTTP/2 only".
            if isinstance(entry, dict):
                resolved = self._resolve_partial_label(entry, label)
                if resolved:
                    return resolved
                return entry.get("_default") or f"{label} — failed"
            return entry
        if base_display and base_display != label:
            return f"{base_display} — failed"
        return f"{label} — failed"

    def _info_phrasing(self, label, partial_label):
        """Phrasing for 0/0 rows (checks that didn't apply)."""
        if partial_label:
            return partial_label
        per_label = {
            "DKIM (common selectors)": "DKIM key not found at common selectors (operator may use a custom selector)",
            "STARTTLS-MX":             "STARTTLS-MX could not be probed (port 25 likely blocked egress)",
        }
        if label in per_label:
            return per_label[label]
        return f"{label} — not evaluated"

    def _resolve_partial_label(self, entry, label):
        """Pick the right partial_label text for a check.

        partial_label entries can be one of:
          - str:  one partial state, use the string as-is
          - dict: multiple partial outcomes (e.g. CSP script-src safety has
                  both nonce_or_hash and host_allowlist as partial outcomes
                  with different scores). Uses the per-check outcome from
                  results to pick the right text. _default is the fallback.

        Returns None if entry is None or doesn't resolve — caller should
        provide a fallback.
        """
        if entry is None:
            return None
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            # CSP script-src safety: outcome stored at csp_analysis.script_src_outcome
            if label == "CSP script-src safety":
                csp_a = self.results.get("csp_analysis") or {}
                outcome = csp_a.get("script_src_outcome")
                if outcome and outcome in entry:
                    return entry[outcome]
            # HTTP version: outcome derived from http_version and server_header.
            # Mirrors the scoring logic in audit_checks.score_results.
            if label == "HTTP version":
                hv      = self.results.get("http_version") or {}
                srv_h   = self.results.get("server_header") or {}
                hv_ver  = hv.get("version")
                http3   = srv_h.get("http3_advertised")
                if http3:
                    outcome = "http3"
                elif hv_ver == "HTTP/2":
                    outcome = "http2"
                elif hv_ver:
                    outcome = "http1"
                else:
                    outcome = None
                if outcome and outcome in entry:
                    return entry[outcome]
            # Default error page: outcome stored on the error_page check itself.
            if label == "Default error page":
                ep = self.results.get("error_page") or {}
                outcome = ep.get("outcome")
                if outcome and outcome in entry:
                    return entry[outcome]
            # DKIM key strength: worst observed strength across found selectors.
            if label == "DKIM key strength":
                dkim = self.results.get("dkim") or {}
                outcome = dkim.get("worst_strength")
                if outcome and outcome in entry:
                    return entry[outcome]
            # CORS configuration: outcome stored on cors result itself.
            # Used by _failure_phrasing's dict-form lookup; the actual partial
            # case (no_cors → 0/0) is rendered via _info_phrasing instead.
            if label == "CORS configuration":
                cors = self.results.get("cors") or {}
                outcome = cors.get("outcome")
                if outcome and outcome in entry:
                    return entry[outcome]
            # Future multi-tier checks would add their lookups here.
            return entry.get("_default")
        return None


# ── Top-level visual blocks ──────────────────────────────────────────────────

def _render_header(data):
    """Title block with heavy ═ rule."""
    try:
        ts_dt = datetime.fromisoformat(data.timestamp.replace("Z", "+00:00"))
        ts_human = ts_dt.strftime("%B %d, %Y at %H:%M:%S %Z").strip()
    except (ValueError, AttributeError):
        ts_human = data.timestamp

    meta = f"{ts_human}   ·   v{data.report_version}"
    return "\n".join([
        RULE_HEAVY,
        "  Vendor Audit",
        f"  {data.original_domain}",
        f"  {meta}",
        "  https://vendoraudit.org",
        "  https://github.com/chrono1313/Vendor-Audit",
        RULE_HEAVY,
    ])


def _render_score_panel(data):
    """Overall score bar + per-category bars.

    Format:
      OVERALL SCORE      62 / 74      █████████████████░░░    84%

        Email           13 / 18       ██████████████░░░░░░    72%
        DNS              8 /  9       █████████████████░░░    89%
        ...

    Fractions are right-aligned within their column width so eye-scan
    works cleanly regardless of single- vs double-digit values."""
    earned_disp   = _fmt_int_or_float(data.earned)
    possible_disp = _fmt_int_or_float(data.possible)

    # Build the list of rows (overall first, then categories) so we can
    # compute consistent column widths across all of them.
    cat_rows = data.category_rows or []
    all_earned = [data.earned] + [r["earned"]   for r in cat_rows]
    all_poss   = [data.possible] + [r["possible"] for r in cat_rows]

    earned_w = max(len(str(_fmt_int_or_float(e))) for e in all_earned)
    poss_w   = max(len(str(_fmt_int_or_float(p))) for p in all_poss)

    def fmt_row(name_col, earned, possible, pct, name_width=14):
        e_disp = _fmt_int_or_float(earned)
        p_disp = _fmt_int_or_float(possible)
        frac = f"{str(e_disp).rjust(earned_w)} / {str(p_disp).rjust(poss_w)}"
        bar = _bar(pct, width=30)
        return f"{name_col.ljust(name_width)}  {frac}      {bar}    {pct:>3}%"

    out = []
    out.append(fmt_row("OVERALL SCORE", data.earned, data.possible, data.pct,
                       name_width=14))
    if cat_rows:
        out.append("")
        for r in cat_rows:
            out.append("  " + fmt_row(r["category"], r["earned"], r["possible"],
                                       r["pct"], name_width=12))
    return "\n".join(out)


def _render_findings_group(title, rows):
    """One severity-grouped block in the Executive Summary.

    Each finding line:
      ✗  Website   Content Security Policy not set                   0 / 2

    Layout:
      4 sp + marker + 2 sp + cat (8 wide) + 1 sp + label … rjust(frac, 7)

    Column widths chosen to total 80. Frac column is anchored to the
    right edge with at least 1 space of padding before it; long labels
    truncate to fit only as a last resort (we let them ride into the
    frac column instead, since truncating loses information)."""
    if not rows:
        return ""

    out = [f"  {title} ({len(rows)})", ""]

    # Width budget — pin labels to WIDTH-2 (2-col right margin) so the
    # frac column right-aligns at the same edge as the rule lines.
    #   2  outer indent (none — start at col 4 below)
    #   4  '    '         pre-marker indent
    #   1  marker
    #   2  '  '           after marker
    #   8  category col (left-justified, padded)
    #   1  space
    #   N  label
    #   2  '  '           label-to-frac gutter (min)
    #   ?  frac col (e.g. "0 / 2", "10 / 10", "1.5 / 2")
    LINE = WIDTH - 2
    LEAD = 4 + 1 + 2  # before category

    # Compute frac strings up-front so we can size the column.
    fracs = []
    for r in rows:
        e_disp = _fmt_int_or_float(r["earned"])
        p_disp = _fmt_int_or_float(r["possible"])
        fracs.append(f"{e_disp} / {p_disp}")
    frac_w = max(len(f) for f in fracs)

    # Categories are padded to a uniform 8 chars (Email, DNS, Routing,
    # TLS, HTTP, Website all fit).
    CAT_W = 8

    for r, frac in zip(rows, fracs):
        marker = _MARKERS.get(r["severity"], "·")
        cat    = r["category"].ljust(CAT_W)
        label  = r["display"]

        # Compute available label width.
        label_w = LINE - LEAD - CAT_W - 1 - 2 - frac_w
        if len(label) <= label_w:
            line = (f"    {marker}  {cat} {label}"
                    f"{' ' * (label_w - len(label))}  {frac.rjust(frac_w)}")
        else:
            # Label longer than fits — wrap on word boundaries onto
            # continuation line(s). The frac column stays on line 1.
            words = label.split()
            line1_words = []
            buf_len = 0
            i = 0
            for w in words:
                add = len(w) + (1 if line1_words else 0)
                if buf_len + add > label_w:
                    break
                line1_words.append(w)
                buf_len += add
                i += 1
            # Edge case: a single word is longer than label_w. Hard-cut
            # only as a fallback so the line still terminates somewhere.
            if not line1_words:
                line1_words = [words[0][:label_w]]
                rest_first = words[0][label_w:]
                rest_words = ([rest_first] if rest_first else []) + words[1:]
            else:
                rest_words = words[i:]

            line1_label = " ".join(line1_words)
            line = (f"    {marker}  {cat} {line1_label}"
                    f"{' ' * (label_w - len(line1_label))}  {frac.rjust(frac_w)}")
            cont_indent = " " * (LEAD + CAT_W + 1)

            # Soft-wrap continuation by words.
            buf = ""
            cont_lines = []
            for w in rest_words:
                if buf and len(buf) + 1 + len(w) > label_w:
                    cont_lines.append(buf)
                    buf = w
                else:
                    buf = (buf + " " + w) if buf else w
            if buf:
                cont_lines.append(buf)
            for cl in cont_lines:
                line += "\n" + cont_indent + cl
        out.append(line)

    return "\n".join(out)


def _render_executive_summary(data):
    """Executive summary: heading + severity-grouped finding lists.

    Fails and warns are folded into a single "POSSIBLE ISSUES" block,
    sorted by criticality (most consequential issues first, regardless
    of category — see _CRITICALITY_RANK_TABLE). The marker symbol
    (✗ vs !) still distinguishes severity within the list. "Not
    evaluated" and "Passing" stay as their own separate blocks.
    """
    fails  = [r for r in data.finding_rows if r["severity"] == "fail"]
    warns  = [r for r in data.finding_rows if r["severity"] == "warn"]
    infos  = [r for r in data.finding_rows if r["severity"] == "info"]
    passes = [r for r in data.finding_rows if r["severity"] == "pass"]

    # Combined Possible Issues: fails + warns sorted by criticality (a flat
    # priority list, not grouped by category — most consequential issue
    # first, whether it's email, TLS, or website). Within the same
    # criticality rank, fails come before warns so the sharper signal leads.
    sev_order = {"fail": 0, "warn": 1}
    issues = sorted(
        fails + warns,
        key=lambda r: (_criticality_rank(r["label"]),
                       sev_order.get(r["severity"], 99)),
    )

    out = [_heading("EXECUTIVE SUMMARY"), ""]
    blocks = []
    if issues:
        blocks.append(_render_findings_group("POSSIBLE ISSUES", issues))
    if infos:
        blocks.append(_render_findings_group("NOT EVALUATED", infos))
    if passes:
        blocks.append(_render_findings_group("PASSING", passes))
    out.append("\n\n".join(b for b in blocks if b))
    return "\n".join(out)


# ── Detailed sections: Email ─────────────────────────────────────────────────

def _render_email_block(domain_label, spf, dmarc, mx, results, prefix=""):
    """SPF + DMARC + MX + mail-transport hardening for one domain."""
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
                f"DNS query failed: {spf.get('error')}"))
        elif s == "null_sender":
            out.append(_status("pass",
                "Null sender (v=spf1 -all) — domain explicitly declares it sends no mail"))
        elif s == "hardfail":
            out.append(_status("pass",
                "Hard fail (-all) — strict policy"))
        elif s == "softfail":
            out.append(_status("warn",
                "Soft fail (~all) — receivers will accept-and-mark, not reject"))
        elif s == "pass_all_DANGEROUS":
            out.append(_status("fail",
                "+all — anyone on the internet can spoof this domain"))
        elif s == "neutral":
            out.append(_status("warn",
                "Neutral (?all) — no enforcement"))
        elif s == "no_all_mechanism":
            out.append(_status("warn",
                "SPF record present but missing 'all' mechanism"))
        elif s == "redirect_no_all":
            out.append(_status("warn",
                "SPF via redirect= — no explicit 'all' in target"))
        elif s == "redirect_target_no_spf":
            out.append(_status("fail",
                "SPF redirect target has no SPF record (broken redirect)"))
        else:
            if has_mx:
                out.append(_status("fail",
                    "No SPF record — domain receives mail (MX present); spoofing trivially easy"))
            else:
                out.append(_status("info",
                    "No SPF record — no MX present, not scored"))

        lc = spf.get("lookup_count")
        if lc is not None and s != "null_sender":
            if lc > 10:
                out.append(_status("fail",
                    f"SPF lookup count: {lc} — exceeds 10-lookup limit (silent failures likely)"))
            elif lc >= 9:
                out.append(_status("warn",
                    f"SPF lookup count: {lc} — approaching 10-lookup limit"))
            else:
                out.append(_status("pass",
                    f"SPF lookup count: {lc}"))

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
        out.append("    No SPF data collected.")

    out.append("")
    out.append("")

    # ── DMARC ────────────────────────────────────────────────────────────
    out.extend(_subheading_with_explanation(
        f"DMARC — {domain_label} (RFC 7489)", "dmarc"))
    if dmarc:
        if dmarc.get("error"):
            out.append(_status("info",
                f"DNS query failed: {dmarc['error']}"))
        elif not dmarc.get("present"):
            out.append(_status("fail", "No DMARC record"))
        else:
            inherited = dmarc.get("inherited_from")
            if inherited:
                out.append(_status("info",
                    f"DMARC inherited from organisational domain {inherited}"))
            pol = dmarc.get("policy")
            if pol == "reject":
                out.append(_status("pass",
                    "Policy: reject — strongest enforcement"))
            elif pol == "quarantine":
                out.append(_status("warn",
                    "Policy: quarantine — partial enforcement"))
            elif pol == "none":
                out.append(_status("fail",
                    "Policy: none — monitoring only, no enforcement"))

            if pol in ("reject", "quarantine"):
                pct = dmarc.get("pct")
                if pct is not None and pct < 100:
                    out.append(_status("fail",
                        f"pct={pct} — policy applies to only {pct}% of mail; full enforcement requires pct=100"))
                else:
                    out.append(_status("pass",
                        "pct=100 — policy applies to all mail"))
                sp = dmarc.get("sp")
                if sp == "none":
                    out.append(_status("fail",
                        "sp=none — subdomain policy explicitly set to none; subdomains are unprotected even with apex reject/quarantine"))
                elif sp in ("reject", "quarantine"):
                    out.append(_status("pass",
                        f"sp={sp} — subdomain policy explicitly enforced"))

            rua = dmarc.get("rua") or []
            if rua:
                if len(rua) == 1:
                    out.append(_status("pass",
                        f"rua= aggregate reports collected at {rua[0]}"))
                else:
                    out.append(_status("pass",
                        f"rua= aggregate reports collected at {len(rua)} destinations",
                        sub_lines=rua))
            else:
                out.append(_status("warn",
                    "No rua= tag — no aggregate reporting destination set; operator cannot see spoofing attempts or legit-mail rejections"))

        if dmarc.get("record"):
            out.append("")
            out.append(_raw_value("Record published:", dmarc["record"]))
    else:
        out.append("    No DMARC data collected.")

    out.append("")
    out.append("")

    # ── MX ───────────────────────────────────────────────────────────────
    out.append(_subheading(f"MX records — {domain_label} (RFC 5321, 7505)"))
    out.append("")
    if mx:
        if mx.get("error"):
            out.append(_status("info",
                f"DNS query failed: {mx['error']}"))
        elif mx.get("null_mx"):
            out.append(_status("pass",
                "Null MX (RFC 7505) — domain explicitly does not send or receive mail"))
        elif not mx.get("entries"):
            out.append("    No MX records — domain does not receive email.")
        else:
            # Plain table, two columns: Priority + Host. Lower priority
            # = preferred — note this once for users who don't know.
            out.append("    Priority   Host")
            out.append("    ────────   " + "─" * 60)
            for entry in mx.get("entries", []):
                pri = str(entry.get("priority", ""))
                host = entry.get("host", "")
                out.append(f"    {pri:>5}      {host}")
            out.append("")
            out.append("    (lower priority value = preferred)")
    else:
        out.append("    No MX data collected.")

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
                    f"MTA-STS DNS lookup failed: {mta_sts['error']}"))
            elif mta_sts.get("present"):
                id_str = (f" (id={mta_sts.get('id')})"
                          if mta_sts.get("id") else "")
                mode = (mta_sts_policy.get("mode")
                        if mta_sts_policy.get("fetched") else None)
                if mode == "enforce":
                    items.append(_status("pass",
                        f"MTA-STS published — mode=enforce{id_str}"))
                elif mode == "testing":
                    items.append(_status("warn",
                        f"MTA-STS in mode=testing — failures reported, not enforced{id_str}"))
                elif mode == "none":
                    items.append(_status("warn",
                        f"MTA-STS mode=none — explicit opt-out{id_str}"))
                elif mta_sts_policy.get("fetched") is False:
                    items.append(_status("warn",
                        f"MTA-STS DNS record present but policy file missing or unreachable{id_str}"))
                else:
                    items.append(_status("pass",
                        f"MTA-STS DNS record published{id_str}"))
            else:
                # Wording fix (3.1.0): senders fall back, not receivers.
                items.append(_status("warn",
                    "No MTA-STS — sending servers have no policy preventing fallback to plaintext SMTP"))

        if tls_rpt:
            if tls_rpt.get("error"):
                items.append(_status("info",
                    f"TLS-RPT DNS lookup failed: {tls_rpt['error']}"))
            elif tls_rpt.get("present"):
                rua_v = tls_rpt.get("rua") or ""
                rua_s = f" — {rua_v}" if rua_v else ""
                items.append(_status("pass",
                    f"TLS-RPT reporting enabled{rua_s}"))
            else:
                items.append(_status("warn",
                    "No TLS-RPT — no failure reporting for inbound mail TLS"))

        if dane and dane.get("mx_count", 0) > 0:
            with_t    = dane.get("with_tlsa", []) or []
            without_t = dane.get("without_tlsa", []) or []
            total = dane["mx_count"]
            if len(with_t) == total:
                items.append(_status("pass",
                    f"DANE/TLSA published on all {total} MX host{'s' if total != 1 else ''}"))
            elif with_t:
                detail = []
                for h in with_t:
                    detail.append(f"✓ {h}")
                for h in without_t:
                    detail.append(f"✗ {h}")
                items.append(_status("warn",
                    f"DANE/TLSA on {len(with_t)}/{total} MX hosts — incomplete",
                    sub_lines=detail))
            else:
                # Wording fix (3.1.0): the old line "STARTTLS downgrade
                # not detected" read like a clean assessment.
                items.append(_status("fail",
                    f"No DANE/TLSA on any MX host — vulnerable to STARTTLS downgrade attacks"))

        if dkim and dkim.get("checked"):
            found   = dkim.get("found", []) or []
            checked = dkim.get("checked", []) or []
            keys    = dkim.get("keys", {}) or {}
            if found:
                items.append(_status("pass",
                    f"DKIM key found at common selector(s): {', '.join(found)}",
                    note_lines=[f"Checked: {', '.join(checked)}"]))
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
                        f"DKIM key strength acceptable: {desc}"))
                elif ws == "weak":
                    items.append(_status("warn",
                        f"DKIM key strength: {desc} — RSA-1024 deprecated by RFC 8301",
                        note_lines=["Upgrade to RSA-2048+ or Ed25519."]))
                elif ws == "broken":
                    items.append(_status("fail",
                        f"DKIM key strength: {desc} — RSA <1024 is broken"))
                elif ws == "unparseable":
                    items.append(_status("info",
                        f"DKIM key strength: could not parse key ({desc})"))
                elif ws == "revoked":
                    items.append(_status("info",
                        f"DKIM key strength: revoked ({desc}) — operator deliberately disabled"))
            else:
                items.append(_status("warn",
                    f"No DKIM at common selectors ({', '.join(checked)})",
                    note_lines=[
                        "Partial check only — DKIM uses arbitrary selector names; absence at",
                        "common names proves nothing. Use rua= reports from DMARC to discover",
                        "the actual selectors in use.",
                    ]))

        if items:
            out.append("")
            out.append("")
            out.extend(_subheading_with_explanation(
                f"Mail transport hardening — {domain_label} (RFC 8461, 8460, 6376, 7672)",
                "mail_transport"))
            out.extend(items)

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
        parts.append("  " + "─" * (WIDTH - 2))
        parts.append(f"  Redirect target: {data.audit_domain}")
        parts.append("  " + "─" * (WIDTH - 2))
        parts.append("")
        para = ("Email is also audited for the redirect target, since "
                "users may receive mail at either domain.")
        for ln in _wrap_at_words(para, WIDTH - 2):
            parts.append(f"  {ln}")
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
                f"Domain — DNS query failed: {dom_d['error']}"))
        elif dom_d.get("dnskey") and dom_d.get("ad_flag"):
            parts.append(_status("pass",
                "Domain DNSSEC enabled and validated (DNSKEY present, AD flag confirmed)"))
        elif dom_d.get("dnskey"):
            parts.append(_status("warn",
                "Domain DNSKEY found but AD flag not set (chain may be incomplete)"))
        else:
            parts.append(_status("warn", "Domain DNSSEC not detected (no DNSKEY)"))
            parts.append(_status("warn",
                "DNSSEC chain not validated (AD flag not set)"))
        parts.append("")
        parts.append("")

    # Nameservers / SOA
    if ns_soa:
        parts.extend(_subheading_with_explanation(
            "Nameservers (RFC 1034)", "nameservers"))
        if ns_soa.get("ns_error"):
            parts.append(_status("info",
                f"NS lookup failed: {ns_soa['ns_error']}"))
        else:
            ns_count = ns_soa.get("ns_count", 0)
            if ns_count >= 2:
                parts.append(_status("pass",
                    f"{ns_count} authoritative nameservers"))
            elif ns_count == 1:
                parts.append(_status("fail",
                    "Single nameserver — RFC 1034 recommends ≥2 for redundancy"))
            else:
                parts.append(_status("info", "No nameservers found"))

        ns_list = ns_soa.get("nameservers", []) or []
        if ns_list:
            parts.append("")
            for h in ns_list:
                parts.append(f"       {h}")

        soa = ns_soa.get("soa")
        if soa:
            parts.append("")
            parts.append(_kv([
                ("SOA primary", soa.get("primary", "")),
                ("SOA serial",  soa.get("serial",  "")),
            ]))
        parts.append("")
        parts.append("")

    # CAA
    if caa:
        parts.extend(_subheading_with_explanation(
            "Certification Authority Authorization (CAA) (RFC 8659)", "caa"))
        if caa.get("error"):
            parts.append(_status("info",
                f"CAA lookup failed: {caa['error']}"))
        elif caa.get("present"):
            inh = caa.get("inherited_from")
            inh_str = f" (inherited from {inh})" if inh else ""
            issuers = caa.get("issue", []) or []
            if not issuers or issuers == [";"]:
                parts.append(_status("pass",
                    f"CAA records published — issuance disallowed by default{inh_str}"))
            else:
                parts.append(_status("pass",
                    f"CAA records published — {len(issuers)} authorised CA{'s' if len(issuers) != 1 else ''}{inh_str}",
                    sub_lines=issuers))
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
                "No CAA records — any public CA can issue certificates for this domain"))

    return "\n".join(parts)


# ── Detailed sections: Routing (IP / ASN / RPKI) ─────────────────────────────

def _render_routing_section(data):
    ipr = data.results.get("ip_routing")
    if not ipr:
        return ""

    parts = ["", _heading("IP / ASN / RPKI (RFC 6480)"), ""]
    parts.extend(_section_explanation_lines("routing"))

    def _af_block(af_label, af):
        addr   = af.get("address")
        af_err = af.get("error")
        prefix = af.get("prefix")
        asn    = af.get("asn")
        asn_name = af.get("asn_name", "")
        rpki   = af.get("rpki_status")

        sub = [_subheading(_AF_LABEL_WITH_RFC.get(af_label, af_label)), ""]

        if not addr and af_err:
            sev = "warn" if (af_label == "IPv6" and "no AAAA" in (af_err or "")) else "info"
            sub.append(_status(sev, f"{af_label} — {af_err}"))
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
                addr_pairs = [(f"Addresses ({len(all_addrs)})", all_addrs[0])]
                sub.append(_kv(addr_pairs))
                # Continuation indent matches _kv's value column. _kv pads
                # keys to max-key-width + 4 (gap). For just one pair, the
                # value column starts at indent + len(key) + 4.
                key_w = len(addr_pairs[0][0])
                value_col = 7 + key_w + 4
                for extra in all_addrs[1:]:
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
                "RPKI: valid — origin AS authorised by ROA"))
        elif rpki == "invalid":
            sub.append(_status("fail",
                "RPKI: invalid — ROA exists but origin AS mismatch (possible route hijack)"))
        elif rpki == "not-found":
            sub.append(_status("warn",
                "RPKI: not-found — no Route Origin Authorization published for this prefix"))
        elif rpki == "error":
            err_str = f": {af_err}" if af_err else ""
            sub.append(_status("info", f"RPKI check failed{err_str}"))

        if af.get("irr_in_ris"):
            sub.append(_status("pass", "IRR: prefix seen in RIS routing table"))
        elif prefix:
            sub.append(_status("info",
                "IRR: prefix not seen in RIS snapshot (may be filtered or new)"))

        return sub

    parts.extend(_af_block("IPv4", ipr.get("v4", {}) or {}))
    parts.append("")
    parts.append("")
    parts.extend(_af_block("IPv6", ipr.get("v6", {}) or {}))

    return "\n".join(parts)


# ── Detailed sections: TLS ───────────────────────────────────────────────────

def _render_tls_section(data):
    r = data.results
    tls = r.get("tls", {}) or {}
    cert_var = r.get("cert_variant", {}) or {}

    if not tls and not cert_var:
        return ""

    parts = ["", _heading("TLS (RFC 8446)"), ""]
    parts.extend(_section_explanation_lines("tls"))

    if tls.get("error"):
        parts.append(_status("fail",
            f"Could not connect on port 443: {tls['error']}"))
    else:
        ver = tls.get("version", "unknown")
        if ver == "TLSv1.3":
            parts.append(_status("pass", f"Negotiated {ver}"))
        elif ver == "TLSv1.2":
            parts.append(_status("warn",
                f"Negotiated {ver} — TLS 1.3 not supported"))
        else:
            parts.append(_status("fail",
                f"Negotiated {ver} — upgrade required"))

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
                                 note_lines=note))
        elif names_match is False:
            parts.append(_status("fail",
                f"Certificate name mismatch — cert does not cover {data.audit_domain}"))

        lifetime = tls.get("cert_lifetime_days")
        issued   = tls.get("cert_issued",  "")
        expires  = tls.get("cert_expires", "")
        if lifetime is not None:
            date_note = [f"Issued:  {issued}", f"Expires: {expires}"]
            if lifetime <= 199:
                parts.append(_status("pass",
                    f"Certificate lifetime: {lifetime} days — automated issuance likely",
                    note_lines=date_note))
            else:
                parts.append(_status("warn",
                    f"Certificate lifetime: {lifetime} days — may indicate manual renewal",
                    note_lines=date_note))

        cv_outcome = cert_var.get("outcome")
        if cv_outcome == "covers":
            parts.append(_status("pass",
                "Certificate covers the redirect source/target variant"))
        elif cv_outcome == "missing_variant":
            missing = cert_var.get("missing", []) or []
            parts.append(_status("warn",
                f"Certificate missing coverage for: {', '.join(missing)} — users typing the uncovered name see a TLS error before the redirect"))

        # Chain completeness — only emit a row when chain inspection actually
        # ran (Python 3.13+). On older Pythons (chain_status='unsupported')
        # stay silent rather than adding a confusing "we couldn't check" line.
        cs = tls.get("chain_status")
        sent = tls.get("chain_sent_count")
        ver_n = tls.get("chain_verified_count")
        if cs == "complete":
            parts.append(_status("pass",
                f"Server sends complete certificate chain (sent {sent}, verified {ver_n})"))
        elif cs == "incomplete":
            parts.append(_status("warn",
                f"Incomplete chain: server sent {sent} cert(s) but {ver_n} were needed",
                note_lines=[
                    "Clients fall back to AIA fetching (some clients don't",
                    "AIA-fetch; captive portals break it; latency suffers).",
                    "Server should send leaf + every needed intermediate.",
                ]))

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
            parts.append(f"       SAN names ({len(san)}):")
            for n in san:
                parts.append(f"         {n}")

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
            f"Response time: {int(elapsed):,} ms",
            note_lines=["Includes DNS + TCP + TLS handshake — not a pure HTTP RTT"]))

    if redirect.get("redirected"):
        if redirect.get("first_hop_https") and redirect.get("first_hop_same_host"):
            parts.append(_status("pass", "First redirect hop is HTTPS on the same host"))
        elif redirect.get("first_hop_url"):
            first_hop = redirect.get("first_hop_url")
            if not redirect.get("first_hop_https"):
                parts.append(_status("warn",
                    f"First redirect hop is plain HTTP ({first_hop}) — bypasses HSTS"))
            else:
                parts.append(_status("warn",
                    f"First redirect hop is off-host ({first_hop}) — leaks Referer and prevents HSTS for the apex"))

    http3       = server.get("http3_advertised")
    alt_svc_val = server.get("alt_svc")
    hv_ver      = hv.get("version")
    if http3:
        alt_note = [f"Alt-Svc: {alt_svc_val}"] if alt_svc_val else None
        parts.append(_status("pass", "HTTP/3 advertised", note_lines=alt_note))
    elif hv_ver == "HTTP/2":
        parts.append(_status("warn", "HTTP/2 supported, HTTP/3 not advertised"))
    elif hv_ver == "HTTP/1.1":
        parts.append(_status("fail",
            "HTTP/1.1 detected — server does not support HTTP/2 or HTTP/3 (http1mustdie.com)"))
    elif hv.get("error"):
        parts.append(_status("info",
            f"HTTP version check failed: {hv['error']}"))

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
                             note_lines=notes))
    elif hr_status == "http_available":
        verify = f"Verify with: curl -v http://{data.audit_domain}"
        trimmed = _trim_redundant_prefix(hr_detail, "Page is accessible over plain HTTP")
        notes = []
        if trimmed:
            notes.append(trimmed)
        notes.append(verify)
        parts.append(_status("fail",
            "Page is accessible over plain HTTP",
            note_lines=notes))
    elif hr_status == "http_error":
        sc = http_redir.get("status_code", "")
        verify = f"Verify with: curl -v http://{data.audit_domain}"
        # Port 80 returned 4xx/5xx without redirecting. Treated as a pass
        # because the security outcome (no plaintext content) is achieved.
        parts.append(_status("pass",
            f"HTTP port 80 refuses plaintext (status {sc} from http://{data.audit_domain})",
            note_lines=[verify]))
    elif hr_status == "unreachable":
        notes = [hr_detail] if hr_detail else None
        parts.append(_status("info",
            "HTTP port 80 not reachable",
            note_lines=notes))

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
            f"Could not fetch HTTPS response: {hsts['error']}"))
    elif not hsts.get("present"):
        parts.append(_status("fail", "Strict-Transport-Security header not set"))
    else:
        parts.append(_status("pass", "Strict-Transport-Security header present"))

        ma = hsts.get("max_age")
        min_age = 15552000  # 180 days — OWASP/Qualys minimum
        if ma is None:
            parts.append(_status("warn",
                "max-age missing — header has no expiry directive"))
        elif ma >= min_age:
            days = ma // 86400
            parts.append(_status("pass",
                f"max-age={int(ma):,} ({days} days)"))
        else:
            days = ma // 86400
            min_days = min_age // 86400
            parts.append(_status("warn",
                f"max-age={int(ma):,} ({days} days) — below the {min_days}-day minimum (OWASP/Qualys)"))

        if hsts.get("includes_subdomains"):
            parts.append(_status("pass", "includeSubDomains set"))
        else:
            parts.append(_status("warn", "includeSubDomains not set"))

    if hsts.get("preload_error") and hsts.get("preloaded") is None:
        parts.append(_status("info",
            f"Preload list check failed: {hsts['preload_error']}"))
    elif hsts.get("preloaded"):
        parts.append(_status("pass", "Domain is on the HSTS preload list"))
    elif hsts.get("present") and hsts.get("preload_directive"):
        parts.append(_status("warn",
            "preload directive present but domain not yet in preload list"))
    elif hsts.get("present") and hsts.get("preloaded") is False:
        parts.append(_status("warn", "Not in HSTS preload list"))

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
        parts.append("    Site unreachable. Server and security headers cannot be evaluated.")
        parts.append(f"    {srv['error']}")
        return "\n".join(parts)

    val = srv.get("server")
    try:
        from .audit_checks import classify_server
        kind = classify_server(val)
    except Exception:
        kind = "unknown"

    if kind == "absent":
        parts.append(_status("pass", "Server header not present"))
    elif kind == "good_proxy":
        parts.append(_status("pass",
            f"Server: {val} — reverse proxy / CDN"))
    elif kind == "origin_with_version":
        parts.append(_status("fail",
            f"Server: {val} — origin server with version disclosed"))
    elif kind == "origin_no_version":
        parts.append(_status("warn",
            f"Server: {val} — origin server exposed (no version)"))
    else:
        if val:
            parts.append(_status("warn",
                f"Server: {val} — server technology disclosed"))

    if srv.get("x_powered_by"):
        parts.append(_status("fail",
            f"X-Powered-By: {srv['x_powered_by']} — technology disclosed"))
    else:
        parts.append(_status("pass", "X-Powered-By header not present"))

    # Server clock
    clock = r.get("clock", {}) or {}
    skew = clock.get("skew_seconds")
    if clock.get("outcome") == "in_sync":
        parts.append(_status("pass",
            f"Server clock in sync with UTC (skew: {skew:+.0f}s)"))
    elif clock.get("outcome") == "minor_skew":
        parts.append(_status("warn",
            f"Server clock skew: {skew:+.0f}s — small but noticeable"))
    elif clock.get("outcome") == "bad_skew":
        parts.append(_status("fail",
            f"Server clock skew: {skew:+.0f}s — large skew can break HSTS, OAuth, and certificate validation"))

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
            display     = _OS_DISPLAY_NAMES.get(os_name, os_name)
            stack_label = f"{display} {ver_display}".rstrip()
            underlying  = finding.get("underlying_os")
            tls_note    = finding.get("tls_capability_note")
            eol_status  = finding.get("eol_status")

            if finding.get("source") == "server_header_iis":
                head = f"IIS {ver} → {underlying or stack_label}"
            else:
                head = stack_label

            if eol_status == "eol":
                date     = finding.get("eol_last_release", "")
                date_str = f" — EOL {date}" if date else ""
                via_str  = ""
                if underlying and stack_label != underlying:
                    via_str = f" (detected via {stack_label})"
                parts.append(_status("fail", f"{head}{date_str}{via_str}",
                                     note_lines=[tls_note] if tls_note else None))
            elif eol_status == "unknown":
                hint = " — version not exposed in Server header" if not ver else ""
                parts.append(_status("info", f"{head}{hint}",
                                     note_lines=[tls_note] if tls_note else None))
            else:
                parts.append(_status("info", head,
                                     note_lines=[tls_note] if tls_note else None))

        if tls_old_stack and tls_signals:
            parts.append(_status("warn",
                f"Legacy TLS still negotiated: {', '.join(tls_signals)}",
                note_lines=["Corroborates old-stack hypothesis"]))

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
            for s in unique:
                parts.append(f"       {s}")

    return "\n".join(parts)


# ── Detailed sections: Versioned libraries ──────────────────────────────────

def _render_versioned_libraries_section(data):
    vlibs = (data.results.get("versioned_libs") or {}).get("libraries") or []
    if not vlibs:
        return ""

    parts = ["", _heading("VERSIONED LIBRARIES (OWASP A06:2021 — vulnerable & outdated components)"), ""]
    parts.extend(_section_explanation_lines("eol_libraries"))
    parts.append(
        f"  {len(vlibs)} client-side librar"
        f"{'y' if len(vlibs)==1 else 'ies'} detected in static HTML."
    )
    parts.append("")

    # Compute column widths from the data.
    name_w = max(len(_LIB_DISPLAY_NAMES.get(l.get("library", ""),
                                             l.get("library", "")))
                 for l in vlibs)
    ver_w = max(len(str(l.get("version", "?"))) for l in vlibs)
    name_w = max(name_w, len("Library"))
    ver_w  = max(ver_w,  len("Version"))

    parts.append(f"    {'Library'.ljust(name_w)}   {'Version'.ljust(ver_w)}   Status     Notes")
    parts.append(f"    {'─' * name_w}   {'─' * ver_w}   ──────     ─────")
    for lib in vlibs:
        name = _LIB_DISPLAY_NAMES.get(lib.get("library", ""),
                                       lib.get("library", ""))
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
        parts.append(_status("pass", "Content-Security-Policy set"))
    elif csp_q == "permissive":
        parts.append(_status("warn",
            "Content-Security-Policy present but appears permissive (wildcard src detected)"))
    else:
        parts.append(_status("warn", "Content-Security-Policy not set"))

    if csp_a.get("present"):
        sso = csp_a.get("script_src_outcome")
        if sso == "strict":
            parts.append(_status("pass",
                "CSP script-src: strict (nonce/hash + 'strict-dynamic')"))
        elif sso == "nonce_or_hash":
            parts.append(_status("pass",
                "CSP script-src: nonce/hash present"))
        elif sso == "host_allowlist":
            parts.append(_status("warn",
                "CSP script-src: host-allowlist (weaker than nonce/hash)"))
        elif sso == "unsafe_inline":
            parts.append(_status("fail",
                "CSP script-src: 'unsafe-inline' without nonce/hash — inline scripts run"))
        elif sso == "wildcard_or_scheme":
            parts.append(_status("fail",
                "CSP script-src: wildcard or dangerous scheme — policy bypass possible"))

        oso = csp_a.get("object_src_outcome")
        if oso == "none_or_self":
            parts.append(_status("pass",
                "CSP object-src restricted ('none' or 'self')"))
        elif oso == "unrestricted":
            parts.append(_status("fail",
                "CSP object-src unrestricted — plugin XSS likely"))
        else:
            parts.append(_status("warn",
                "CSP object-src missing — plugins (Flash, Java) can be injected"))

        buo = csp_a.get("base_uri_outcome")
        if buo == "set":
            parts.append(_status("pass",
                "CSP base-uri restricted (prevents <base> hijack)"))
        else:
            parts.append(_status("warn",
                "CSP base-uri missing — <base> tag injection can hijack relative URLs"))

        fao     = csp_a.get("frame_ancestors_outcome")
        xfo_now = srv.get("x_frame_options")
        if fao == "set":
            parts.append(_status("pass", "CSP frame-ancestors restricted"))
        elif not xfo_now:
            parts.append(_status("warn",
                "CSP frame-ancestors missing — and no X-Frame-Options either"))

        if csp_a.get("enforcement_outcome") == "report_only":
            parts.append(_status("warn",
                "CSP is in Report-Only mode — violations logged but not blocked"))

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
            note_lines=["frame-ancestors also set in CSP"]))
    elif csp_fa:
        parts.append(_status("pass",
            "X-Frame-Options covered by CSP frame-ancestors"))
    elif xfo:
        xfo_first = xfo.split(",")[0].strip().upper()
        if xfo_first in ("DENY", "SAMEORIGIN"):
            dupe = " — header sent multiple times" if "," in xfo else ""
            parts.append(_status("pass",
                f"X-Frame-Options: {xfo_first}{dupe}"))
        else:
            parts.append(_status("warn",
                f"X-Frame-Options: {xfo} — unrecognised value"))
    else:
        parts.append(_status("warn", "X-Frame-Options not set"))

    # X-Content-Type-Options
    xcto = srv.get("x_content_type")
    if xcto and xcto.lower() == "nosniff":
        parts.append(_status("pass", "X-Content-Type-Options: nosniff"))
    elif xcto:
        parts.append(_status("warn",
            f"X-Content-Type-Options: {xcto} — expected nosniff"))
    else:
        parts.append(_status("warn", "X-Content-Type-Options not set"))

    # Referrer-Policy
    rp = srv.get("referrer_policy")
    if rp:
        rp_first = rp.split(",")[0].strip().lower()
        dupe = " — header sent multiple times" if "," in rp else ""
        if rp_first in _STRONG_REFERRER_POLICIES:
            parts.append(_status("pass",
                f"Referrer-Policy: {rp_first}{dupe}"))
        else:
            parts.append(_status("warn",
                f"Referrer-Policy: {rp_first}{dupe} — consider a stricter policy"))
    else:
        parts.append(_status("warn", "Referrer-Policy not set"))

    # Permissions-Policy
    pp = srv.get("permissions_policy")
    if pp:
        parts.append(_status("pass", "Permissions-Policy set"))
    else:
        parts.append(_status("warn", "Permissions-Policy not set"))

    # COOP
    coop     = (srv.get("coop") or "").strip()
    coop_low = coop.lower()
    if coop_low == "same-origin":
        parts.append(_status("pass", f"Cross-Origin-Opener-Policy: {coop}"))
    elif coop_low == "same-origin-allow-popups":
        parts.append(_status("warn",
            f"Cross-Origin-Opener-Policy: {coop} — partial isolation"))
    elif coop:
        parts.append(_status("warn",
            f"Cross-Origin-Opener-Policy: {coop} — weak value"))
    else:
        parts.append(_status("warn", "Cross-Origin-Opener-Policy not set"))

    # CORP
    corp     = (srv.get("corp") or "").strip()
    corp_low = corp.lower()
    if corp_low in ("same-origin", "same-site"):
        parts.append(_status("pass", f"Cross-Origin-Resource-Policy: {corp}"))
    elif corp_low == "cross-origin":
        parts.append(_status("warn",
            f"Cross-Origin-Resource-Policy: {corp} — explicit cross-origin"))
    elif corp:
        parts.append(_status("warn",
            f"Cross-Origin-Resource-Policy: {corp}"))
    else:
        parts.append(_status("warn", "Cross-Origin-Resource-Policy not set"))

    # COEP — informational
    coep = (srv.get("coep") or "").strip()
    if coep:
        parts.append(_status("info", f"Cross-Origin-Embedder-Policy: {coep}"))

    # X-XSS-Protection — deprecated. Wording fix (3.1.0): "correctly absent"
    # phrasing instead of "not enabled" which sounded like a problem.
    xxp = (srv.get("x_xss_protection") or "").strip()
    if xxp.startswith("0"):
        parts.append(_status("pass",
            "X-XSS-Protection: 0 — explicitly disabled (correct, header is deprecated)"))
    elif xxp:
        parts.append(_status("warn",
            f"X-XSS-Protection: {xxp} — header is deprecated; setting it can introduce XSS in older browsers. Recommended: remove or set to 0"))

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
        para = ("No Set-Cookie headers on this response (cookies set after "
                "login or by JavaScript are not visible here).")
        for ln in _wrap_at_words(para, WIDTH - 4):
            parts.append(f"    {ln}")
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
            f"Could not fetch security.txt: {sectxt['error']}"))
    elif sectxt.get("present") and sectxt.get("contact"):
        found_at = sectxt.get("found_at", "")
        if found_at and "/security.txt" in found_at and "/.well-known/" not in found_at:
            parts.append(_status("warn",
                f"Found at legacy path: {found_at} (consider moving to /.well-known/security.txt)"))
        for contact in sectxt.get("contact", []) or []:
            parts.append(_status("pass", f"Contact: {contact}"))
        if sectxt.get("policy"):
            parts.append(_status("info", f"Policy: {sectxt['policy']}"))
        expires = sectxt.get("expires")
        expired = sectxt.get("expired")
        if expires and expired is False:
            parts.append(_status("pass", f"Expires: {expires}"))
        elif expires and expired is True:
            parts.append(_status("fail",
                f"Expires: {expires} — security.txt has expired"))
        elif expires is None:
            parts.append(_status("warn",
                "Expires field missing — required by RFC 9116"))
    elif sectxt.get("present"):
        parts.append(_status("warn",
            "security.txt present but no Contact: field found"))
    else:
        parts.append(_status("warn", "security.txt not found"))

    return "\n".join(parts)


# ── Detailed sections: Default error page / CORS / Reporting endpoints ──────

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
            f"Custom error page (status {status}) — no default-server fingerprint matched"))
    elif epo == "default_no_version":
        parts.append(_status("warn",
            f"Default {detected} error page detected (status {status}) — no version disclosed",
            note_lines=[
                "Operator has not customised the default 404. Strip or override",
                "to avoid disclosing server software in error responses.",
            ]))
    elif epo == "default_with_version":
        parts.append(_status("fail",
            f"Default {detected}/{version} error page (status {status})",
            note_lines=[
                f"Default 404 reveals {detected} version {version}.",
                "Strip the default error page or replace it with a custom template.",
            ]))
    elif epo == "spa_or_2xx":
        parts.append(_status("info",
            f"Probe path returned {status} (SPA shell or wildcard route) — no 404 to inspect"))
    elif epo == "error":
        parts.append(_status("info",
            f"Could not probe error page: {epr.get('error', '?')}"))

    return "\n".join(parts)


def _render_cors_section(data):
    cors = data.results.get("cors", {}) or {}
    if not cors.get("outcome"):
        return ""

    parts = ["", _heading("CORS CONFIGURATION"), ""]

    co_outcome = cors.get("outcome")
    if co_outcome == "no_cors":
        parts.append(_status("pass",
            "No CORS headers — secure default (browsers refuse cross-origin reads)"))
    elif co_outcome == "weak_wildcard_with_credentials":
        parts.append(_status("fail",
            "ACAO=* combined with Allow-Credentials=true — spec-forbidden pairing",
            note_lines=[
                "Browsers refuse this combination at runtime, but a server emitting",
                "it indicates the operator believes credentials flow cross-origin",
                "from any origin — a real misconfiguration.",
            ]))
    elif co_outcome == "weak_null_origin":
        parts.append(_status("fail",
            "ACAO=null — trusts sandboxed iframes and other null-origin contexts"))
    elif co_outcome == "weak_reflective":
        parts.append(_status("fail",
            "Reflective ACAO — server echoes whatever Origin: the client sends",
            note_lines=[
                "Verified by sending Origin: https://vendor-audit-cors-probe.example",
                "and observing the same value returned in Access-Control-Allow-Origin.",
                "Any origin is effectively trusted; equivalent to ACAO=*.",
            ]))
    elif co_outcome == "error":
        parts.append(_status("info",
            f"Could not probe CORS: {cors.get('error', '?')}"))

    return "\n".join(parts)


def _render_reporting_endpoints_section(data):
    srv = data.results.get("server_header", {}) or {}
    if srv.get("error"):
        return ""
    rt  = srv.get("report_to")
    re_ = srv.get("reporting_endpoints")
    nel = srv.get("nel")
    if not (rt or re_ or nel):
        # Absent is not a finding — don't emit a section at all.
        return ""

    parts = ["", _heading("REPORTING ENDPOINTS (CSP / NEL TELEMETRY)"), ""]
    if re_:
        parts.append(_status("pass", "Reporting-Endpoints header set (W3C Reporting API)"))
    if rt:
        parts.append(_status("pass", "Report-To header set (legacy, still widely deployed)"))
    if nel:
        parts.append(_status("pass", "NEL header set (Network Error Logging)"))
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
        parts.append(_status("info", "No grade returned from SSL Labs"))
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

        # Score the grade using the same rubric the breakdown uses, so
        # the detail line displays "Grade: B (3/5)" — matching the
        # breakdown row in the executive summary.
        grade_table = data.rubric.get("weights", {}).get("SSL Labs grade", {}) or {}
        grade_entry = grade_table.get(worst)
        score_str   = ""
        if grade_entry:
            e = _fmt_int_or_float(grade_entry.get("earned"))
            p = _fmt_int_or_float(grade_entry.get("possible"))
            score_str = f"  ({e}/{p})"

        # Wording fix (3.1.0): include the grade in the label so the
        # reader sees the verdict without scrolling to find a fraction.
        parts.append(_status(sev,
            f"Grade: {worst}{score_str}{ep_str}",
            note_lines=[
                f"Re-run anytime: https://www.ssllabs.com/ssltest/analyze.html?d={data.audit_domain}",
            ]))

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
        for ln in _wrap_at_words(para, WIDTH - 2):
            parts.append(f"  {ln}")
        parts.append("")
    if not looks_html and (page.get("body_bytes") or 0) > 0:
        para = ("Response body does not look like HTML. Page-level counts "
                "below are unreliable. Common causes: bot-mitigation "
                "challenge page (Akamai / AWS WAF), non-HTML payload "
                "(JSON API, PDF), or a CDN that ignored Accept-Encoding.")
        for ln in _wrap_at_words(para, WIDTH - 2):
            parts.append(f"  {ln}")
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
    parts.append(_kv([
        ("HTML inspected",        _fmt_kb_or_mb(body_bytes)),
        ("<script>",              str(scripts)),
        ("<link rel=stylesheet>", str(stylesheets)),
        ("<img>",                 str(img_total)),
        ("<input>",               str(inp_total)),
        ("<iframe>",              str(iframe_n)),
    ]))
    parts.append("")

    if (looks_html and scripts > 0 and img_total == 0 and inp_total == 0
            and not redirect.get("body_truncated")):
        para = ("Most likely a bot-protection or captcha challenge page "
                "(Cloudflare / Akamai / AWS WAF) — could also be a real "
                "SPA shell rendered client-side. Either way the static "
                "HTML has no <img>/<input>.")
        for ln in _wrap_at_words(para, WIDTH - 2):
            parts.append(f"  {ln}")
        parts.append("")

    sri_outcome = page.get("sri_outcome")
    protected   = page.get("sri_protected", 0)
    ext_total   = page.get("sri_external_total", 0)
    if sri_outcome == "no_external_scripts":
        parts.append(_status("pass", "No external scripts/stylesheets — SRI not needed"))
    elif sri_outcome == "all_external_have_sri":
        parts.append(_status("pass",
            f"Subresource Integrity on all {ext_total} external resources"))
    elif sri_outcome == "some_external_have_sri":
        parts.append(_status("warn",
            f"Subresource Integrity on {protected}/{ext_total} external resources"))
    elif sri_outcome == "external_without_sri":
        # Wording fix (3.1.0): "any of 1" was awkward.
        if ext_total == 1:
            parts.append(_status("fail",
                "No Subresource Integrity on the only external resource — a CDN compromise could inject arbitrary code"))
        else:
            parts.append(_status("fail",
                f"No Subresource Integrity on any of the {ext_total} external resources — a CDN compromise could inject arbitrary code"))

    mc_outcome = page.get("mixed_outcome")
    mc_count   = page.get("mixed_active_count", 0)
    mc_list    = page.get("mixed_active", []) or []
    if mc_outcome == "active":
        parts.append(_status("fail",
            f"Mixed content (active): {mc_count} HTTP resource(s) on HTTPS page",
            sub_lines=mc_list if mc_list else None))
    elif mc_outcome == "passive_only":
        parts.append(_status("warn",
            "Mixed content (passive only) — images/media loaded over HTTP"))
    elif mc_outcome == "none":
        parts.append(_status("pass", "No mixed content detected"))

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
                "<html> has no lang attribute"))
        else:
            parts.append(_status("pass",
                f'<html lang="{a.get("html_lang") or "?"}">'))

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
        para = ("A11y signals are not scored — they are reported for "
                "awareness only. For a full audit use WebAIM WAVE, "
                "Axe DevTools, or pa11y.")
        for ln in _wrap_at_words(para, WIDTH - 2):
            parts.append(f"  {ln}")

    return "\n".join(parts)


# ── Detailed sections: STARTTLS-MX probe (--deep) ───────────────────────────

def _render_starttls_section(data):
    starttls = data.results.get("starttls_mx")
    if starttls is None or starttls.get("mx_count", 0) == 0:
        return ""

    parts = ["", _heading("MX STARTTLS PROBE (--deep) (RFC 3207)"), ""]
    para = ("Probing port 25 → EHLO → STARTTLS on each MX host. Many "
            "networks block port 25 egress; partial results are normal.")
    for ln in _wrap_at_words(para, WIDTH - 2):
        parts.append(f"  {ln}")
    parts.append("")

    rows = starttls.get("results") or {}
    if not rows:
        parts.append("    No probe results.")
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

def _render_text(data):
    """Compose the final text document from the prepared _ReportData."""
    redirected = (data.results.get("redirect") or {}).get("redirected")

    out = []
    out.append(_render_header(data))
    out.append("")
    out.append("")

    # Partial-audit banner. Mirrors the web result page's banner so the
    # downloadable .txt is also clearly marked as incomplete when the
    # audit hit its wall-clock deadline.
    if data.results.get("_partial"):
        reason = data.results.get("_partial_reason") or \
            "Some checks did not complete."
        out.append("  ⚠ PARTIAL AUDIT")
        out.append(f"    {reason}")
        out.append("")
        out.append("")

    if redirected and data.audit_domain != data.original_domain:
        out.append(f"  Redirect: {data.original_domain} redirects to {data.audit_domain}.")
        out.append("  Email is audited for both domains; web / TLS reflects the destination.")
        out.append("")
        out.append("")

    out.append(_render_score_panel(data))
    out.append("")
    out.append("")

    out.append(_render_executive_summary(data))

    # Detailed sections — each returns "" when its source data is absent.
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
        _render_reporting_endpoints_section,
        _render_ssl_labs_section,
        _render_page_analysis_section,
        _render_starttls_section,
    ):
        block = renderer(data)
        if block:
            out.append(block)

    out.append(_render_scan_footer(data))
    out.append("")
    out.append(RULE_HEAVY)
    out.append(f"  Generated by vendor_audit {data.report_version}")
    out.append("  https://vendoraudit.org")
    out.append("  https://github.com/chrono1313/Vendor-Audit")
    out.append(RULE_HEAVY)
    out.append("")  # final trailing newline

    return "\n".join(out)


# ── Public entry point ───────────────────────────────────────────────────────

def write_txt_report(original_domain, audit_domain, results, timestamp,
                     out_path, report_version=None):
    """Build a detailed plain-text report and write it to disk.

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

    File is written UTF-8 (no BOM). Targets Notepad on Windows 11, which
    auto-detects UTF-8 since the 2019 update.

    Raises:
        OSError: filesystem write failures bubble up unchanged.
    """
    data = _ReportData(
        original_domain=original_domain,
        audit_domain=audit_domain,
        results=results,
        timestamp=timestamp,
        report_version=report_version or __version__,
    )
    text = _render_text(data)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
