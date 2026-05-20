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


__version__ = "1.2.1"


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
    "Authoritative delegation":     49,   # lame NS = some users get NODATA/SERVFAIL
    "NS not open resolver":         50,   # DDoS-amp risk; not a takeover but real
    "MX target hygiene":            51,   # RFC 2181 violation; sending MTAs vary

    # ── Tier 3: defence-in-depth / hardening ────────────────────────────
    "TLS 1.3":                      55,
    "HTTP→HTTPS redirect":          56,
    "www and apex unified":         57,
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

    EOL OS and EOL libraries both sort to the very top — both signal
    "running unpatched software" and are usually the most consequential
    issues a vendor has, ahead of email or TLS configuration. EOL OS
    edges ahead (rank 5) because a kernel-level CVE on an EOL OS is
    typically more urgent than a client-side library bug; EOL libraries
    sit just behind at rank 8. Both ranks are above the most-critical
    Tier 1 entries (SPF policy, DMARC, TLS connection) so EOL findings
    always lead the Possible Issues list when present.
    """
    if not label:
        return _CRITICALITY_DEFAULT_RANK
    if label.startswith("EOL OS:"):
        return 5
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
# Keep each line under ~140 characters so they wrap cleanly in the 100-col
# txt report and don't require a second wrap on a typical browser width.
EXPLANATIONS = {
    "spf": {
        "what": "SPF is a DNS record that lists which mail servers are allowed to send email using your domain.",
        "why":  "Without enforcement, anyone can spoof your domain in phishing emails — recipients can't tell a forgery from a real message.",
        "fix":  "Publish a v=spf1 record listing your senders and end with -all (hard fail) so receivers reject unauthorised mail.",
        "details": [
            "Sender Policy Framework (SPF, RFC 7208) is published as a DNS TXT record on your domain. When a receiving mail server gets a message claiming to be from your domain, it can read the SPF record and check whether the sending IP appears on your authorised list. If it doesn't, the receiver applies whatever policy your record's qualifier specifies.",
            "The qualifier — the symbol before all in the record — is what determines what receivers actually do. -all means hard fail (reject). ~all means soft fail (accept but mark, often spam-folder). ?all is neutral (no opinion). +all is permissive (anyone can send, almost certainly a misconfiguration). Only -all and a properly-published null sender (v=spf1 -all) on a non-sending domain are considered fully enforcing.",
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
            "Key strength matters. RSA-1024 has been formally deprecated by RFC 8301 since 2018; modern best practice is RSA-2048 or higher, or the more efficient Ed25519. M3AAWG's DKIM Key Rotation Best Common Practices recommends rotating keys roughly every six months, which the selector mechanism makes easy: publish a new key under a new selector, switch your signer to it, retire the old selector after a propagation window.",
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
        "what": "RFC 1034 requires every domain to have at least two authoritative nameservers for redundancy.",
        "why":  "A single nameserver is a single point of failure — if it goes down, your domain effectively disappears from the internet.",
        "fix":  "Configure at least two nameservers, ideally on different networks; most DNS providers do this automatically.",
        "details": [
            "Two-or-more nameservers is one of the oldest requirements in DNS — RFC 1034 specified it in 1987. The reason hasn't changed: DNS resolution is the gate to every other service, and a single point of failure for DNS is a single point of failure for the entire domain. Mail, web, APIs all stop working if name resolution fails.",
            "For redundancy to actually help, the nameservers should be diverse. Two nameservers at the same hosting provider in the same datacentre give you resilience against process crashes but not against network outages or BGP issues at that provider. Many TLDs and registries actively encourage anycast deployment (where each nameserver name resolves to multiple IPs around the world) and require nameservers to be on different IPv4 prefixes.",
            "Modern managed DNS services (Cloudflare, Route 53, Google Cloud DNS, NS1) handle this automatically — assigning four or more anycast nameservers across global infrastructure. If you're running your own nameservers, RFC 2182 has specific guidance on diversity and security; in particular, secondaries should be at a different physical location and ideally a different ISP.",
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
            "Certificate lifetime is now an enforcement point in its own right. Under the CA/Browser Forum's Ballot SC081v3, the maximum lifetime stepped down from 398 days to 200 days on March 15, 2026; it drops to 100 days on March 15, 2027 and to 47 days on March 15, 2029. Short-lived certificates with automated renewal (ACME / Let's Encrypt) are the only path that scales at the 47-day endpoint; manually-renewed certificates are already strained at 200 days and won't be viable at 100. Operators still on annual-renewal workflows should plan automation now rather than during the next squeeze.",
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
        "what": "HTTP/2 and HTTP/3 are modern transport protocols that are faster and more efficient than HTTP/1.1.",
        "why":  "HTTP/3 in particular improves performance on mobile networks and high-latency links; both fix head-of-line blocking from HTTP/1.1.",
        "fix":  "Enable HTTP/2 and HTTP/3 in your web server or CDN; most modern stacks support both with a single config flag.",
        "details": [
            "HTTP/2 (originally RFC 7540 in 2015, current revision RFC 9113 in 2022) and HTTP/3 (RFC 9114, 2022) are the modern HTTP transports. HTTP/2 multiplexes many requests over a single TCP connection, eliminating the connection-pool overhead of HTTP/1.1 and the artificial sharding workarounds (multiple subdomains, sprite sheets) sites used to need. HTTP/3 takes the same idea to UDP via QUIC, improving handshake latency and resilience to packet loss.",
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
            "Vendor Audit infers the OS from the Server response header and matches against a hand-curated list of EOL versions: CentOS 6/7/8, RHEL 5/6/7 (without ELS), Ubuntu LTS releases past their support window, Debian past oldoldstable, FreeBSD older than the supported branches, and old IIS / Windows Server combinations. The library_eol.json and os_eol.json files in the repo carry the support floor for each, with citations.",
            "Detection is best-effort. Sites behind Cloudflare, Akamai, or AWS CloudFront usually return the CDN's Server header, masking the origin entirely — the audit can't see what's running underneath. Some operators set the Server header to a custom string for the same reason. A clean EOL OS check on a CDN-fronted site means the audit couldn't determine the origin OS, not that the origin is supported.",
            "If business or compliance reasons prevent immediate upgrade, the practical mitigation is to put the EOL system behind aggressive WAF rules, restrict its network exposure, and accelerate the migration plan. Extended Support Subscriptions (RHEL ELS, Ubuntu ESM) are a paid path to keep getting security updates for one or two years past the standard EOL — useful as a bridge while migrating, not as a permanent strategy.",
        ],
    },
    "eol_libraries": {
        "what": "An end-of-life client-side library (jQuery, Bootstrap, Angular, etc.) no longer receives security or compatibility updates.",
        "why":  "Browser environments evolve constantly; an unmaintained library is increasingly likely to break or harbour known XSS vulnerabilities.",
        "fix":  "Upgrade to the current major version of the library, or migrate to a supported alternative.",
        "details": [
            "Client-side JavaScript libraries have their own support lifecycles — usually shorter than operating systems, often 18-36 months from a major release. jQuery, Bootstrap, Angular, Vue, Ember, the WordPress / Drupal / Joomla CMSes, and many smaller libraries publish a support policy that names which majors still receive security fixes.",
            "Vendor Audit recognises about 185 client-side libraries via static HTML inspection — script src attributes, inline version markers, well-known global object signatures. Of those, 28 have curated EOL dates (jQuery 1.x and 2.x, Bootstrap 2.x and 3.x, AngularJS, Angular versions before the current LTS, etc.). The remaining ~150 are reported with their version but not flagged as EOL — version detection is reliable, but EOL judgments require maintenance and citation.",
            "Upgrading client-side libraries is sometimes a small change (a single CDN URL update) and sometimes a months-long migration. AngularJS to Angular is the canonical hard case: different framework, complete rewrite. jQuery 1.x to 3.x is mostly mechanical but breaks in subtle ways with custom plugins. Regardless, an EOL library is a known-fragile dependency and the cost of replacement only goes up over time.",
            "If immediate upgrade is impossible, the next-best step is to add Subresource Integrity (SRI) attributes to the library's <script> tag and pin the version — at least preventing a CDN compromise from substituting a malicious version. But SRI doesn't fix vulnerabilities in the library itself; it just keeps the library you have from being silently swapped out.",
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
    "reporting_endpoints": {
        "what": "The Reporting-Endpoints header (and its predecessor Report-To) names URLs where the browser can POST violation reports for CSP, network errors, deprecations, and other policies.",
        "why":  "Without a reporting endpoint, you're flying blind — CSP violations, certificate transparency failures, and other client-side issues are invisible to you.",
        "fix":  "Add Reporting-Endpoints: csp-endpoint=\"https://example.com/csp\" (and other named endpoints), then reference them with report-to in your CSP and other policy headers.",
        "details": [
            "The Reporting API (W3C) is the modern way to collect telemetry from browsers about policy violations and network failures. CSP, Cross-Origin-Opener-Policy, Document-Policy, certificate transparency expectations, and deprecation/intervention reports all flow through this single channel. Without an endpoint configured, every violation is silently discarded — you find out about CSP misconfigurations from user complaints instead of telemetry.",
            "Two header generations exist. The legacy Report-To header (JSON-formatted, with groups and endpoints) is being phased out. The modern Reporting-Endpoints header is simpler: a structured-fields list of named URLs, e.g. Reporting-Endpoints: csp-endpoint=\"https://example.com/csp\", coop-endpoint=\"https://example.com/coop\". Other policy headers reference an endpoint by name with report-to=\"csp-endpoint\". Browsers buffer reports and POST them as JSON to the endpoint, batched on a schedule.",
            "Setting up an endpoint is straightforward but operationally meaningful. The URL receives JSON POSTs and needs to handle bursts (a misconfigured CSP can generate thousands of reports per minute when first deployed). Common patterns are pointing at a SaaS reporting service (Report URI, Sentry's CSP reporting, etc.) or a small in-house collector that drops reports into your existing log pipeline. The endpoint should be on a domain that doesn't itself trigger the policy you're reporting on — otherwise you create a loop.",
            "Vendor Audit checks for either header. A passing site has at least one endpoint configured; a failing site has neither and is missing the visibility loop entirely. Note that having the endpoint header is just the plumbing — the policies (CSP, COOP, etc.) still need their own report-to= directives to actually emit reports through it.",
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

            # Reinforce the "IPv4 is the legacy protocol" framing on every
            # finding row whose display string leads with bare "IPv4 ".
            # The rubric's partial_label and score_label_display strings
            # (in scoring_rubric.json) carry phrasings like "IPv4 RPKI
            # not-found" or "IPv4 route registered in IRR" that we don't
            # rewrite at the rubric level (rubric is the system-of-record
            # for scoring keys; we don't modify it). Patch the displayed
            # text instead. Only triggers on the bare-leading form so we
            # don't double-label something that's already been qualified
            # (e.g. "IPv4 (legacy IP) prefix has no..." from
            # _failure_phrasing).
            if display and display.startswith("IPv4 ") and "IPv4 (legacy IP)" not in display:
                display = "IPv4 (legacy IP) " + display[len("IPv4 "):]

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
            "Authoritative delegation":  "At least one nameserver listed at the parent registry is lame \u2014 it does not answer authoritatively for this zone (RFC 1034)",
            "NS not open resolver":      "At least one authoritative nameserver also serves open recursion \u2014 abusable for DNS amplification attacks (RFC 5358 / BCP 140)",
            "MX target hygiene":         {
                "_default":     "MX target hygiene problem (RFC 2181 \u00a710.3)",
                "cname_target": "At least one MX target is a CNAME (RFC 2181 \u00a710.3 violation \u2014 some receivers may bounce)",
                "ip_literal":   "At least one MX target is an IP literal (RFC 5321 \u00a75.1 violation \u2014 MX RDATA must be a hostname)",
                "cname_and_ip": "MX targets include both an IP literal and a CNAME target (RFC 2181 \u00a710.3 / RFC 5321 \u00a75.1 violations)"
            },
            "IPv6":                    "IPv6 not configured",
            "IPv4 RPKI":               "IPv4 (legacy IP) prefix has no Route Origin Authorization (RPKI)",
            "IPv6 RPKI":               "IPv6 prefix has no Route Origin Authorization (RPKI)",
            "IPv4 IRR/RIS":            "IPv4 (legacy IP) route not registered in IRR / RIS",
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
            "www and apex unified":    {
                "_default":     "Apex and www variants are not unified",
                "split":        "Apex and www both serve content but neither redirects to the other (Mozilla deployment guidance: one canonical host)",
                "half_missing_apex": "Apex has no A/AAAA records \u2014 users typing the bare domain get a DNS error",
                "half_missing_www":  "www variant has no A/AAAA records \u2014 users typing www get a DNS error"
            },
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
            # RIPEstat lookup failures — emitted as 0/0 rows when the
            # prefix-overview call to RIPEstat returns an error or
            # times out, so the row appears in the executive summary
            # rather than silently disappearing. See score_results in
            # audit_checks for the emission point.
            "IPv4 RPKI":      "IPv4 (legacy IP) RPKI check could not run (RIPEstat lookup failed)",
            "IPv4 IRR/RIS":   "IPv4 (legacy IP) IRR/RIS check could not run (RIPEstat lookup failed)",
            "IPv6 RPKI":      "IPv6 RPKI check could not run (RIPEstat lookup failed)",
            "IPv6 IRR/RIS":   "IPv6 IRR/RIS check could not run (RIPEstat lookup failed)",
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
            # www/apex unification: outcome can be 'unified', 'split',
            # 'half_missing', or 'not_scored'. For half_missing we
            # synthesize a key like 'half_missing_apex' or
            # 'half_missing_www' from results['www_apex_unified'].missing_side
            # so the finding text can name the missing variant. Falls
            # back to _default if missing_side isn't set or the key
            # isn't present in the entry.
            if label == "www and apex unified":
                wau = self.results.get("www_apex_unified") or {}
                outcome = wau.get("outcome")
                if outcome == "half_missing":
                    side = wau.get("missing_side")
                    key = f"half_missing_{side}" if side else "half_missing"
                    if key in entry:
                        return entry[key]
                    if "half_missing" in entry:
                        return entry["half_missing"]
                elif outcome and outcome in entry:
                    return entry[outcome]
            # HSTS preloaded: two partial outcomes ('pending' and
            # 'preload_directive') need different finding text. The
            # scoring code maps preload_status=='pending' to outcome
            # 'pending' and (header has preload, no API confirmation)
            # to outcome 'preload_directive'. We re-derive the same
            # mapping here from the hsts result so the partial-label
            # text agrees with the score row.
            if label == "HSTS preloaded":
                hsts = self.results.get("hsts") or {}
                if hsts.get("preload_status") == "pending":
                    outcome = "pending"
                elif hsts.get("preload_directive"):
                    outcome = "preload_directive"
                else:
                    outcome = None
                if outcome and outcome in entry:
                    return entry[outcome]
            # MX target hygiene: outcome derived from which of
            # mx_targets_ip / mx_targets_cname is non-empty. Mirrors
            # the scoring code in _score_email_block.
            if label == "MX target hygiene":
                mx = self.results.get("mx") or {}
                has_cname = bool(mx.get("mx_targets_cname"))
                has_ip    = bool(mx.get("mx_targets_ip"))
                if has_cname and has_ip:
                    outcome = "cname_and_ip"
                elif has_cname:
                    outcome = "cname_target"
                elif has_ip:
                    outcome = "ip_literal"
                else:
                    outcome = None
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
    out.extend(_subheading_with_explanation(
        f"MX records — {domain_label} (RFC 5321, 7505)", "mx"))
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

            # MX target hygiene findings (RFC 2181 §10.3 / RFC 5321 §5.1)
            mx_targets_ip    = mx.get("mx_targets_ip") or []
            mx_targets_cname = mx.get("mx_targets_cname") or []
            if mx_targets_ip or mx_targets_cname:
                out.append("")
            for tgt in mx_targets_ip:
                out.append(_status("fail",
                    f"MX target is an IP literal: {tgt} \u2014 violates RFC 5321 \u00a75.1; "
                    f"sending MTAs may refuse or skip hostname-keyed checks"))
            for tgt in mx_targets_cname:
                out.append(_status("fail",
                    f"MX target is a CNAME: {tgt} \u2014 violates RFC 2181 \u00a710.3; "
                    f"some receivers may bounce"))
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
                            f"does not answer authoritatively for this zone (RFC 1034)"))
                    else:
                        parts.append(_status("fail",
                            f"{len(lame)} lame nameservers: {', '.join(lame)} \u2014 "
                            f"listed in delegation but do not answer authoritatively (RFC 1034)"))
                else:
                    parts.append(_status("pass",
                        "All authoritative nameservers respond authoritatively"))

                opens = ns_health.get("open_resolver_ns") or []
                if opens:
                    if len(opens) == 1:
                        parts.append(_status("fail",
                            f"Open recursive resolver: {opens[0]} \u2014 answers "
                            f"recursion for arbitrary clients; abusable for DNS "
                            f"amplification attacks (RFC 5358 / BCP 140)"))
                    else:
                        parts.append(_status("fail",
                            f"{len(opens)} open recursive resolvers: {', '.join(opens)} \u2014 "
                            f"abusable for DNS amplification attacks (RFC 5358 / BCP 140)"))
                else:
                    parts.append(_status("pass",
                        "Nameservers do not serve open recursion"))

                unprobed = ns_health.get("unprobed") or []
                for ns_host, reason in unprobed:
                    parts.append(_status("info",
                        f"Could not probe {ns_host}: {reason}"))

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

        # Display label for messages — "IPv4 (legacy IP)" for v4 to
        # reinforce the messaging that IPv4 is the deprecated protocol;
        # plain "IPv6" for v6.
        af_display = "IPv4 (legacy IP)" if af_label == "IPv4" else af_label

        sub = [_subheading(_AF_LABEL_WITH_RFC.get(af_label, af_label)), ""]

        if not addr and af_err:
            sev = "warn" if (af_label == "IPv6" and "no AAAA" in (af_err or "")) else "info"
            sub.append(_status(sev, f"{af_display} — {af_err}"))
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

    # ── www and apex unified (1.1) ───────────────────────────────────────────
    wau = r.get("www_apex_unified", {}) or {}
    wau_outcome = wau.get("outcome")
    if wau_outcome == "unified":
        apex_h = wau.get("apex_host", "")
        www_h  = wau.get("www_host", "")
        parts.append(_status("pass",
            f"Apex and www unified ({apex_h} \u2194 {www_h})"))
    elif wau_outcome == "split":
        apex_h = wau.get("apex_host", "")
        www_h  = wau.get("www_host", "")
        parts.append(_status("fail",
            f"Apex and www serve separate pages \u2014 neither {apex_h} nor {www_h} "
            f"redirects to the other"))
    elif wau_outcome == "half_missing":
        missing = wau.get("missing_side")
        if missing == "apex":
            apex_h = wau.get("apex_host", "")
            www_h  = wau.get("www_host", "")
            parts.append(_status("fail",
                f"Apex {apex_h} has no A/AAAA records \u2014 users typing the bare "
                f"domain get a DNS error (web/TLS audited at {www_h} via fallback)"))
        else:  # "www"
            apex_h = wau.get("apex_host", "")
            www_h  = wau.get("www_host", "")
            parts.append(_status("fail",
                f"www variant {www_h} has no A/AAAA records \u2014 users typing the "
                f"www form get a DNS error"))
    # wau_outcome == "not_scored" or missing: no row emitted

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
    elif hsts.get("preload_status") == "pending":
        # Submitted to hstspreload.org AND accepted, waiting for next Chrome
        # rollup. Distinct from the bare preload-directive case below.
        parts.append(_status("warn",
            "HSTS preload submission pending \u2014 accepted by hstspreload.org, "
            "waiting for the next Chrome release rollup (typically 2\u20133 months)"))
    elif hsts.get("present") and hsts.get("preload_directive"):
        parts.append(_status("warn",
            "preload directive present in header but domain not submitted to "
            "hstspreload.org"))
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
