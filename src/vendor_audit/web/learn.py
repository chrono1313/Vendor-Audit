"""Explainer pages: /learn/ and /learn/<page>.

One page per topic (SPF, DMARC, HSTS, …), built from text the audit
already has, so the pages can't drift from what the audit checks and says:

  - the topic explanation behind the report's "What this means" section
    (audit_txt_report.EXPLANATIONS: what, why, fix, details)
  - every check in that topic, in rubric order (audit_records.topic_for),
    with its what / why / fix (audit_records._CHECK_TEXT), the standard it
    cites (audit_records._STANDARD, linked), and every result it can give
    with its rating and the exact wording the report uses (rubric.json)

Nothing on these pages runs an audit, so they are safe for search engines
to crawl (robots.txt only closes /audit). Pages are built once and kept.

PAGES below holds only what isn't in the audit's data: the page's address,
its title and description for search results, and its group on /learn/.
A test checks that every rated check appears on exactly one page.
"""

import json
import os
import re
from functools import lru_cache
from pathlib import Path

from markupsafe import Markup, escape

from .. import audit_checks, audit_records, audit_txt_report

SITE = os.environ.get("VENDOR_AUDIT_SERVICE_URL", "https://vendoraudit.org").rstrip("/")

GROUPS = ["Email", "DNS", "TLS", "HTTP", "Website", "Routing", "End of life"]

# slug → page. "topics" are audit topic keys (audit_records.topic_for);
# by default the one named like the slug.
PAGES = {
    # ── Email ──
    "spf": {
        "group": "Email", "name": "SPF",
        "title": "SPF records: how they work, the 10-lookup limit, and how to fix them",
        "h1": "SPF (Sender Policy Framework)",
        "description": ("How SPF records work, ~all versus -all, the 10 DNS lookup limit, and the SPF checks "
                        "Vendor Audit runs, each with the RFC behind it and how to fix what fails."),
        "related": ["dmarc", "dkim", "mx"],
    },
    "dmarc": {
        "group": "Email", "name": "DMARC",
        "title": "DMARC: moving from p=none to p=reject, sp=, pct= and reports",
        "h1": "DMARC (Domain-based Message Authentication, Reporting and Conformance)",
        "description": ("How DMARC uses SPF and DKIM to stop spoofed mail, how to move from p=none to p=reject, "
                        "subdomain policy and reporting, and the DMARC checks Vendor Audit runs."),
        "related": ["spf", "dkim", "bimi"],
    },
    "dkim": {
        "group": "Email", "name": "DKIM",
        "title": "DKIM: selectors, key length, and why signatures survive forwarding",
        "h1": "DKIM (DomainKeys Identified Mail)",
        "description": ("How DKIM signs outgoing mail, how selectors work, why keys should be 2048 bits, and the "
                        "DKIM checks Vendor Audit runs, with the standard behind each."),
        "related": ["spf", "dmarc"],
    },
    "mta-sts": {
        "group": "Email", "name": "MTA-STS", "topics": ["mta_sts"],
        "title": "MTA-STS: making TLS mandatory for mail to your domain",
        "h1": "MTA-STS (SMTP MTA Strict Transport Security)",
        "description": ("How MTA-STS stops STARTTLS downgrade attacks, how to publish the DNS record and policy "
                        "file, testing versus enforce mode, and the MTA-STS checks Vendor Audit runs."),
        "related": ["tls-rpt", "starttls-dane", "mx"],
    },
    "tls-rpt": {
        "group": "Email", "name": "TLS-RPT", "topics": ["tls_rpt"],
        "title": "TLS-RPT: reports of failed TLS when mail is sent to you",
        "h1": "TLS-RPT (SMTP TLS Reporting)",
        "description": ("How SMTP TLS Reporting tells you when mail to your domain failed TLS or MTA-STS, how to "
                        "publish the _smtp._tls record, and what Vendor Audit checks."),
        "related": ["mta-sts", "starttls-dane"],
    },
    "starttls-dane": {
        "group": "Email", "name": "STARTTLS and DANE", "topics": ["mail_transport"],
        "title": "STARTTLS and DANE: encrypting mail between servers",
        "h1": "Mail transport security: STARTTLS and DANE",
        "description": ("Why STARTTLS on its own can be stripped, how DANE TLSA records and MTA-STS make TLS "
                        "mandatory for mail, and the mail transport checks Vendor Audit runs."),
        "related": ["mta-sts", "tls-rpt", "dnssec"],
    },
    "mx": {
        "group": "Email", "name": "MX records",
        "title": "MX records: null MX, reverse DNS, and hostname targets",
        "h1": "MX records",
        "description": ("How MX records route mail, null MX for domains that take no mail, why MX targets must "
                        "be hostnames and not CNAMEs, reverse DNS, and the MX checks Vendor Audit runs."),
        "related": ["spf", "starttls-dane", "mta-sts"],
    },
    "bimi": {
        "group": "Email", "name": "BIMI",
        "title": "BIMI: brand logos in the inbox, and why DMARC comes first",
        "h1": "BIMI (Brand Indicators for Message Identification)",
        "description": ("How BIMI shows your logo beside authenticated mail, why it needs DMARC at quarantine or "
                        "reject, mark certificates, and what Vendor Audit checks."),
        "related": ["dmarc"],
    },
    # ── DNS ──
    "dnssec": {
        "group": "DNS", "name": "DNSSEC",
        "title": "DNSSEC: the chain of trust, DS records, and algorithms",
        "h1": "DNSSEC (DNS Security Extensions)",
        "description": ("How DNSSEC's chain of trust works, what goes wrong with DS records, which signing "
                        "algorithms and DS digests to use, and the DNSSEC checks Vendor Audit runs."),
        "related": ["nameservers", "starttls-dane", "caa"],
    },
    "nameservers": {
        "group": "DNS", "name": "Nameservers",
        "title": "Nameservers: redundancy, lame delegation, open resolvers and SOA",
        "h1": "Nameservers",
        "description": ("Why a domain needs more than one authoritative nameserver, lame delegations, open "
                        "resolvers, matching NS records at the registry, SOA serials and timers, and network spread."),
        "related": ["dnssec", "rpki", "ipv6"],
    },
    "caa": {
        "group": "DNS", "name": "CAA",
        "title": "CAA records: limiting which CAs can issue your certificates",
        "h1": "CAA (Certification Authority Authorization)",
        "description": ("How CAA records restrict certificate issuance to the CAs you use, the issue and "
                        "issuewild tags, binding issuance to an ACME account, and what Vendor Audit checks."),
        "related": ["tls", "dnssec"],
    },
    "dangling-dns": {
        "group": "DNS", "name": "Dangling DNS", "topics": ["dangling_dns"],
        "title": "Dangling CNAME records and subdomain takeover",
        "h1": "Dangling DNS records",
        "description": ("How a CNAME left pointing at a deleted cloud resource lets someone else take over the "
                        "subdomain, how to find and fix it, and what Vendor Audit checks."),
        "related": ["nameservers", "tls"],
    },
    # ── TLS ──
    "tls": {
        "group": "TLS", "name": "TLS and certificates",
        "title": "TLS and certificates: TLS 1.3, forward secrecy, keys and lifetimes",
        "h1": "TLS and certificates",
        "description": ("TLS versions, forward secrecy, certificate name match, key size, signature, chain and "
                        "the shrinking maximum certificate lifetime, and the TLS checks Vendor Audit runs."),
        "related": ["hsts", "caa", "https-redirect"],
    },
    "hsts": {
        "group": "TLS", "name": "HSTS",
        "title": "HSTS: max-age, includeSubDomains, and the preload list",
        "h1": "HSTS (HTTP Strict Transport Security)",
        "description": ("How HSTS stops SSL stripping, what max-age and includeSubDomains should be, what to do "
                        "before preloading, and the HSTS checks Vendor Audit runs."),
        "related": ["https-redirect", "tls", "cookies"],
    },
    # ── HTTP ──
    "https-redirect": {
        "group": "HTTP", "name": "HTTP to HTTPS redirect", "topics": ["http_redirect"],
        "title": "Redirecting HTTP to HTTPS the right way",
        "h1": "HTTP to HTTPS redirect",
        "description": ("Why every http:// request should get a 301 to https:// on the same host, what happens "
                        "without it, and what Vendor Audit checks."),
        "related": ["www-and-apex", "hsts"],
    },
    "www-and-apex": {
        "group": "HTTP", "name": "www and apex", "topics": ["http"],
        "title": "www and apex: one canonical site, and the first redirect",
        "h1": "www, apex and the first redirect",
        "description": ("Why the bare domain and www should both resolve and lead to one site, MDN's guidance on "
                        "a canonical hostname, first-hop redirect hygiene, and the checks Vendor Audit runs."),
        "related": ["https-redirect", "hsts", "tls"],
    },
    "http-versions": {
        "group": "HTTP", "name": "HTTP/2 and HTTP/3", "topics": ["http_version"],
        "title": "HTTP/2, HTTP/3, request smuggling, and the HTTPS DNS record",
        "h1": "HTTP versions",
        "description": ("Why HTTP/1.1 invites request smuggling, how to enable HTTP/2 and HTTP/3, the HTTPS DNS "
                        "record (RFC 9460), and what Vendor Audit checks."),
        "related": ["tls", "www-and-apex"],
    },
    # ── Website ──
    "security-headers": {
        "group": "Website", "name": "Security headers", "topics": ["security_headers"],
        "title": "Browser security headers: framing, nosniff, Referrer-Policy and more",
        "h1": "Browser security headers",
        "description": ("Clickjacking protection, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, "
                        "COOP and CORP, which old headers to remove, and the header checks Vendor Audit runs."),
        "related": ["csp", "cookies", "hsts"],
    },
    "csp": {
        "group": "Website", "name": "Content Security Policy",
        "title": "Content Security Policy: script-src, object-src and base-uri",
        "h1": "Content Security Policy (CSP)",
        "description": ("How CSP limits the damage of cross-site scripting, what makes script-src safe, why "
                        "object-src and base-uri matter, how to roll a policy out, and the CSP checks."),
        "related": ["security-headers", "page-content"],
    },
    "cookies": {
        "group": "Website", "name": "Cookies",
        "title": "Cookie security: Secure, HttpOnly, SameSite and __Host- prefixes",
        "h1": "Cookie security",
        "description": ("What the Secure, HttpOnly and SameSite cookie attributes protect against, the __Host- "
                        "and __Secure- name prefixes, and the cookie checks Vendor Audit runs."),
        "related": ["hsts", "security-headers"],
    },
    "server-headers": {
        "group": "Website", "name": "Server headers", "topics": ["server_disclosure"],
        "title": "Server and X-Powered-By headers: version disclosure and clocks",
        "h1": "Server disclosure",
        "description": ("Why Server and X-Powered-By headers that name exact versions help attackers, how to "
                        "hide them, why the server's clock matters, and the checks Vendor Audit runs."),
        "related": ["error-pages", "end-of-life"],
    },
    "error-pages": {
        "group": "Website", "name": "Error pages", "topics": ["error_page"],
        "title": "Default error pages and server version disclosure",
        "h1": "Default error pages",
        "description": ("How the default 404 and 500 pages from Apache, nginx, IIS and Tomcat reveal the server "
                        "and its version, how to replace them, and what Vendor Audit checks."),
        "related": ["server-headers", "end-of-life"],
    },
    "cors": {
        "group": "Website", "name": "CORS",
        "title": "CORS misconfigurations: wildcards, null, and reflected origins",
        "h1": "CORS (Cross-Origin Resource Sharing)",
        "description": ("How CORS relaxes the same-origin policy, the dangerous patterns (wildcard with "
                        "credentials, null, reflected origins, broad wildcards), and what Vendor Audit checks."),
        "related": ["cookies", "security-headers"],
    },
    "security-txt": {
        "group": "Website", "name": "security.txt", "topics": ["security_txt"],
        "title": "security.txt: telling researchers how to report vulnerabilities",
        "h1": "security.txt (RFC 9116)",
        "description": ("What goes in a security.txt file, where to publish it, the Contact, Expires and "
                        "Canonical fields, and the security.txt checks Vendor Audit runs."),
        "related": ["security-headers"],
    },
    "page-content": {
        "group": "Website", "name": "Page content", "topics": ["page_analysis"],
        "title": "Subresource Integrity, mixed content, and page language",
        "h1": "Page content checks",
        "description": ("Why third-party scripts need Subresource Integrity, how mixed content undermines HTTPS, "
                        "declaring the page language, and the page checks a deep scan runs."),
        "related": ["csp", "end-of-life"],
    },
    # ── Routing ──
    "rpki": {
        "group": "Routing", "name": "RPKI",
        "title": "RPKI and ROAs: protecting your IP prefixes from BGP hijacks",
        "h1": "RPKI (Resource Public Key Infrastructure)",
        "description": ("How Route Origin Authorizations stop BGP origin hijacks, the valid, not-found and "
                        "invalid states, and the RPKI checks for the website, nameservers and mail servers."),
        "related": ["bgp-routing", "ipv6", "nameservers"],
    },
    "bgp-routing": {
        "group": "Routing", "name": "BGP routing", "topics": ["routing"],
        "title": "BGP routing visibility for your site's addresses",
        "h1": "BGP routing visibility",
        "description": ("Whether the global routing table shows your site's IPv4 and IPv6 prefixes announced by "
                        "their own network, as RIPE's route collectors see it, and what Vendor Audit checks."),
        "related": ["rpki", "ipv6"],
    },
    "ipv6": {
        "group": "Routing", "name": "IPv6",
        "title": "IPv6: AAAA records for the website, nameservers and mail servers",
        "h1": "IPv6",
        "description": ("Why IPv4-only sites are slower and less reliable for IPv6-first users, how to add AAAA "
                        "records, and the IPv6 checks for the website, nameservers and mail servers."),
        "related": ["rpki", "bgp-routing", "nameservers"],
    },
    # ── End of life ──
    "end-of-life": {
        "group": "End of life", "name": "End-of-life software",
        "topics": ["eol_tech", "eol_os", "eol_mail", "eol_dns", "eol_libraries"],
        "title": "End-of-life software: servers, operating systems, and libraries",
        "h1": "End-of-life software",
        "description": ("How Vendor Audit spots unsupported operating systems, web servers, applications, mail "
                        "and DNS servers and JavaScript libraries from what servers volunteer, and what to do."),
        "related": ["server-headers", "error-pages", "page-content"],
    },
}

_SEVERITY_ORDER = ["pass", "critical", "high", "medium", "low", "info"]
_SEVERITY_LABEL = {"pass": "PASS", "critical": "Critical", "high": "High", "medium": "Medium",
                   "low": "Low", "info": "Info"}

# Standards that aren't RFCs, by the name the report cites them under.
_STANDARD_URLS = {
    "M3AAWG": "https://www.m3aawg.org/published-documents",
    "MDN": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Choosing_between_www_and_non-www_URLs",
    "hstspreload.org": "https://hstspreload.org/",
    "IANA name server requirements": "https://www.iana.org/help/nameserver-requirements",
    "CA/B Forum BR": "https://cabforum.org/working-groups/server/baseline-requirements/",
    "BIMI Group draft": "https://bimigroup.org/",
    "CSP Level 3": "https://www.w3.org/TR/CSP3/",
    "OWASP Secure Headers": "https://owasp.org/www-project-secure-headers/",
    "OWASP WSTG-CONF-10": "https://owasp.org/www-project-web-security-testing-guide/",
    "OWASP WSTG": "https://owasp.org/www-project-web-security-testing-guide/",
    "SSL Labs": "https://www.ssllabs.com/",
    "W3C Mixed Content": "https://www.w3.org/TR/mixed-content/",
    "W3C Permissions Policy": "https://www.w3.org/TR/permissions-policy/",
    "W3C Referrer Policy": "https://www.w3.org/TR/referrer-policy/",
    "W3C SRI": "https://www.w3.org/TR/SRI/",
    "WCAG 2.1 SC 3.1.1": "https://www.w3.org/TR/WCAG21/#language-of-page",
    "WHATWG Fetch": "https://fetch.spec.whatwg.org/",
    "WHATWG HTML": "https://html.spec.whatwg.org/",
    "RFC 6265bis": "https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/",
}

_RFC_RE = re.compile(r"RFC (\d{3,5})(?!\d|bis)((?: §[\d.]+)?)")


def standard_html(text):
    """The cited standard, with each RFC (and its first § if given) and
    each known non-RFC standard linked."""
    if not text:
        return Markup("")
    out, pos = [], 0
    for m in _RFC_RE.finditer(text):
        out.append(_link_names(text[pos:m.start()]))
        section = m.group(2).strip(" §")
        url = f"https://www.rfc-editor.org/rfc/rfc{m.group(1)}.html" + (f"#section-{section}" if section else "")
        out.append(Markup('<a href="{}">{}</a>').format(url, m.group(0)))
        pos = m.end()
    out.append(_link_names(text[pos:]))
    return Markup("").join(out)


def _link_names(text):
    html = str(escape(text))
    for name, url in sorted(_STANDARD_URLS.items(), key=lambda kv: -len(kv[0])):
        n = str(escape(name))
        m = re.search(rf"(?<![\w/>]){re.escape(n)}(?![\w<])", html)
        if m:
            html = html[:m.start()] + str(Markup('<a href="{}">{}</a>').format(url, name)) + html[m.end():]
    return Markup(html)


# Record syntax in running text, shown as code. Matched on the escaped text;
# none of these patterns contain characters that escaping changes.
_CODE_RE = re.compile(
    r"(v=spf1(?: -all)?|v=DMARC1(?:; p=reject)?|v=STSv1|v=TLSRPTv1|v=BIMI1|(?<![\w-])[-~?+]all\b"
    r"|\b(?:include|ip4|ip6|a|mx|ptr|exists):|\bredirect=|\b(?:p|sp|pct|rua|ruf|adkim|aspf)=(?:none|quarantine|reject|\d+)?"
    r"|\bmode=(?:none|testing|enforce)|\bmax-age=\d*|\b0 \.(?=\s|\)|$)"
    r"|_dmarc\.&lt;domain&gt;|&lt;selector&gt;\._domainkey\.&lt;domain&gt;|_mta-sts\.&lt;domain&gt;"
    r"|_smtp\._tls\.&lt;domain&gt;|default\._bimi\.&lt;domain&gt;|/\.well-known/[\w.-]*\w)")


def codeify(text):
    """Escape text and set record syntax in <code>."""
    html = _CODE_RE.sub(lambda m: f"<code>{m.group(0)}</code>", str(escape(text)))
    # A quoted record ("v=spf1 -all") needs no quotes once it is code.
    return Markup(re.sub(r"&#34;(<code>[^<]*</code>)&#34;", r"\1", html))


def _results(label):
    seen = []
    for severity, text in audit_checks.RUBRIC["findings"][label].values():
        if (severity, text) not in seen:
            seen.append((severity, text))
    seen.sort(key=lambda r: _SEVERITY_ORDER.index(r[0]))
    return [{"severity": s, "label": _SEVERITY_LABEL[s], "text": t} for s, t in seen]


def _topics(slug):
    return PAGES[slug].get("topics") or [slug]


def checks_by_page():
    """{slug: [check label, …]} in rubric order."""
    labels = [label for checks in audit_checks.RUBRIC["categories"].values() for label in checks]
    return {slug: [lb for lb in labels if audit_records.topic_for(lb) in _topics(slug)] for slug in PAGES}


@lru_cache(maxsize=None)
def _topic_index():
    return {topic: slug for slug in PAGES for topic in _topics(slug)}


def url_for_check(label):
    """The address of a check's section on its explainer page, or None."""
    slug = _topic_index().get(audit_records.topic_for(label))
    return f"{SITE}/learn/{slug}#{audit_records.slug(label)}" if slug else None


def url_for_topic(topic):
    slug = _topic_index().get(topic)
    return f"{SITE}/learn/{slug}" if slug else None


def _check(label):
    what, why, fix = audit_records._CHECK_TEXT.get(label, (None, None, None))
    return {"name": label, "anchor": audit_records.slug(label),
            "standard": standard_html(audit_records._STANDARD.get(label)),
            "what": codeify(what) if what else None, "why": codeify(why) if why else None,
            "fix": codeify(fix) if fix else None, "results": _results(label)}


def _product_lists():
    """For the end-of-life page: what the audit can recognise and judge."""
    here = Path(audit_checks.__file__).parent

    def names(fname):
        data = json.loads((here / fname).read_text(encoding="utf-8"))
        return sorted({v.get("name", k) for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)},
                      key=str.lower)
    return [("Server software and applications", names("tech_eol.json")),
            ("Operating systems (and IIS, whose version identifies its Windows release)", names("os_eol.json")),
            ("JavaScript libraries and CMSes", names("library_eol.json"))]


@lru_cache(maxsize=None)
def page(slug):
    """Everything learn_topic.html needs, or None."""
    meta = PAGES.get(slug)
    if meta is None:
        return None
    topics = [t for t in _topics(slug) if t in audit_txt_report.EXPLANATIONS]
    if not topics:
        return None
    first = audit_txt_report.EXPLANATIONS[topics[0]]
    details, fixes = [], []
    for t in topics:
        e = audit_txt_report.EXPLANATIONS[t]
        if len(topics) > 1:                       # one heading per part
            details.append((audit_records.TOPIC_TITLES.get(t, t), codeify(f"{e['what']} {e['why']}")))
            fixes.append((audit_records.TOPIC_TITLES.get(t, t), [codeify(x) for x in e["fix"].split("\n")]))
        else:
            fixes.append((None, [codeify(x) for x in e["fix"].split("\n")]))
        for d in e.get("details") or []:
            if isinstance(d, tuple):
                details.append((d[0].rstrip("."), codeify(d[1])))
            else:
                details.append((None, codeify(d)))
    return {
        "slug": slug,
        "url": f"{SITE}/learn/{slug}",
        "meta": meta,
        "multi": len(topics) > 1,
        "what": codeify(first["what"]),
        "why": codeify(first["why"]),
        "fixes": fixes,
        "details": details,
        "checks": [_check(lb) for lb in checks_by_page()[slug]],
        "lists": _product_lists() if slug == "end-of-life" else [],
        "related": [(s, PAGES[s]["name"]) for s in meta["related"] if s in PAGES],
    }


@lru_cache(maxsize=None)
def index():
    """The /learn/ page: every page, by group."""
    groups = []
    for g in GROUPS:
        items = [(slug, m["name"], m["description"], len(checks_by_page()[slug]))
                 for slug, m in PAGES.items() if m["group"] == g]
        groups.append((g, items))
    return {"url": f"{SITE}/learn/", "groups": groups}


def sitemap_xml():
    """sitemap.xml: the front page, every explainer page and the example
    report (web/example.py). /audit pages
    stay out: they run audits and robots.txt closes them."""
    urls = ([f"{SITE}/", f"{SITE}/learn/", f"{SITE}/learn/example-report"]
            + [f"{SITE}/learn/{slug}" for slug in PAGES])
    rows = "".join(f"<url><loc>{u}</loc></url>" for u in urls)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{rows}</urlset>\n')
