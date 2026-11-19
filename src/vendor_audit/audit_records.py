"""vendor_audit.audit_records — one structured record per check.

A record is everything a report needs to show one check:

    id         stable slug, used as the anchor ("dmarc-policy")
    label      the check's name in rubric.json
    title      the finding sentence
    severity   critical | high | medium | low | info | pass
    category   Email | DNS | Routing | TLS | HTTP | Website
    outcome    the outcome code the check resolved to
    standard   the document the practice comes from ("RFC 7489")
    topic      key into audit_txt_report.EXPLANATIONS
    what, why, fix   one sentence each, from EXPLANATIONS
    evidence   what was observed, as a list of items:
                 ("kv",   [(name, value), ...])
                 ("code", caption, text)
                 ("list", caption, [text, ...])
                 ("note", text)

Records are built from the findings (audit_checks.assess_results) and the
raw results dict. Nothing here decides a severity or runs a check; it only
gathers what the checks already found into one shape, so a renderer never
has to parse another renderer's output.

The evidence builders read the results dict defensively. A builder that
meets an unexpected shape yields no evidence rather than an error.
"""
from __future__ import annotations

import re

from . import audit_txt_report as _t

SEVERITY_ORDER = _t.SEVERITY_ORDER
ISSUE_SEVERITIES = _t.ISSUE_SEVERITIES

_REDIRECT_PREFIX = "redirect target: "


# ── Label → explanation topic ────────────────────────────────────────────────

_TOPIC = {
    "SPF policy": "spf", "SPF lookup count": "spf",
    "DMARC policy": "dmarc", "DMARC sp": "dmarc", "DMARC pct": "dmarc",
    "DMARC rua reporting": "dmarc",
    "MX target hygiene": "mx",
    "MTA-STS": "mta_sts", "TLS-RPT": "tls_rpt",
    "DANE TLSA on MX": "mail_transport", "STARTTLS-MX": "mail_transport",
    "DKIM (common selectors)": "dkim", "DKIM key strength": "dkim",
    "BIMI": "bimi",
    "DNSSEC": "dnssec", "DNSSEC TLD signed": "dnssec",
    "CAA records": "caa",
    "Nameserver count": "nameservers", "Authoritative delegation": "nameservers",
    "NS not open resolver": "nameservers",
    "IPv6": "ipv6",
    "IPv4 RPKI": "rpki", "IPv6 RPKI": "rpki",
    "IPv4 IRR/RIS": "routing", "IPv6 IRR/RIS": "routing",
    "TLS connection": "tls", "TLS 1.3": "tls", "Certificate lifetime": "tls",
    "Certificate renewal": "tls", "Certificate name match": "tls",
    "Cert covers www variant": "tls", "Cert chain completeness": "tls",
    "SSL Labs grade": "tls",
    "HSTS": "hsts", "HSTS preload": "hsts",
    "HTTP version": "http_version", "HTTP→HTTPS redirect": "http_redirect",
    "Redirect first-hop hygiene": "http", "www and apex unified": "http",
    "Server header": "server_disclosure", "X-Powered-By absent": "server_disclosure",
    "Server clock accuracy": "server_disclosure",
    "Clickjacking protection": "security_headers",
    "X-Content-Type-Options": "security_headers", "Referrer-Policy": "security_headers",
    "Permissions-Policy": "security_headers",
    "Cross-Origin-Opener-Policy": "security_headers",
    "Cross-Origin-Resource-Policy": "security_headers",
    "X-XSS-Protection deprecated": "security_headers",
    "CSP script-src safety": "csp",
    "Cookie Secure": "cookies", "Cookie HttpOnly": "cookies",
    "Cookie SameSite": "cookies", "Cookie name prefixes": "cookies",
    "security.txt": "security_txt",
    "Default error page": "error_page",
    "CORS configuration": "cors",
    "Subresource Integrity": "page_analysis", "Mixed content (in-page)": "page_analysis",
}

# Short display names for topics, used to title the background reading.
TOPIC_TITLES = {
    "spf": "SPF", "dmarc": "DMARC", "dkim": "DKIM", "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT", "bimi": "BIMI", "mx": "MX records",
    "mail_transport": "Mail transport security", "dnssec": "DNSSEC", "caa": "CAA",
    "nameservers": "Nameservers", "tls": "TLS and certificates", "hsts": "HSTS",
    "http_redirect": "HTTP to HTTPS redirect", "http": "HTTP transport",
    "http_version": "HTTP versions", "server_disclosure": "Server disclosure",
    "csp": "Content Security Policy", "security_headers": "Browser security headers",
    "cookies": "Cookies", "security_txt": "security.txt",
    "eol_os": "End-of-life operating systems", "eol_libraries": "End-of-life libraries",
    "eol_tech": "End-of-life server software", "error_page": "Default error pages",
    "cors": "CORS", "rpki": "RPKI", "routing": "Routing", "ipv6": "IPv6",
    "page_analysis": "Page analysis",
}


# ── Label → standard ─────────────────────────────────────────────────────────

_STANDARD = {
    "SPF policy": "RFC 7208", "SPF lookup count": "RFC 7208 §4.6.4",
    "DMARC policy": "RFC 7489", "DMARC sp": "RFC 7489", "DMARC pct": "RFC 7489",
    "DMARC rua reporting": "RFC 7489",
    "MX target hygiene": "RFC 2181 §10.3",
    "MTA-STS": "RFC 8461", "TLS-RPT": "RFC 8460",
    "DANE TLSA on MX": "RFC 7672", "STARTTLS-MX": "RFC 3207",
    "DKIM (common selectors)": "RFC 6376", "DKIM key strength": "RFC 8301",
    "BIMI": "BIMI Group draft",
    "DNSSEC": "RFC 4033", "DNSSEC TLD signed": "RFC 4033",
    "CAA records": "RFC 8659",
    "Nameserver count": "RFC 2182", "Authoritative delegation": "RFC 1034",
    "NS not open resolver": "RFC 5358",
    "IPv6": "RFC 8200",
    "IPv4 RPKI": "RFC 6480", "IPv6 RPKI": "RFC 6480",
    "IPv4 IRR/RIS": "RFC 7454", "IPv6 IRR/RIS": "RFC 7454",
    "TLS connection": "RFC 8446", "TLS 1.3": "RFC 8446",
    "Certificate lifetime": "CA/B Forum BR", "Certificate renewal": "CA/B Forum BR",
    "Certificate name match": "RFC 9110 §4.3", "Cert covers www variant": "RFC 9110 §4.3",
    "Cert chain completeness": "RFC 8446 §4.4.2", "SSL Labs grade": "SSL Labs",
    "HSTS": "RFC 6797", "HSTS preload": "hstspreload.org",
    "HTTP version": "RFC 9113, 9114", "HTTP→HTTPS redirect": "RFC 6797 §7.2",
    "Redirect first-hop hygiene": "RFC 6797", "www and apex unified": "Common practice",
    "Server header": "RFC 9110 §10.2.4", "X-Powered-By absent": "OWASP Secure Headers",
    "Server clock accuracy": "RFC 9110 §6.6.1",
    "Clickjacking protection": "CSP Level 3", "X-Content-Type-Options": "WHATWG Fetch",
    "Referrer-Policy": "W3C Referrer Policy", "Permissions-Policy": "W3C Permissions Policy",
    "Cross-Origin-Opener-Policy": "WHATWG HTML", "Cross-Origin-Resource-Policy": "WHATWG Fetch",
    "X-XSS-Protection deprecated": "OWASP Secure Headers",
    "CSP script-src safety": "CSP Level 3",
    "Cookie Secure": "RFC 6265", "Cookie HttpOnly": "RFC 6265",
    "Cookie SameSite": "RFC 6265bis", "Cookie name prefixes": "RFC 6265bis",
    "security.txt": "RFC 9116",
    "Default error page": "OWASP WSTG",
    "CORS configuration": "WHATWG Fetch",
    "Subresource Integrity": "W3C SRI", "Mixed content (in-page)": "W3C Mixed Content",
}


# ── Per-check explanation ────────────────────────────────────────────────────
# EXPLANATIONS is written per topic, and a topic often spans several checks
# ("TLS" covers protocol versions and five certificate checks). Where the
# topic text would not describe a check, the check gets its own three
# sentences here: what it is, why it matters, how to fix it.

_CHECK_TEXT = {
    "SPF lookup count": (
        "Evaluating an SPF record may trigger at most 10 DNS lookups.",
        "Past that limit receivers return a permanent error and treat the record as broken.",
        "Remove include: entries that are no longer used, or replace them with IP ranges."),
    "MX target hygiene": (
        "An MX record must point to a host name that has its own address records, not to an IP address or a CNAME.",
        "Mail servers handle the invalid forms differently, so some mail is delayed or bounced.",
        "Point each MX record at a host name with its own A or AAAA record."),
    "DANE TLSA on MX": (
        "DANE publishes the mail server's certificate fingerprint in DNSSEC-signed TLSA records.",
        "It lets a sending server verify the receiving server's certificate and refuse to fall back to plain text.",
        "Sign the zone with DNSSEC, then publish a TLSA record for each MX host. MTA-STS covers the same risk without DNSSEC."),
    "STARTTLS-MX": (
        "STARTTLS upgrades an SMTP connection between mail servers to TLS.",
        "Mail delivered to a server without it travels in plain text.",
        "Enable STARTTLS with TLS 1.2 or later on every MX host."),
    "DKIM key strength": (
        "A DKIM signing key should be RSA of at least 2048 bits, or Ed25519.",
        "A shorter RSA key can be factored, which lets someone else sign mail as the domain.",
        "Generate a 2048-bit key under a new selector, switch signing to it, then retire the old selector."),
    "IPv4 IRR/RIS": (
        "The address prefix the site sits in should be visible in the global routing table.",
        "A prefix that route collectors do not see may be unreachable from parts of the internet.",
        "Ask the hosting or network provider to confirm the prefix is announced and registered."),
    "Certificate lifetime": (
        "How long the site's TLS certificate is valid, from issue to expiry.",
        "A long-lived certificate usually means renewal is done by hand, and a stolen key stays useful for longer. "
        "The CA/Browser Forum is lowering the maximum lifetime in steps, to 47 days by 2029.",
        "Issue certificates through an automated client (ACME) with a lifetime of 90 days or less."),
    "Certificate renewal": (
        "How much of the certificate's lifetime is left.",
        "Automated renewal replaces a certificate well before it expires. One that is nearly spent suggests "
        "renewal is manual or has failed, and browsers block a site whose certificate has expired.",
        "Renew the certificate now, then automate renewal so it happens well before expiry."),
    "Certificate name match": (
        "The certificate must list the name the visitor asked for.",
        "When it does not, browsers show a full-page warning instead of the site.",
        "Reissue the certificate with every name the site answers on."),
    "Cert covers www variant": (
        "The certificate should cover both the bare domain and its www form.",
        "A visitor who types the form that is not covered gets a certificate warning before any redirect can happen.",
        "Reissue the certificate with both names."),
    "Cert chain completeness": (
        "The server should send its certificate together with the intermediate certificates that link it to a trusted root.",
        "Some clients cannot fetch a missing intermediate and fail the connection, even where browsers recover.",
        "Install the full chain file from the certificate authority, not only the site's own certificate."),
    "SSL Labs grade": (
        "Qualys SSL Labs grades a server's TLS setup from A+ to F.",
        "The grade reflects protocol versions, cipher suites and known weaknesses that this audit does not test one by one.",
        "Open the SSL Labs report and work through the items it lists, starting with anything that caps the grade."),
    "Redirect first-hop hygiene": (
        "The first redirect from http:// should go to https:// on the same host.",
        "A first hop to a different host skips this host's HSTS policy.",
        "Redirect http://<domain> to https://<domain> first, then on to the final address."),
    "www and apex unified": (
        "The bare domain and its www form should both resolve and end at the same site.",
        "When one form is missing or serves something else, some visitors get an error or a different site.",
        "Publish DNS records for both forms and redirect one to the other."),
    "Server clock accuracy": (
        "The Date header shows the server's clock.",
        "A clock that is far off breaks certificate validation, signed tokens and the matching of logs between systems.",
        "Run a time-synchronisation service (NTP or chrony) on the server."),
    "Clickjacking protection": (
        "X-Frame-Options, or the frame-ancestors directive of a Content-Security-Policy, tells browsers which sites may show this one inside a frame.",
        "Without it another site can load this one invisibly and trick a visitor into clicking on it.",
        "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), and X-Frame-Options: DENY for older browsers."),
    "X-Content-Type-Options": (
        "X-Content-Type-Options: nosniff tells browsers to trust the declared content type of a response.",
        "Without it a browser may guess the type, and treat an uploaded file as a script.",
        "Send X-Content-Type-Options: nosniff on every response."),
    "Referrer-Policy": (
        "Referrer-Policy controls how much of the current address is sent along when a visitor follows a link to another site.",
        "Setting it gives every browser the same behaviour and keeps full addresses from reaching other sites.",
        "Send Referrer-Policy: strict-origin-when-cross-origin, or no-referrer."),
    "Permissions-Policy": (
        "Permissions-Policy states which browser features, such as camera, microphone and location, the page and its frames may use.",
        "A feature left open can be requested by any script or embedded frame on the page.",
        "Send a Permissions-Policy that turns off what the site does not use, for example geolocation=(), camera=(), microphone=()."),
    "Cross-Origin-Opener-Policy": (
        "Cross-Origin-Opener-Policy separates this page from windows that other sites open or that open it.",
        "Without it a site that opens this one keeps a handle to the window, which cross-site leak attacks rely on.",
        "Send Cross-Origin-Opener-Policy: same-origin."),
    "Cross-Origin-Resource-Policy": (
        "Cross-Origin-Resource-Policy states which sites may load this site's resources.",
        "Without it any site can embed these resources, which side-channel attacks such as Spectre rely on.",
        "Send Cross-Origin-Resource-Policy: same-origin, or same-site when subdomains share resources."),
    "X-XSS-Protection deprecated": (
        "X-XSS-Protection switched on an old browser filter for cross-site scripting. Browsers have since removed that filter.",
        "Where the header is still honoured, its filtering mode has itself been used to attack pages.",
        "Remove the header or send X-XSS-Protection: 0, and rely on a Content-Security-Policy instead."),
    "Subresource Integrity": (
        "Subresource Integrity adds a hash to a script or stylesheet tag so the browser can check the file it downloads.",
        "Without it, whoever can change the file on the other host can run code on this site.",
        "Add integrity= and crossorigin= attributes to tags that load from other origins, or host the files on the site itself."),
    "Mixed content (in-page)": (
        "A page served over HTTPS should load every resource over HTTPS.",
        "A resource loaded over plain HTTP can be read or changed in transit, and browsers block or warn about it.",
        "Change the http:// addresses to https://, or host the resource on the site itself."),
}
_CHECK_TEXT["IPv6 IRR/RIS"] = _CHECK_TEXT["IPv4 IRR/RIS"]


def explanation_for(label):
    """(what, why, fix) for a check: its own text where it has one, else its
    topic's."""
    own = _CHECK_TEXT.get(_base_label(label))
    if own:
        return own
    expl = _t.EXPLANATIONS.get(topic_for(label)) or {}
    return expl.get("what", ""), expl.get("why", ""), expl.get("fix", "")


def _base_label(label):
    return label[len(_REDIRECT_PREFIX):] if label.startswith(_REDIRECT_PREFIX) else label


def topic_for(label):
    base = _base_label(label)
    if base.startswith("EOL OS"):
        return "eol_os"
    if base.startswith("EOL library"):
        return "eol_libraries"
    if base.startswith("EOL "):
        return "eol_tech"
    return _TOPIC.get(base)


def standard_for(label):
    base = _base_label(label)
    if base.startswith("EOL "):
        return "endoflife.date"
    return _STANDARD.get(base, "")


def slug(label):
    """'DMARC policy' → 'dmarc-policy'; 'HTTP→HTTPS redirect' → 'http-https-redirect'."""
    return re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")


# ── Evidence builders ────────────────────────────────────────────────────────
# Each takes G, a getter for result blocks (G("spf") → dict), and returns a
# list of evidence items. For a redirect-target email check, G reads the
# redirect_target_* blocks instead.

def _yn(value):
    return "yes" if value else "no"


def _kv(*pairs):
    """A kv item holding only the pairs that have a value."""
    rows = [(k, str(v)) for k, v in pairs if v not in (None, "", [], {})]
    return [("kv", rows)] if rows else []


def _code(caption, text):
    return [("code", caption, str(text))] if text else []


def _list(caption, items):
    items = [str(i) for i in (items or []) if i not in (None, "")]
    return [("list", caption, items)] if items else []


_SPF_ENDING = {
    "hardfail": "-all (hard fail)", "null_sender": "-all (the domain sends no mail)",
    "softfail": "~all (soft fail)", "neutral": "?all (neutral)",
    "pass_all_DANGEROUS": "+all (anyone may send)", "missing": "no SPF record",
    "no_all_mechanism": "no 'all' mechanism", "redirect_no_all": "redirect with no 'all'",
    "redirect_target_no_spf": "redirect to a domain with no SPF record",
}


def _ev_spf(G):
    spf = G("spf")
    return (_kv(("Ends with", _SPF_ENDING.get(spf.get("status"), spf.get("status"))),
                ("DNS lookups", None if spf.get("lookup_count") is None
                 else f'{spf["lookup_count"]} of 10 allowed'),
                ("Redirects to", spf.get("redirect_target")),
                ("Lookup error", spf.get("error")))
            + _code("SPF record published", spf.get("record")))


def _ev_dmarc(G):
    d = G("dmarc")
    if not d.get("present"):
        return _kv(("DMARC record", "none published"), ("Lookup error", d.get("error")))
    return (_kv(("Policy", f'p={d.get("policy")}' if d.get("policy") else None),
                ("Subdomain policy", f'sp={d["sp"]}' if d.get("sp") else "not set (subdomains follow p=)"),
                ("Applies to", None if d.get("pct") is None else f'{d["pct"]}% of failing mail'),
                ("Aggregate reports", ", ".join(d.get("rua") or []) or "no rua= address"),
                ("Failure reports", ", ".join(d.get("ruf") or [])),
                ("Inherited from", d.get("inherited_from")))
            + _code("DMARC record published", d.get("record")))


def _ev_mx(G):
    mx = G("mx")
    if mx.get("null_mx"):
        return [("note", "Null MX published (RFC 7505): the domain accepts no mail.")]
    hosts = [f'{e.get("priority")}  {e.get("host")}' for e in (mx.get("entries") or [])]
    return (_list("MX records (priority, host)", hosts)
            + _list("MX targets that are IP addresses", mx.get("mx_targets_ip"))
            + _list("MX targets that are CNAMEs", mx.get("mx_targets_cname"))
            + _kv(("Lookup error", mx.get("error"))))


def _ev_mta_sts(G):
    rec, pol = G("mta_sts"), G("mta_sts_policy")
    out = _kv(("TXT record at _mta-sts", rec.get("record") or "none published"),
              ("Policy id", rec.get("id")))
    if pol.get("fetched"):
        out += _kv(("Policy mode", pol.get("mode")), ("Policy max_age", pol.get("max_age")))
        out += _list("MX hosts named in the policy", pol.get("mx"))
    elif rec.get("present"):
        out += _kv(("Policy file", f'could not be fetched ({pol.get("error")})'
                    if pol.get("error") else "not fetched (runs with --deep)"))
    return out


def _ev_tls_rpt(G):
    t = G("tls_rpt")
    if not t.get("present"):
        return _kv(("TXT record at _smtp._tls", "none published"))
    return _kv(("Reports go to", t.get("rua"))) + _code("TLS-RPT record published", t.get("record"))


def _ev_dane(G):
    d = G("dane")
    return (_list("MX hosts with TLSA records", d.get("with_tlsa"))
            + _list("MX hosts without TLSA records", d.get("without_tlsa")))


def _ev_starttls(G):
    s = G("starttls_mx")
    rows = []
    for host, r in (s.get("results") or {}).items():
        r = r or {}
        if r.get("error"):
            rows.append((host, f'not reached ({r["error"]})'))
        else:
            bits = [r.get("tls_version"), _t._expand_cert_issuer(r.get("cert_issuer")),
                    f'certificate expires {r["cert_expires"]}' if r.get("cert_expires") else None]
            rows.append((host, " · ".join(b for b in bits if b)))
    out = [("kv", rows)] if rows else []
    if not rows:
        out.append(("note", "Mail servers are probed on port 25 only with the Deep option. "
                            "Many networks block outbound port 25, so an empty result is common."))
    return out


def _ev_dkim(G):
    d = G("dkim")
    keys = d.get("keys") or {}
    strengths = [(sel, f'{str(k.get("algorithm", "")).upper()}-{k.get("bits")}'
                  if k.get("bits") else str(k.get("algorithm", "")).upper())
                 for sel, k in keys.items()]
    out = _kv(("Selectors checked", ", ".join(d.get("checked") or [])),
              ("Keys found at", ", ".join(d.get("found") or []) or "none of them"))
    if strengths:
        out.append(("kv", [(f"Key at {sel}", val) for sel, val in strengths]))
    if not d.get("found"):
        out.append(("note", "A selector is a name the mail provider chooses, so a domain can sign "
                            "mail with a key this probe never looks for."))
    return out


def _ev_bimi(G):
    b = G("bimi")
    if not b.get("present"):
        return _kv(("TXT record at default._bimi", "none published"))
    return (_kv(("Logo", b.get("logo_url")), ("Mark certificate", b.get("vmc_url") or "none"))
            + _code("BIMI record published", b.get("record")))


def _ev_dnssec(G):
    d = G("dnssec")
    tld, dom = d.get("tld") or {}, d.get("domain") or {}
    return _kv(("Parent zone", f'.{tld.get("tld")} is {"signed" if tld.get("signed") else "not signed"}'
                if tld.get("tld") else None),
               ("DNSKEY published", None if dom.get("error") else _yn(dom.get("dnskey"))),
               ("Answers validate (AD flag)", None if dom.get("error") else _yn(dom.get("ad_flag"))),
               ("Lookup error", dom.get("error") or tld.get("error")))


def _ev_caa(G):
    c = G("caa")
    if not c.get("present"):
        return _kv(("CAA records", "none published"), ("Lookup error", c.get("error")))
    return (_kv(("Inherited from", c.get("inherited_from")),
                ("Violation reports go to", ", ".join(c.get("iodef") or [])))
            + _list("CAA records published", c.get("records")))


def _ev_nameservers(G):
    n = G("ns_soa")
    soa = n.get("soa") or {}
    return (_list("Authoritative nameservers", n.get("nameservers"))
            + _kv(("SOA primary", soa.get("primary")), ("SOA serial", soa.get("serial")),
                  ("Lookup error", n.get("ns_error"))))


def _ev_ns_health(G):
    h = G("ns_health")
    return (_kv(("Nameservers probed", h.get("probed")), ("Lookup error", h.get("error")))
            + _list("Not answering authoritatively (lame)", h.get("lame_ns"))
            + _list("Answering recursive queries from anyone", h.get("open_resolver_ns"))
            + _list("Could not be probed", h.get("unprobed")))


def _ev_family(family):
    def build(G):
        af = (G("ip_routing").get(family) or {})
        if not af.get("address"):
            return _kv(("Address", af.get("error") or "none"))
        asn = f'AS{af.get("asn")}' + (f' ({af.get("asn_name")})' if af.get("asn_name") else "") \
            if af.get("asn") else None
        extra = [a for a in (af.get("all_addresses") or []) if a != af.get("address")]
        return _kv(("Address", af.get("address")), ("Other addresses", ", ".join(extra)),
                   ("Announced prefix", af.get("prefix")), ("Origin network", asn),
                   ("RPKI status", af.get("rpki_status")),
                   ("Seen in the RIS routing table", _yn(af.get("irr_in_ris"))),
                   ("Lookup error", af.get("error")))
    return build


def _ev_tls(G):
    t = G("tls")
    return _kv(("Negotiated", t.get("version")), ("ALPN protocol", t.get("alpn_protocol")),
               ("Connection error", t.get("error")))


def _ev_cert(G):
    t = G("tls")
    left = None
    if t.get("cert_remaining_seconds") is not None:
        left = _t._humanize_seconds(t["cert_remaining_seconds"])
        if t.get("cert_remaining_pct") is not None:
            left += f' ({t["cert_remaining_pct"]:g}% of its lifetime)'
    return _kv(("Issuer", _t._expand_cert_issuer(t.get("cert_issuer"))),
               ("Issued", t.get("cert_issued")), ("Expires", t.get("cert_expires")),
               ("Lifetime", None if t.get("cert_lifetime_days") is None
                else f'{t["cert_lifetime_days"]} days'),
               ("Time left", left))


def _ev_cert_names(G):
    t, v = G("tls"), G("cert_variant")
    return (_kv(("Name matches", None if t.get("cert_names_match") is None
                 else _yn(t.get("cert_names_match"))),
                ("www / apex coverage", {"covers": "both names are on the certificate",
                                         "missing_variant": "one of the two names is missing",
                                         "no_redirect": None}.get(v.get("outcome"), v.get("outcome"))),
                ("Missing name", v.get("missing")))
            + _list("Names on the certificate", t.get("cert_san_names")))


def _ev_chain(G):
    t = G("tls")
    status = {"unsupported": "not checked (needs Python 3.13 or later on the audit host)"}.get(
        t.get("chain_status"), t.get("chain_status"))
    return _kv(("Chain status", status), ("Certificates sent", t.get("chain_sent_count")),
               ("Certificates in the verified chain", t.get("chain_verified_count")))


def _ev_hsts(G):
    h = G("hsts")
    if not h.get("present"):
        return _kv(("Strict-Transport-Security header", "not sent"),
                   ("Preload list", h.get("preload_status") if h.get("preloaded") else None))
    age = h.get("max_age")
    age_txt = None if age is None else f"{age} seconds ({age // 86400} days)"
    return _kv(("max-age", age_txt), ("includeSubDomains", _yn(h.get("includes_subdomains"))),
               ("preload directive", _yn(h.get("preload_directive"))),
               ("Browser preload list", h.get("preload_status")),
               ("Preloaded through", h.get("preloaded_via")
                if h.get("preloaded_via") and h.get("preloaded") else None))


def _ev_ssl_labs(G):
    s = G("ssl_labs")
    return _kv(("Grades by endpoint", ", ".join(str(g) for g in (s.get("grades") or []))),
               ("Error", s.get("error")))


def _ev_http_version(G):
    v, sh, t = G("http_version"), G("server_header"), G("tls")
    return _kv(("Negotiated", v.get("version")), ("ALPN protocol", t.get("alpn_protocol")),
               ("HTTP/3 advertised", _yn(sh.get("http3_advertised")) if sh else None),
               ("Alt-Svc header", sh.get("alt_svc")), ("Error", v.get("error")))


def _ev_http_redirect(G):
    r = G("http_redirect")
    return _kv(("Result", r.get("detail")), ("Final address", r.get("final_url")),
               ("Final status", r.get("status_code")))


def _ev_first_hop(G):
    r = G("redirect")
    if not r.get("first_hop_url"):
        return [("note", "The site answered without redirecting.")]
    return _kv(("First redirect goes to", r.get("first_hop_url")),
               ("First hop uses HTTPS", _yn(r.get("first_hop_https"))),
               ("First hop stays on the same host", _yn(r.get("first_hop_same_host"))))


def _ev_www_apex(G):
    w = G("www_apex_unified")
    def side(resolves, final, err):
        if not resolves:
            return f'does not resolve ({err})' if err else "does not resolve"
        return f"ends at {final}" if final else "resolves"
    return _kv((w.get("apex_host") or "apex", side(w.get("apex_resolves"), w.get("apex_final"), w.get("apex_error"))),
               (w.get("www_host") or "www", side(w.get("www_resolves"), w.get("www_final"), w.get("www_error"))))


def _header(name, key, absent="not sent"):
    def build(G):
        return _kv((f"{name} header", G("server_header").get(key) or absent))
    return build


def _ev_powered_by(G):
    s = G("server_header")
    return _kv(("X-Powered-By header", s.get("x_powered_by") or "not sent"),
               ("X-AspNet-Version header", s.get("x_aspnet_version")),
               ("X-AspNetMvc-Version header", s.get("x_aspnetmvc_version")),
               ("SharePoint version header", s.get("sharepoint_version")))


def _ev_clickjacking(G):
    s = G("server_header")
    return _kv(("X-Frame-Options header", s.get("x_frame_options") or "not sent"),
               ("CSP frame-ancestors", "set" if s.get("csp_frame_ancestors") else "not set"))


def _ev_cross_origin(G):
    s = G("server_header")
    return _kv(("Cross-Origin-Opener-Policy", s.get("coop") or "not sent"),
               ("Cross-Origin-Resource-Policy", s.get("corp") or "not sent"),
               ("Cross-Origin-Embedder-Policy", s.get("coep")))


def _ev_csp(G):
    s, a = G("server_header"), G("csp_analysis")
    if not s.get("csp") and not s.get("csp_report_only"):
        return _kv(("Content-Security-Policy header", "not sent"))
    out = _kv(("script-src", (a.get("script_src_outcome") or "").replace("_", " ")),
              ("object-src", (a.get("object_src_outcome") or "").replace("_", " ")),
              ("base-uri", (a.get("base_uri_outcome") or "").replace("_", " ")),
              ("Mode", "report-only" if not s.get("csp") else "enforced"))
    out += _list("Policy notes", [f[1] if isinstance(f, (list, tuple)) and len(f) > 1 else f
                                  for f in (a.get("findings") or [])])
    out += _code("Content-Security-Policy", s.get("csp"))
    out += _code("Content-Security-Policy-Report-Only", s.get("csp_report_only"))
    return out


def _ev_cookies(G):
    cookies = G("server_header").get("cookies") or []
    if not cookies:
        return [("note", "No cookies were set on the home page response. Cookies set after "
                         "sign-in or by scripts are not visible to this check.")]
    rows = []
    for c in cookies:
        flags = [("Secure" if c.get("secure") else "no Secure"),
                 ("HttpOnly" if c.get("httponly") else "no HttpOnly"),
                 (f'SameSite={c["samesite"]}' if c.get("samesite") else "no SameSite")]
        if c.get("infra"):
            flags.append("set by the CDN or firewall")
        rows.append((c.get("name") or "(unnamed)", ", ".join(flags)))
    return [("kv", rows)]


def _ev_security_txt(G):
    s = G("security_txt")
    if not s.get("present"):
        return _kv(("/.well-known/security.txt", "not found"), ("Error", s.get("error")))
    return _kv(("Found at", s.get("found_at")), ("Contact", ", ".join(s.get("contact") or [])),
               ("Expires", s.get("expires")), ("Policy", s.get("policy")))


def _ev_error_page(G):
    e = G("error_page")
    return _kv(("Probe status", e.get("status")), ("Server software recognised", e.get("detected")),
               ("Version shown", e.get("version")), ("Banner", e.get("banner")),
               ("Error", e.get("error")))


def _ev_cors(G):
    c = G("cors")
    d = c.get("details") or {}
    return _kv(("Access-Control-Allow-Origin (same-origin request)", d.get("acao_same_origin_probe") or "not sent"),
               ("Access-Control-Allow-Origin (foreign-origin request)", d.get("acao_attacker_probe")),
               ("Access-Control-Allow-Credentials", d.get("acac_attacker_probe") or d.get("acac_same_origin_probe")),
               ("Error", c.get("error")))


def _ev_clock(G):
    c = G("clock")
    skew = c.get("skew_seconds")
    return _kv(("Server time", c.get("server_time")),
               ("Difference from UTC", None if skew is None else f"{skew:+.0f} seconds"))


def _ev_sri(G):
    p = G("page_signals")
    if not p.get("parsed"):
        return [("note", "The page body is read only with the Deep option.")]
    return (_kv(("External scripts", p.get("external_scripts")),
                ("External stylesheets", p.get("external_styles")),
                ("With an integrity attribute", f'{p.get("sri_protected", 0)} of {p.get("sri_external_total", 0)}'))
            + _list("Third-party origins", p.get("third_party_origins")))


def _ev_mixed(G):
    p = G("page_signals")
    if not p.get("parsed"):
        return [("note", "The page body is read only with the Deep option.")]
    return (_kv(("HTTP resources on the HTTPS page", p.get("mixed_active_count", 0)))
            + _list("Loaded over plain HTTP", p.get("mixed_active")))


_EVIDENCE = {
    "SPF policy": _ev_spf, "SPF lookup count": _ev_spf,
    "DMARC policy": _ev_dmarc, "DMARC sp": _ev_dmarc, "DMARC pct": _ev_dmarc,
    "DMARC rua reporting": _ev_dmarc,
    "MX target hygiene": _ev_mx,
    "MTA-STS": _ev_mta_sts, "TLS-RPT": _ev_tls_rpt,
    "DANE TLSA on MX": _ev_dane, "STARTTLS-MX": _ev_starttls,
    "DKIM (common selectors)": _ev_dkim, "DKIM key strength": _ev_dkim,
    "BIMI": _ev_bimi,
    "DNSSEC": _ev_dnssec, "DNSSEC TLD signed": _ev_dnssec,
    "CAA records": _ev_caa,
    "Nameserver count": _ev_nameservers,
    "Authoritative delegation": _ev_ns_health, "NS not open resolver": _ev_ns_health,
    "IPv6": _ev_family("v6"),
    "IPv4 RPKI": _ev_family("v4"), "IPv4 IRR/RIS": _ev_family("v4"),
    "IPv6 RPKI": _ev_family("v6"), "IPv6 IRR/RIS": _ev_family("v6"),
    "TLS connection": _ev_tls, "TLS 1.3": _ev_tls,
    "Certificate lifetime": _ev_cert, "Certificate renewal": _ev_cert,
    "Certificate name match": _ev_cert_names, "Cert covers www variant": _ev_cert_names,
    "Cert chain completeness": _ev_chain,
    "HSTS": _ev_hsts, "HSTS preload": _ev_hsts,
    "SSL Labs grade": _ev_ssl_labs,
    "HTTP version": _ev_http_version, "HTTP→HTTPS redirect": _ev_http_redirect,
    "Redirect first-hop hygiene": _ev_first_hop, "www and apex unified": _ev_www_apex,
    "Server header": _header("Server", "server"),
    "X-Powered-By absent": _ev_powered_by,
    "Clickjacking protection": _ev_clickjacking,
    "X-Content-Type-Options": _header("X-Content-Type-Options", "x_content_type"),
    "Referrer-Policy": _header("Referrer-Policy", "referrer_policy"),
    "Permissions-Policy": _header("Permissions-Policy", "permissions_policy"),
    "Cross-Origin-Opener-Policy": _ev_cross_origin,
    "Cross-Origin-Resource-Policy": _ev_cross_origin,
    "X-XSS-Protection deprecated": _header("X-XSS-Protection", "x_xss_protection"),
    "CSP script-src safety": _ev_csp,
    "Cookie Secure": _ev_cookies, "Cookie HttpOnly": _ev_cookies,
    "Cookie SameSite": _ev_cookies, "Cookie name prefixes": _ev_cookies,
    "security.txt": _ev_security_txt,
    "Default error page": _ev_error_page,
    "CORS configuration": _ev_cors,
    "Server clock accuracy": _ev_clock,
    "Subresource Integrity": _ev_sri, "Mixed content (in-page)": _ev_mixed,
}


def _ev_eol(label, results):
    """Evidence for a dynamic end-of-life label ('EOL OS: iis 8.0')."""
    def rows(entry, name, extra=()):
        return _kv(("Detected", name), *extra,
                   ("Status", entry.get("eol_message")),
                   ("End of life since", entry.get("eol_last_release")),
                   ("Source", entry.get("eol_source")))
    for f in ((results.get("os_eol") or {}).get("os_findings") or []):
        ver = f.get("version") or ""
        key = f'EOL OS: {f.get("os", "?")}' + (f" {ver}" if ver and ver != "?" else "")
        if key == label:
            return rows(f, f'{f.get("name") or f.get("os")} {ver}'.strip(),
                        (("Implies", f.get("underlying_os")),
                         ("Seen in", (f.get("source") or "").replace("_", " "))))
    for lib in ((results.get("versioned_libs") or {}).get("libraries") or []):
        if label == f'EOL library: {lib.get("library")} {lib.get("version")}':
            return rows(lib, f'{lib.get("name") or lib.get("library")} {lib.get("version")}',
                        (("Last release in this line", lib.get("eol_last_version")),))
    for tech in ((results.get("tech_eol") or {}).get("techs") or []):
        if label.endswith(f'{tech.get("tech")} {tech.get("version")}'):
            return rows(tech, f'{tech.get("name") or tech.get("tech")} {tech.get("version")}',
                        (("Seen in", (tech.get("source") or "").replace("_", " ")),))
    return []


def evidence_for(label, results):
    """Evidence items for one check. Never raises."""
    redirect_target = label.startswith(_REDIRECT_PREFIX)
    base = _base_label(label)

    def G(key):
        if redirect_target:
            return results.get(f"redirect_target_{key}") or {}
        return results.get(key) or {}

    try:
        if base.startswith("EOL "):
            return _ev_eol(base, results)
        builder = _EVIDENCE.get(base)
        return builder(G) if builder else []
    except Exception:                                   # noqa: BLE001
        return []


# ── Records ──────────────────────────────────────────────────────────────────

def build_records(data):
    """One record per finding row of a _ReportData, in report order: issues
    from critical to low (each ranked by how much the practice matters),
    then informational, then passing."""
    sev_index = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows = sorted(
        data.finding_rows,
        key=lambda r: (sev_index.get(r["severity"], 99),
                       _t._criticality_rank(_base_label(r["label"])), r["label"]))
    records, seen = [], set()
    for r in rows:
        label = r["label"]
        rid = slug(label)
        while rid in seen:                              # two labels, one slug
            rid += "-2"
        seen.add(rid)
        topic = topic_for(label)
        what, why, fix = explanation_for(label)
        records.append({
            "id":       rid,
            "label":    label,
            "title":    r["display"],
            "severity": r["severity"],
            "category": r["category"],
            "outcome":  r["outcome"],
            "standard": standard_for(label),
            "topic":    topic,
            "what":     what,
            "why":      why,
            "fix":      fix,
            "evidence": evidence_for(label, data.results),
        })
    return records
