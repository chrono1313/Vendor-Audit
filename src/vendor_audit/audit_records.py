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
    "SPF single record": "spf",
    "SPF mechanisms": "spf",
    "DMARC single record": "dmarc",
    "DMARC external reports": "dmarc",
    "MX hosts resolve": "mx",
    "MX reverse DNS": "mx",
    "Null MX on no-mail domain": "mx",
    "MTA-STS policy MX match": "mta_sts",
    "MTA-STS max_age": "mta_sts",
    "Dangling CNAME": "dangling_dns",
    "DNSSEC algorithm": "dnssec",
    "SOA timers": "nameservers",
    "Nameservers on IPv6": "ipv6",
    "Nameserver networks": "nameservers",
    "Nameserver RPKI": "rpki",
    "Mail servers on IPv6": "ipv6",
    "Mail server RPKI": "rpki",
    "HTTPS DNS record": "http_version",
    "Legacy TLS disabled": "tls",
    "Forward secrecy": "tls",
    "Certificate key strength": "tls",
    "CSP object-src": "csp",
    "CSP base-uri": "csp",
    "security.txt location": "security_txt",
    "security.txt Canonical": "security_txt",
    "Deprecated security headers": "security_headers",
    "Page language declared": "page_analysis",
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
    "dangling_dns": "Dangling DNS records", "infra_routing": "Nameserver and mail server addresses",
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
    "SPF single record": "RFC 7208 §3.2",
    "SPF mechanisms": "RFC 7208 §4.6.4, §5.5",
    "DMARC single record": "RFC 7489 §6.6.3",
    "DMARC external reports": "RFC 7489 §7.1",
    "MX hosts resolve": "RFC 5321 §5.1",
    "MX reverse DNS": "M3AAWG; RFC 1912 §2.1",
    "Null MX on no-mail domain": "RFC 7505",
    "MTA-STS policy MX match": "RFC 8461 §4.1",
    "MTA-STS max_age": "RFC 8461 §3.2",
    "Dangling CNAME": "RFC 1034; OWASP WSTG-CONF-10",
    "DNSSEC algorithm": "RFC 8624; RFC 9905",
    "SOA timers": "RFC 1912 §2.2; RFC 2308 §5",
    "Nameservers on IPv6": "RFC 3901",
    "Nameserver networks": "RFC 2182 §3.1",
    "Nameserver RPKI": "RFC 6480; RFC 6811",
    "Mail servers on IPv6": "RFC 8200",
    "Mail server RPKI": "RFC 6480; RFC 6811",
    "HTTPS DNS record": "RFC 9460",
    "Legacy TLS disabled": "RFC 8996",
    "Forward secrecy": "RFC 9325 §4.1",
    "Certificate key strength": "CA/B Forum BR §6.1.5",
    "CSP object-src": "CSP Level 3",
    "CSP base-uri": "CSP Level 3",
    "security.txt location": "RFC 9116 §3",
    "security.txt Canonical": "RFC 9116 §2.5.2",
    "Deprecated security headers": "RFC 7469 (obsolete); RFC 9163",
    "Page language declared": "WCAG 2.1 SC 3.1.1",
}


# ── Per-check explanation ────────────────────────────────────────────────────
# EXPLANATIONS is written per topic, and a topic often spans several checks
# ("TLS" covers protocol versions and five certificate checks). Where the
# topic text would not describe a check, the check gets its own three
# sentences here: what it is, why it matters, how to fix it.

_CHECK_TEXT = {
    "SPF lookup count": (
        "Evaluating an SPF record may trigger at most 10 DNS lookups.",
        "Past that limit receivers treat the record as broken, so SPF no longer stops anyone sending mail that claims to be from the domain.",
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
        "Full addresses can carry session tokens, password-reset links or search terms; without a policy they can leak to every site the page links to or loads from.",
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
    "SPF single record": (
        "A domain may publish only one TXT record that starts with v=spf1.",
        "With two or more, receivers treat the domain as having no usable SPF, so mail forged in its name is no longer rejected on SPF.",
        "Merge the records into one, keeping every sender they list."),
    "SPF mechanisms": (
        "Each name an SPF record looks up should exist, and the ptr mechanism should not be used.",
        "An include: of a domain with no SPF record breaks the whole record, and more than two lookups that return nothing may make receivers give up; either way forged mail is no longer stopped by SPF. ptr is slow and unreliable.",
        "Remove include:, a: and mx: entries for names that no longer exist, and replace ptr with ip4:, ip6: or include: entries."),
    "DMARC single record": (
        "A domain may publish only one DMARC record at _dmarc.<domain>.",
        "With more than one, receivers ignore DMARC for the domain as if it had none, so phishing mail spoofing it is delivered whatever the policy says.",
        "Delete the extra records and keep a single v=DMARC1 record."),
    "DMARC external reports": (
        "When DMARC reports go to an address at another organisation, that organisation must publish a record saying it accepts them.",
        "Without that record, receivers do not send the reports there, so spoofing of the domain and legitimate mail that fails authentication go unseen.",
        "Ask the report provider to publish <your domain>._report._dmarc.<their domain> TXT \"v=DMARC1\", or send reports to an address in your own domain."),
    "MX hosts resolve": (
        "Every host an MX record names must have an A or AAAA record.",
        "Mail sent to a host with no address is delayed and then bounced.",
        "Remove MX records for hosts that no longer exist, or give the host its address records back."),
    "MX reverse DNS": (
        "Each mail server address should have a reverse DNS (PTR) name that resolves back to the same address.",
        "Large mail providers check this for servers that send mail, and junk or refuse mail from servers that fail it.",
        "Ask whoever controls the address range (usually the hosting provider) to set a PTR record to a name whose A or AAAA record is that address."),
    "Null MX on no-mail domain": (
        "A domain that receives no mail should publish a null MX record (0 .) to say so.",
        "Without any MX, senders fall back to the domain's A or AAAA address and queue mail for it, and spammers forging the domain get no clear signal that its mail is never legitimate.",
        "Publish MX 0 . together with v=spf1 -all and a DMARC record with p=reject."),
    "MTA-STS policy MX match": (
        "Every MX host must match an mx: line in the MTA-STS policy.",
        "In enforce mode, sending servers refuse to deliver to an MX host the policy does not name, so mail routed there fails.",
        "Add an mx: line for each MX host (a *.example.com pattern covers one label), then change the policy id."),
    "MTA-STS max_age": (
        "max_age tells sending servers how long to keep the MTA-STS policy.",
        "A short value means senders refetch it often, and an attacker who blocks the refetch can make them fall back to delivering without TLS. RFC 8461 suggests weeks or more.",
        "Set max_age to at least 604800 (one week); 1209600 or more is common."),
    "Dangling CNAME": (
        "A CNAME on the domain or its www form should point at a name that still exists.",
        "When the target was a deleted cloud resource, anyone who re-creates it at the provider can serve content on this domain.",
        "Delete the CNAME, or re-create the resource it points at."),
    "DNSSEC algorithm": (
        "The algorithm the zone's DNSSEC keys sign with.",
        "RFC 9905 forbids SHA-1 signing (algorithms 5 and 7), and validating resolvers now treat a zone signed only with it as unsigned, so DNSSEC no longer protects it.",
        "Roll the keys over to ECDSAP256SHA256 (algorithm 13) or RSASHA256 (8). Most DNS providers do this with a setting change."),
    "SOA timers": (
        "The SOA record's timers tell secondary nameservers how often to refresh the zone, when to give up on the primary, and how long resolvers keep a 'does not exist' answer.",
        "An expire under a week drops the zone from secondaries during a short outage of the primary, and a long negative TTL keeps newly added names unresolvable for a day or more.",
        "Keep retry shorter than refresh, expire at two weeks or more, and the minimum (negative TTL) at one to three hours."),
    "Nameservers on IPv6": (
        "Nameservers should have IPv6 addresses, at least two of them.",
        "Resolvers that reach the internet only over IPv6 cannot look up a domain whose nameservers have no IPv6 address, and one IPv6 nameserver is a single point of failure for them.",
        "Ask the DNS provider for IPv6 on its nameservers, or move to a provider that offers it."),
    "Nameserver networks": (
        "The networks (ASNs) the nameservers' addresses sit in.",
        "Nameservers in one network share its outages and routing problems. RFC 2182 asks for diversity, though a large anycast network is resilient in practice.",
        "Add a secondary DNS provider on a different network, or accept the risk of a well-run anycast provider."),
    "Nameserver RPKI": (
        "Whether the routes to the nameservers' addresses are covered by a Route Origin Authorization.",
        "A hijacked route to the nameservers lets someone answer DNS for the whole domain: web, mail and certificates.",
        "Ask the DNS provider to publish ROAs for its prefixes, or move to one that does."),
    "Mail servers on IPv6": (
        "Mail servers should have IPv6 addresses.",
        "Senders that reach the internet only over IPv6 cannot deliver to a mail server without one.",
        "Enable IPv6 on the mail servers, or ask the mail provider to."),
    "Mail server RPKI": (
        "Whether the routes to the mail servers' addresses are covered by a Route Origin Authorization.",
        "A hijacked route to the mail servers lets someone receive the domain's mail.",
        "Ask the mail provider to publish ROAs for its prefixes, or move to one that does."),
    "HTTPS DNS record": (
        "An HTTPS DNS record (RFC 9460) tells browsers, before they connect, that the site speaks HTTPS and which protocols it offers.",
        "It lets browsers go straight to HTTPS and HTTP/3, and it carries the key for Encrypted ClientHello. It is optional.",
        "Many DNS providers publish it automatically; otherwise add an HTTPS record with alpn=\"h2,h3\"."),
    "Legacy TLS disabled": (
        "Whether the server still accepts TLS 1.0 or 1.1 when a client asks for them.",
        "Both are deprecated (RFC 8996) and fail PCI DSS. A server that accepts them lets an attacker who can interfere with the connection push clients down to the weaker protocol.",
        "Set the server's minimum TLS version to 1.2."),
    "Forward secrecy": (
        "Whether the server accepts TLS 1.2 key exchanges without forward secrecy, or ciphers without encryption.",
        "With static RSA key exchange, anyone who later obtains the server's private key can decrypt recorded traffic. RFC 9325 says these cipher suites should not be used.",
        "Allow only ECDHE (or DHE) key exchange with AES-GCM or ChaCha20-Poly1305 for TLS 1.2, and remove NULL ciphers."),
    "Certificate key strength": (
        "The size of the certificate's public key and the hash it is signed with.",
        "An RSA key under 2048 bits can be factored, and a SHA-1 or MD5 signature can be forged; public CAs stopped issuing both years ago, so one usually means a private CA or a very old certificate.",
        "Issue a new certificate with an RSA 2048-bit or larger key, or ECDSA P-256, from a CA that signs with SHA-256."),
    "CSP object-src": (
        "object-src controls what <object> and <embed> elements may load.",
        "Left open, an attacker who can inject HTML can load script through them and get around script-src.",
        "Add object-src 'none' to the policy."),
    "CSP base-uri": (
        "base-uri controls which <base> element a page may use.",
        "Without it, an injected <base href> makes every relative script and link on the page load from the attacker's server, even under a nonce-based script-src.",
        "Add base-uri 'none' (or 'self' if the site uses a <base> element)."),
    "security.txt location": (
        "RFC 9116 places security.txt at /.well-known/security.txt; /security.txt is a fallback.",
        "Tools and researchers look in /.well-known/ first, and some look only there.",
        "Serve the file at /.well-known/security.txt; the root copy can stay as a redirect."),
    "security.txt Canonical": (
        "The Canonical field names the URLs where the file is meant to be found.",
        "When it does not list the URL the file was served from, readers can't tell whether the file is the owner's or a stale copy, and RFC 9116 says to treat its contents with caution.",
        "Make Canonical list the file's real URL, for example https://example.com/.well-known/security.txt."),
    "Deprecated security headers": (
        "Public-Key-Pins (HPKP) and Expect-CT are security headers browsers no longer support.",
        "HPKP locks visitors out of the site for the pin's lifetime if the pinned keys are lost or rotated, in the browsers that still honour a cached pin. Expect-CT is harmless but does nothing.",
        "Remove both headers. Certificate Transparency is enforced by browsers without them."),
    "Page language declared": (
        "The lang attribute on <html> names the page's language.",
        "Screen readers use it to pick a voice and pronunciation, and browsers to offer translation. WCAG 2.1 requires it (success criterion 3.1.1).",
        "Add lang to the <html> element, for example <html lang=\"en\">."),
}
_CHECK_TEXT["IPv6 IRR/RIS"] = _CHECK_TEXT["IPv4 IRR/RIS"]


# Outcomes whose cause differs from the check's usual subject, with text of
# their own. A failed certificate is not a TLS-version problem, so it should
# not be explained as one.
_CERT_BLOCKED = ("Browsers show a full-page warning and most visitors cannot continue. Visitors who click "
                 "through, and apps and scripts that skip the check, lose the protection a certificate gives "
                 "against someone on the network impersonating the site.")
_OUTCOME_TEXT = {
    ("DKIM key strength", "weak_rotation"): (
        "Every DKIM key a domain publishes can verify mail signed with it.",
        "A 1024-bit key beside a 2048-bit one is usually left over from a key rotation, but receivers still "
        "accept signatures made with it, so anyone who factors it can sign mail as the domain.",
        "Rotate once more so the old selector also gets a 2048-bit key, or remove the old key once nothing signs with it."),
    ("TLS connection", "cert_expired"): (
        "The site's TLS certificate has passed its expiry date.",
        _CERT_BLOCKED,
        "Renew the certificate and install it together with its intermediate certificate. Automate renewal "
        "(ACME, for example Let's Encrypt or the CDN's managed certificates) so it can't lapse again."),
    ("TLS connection", "cert_not_yet_valid"): (
        "The certificate's start date is still in the future.",
        _CERT_BLOCKED + " Usually the server's clock is wrong, or a new certificate was installed before it became valid.",
        "Check the server's clock (NTP), and install a certificate that is already valid."),
    ("TLS connection", "cert_self_signed"): (
        "The certificate was signed by the server itself, not by a certificate authority browsers trust.",
        "Browsers block the site, and anyone on the network path can present a self-signed certificate of "
        "their own — visitors who click through cannot tell it from the real one.",
        "Install a certificate from a public certificate authority; Let's Encrypt issues them free."),
    ("TLS connection", "cert_untrusted"): (
        "The certificate does not chain to a certificate authority browsers trust. Usually the server leaves "
        "out its intermediate certificate, or the certificate comes from a private CA.",
        "Clients that cannot complete the chain refuse the connection, and browsers may block the site.",
        "Configure the server to send the full chain (certificate plus intermediates). Replace a certificate "
        "from a private CA with one from a public CA."),
    ("TLS connection", "cert_error"): (
        "The site's TLS certificate failed verification.",
        _CERT_BLOCKED,
        "Check the certificate and its chain (SSL Labs shows exactly what fails), then install a valid "
        "certificate from a public CA with its intermediates."),
    ("TLS connection", "no_tls"): (
        "The server does not complete an HTTPS (TLS) connection on port 443.",
        "Without HTTPS every page, password and cookie travels in plain text, readable and changeable by "
        "anyone on the network path, and browsers mark the site Not Secure.",
        "Enable HTTPS on port 443 with a certificate from a public CA, then redirect HTTP to HTTPS."),
}


def explanation_for(label, outcome=None):
    """(what, why, fix) for a check: text for its outcome where that has its
    own, else the check's own text, else its topic's."""
    by_outcome = _OUTCOME_TEXT.get((_base_label(label), outcome))
    if by_outcome:
        return by_outcome
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
    mx = G("mx")
    # 3.4.6: a domain with no SPF and no MX most likely sends no mail at all.
    no_mail = ("no MX records, so the domain appears to send no mail: v=spf1 -all is all it needs"
               if spf.get("status") == "missing" and not spf.get("record") and "entries" in mx
               and not mx["entries"] and not mx.get("null_mx") and not mx.get("error") else None)
    return (_kv(("Ends with", _SPF_ENDING.get(spf.get("status"), spf.get("status"))),
                ("DNS lookups", None if spf.get("lookup_count") is None
                 else f'{spf["lookup_count"]} of 10 allowed'),
                ("Redirects to", spf.get("redirect_target")),
                ("Lookup error", spf.get("error")),
                ("Mail", no_mail))
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
        out += _kv(("Policy mode", pol.get("mode")), ("Policy max_age", pol.get("max_age")),
                   ("Problems", "; ".join(pol.get("problems") or []) or None))
        out += _list("MX hosts named in the policy", pol.get("mx"))
    elif rec.get("present"):
        out += _kv(("Policy file", f'could not be fetched ({pol.get("error")})'
                    if pol.get("error") else "not fetched"))
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
        if af.get("error") == "no BGP prefix announced for this IP":
            return _kv(("Address", af.get("address")),
                       ("Routing", "not announced in BGP — no route to this address on the internet"))
        return _kv(("Address", af.get("address")), ("Other addresses", ", ".join(extra)),
                   ("Announced prefix", af.get("prefix")), ("Origin network", asn),
                   ("RPKI status", af.get("rpki_status")),
                   ("Seen in the RIS routing table", _yn(af.get("irr_in_ris"))),
                   ("Lookup error", af.get("error")))
    return build


_CERT_REASON_WORDS = {
    "expired": "the certificate has expired", "not_yet_valid": "the certificate is not valid yet",
    "self_signed": "the certificate is self-signed", "untrusted": "the issuer is not trusted (missing intermediate or private CA)",
}


def _days_from_now(iso):
    from datetime import datetime, timezone
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (when - datetime.now(timezone.utc)).days


def _ev_tls(G):
    t = G("tls")
    out = _kv(("Negotiated", t.get("version")), ("ALPN protocol", t.get("alpn_protocol")),
              ("Why verification failed", _CERT_REASON_WORDS.get(t.get("cert_error_reason"))),
              ("Connection error", t.get("error")))
    c = t.get("cert_failed_details") or {}
    if c:
        days = _days_from_now(c.get("not_after"))
        if days is not None and days < 0:
            ends = f'{c["not_after"][:10]} ({-days} day{"s" if days != -1 else ""} ago)'
        elif days is not None:
            ends = f'{c["not_after"][:10]} (in {days} day{"s" if days != 1 else ""})'
        else:
            ends = c.get("not_after")
        out += [("note", "Read from the certificate the server sent; it was not trusted.")]
        out += _kv(("Issued to", c.get("subject_cn")), ("Issued by", c.get("issuer_cn")),
                   ("Valid from", (c.get("not_before") or "")[:10]), ("Valid until", ends),
                   ("Key", f'{c["cert_key_type"]} {c["cert_key_bits"]}-bit' if c.get("cert_key_bits")
                    else c.get("cert_key_type")))
    return out


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
    # 3.4.6: a wrong certificate on the bare name of a site that lives on www.
    wau, landing = G("www_apex_unified"), None
    if t.get("cert_names_match") is False:
        for final in (wau.get("www_final"), wau.get("apex_final")):
            if final and wau.get("apex_host") and final.lower() != wau["apex_host"].lower():
                landing = final
                break
    return (_kv(("Name matches", None if t.get("cert_names_match") is None
                 else _yn(t.get("cert_names_match"))),
                ("Site lands on", landing),
                ("Why a browser may look fine", None if not landing else
                 "typing the bare name usually starts on http://, which redirects to the site; "
                 "links and bookmarks to the https:// bare name get the warning"),
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
    return (_kv(("Found at", s.get("found_at")), ("Contact", ", ".join(s.get("contact") or [])),
                ("Expires", s.get("expires")), ("Policy", s.get("policy")))
            + _list("Canonical", s.get("canonical")))


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


# ── Evidence for the checks added in 3.4 ─────────────────────────────────────

def _ev_spf_mechanisms(G):
    spf = G("spf")
    return (_kv(("SPF records published", spf.get("record_count")),
                ("Lookups that return nothing", None if "void_lookups" not in spf
                 else f'{spf["void_lookups"]} (2 allowed)'),
                ("Uses ptr", "yes" if spf.get("uses_ptr") else None))
            + _list("Included domains with no SPF record", spf.get("missing_includes"))
            + _code("SPF record published", spf.get("record")))


def _ev_dmarc_extra(G):
    d = G("dmarc")
    rows = [f'{e["domain"]}: ' + {True: "authorized", False: "not authorized", None: "lookup failed"}[e.get("authorized")]
            for e in d.get("rua_external") or []]
    return (_kv(("DMARC records published", d.get("record_count")))
            + _list("Report destinations at other domains", rows)
            + _code("DMARC record published", d.get("record")))


def _ev_mx_hosts(G):
    mx = G("mx")
    rows, ptrs = [], []
    for host, info in (mx.get("mx_hosts") or {}).items():
        addrs = ", ".join((info.get("v4") or []) + (info.get("v6") or [])) or "no A or AAAA record"
        rows.append(f"{host}: {addrs}")
        for p in info.get("ptr") or []:
            state = {True: "maps back", False: "does not map back" if p.get("name") else "no PTR record",
                     None: "lookup failed"}[p.get("confirmed")]
            ptrs.append(f'{p["address"]} → {p.get("name") or "—"} ({state})')
    return _list("MX hosts and their addresses", rows) + _list("Reverse DNS", ptrs)


def _ev_null_mx(G):
    mx = G("mx")
    return _kv(("MX records", "null MX (0 .)" if mx.get("null_mx") else
                ("none" if not mx.get("entries") else f'{len(mx["entries"])} published')))


def _ev_mta_sts_mx(G):
    pol, mx = G("mta_sts_policy"), G("mx")
    return (_list("MX hosts", [e.get("host") for e in mx.get("entries") or []])
            + _list("mx lines in the policy", pol.get("mx"))
            + _kv(("Policy mode", pol.get("mode")), ("max_age",
                   None if pol.get("max_age") is None else f'{pol["max_age"]} s ({pol["max_age"] / 86400:.1f} days)')))


def _ev_dangling(G):
    d = G("dangling_cname")
    rows = []
    for name, info in (d.get("names") or {}).items():
        chain = " → ".join([name] + (info.get("chain") or []))
        rows.append(f'{chain}  ({ {"nxdomain": "target does not exist", "ok": "target exists", "none": "no CNAME", "absent": "name does not exist", "error": "lookup failed"}.get(info.get("end"), info.get("end")) })')
    return _list("CNAME chains checked", rows)


def _ev_dnssec_alg(G):
    algs = (G("dnssec").get("domain") or {}).get("algorithms") or []
    from .audit_txt_report import _DNSSEC_ALG_NAMES
    return _list("DNSKEY algorithms", [f"{a} ({_DNSSEC_ALG_NAMES.get(a, 'unknown')})" for a in algs])


def _ev_soa(G):
    soa = G("ns_soa").get("soa") or {}
    from .audit_checks import _soa_issues
    return (_kv(("Refresh", soa.get("refresh")), ("Retry", soa.get("retry")), ("Expire", soa.get("expire")),
                ("Minimum (negative TTL)", soa.get("minimum")))
            + _list("Outside guidance", _soa_issues(soa) if soa else []))


def _ev_infra(kind):
    def build(G):
        block = (G("infra_routing").get(kind) or {})
        hosts = [f'{h}: ' + (", ".join((i.get("v4") or []) + (i.get("v6") or [])) or "no address")
                 for h, i in (block.get("hosts") or {}).items()]
        looks = [f'{l["host"]} {l["address"]}: ' + (f'AS{l["asn"]} {l["prefix"]}, RPKI {l.get("rpki_status") or "unknown"}'
                                                     if l.get("prefix") else (l.get("error") or "no data"))
                 for l in block.get("lookups") or []]
        # 3.4.5: say when the sample or the lookup cap left hosts out.
        n_hosts = len(block.get("hosts") or {})
        total = block.get("total") or 0
        sampled = (f"first {n_hosts} of {total}, by priority" if kind == "mx" else f"first {n_hosts} of {total}"
                   ) if total > n_hosts else None
        from .audit_checks import _INFRA_MAX_LOOKUPS
        cap = G("infra_routing").get("max_lookups") or _INFRA_MAX_LOOKUPS
        skipped = (f"{block['unchecked']} more not looked up (at most {cap} routing lookups per scan)"
                   if block.get("unchecked") else None)
        return (_kv(("Hosts checked", sampled), ("Addresses", skipped))
                + _list("Hosts and addresses", hosts) + _list("Routing (RIPEstat)", looks))
    return build


def _ev_https_rr(G):
    h = G("https_rr")
    return (_kv(("HTTPS record", "published" if h.get("present") else "none"),
                ("Protocols (alpn)", ", ".join(h.get("alpn") or [])),
                ("Encrypted ClientHello key", "yes" if h.get("ech") else None))
            + _list("Records", h.get("records")))


def _ev_tls_legacy(G):
    l = G("tls_legacy")
    word = {"accepted": "accepted", "refused": "refused", "unreachable": "no answer",
            "unprobed": "not tested (this OpenSSL cannot offer it)"}
    return _kv(("TLS 1.0", word.get(l.get("tls1_0"))), ("TLS 1.1", word.get(l.get("tls1_1"))),
               ("Static RSA key exchange", word.get(l.get("static_rsa"))),
               ("NULL ciphers", word.get(l.get("null_cipher"))))


def _ev_cert_key(G):
    t = G("tls")
    return _kv(("Key", f'{t.get("cert_key_type")} {t.get("cert_key_bits")}-bit' if t.get("cert_key_bits")
                else t.get("cert_key_type")), ("Signature", t.get("cert_sig_alg")))


def _ev_deprecated_headers(G):
    s = G("server_header")
    return _kv(("Public-Key-Pins", s.get("public_key_pins") or "not sent"),
               ("Expect-CT", s.get("expect_ct") or "not sent"))


def _ev_lang(G):
    a = G("page_signals").get("a11y") or {}
    return _kv(("<html lang>", a.get("html_lang") or "not set"))


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
    # 3.4
    "SPF single record": _ev_spf_mechanisms, "SPF mechanisms": _ev_spf_mechanisms,
    "DMARC single record": _ev_dmarc_extra, "DMARC external reports": _ev_dmarc_extra,
    "MX hosts resolve": _ev_mx_hosts, "MX reverse DNS": _ev_mx_hosts,
    "Null MX on no-mail domain": _ev_null_mx,
    "MTA-STS policy MX match": _ev_mta_sts_mx, "MTA-STS max_age": _ev_mta_sts_mx,
    "Dangling CNAME": _ev_dangling, "DNSSEC algorithm": _ev_dnssec_alg, "SOA timers": _ev_soa,
    "Nameservers on IPv6": _ev_infra("ns"), "Nameserver networks": _ev_infra("ns"),
    "Nameserver RPKI": _ev_infra("ns"),
    "Mail servers on IPv6": _ev_infra("mx"), "Mail server RPKI": _ev_infra("mx"),
    "HTTPS DNS record": _ev_https_rr,
    "Legacy TLS disabled": _ev_tls_legacy, "Forward secrecy": _ev_tls_legacy,
    "Certificate key strength": _ev_cert_key,
    "CSP object-src": _ev_csp, "CSP base-uri": _ev_csp,
    "security.txt location": _ev_security_txt, "security.txt Canonical": _ev_security_txt,
    "Deprecated security headers": _ev_deprecated_headers,
    "Page language declared": _ev_lang,
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
        what, why, fix = explanation_for(label, r.get("outcome"))
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
