"""vendor_audit.web.validate — input validation and SSRF guard.

This module is the security perimeter of the web layer. Every code path that
takes user input MUST funnel through validate_domain_input() before any audit
work is started. The guarantees the validator provides:

  1. The input parses to a valid registrable domain (not an IP literal,
     not localhost, not a single label, not an empty string).

  2. The domain resolves to at least one address that is publicly routable
     (not RFC1918, not loopback, not link-local, not unique-local v6, not
     cloud-metadata).

  3. The string handed back to the caller is a normalized ASCII (Punycode)
     domain — safe to feed to dnspython, httpx, and ssl.

The validator does NOT:

  - Protect against post-validation DNS rebinding or redirects to internal
    addresses by itself. Between this lookup and the audit's own, the answer
    can change, and a public site can redirect to http://192.168.1.1/. The
    web service's audit workers close both by checking every connection's
    addresses at connect time (vendor_audit.netguard.install), on each
    redirect hop too. The DMZ firewall remains the backstop.

  - Validate that the domain is "safe to scan" in any policy sense. We block
    obviously-internal targets; we do not block "things you shouldn't
    scan." Vendor Audit is passive (no active probing) and the project's
    stated scope is that it's safe to run against any third party.

The threats this module DOES address are SSRF-via-input-spoofing: a user
submitting "localhost" or "192.168.1.1" or a domain whose A record happens
to point inside our network. Those are caught here and rejected with a 400
before any audit code sees the input.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from .. import audit  # for normalize_domain — the canonical normalizer
from ..netguard import is_public_address

# ── Configuration constants ──────────────────────────────────────────────────

# DNS limits an FQDN to 253 ASCII chars. Allow a bit of slop for messy input
# (trailing dots, schemes, paths) before normalization strips them.
_MAX_INPUT_LENGTH = 512

# After normalization, the domain itself must fit in DNS limits. 253 is the
# spec ceiling; some real-world tools cap lower, but 253 is correct.
_MAX_NORMALIZED_LENGTH = 253

# Characters allowed in a raw input. Permissive — we accept URLs, mixed case,
# Unicode (handled by normalize_domain via IDNA). This is just a sanity gate
# against control characters and obvious junk.
#
# Why a regex and not "anything not-control": Unicode classes are large and
# the validator's job here is to fail fast on inputs that clearly aren't
# domains, not to be exhaustive. The IDNA encoder downstream is the real
# arbiter for Unicode.
_RAW_INPUT_PATTERN = re.compile(
    r"^[\x20-\x7E\u00A0-\uFFFF]+$"  # printable ASCII + a chunk of BMP
)

# The address rules live in vendor_audit.netguard, shared with the
# connect-time guard the web service's audit workers install.


# ── Public API ───────────────────────────────────────────────────────────────

class ValidationError(ValueError):
    """Raised when input fails any validation step.

    Carries a `code` attribute so the web layer can decide how to render
    the error (and so logs can group similar failures). The `message` is
    safe to show to the user; it never leaks internal details.
    """
    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ValidatedDomain:
    """The result of a successful validation."""
    domain: str             # normalized ASCII (Punycode) domain
    original: str           # the raw input as received
    addresses: tuple[str, ...]  # IPs the domain resolved to, for logging


def validate_domain_input(raw: str, *, dns_check: bool = True) -> ValidatedDomain:
    """Validate user input and return a ValidatedDomain on success.

    Raises ValidationError with one of these codes:
      empty            input was empty / whitespace
      too_long         input or normalized form exceeded length cap
      bad_charset      input contained control chars or other junk
      not_a_domain     input parsed to something that isn't a registrable domain
                       (single label, IP literal, empty after normalization, etc.)
      cannot_resolve   the DNS lookup returned no addresses
      non_public       the domain resolves to an internal / reserved / loopback
                       address (this is the SSRF guard)

    On success returns a ValidatedDomain. The web layer then passes
    .domain to safe_run_audit().

    With dns_check=False, layers 1-3 (shape, normalization, IP-rejection)
    run normally but layer 4 (DNS resolution + SSRF guard) is skipped.
    The returned ValidatedDomain has an empty addresses tuple. This mode
    is for callers that need fast pre-flight validation without the
    network round-trip — typically as a feasibility check before showing
    a "loading" UI; the full validation runs again on the path that
    actually does the audit.
    """
    # Layer 1: shape — cheap, no I/O.
    if raw is None:
        raise ValidationError("Please enter a domain to audit.", code="empty")
    raw = raw.strip()
    if not raw:
        raise ValidationError("Please enter a domain to audit.", code="empty")
    if len(raw) > _MAX_INPUT_LENGTH:
        raise ValidationError(
            f"Input is too long (limit {_MAX_INPUT_LENGTH} characters).",
            code="too_long",
        )
    if not _RAW_INPUT_PATTERN.match(raw):
        raise ValidationError(
            "Input contains characters that aren't allowed in a domain name.",
            code="bad_charset",
        )

    # Layer 2: normalization. Use the same normalizer the CLI uses, so what
    # the web layer audits is exactly what the CLI would audit for the same
    # input. normalize_domain never raises (by design), but it can return an
    # empty string or a malformed domain on weird input.
    try:
        normalized = audit.normalize_domain(raw)
    except Exception as exc:
        # Defensive — normalize_domain is documented as never-raises, but if
        # an idna corner case slips through we want a clean rejection.
        raise ValidationError(
            "Could not parse the input as a domain name.",
            code="not_a_domain",
        ) from exc

    if not normalized:
        raise ValidationError(
            "Could not parse the input as a domain name.",
            code="not_a_domain",
        )
    if len(normalized) > _MAX_NORMALIZED_LENGTH:
        raise ValidationError(
            "The domain name is too long.",
            code="too_long",
        )

    # Layer 3: shape after normalization. Reject IP literals, single labels,
    # and obviously bogus values. tldextract is the tool of choice for the
    # "is this a registrable domain" question, but for v1 a simpler pair of
    # checks is enough:
    #   - rejects "localhost" (no dot)
    #   - rejects "192.168.1.1" (parses as IP)
    #   - rejects "[::1]" (parses as IP after bracket strip — but
    #     normalize_domain already strips ports, not brackets, so we do it
    #     here)
    candidate = normalized.strip("[]")
    if _looks_like_ip(candidate):
        raise ValidationError(
            "Please enter a domain name, not an IP address.",
            code="not_a_domain",
        )
    if "." not in normalized:
        raise ValidationError(
            "Please enter a full domain name (e.g. example.com).",
            code="not_a_domain",
        )

    # Layer 4: SSRF guard. Resolve the domain HERE and reject if any answer
    # is a non-public address. This is a pre-flight resolution; the audit
    # itself will resolve again via dnspython, and an attacker controlling
    # the authoritative nameserver could in theory return different answers
    # to the two resolvers (DNS rebinding). That's a known gap — see module
    # docstring. The DMZ firewall is the second line of defense.
    if not dns_check:
        # Caller asked to skip DNS — return shape-only result. addresses
        # is empty tuple to make this fact obvious to consumers (passing
        # such a ValidatedDomain into safe_run_audit would normally not
        # happen because the next call to validate_domain_input on the
        # same input would re-check DNS).
        return ValidatedDomain(
            domain=normalized,
            original=raw,
            addresses=tuple(),
        )

    addresses = _resolve_all(normalized)

    # www-fallback (1.1): some domains (notably gov sites whose registrars
    # can't ALIAS the apex to a CDN — see sutherlinoregon.gov) publish A
    # records only on the www variant. The apex still hosts MX/SPF/DMARC
    # records, so it IS a real, auditable domain — just not for the web
    # checks at the apex itself. Accept the apex as the canonical domain
    # if www.<apex> resolves to a public address; the audit orchestrator
    # routes web checks at www in that case and the www-and-apex-unification
    # check flags the missing apex record as a finding.
    if not addresses and not normalized.startswith("www."):
        www_candidate = "www." + normalized
        www_addresses = _resolve_all(www_candidate)
        if www_addresses:
            addresses = www_addresses

    if not addresses:
        # No A/AAAA — but the domain may still be a legitimate audit target
        # if it's mail-only (MX records, no website). Examples: a dedicated
        # mail-receiving subdomain like records.example.com, or a domain that
        # exists purely for email. We check for MX before rejecting; if MX
        # exists, we accept the domain with an empty addresses tuple and let
        # the audit proceed — the scorer skips the web-side rubric for a
        # no-web-presence domain and audits email / DNS / mail-transport
        # normally.
        if _has_mx(normalized):
            return ValidatedDomain(
                domain=normalized,
                original=raw,
                addresses=(),   # mail-only: no web address, and that's fine
            )
        raise ValidationError(
            f"{normalized} did not resolve to any address.",
            code="cannot_resolve",
        )
    for addr in addresses:
        if not _is_public_address(addr):
            raise ValidationError(
                "That domain resolves to a non-public address and cannot be audited.",
                code="non_public",
            )

    return ValidatedDomain(
        domain=normalized,
        original=raw,
        addresses=tuple(addresses),
    )


# ── Internals ────────────────────────────────────────────────────────────────

def _looks_like_ip(s: str) -> bool:
    """True if the string parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _resolve_all(domain: str) -> list[str]:
    """Return all A and AAAA addresses for the domain, as strings.

    Uses socket.getaddrinfo with a short timeout via socket.setdefaulttimeout
    is not great (it's process-wide). Instead we rely on the system resolver
    being snappy on a healthy VM; if it isn't, the worst case is a slow 400.
    The audit itself uses dnspython and has its own timeouts; this function
    is just for the validation pre-flight.

    Returns an empty list on NXDOMAIN / SERVFAIL / no records. Does not
    raise — the caller distinguishes empty (cannot_resolve) from non-empty.
    """
    try:
        infos = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for fam, _socktype, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        # IPv6 sockaddr is (host, port, flowinfo, scopeid); host is what we want.
        if addr in seen:
            continue
        seen.add(addr)
        out.append(addr)
    return out


def _has_mx(domain: str) -> bool:
    """True if the domain publishes at least one usable MX record.

    Used to accept mail-only domains (no A/AAAA but real MX) as auditable
    rather than rejecting them as unresolvable. A Null MX (RFC 7505 — a
    single '0 .' record) is an explicit declaration of no mail and does
    NOT count: such a domain has neither web nor mail and isn't a useful
    audit target, so it should still get the cannot_resolve rejection.

    Uses dnspython (already a project dependency) with a short timeout.
    Returns False on any error — fail-closed, so a resolver hiccup means
    the domain is rejected as unresolvable rather than accepted on a
    maybe. That's the safe default for the validation perimeter.
    """
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 4.0
        answers = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        if answers.rrset is None:
            return False
        for rdata in answers:
            parts = str(rdata).split()
            # Null MX is "0 ." — preference 0, target a bare dot.
            if len(parts) == 2 and parts[0] == "0" and parts[1] in (".", ""):
                continue  # explicit no-mail declaration; not a real MX
            # Any non-null MX record counts.
            return True
        return False
    except Exception:
        return False


_is_public_address = is_public_address
