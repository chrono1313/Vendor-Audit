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

  - Protect against post-validation DNS rebinding. Between the time we resolve
    the domain here and the time the audit code resolves it again, the answer
    can change. A determined attacker controlling a domain's authoritative
    nameservers can serve a public IP to our resolver and an RFC1918 IP to
    the audit's resolver. Mitigations for that require pinning the resolved
    IP and passing it down through the audit (or running the whole stack
    through a TTL-respecting cache that the audit code shares). Out of scope
    for v1; the DMZ firewall is the backstop.

  - Protect against redirects to internal addresses. The audit follows one
    HTTP redirect. If a hostile public domain redirects to
    http://192.168.1.1/, we'd send a GET there. Same mitigation applies as
    for rebinding (pin and re-check on each hop). Out of scope for v1.

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
from typing import Iterable

from .. import audit  # for normalize_domain — the canonical normalizer

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

# IP networks we consider non-public. These are checked against EVERY address
# the domain resolves to (both A and AAAA). If any returned address falls in
# any of these networks, the domain is rejected.
#
# The list is intentionally broad. False positives (rejecting a domain that
# legitimately resolves to one of these ranges) are acceptable here — the
# alternative is letting an attacker target our internal network through the
# audit's HTTP fetcher.
_NON_PUBLIC_V4_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),         # "this network"
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT / RFC 6598
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local + AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),     # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
    ipaddress.ip_network("255.255.255.255/32"),# broadcast
]

_NON_PUBLIC_V6_NETS = [
    ipaddress.ip_network("::/128"),            # unspecified
    ipaddress.ip_network("::1/128"),           # loopback
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped (rejected via v4 check too)
    ipaddress.ip_network("64:ff9b::/96"),      # NAT64 (semantics depend on operator)
    ipaddress.ip_network("100::/64"),          # discard prefix
    ipaddress.ip_network("2001:db8::/32"),     # documentation
    ipaddress.ip_network("fc00::/7"),          # unique local
    ipaddress.ip_network("fe80::/10"),         # link-local
    ipaddress.ip_network("ff00::/8"),          # multicast
]


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


def validate_domain_input(raw: str) -> ValidatedDomain:
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
    addresses = _resolve_all(normalized)
    if not addresses:
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


def _is_public_address(addr: str) -> bool:
    """True if `addr` is a publicly-routable IP, false otherwise.

    `addr` must be a valid IP string; we trust _resolve_all to have given
    us valid input. If parsing fails (shouldn't happen) we treat it as
    non-public — fail-closed.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False

    # Python's stdlib has good built-in classification flags. Use them as
    # a first pass; they cover the major categories.
    if ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_unspecified or ip.is_reserved:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        if ip.is_private:
            return False
        return _not_in_any(ip, _NON_PUBLIC_V4_NETS)
    else:  # IPv6Address
        if ip.is_private or ip.is_site_local:
            return False
        return _not_in_any(ip, _NON_PUBLIC_V6_NETS)


def _not_in_any(ip, nets: Iterable[ipaddress._BaseNetwork]) -> bool:
    """True if `ip` is not contained in any of the given networks."""
    for net in nets:
        if ip in net:
            return False
    return True
