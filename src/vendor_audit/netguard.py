"""vendor_audit.netguard — which addresses the web service may connect to.

Two layers use the same rules:

  * web/validate.py rejects a domain at input time when it resolves to a
    non-public address (a 400 before any audit work starts).

  * install() guards every connection an audit makes in the web service's
    worker processes. It wraps socket.getaddrinfo, which every outbound
    connection in the audit goes through (socket.create_connection, and so
    httpx, smtplib and the raw TLS probe), and drops non-public addresses
    from each answer. The check runs on the same lookup the connection then
    uses, so a domain that resolves to a public address at input time and a
    private one a moment later (DNS rebinding) is still refused, and so is
    every redirect hop. When nothing public is left the lookup fails with
    NonPublicAddressError and that one check reports it as an error.

install() also removes proxy settings (HTTPS_PROXY and the like) from the
worker's environment. Through a forward proxy the worker would connect to
the proxy, not the audited site, and the check above would only ever see
the proxy's address. The site's audits connect directly.

The command-line tool doesn't install the guard: auditing your own internal
names from your own machine is a legitimate use.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Iterable

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


def is_public_address(addr: str) -> bool:
    """True if `addr` is a publicly-routable IP, false otherwise.

    A string that doesn't parse as an IP address is treated as non-public —
    fail-closed.
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


class NonPublicAddressError(socket.gaierror):
    """A lookup returned only addresses the service must not connect to."""


_real_getaddrinfo = socket.getaddrinfo


def _guarded_getaddrinfo(host, port, *args, **kwargs):
    results = _real_getaddrinfo(host, port, *args, **kwargs)
    if host is None:
        return results                      # a local bind, not a connection
    kept = [r for r in results if is_public_address(r[4][0].split("%", 1)[0])]
    if not kept:
        name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
        raise NonPublicAddressError(
            socket.EAI_NONAME, f"{name} resolves only to non-public addresses; not connecting")
    return kept


# Environment variables HTTP clients (httpx, urllib) read proxy settings from.
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


def install() -> None:
    """Guard every connection in this process. Safe to call more than once."""
    for name in _PROXY_VARS:
        os.environ.pop(name, None)
        os.environ.pop(name.lower(), None)
    socket.getaddrinfo = _guarded_getaddrinfo


def installed() -> bool:
    return socket.getaddrinfo is _guarded_getaddrinfo
