"""vendor_audit.tls_hello — hand-built TLS ClientHello probes (3.5.17).

Some questions about a server's TLS can't be asked through Python's ssl
module: OpenSSL 3 can no longer offer RC4 or 3DES at all, and Python has
no way to choose the key-exchange groups it offers. These probes build the
ClientHello by hand instead.

Each probe is ONE connection. It sends one ClientHello that offers only
the thing being asked about, reads the server's first reply, and closes:

  - a ServerHello naming one of the offered cipher suites: accepted
  - a HelloRetryRequest naming one of the offered groups: offered
  - an alert, or the connection closed: refused

No handshake is completed and no keys are exchanged, so there is nothing
to decrypt and no cryptography is needed. Scanners that list a server's
every cipher suite (SSL Labs, testssl.sh) make dozens of these; asking
yes-or-no for one group of suites takes one.

References: RFC 8446 §4.1.2–4.1.4 (ClientHello, ServerHello,
HelloRetryRequest), §4.2 (extensions); RFC 5246 §7.4.1 (TLS 1.2).
"""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time

# RFC 8446 §4.1.3: a ServerHello with this random is a HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

SUITE_NAMES = {
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
RC4_SUITES = [0xC011, 0xC007, 0x0005, 0x0004]
DES3_SUITES = [0xC012, 0xC008, 0x0016, 0x000A]
CBC_SUITES = [0xC027, 0xC028, 0xC023, 0xC024, 0xC013, 0xC014, 0xC009, 0xC00A,
              0x003C, 0x003D, 0x002F, 0x0035, 0x0067, 0x006B, 0x0033, 0x0039]
TLS13_SUITES = [0x1301, 0x1302, 0x1303]

# Hybrid post-quantum groups (IANA TLS Supported Groups registry).
PQ_GROUPS = {0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024"}
_CLASSIC_GROUPS = [0x001D, 0x0017, 0x0018]          # x25519, secp256r1, secp384r1
_SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201]

TLS10, TLS12, TLS13 = 0x0301, 0x0303, 0x0304
_MAX_MESSAGE = 1 << 16


def _u8(n):
    return struct.pack("!B", n)


def _u16(n):
    return struct.pack("!H", n)


def _vec16(b):
    return _u16(len(b)) + b


def _ext(kind, body=b""):
    return _u16(kind) + _vec16(body)


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def client_hello(host, suites, *, tls13=False, groups=None, random=None):
    """The bytes of one ClientHello record.

    tls13=False: a TLS 1.2 ClientHello (RFC 5246) offering `suites`; the
    server may answer at TLS 1.2 or lower. tls13=True: a TLS 1.3-only
    ClientHello (RFC 8446) offering `groups` with no key share, so a server
    that supports one of them must answer with a HelloRetryRequest."""
    random = random or os.urandom(32)
    exts = b""
    if host and not _is_ip(host):
        name = host.encode("idna") if not host.isascii() else host.encode()
        exts += _ext(0x0000, _vec16(_u8(0) + _vec16(name)))                       # server_name
    exts += _ext(0x000A, _vec16(b"".join(_u16(g) for g in (groups or _CLASSIC_GROUPS))))  # supported_groups
    exts += _ext(0x000D, _vec16(b"".join(_u16(a) for a in _SIG_ALGS)))           # signature_algorithms
    if tls13:
        exts += _ext(0x002B, _u8(2) + _u16(TLS13))                                # supported_versions
        exts += _ext(0x002D, _u8(1) + _u8(1))                                     # psk_key_exchange_modes
        exts += _ext(0x0033, _vec16(b""))                                         # key_share: none
        session_id = os.urandom(32)                                               # RFC 8446 §D.4
    else:
        exts += _ext(0x000B, _u8(1) + _u8(0))                                     # ec_point_formats
        exts += _ext(0x0017)                                                      # extended_master_secret
        exts += _ext(0xFF01, _u8(0))                                              # renegotiation_info
        session_id = b""
    body = (_u16(TLS12) + random + _u8(len(session_id)) + session_id
            + _vec16(b"".join(_u16(s) for s in suites)) + _u8(1) + _u8(0) + _vec16(exts))
    handshake = _u8(1) + struct.pack("!I", len(body))[1:] + body
    return _u8(22) + _u16(TLS10) + _vec16(handshake)


def _recv(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def read_reply(sock, deadline):
    """("alert", description) or ("handshake", type, body) for the server's
    first message. Raises EOFError if the server closes, ValueError on
    something that is not TLS."""
    hs = b""
    while True:
        ctype, version, length = struct.unpack("!BHH", _recv(sock, 5, deadline))
        if version >> 8 != 3 or length > 18432:
            raise ValueError("not a TLS record")
        payload = _recv(sock, length, deadline)
        if ctype == 21:
            if len(payload) < 2:
                raise ValueError("short alert")
            return ("alert", payload[1])
        if ctype != 22:
            raise ValueError(f"unexpected record type {ctype}")
        hs += payload
        if len(hs) >= 4:
            n = int.from_bytes(hs[1:4], "big")
            if n > _MAX_MESSAGE:
                raise ValueError("handshake message too long")
            if len(hs) >= 4 + n:
                return ("handshake", hs[0], hs[4:4 + n])


def parse_server_hello(body):
    """{"version", "cipher", "hrr", "extensions": {type: bytes}} from a
    ServerHello (or HelloRetryRequest) body."""
    version = int.from_bytes(body[0:2], "big")
    random = body[2:34]
    i = 34
    sid_len = body[i]
    i += 1 + sid_len
    cipher = int.from_bytes(body[i:i + 2], "big")
    i += 3                                              # cipher suite, compression method
    exts = {}
    if i + 2 <= len(body):
        end = i + 2 + int.from_bytes(body[i:i + 2], "big")
        i += 2
        while i + 4 <= end:
            kind, n = struct.unpack("!HH", body[i:i + 4])
            exts[kind] = body[i + 4:i + 4 + n]
            i += 4 + n
    sv = exts.get(0x002B)
    if sv and len(sv) >= 2:
        version = int.from_bytes(sv[:2], "big")         # RFC 8446 §4.2.1
    return {"version": version, "cipher": cipher, "hrr": random == HRR_RANDOM, "extensions": exts}


def _exchange(host, port, hello, timeout):
    """("reply", kind, …) | ("refused",) | ("unreachable",) for one probe."""
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return ("unreachable",)
    try:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        sock.sendall(hello)
        return ("reply",) + read_reply(sock, deadline)
    except (EOFError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return ("refused",)              # closed on the ClientHello
    except (OSError, ValueError):
        return ("unreachable",)          # timed out, or not TLS: not determined
    finally:
        try:
            sock.close()
        except OSError:
            pass


_VERSION_NAMES = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}


def cipher_probe(host, suites, port=443, timeout=1.5):
    """Does the server accept any of `suites`? One connection.

    {"result": "accepted" | "refused" | "unreachable", "suite": name or None,
     "version": "TLSv1.2" or None}"""
    got = _exchange(host, port, client_hello(host, suites), timeout)
    out = {"result": "unreachable", "suite": None, "version": None}
    if got[0] in ("refused", "unreachable"):
        out["result"] = got[0]
    elif got[1] == "alert":
        out["result"] = "refused"
    elif got[2] == 2:                                   # ServerHello
        try:
            sh = parse_server_hello(got[3])
        except (IndexError, ValueError):
            return out
        if sh["cipher"] in suites and not sh["hrr"]:
            out.update(result="accepted", suite=SUITE_NAMES.get(sh["cipher"], f"0x{sh['cipher']:04X}"),
                       version=_VERSION_NAMES.get(sh["version"]))
        # A suite we did not offer is a broken server: not determined.
    return out


def pq_probe(host, port=443, timeout=1.5):
    """Does the server offer a hybrid post-quantum key exchange in TLS 1.3?
    One connection; the ClientHello names only the PQ groups and sends no
    key share, so a server that supports one answers with a
    HelloRetryRequest naming it.

    {"result": "offered" | "not_offered" | "unreachable", "group": name or None}"""
    got = _exchange(host, port, client_hello(host, TLS13_SUITES, tls13=True, groups=list(PQ_GROUPS)), timeout)
    out = {"result": "unreachable", "group": None}
    if got[0] == "refused" or (got[0] == "reply" and got[1] == "alert"):
        out["result"] = "not_offered"
    elif got[0] == "reply" and got[2] == 2:
        try:
            sh = parse_server_hello(got[3])
        except (IndexError, ValueError):
            return out
        ks = sh["extensions"].get(0x0033) or b""
        group = int.from_bytes(ks[:2], "big") if len(ks) >= 2 else None
        if sh["hrr"] and group in PQ_GROUPS:
            out.update(result="offered", group=PQ_GROUPS[group])
        else:
            out["result"] = "not_offered"
    return out
