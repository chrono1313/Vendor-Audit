#!/usr/bin/env python3
"""Checks added in 3.5.17.

  - tls_hello.py, the hand-built ClientHello probes: against fake servers
    that send exact replies (a ServerHello choosing RC4 or 3DES, a
    HelloRetryRequest, an alert, a dropped connection, garbage), and
    against a real TLS server run by this Python's OpenSSL
  - obsolete ciphers, CBC suites and post-quantum key exchange, rated
  - mail server certificates, with DANE exempting self-signed ones
  - wildcard DNS, DMARC alignment, Cache-Control on cookie responses
  - known-vulnerable libraries from the retire.js data
  - image alt text, form labels, third-party scripts

Run:  python3 tests/test_more_checks.py
"""
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from datetime import date
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from vendor_audit import audit_checks as ac           # noqa: E402
from vendor_audit import audit_records                # noqa: E402
from vendor_audit import tls_hello as th              # noqa: E402
from test_new_checks import everything as sample      # noqa: E402 — every check's data

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def findings(results):
    return {f["label"]: (f["severity"], f.get("outcome")) for f in ac.assess_results(results)}


# ── Fake TLS servers ─────────────────────────────────────────────────────────

def _server_hello(cipher, *, version=th.TLS12, random=None, exts=b""):
    body = (struct.pack("!H", version) + (random or os.urandom(32)) + b"\x00"
            + struct.pack("!H", cipher) + b"\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _hrr(group):
    exts = (struct.pack("!HH", 0x002B, 2) + struct.pack("!H", th.TLS13)
            + struct.pack("!HH", 0x0033, 2) + struct.pack("!H", group))
    return _server_hello(0x1301, random=th.HRR_RANDOM, exts=exts)


ALERT = b"\x15\x03\x03\x00\x02\x02\x28"           # fatal handshake_failure


def fake_server(reply):
    """A one-shot server on 127.0.0.1 that reads the ClientHello and sends
    `reply` (bytes, a callable(hello) → bytes, or None to just close)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    got = {}

    def serve():
        try:
            c, _ = s.accept()
            c.settimeout(2)
            hello = c.recv(65536)
            got["hello"] = hello
            data = reply(hello) if callable(reply) else reply
            if data:
                c.sendall(data)
            c.close()
        except OSError:
            pass
        finally:
            s.close()
    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()[1], got


def _offered_suites(hello):
    """The cipher suites in a ClientHello record."""
    body = hello[9:]
    i = 2 + 32
    i += 1 + body[i]
    n = struct.unpack("!H", body[i:i + 2])[0]
    return [struct.unpack("!H", body[i + 2 + k:i + 4 + k])[0] for k in range(0, n, 2)]


def test_client_hello_shape():
    h = th.client_hello("example.com", th.DES3_SUITES)
    check(h[0] == 22 and h[5] == 1, "a handshake record holding a ClientHello")
    check(struct.unpack("!H", h[3:5])[0] == len(h) - 5, "record length matches")
    check(_offered_suites(h) == th.DES3_SUITES, "offers exactly the suites asked about")
    check(b"example.com" in h, "names the server (SNI)")
    check(b"example.com" not in th.client_hello("192.0.2.1", th.RC4_SUITES) and
          b"192.0.2.1" not in th.client_hello("192.0.2.1", th.RC4_SUITES), "no SNI for an address")
    h13 = th.client_hello("example.com", th.TLS13_SUITES, tls13=True, groups=list(th.PQ_GROUPS))
    check(_offered_suites(h13) == th.TLS13_SUITES, "TLS 1.3 hello offers the TLS 1.3 suites")
    check(struct.pack("!HH", 0x0033, 2) + b"\x00\x00" in h13, "TLS 1.3 hello sends an empty key_share")
    check(struct.pack("!H", 0x11EC) in h13, "TLS 1.3 hello offers X25519MLKEM768")


def test_probe_replies():
    port, got = fake_server(lambda hello: _server_hello(0x000A))
    r = th.cipher_probe("127.0.0.1", th.DES3_SUITES, port)
    check(r == {"result": "accepted", "suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "version": "TLSv1.2"},
          f"a ServerHello choosing 3DES is accepted: {r}")
    check(_offered_suites(got.get("hello", b"\x00" * 64)) == th.DES3_SUITES, "the server saw only 3DES suites")

    port, _ = fake_server(_server_hello(0xC011, version=0x0301))
    r = th.cipher_probe("127.0.0.1", th.RC4_SUITES, port)
    check(r["result"] == "accepted" and r["version"] == "TLSv1.0" and "RC4" in r["suite"],
          f"RC4 chosen at TLS 1.0 is accepted: {r}")

    port, _ = fake_server(_server_hello(0x1301))
    check(th.cipher_probe("127.0.0.1", th.RC4_SUITES, port)["result"] == "unreachable",
          "a suite we did not offer is not determined, not accepted")
    port, _ = fake_server(ALERT)
    check(th.cipher_probe("127.0.0.1", th.RC4_SUITES, port)["result"] == "refused", "an alert is refused")
    port, _ = fake_server(None)
    check(th.cipher_probe("127.0.0.1", th.RC4_SUITES, port)["result"] == "refused", "closing is refused")
    port, _ = fake_server(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    check(th.cipher_probe("127.0.0.1", th.RC4_SUITES, port)["result"] == "unreachable",
          "a reply that isn't TLS is not determined")

    # A ServerHello split across two records still parses.
    whole = _server_hello(0xC012)
    split = (b"\x16\x03\x03\x00\x0a" + whole[5:15] + b"\x16\x03\x03"
             + struct.pack("!H", len(whole) - 15) + whole[15:])
    port, _ = fake_server(split)
    check(th.cipher_probe("127.0.0.1", th.DES3_SUITES, port)["result"] == "accepted",
          "a ServerHello split across records")

    port, _ = fake_server(_hrr(0x11EC))
    check(th.pq_probe("127.0.0.1", port) == {"result": "offered", "group": "X25519MLKEM768"},
          "a HelloRetryRequest for X25519MLKEM768 is offered")
    port, _ = fake_server(_hrr(0x001D))
    check(th.pq_probe("127.0.0.1", port)["result"] == "not_offered", "a retry for x25519 is not PQ")
    port, _ = fake_server(ALERT)
    check(th.pq_probe("127.0.0.1", port)["result"] == "not_offered", "an alert: not offered")

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    closed = s.getsockname()[1]
    s.close()
    check(th.cipher_probe("127.0.0.1", th.CBC_SUITES, closed)["result"] == "unreachable",
          "nothing listening is not determined")


def _real_server(ctx):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    stop = threading.Event()

    def serve():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = s.accept()
            except OSError:
                continue
            try:
                c.settimeout(2)
                with ctx.wrap_socket(c, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass
        s.close()
    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()[1], stop


def test_against_real_openssl():
    """This Python's OpenSSL as the server: what it accepts is known."""
    with tempfile.TemporaryDirectory() as d:
        key, cert = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                            "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                           check=True, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            print("       (skipped: no openssl command)")
            return
        default = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        default.load_cert_chain(cert, key)
        aead = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        aead.load_cert_chain(cert, key)
        aead.maximum_version = ssl.TLSVersion.TLSv1_2
        aead.set_ciphers("ECDHE+AESGCM")
        p1, s1 = _real_server(default)
        p2, s2 = _real_server(aead)
        try:
            for suites, what in ((th.RC4_SUITES, "RC4"), (th.DES3_SUITES, "3DES")):
                check(th.cipher_probe("127.0.0.1", suites, p1)["result"] == "refused",
                      f"OpenSSL refuses {what}")
            r = th.cipher_probe("127.0.0.1", th.CBC_SUITES, p1)
            check(r["result"] == "accepted" and "CBC" in (r["suite"] or ""),
                  f"OpenSSL's default list accepts a CBC suite in TLS 1.2: {r}")
            check(th.cipher_probe("127.0.0.1", th.CBC_SUITES, p2)["result"] == "refused",
                  "an AES-GCM-only server refuses CBC")
            pq = th.pq_probe("127.0.0.1", p1)["result"]
            want = "offered" if ssl.OPENSSL_VERSION_INFO[:2] >= (3, 5) else "not_offered"
            check(pq == want, f"{ssl.OPENSSL_VERSION}: post-quantum {pq}, want {want}")
            check(th.pq_probe("127.0.0.1", p2)["result"] == "not_offered", "a TLS 1.2-only server: no PQ")
        finally:
            s1.set()
            s2.set()


def test_cipher_and_pq_ratings():
    base = sample()
    for legacy, label, want in (
            ({"rc4": "accepted", "des3": "accepted"}, "Obsolete ciphers", ("high", "rc4")),
            ({"rc4": "refused", "des3": "accepted"}, "Obsolete ciphers", ("medium", "3des")),
            ({"rc4": "refused", "des3": "refused"}, "Obsolete ciphers", ("pass", "refused")),
            ({"rc4": "refused", "des3": "unreachable"}, "Obsolete ciphers", None),
            ({"cbc": "accepted"}, "TLS 1.2 CBC ciphers", ("low", "cbc")),
            ({"cbc": "refused"}, "TLS 1.2 CBC ciphers", ("pass", "aead_only")),
            ({"cbc": "unreachable"}, "TLS 1.2 CBC ciphers", None),
            ({"pq": "offered"}, "Post-quantum key exchange", ("pass", "offered")),
            ({"pq": "not_offered"}, "Post-quantum key exchange", ("info", "not_offered"))):
        d = dict(base, tls_legacy={**base.get("tls_legacy", {}), **legacy})
        got = findings(d).get(label)
        check(got == want, f"{label} for {legacy}: {got}, want {want}")


def test_mail_server_certificates():
    def mx(**hosts):
        return {"mx_count": len(hosts), "results": hosts}
    ok = {"tls_version": "TLSv1.3", "cert_verified": True, "cert_remaining_pct": 60.0}
    bad = {"tls_version": "TLSv1.2", "cert_verified": False, "cert_verify_reason": "self_signed"}
    old = {"tls_version": "TLSv1.3", "cert_verified": True, "cert_remaining_pct": 4.0}
    gone = {"tls_version": None, "error": "timed out"}
    o = ac._mail_cert_outcome
    check(o(mx(a=ok, b=ok), {}) == "valid", "all valid")
    check(o(mx(a=ok, b=bad), {}) == "invalid", "one self-signed is invalid")
    check(o(mx(a=ok, b=bad), {"with_tlsa": ["b"]}) == "valid", "self-signed with a TLSA record is fine (RFC 7672)")
    check(o(mx(a=old), {}) == "renewal_overdue", "4% left is overdue")
    check(o(mx(a=gone), {}) is None, "nothing probed: not rated")
    d = dict(sample(), starttls_mx={"mx_count": 1, "results": {"mx.example.com": dict(bad, error=None)}})
    check(findings(d).get("Mail server certificates") == ("medium", "invalid"), "rated medium")


def test_wildcard_dns():
    def fake(answers):
        return lambda name, rtype, lifetime=None: answers.get(rtype, [])
    with mock.patch.object(ac, "resolve", side_effect=fake({"A": ["192.0.2.7"]})):
        r = ac.check_wildcard_dns("example.com")
    check(r["wildcard"] is True and r["addresses"] == ["192.0.2.7"] and r["name"].endswith(".example.com"),
          f"an answer for a random name is a wildcard: {r}")
    with mock.patch.object(ac, "resolve", side_effect=fake({})):
        check(ac.check_wildcard_dns("example.com")["wildcard"] is False, "no answer: no wildcard")
    with mock.patch.object(ac, "resolve", side_effect=fake({"A": ["ERROR:timeout"], "AAAA": ["ERROR:timeout"]})):
        check(ac.check_wildcard_dns("example.com")["wildcard"] is None, "both lookups failed: unknown")
    with mock.patch.object(ac, "resolve", side_effect=fake({})):
        a, b = ac.check_wildcard_dns("example.com")["name"], ac.check_wildcard_dns("example.com")["name"]
    check(a != b, "a different random name each time")
    for w, want in ((True, ("info", "wildcard")), (False, ("pass", "none")), (None, None)):
        d = dict(sample(), wildcard_dns={"wildcard": w, "name": "x", "addresses": []})
        check(findings(d).get("Wildcard DNS") == want, f"wildcard={w}: {findings(d).get('Wildcard DNS')}")


def test_dmarc_alignment():
    p = ac._parse_dmarc_record
    check(p("v=DMARC1; p=reject")["adkim"] == "r" and p("v=DMARC1; p=reject")["aspf"] == "r", "relaxed by default")
    r = p("v=DMARC1; p=reject; adkim=s; ASPF=S")
    check(r["adkim"] == "s" and r["aspf"] == "s", "strict, any case")
    base = sample()
    for tags, want in ((("s", "s"), ("pass", "strict")), (("s", "r"), ("info", "mixed")),
                       (("r", "r"), ("info", "relaxed"))):
        d = dict(base, dmarc={"present": True, "policy": "reject", "pct": 100, "sp": None, "rua": [],
                              "ruf": [], "record": "v=DMARC1; p=reject", "adkim": tags[0], "aspf": tags[1]})
        check(findings(d).get("DMARC alignment") == want, f"alignment {tags}: {findings(d).get('DMARC alignment')}")


def test_cache_control_on_cookies():
    s = ac._shared_cacheable
    check(not s({"cache_control": "private, max-age=600"}), "private")
    check(not s({"cache_control": "no-store"}), "no-store")
    check(not s({"cache_control": "public, no-cache"}), "no-cache: every reuse revalidates")
    check(s({"cache_control": "public"}), "public")
    check(s({"cache_control": "s-maxage=60"}), "s-maxage")
    check(s({"cache_control": "max-age=300"}), "max-age above 0")
    check(not s({"cache_control": "max-age=0"}), "max-age=0")
    check(not s({}), "no Cache-Control and no Expires: not explicitly cacheable")
    check(s({"expires": "Wed, 01 Jan 2031 00:00:00 GMT", "date": "Fri, 27 Nov 2026 00:00:00 GMT"}),
          "a future Expires")
    check(not s({"expires": "Thu, 19 Nov 1981 08:52:00 GMT", "date": "Fri, 27 Nov 2026 00:00:00 GMT"}),
          "a past Expires (PHP's default)")
    check(not s({"cache_control": "max-age=0", "expires": "Wed, 01 Jan 2031 00:00:00 GMT"}),
          "max-age wins over Expires")
    base = sample()
    srv = dict(base["server_header"], cookies=[{"name": "sid", "secure": True, "httponly": True, "samesite": "Lax",
                                                "path": "/", "domain": None, "infra": False, "issues": []}])
    for cc, want in (("public, max-age=3600", ("low", "shared_cacheable")), ("private", ("pass", "not_shared"))):
        d = dict(base, server_header=dict(srv, cache_control=cc))
        check(findings(d).get("Cache-Control on cookie responses") == want, f"{cc}: {findings(d)}")
    d = dict(base, server_header=dict(srv, cookies=[dict(srv["cookies"][0], infra=True)], cache_control="public"))
    check("Cache-Control on cookie responses" not in findings(d), "only CDN cookies: not rated")


def test_vulnerable_libraries():
    v = ac.check_vulnerable_libraries
    r = v('<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>')
    libs = {(x["library"], x["version"]): x for x in r["libraries"]}
    check(list(libs) == [("jquery", "3.4.1")], f"jQuery 3.4.1 from its file name, once: {list(libs)}")
    cves = {c for x in libs.get(("jquery", "3.4.1"), {}).get("vulnerabilities", []) for c in x["cve"]}
    check({"CVE-2020-11022", "CVE-2020-11023"} <= cves, f"jQuery 3.4.1's htmlPrefilter XSS CVEs: {cves}")
    check(r["worst"] == "medium", f"worst is medium: {r['worst']}")
    check(v('<script src="https://code.jquery.com/jquery-3.5.0.min.js"></script>')["libraries"] == [],
          "jQuery 3.5.0 fixed them")
    check(v("", {"jquery": "1.9.1"})["libraries"], "versions from the page patterns count too")
    check(v("", {"underscore": "1.12.0"})["libraries"][0]["library"] == "underscore.js", "names mapped to retire.js's")
    check(v("", {"ckeditor": "41.0.0"})["libraries"] == [] or
          v("", {"ckeditor": "41.0.0"})["libraries"][0]["library"] == "ckeditor5", "CKEditor 5 judged as ckeditor5")
    check(v("<p>no scripts</p>") == {"libraries": [], "worst": None}, "nothing found")
    c = ac._version_cmp
    check(c("1.9.0b1", "1.9.0") < 0 and c("3.5", "3.5.0") == 0 and c("3.10.0", "3.9.9") > 0
          and c("2.0.0-rc.1", "2.0.0") < 0, "version order")
    check(ac._clean_version("3.4.1.min") == "3.4.1" and ac._clean_version("3.4.1.slim.min") == "3.4.1",
          "build words dropped")
    full = sample()
    check(findings(full).get("Known-vulnerable libraries", (None,))[0] in ("low", "medium", "high"),
          "the sample's jQuery 1.9.1 is rated")
    d = dict(full, versioned_libs={"libraries": [], "any_eol": False,
                                   "vulnerable": {"libraries": [], "worst": None}})
    check(findings(d).get("Known-vulnerable libraries") == ("pass", "none"), "none found: pass")


def test_vulnerability_data():
    data = ac.LIBRARY_VULNS
    check(len(data) > 50 and "jquery" in data, f"retire.js data loaded ({len(data)} libraries)")
    check(all(x.get("below") for lib in data.values() for x in lib["vulnerabilities"]), "every entry has 'below'")
    check(all(x["severity"] in ("low", "medium", "high", "critical") for lib in data.values()
              for x in lib["vulnerabilities"]), "known severities")
    import json
    meta = json.load(open(ac._LIBRARY_VULNS_PATH, encoding="utf-8"))
    age = (date.today() - date.fromisoformat(meta["_generated_on"])).days
    check(age <= 365, f"library_vulns.json is {age} days old — run: python3 tools/update_vuln_data.py")


def test_page_checks():
    base = sample()
    page = dict(base.get("page_signals") or {"parsed": True})
    for a11y, label, want in (({"images_total": 5, "images_missing_alt": 0}, "Image alt text", ("pass", "all")),
                              ({"images_total": 5, "images_missing_alt": 2}, "Image alt text", ("low", "missing")),
                              ({"images_total": 0, "images_missing_alt": 0}, "Image alt text", None),
                              ({"inputs_total": 3, "inputs_unlabeled": 1}, "Form labels", ("low", "missing")),
                              ({"inputs_total": 0, "inputs_unlabeled": 0}, "Form labels", None)):
        d = dict(base, page_signals=dict(page, a11y={**page.get("a11y", {}), **a11y}))
        check(findings(d).get(label) == want, f"{label} {a11y}: {findings(d).get(label)}")
    html = ('<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
            '<script src="/js/app.js"></script><script src="https://cdn.example.com/x.js"></script>')
    p = ac.check_page_security_signals(html, "https://example.com/", "example.com")
    check(p["third_party_script_origins"] == ["www.googletagmanager.com"],
          f"other sites' scripts, not the site's own subdomains: {p['third_party_script_origins']}")
    d = dict(base, page_signals=p)
    check(findings(d).get("Third-party scripts") == ("info", "listed"), "listed as info")
    p2 = ac.check_page_security_signals('<script src="/a.js"></script>', "https://example.com/", "example.com")
    check(findings(dict(base, page_signals=p2)).get("Third-party scripts") == ("pass", "none"), "none: pass")


def test_new_checks_documented():
    labels = ["CAA allows current CA", "Obsolete ciphers", "TLS 1.2 CBC ciphers", "Post-quantum key exchange", "Mail server certificates",
              "Wildcard DNS", "DMARC alignment", "Cache-Control on cookie responses", "Known-vulnerable libraries",
              "Image alt text", "Form labels", "Third-party scripts"]
    for lb in labels:
        check(lb in ac.RUBRIC["findings"], f"{lb} in the rubric")
        check(audit_records.topic_for(lb), f"{lb} has a topic")
    deep = {"Mail server certificates", "Third-party scripts", "Image alt text", "Form labels"}
    check(deep <= ac.DEEP_ONLY_CHECKS, "the page and port-25 checks are deep-only")


def test_caa_allows_current_ca():
    """3.5.18: the current certificate's CA against the domain's CAA records."""
    # The Authority Key Identifier, read from a leaf openssl signs with its own CA.
    with tempfile.TemporaryDirectory() as d:
        j = lambda n: os.path.join(d, n)                                          # noqa: E731
        try:
            run = lambda *a: subprocess.run(list(a), check=True, capture_output=True, timeout=30)  # noqa: E731
            run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", j("ca.key"), "-out", j("ca.pem"),
                "-days", "1", "-subj", "/CN=Test CA")
            run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", j("leaf.key"), "-out", j("leaf.csr"),
                "-subj", "/CN=example.com")
            with open(j("ext"), "w") as f:
                f.write("authorityKeyIdentifier=keyid\nsubjectAltName=DNS:example.com\n")
            run("openssl", "x509", "-req", "-in", j("leaf.csr"), "-CA", j("ca.pem"), "-CAkey", j("ca.key"),
                "-CAcreateserial", "-out", j("leaf.pem"), "-days", "1", "-extfile", j("ext"))
            ski = run("openssl", "x509", "-in", j("ca.pem"), "-noout", "-ext", "subjectKeyIdentifier").stdout.decode()
            leaf = ssl.PEM_cert_to_DER_cert(open(j("leaf.pem")).read())
        except (OSError, subprocess.SubprocessError):
            print("       (skipped AKI part: no openssl command)")
            leaf = None
        if leaf:
            want = ski.split("\n", 1)[1].strip().replace(":", "").upper()
            check(ac._cert_aki(leaf) == want, f"AKI {ac._cert_aki(leaf)} should be the CA's SKI {want}")
            ca = ssl.PEM_cert_to_DER_cert(open(j("ca.pem")).read())
            check(ac._cert_aki(ca) in (None, want), "a self-signed CA's AKI is its own key, or absent")

    data = ac.CAA_IDENTIFIERS
    check(len(data["by_ski"]) > 1000, f"CCADB data loaded ({len(data['by_ski'])} CA certificates)")
    le_r12 = "00B529F22D8E6F31E89B4CAD783EFADCE90CD1D2"
    check(ac.ca_caa_names({"cert_aki": le_r12}) == (["letsencrypt.org"], "key"), "Let's Encrypt R12 by its key")
    check(ac.ca_caa_names({"cert_issuer": "WE1"})[0] == ["pki.goog"], "Google's WE1 by name")
    check(ac.ca_caa_names({"cert_issuer": "No Such CA"}) == (None, None), "an unknown CA")
    import json
    age = (date.today() - date.fromisoformat(json.load(open(ac._CAA_IDS_PATH, encoding="utf-8"))["_generated_on"])).days
    check(age <= 365, f"caa_identifiers.json is {age} days old — run: python3 tools/update_caa_data.py")

    o = ac._caa_issuer_outcome
    le = {"cert_aki": le_r12, "error": None, "cert_san_names": ["example.com"]}
    caa = lambda issue, wild=(): {"present": True, "issue": list(issue), "issue_wild": list(wild), "iodef": []}  # noqa: E731
    check(o(caa(['letsencrypt.org']), le) == "allowed", "allowed")
    check(o(caa(['LetsEncrypt.org; validationmethods=dns-01']), le) == "allowed", "parameters and case ignored")
    check(o(caa(['digicert.com']), le) == "not_allowed", "another CA only: not allowed")
    check(o(caa([';']), le) == "not_allowed", "issue \";\" allows no CA")
    check(o(caa([], wild=['digicert.com']), le) == "allowed", "only issuewild: issue is unrestricted")
    wild_le = dict(le, cert_san_names=["*.example.com", "example.com"])
    check(o(caa(['letsencrypt.org'], wild=['digicert.com']), wild_le) == "not_allowed",
          "a wildcard certificate is judged by issuewild")
    check(o(caa(['letsencrypt.org']), wild_le) == "allowed", "no issuewild: issue covers wildcards")
    check(o({"present": False, "issue": []}, le) is None, "no CAA records: not rated")
    check(o(caa(['letsencrypt.org']), {"cert_issuer": "No Such CA", "error": None}) is None, "unknown CA: not rated")
    check(o(caa(['letsencrypt.org']), dict(le, error="timed out")) is None, "no certificate: not rated")
    base = sample()
    d = dict(base, caa=caa(['digicert.com']), tls=dict(base["tls"], cert_aki=le_r12, error=None))
    check(findings(d).get("CAA allows current CA") == ("medium", "not_allowed"), f"rated: {findings(d).get('CAA allows current CA')}")


TESTS = [test_client_hello_shape, test_probe_replies, test_against_real_openssl, test_cipher_and_pq_ratings,
         test_mail_server_certificates, test_wildcard_dns, test_dmarc_alignment, test_cache_control_on_cookies,
         test_vulnerable_libraries, test_vulnerability_data, test_page_checks, test_new_checks_documented,
         test_caa_allows_current_ca]


def run():
    for fn in TESTS:
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nFAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll 3.5.17 check tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
