#!/usr/bin/env python3
"""Checks added in 3.4, run against a fake DNS zone (no network).

Each check is tested where its data is collected, where it is rated, and
on the .txt line that reports it.

Run:  python3 tests/test_new_checks.py
"""
import contextlib
import copy
import os
import re
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from vendor_audit import audit_checks as ac           # noqa: E402
from vendor_audit import audit_txt_report as atr      # noqa: E402
from test_findings import sample                      # noqa: E402

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


@contextlib.contextmanager
def zone(records):
    """Answer resolve() from `records`: {(name, TYPE): [values] | "ERROR:..."}.
    Names not listed answer nothing (NXDOMAIN / no data)."""
    def fake(name, rtype, lifetime=None):
        key = (name.rstrip(".").lower(), rtype.upper())
        val = records.get(key, [])
        return [val] if isinstance(val, str) else list(val)
    with mock.patch.object(ac, "resolve", side_effect=fake):
        ac._spf_cache.clear()
        yield


def findings(results):
    return {f["label"]: f["severity"] for f in ac.assess_results(results)}


def detail(results, domain="example.com"):
    data = atr._ReportData(domain, domain, results, "2026-11-20T00:00:00Z", "3.4.0")
    return atr.strip_tags(atr.render_detail_sections(data))


def line(text, word, phrase):
    return re.search(rf"^\s+{word}\s+.*{re.escape(phrase)}", text, re.M) is not None


# ── Email ────────────────────────────────────────────────────────────────────

def test_spf_records_and_mechanisms():
    with zone({("example.com", "TXT"): ["v=spf1 -all", "v=spf1 include:_spf.example.net -all"]}):
        r = ac.check_spf("example.com")
    check(r.get("record_count") == 2, f"two SPF records should be counted: {r}")

    with zone({("example.com", "TXT"): ["v=spf1 include:gone.example.net mx ptr -all"]}):
        r = ac.check_spf("example.com")
    check(r.get("missing_includes") == ["gone.example.net"], f"include without SPF: {r}")
    check(r.get("void_lookups") == 2, f"the include and the bare mx (no MX) are void lookups: {r}")
    check(r.get("uses_ptr") is True, "ptr should be noticed")

    with zone({("example.com", "TXT"): ["v=spf1 a:x1.example.com a:x2.example.com a:x3.example.com -all"],
               ("example.com", "MX"): ["10 mx.example.com"]}):
        r = ac.check_spf("example.com")
    check(r.get("void_lookups") == 3 and not r.get("missing_includes"), f"three a: names with no address: {r}")

    with zone({("example.com", "TXT"): ["v=spf1 a:x.example.com -all"],
               ("x.example.com", "A"): "ERROR:timeout"}):
        r = ac.check_spf("example.com")
    check(r.get("void_lookups") == 0, "a DNS error is not a void lookup")

    d = sample()
    for spf, want in (({"record_count": 2}, ("SPF single record", "high")),
                      ({"missing_includes": ["x"], "void_lookups": 1}, ("SPF mechanisms", "high")),
                      ({"void_lookups": 3}, ("SPF mechanisms", "medium")),
                      ({"void_lookups": 0, "uses_ptr": True}, ("SPF mechanisms", "low")),
                      ({"void_lookups": 0, "record_count": 1}, ("SPF mechanisms", "pass"))):
        d["spf"] = {"status": "hardfail", "record": "v=spf1 -all", "lookup_count": 1, **spf}
        got = findings(d).get(want[0])
        check(got == want[1], f"{spf}: {want[0]} should be {want[1]}, got {got}")
    d["spf"] = {"status": "hardfail", "record": "v=spf1 -all", "lookup_count": 1, "record_count": 2,
                "void_lookups": 3, "missing_includes": []}
    txt = detail(d)
    check(line(txt, "HIGH", "2 SPF records published"), "multiple-records line should read HIGH")
    check(line(txt, "MEDIUM", "3 SPF lookups return nothing"), "void-lookup line should read MEDIUM")


def test_dmarc_records_and_external_reports():
    rec = "v=DMARC1; p=reject; rua=mailto:d@reports.vendor.net,mailto:me@example.com"
    with zone({("_dmarc.example.com", "TXT"): [rec, "v=DMARC1; p=none"]}):
        r = ac.check_dmarc("example.com")
    check(r.get("record_count") == 2, f"two DMARC records: {r.get('record_count')}")
    ext = r.get("rua_external") or []
    check([e["domain"] for e in ext] == ["reports.vendor.net"], f"only the outside address is checked: {ext}")
    check(ext and ext[0]["authorized"] is False, "no authorization record → not authorized")

    with zone({("_dmarc.example.com", "TXT"): [rec],
               ("example.com._report._dmarc.reports.vendor.net", "TXT"): ["v=DMARC1"]}):
        r = ac.check_dmarc("example.com")
    check(r["rua_external"][0]["authorized"] is True, "authorization record → authorized")
    check(r.get("record_count") == 1, "one record")

    d = sample()
    d["dmarc"] = {"present": True, "policy": "reject", "pct": 100, "rua": ["mailto:d@reports.vendor.net"],
                  "record_count": 2, "record": rec,
                  "rua_external": [{"address": "d@reports.vendor.net", "domain": "reports.vendor.net",
                                    "authorized": False}]}
    f = findings(d)
    check(f.get("DMARC single record") == "high", f"multiple DMARC → high, got {f.get('DMARC single record')}")
    check(f.get("DMARC external reports") == "low", "unauthorized reports → low")
    txt = detail(d)
    check(line(txt, "LOW", "Reports to reports.vendor.net are not authorized"), "unauthorized line should read LOW")


def test_mx_hosts_and_reverse_dns():
    z = {("example.com", "MX"): ["10 mx1.example.com.", "20 gone.example.com."],
         ("mx1.example.com", "A"): ["192.0.2.10"],
         ("10.2.0.192.in-addr.arpa", "PTR"): ["mail.example.net."],
         ("mail.example.net", "A"): ["192.0.2.99"]}
    with zone(z):
        r = ac.check_mx("example.com")
    hosts = r.get("mx_hosts") or {}
    check(hosts.get("gone.example.com", {}).get("resolves") is False, f"host with no address: {hosts}")
    check(hosts.get("mx1.example.com", {}).get("resolves") is True, "host with an address")
    ptr = (hosts.get("mx1.example.com") or {}).get("ptr") or [{}]
    check(ptr[0].get("name") == "mail.example.net" and ptr[0].get("confirmed") is False,
          f"reverse name that resolves elsewhere is not confirmed: {ptr}")
    z[("mail.example.net", "A")] = ["192.0.2.10"]
    with zone(z):
        r = ac.check_mx("example.com")
    check(r["mx_hosts"]["mx1.example.com"]["ptr"][0]["confirmed"] is True, "matching reverse DNS is confirmed")

    d = sample()
    d["mx"] = {"entries": [{"priority": 10, "host": "mx1.example.com"}, {"priority": 20, "host": "gone.example.com"}],
               "null_mx": False, "mx_targets_ip": [], "mx_targets_cname": [],
               "mx_hosts": {"mx1.example.com": {"v4": ["192.0.2.10"], "v6": [], "resolves": True,
                                                "ptr": [{"address": "192.0.2.10", "name": None, "confirmed": False}]},
                            "gone.example.com": {"v4": [], "v6": [], "resolves": False, "ptr": []}}}
    f = findings(d)
    check(f.get("MX hosts resolve") == "high", f"missing MX host → high, got {f.get('MX hosts resolve')}")
    check(f.get("MX reverse DNS") == "low", "missing reverse DNS → low")
    txt = detail(d)
    check(line(txt, "HIGH", "MX host gone.example.com has no A or AAAA record"), "missing host line reads HIGH")
    check(line(txt, "LOW", "Mail server reverse DNS missing"), "reverse DNS line reads LOW")


def test_null_mx():
    d = sample()
    d["mx"] = {"entries": [], "null_mx": False, "mx_targets_ip": [], "mx_targets_cname": []}
    check(findings(d).get("Null MX on no-mail domain") == "medium", "no MX at all → medium")
    check(line(detail(d), "MEDIUM", "No MX records and no null MX"), "null MX line reads MEDIUM")
    d["mx"] = {"entries": [], "null_mx": True}
    check(findings(d).get("Null MX on no-mail domain") == "pass", "null MX → pass")
    d = sample()
    check("Null MX on no-mail domain" not in findings(d), "a domain with MX is not rated")


def test_mta_sts_mx_match_and_max_age():
    m = ac._mx_pattern_match
    check(m("*.example.com", "mx1.example.com"), "wildcard covers one label")
    check(not m("*.example.com", "a.b.example.com"), "wildcard covers only one label")
    check(not m("*.example.com", "example.com"), "wildcard does not cover the bare name")
    check(m("MX.Example.com.", "mx.example.com"), "match ignores case and the trailing dot")

    d = sample()
    d["mx"] = {"entries": [{"priority": 10, "host": "mx1.example.com"}, {"priority": 20, "host": "backup.other.net"}],
               "null_mx": False}
    d["mta_sts"] = {"present": True, "id": "1"}
    for mode, sev in (("enforce", "high"), ("testing", "medium")):
        d["mta_sts_policy"] = {"fetched": True, "mode": mode, "max_age": 86400, "mx": ["*.example.com"], "problems": []}
        f = findings(d)
        check(f.get("MTA-STS policy MX match") == sev, f"{mode}: uncovered MX → {sev}, got {f.get('MTA-STS policy MX match')}")
        check(f.get("MTA-STS max_age") == "low", "a one-day max_age → low")
    txt = detail(d)
    check(line(txt, "MEDIUM", "MTA-STS policy does not name every MX host"), "MX match line reads MEDIUM")
    check(line(txt, "LOW", "MTA-STS max_age 86400"), "max_age line reads LOW")
    d["mta_sts_policy"] = {"fetched": True, "mode": "enforce", "max_age": 1209600,
                           "mx": ["*.example.com", "backup.other.net"], "problems": []}
    f = findings(d)
    check(f.get("MTA-STS policy MX match") == "pass" and f.get("MTA-STS max_age") == "pass", f"covered policy: {f}")
    d["mta_sts_policy"] = {"fetched": True, "mode": "none", "max_age": 60, "mx": [], "problems": []}
    check("MTA-STS policy MX match" not in findings(d), "mode none: nothing to match")


# ── DNS and routing ──────────────────────────────────────────────────────────

class _FakeResolver:
    """resolve(name, rtype) from {(name, TYPE): target | "NXDOMAIN" | "ERROR"}."""
    def __init__(self, table):
        self.table = table

    def resolve(self, name, rtype, raise_on_no_answer=True):
        import dns.resolver
        val = self.table.get((name.rstrip(".").lower(), rtype))
        if val == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        if val == "ERROR":
            raise dns.resolver.Timeout()

        class _T:
            def __init__(self, t):
                self.target = mock.Mock(to_text=lambda: t + ".")

        class _A:
            rrset = [_T(val)] if (val and rtype == "CNAME") else ([val] if val else None)
        return _A()


def test_dangling_cname():
    table = {("example.com", "CNAME"): None, ("example.com", "A"): "192.0.2.1",
             ("www.example.com", "CNAME"): "old-site.azurewebsites.net",
             ("old-site.azurewebsites.net", "CNAME"): None,
             ("old-site.azurewebsites.net", "A"): "NXDOMAIN"}
    with mock.patch.object(ac, "_get_resolver", return_value=_FakeResolver(table)):
        r = ac.check_dangling_cname("example.com")
    check(r["dangling"] == ["www.example.com"], f"www → deleted target is dangling: {r}")
    table[("old-site.azurewebsites.net", "A")] = "192.0.2.5"
    with mock.patch.object(ac, "_get_resolver", return_value=_FakeResolver(table)):
        r = ac.check_dangling_cname("example.com")
    check(not r["dangling"] and r["names"]["www.example.com"]["end"] == "ok", "existing target is fine")
    table[("old-site.azurewebsites.net", "A")] = "ERROR"
    with mock.patch.object(ac, "_get_resolver", return_value=_FakeResolver(table)):
        r = ac.check_dangling_cname("example.com")
    check(not r["dangling"], "a timeout is not dangling")

    d = sample()
    d["dangling_cname"] = {"names": {"www.example.com": {"chain": ["old-site.azurewebsites.net"], "end": "nxdomain"},
                                     "example.com": {"chain": [], "end": "none"}},
                           "dangling": ["www.example.com"]}
    check(findings(d).get("Dangling CNAME") == "high", "dangling → high")
    check(line(detail(d), "HIGH", "old-site.azurewebsites.net — the target does not exist"), "dangling line reads HIGH")


def test_dnssec_algorithm_and_soa():
    d = sample()
    d["dnssec"] = {"tld": {"signed": True, "tld": "com"},
                   "domain": {"dnskey": True, "ad_flag": True, "algorithms": [5]}}
    check(findings(d).get("DNSSEC algorithm") == "medium", "SHA-1 only → medium")
    check(line(detail(d), "MEDIUM", "5 (RSASHA1) — must not be used"), "algorithm line reads MEDIUM")
    d["dnssec"]["domain"]["algorithms"] = [5, 13]
    check(findings(d).get("DNSSEC algorithm") == "pass", "a rollover to 13 validates")
    d["dnssec"]["domain"]["algorithms"] = [10]
    check(findings(d).get("DNSSEC algorithm") == "low", "RSASHA512 → low")

    with zone({("example.com", "DNSKEY"): ["257 3 13 AAAA", "256 3 13 BBBB"]}), \
         mock.patch.object(ac, "udp_query", return_value=None):
        r = ac.check_dnssec("example.com")
    check(r["domain"].get("algorithms") == [13], f"algorithms read from DNSKEY: {r['domain']}")

    soa = {"primary": "ns1", "admin": "h", "serial": 1, "refresh": 3600, "retry": 7200,
           "expire": 259200, "minimum": 172800}
    issues = ac._soa_issues(soa)
    check(len(issues) == 3, f"retry ≥ refresh, short expire, long minimum: {issues}")
    d["ns_soa"] = {"nameservers": ["ns1.example.com", "ns2.example.com"], "ns_count": 2, "soa": soa}
    check(findings(d).get("SOA timers") == "info", "SOA outside guidance → info")
    d["ns_soa"]["soa"] = {**soa, "retry": 900, "expire": 1209600, "minimum": 3600}
    check(findings(d).get("SOA timers") == "pass", "Route 53-style SOA passes")


def test_infra_routing():
    z = {("example.com", "NS"): ["ns1.dns.net.", "ns2.dns.net."],
         ("example.com", "MX"): ["10 mx1.mail.net."],
         ("ns1.dns.net", "A"): ["192.0.2.1"], ("ns1.dns.net", "AAAA"): ["2001:db8::1"],
         ("ns2.dns.net", "A"): ["192.0.2.2"],
         ("mx1.mail.net", "A"): ["198.51.100.7"]}
    def ripe(ip):
        asn = 64500 if ip.startswith("192.0.2") or ip.startswith("2001") else 64511
        return {"address": ip, "prefix": ip + "/24", "asn": asn,
                "rpki_status": "not-found" if ip == "198.51.100.7" else "valid", "error": None}
    with zone(z), mock.patch.object(ac, "_ripe_prefix_rpki", side_effect=ripe):
        r = ac.check_infra_routing("example.com")
    check(set(r["ns"]["hosts"]) == {"ns1.dns.net", "ns2.dns.net"}, f"nameserver hosts: {r['ns']['hosts']}")
    check(len(r["ns"]["lookups"]) == 3 and len(r["mx"]["lookups"]) == 1, f"one v4 + one v6 per host: {r}")

    d = sample()
    d["infra_routing"] = r
    f = findings(d)
    check(f.get("Nameservers on IPv6") == "low", "one of two nameservers on IPv6 → low")
    check(f.get("Nameserver networks") == "info", "one network → info")
    check(f.get("Nameserver RPKI") == "pass", "valid nameserver routes pass")
    check(f.get("Mail servers on IPv6") == "low", "mail server without IPv6 → low")
    check(f.get("Mail server RPKI") == "medium", "mail route without ROA → medium")
    txt = detail(d)
    check(line(txt, "MEDIUM", "Mail server RPKI not-found: mx1.mail.net 198.51.100.7"), "mail RPKI line reads MEDIUM")
    check(line(txt, "INFO", "All nameservers checked are in one network (AS64500)"), "network line reads INFO")

    # the cap keeps RIPEstat lookups bounded
    many = {("example.com", "NS"): [f"ns{i}.dns.net." for i in range(9)],
            ("example.com", "MX"): [f"{i} mx{i}.mail.net." for i in range(9)]}
    for i in range(9):
        many[(f"ns{i}.dns.net", "A")] = [f"192.0.2.{i}"]
        many[(f"ns{i}.dns.net", "AAAA")] = [f"2001:db8::{i}"]
        many[(f"mx{i}.mail.net", "A")] = [f"198.51.100.{i}"]
    with zone(many), mock.patch.object(ac, "_ripe_prefix_rpki", side_effect=ripe) as rp:
        r = ac.check_infra_routing("example.com")
    check(rp.call_count == ac._INFRA_MAX_LOOKUPS, f"lookups capped at {ac._INFRA_MAX_LOOKUPS}, made {rp.call_count}")
    check(r["mx"]["lookups"], "mail servers still get lookups when nameservers are many")


def test_https_rr():
    with zone({("example.com", "HTTPS"): ['1 . alpn="h3,h2" ech=AEX+']}):
        r = ac.check_https_rr("example.com")
    check(r["present"] and r["alpn"] == ["h2", "h3"] and r["ech"], f"HTTPS record parsed: {r}")
    d = sample()
    d["https_rr"] = {"present": False, "records": [], "alpn": [], "ech": False, "error": None}
    check(findings(d).get("HTTPS DNS record") == "info", "missing HTTPS record → info")


# ── TLS ──────────────────────────────────────────────────────────────────────

def _make_cert(tmp, name, key_args, digest="sha256"):
    """Self-signed certificate made with the openssl command; None without it."""
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return None
    key, crt = os.path.join(tmp, name + ".key"), os.path.join(tmp, name + ".crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", *key_args, "-nodes", "-keyout", key, "-out", crt,
                    "-days", "2", "-subj", "/CN=localhost", f"-{digest}"],
                   check=True, capture_output=True)
    return key, crt


@contextlib.contextmanager
def tls_server(cert, min_v, max_v, ciphers):
    import socket
    import ssl
    import threading
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version, ctx.maximum_version = min_v, max_v
        ctx.set_ciphers(ciphers)
    ctx.load_cert_chain(cert[1], cert[0])
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                conn.settimeout(2)
                with ctx.wrap_socket(conn, server_side=True) as t:
                    t.recv(1)
            except Exception:
                pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        th.join(2)
        srv.close()


def test_cert_key_parser():
    import ssl
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        cases = [("rsa2048", ["rsa:2048"], "sha256", ("RSA", 2048, "sha256WithRSAEncryption")),
                 ("rsa1024", ["rsa:1024"], "sha1", ("RSA", 1024, "sha1WithRSAEncryption")),
                 ("ec384", ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"], "sha384", ("EC", 384, "ecdsa-with-SHA384")),
                 ("ed25519", ["ed25519"], "sha256", ("Ed25519", 256, "Ed25519"))]
        for name, args, digest, want in cases:
            made = _make_cert(tmp, name, args, digest if name != "ed25519" else "sha512")
            if made is None:
                print("    (skipped: no openssl command)")
                return
            der = ssl.PEM_cert_to_DER_cert(open(made[1]).read())
            got = ac._cert_key_info(der)
            check((got["cert_key_type"], got["cert_key_bits"], got["cert_sig_alg"]) == want, f"{name}: {got}")
    for tls, want in (({"cert_key_type": "RSA", "cert_key_bits": 1024, "cert_sig_alg": "sha256WithRSAEncryption"}, "weak_key"),
                      ({"cert_key_type": "RSA", "cert_key_bits": 2048, "cert_sig_alg": "sha1WithRSAEncryption"}, "weak_signature"),
                      ({"cert_key_type": "EC", "cert_key_bits": 256, "cert_sig_alg": "ecdsa-with-SHA256"}, "strong")):
        check(ac._cert_key_outcome(tls) == want, f"{tls} → {want}")


def _expired_cert(tmp):
    """(ca.crt, (leaf.key, leaf.crt)): a CA, and a leaf it signed that
    expired in 2020. None without the openssl command."""
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return None
    j = lambda n: os.path.join(tmp, n)                          # noqa: E731
    run = lambda *a: subprocess.run(a, check=True, capture_output=True, cwd=tmp)  # noqa: E731
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", j("ca.key"), "-out", j("ca.crt"),
        "-days", "2", "-subj", "/CN=Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", j("leaf.key"), "-out", j("leaf.csr"),
        "-subj", "/CN=localhost")
    open(j("index.txt"), "w").close()
    open(j("serial"), "w").write("01\n")
    open(j("ca.cnf"), "w").write(
        "[ca]\ndefault_ca=d\n[d]\ndir=.\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\n"
        "default_md=sha256\npolicy=p\nunique_subject=no\n[p]\ncommonName=supplied\n")
    run("openssl", "ca", "-batch", "-config", "ca.cnf", "-cert", "ca.crt", "-keyfile", "ca.key",
        "-in", "leaf.csr", "-out", "leaf.crt", "-startdate", "20200101000000Z", "-enddate", "20200201000000Z")
    return j("ca.crt"), (j("leaf.key"), j("leaf.crt"))


def test_certificate_failures_named():
    """An expired or self-signed certificate is named as such, with the
    certificate's own dates and issuer, and explained as a certificate
    problem rather than a TLS-version one."""
    import ssl
    import tempfile
    from vendor_audit import audit_records as ar
    V = ssl.TLSVersion
    with tempfile.TemporaryDirectory() as tmp:
        made = _expired_cert(tmp)
        if made is None:
            print("    (skipped: no openssl command)")
            return
        ca, leaf = made
        trusting = ssl.create_default_context(cafile=ca)
        trusting.check_hostname = False
        with tls_server(leaf, V.TLSv1_2, V.TLSv1_3, "DEFAULT") as port, \
             mock.patch.object(ac, "_TLS_CTX", trusting):
            expired = ac.check_tls("127.0.0.1", port)
        selfsigned = _make_cert(tmp, "self", ["rsa:2048"])
        with tls_server(selfsigned, V.TLSv1_2, V.TLSv1_3, "DEFAULT") as port:
            selfs = ac.check_tls("127.0.0.1", port)
    check(expired.get("cert_error_reason") == "expired", f"expired cert reason: {expired.get('cert_error_reason')} {expired.get('error')}")
    c = expired.get("cert_failed_details") or {}
    check(c.get("not_after", "").startswith("2020-02-01") and c.get("issuer_cn") == "Test CA"
          and c.get("subject_cn") == "localhost", f"details read from the untrusted cert: {c}")
    check(selfs.get("cert_error_reason") == "self_signed", f"self-signed reason: {selfs.get('cert_error_reason')}")

    d = sample()
    d["tls"] = expired
    rows = {f["label"]: f for f in ac.assess_results(d)}
    check(rows["TLS connection"]["outcome"] == "cert_expired" and rows["TLS connection"]["severity"] == "critical",
          f"expired → cert_expired critical: {rows['TLS connection']}")
    what, why, fix = ar.explanation_for("TLS connection", "cert_expired")
    check("expiry" in what and "TLS 1.3" not in fix and "Renew" in fix, f"explained as a certificate problem: {fix}")
    check(ar.explanation_for("TLS connection", "ok") == ar.explanation_for("TLS connection"),
          "a working connection keeps the general TLS text")
    ev = ar.evidence_for("TLS connection", d)
    flat = str(ev)
    check("2020-02-01" in flat and "days ago" in flat and "Test CA" in flat, f"evidence shows when and who: {ev}")
    txt = detail(d)
    check(line(txt, "CRITICAL", "Certificate has expired (on 2020-02-01) — browsers block the site"),
          "the .txt names the cause and date")
    from vendor_audit.web import render_html
    page = render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                      "results": d, "timestamp": "2026-11-20T00:00:00Z", "duration_ms": 1})
    check("Expired " in page and "days ago" in page, "the certificate card says how long ago it expired")
    check("Enable TLS 1.3 in your web server" not in page[page.index('id="check-tls-connection"'):][:4000],
          "the drawer no longer gives TLS-version advice for an expired certificate")


def test_legacy_tls_probes():
    import ssl
    import tempfile
    V = ssl.TLSVersion
    with tempfile.TemporaryDirectory() as tmp:
        cert = _make_cert(tmp, "srv", ["rsa:2048"])
        if cert is None:
            print("    (skipped: no openssl command)")
            return
        with tls_server(cert, V.TLSv1, V.TLSv1_2, "DEFAULT:@SECLEVEL=0") as port:
            old = ac.check_tls_legacy("127.0.0.1", port)
        with tls_server(cert, V.TLSv1_2, V.TLSv1_3, "ECDHE+AESGCM") as port:
            new = ac.check_tls_legacy("127.0.0.1", port)
    if old.get("tls1_0") == "unprobed":
        print("    (TLS 1.0 not available in this OpenSSL; outcome checked as unprobed)")
        check(ac._legacy_tls_outcome(old) == "unprobed", f"unprobed client: {old}")
    else:
        check(old["tls1_0"] == "accepted" and old["tls1_1"] == "accepted", f"old server accepts 1.0/1.1: {old}")
        check(old["static_rsa"] == "accepted", f"old server accepts static RSA: {old}")
    check(new["tls1_0"] in ("refused", "unprobed") and new["tls1_1"] in ("refused", "unprobed"),
          f"modern server refuses 1.0/1.1: {new}")
    check(new["static_rsa"] == "refused" and new["null_cipher"] in ("refused", "unprobed"),
          f"modern server requires forward secrecy: {new}")
    closed = ac.check_tls_legacy("127.0.0.1", 9)        # discard port: nothing listening
    check(set(closed.values()) <= {"unreachable", "unprobed"}, f"nothing listening is not a pass: {closed}")
    check(ac._legacy_tls_outcome(closed) in (None, "unprobed"), "unreachable is not rated")

    d = sample()
    d["tls_legacy"] = {"tls1_0": "accepted", "tls1_1": "accepted", "static_rsa": "accepted", "null_cipher": "refused"}
    f = findings(d)
    check(f.get("Legacy TLS disabled") == "high" and f.get("Forward secrecy") == "medium", f"old server rated: {f}")
    txt = detail(d)
    check(line(txt, "HIGH", "TLS 1.0 and TLS 1.1 still accepted"), "legacy line reads HIGH")
    check(line(txt, "MEDIUM", "Static RSA key exchange accepted"), "forward secrecy line reads MEDIUM")
    d["tls_legacy"] = {"tls1_0": "refused", "tls1_1": "refused", "static_rsa": "refused", "null_cipher": "refused"}
    f = findings(d)
    check(f.get("Legacy TLS disabled") == "pass" and f.get("Forward secrecy") == "pass", f"modern server: {f}")


# ── Website ──────────────────────────────────────────────────────────────────

def test_csp_subchecks():
    d = sample()
    csp = "default-src 'self'; script-src 'self' 'nonce-abc'"
    d["server_header"] = dict(d["server_header"], csp=csp, csp_report_only=None, csp_quality="present")
    d["csp_analysis"] = ac.analyze_csp(csp)
    f = findings(d)
    check(f.get("CSP object-src") == "pass", f"default-src 'self' restricts object-src: {f.get('CSP object-src')}")
    check(f.get("CSP base-uri") == "low", "no base-uri → low")
    check(line(detail(d), "LOW", "CSP base-uri missing"), "base-uri line reads LOW")

    d["server_header"] = dict(d["server_header"], csp=None, csp_report_only=csp, csp_quality=None)
    d["csp_analysis"] = ac.analyze_csp(None, csp_report_only=True)
    f = findings(d)
    check(f.get("CSP script-src safety") == ac.RUBRIC["findings"]["CSP script-src safety"]["missing"][0],
          "Report-Only only rates like a missing CSP")
    check("Report-Only" in [x for x in ac.assess_results(d) if x["label"] == "CSP script-src safety"][0]["text"],
          "and says Report-Only")
    check("CSP object-src" not in f and "CSP base-uri" not in f, "no CSP enforced: sub-checks not rated twice")
    check(line(detail(d), "HIGH", "only sent as Report-Only"), "Report-Only line reads HIGH")


def test_security_txt_subchecks():
    d = sample()
    base = {"present": True, "contact": ["mailto:s@example.com"], "policy": None, "error": None}
    d["security_txt"] = {**base, "expires": "2020-01-01T00:00:00Z", "expired": True,
                         "found_at": "https://example.com/security.txt",
                         "final_url": "https://example.com/security.txt",
                         "canonical": ["https://example.com/.well-known/security.txt"]}
    f = findings(d)
    text = {x["label"]: x["text"] for x in ac.assess_results(d)}
    check(f.get("security.txt") == "info" and text["security.txt"] == "security.txt has expired",
          f"expired gets its own wording: {text.get('security.txt')}")
    check(f.get("security.txt location") == "info", "legacy path → info")
    check(f.get("security.txt Canonical") == "low", "Canonical mismatch → low")
    txt = detail(d)
    check(line(txt, "LOW", "Canonical: does not list where the file was found"), "Canonical line reads LOW")
    d["security_txt"] = {**base, "expires": "2030-01-01T00:00:00Z", "expired": False,
                         "found_at": "https://example.com/.well-known/security.txt",
                         "final_url": "https://example.com/.well-known/security.txt",
                         "canonical": ["https://example.com/.well-known/security.txt"]}
    f = findings(d)
    check(f.get("security.txt location") == "pass" and f.get("security.txt Canonical") == "pass", f"good file: {f}")


def test_deprecated_headers_and_lang():
    d = sample()
    d["server_header"] = dict(d["server_header"], public_key_pins='pin-sha256="x"; max-age=5184000', expect_ct="max-age=0")
    check(findings(d).get("Deprecated security headers") == "low", "HPKP → low")
    check(line(detail(d), "LOW", "Public-Key-Pins (HPKP) set"), "HPKP line reads LOW")
    d["server_header"] = dict(d["server_header"], public_key_pins=None, expect_ct="max-age=86400")
    check(findings(d).get("Deprecated security headers") == "info", "Expect-CT → info")
    d["server_header"] = dict(d["server_header"], public_key_pins=None, expect_ct=None)
    check(findings(d).get("Deprecated security headers") == "pass", "neither → pass")
    old = sample()
    old["server_header"].pop("public_key_pins", None)
    check("Deprecated security headers" not in findings(old), "scans saved before 3.4 are not rated")

    d["page_signals"] = {"parsed": True, "sri_outcome": "none_needed", "mixed_outcome": "none",
                         "a11y": {"html_lang_set": False, "html_lang": None, "images_total": 0,
                                  "images_missing_alt": 0, "inputs_total": 0, "inputs_unlabeled": 0}}
    check(findings(d).get("Page language declared") == "info", "no lang → info")


def test_slow_upstreams_are_bounded():
    """A hanging RIPEstat or a server that never finishes the handshake
    costs a bounded time and is reported as unknown, not as a pass."""
    import socket
    import threading
    import time
    z = {("example.com", "NS"): ["ns1.dns.net."], ("ns1.dns.net", "A"): ["192.0.2.1"]}
    with zone(z), mock.patch.object(ac, "_ripe_prefix_rpki", side_effect=lambda ip: time.sleep(10)):
        t = time.monotonic()
        r = ac.check_infra_routing("example.com")
        took = time.monotonic() - t
    check(took < ac._INFRA_RIPE_BUDGET + 1, f"hanging RIPEstat held the check {took:.1f}s")
    check(r["ns"]["lookups"] and r["ns"]["lookups"][0]["rpki_status"] is None, f"reported as failed: {r['ns']}")

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    held = []
    stop = threading.Event()

    def accept_and_hold():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(srv.accept()[0])     # never answers the ClientHello
            except OSError:
                pass
    th = threading.Thread(target=accept_and_hold, daemon=True)
    th.start()
    try:
        t = time.monotonic()
        r = ac.check_tls_legacy("127.0.0.1", srv.getsockname()[1])
        took = time.monotonic() - t
    finally:
        stop.set()
        th.join(1)
        for c in held:
            c.close()
        srv.close()
    check(took < ac._LEGACY_PROBE_TIMEOUT + 0.5, f"silent server held the probes {took:.1f}s")
    check(ac._legacy_tls_outcome(r) in (None, "unprobed"), f"silent server is not a pass: {r}")


# ── Every new check, end to end ──────────────────────────────────────────────

NEW_LABELS = [
    "SPF single record", "SPF mechanisms", "DMARC single record", "DMARC external reports",
    "MX hosts resolve", "MX reverse DNS", "MTA-STS policy MX match", "MTA-STS max_age",
    "Dangling CNAME", "DNSSEC algorithm", "SOA timers", "Nameservers on IPv6", "Nameserver networks",
    "Nameserver RPKI", "Mail servers on IPv6", "Mail server RPKI", "HTTPS DNS record",
    "Legacy TLS disabled", "Forward secrecy", "Certificate key strength",
    "CSP object-src", "CSP base-uri", "security.txt location", "security.txt Canonical",
    "Deprecated security headers", "Page language declared",
]


def everything():
    """The sample scan with data for every check added in 3.4 (Null MX
    excluded: it applies only to a domain without MX, see test_null_mx)."""
    d = sample()
    d["spf"] = {"status": "hardfail", "record": "v=spf1 include:gone.example.net ptr -all", "lookup_count": 2,
                "record_count": 2, "void_lookups": 1, "uses_ptr": True, "missing_includes": ["gone.example.net"]}
    d["dmarc"] = {"present": True, "policy": "reject", "pct": 100, "sp": None, "ruf": [],
                  "rua": ["mailto:d@reports.vendor.net"], "record_count": 2, "inherited_from": None,
                  "record": "v=DMARC1; p=reject; rua=mailto:d@reports.vendor.net",
                  "rua_external": [{"address": "d@reports.vendor.net", "domain": "reports.vendor.net", "authorized": False}]}
    d["mx"] = {"entries": [{"priority": 10, "host": "mx1.example.com"}, {"priority": 20, "host": "gone.example.com"}],
               "null_mx": False, "mx_targets_ip": [], "mx_targets_cname": [],
               "mx_hosts": {"mx1.example.com": {"v4": ["192.0.2.10"], "v6": [], "resolves": True,
                                                "ptr": [{"address": "192.0.2.10", "name": None, "confirmed": False}]},
                            "gone.example.com": {"v4": [], "v6": [], "resolves": False, "ptr": []}}}
    d["mta_sts"] = {"present": True, "id": "1", "record": "v=STSv1; id=1"}
    d["mta_sts_policy"] = {"fetched": True, "mode": "enforce", "max_age": 86400, "mx": ["*.example.com"], "problems": []}
    d["dangling_cname"] = {"names": {"www.example.com": {"chain": ["old.azurewebsites.net"], "end": "nxdomain"}},
                           "dangling": ["www.example.com"]}
    d["dnssec"] = {"tld": {"signed": True, "tld": "com"}, "domain": {"dnskey": True, "ad_flag": True, "algorithms": [5]}}
    d["ns_soa"] = {"nameservers": ["ns1.dns.net", "ns2.dns.net"], "ns_count": 2,
                   "soa": {"primary": "ns1.dns.net", "admin": "h", "serial": 1, "refresh": 3600, "retry": 7200,
                           "expire": 259200, "minimum": 172800}}
    d["infra_routing"] = {
        "ns": {"hosts": {"ns1.dns.net": {"v4": ["192.0.2.1"], "v6": []}, "ns2.dns.net": {"v4": ["192.0.2.2"], "v6": []}},
               "lookups": [{"host": "ns1.dns.net", "address": "192.0.2.1", "prefix": "192.0.2.0/24", "asn": 64500,
                            "rpki_status": "not-found", "error": None}], "error": None},
        "mx": {"hosts": {"mx1.example.com": {"v4": ["192.0.2.10"], "v6": []}},
               "lookups": [{"host": "mx1.example.com", "address": "192.0.2.10", "prefix": "192.0.2.0/24",
                            "asn": 64500, "rpki_status": "invalid", "error": None}], "error": None}}
    d["https_rr"] = {"present": False, "records": [], "alpn": [], "ech": False, "error": None}
    d["tls_legacy"] = {"tls1_0": "accepted", "tls1_1": "accepted", "static_rsa": "accepted", "null_cipher": "refused"}
    d["tls"] = dict(d["tls"], cert_key_type="RSA", cert_key_bits=1024, cert_sig_alg="sha256WithRSAEncryption")
    csp = "default-src https:; script-src 'self'"
    d["server_header"] = dict(d["server_header"], csp=csp, csp_report_only=None, csp_quality="present",
                              public_key_pins='pin-sha256="x"; max-age=1', expect_ct=None)
    d["csp_analysis"] = ac.analyze_csp(csp)
    d["security_txt"] = {"present": True, "contact": ["mailto:s@example.com"], "policy": None, "error": None,
                         "expires": "2020-01-01T00:00:00Z", "expired": True,
                         "found_at": "https://example.com/security.txt", "final_url": "https://example.com/security.txt",
                         "canonical": ["https://example.com/.well-known/security.txt"]}
    d["page_signals"] = dict(d.get("page_signals") or {}, parsed=True,
                             a11y={"html_lang_set": False, "html_lang": None, "images_total": 0,
                                   "images_missing_alt": 0, "inputs_total": 0, "inputs_unlabeled": 0})
    d.setdefault("_scan", {"deep": True, "version": "3.4.0"})
    return d


def test_every_new_check_end_to_end():
    from vendor_audit import audit_records as ar
    d = everything()
    f = findings(d)
    data = atr._ReportData("example.com", "example.com", d, "2026-11-20T00:00:00Z", "3.4.0")
    by_label = {}
    for r in ar.build_records(data):
        by_label.setdefault(r.get("label") or r.get("id"), r)
    tagged = atr.render_detail_sections(data)
    checked = set()
    real = atr._status_word

    def spy(sev, chk):
        if chk:
            checked.add(chk)
        return real(sev, chk)
    atr._status_word = spy
    try:
        atr.render_detail_sections(data)
    finally:
        atr._status_word = real
    known = set(ac.RUBRIC["findings"])
    for label in NEW_LABELS:
        check(label in known, f"{label}: not in rubric.json")
        check(label in f, f"{label}: no finding from the sample data")
        check(ar.topic_for(label) in ar.TOPIC_TITLES, f"{label}: topic {ar.topic_for(label)!r} has no title")
        check(ar.standard_for(label), f"{label}: no standard")
        what, why, fix = ar.explanation_for(label)
        check(what and why and fix, f"{label}: explanation incomplete")
        check(ar.evidence_for(label, d), f"{label}: no evidence for the page's detail drawer")
        check(label in checked, f"{label}: no .txt status line names it")
        cats = [c for c, labels in ac.RUBRIC["categories"].items() if label in labels]
        check(len(cats) == 1, f"{label}: should be in exactly one category, is in {cats}")
    check("\x1e" not in atr.strip_tags(tagged), "no tags leak")

    from vendor_audit.web import render_html
    page = render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                      "results": d, "timestamp": "2026-11-20T00:00:00Z", "duration_ms": 1})
    card = page[page.index("Email authentication"):][:600]
    check("Broken" in card and "ignored (more than one record)" in card,
          "the email card should not say Enforced when receivers discard the records")
    for label in NEW_LABELS:
        check(f'id="check-{ar.slug(label)}"' in page or ar.slug(label) in page, f"{label}: no drawer on the page")


TESTS = [test_spf_records_and_mechanisms, test_dmarc_records_and_external_reports,
         test_mx_hosts_and_reverse_dns, test_null_mx, test_mta_sts_mx_match_and_max_age,
         test_dangling_cname, test_dnssec_algorithm_and_soa, test_infra_routing, test_https_rr,
         test_cert_key_parser, test_certificate_failures_named, test_legacy_tls_probes,
         test_csp_subchecks, test_security_txt_subchecks, test_deprecated_headers_and_lang,
         test_slow_upstreams_are_bounded, test_every_new_check_end_to_end]


def run():
    for fn in TESTS:
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nNEW-CHECK FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll new-check tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
