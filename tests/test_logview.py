"""Audit log page tests (deploy/vendor-audit-logview, 3.5.13).

The page sits behind Cloudflare Access; these tests hold its own check of
the Access token, the page it renders, and the unit that runs it.
"""
import base64
import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from unittest import mock

_HERE = os.path.dirname(__file__)
_DEPLOY = os.path.join(_HERE, "..", "deploy")

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append(msg)
        print(f"FAIL: {msg}")


def _tool():
    path = os.path.join(_DEPLOY, "vendor-audit-logview")
    loader = SourceFileLoader("vendor_audit_logview", path)
    mod = module_from_spec(spec_from_loader("vendor_audit_logview", loader))
    loader.exec_module(mod)
    return mod


# A throwaway 2048-bit RSA test key (made with `openssl genpkey` for these
# tests only; it protects nothing).
N = int(
    "843e1d0b04b66ef40653dd64977951180c543a77009faacc5541ee4280f072d3c3ac10636f2b2a60bb90ebd0"
    "726aa115b59c83796efb721d19bee5058442ff7900eb9029bd8c4f0b3815aaf6ec82822df564c41747de2f59"
    "730873e9c06378213fe742ae4a101290aa7b7927d8eb725125d69a78e2004f58201ca354134d2f790f5b1685"
    "8b4cecb41e5fdd1f44053028636c3555f0d2816466e9849d9e307c99d03c24715eddc728d99e1a38afa140cb"
    "5940b2ee4c233225ec01ddd278f125cebf408f12680ebe6008fe5ce272be152267dee10e0ecdab3acfba8c81"
    "c8825a4a7e052862105f3aec0c6a96dd38c5849137e1c73b3afe90fa7364b6a35a39e881", 16)
D = int(
    "1f3006e972531417b8e64e704ac8f1b71a3143188dad1a3ad660963058f85c1c55295f341423b9fad641775b"
    "d1a0141d6a975eea64a22867748af0b83c5910a718f0752f62e4943fb11a6b1790efb683e03bc3833a0fcc5a"
    "ec2632300e8f66e5708cb9cd20ea697674be69f45bd42b41b80ac4a37da9550d1385ad7f468e0d83c8b1adef"
    "757f407db99d7fec444f8f3b4afbbccd292c7c53b56874eae2d0b98067b46c72ac043c88a720e1b0a0af847a"
    "f2b87d2db2def626b8635a6b7642001960a114fef0db8fecdf86ec15d2cd5124049a89a7ed29de60b9255812"
    "055ac4b26806c193f3e3e94d44ff46c9d737496d3495ec28b75133e74b64904642e0621", 16)
E = 65537

# Known answer: a token signed by `openssl dgst -sha256 -sign` with that
# key, so the RS256 check is held to OpenSSL's output, not just to itself.
OPENSSL_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImthdCIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsia2F0Il0sImlzcyI6Imh0dHB"
    "zOi8va2F0LmNsb3VkZmxhcmVhY2Nlc3MuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJlbWFpbCI6ImthdEBleGFtcGx"
    "lLmNvbSJ9.BNr7bS-n7nBeq_M_R9nbjLXtsJvnNQoscFt997tpn9Rb40Od-bYTMlQqYR2nfL1NvSOrPhwQ7aFSk0"
    "Df-nd6KrYDjqKGqNZ0k3NfIJDzEi8Lhibk8p2mJGU8t15Ds029T69zuvvB5q92DInm27JU7a_to9usIR3QVbubSn"
    "YwQmWC59187qH50VhGQSqfQRuaFvL5UoDYXf9MGIuPODHsVf-IAPVcSBGia1R18yaaugog3YAlYORfQLAOYHtgRr"
    "7JUgi0GSFnPPfF0GBt9EaXAPdxB7mx2vUp_n-MqscqGlLD9OEhoDsX7uVxw670eolAt4jqh_n6VFkgeIYLH2CVoA")

TEAM = "kat.cloudflareaccess.com"
AUD = "ab" * 32
NOW = 1_800_000_000


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk(kid="k1"):
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "e": b64(E.to_bytes(3, "big")),
            "n": b64(N.to_bytes(256, "big"))}


def sign(claims, kid="k1", alg="RS256"):
    head = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(f"{head}.{body}".encode()).digest()
    em = b"\x00\x01" + b"\xff" * (256 - len(t) - 3) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), D, N).to_bytes(256, "big")
    return f"{head}.{body}.{b64(sig)}"


def good_claims(**over):
    c = {"aud": [AUD], "iss": f"https://{TEAM}", "exp": NOW + 3600, "iat": NOW - 10, "nbf": NOW - 10,
         "email": "me@example.com"}
    c.update(over)
    return c


def verifier(lv, fetch=None):
    calls = []

    def default_fetch(url):
        calls.append(url)
        return {"keys": [jwk()]}
    v = lv.AccessVerifier(TEAM, AUD, fetch=fetch or default_fetch, clock=lambda: NOW)
    return v, calls


def test_rs256_against_openssl():
    lv = _tool()
    head, body, sig = OPENSSL_TOKEN.split(".")
    check(lv.rs256_verify(N, E, f"{head}.{body}".encode(), lv._b64url(sig)), "OpenSSL's RS256 signature verifies")
    bad = bytearray(lv._b64url(sig))
    bad[-1] ^= 1
    check(not lv.rs256_verify(N, E, f"{head}.{body}".encode(), bytes(bad)), "a flipped bit fails")
    check(not lv.rs256_verify(N, E, f"{head}.{body}x".encode(), lv._b64url(sig)), "a changed message fails")
    check(not lv.rs256_verify(N, E, f"{head}.{body}".encode(), b""), "an empty signature fails")
    # The same token through the verifier: right signature, but not this team or audience.
    v = lv.AccessVerifier("kat.cloudflareaccess.com", "kat", fetch=lambda u: {"keys": [jwk("kat")]},
                          clock=lambda: 1_900_000_000)
    check(v.verify(OPENSSL_TOKEN) == {"aud": ["kat"], "iss": "https://kat.cloudflareaccess.com",
                                      "exp": 2000000000, "email": "kat@example.com"}, "the verifier accepts it")


def test_access_token_rules():
    lv = _tool()
    v, calls = verifier(lv)
    check(v.verify(sign(good_claims()))["email"] == "me@example.com", "a valid token is accepted")
    check(calls == [f"https://{TEAM}/cdn-cgi/access/certs"], f"keys come from the team's certs URL: {calls}")
    v.verify(sign(good_claims()))
    check(len(calls) == 1, "keys are cached")
    check(v.verify(sign(good_claims(aud=["0" * 64]))) is None, "another application's token")
    check(v.verify(sign(good_claims(aud=AUD))) is not None, "aud as a plain string is fine")
    check(v.verify(sign(good_claims(iss="https://evil.cloudflareaccess.com"))) is None, "another team's token")
    check(v.verify(sign(good_claims(exp=NOW - 120))) is None, "an expired token")
    check(v.verify(sign(good_claims(exp=NOW - 30))) is not None, "a minute of clock skew is allowed")
    check(v.verify(sign(good_claims(nbf=NOW + 600))) is None, "a token not valid yet")
    check(v.verify(sign(good_claims(), alg="HS256")) is None, "HS256 is refused")
    none_tok = ".".join([b64(b'{"alg":"none","kid":"k1"}'), b64(json.dumps(good_claims()).encode()), ""])
    check(v.verify(none_tok) is None, "alg none is refused")
    t = sign(good_claims())
    h, b, s = t.split(".")
    forged = ".".join([h, b64(json.dumps(good_claims(email="attacker@example.com")).encode()), s])
    check(v.verify(forged) is None, "changed claims with the old signature are refused")
    for junk in ("", "abc", "a.b", "a.b.c", "x" * 9000, None):
        check(v.verify(junk) is None, f"junk token {junk!r:.20}")

    # A key Access rotated in: one early refetch, then at most once a minute.
    v._clock = lambda: NOW + 120
    check(v.verify(sign(good_claims(), kid="new")) is None and len(calls) == 2, "unknown kid: one refetch")
    v.verify(sign(good_claims(), kid="new"))
    check(len(calls) == 2, "and not again within a minute")

    def failing(url):
        raise OSError("network down")
    v2, _ = verifier(lv)
    v2.verify(sign(good_claims()))
    v2._fetch = failing
    v2._fetched = NOW - 7200
    check(v2.verify(sign(good_claims())) is not None, "a failed refresh keeps the keys it has")
    v3 = lv.AccessVerifier(TEAM, AUD, fetch=failing, clock=lambda: NOW)
    check(v3.verify(sign(good_claims())) is None, "no keys at all: everything is refused")


def _journal(*rows):
    out = []
    for t, msg in rows:
        out.append(json.dumps({"MESSAGE": "INFO vendor_audit.web: " + msg, "__REALTIME_TIMESTAMP": str(t * 10**6)}))
    return "\n".join(out) + "\n"


def _req(domain, ip, flags=""):
    return f"audit request: original='{domain}' normalized='{domain}' addresses=192.0.2.1 ip={ip}{flags}"


def test_page_and_server():
    lv = _tool()
    journal = _journal((NOW - 400, _req("deep.example", "203.0.113.7", " deep=1")),
                       (NOW - 300, _req("example.com", "203.0.113.7")),
                       (NOW - 200, _req("vendoraudit.org", "198.51.100.2", " fresh=1")),
                       (NOW - 198, "audit cache hit (fresh): domain='vendoraudit.org' ip=198.51.100.2"),
                       (NOW - 100, _req("<script>x.example", "203.0.113.7")))
    ran = []

    def fake_run(cmd, **kw):
        ran.append(cmd)
        return mock.Mock(stdout=journal, stderr="", returncode=0)

    with mock.patch.object(lv.subprocess, "run", side_effect=fake_run):
        rows = lv.read_rows("24 hours ago")
        rows_all = lv.read_rows("24 hours ago", include_follow_ups=True)
    check(ran[0][:2] == ["journalctl", "--namespace=vendor-audit"] and "--since" in ran[0],
          f"reads the vendor-audit namespace: {ran[0]}")
    check([r["domain"] for r in rows] == ["deep.example", "example.com", "vendoraudit.org", "<script>x.example"],
          f"rows, with the re-audit's follow-up folded: {[r['domain'] for r in rows]}")
    check(len(rows_all) == 5, "all=1 keeps the follow-up")

    server = ThreadingHTTPServer(("127.0.0.1", 0), lv.Handler)
    server.verifier, _ = verifier(lv)
    from zoneinfo import ZoneInfo
    server.config = {"tz": ZoneInfo("UTC"), "tz_name": "UTC", "namespace": "vendor-audit",
                     "site": "https://site.example"}
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def get(path, token=None):
        req = urllib.request.Request(base + path, headers={"Cf-Access-Jwt-Assertion": token} if token else {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    tok = sign(good_claims())
    try:
        with mock.patch.object(lv.subprocess, "run", side_effect=fake_run):
            status, body, _ = get("/")
            check(status == 403 and "Cloudflare Access" in body, f"no token: 403 ({status})")
            check(get("/", sign(good_claims(aud=["0" * 64])))[0] == 403, "wrong audience: 403")
            check(get("/healthz")[:2] == (200, "ok\n"), "healthz needs no sign-in and says nothing")
            check(get("/nope", tok)[0] == 404, "other paths: 404")
            check(get("/nope")[0] == 403, "and 403 before sign-in, so nothing is revealed")
            status, body, headers = get("/", tok)
            check(status == 200 and "example.com" in body and "vendoraudit.org" in body, f"the page ({status})")
            check("<script>x" not in body and "&lt;script&gt;x.example" in body, "log contents are escaped")
            check("signed in as me@example.com" in body, "shows who is signed in")
            check(body.index("&lt;script&gt;") < body.index(">example.com<"), "newest first")
            check("default-src 'none'" in headers.get("Content-Security-Policy", "")
                  and headers.get("Cache-Control") == "no-store"
                  and "noindex" in headers.get("X-Robots-Tag", ""), "locked-down headers")
            check("<script" not in body.replace("&lt;script", ""), "the page itself has no script")
            # Each row links to the domain's result page on the public site
            # (cached, or audited again), deep audits to the deep result.
            check('href="https://site.example/audit/result?domain=example.com" target=_blank' in body,
                  "a View link to the result page")
            check('href="https://site.example/audit/result?domain=deep.example&amp;deep=1"' in body
                  and "View deep" in body, "a deep audit links to the deep result")
            check("domain=%3Cscript%3Ex.example" in body, "the domain is URL-encoded in the link")
            check('rel="noopener noreferrer"' in body, "opened without a referrer")
            body = get("/?ip=198.51.100.2", tok)[1]
            check("vendoraudit.org" in body and ">example.com<" not in body, "filter by visitor")
            body = get("/?domain=198.51.100.2", tok)[1]
            check("vendoraudit.org" in body and ">example.com<" not in body, "an IP typed in the search box")
            body = get("/?domain=EXAMPLE.COM.", tok)[1]
            check(">example.com<" in body and "vendoraudit.org" not in body, "filter by domain")
            check("--since" in ran[-1] and ran[-1][ran[-1].index("--since") + 1] == "30 days ago",
                  "a filter looks back 30 days")
            body = get("/?view=top&since=7d", tok)[1]
            check("Visitors (2)" in body and "Domains (4)" in body, "top view")
            check('https://site.example/audit/result?domain=vendoraudit.org' in body, "top view links too")
            check(get("/?since=forever", tok)[0] == 200, "an unknown period falls back")
            check(get("/?" + "&".join(f"a{i}=1" for i in range(50)), tok)[0] == 200, "too many fields: ignored")
    finally:
        server.shutdown()
        server.server_close()


def test_config_and_unit():
    lv = _tool()
    cfg = lv.config_from_env({"ACCESS_TEAM_DOMAIN": "Solitary-Sun.cloudflareaccess.com", "ACCESS_AUD": AUD.upper(),
                              "LOGVIEW_TZ": "America/Los_Angeles"})
    check(cfg["team"] == "solitary-sun.cloudflareaccess.com" and cfg["aud"] == AUD and cfg["port"] == 8001, f"{cfg}")
    check(cfg["site"] == "https://vendoraudit.org", "View links go to the public site by default")
    check(lv.config_from_env({"ACCESS_TEAM_DOMAIN": TEAM, "ACCESS_AUD": AUD,
                              "LOGVIEW_SITE": "https://audit.example/"})["site"] == "https://audit.example",
          "LOGVIEW_SITE")
    for env in ({"ACCESS_TEAM_DOMAIN": "evil.example.com", "ACCESS_AUD": AUD},
                {"ACCESS_TEAM_DOMAIN": TEAM, "ACCESS_AUD": "short"}, {},
                {"ACCESS_TEAM_DOMAIN": TEAM, "ACCESS_AUD": AUD, "LOGVIEW_SITE": "javascript:alert(1)"}):
        try:
            lv.config_from_env(env)
            check(False, f"bad config accepted: {env}")
        except SystemExit:
            pass
    src = open(os.path.join(_DEPLOY, "vendor-audit-logview")).read()
    check('ThreadingHTTPServer(("127.0.0.1", cfg["port"])' in src, "listens on loopback only")
    unit = {}
    for line in open(os.path.join(_DEPLOY, "vendor-audit-logview.service")):
        line = line.strip()
        if line and not line.startswith(("#", "[")) and "=" in line:
            k, v = line.split("=", 1)
            unit.setdefault(k, v)
    check(unit.get("DynamicUser") == "yes" and unit.get("SupplementaryGroups") == "systemd-journal",
          "a throwaway user that can read the journal and nothing more")
    check(unit.get("ExecStart") == "/usr/bin/python3 -I /opt/vendor-audit/deploy/vendor-audit-logview", unit.get("ExecStart"))
    check(unit.get("EnvironmentFile") == "/etc/vendor-audit/logview.env", "settings from logview.env")
    for k in ("ProtectSystem", "NoNewPrivileges", "MemoryDenyWriteExecute", "CapabilityBoundingSet"):
        check(k in unit, f"sandbox: {k}")
    example = open(os.path.join(_DEPLOY, "logview.env.example")).read()
    check("ACCESS_TEAM_DOMAIN=yourteam.cloudflareaccess.com" in example, "the example holds no real team")


def run():
    for fn in (test_rs256_against_openssl, test_access_token_rules, test_page_and_server, test_config_and_unit):
        fn()
    print(f"{len(_failures)} failure(s)")
    return not _failures


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
