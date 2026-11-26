#!/usr/bin/env python3
"""Connect-time address guard (vendor_audit.netguard).

The web service's audit workers refuse to connect to non-public addresses
at connect time, so neither DNS rebinding nor a redirect can steer an audit
inside the network. These tests run real sockets against a local server.
Loopback stands in for both sides: 127.0.0.1 is treated as "public" and
127.0.0.2 as "private" for the duration of each test.

  - the address rules match the validator's (one list, shared)
  - a name that resolves only to a private address is refused
  - a redirect from a public host to a private one is refused at the hop
  - a name that answers public, then private (rebinding), is refused on the
    second connection
  - mixed answers keep only the public addresses
  - install() is idempotent; the CLI process never installs it

Run:  python3 tests/test_netguard.py
"""
import contextlib
import http.server
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx                                         # noqa: E402
from vendor_audit import netguard                    # noqa: E402

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


@contextlib.contextmanager
def guarded(names):
    """Install the guard with a fake resolver: names → list of addresses,
    and 127.0.0.1 counted as public."""
    real_gai, real_pub, before = netguard._real_getaddrinfo, netguard.is_public_address, socket.getaddrinfo
    before_cc, before_wrap = socket.create_connection, ssl.SSLContext.wrap_socket     # 3.5.7 tracking
    saved_env = dict(os.environ)          # install() drops proxy settings

    def fake_gai(host, port, *args, **kw):
        h = host.decode() if isinstance(host, bytes) else host
        if h in names:
            addrs = names[h]() if callable(names[h]) else names[h]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addrs]
        return real_gai(host, port, *args, **kw)

    netguard._real_getaddrinfo = fake_gai
    netguard.is_public_address = lambda a: a == "127.0.0.1" or real_pub(a)
    netguard.install()
    try:
        yield
    finally:
        socket.getaddrinfo = before
        socket.create_connection, ssl.SSLContext.wrap_socket = before_cc, before_wrap
        netguard._real_getaddrinfo, netguard.is_public_address = real_gai, real_pub
        os.environ.clear()
        os.environ.update(saved_env)


@contextlib.contextmanager
def server(redirect_to=None):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if redirect_to and self.path == "/":
                self.send_response(302)
                self.send_header("Location", redirect_to)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("", 0), H)     # all loopback addresses
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()


def _client():
    return httpx.Client(trust_env=False, timeout=3)


def test_rules_shared():
    from vendor_audit.web import validate
    check(validate._is_public_address is netguard.is_public_address, "validator should use netguard's rules")
    for a in ("10.1.2.3", "127.0.0.1", "169.254.169.254", "192.168.0.1", "fd00::1", "::1", "100.64.0.1"):
        check(not netguard.is_public_address(a), f"{a} should be non-public")
    for a in ("8.8.8.8", "2606:4700:4700::1111"):
        check(netguard.is_public_address(a), f"{a} should be public")


def test_private_name_refused():
    with guarded({"inside.test": ["127.0.0.2"]}):
        try:
            socket.create_connection(("inside.test", 80), timeout=1)
            check(False, "connecting to a private-only name should fail")
        except netguard.NonPublicAddressError as e:
            check("non-public" in str(e), f"error should say why: {e}")


def test_redirect_hop_refused():
    with server() as inner_port:
        target = f"http://inside.test:{inner_port}/"
        with server(redirect_to=target) as port, guarded({"public.test": ["127.0.0.1"], "inside.test": ["127.0.0.2"]}):
            with _client() as c:
                r = c.get(f"http://public.test:{port}/x")
                check(r.status_code == 200, f"the public host itself should be reachable, got {r.status_code}")
                try:
                    c.get(f"http://public.test:{port}/", follow_redirects=True)
                    check(False, "the redirect to a private address should be refused")
                except httpx.ConnectError as e:
                    check("non-public" in str(e), f"refusal should name the reason: {e}")


def test_rebinding_refused():
    answers = iter([["127.0.0.1"], ["127.0.0.2"]])
    with server() as port, guarded({"flip.test": lambda: next(answers)}):
        with _client() as c:
            check(c.get(f"http://flip.test:{port}/").status_code == 200, "first answer is public")
        with _client() as c:                         # a fresh connection, a fresh lookup
            try:
                c.get(f"http://flip.test:{port}/")
                check(False, "the rebound (private) answer should be refused")
            except httpx.ConnectError:
                pass


def test_mixed_answers_filtered():
    with guarded({"mixed.test": ["127.0.0.2", "127.0.0.1"]}):
        got = [r[4][0] for r in socket.getaddrinfo("mixed.test", 80)]
        check(got == ["127.0.0.1"], f"only public addresses should remain: {got}")


def test_proxy_settings_removed():
    """A worker connects directly: proxy settings would hide the real address."""
    import subprocess
    code = ("import os; from vendor_audit import netguard; netguard.install(); "
            "print(sorted(k for k in os.environ if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')))")
    env = dict(os.environ, HTTPS_PROXY="http://10.0.0.1:3128", http_proxy="http://10.0.0.1:3128",
               PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=30)
    check(out.stdout.strip() == "[]", f"proxy settings should be gone after install(): {out.stdout or out.stderr}")


def test_install_scope():
    before = socket.getaddrinfo
    with guarded({}):
        netguard.install()
        check(netguard.installed(), "guard should be installed")
    check(socket.getaddrinfo is before, "test helper should restore getaddrinfo")
    check(socket.create_connection is netguard._real_create_connection
          and ssl.SSLContext.wrap_socket is netguard._real_wrap_socket,
          "and the connection tracking")
    from vendor_audit import cli  # noqa: F401
    check(not netguard.installed(), "importing the CLI must not install the guard")


def run():
    for fn in (test_rules_shared, test_private_name_refused, test_redirect_hop_refused,
               test_rebinding_refused, test_mixed_answers_filtered, test_proxy_settings_removed,
               test_install_scope):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nNETGUARD FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll netguard checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
