"""Fetch limit tests (3.5.7).

Every network call has a time limit and every body read a size limit (see
"Limits on every fetch" in audit_checks.py). These throw hostile responses
at each one and check the audit stops in time without reading it all:

  - an endless body, a compressed bomb and a body that drips a byte at a
    time, through the shared capped fetch
  - the three checks that used to read a whole response (CORS,
    security.txt, the MTA-STS policy)
  - a mail server that never ends its reply
  - a connection left open after an audit, which the web worker closes
"""
import contextlib
import gzip
import os
import socket
import sys
import threading
import time
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx                                           # noqa: E402

from vendor_audit import audit_checks as ac, netguard  # noqa: E402

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append(msg)
        print(f"FAIL: {msg}")


def _endless():
    chunk = b"x" * 65536
    while True:
        yield chunk


def _drip():
    while True:
        yield b"x"
        time.sleep(0.05)


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_capped_fetch():
    with mock.patch.object(ac, "_get_client", return_value=_client(lambda r: httpx.Response(200, content=_endless()))):
        t = time.monotonic()
        resp = ac._http_get("https://example.com/")
        took = time.monotonic() - t
    check(len(resp.content) == ac._FETCH_MAX_BYTES and resp.body_truncated, f"endless body capped: {len(resp.content)}")
    check(took < 2, f"endless body read quickly: {took:.1f}s")
    check(resp.text.startswith("xxx"), "the capped body still reads as text")

    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024))        # 64 MB of zeros in ~64 KB
    with mock.patch.object(ac, "_get_client", return_value=_client(
            lambda r: httpx.Response(200, content=bomb, headers={"Content-Encoding": "gzip"}))):
        resp = ac._http_get("https://example.com/")
    check(len(resp.content) == ac._FETCH_MAX_BYTES and resp.body_truncated,
          f"compressed bomb stops at the cap after decoding: {len(resp.content)}")

    with mock.patch.object(ac, "_get_client", return_value=_client(lambda r: httpx.Response(200, content=_drip()))), \
         mock.patch.object(ac, "_FETCH_BODY_BUDGET_S", 0.5):
        t = time.monotonic()
        resp = ac._read_capped(httpx.Response(200, content=_drip()), ac._FETCH_MAX_BYTES, 0.5)
        took = time.monotonic() - t
    body, truncated = resp
    check(truncated and took < 1.5 and 0 < len(body) < 100, f"dripping body stops at the budget: {took:.1f}s, {len(body)}")

    with mock.patch.object(ac, "_get_client", return_value=_client(
            lambda r: httpx.Response(200, json={"data": {"ok": True}}))):
        resp = ac._http_get("https://stat.ripe.net/data/x/data.json", max_bytes=ac._API_MAX_BYTES)
    check(resp.json() == {"data": {"ok": True}} and not resp.body_truncated, "a normal answer is untouched")
    check(ac._FETCH_BODY_BUDGET_S >= 15, "the body budget is never shorter than the check deadline")


def test_checks_that_read_whole_bodies():
    endless = _client(lambda r: httpx.Response(200, content=_endless(),
                                               headers={"Access-Control-Allow-Origin": "*"}))
    with mock.patch.object(ac, "_get_client", return_value=endless):
        t = time.monotonic()
        out = ac.check_cors("example.com")
        took = time.monotonic() - t
    check(out["outcome"] == "public_wildcard" and took < 3, f"CORS reads headers, not 1 GB: {out['outcome']}, {took:.1f}s")

    with mock.patch.object(ac, "_get_client", return_value=_client(
            lambda r: httpx.Response(200, content=_endless(), headers={"Content-Type": "text/plain"}))):
        t = time.monotonic()
        ac.check_security_txt("example.com")
        took = time.monotonic() - t
    check(took < 5, f"security.txt with an endless body: {took:.1f}s")

    real_client = httpx.Client

    def fake_client(*a, **k):
        k.pop("verify", None)
        return real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=_endless())), **k)
    with mock.patch.object(ac, "_has_a_or_aaaa", return_value=True), \
         mock.patch.object(ac.httpx, "Client", fake_client):
        t = time.monotonic()
        out = ac.check_mta_sts_policy("example.com")
        took = time.monotonic() - t
    check(took < 3 and out.get("fetched") is not None, f"MTA-STS policy with an endless body: {out}, {took:.1f}s")


@contextlib.contextmanager
def _tcp_server(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            threading.Thread(target=handler, args=(conn, stop), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        srv.close()


def test_smtp_reply_cap():
    def endless_greeting(conn, stop):
        try:
            while not stop.is_set():
                conn.sendall(b"220-still going\r\n" * 50)
        except OSError:
            pass
    with _tcp_server(endless_greeting) as port:
        smtp = ac._bounded_smtp(5)
        t = time.monotonic()
        try:
            smtp.connect("127.0.0.1", port)
            err = None
        except Exception as e:                         # noqa: BLE001
            err = e
        took = time.monotonic() - t
        smtp.close()
    check(err is not None and "200 lines" in str(err) and took < 2,
          f"an endless SMTP reply is cut off at the line cap: {err!r}, {took:.1f}s")


def test_leftover_connections_closed():
    def silent(conn, stop):
        stop.wait(10)
        conn.close()
    with _tcp_server(silent) as port, \
         mock.patch.object(socket, "getaddrinfo", netguard._real_getaddrinfo):
        netguard.close_leftover_connections()          # start from nothing tracked
        sock = netguard._tracked_create_connection(("127.0.0.1", port), timeout=10)
        got = {}

        def reader():
            t = time.monotonic()
            try:
                got["data"] = sock.recv(100)
            except OSError as e:
                got["data"] = e
            got["took"] = time.monotonic() - t
        th = threading.Thread(target=reader)
        th.start()
        time.sleep(0.3)
        n = netguard.close_leftover_connections()
        th.join(3)
        sock.close()
    check(n == 1, f"one leftover connection closed: {n}")
    check(not th.is_alive() and got.get("took", 99) < 1.5,
          f"the thread blocked on it was woken: {got}")
    check(netguard.close_leftover_connections() == 0, "nothing left afterwards")


def run():
    for fn in (test_capped_fetch, test_checks_that_read_whole_bodies, test_smtp_reply_cap,
               test_leftover_connections_closed):
        fn()
    print(f"{len(_failures)} failure(s)")
    return not _failures


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
