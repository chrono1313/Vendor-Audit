#!/usr/bin/env python3
"""Web service tests — app structure, result cache, event loop.

  - every route, exception handler and middleware is registered once, and
    no module defines the same top-level function twice (2.2 shipped with
    ~500 lines of app.py duplicated; the copies matched, so nothing broke,
    but a later edit to one copy would have been silently ignored)
  - cache entries are stored compressed and come back unchanged
  - a slow DNS lookup during input validation does not stall other
    requests (the web service runs every request on one event loop)

Run:  python3 tests/test_web.py
Exits non-zero on failure. Skips itself if the web extras are missing.
"""
import ast
import asyncio
import glob
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    import httpx
    from vendor_audit.web import app as appmod
except Exception as _exc:                        # web extras not installed
    appmod = None
    _SKIP = str(_exc)

_failures = []
SRC = os.path.join(os.path.dirname(__file__), "..", "src", "vendor_audit")


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def _skip():
    if appmod is None:
        try:
            import pytest
            pytest.skip(f"web extras not installed: {_SKIP}")
        except ImportError:
            print(f"       (skipped: {_SKIP})")
        return True
    return False


def test_no_duplicate_definitions():
    """No module in the package defines a top-level name twice."""
    for path in sorted(glob.glob(os.path.join(SRC, "**", "*.py"), recursive=True)):
        tree = ast.parse(open(path, encoding="utf-8").read(), path)
        seen = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in seen:
                    check(False, f"{os.path.relpath(path, SRC)}: {node.name} defined at lines "
                                 f"{seen[node.name]} and {node.lineno}")
                seen.setdefault(node.name, node.lineno)


def test_routes_registered_once():
    if _skip():
        return
    pairs = []
    for r in appmod.app.routes:
        for m in sorted(getattr(r, "methods", None) or ["*"]):
            pairs.append((getattr(r, "path", repr(r)), m))
    dupes = sorted({p for p in pairs if pairs.count(p) > 1})
    check(not dupes, f"routes registered more than once: {dupes}")
    names = [m.cls.__name__ for m in appmod.app.user_middleware]
    check(names.count("SecurityHeadersMiddleware") == 1, f"middleware stack: {names}")
    for path in ("/audit/{domain}.txt", "/audit/{domain}.html", "/audit/result", "/static/result.js"):
        check(any(p == path for p, _m in pairs), f"route {path} missing")


def test_cache_compressed():
    if _skip():
        return
    page = "<p>Vendor Audit — résumé · ✓</p>\n" * 6000
    txt = "FINDINGS    2 critical · 4 high\n" * 800
    key = "cache-test.example"
    appmod._result_cache_set(key, page, txt, {"Content-Disposition": "x"}, 1.0)
    stored = appmod._result_cache[key]
    check(isinstance(stored[0], bytes) and isinstance(stored[1], bytes), "entries should be stored as bytes")
    check(len(stored[0]) < len(page.encode("utf-8")) / 5, f"page should be compressed ({len(stored[0])} bytes)")
    got = appmod._result_cache_get(key)
    check(got is not None and got[0] == page and got[1] == txt, "cache must return exactly what was stored")
    check(got is not None and got[2] == {"Content-Disposition": "x"} and got[3] == 1.0, "headers and timestamp kept")
    appmod._result_cache.pop(key, None)


def test_slow_dns_does_not_stall_other_requests():
    """One request waits on a slow lookup; another must still be answered."""
    if _skip():
        return
    real = appmod.validate_domain_input

    from vendor_audit.web.validate import ValidationError

    def slow(domain, *, dns_check=True):
        if not dns_check:
            return real(domain, dns_check=False)
        time.sleep(1.5)                           # a slow name server, then no answer
        raise ValidationError("could not resolve", code="cannot_resolve")

    async def scenario():
        transport = httpx.ASGITransport(app=appmod.app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # The clock starts before the slow request does. If the lookup
            # blocks the event loop, even the short pause below sits
            # through it, so the time has to be measured from here.
            t = time.perf_counter()
            slow_req = asyncio.ensure_future(client.get("/audit/result", params={"domain": "slow-dns.example"}))
            await asyncio.sleep(0.1)              # let it reach the lookup
            r = await client.get("/healthz")
            fast = time.perf_counter() - t
            slow_status = (await slow_req).status_code
            return r.status_code, fast, slow_status

    appmod.validate_domain_input = slow
    try:
        status, fast, slow_status = asyncio.run(scenario())
    finally:
        appmod.validate_domain_input = real
    check(status == 200, f"/healthz answered {status}")
    check(fast < 0.6, f"/healthz took {fast:.2f}s while another request waited on DNS")
    check(slow_status == 400, f"the slow request should end in a rejection, got {slow_status}")


def run():
    for fn in (test_no_duplicate_definitions, test_routes_registered_once,
               test_cache_compressed, test_slow_dns_does_not_stall_other_requests):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nWEB FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll web checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
