#!/usr/bin/env python3
"""Web service tests — app structure, result cache, event loop.

  - every route, exception handler and middleware is registered once, and
    no module defines the same top-level function twice (2.2 shipped with
    ~500 lines of app.py duplicated; the copies matched, so nothing broke,
    but a later edit to one copy would have been silently ignored)
  - cache entries are stored compressed and come back unchanged
  - a slow DNS lookup during input validation does not stall other
    requests (the web service runs every request on one event loop)
  - the CSP names every inline <style> block by hash (no 'unsafe-inline')
    and no page uses a style= attribute
  - HEAD is answered on every GET route, with the GET's headers and no body

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
    for path in ("/audit/{domain}.md", "/audit/{domain}.html", "/audit/result", "/static/result.js"):
        check(any(p == path for p, _m in pairs), f"route {path} missing")
    check(not any(p == "/audit/{domain}.txt" for p, _m in pairs), "the .txt download was removed in 3.5.0")


def test_workers_guard_connections():
    """Every audit worker installs the connect-time address guard."""
    if _skip():
        return
    import inspect
    check("initializer=netguard.install" in inspect.getsource(appmod.lifespan),
          "the process pool should install netguard in each worker")
    check("netguard.install()" in inspect.getsource(appmod._worker_audit),
          "_worker_audit should install netguard before auditing")


def test_cache_compressed():
    if _skip():
        return
    page = "<p>Vendor Audit — résumé · ✓</p>\n" * 6000
    txt = "- **HIGH** Website — résumé · ✓\n" * 800
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


def _request(method, url):
    """One request to the app in-process (httpx's ASGI transport)."""
    async def go():
        transport = httpx.ASGITransport(app=appmod.app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.request(method, url)
    return asyncio.run(go())


def _pages():
    """(name, html, csp) for each kind of page the site serves."""
    sys.path.insert(0, os.path.dirname(__file__))
    from test_findings import sample
    out = []
    for name, url in (("form", "/"), ("error", "/no-such-page"), ("bad input", "/audit/result?domain=not a domain"),
                      ("learn", "/learn/spf"), ("learn index", "/learn/"), ("learn eol", "/learn/end-of-life"),
                      ("example report", "/learn/example-report")):
        r = _request("GET", url)
        out.append((name, r.text, r.headers.get("content-security-policy", "")))
    d = sample(); d["_scan"] = {"deep": True, "version": "3.4.4"}
    page = appmod.render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                             "results": d, "timestamp": "2026-11-19T04:55:32Z", "duration_ms": 1200})
    out.append(("result", page, f"{appmod._STYLE_SRC};"))
    loading = appmod.templates.get_template("loading.html").render(
        display_domain="example.com", result_url="/audit/result?domain=example.com", refresh_url="x",
        version="3.4.4", request=None)
    out.append(("loading", loading, _request("GET", "/").headers.get("content-security-policy", "")))
    return out


def test_csp_styles():
    """No 'unsafe-inline': every <style> block is named by hash in the CSP,
    and no page uses a style= attribute (hashes don't cover those)."""
    if _skip():
        return
    import base64
    import hashlib
    import re
    for name, html, csp in _pages():
        check("unsafe-inline" not in csp, f"{name}: CSP still allows 'unsafe-inline'")
        blocks = re.findall(r"<style>(.*?)</style>", html, re.S)
        check(blocks, f"{name}: expected a <style> block")
        for b in blocks:
            h = base64.b64encode(hashlib.sha256(b.encode("utf-8")).digest()).decode()
            check(f"'sha256-{h}'" in csp, f"{name}: <style> block hash sha256-{h[:10]}… not in the CSP")
        attrs = re.findall(r"<[^>]*\sstyle=", html)
        check(not attrs, f"{name}: style= attribute(s) found: {attrs[:2]}")


def test_front_page_counts():
    """The front page states the check count from rubric.json."""
    if _skip():
        return
    import re
    from vendor_audit import audit_checks as ac
    n = ac.check_counts()
    text = re.sub(r"<[^>]+>", "", _request("GET", "/").text)
    check(f"The audit runs {n['standard']} checks in six categories" in text, "front page check count")
    check(f"Deep checks add {n['deep_extra']} more" in text, "front page deep count")
    check("about 60 checks" not in text, "the old count is gone")
    heads = re.findall(r"<h2>([^<]+)</h2>", _request("GET", "/").text)
    want = ["What it's for", "Share it with the vendor", "What it checks", "How it checks"]
    check(heads == want, f"3.5.1: the front page has four sections in order: {heads}")


def test_head():
    """HEAD answers like GET, without the body."""
    if _skip():
        return
    for url in ("/", "/healthz", "/robots.txt", "/.well-known/security.txt", "/favicon.svg", "/static/result.js"):
        g, h = _request("GET", url), _request("HEAD", url)
        check(h.status_code == g.status_code == 200, f"HEAD {url}: {h.status_code} (GET {g.status_code})")
        check(h.content == b"", f"HEAD {url} sent a body")
        for k in ("content-type", "content-security-policy", "content-length"):
            check(h.headers.get(k) == g.headers.get(k), f"HEAD {url}: {k} differs from GET")
    check(_request("HEAD", "/no-such-page").status_code == 404, "HEAD on a missing page should be 404")
    refused = _request("POST", "/")
    check(refused.status_code == 405, "POST should still be refused")
    check(refused.headers.get("allow") == "GET, HEAD", f"405 should list GET, HEAD: {refused.headers.get('allow')}")


def test_fast_clicks_share_one_audit():
    """3.4.9: repeat requests for a domain already being audited wait for
    that run instead of starting their own; a regular request can join a
    deep run, but not the other way round; a cancelled waiter doesn't stop
    the run the others are waiting for."""
    if _skip():
        return
    calls = []

    async def fake_run(pool, domain, *, deep=False):
        calls.append((domain, deep))
        await asyncio.sleep(0.2)
        return {"ok": True, "domain": domain, "deep": deep}

    async def scenario():
        real = appmod._run_audit_in_pool
        appmod._run_audit_in_pool = fake_run
        try:
            r = await asyncio.gather(*(appmod._run_audit_shared(None, "a.example", deep=True) for _ in range(3)))
            check(len(calls) == 1 and all(x["deep"] for x in r), f"three deep clicks, one audit: {calls}")
            calls.clear()
            deep = asyncio.ensure_future(appmod._run_audit_shared(None, "b.example", deep=True))
            await asyncio.sleep(0.01)
            regular = await appmod._run_audit_shared(None, "b.example")
            check(len(calls) == 1 and regular["deep"], f"regular request joins the deep run: {calls}")
            await deep
            calls.clear()
            first = asyncio.ensure_future(appmod._run_audit_shared(None, "c.example"))
            await asyncio.sleep(0.01)
            deep_c = await appmod._run_audit_shared(None, "c.example", deep=True)
            check(len(calls) == 2 and deep_c["deep"], f"a deep request never takes a regular run: {calls}")
            await first
            calls.clear()
            quitter = asyncio.ensure_future(appmod._run_audit_shared(None, "d.example"))
            await asyncio.sleep(0.01)
            stayer = asyncio.ensure_future(appmod._run_audit_shared(None, "d.example"))
            await asyncio.sleep(0.01)
            quitter.cancel()
            got = await stayer
            check(got["ok"] and len(calls) == 1, "closing one tab doesn't cancel the shared audit")
            check(not appmod._inflight, f"nothing left in flight: {list(appmod._inflight)}")
            await asyncio.sleep(0.25)
            await appmod._run_audit_shared(None, "a.example", deep=True)
            check(len(calls) == 2, "a finished run is not reused (the result cache does that)")
        finally:
            appmod._run_audit_in_pool = real

    asyncio.run(scenario())


def test_downloads():
    """3.5.0: the text report downloads as .md; the old .txt path is gone
    (404), and the web page download is named after the same audit."""
    if _skip():
        return
    import types
    sys.path.insert(0, os.path.dirname(__file__))
    from test_findings import sample
    d = sample(); d["_scan"] = {"deep": False, "version": appmod.audit.__version__}
    env = {"ok": True, "domain": "dl-test.example", "audit_domain": "dl-test.example",
           "results": d, "timestamp": "2026-11-25T04:46:50Z", "duration_ms": 1}
    md, headers = appmod._render_report(
        types.SimpleNamespace(original="dl-test.example", domain="dl-test.example"), env)
    page = appmod.render_html.render_result(env)
    appmod._result_cache_set("dl-test.example", page, md, headers, 1.0)
    try:
        r = _request("GET", "/audit/dl-test.example.md")
        check(r.status_code == 200, f".md download: {r.status_code}")
        check(r.headers.get("content-type", "").startswith("text/markdown"), f".md type: {r.headers.get('content-type')}")
        check(r.headers.get("content-disposition", "").endswith('_2026-11-25T04-46-50Z.md"'),
              f".md name: {r.headers.get('content-disposition')}")
        check(r.text.startswith("# Vendor Audit — dl-test.example\n"), "the .md is the Markdown report")
        h = _request("GET", "/audit/dl-test.example.html")
        check(h.headers.get("content-disposition", "").endswith('_2026-11-25T04-46-50Z.html"'),
              f".html name: {h.headers.get('content-disposition')}")
        check(_request("GET", "/audit/dl-test.example.txt").status_code == 404, "old .txt links answer 404")
        check('href="/audit/dl-test.example.md"' in page and ">Download text report (.md)<" in page
              and ">Download web page (.html)<" in page, "the page links to both downloads")
        form = _request("GET", "/").text
        check("Every report can be downloaded as a text file or a web page." in form
              and "Please share the text report with the vendor." in form
              and ".txt" not in form.replace("security.txt", ""),
              "the front page describes the two downloads")
    finally:
        appmod._result_cache.pop("dl-test.example", None)


def test_learn_pages():
    """3.5.14: /learn/ explainer pages, built from the audit's own text:
    every rated check on exactly one page, with every result it can give;
    an index, a sitemap, and links from the front page and from results."""
    if _skip():
        return
    import html as htmlmod
    import re
    from vendor_audit import audit_checks as ac
    from vendor_audit import audit_records as ar
    from vendor_audit.web import learn
    placed = [lb for labels in learn.checks_by_page().values() for lb in labels]
    check(sorted(placed) == sorted(ac.RUBRIC["findings"]),
          f"every check on exactly one page: missing {set(ac.RUBRIC['findings']) - set(placed)}, "
          f"twice {[lb for lb in set(placed) if placed.count(lb) > 1]}")
    for slug, labels in learn.checks_by_page().items():
        r = _request("GET", f"/learn/{slug}")
        check(r.status_code == 200, f"/learn/{slug}: {r.status_code}")
        page = htmlmod.unescape(r.text)
        check(f'rel="canonical" href="https://vendoraudit.org/learn/{slug}"' in page, f"{slug}: canonical URL")
        check(f"<title>{learn.PAGES[slug]['title']} | Vendor Audit</title>" in page, f"{slug}: title")
        check(len(learn.PAGES[slug]["description"]) <= 200, f"{slug}: description fits a search result")
        check('<form class="try" method="get" action="/audit">' in page, f"{slug}: a form to run an audit")
        for label in labels:
            check(f'id="{ar.slug(label)}"' in r.text, f"{slug}: {label} has its own section")
            for severity, text in ac.RUBRIC["findings"][label].values():
                check(text in page, f"{slug}: {label}: result text missing: {text[:50]}")
        for rel in learn.PAGES[slug]["related"]:
            check(rel in learn.PAGES, f"{slug}: related page {rel} exists")
        check("<script" not in r.text and "&#34;<code>" not in r.text, f"{slug}: no script, no quoted code")
    spf = _request("GET", "/learn/spf").text
    check('href="https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4"' in spf, "standards are linked")
    check("<code>v=spf1 -all</code>" in spf, "record syntax set as code")
    eol = htmlmod.unescape(_request("GET", "/learn/end-of-life").text)
    check("Exim" in eol and "Ubuntu" in eol and "jQuery" in eol, "the end-of-life page lists what it recognises")
    check(_request("GET", "/learn/no-such-topic").status_code == 404, "unknown page: 404")
    ix = _request("GET", "/learn/")
    check(ix.status_code == 200 and all(f'href="/learn/{slug}"' in ix.text for slug in learn.PAGES),
          "the index links every page")
    check(_request("GET", "/learn").status_code in (200, 301), "/learn redirects to /learn/")
    sm = _request("GET", "/sitemap.xml")
    check(sm.status_code == 200 and "xml" in sm.headers.get("content-type", "")
          and all(f"<loc>https://vendoraudit.org/learn/{slug}</loc>" in sm.text for slug in learn.PAGES)
          and "/audit" not in sm.text, "sitemap.xml lists the pages and no /audit URL")
    robots = _request("GET", "/robots.txt").text
    check("Disallow: /audit" in robots and "Disallow: /learn" not in robots and "Disallow: /\n" not in robots
          and "Sitemap: https://vendoraudit.org/sitemap.xml" in robots, "robots.txt: /learn open, sitemap named")
    front = _request("GET", "/").text
    links = set(re.findall(r'href="(/learn/[^"#]*)"', front))
    check(len(links) >= 15 and all(_request("GET", u).status_code == 200 for u in links),
          f"the front page links the guides, and every link works: {sorted(links)}")
    ex = _request("GET", "/learn/example-report")
    check(ex.status_code == 200 and "script-src 'self'" in ex.headers.get("content-security-policy", "")
          and '<script src="/static/result.js' in ex.text and "<!--AGO-->" not in ex.text,
          "example report: served, with its script allowed")
    check("<loc>https://vendoraudit.org/learn/example-report</loc>" in sm.text, "sitemap lists the example report")
    check('href="/learn/example-report"' in front and 'href="/learn/example-report"' in ix.text,
          "the front page and /learn/ link the example report")
    md = _request("GET", "/learn/example-report.md")
    check(md.status_code == 200 and md.text.startswith("# Vendor Audit — sample-vendor.example")
          and 'filename="vendor-audit-example-report.md"' in md.headers.get("content-disposition", ""),
          "example report .md download")
    saved = _request("GET", "/learn/example-report.html")
    check(saved.status_code == 200 and "<script>" in saved.text and "See the current example" in saved.text
          and 'filename="vendor-audit-example-report.html"' in saved.headers.get("content-disposition", ""),
          "example report .html download")
    sys.path.insert(0, os.path.dirname(__file__))
    from test_findings import sample
    page = appmod.render_html.render_result({"ok": True, "domain": "example.com", "audit_domain": "example.com",
                                             "results": sample(), "timestamp": "2026-11-27T00:00:00Z",
                                             "duration_ms": 1})
    guides = re.findall(r'class="guide-link" href="([^"]+)"', page)
    check(guides and all(g.startswith("https://vendoraudit.org/learn/") for g in guides)
          and 'href="https://vendoraudit.org/learn/hsts#hsts"' in page,
          f"each finding links its guide section: {guides[:3]}")


def run():
    for fn in (test_no_duplicate_definitions, test_routes_registered_once,
               test_workers_guard_connections, test_cache_compressed, test_slow_dns_does_not_stall_other_requests,
               test_csp_styles, test_front_page_counts, test_head, test_fast_clicks_share_one_audit, test_downloads,
               test_learn_pages):
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
