"""vendor_audit.web.app — FastAPI application.

The web layer wraps the audit library in a small HTTP service:

  GET  /                       — input form
  POST /audit                  — run an audit, render result
  GET  /audit/<domain>.txt     — re-run audit, return as plain text
  GET  /healthz                — liveness probe (no audit)
  GET  /robots.txt             — Disallow: /

The application is meant to bind to 127.0.0.1 only and sit behind cloudflared
(or another tunnel) which provides TLS and the public path. Direct exposure
on the LAN is not supported.

DESIGN DECISIONS
----------------

Process pool, not thread pool. Each audit runs in a forked child process, so
that catastrophic-backtracking regexes on adversarial HTML, OOM in a parser,
or any other process-crashing bug only takes out one worker. The pool fills
gradually as workers are reaped and replaced.

Wall-clock timeout per audit. asyncio.wait_for() bounds the time we spend
waiting on a future. If the timeout fires, we cancel the future, but the
worker process keeps running until the audit's own internal timeouts finish
the job — that's why the pool is sized larger than peak concurrency: we can
afford some workers to be slow-stragglers without blocking new requests.

Rate limiting via slowapi. In-memory storage; one instance per app process.
This is intentional: a single uvicorn worker is the deployment target, and
we don't need cross-instance coordination. If we ever go multi-worker we'll
plug in a Redis backend and update this comment.

No shared state between requests. The app is stateless. Audit results aren't
cached (the handoff explicitly defers caching). Refreshing the result page
re-runs the audit; that's fine for v1 traffic.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from .. import audit, audit_txt_report
from . import render_html
from .validate import ValidationError, validate_domain_input

log = logging.getLogger("vendor_audit.web")

# Configure our logger to actually emit. Uvicorn configures its own
# loggers (the "INFO: ..." lines you see at startup) but doesn't set up
# anything that captures application-level loggers like ours. Without
# this block our log.info() / log.warning() calls would be silently
# discarded — bad for operational visibility.
#
# stderr → captured by systemd → visible in `journalctl -u vendor-audit`.
# We set propagate=False so that if a future operator calls
# logging.basicConfig() elsewhere, we don't get duplicate lines.
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)
    log.propagate = False

# ── Configuration (env vars, with sensible defaults for dev) ─────────────────

# Number of process-pool workers. Audits are mixed CPU+I/O — network
# waits dominate but TLS handshakes, regex evaluation, and JSON parsing
# are real CPU work. Sized at roughly 1.5× core count for a typical
# small VM (10 cores → 16 workers), giving margin for I/O-blocked
# workers during sustained bursts. Going past ~2× core count adds
# context-switch overhead without throughput because the GIL serializes
# in-process Python work.
#
# Memory: each worker is ~80MB resident (Python + tldextract +
# httpx + audit deps), so 16 workers = ~1.3GB. Adjust systemd's
# MemoryMax accordingly.
#
# Override with VENDOR_AUDIT_WORKERS for tuning.
WORKERS = int(os.environ.get("VENDOR_AUDIT_WORKERS", "16"))

# Wall-clock cap per audit at the web layer. The audit itself has its own
# internal deadlines: check_redirect (6s hard), parallel-checks pool
# (~15s — see audit.AUDIT_WALL_DEADLINE_S), post-pool jobs (~7s). Worst
# case: 6 + 15 + 7 = 28s. This outer timeout is the safety net if those
# deadlines are bypassed. 35s leaves slack above the audit's ~28s worst
# case for synthesis (CSP analysis, etc.) and for rendering the result.
AUDIT_TIMEOUT_S = int(os.environ.get("VENDOR_AUDIT_TIMEOUT_S", "35"))

# Per-IP rate limits. Tuned by handoff guidance ("~3 per 10s") but expressed
# as slowapi-compatible strings. The /audit POST endpoint is the expensive
# one; the form page is lightly limited just to stop pure flooding. The
# .txt endpoint isn't rate-limited at this layer — its in-memory cache
# (the unified result cache) makes repeat downloads free, and fresh audits
# triggered through it are bounded by the worker pool size.
LIMIT_AUDIT = os.environ.get("VENDOR_AUDIT_LIMIT_AUDIT", "3/10seconds")
LIMIT_FORM  = os.environ.get("VENDOR_AUDIT_LIMIT_FORM",  "60/minute")

# When True, the app trusts the X-Forwarded-For / CF-Connecting-IP headers.
# This must be True in production (cloudflared sends connections from
# 127.0.0.1 with the real client IP in headers) and False in local dev.
TRUST_PROXY_HEADERS = os.environ.get("VENDOR_AUDIT_TRUST_PROXY", "1") == "1"

# Public URL of this service. Embedded in security.txt's Canonical: line
# (RFC 9116) so vulnerability researchers can verify they're looking at
# the canonical file. Self-hosters should set this to their own URL.
SERVICE_URL = os.environ.get("VENDOR_AUDIT_SERVICE_URL", "https://vendoraudit.org")

# Deprecated env vars (TXT cache merged into the unified result cache).
# Warn at startup if an operator still has these set so they discover
# the deprecation without it silently being a no-op.
for _deprecated in ("VENDOR_AUDIT_TXT_CACHE_TTL_S", "VENDOR_AUDIT_TXT_CACHE_MAX"):
    if os.environ.get(_deprecated) is not None:
        # Use plain logging since our logger isn't configured yet at
        # module import time. Goes to stderr; systemd captures it.
        import sys
        print(
            f"[vendor-audit] warning: {_deprecated} is deprecated and ignored. "
            f"The TXT cache is now merged with the HTML cache; configure via "
            f"VENDOR_AUDIT_HTML_CACHE_TTL_S / VENDOR_AUDIT_HTML_CACHE_MAX.",
            file=sys.stderr,
        )

# ── HTML result-page cache ────────────────────────────────────────────────────
#
# Caches the rendered result-page HTML for each audited domain. The reason
# is the viral-link case: a popular share of a single audit URL drives
# many simultaneous requests, all of which would otherwise run identical
# audits. With this cache, only the first hit pays the audit cost; the
# rest are served from cache for the duration of the TTL.
#
# 24 hours: most vendor security postures don't change daily; cache hits
# across a full day of viral-link traffic save substantial worker-pool
# work. The age of the cached result is displayed prominently to the
# user ("Scanned N hours ago") so a stale view is honest rather than
# deceptive — and the re-audit form posts with ?fresh=1 to bypass this
# cache for anyone explicitly asking for a fresh audit.
HTML_CACHE_TTL_S = int(os.environ.get("VENDOR_AUDIT_HTML_CACHE_TTL_S", "86400"))

# Hard cap on the number of result-page cache entries. Each entry holds
# both the HTML and the TXT rendering — ~80KB combined — so 5000 entries
# = ~400MB max. Sized for sustained worldwide use beyond a single viral
# link burst: technical users auditing their vendor lists collectively
# touch thousands of distinct domains over a 24-hour window. At 1000 the
# cache would fill within a few days of broad usage and start evicting
# entries that are still being actively viewed (popular vendors get
# repeat traffic for weeks). 5000 keeps a comfortable cushion against
# memory while preserving cache hits across the full TTL.
HTML_CACHE_MAX_ENTRIES = int(os.environ.get("VENDOR_AUDIT_HTML_CACHE_MAX", "5000"))


# ── Unified result cache (HTML + TXT) ────────────────────────────────────────
#
# Module-level dict, intentionally simple. FastAPI request handlers run
# on a single asyncio loop thread, so dict access between awaits is
# atomic. The race on concurrent first-cache-misses (two requests both
# run the audit, last one wins on cache_set) is benign — the work is
# idempotent and the wasted audit is bounded to one duplicate per
# domain per TTL window in the worst case.
#
# Both rendering forms (HTML and TXT) are stored together so a download
# triggered from a cached HTML view returns the txt that corresponds
# *exactly* to that HTML — same audit run, same timestamp, same
# findings. Without this unification the two caches drift independently
# and a cached 12-hour-old HTML view would show a fresh audit's txt
# (which contradicts what the user is reading on screen).
#
# Entries: {domain: (html, txt, txt_headers, audit_ts, expires)}
#   html         — rendered result-page HTML with <!--AGO--> placeholder
#   txt          — rendered .txt report (final, no placeholder)
#   txt_headers  — Content-Disposition etc. for the txt response
#   audit_ts     — unix timestamp of the audit; powers "ago" display
#   expires      — unix timestamp; eviction trigger
#
# Eviction: lazy on read (expired entries are dropped when accessed),
# plus an explicit prune on write when len(_result_cache) hits the cap.

_result_cache: dict = {}


def _result_cache_get(key: str):
    """Return (html, txt, txt_headers, audit_ts) tuple if cached and not
    expired, else None.

    All four fields are returned together so the caller picks what it
    needs. The HTML serve path uses html+audit_ts; the .txt download
    path uses txt+txt_headers.
    """
    entry = _result_cache.get(key)
    if entry is None:
        return None
    html, txt, txt_headers, audit_ts, expires = entry
    if time.time() >= expires:
        # Lazy eviction — drop and return miss
        _result_cache.pop(key, None)
        return None
    return (html, txt, txt_headers, audit_ts)


def _result_cache_set(key: str, html: str, txt: str, txt_headers: dict, audit_ts: float):
    """Store the rendered HTML+TXT pair with HTML_CACHE_TTL_S TTL.

    Approximate LRU: dropping the soonest-to-expire entry isn't true
    LRU (which would require tracking access times) but it's close
    enough — that entry was going to be gone shortly anyway, and the
    approximation avoids the complexity of separate access tracking.
    """
    expires = time.time() + HTML_CACHE_TTL_S
    if len(_result_cache) >= HTML_CACHE_MAX_ENTRIES and key not in _result_cache:
        oldest_key = min(_result_cache, key=lambda k: _result_cache[k][4])
        _result_cache.pop(oldest_key, None)
    _result_cache[key] = (html, txt, txt_headers, audit_ts, expires)


def _format_age(seconds: float) -> str:
    """Format a duration as 'N minutes/hours/days ago' for display.

    Thresholds:
      < 1 min   → 'just now'
      < 60 min  → 'N minute(s) ago'
      < 24 hr   → 'N hour(s) ago'
      ≥ 24 hr   → 'N day(s) ago'
    """
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        n = int(seconds // 60)
        return f"{n} minute{'s' if n != 1 else ''} ago"
    if seconds < 86400:
        n = int(seconds // 3600)
        return f"{n} hour{'s' if n != 1 else ''} ago"
    n = int(seconds // 86400)
    return f"{n} day{'s' if n != 1 else ''} ago"


def _inject_age(html: str, audit_ts: float) -> str:
    """Replace the <!--AGO--> placeholder in rendered HTML with the
    appropriate "scanned status" string for this request.

    Two cases the user can be in:
      1. They just triggered an audit (form submit or re-audit). They
         sat through the loading page and got a result. From their
         perspective they ran an audit. Show "just now" — *not* "from
         cache" — even though the 303-redirect mechanics mean the
         response technically came through the cache that their own
         fresh=1 request populated milliseconds earlier.
      2. They opened a shared link or refreshed a previous result.
         The data was prepared by someone else's prior request. Show
         "From cache, N ago".

    The two cases differ by cache-entry age. Measured round-trip on
    the production VM is ~2-3s under load (fresh audit completion +
    303 + browser follow + handler dispatch on a busy worker pool),
    so a sub-10-second-old entry is almost certainly being served to
    the user who triggered the audit. An older entry is a genuine
    cache hit by a different visitor.

    Edge case: if user B opens a shared link 8 seconds after user
    A's audit completes, user B sees "just now" instead of "From
    cache, just now." Benign — the data IS fresh, and "just now" is
    accurate even if the framing is slightly off.

    The placeholder pattern lets us cache HTML domain-keyed (one entry
    per domain) and still produce per-request text — each visitor
    gets the substitution that matches their moment of viewing.
    """
    age = time.time() - audit_ts
    # Sub-10-second threshold: the user is almost certainly viewing a
    # result they just triggered (303-redirect round trip, which can
    # run 2-3s on the production VM under load).
    if age < 10:
        replacement = " · just now"
    else:
        replacement = f" · From cache, {_format_age(age)}"
    return html.replace("<!--AGO-->", replacement)


# security.txt content (RFC 9116). Configured via env so the operator can
# rotate the contact address or extend the expiry without a code deploy.
# All values are strings; the endpoint assembles the file from them.
#
# Expires must be ISO 8601 UTC (e.g. "2027-01-01T00:00:00Z"). Per RFC 9116
# the value should not be more than a year out; Vendor Audit's own checker
# warns at >12 months. Default is "1 year from server start" which is a
# safe value but means restarting the service rolls Expires forward.
SECURITY_CONTACT  = os.environ.get(
    "VENDOR_AUDIT_SECURITY_CONTACT",
    "https://github.com/chrono1313/Vendor-Audit/security/advisories/new",
)
_default_expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
SECURITY_EXPIRES  = os.environ.get("VENDOR_AUDIT_SECURITY_EXPIRES", _default_expires)
SECURITY_LANG     = os.environ.get("VENDOR_AUDIT_SECURITY_LANG", "en")


# ── Client-IP resolution for rate limiting ───────────────────────────────────

def _client_ip(request: Request) -> str:
    """Return the originating client IP for rate-limit keying.

    In production the request hits 127.0.0.1 from cloudflared, so
    request.client.host is always 127.0.0.1 — useless for per-client
    limits. Cloudflare sets CF-Connecting-IP with the real public IP;
    that's what we key on when TRUST_PROXY_HEADERS is set.

    Falls back to X-Forwarded-For (first hop) if CF-Connecting-IP isn't
    present, then to request.client.host. The fallback chain matters for
    local testing without Cloudflare.
    """
    if TRUST_PROXY_HEADERS:
        cf = request.headers.get("CF-Connecting-IP")
        if cf:
            return cf.strip()
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            # XFF is comma-separated; left-most is the original client.
            return xff.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=_client_ip)


# ── Process pool lifecycle ───────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Spin up the process pool on startup, shut it down on exit."""
    log.info("starting process pool with %d workers", WORKERS)
    # max_tasks_per_child recycles each worker process after this many
    # audits, capping any per-process state buildup. The audit's
    # deadline path can leak threads (sockets stuck on blackholing
    # hosts that exit only after their TCP connect timeout fires);
    # those threads are harmless but use memory until they wind down.
    # Recycling at 50 tasks bounds the worst case to ~50 leaked threads
    # per worker before a fresh process replaces it. Python 3.11+
    # supports this kwarg; on older runtimes the worker just lives
    # longer (still correct, just bigger memory ceiling).
    pool = ProcessPoolExecutor(max_workers=WORKERS, max_tasks_per_child=50)
    app.state.pool = pool
    try:
        yield
    finally:
        log.info("shutting down process pool")
        pool.shutdown(wait=False, cancel_futures=True)


# ── Worker entry point (runs in a child process) ─────────────────────────────

def _worker_audit(domain: str, *, deep: bool = False) -> dict:
    """Top-level function for the process pool. Must be picklable.

    safe_run_audit handles the per-worker config setters (set_deep,
    set_http_timeout) and returns the {ok, error, ...} envelope. Any
    exception escaping THIS function would kill the worker; safe_run_audit
    catches everything internally so this should never happen, but the
    pool will recover if it does.
    """
    return audit.safe_run_audit(domain, deep=deep)


# ── Templates ────────────────────────────────────────────────────────────────

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATE_DIR)


# ── App construction ─────────────────────────────────────────────────────────

app = FastAPI(
    title="Vendor Audit",
    description="Passive domain security and maturity audit.",
    version=audit.__version__,
    docs_url=None,        # no public OpenAPI docs
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.state.limiter = limiter


# ── Exception handlers ───────────────────────────────────────────────────────

# Replace FastAPI/Starlette's default JSON error responses with our HTML
# error page. Reasons:
#   1. Consistency: validation errors already render error.html; 404 / 405
#      / 429 / 500 should match.
#   2. Audience: most people landing on a 404 are users who mistyped a URL
#      or followed a stale link, not API clients. JSON is hostile to them.
#   3. Tone: a 500 in particular is exactly when a "what happened, what
#      to do" message is most valuable. The default JSON shape is just
#      anxiety-inducing.
#
# The HTTP status code is preserved (we still return 404, 429, 500) — only
# the body shape changes from JSON to HTML.

def _render_error_page(
    request: Request,
    *,
    status_code: int,
    title: str,
    message: str,
    code: str,
) -> HTMLResponse:
    """Render error.html with the given context.

    Helper so the four handlers below stay short and consistent.
    """
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "title": title,
            "message": message,
            "code": code,
            "version": audit.__version__,
        },
        status_code=status_code,
    )


async def _http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Catch 404, 405, and other framework-raised HTTPException responses.

    FastAPI itself raises StarletteHTTPException for unmatched routes (404)
    and method-not-allowed (405); explicit HTTPException(...) raises in our
    code path through here too.
    """
    if exc.status_code == 404:
        return _render_error_page(
            request,
            status_code=404,
            title="Page not found",
            message=(
                "That URL doesn't match any page on this site. The link may "
                "be stale, or the address may have a typo. Head back to the "
                "home page to start a new audit."
            ),
            code="not_found",
        )
    if exc.status_code == 405:
        return _render_error_page(
            request,
            status_code=405,
            title="That action isn't supported",
            message=(
                "This URL exists but doesn't accept the request method that "
                "was used. Head back to the home page to start an audit."
            ),
            code="method_not_allowed",
        )
    # Catch-all for any other HTTPException we haven't tailored. Preserves
    # the original status code and uses the exception's detail as the body.
    return _render_error_page(
        request,
        status_code=exc.status_code,
        title=f"Error {exc.status_code}",
        message=str(exc.detail) if exc.detail else "An error occurred handling that request.",
        code=f"http_{exc.status_code}",
    )


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Replace slowapi's default JSON 429 with our HTML error page.

    The default response is a plain `{"error": "Rate limit exceeded: 3 per
    10 second"}` — accurate but unhelpful to a user who just hit refresh
    too fast. The HTML page tells them what to do.
    """
    return _render_error_page(
        request,
        status_code=429,
        title="Too many requests",
        message=(
            "You've sent more requests than the rate limit allows. This is "
            "to keep the service responsive for everyone. Wait a few "
            "seconds and try again."
        ),
        code="rate_limited",
    )


async def _server_error_handler(request: Request, exc: Exception):
    """Catch any unhandled exception and render a generic 500 page.

    The exception is logged at error level so we can investigate; the
    user just sees a friendly "something went wrong" message rather than
    a stack trace or the default JSON.
    """
    log.exception("unhandled exception during request: path=%s", request.url.path)
    return _render_error_page(
        request,
        status_code=500,
        title="Something went wrong",
        message=(
            "An error occurred handling that request. The error has been "
            "logged. Try again, or head back to the home page to start a "
            "new audit."
        ),
        code="server_error",
    )


app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
app.add_exception_handler(Exception, _server_error_handler)


# ── Security headers middleware ──────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply baseline security headers to every response.

    Vendor Audit's whole purpose is grading other domains on their security
    headers. Our own headers being right is table stakes — and the tool
    will (correctly) flag itself otherwise.

    The CSP is intentionally tight because the result page renders
    user-provided domain names. We don't reflect them in any way that
    allows HTML injection (Jinja autoescapes), but a strict CSP is the
    right belt-and-suspenders.

    All our pages are JS-free except for the result page, which loads
    /static/result.js for the expand-all / collapse-all controls.
    The CSP for the result page allows script-src 'self' (own-origin
    only, no inline, no eval); every other page stays at script-src
    'none'. The strongest possible setting per page.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Most pages are JS-free → script-src 'none' (the strictest setting,
        # blocking even legitimate scripts on the page).
        #
        # The result page loads /static/result.js for the expand-all /
        # collapse-all buttons and the inline-form blank-submit / same-
        # domain bypass-cache helpers. Cloudflare also auto-injects its
        # Web Analytics / Rocket Loader / Email Decoder scripts into
        # responses behind its proxy — both as external loads from
        # cloudflareinsights.com / ajax.cloudflare.com / cdn-cgi/, and
        # as small inline bootstrap snippets. To let those Cloudflare
        # injections run, the result-page CSP includes 'unsafe-inline'
        # and the relevant Cloudflare hosts. This is a deliberate
        # trade-off:
        #
        #   - Our /static/result.js is same-origin and would have run
        #     under the stricter script-src 'self' too — the loosening
        #     is purely for Cloudflare's injected code, not ours.
        #   - 'unsafe-inline' weakens defence-in-depth: if there's
        #     ever an XSS bug in our HTML rendering, the CSP no longer
        #     blocks the injected payload. The mitigation is that
        #     Jinja2 autoescaping is on for all templates and we
        #     manually escape (_h) every user-supplied value into the
        #     rendered HTML.
        #   - Vendor Audit's own audit will flag this as a CSP weakness
        #     when run against vendoraudit.org. That's accurate — and
        #     fixable later by either disabling Cloudflare's injected
        #     scripts (Web Analytics off, Rocket Loader off) or moving
        #     to a nonce-per-request CSP that lets specific scripts
        #     through without 'unsafe-inline'.
        #
        # The form, loading, and error pages stay at script-src 'none'.
        # No JS lives there and the user input is short-lived; tighter
        # is better.
        path = request.url.path
        is_result_page = (
            path == "/audit/result" or path == "/static/result.js"
        )
        if is_result_page:
            script_src = (
                "script-src 'self' 'unsafe-inline' "
                "https://static.cloudflareinsights.com "
                "https://ajax.cloudflare.com"
            )
        else:
            script_src = "script-src 'none'"

        # connect-src controls fetch/XHR/beacon destinations. Cloudflare
        # Web Analytics POSTs page metrics to cloudflareinsights.com,
        # which the default 'self' fallback would block. Same scope as
        # script-src — only loosened for the result page.
        if is_result_page:
            connect_src = "connect-src 'self' https://cloudflareinsights.com"
        else:
            connect_src = "connect-src 'self'"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"{script_src}; "
            f"{connect_src}; "
            "style-src 'self' 'unsafe-inline'; "  # inline styles in templates
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )
        # X-Frame-Options redundant with frame-ancestors but cheap insurance
        # for older browsers / proxies.
        response.headers["X-Frame-Options"] = "DENY"

        # Cross-Origin isolation headers. We set the strictest values
        # because the site has no cross-origin embedding needs:
        #   COOP=same-origin: a top-level browsing context with this
        #     header cannot share a browsing-context group with cross-
        #     origin pages — defends against tab-nabbing and Spectre.
        #   CORP=same-origin: any cross-origin loader (image, iframe,
        #     script tag elsewhere) cannot embed our resources at all.
        # Together these enable cross-origin isolation; we don't actually
        # need that capability (no SharedArrayBuffer), but the headers
        # are also good defense in depth on their own.
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # HSTS is set by Cloudflare at the edge. We don't set it here because
        # it's the proxy that terminates TLS; setting it on the upstream
        # plain-HTTP response is meaningless.
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
@limiter.limit(LIMIT_FORM)
async def form_page(request: Request):
    """The audit input form."""
    return templates.TemplateResponse(
        request=request,
        name="form.html",
        context={"version": audit.__version__},
    )


@app.get("/audit", include_in_schema=False)
@app.get("/audit/", include_in_schema=False)
@limiter.limit(LIMIT_FORM)
async def audit_get(request: Request, domain: str = "", fresh: int = 0, deep: int = 0):
    """GET entry point — bookmarkable / shareable URL.

    With no `?domain=` query param, redirects to the form page (303).
    With a domain, returns a small "Auditing example.com..." loading
    page that meta-refreshes to /audit/result?domain=foo where the
    audit actually runs. The two-step gives the user immediate visual
    feedback during slow audits (blackholed hosts in particular)
    instead of staring at a blank page until the audit's deadline
    fires.

    The shareable URL is /audit?domain=foo — recipients always see the
    loading page first, then the result. The result URL itself is also
    bookmarkable for power users who want to skip the brief loading
    flash.

    fresh=1 is forwarded through to /audit/result, so the re-audit
    button (which submits here with fresh=1) shows the loading page
    too — important now that re-audit always runs a fresh audit (the
    cache is 24h, so re-audit is a real 3-5s operation, not the
    sub-second cache hit it used to be when TTL was 60s).

    deep=1 enables --deep-mode checks (DANE, STARTTLS-MX, page parse).
    The form's optional checkbox sends this; it adds 3-5 seconds and
    is opt-in to keep the default audit fast. The flag is forwarded
    through to /audit/result and contributes to the cache key, so
    deep and non-deep results don't poison each other's cache.

    Rate-limited under LIMIT_FORM (60/min) since this endpoint does no
    audit work — the actual audit happens at /audit/result, where
    LIMIT_AUDIT (3/10s) applies. If we used LIMIT_AUDIT here too, every
    form submission would burn TWO tokens (loading + result), cutting
    user capacity in half.

    We do basic shape validation here (cheap, no network) so obviously-
    bad input goes straight to the error page without the loading
    detour. The /audit/result endpoint re-validates with the full
    SSRF-guard pipeline before doing any audit work.
    """
    if not domain or not domain.strip():
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    # Cheap pre-flight: catch obviously bad input here so the user
    # doesn't see a loading page that resolves to an error. The full
    # SSRF/DNS validation runs in /audit/result; if THAT fails (e.g.
    # private IP), the user lands on the error page after the loading
    # flash. Slightly worse UX than catching everything here, but
    # keeping this endpoint network-free preserves the "instant
    # response" property we want.
    try:
        validate_domain_input(domain, dns_check=False)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "That input couldn't be audited",
                "message": str(exc),
                "code": exc.code,
                "version": audit.__version__,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Pass the domain (and the fresh / deep flags if set) through. We
    # URL-encode the domain to be safe against any character that might
    # survive shape validation but confuse the URL parser.
    from urllib.parse import quote
    result_url = f"/audit/result?domain={quote(domain.strip())}"
    if fresh:
        result_url += "&fresh=1"
    if deep:
        result_url += "&deep=1"
    return templates.TemplateResponse(
        request=request,
        name="loading.html",
        context={
            "display_domain": domain.strip(),
            "result_url": result_url,
        },
    )


@app.get("/audit/result", include_in_schema=False)
@limiter.limit(LIMIT_AUDIT)
async def audit_result(request: Request, domain: str = "", fresh: int = 0, deep: int = 0):
    """Actual audit-running endpoint. Renders the result page.

    Shape: same as the old /audit GET — validate, run audit, render.
    Reachable directly (e.g. bookmarked from the URL bar) and reached
    via meta refresh from /audit. Also where the form page submits
    its result requests via the GET form.

    fresh=1 bypasses the result-page HTML cache (and refreshes the
    cache entry with the new result). The re-audit form submits with
    fresh=1 so a user explicitly asking for a fresh audit always gets
    one, not a 60-second-old cache hit.

    deep=1 enables the audit's --deep-mode checks. Becomes part of the
    cache key — a deep-mode result and a regular result for the same
    domain are stored separately so the user always sees what they
    asked for, not an opportunistically-cached different mode.
    """
    if not domain or not domain.strip():
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return await _run_audit_and_render(request, domain,
                                        fresh=bool(fresh), deep=bool(deep))


async def _run_audit_and_render(request: Request, domain: str, *,
                                 fresh: bool = False, deep: bool = False):
    """Shared audit→render flow used by both POST and GET /audit.

    Returns:
        - HTMLResponse on success (the result page)
        - TemplateResponse(error.html, 400) on validation failure
        - TemplateResponse(error.html, 5xx-ish) on audit failure

    The validation step runs synchronously (DNS resolution included via
    the SSRF guard); the audit itself goes to the worker pool.

    fresh=True bypasses the HTML cache check; the audit runs and the
    new result is stored in the cache. fresh=False (default) returns a
    cached result if one exists, otherwise runs the audit and caches.

    deep=True enables the audit's --deep-mode checks (DANE, STARTTLS-MX,
    page parse). Cache lookup honors deep-as-superset: a regular
    request first checks its own slot, then falls back to the deep
    slot if present. A deep request only checks the deep slot — it
    never serves a regular-cached result, because the regular result
    doesn't have the deep checks the user asked for.
    """
    # Two-stage validation: shape-only first (cheap, no I/O) so we can
    # check the cache without a DNS round-trip. Full validation with the
    # SSRF guard runs only on cache miss, before we actually run the
    # audit. Without this split, every request — even cache hits — would
    # block on DNS for 1-5s, defeating the cache's purpose.
    try:
        shape_only = validate_domain_input(domain, dns_check=False)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "That input couldn't be audited",
                "message": str(exc),
                "code": exc.code,
                "version": audit.__version__,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Cache keys: regular at <domain>, deep at <domain>::deep.
    cache_key = shape_only.domain + ("::deep" if deep else "")

    # Cache check, with deep-as-superset fallback.
    #
    # Lookup order:
    #   - Regular request: own slot first; if miss, deep slot.
    #     Rationale: a deep audit ran every check a regular audit
    #     would have, plus more. Serving deep-cached to a regular
    #     requester is honest (the page declares --deep) and avoids
    #     a redundant audit run when we already have the answer.
    #   - Deep request: only the deep slot. Never falls back to
    #     regular — that would silently downgrade what the user
    #     asked for.
    # Skipped when fresh=True (re-audit / explicit cache bypass).
    if not fresh:
        cached = _result_cache_get(cache_key)
        cache_hit_kind = "exact" if cached else None
        if cached is None and not deep:
            # Regular request, regular cache missed → try the deep slot.
            cached = _result_cache_get(shape_only.domain + "::deep")
            if cached is not None:
                cache_hit_kind = "deep-fallback"
        if cached is not None:
            cached_html, _, _, cached_audit_ts = cached
            log.info("audit cache hit (%s): domain=%r ip=%s%s",
                     cache_hit_kind, shape_only.domain, _client_ip(request),
                     " deep=1" if deep else "")
            return HTMLResponse(content=_inject_age(cached_html, cached_audit_ts))

    # Cache miss (or fresh=True): full validation with DNS / SSRF guard
    # before running the audit. This is the slow path.
    try:
        validated = validate_domain_input(domain)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "That input couldn't be audited",
                "message": str(exc),
                "code": exc.code,
                "version": audit.__version__,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    log.info(
        "audit request: original=%r normalized=%r addresses=%s ip=%s%s%s",
        validated.original, validated.domain,
        ",".join(validated.addresses), _client_ip(request),
        " fresh=1" if fresh else "",
        " deep=1" if deep else "",
    )

    envelope = await _run_audit_in_pool(
        request.app.state.pool, validated.domain, deep=deep)

    if envelope["ok"]:
        body = render_html.render_result(envelope)
        # Convert audit timestamp (ISO 8601 UTC) to unix seconds for the
        # cache and the age-injection helper. Falls back to "now" if the
        # timestamp can't be parsed (defensive — would mean a worker bug).
        try:
            audit_ts = datetime.fromisoformat(
                envelope["timestamp"].replace("Z", "+00:00")
            ).timestamp()
        except (ValueError, AttributeError):
            audit_ts = time.time()
        # Render the .txt eagerly and cache it alongside the HTML, so a
        # download triggered later from this cached page returns the txt
        # corresponding to *exactly* this audit run. ~tens of ms of extra
        # work per audit, in exchange for consistency between the on-
        # screen view and the downloadable artifact.
        txt = _render_txt_to_string(
            original_domain=validated.original,
            audit_domain=envelope["audit_domain"],
            results=envelope["results"],
            timestamp=envelope["timestamp"],
        )
        txt_headers = {
            "Content-Disposition": (
                f'attachment; filename="{validated.domain}_'
                f'{envelope["timestamp"].replace(":", "-")}.txt"'
            ),
        }
        # Store in cache regardless of fresh flag — fresh requests should
        # update the cache so subsequent hits get the latest result. Use
        # the deep-aware cache_key, not the bare domain.
        _result_cache_set(cache_key, body, txt, txt_headers, audit_ts)

        # On a fresh audit, redirect to the canonical URL (without
        # fresh=1, but keeping deep=1 if it was set). Otherwise the
        # browser's address bar shows the ?fresh=1 query, and any reload
        # or shared link forces another cache-bypassing audit. The
        # redirect strips the fresh flag so the next hit is a normal
        # cache lookup. The follow-up request finds the entry we just
        # populated and serves it instantly (~tens of ms), so the extra
        # round-trip is negligible.
        if fresh:
            from urllib.parse import quote
            canonical = f"/audit/result?domain={quote(validated.domain)}"
            if deep:
                canonical += "&deep=1"
            return RedirectResponse(
                url=canonical,
                status_code=status.HTTP_303_SEE_OTHER,
            )

        return HTMLResponse(content=_inject_age(body, audit_ts))
    else:
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "Audit could not be completed",
                "message": envelope["error"]["message"],
                "code": envelope["error"]["kind"],
                "version": audit.__version__,
            },
            status_code=_status_for_error_kind(envelope["error"]["kind"]),
        )


@app.get("/audit/{domain}.txt", response_class=PlainTextResponse)
async def download_txt(request: Request, domain: str, deep: int = 0):
    """Plain-text report. Serves from the unified result cache on hit;
    runs the audit on miss (and populates both HTML and txt entries
    so a subsequent HTML view of the same domain returns the page that
    matches this txt).

    No rate-limit decorator on this endpoint. The cache makes repeat
    downloads free, and the audit endpoint (which is rate-limited) is
    the only other path that triggers an audit. A determined attacker
    could enumerate distinct domains here, but the worker pool naturally
    serializes that work, and the per-client form-page limit catches
    obvious flooding.

    Cache: shared with the HTML serve path. Same TTL, same key. Deep
    and non-deep audits use distinct cache keys so the .txt always
    matches the HTML view that linked to it.
    Cache survives only as long as the process; restart purges it.
    """
    # Two-stage validation: shape-only first (cheap, no I/O) so a cache
    # hit doesn't pay the DNS round-trip. Same pattern as the HTML
    # serve path. The cache key is the normalized domain (plus the
    # ::deep suffix when applicable) — matches what the HTML handler
    # uses, so a cache entry seeded by either handler is visible to
    # the other.
    try:
        shape_only = validate_domain_input(domain, dns_check=False)
    except ValidationError as exc:
        return PlainTextResponse(
            content=f"# Vendor Audit\n\nInput rejected: {exc}\n",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    deep_flag = bool(deep)
    cache_key = shape_only.domain + ("::deep" if deep_flag else "")
    # Cache lookup with deep-as-superset fallback. A regular .txt request
    # falls back to the deep slot if the regular slot misses; a deep
    # request only checks the deep slot. Same logic as the HTML serve
    # path — see _run_audit_and_render for the rationale.
    cached = _result_cache_get(cache_key)
    if cached is None and not deep_flag:
        cached = _result_cache_get(shape_only.domain + "::deep")
    if cached is not None:
        _, txt, txt_headers, _ = cached
        return PlainTextResponse(content=txt, headers=txt_headers)

    # Cache miss: full validation with DNS / SSRF guard before running
    # the audit.
    try:
        validated = validate_domain_input(domain)
    except ValidationError as exc:
        return PlainTextResponse(
            content=f"# Vendor Audit\n\nInput rejected: {exc}\n",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    envelope = await _run_audit_in_pool(
        request.app.state.pool, validated.domain, deep=deep_flag)
    if not envelope["ok"]:
        return PlainTextResponse(
            content=(
                f"# Vendor Audit — {validated.domain}\n\n"
                f"Audit could not be completed: {envelope['error']['message']}\n"
            ),
            status_code=_status_for_error_kind(envelope["error"]["kind"]),
        )

    # Render BOTH forms and cache them together. We always render the
    # HTML too — even on a .txt-first request — so a subsequent visit
    # to the result page returns the matching cached page rather than
    # re-running the audit. The eager double-render is bounded (~tens
    # of ms) and pays off across any later view of the same domain.
    body = render_html.render_result(envelope)
    txt = _render_txt_to_string(
        original_domain=validated.original,
        audit_domain=envelope["audit_domain"],
        results=envelope["results"],
        timestamp=envelope["timestamp"],
    )
    txt_headers = {
        "Content-Disposition": (
            f'attachment; filename="{validated.domain}_'
            f'{envelope["timestamp"].replace(":", "-")}.txt"'
        ),
    }
    try:
        audit_ts = datetime.fromisoformat(
            envelope["timestamp"].replace("Z", "+00:00")
        ).timestamp()
    except (ValueError, AttributeError):
        audit_ts = time.time()
    _result_cache_set(cache_key, body, txt, txt_headers, audit_ts)
    return PlainTextResponse(content=txt, headers=txt_headers)


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz():
    """Liveness probe — does not run an audit, doesn't touch the pool.

    Returning the version makes a /healthz curl useful for confirming
    rolling deployments. No rate limit because Cloudflare's health check
    will hit it.
    """
    return PlainTextResponse(
        content=f"ok\nversion={audit.__version__}\n",
        status_code=status.HTTP_200_OK,
    )


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    """Disallow everything. The handoff specifies this.

    The audit results don't need to be in any search index — they're
    re-run each time, and indexing them would suggest they're authoritative
    longer than they are.
    """
    return PlainTextResponse(content="User-agent: *\nDisallow: /\n")


# ── security.txt (RFC 9116) ──────────────────────────────────────────────────

# Per RFC 9116 the canonical location is /.well-known/security.txt. The
# RFC also permits /security.txt at the root for backward compatibility;
# we serve the same content from both paths so legacy crawlers find it.
#
# The body is assembled once at module load (it's static apart from
# config) so the endpoint is a near-zero-cost lookup.
def _build_security_txt() -> str:
    lines = [
        f"Contact: {SECURITY_CONTACT}",
        f"Expires: {SECURITY_EXPIRES}",
        f"Preferred-Languages: {SECURITY_LANG}",
        f"Canonical: {SERVICE_URL}/.well-known/security.txt",
    ]
    return "\n".join(lines) + "\n"


_SECURITY_TXT_BODY = _build_security_txt()


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt_well_known():
    """Vulnerability disclosure metadata, per RFC 9116."""
    return PlainTextResponse(content=_SECURITY_TXT_BODY)


@app.get("/security.txt", response_class=PlainTextResponse)
async def security_txt_root():
    """Compatibility alias for the RFC 9116 file."""
    return PlainTextResponse(content=_SECURITY_TXT_BODY)


# ── favicon ──────────────────────────────────────────────────────────────────

# Modern browsers all accept SVG favicons. Same SVG used elsewhere on the
# site (form page header, result page header, error page header). Cached
# aggressively because it never changes during a release.

_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" '
    'role="img" aria-label="Vendor Audit">'
    # Default text color for tab strips in dark UAs is white-ish, in
    # light UAs it's dark. Use a neutral mid-tone that reads on both —
    # we pin to the brand accent so the icon matches the site.
    '<circle cx="40" cy="40" r="28" fill="none" stroke="#7eb6ff" stroke-width="6"/>'
    '<line x1="60" y1="60" x2="82" y2="82" stroke="#7eb6ff" stroke-width="10" stroke-linecap="round"/>'
    '<circle cx="32" cy="38" r="5" fill="#7eb6ff"/>'
    '<circle cx="46" cy="34" r="5" fill="#7eb6ff"/>'
    '<circle cx="50" cy="48" r="5" fill="#7eb6ff"/>'
    '</svg>'
)


@app.get("/favicon.ico")
async def favicon_ico():
    """Browsers request /favicon.ico by default. We serve the SVG version
    with the right MIME type — modern browsers (Chrome 80+, Firefox 41+,
    Safari 9+) all handle SVG favicons.

    The icon is a simplified version of the page logo: thicker strokes
    and larger nodes so it remains legible at 16x16 px in a tab strip.
    """
    return Response(
        content=_FAVICON_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/favicon.svg")
async def favicon_svg():
    """Modern <link rel="icon"> path; same body as /favicon.ico."""
    return Response(
        content=_FAVICON_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


# ── Static JS for the result page ────────────────────────────────────────────

# Small inline script for the result page's expand-all / collapse-all
# buttons. Served as an external file (rather than inlined into the
# rendered HTML) so the result-page CSP can stay at script-src 'self'
# rather than needing 'unsafe-inline' or per-payload hashes.
#
# Behavior:
#   - Click "Expand all details" → open every <details class="detail-section">
#     and every <details class="subsection"> on the page. Does NOT toggle
#     the deeper "More about this check" disclosures (those stay opt-in).
#   - Click "Collapse all details" → close everything in the same set.
#
# The script is tolerant: if anything's missing (no buttons, no details,
# JS disabled) the page still works because the buttons are convenience
# only — every <details> remains independently clickable.
_RESULT_JS = """\
(function () {
  'use strict';

  // Flag for diagnostics. Lets us confirm from the browser console
  // whether the IIFE actually ran on a given page load:
  //   window.__VENDOR_AUDIT_JS_RAN__   // -> true if this ran
  // Useful when investigating script-execution issues (CSP, third-
  // party tag interference, deferred-script ordering bugs).
  try { window.__VENDOR_AUDIT_JS_RAN__ = true; } catch (e) { /* sandboxed */ }

  // ── Expand-all / collapse-all controls ────────────────────────────
  function setAll(open) {
    var nodes = document.querySelectorAll(
      'details.detail-section, details.subsection'
    );
    for (var i = 0; i < nodes.length; i++) {
      if (open) {
        nodes[i].setAttribute('open', '');
      } else {
        nodes[i].removeAttribute('open');
      }
    }
  }

  function initExpandCollapse() {
    var buttons = document.querySelectorAll('.detail-controls .detail-btn');
    for (var i = 0; i < buttons.length; i++) {
      (function (btn) {
        btn.addEventListener('click', function (ev) {
          ev.preventDefault();
          var action = btn.getAttribute('data-action');
          if (action === 'expand-all') {
            setAll(true);
          } else if (action === 'collapse-all') {
            setAll(false);
          }
        });
      })(buttons[i]);
    }
  }

  // ── Inline audit form: blank-submit → current domain; same-domain
  //    submit → bypass cache (fresh=1).
  //
  // Two conveniences for users on the result page who want to either
  // re-audit the current domain (with possibly different deep state)
  // or audit something different:
  //
  //   1. Blank submit → fill input with the current domain. The form's
  //      data-current-domain attribute carries it. Without this, the
  //      form would refuse to submit (or the server would see an empty
  //      domain). With this, clicking Audit with an empty input audits
  //      whatever's currently displayed.
  //
  //   2. Same-domain submit → add a hidden fresh=1 input before submit,
  //      so the server bypasses the cache. Without this, asking to
  //      "re-audit example.com" on the example.com result page would
  //      just return the same cached page, which isn't what the user
  //      meant.
  //
  // Domain comparison is case-insensitive and trims whitespace, so
  // "Example.com" submitted against "example.com" still triggers the
  // fresh-1 path.
  function initInlineForm() {
    var form = document.querySelector('.inline-audit-form');
    if (!form) return;
    var input = form.querySelector('input[name="domain"]');
    if (!input) return;
    var current = (form.getAttribute('data-current-domain') || '').trim().toLowerCase();

    form.addEventListener('submit', function (ev) {
      var typed = (input.value || '').trim();
      // (1) Blank submit → fill with current domain.
      if (typed === '' && current) {
        input.value = current;
        typed = current;
      }
      // (2) Same-domain submit → add fresh=1 to bypass cache.
      if (typed && current && typed.toLowerCase() === current) {
        // Avoid duplicate hidden inputs if the user submits twice.
        var existing = form.querySelector('input[name="fresh"]');
        if (!existing) {
          var hidden = document.createElement('input');
          hidden.type = 'hidden';
          hidden.name = 'fresh';
          hidden.value = '1';
          form.appendChild(hidden);
        }
      }
    });
  }

  function init() {
    initExpandCollapse();
    initInlineForm();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
"""


@app.get("/static/result.js")
async def result_js():
    """Tiny client-side script for the result page's expand/collapse-all
    buttons. The result page is the only page that loads JS on the site;
    the form, loading, and error pages stay JS-free (their CSP keeps
    script-src 'none').

    Cached aggressively — the file changes only when this app.py changes.
    Cloudflare in front will further cache by URL.
    """
    return Response(
        content=_RESULT_JS,
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "public, max-age=86400",
            # The script is for the result page only; it has no need to
            # be embedded by other origins. CORP=same-origin matches our
            # default policy from SecurityHeadersMiddleware but is added
            # here too as belt-and-suspenders.
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _run_audit_in_pool(pool: ProcessPoolExecutor, domain: str,
                              *, deep: bool = False) -> dict:
    """Submit the audit to the worker pool with a wall-clock cap.

    Returns the safe_run_audit envelope. On wall-clock timeout we
    synthesize a timeout envelope here rather than waiting for the worker
    to finish; the worker will eventually return its own result, but we
    don't await it.

    `deep` toggles --deep-mode checks. ProcessPoolExecutor.run_in_executor
    can't pass kwargs, so we wrap _worker_audit with functools.partial to
    bind the deep flag before submission.
    """
    loop = asyncio.get_running_loop()
    started_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    started_mono = time.monotonic()
    submit = functools.partial(_worker_audit, domain, deep=deep)
    future = loop.run_in_executor(pool, submit)
    try:
        return await asyncio.wait_for(future, timeout=AUDIT_TIMEOUT_S)
    except asyncio.TimeoutError:
        log.warning("audit timed out after %ds: domain=%r%s",
                    AUDIT_TIMEOUT_S, domain, " deep=1" if deep else "")
        # Deliberately do NOT cancel the future — ProcessPoolExecutor
        # cancellation of an already-running task isn't supported, and
        # the worker will finish its own work via internal timeouts. We
        # just stop waiting on it.
        return {
            "ok": False,
            "domain": None,
            "original_input": domain,
            "timestamp": started_iso,
            "duration_ms": int((time.monotonic() - started_mono) * 1000),
            "results": None,
            "audit_domain": None,
            "error": {
                "kind": "timeout",
                "message": (
                    f"The audit took longer than {AUDIT_TIMEOUT_S} seconds "
                    "and was stopped."
                ),
                "detail": None,
            },
        }


def _status_for_error_kind(kind: str) -> int:
    """Map an error envelope's kind to an HTTP status code."""
    return {
        "validation": status.HTTP_400_BAD_REQUEST,
        "resolution": status.HTTP_400_BAD_REQUEST,
        "timeout":    status.HTTP_504_GATEWAY_TIMEOUT,
        "internal":   status.HTTP_500_INTERNAL_SERVER_ERROR,
    }.get(kind, status.HTTP_500_INTERNAL_SERVER_ERROR)


def _render_txt_to_string(*, original_domain, audit_domain, results, timestamp) -> str:
    """Run audit_txt_report.write_txt_report into an in-memory buffer.

    write_txt_report writes to a file path. We don't want to write to
    disk just to read back the bytes, so we monkeypatch open() temporarily
    via a StringIO. There's a cleaner approach (refactor write_txt_report
    to take a file-like object), but that's a CLI change with broader
    consequences and we keep the web layer non-invasive for v1.
    """
    import io
    import tempfile

    # Easiest correct solution: write to a temp file in /tmp, read it back,
    # delete it. The worker is short-lived, the file is small (< 50KB
    # typical), and tempfile cleans up reliably. Avoids monkeypatching.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".txt", delete=False
    ) as tmp:
        tmp_path = tmp.name
    try:
        audit_txt_report.write_txt_report(
            original_domain, audit_domain, results, timestamp, tmp_path,
        )
        with open(tmp_path, "r", encoding="utf-8") as f:
            return f.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
