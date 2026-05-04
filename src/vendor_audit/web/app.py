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

# Number of process-pool workers. Audits are I/O bound (network), so the
# CPU per worker is low — concurrency is dominated by socket waits. 8
# workers gives comfortable headroom for ~50-100 simultaneous visitors
# while staying well within memory bounds (each worker is ~150MB resident,
# so 8 workers = ~1.2GB). Override with VENDOR_AUDIT_WORKERS for tuning;
# the right value depends on memory budget and expected peak concurrency.
WORKERS = int(os.environ.get("VENDOR_AUDIT_WORKERS", "8"))

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
# (TXT_CACHE_TTL_S below) makes repeat downloads free, and fresh audits
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

# How long a generated .txt report stays in the in-memory cache, in
# seconds. Repeat downloads of the same domain within this window are
# served from cache and don't trigger a fresh audit (or a rate-limit
# rejection). 5 minutes is long enough to cover "user clicks Download,
# decides they want it again" but short enough that cached reports
# won't drift far from the current state of the audited domain.
TXT_CACHE_TTL_S = int(os.environ.get("VENDOR_AUDIT_TXT_CACHE_TTL_S", "300"))

# Hard cap on the number of cache entries. At 50KB per entry that's
# ~25MB. The web service's MemoryMax is 512MB; this cap keeps the cache
# well within bounds even under heavy distinct-domain traffic.
TXT_CACHE_MAX_ENTRIES = int(os.environ.get("VENDOR_AUDIT_TXT_CACHE_MAX", "500"))

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

# Hard cap on the number of result-page cache entries. ~50KB each, so
# 1000 entries = ~50MB max. Sized for sustained viral traffic across a
# 24-hour TTL window — at 200 entries the cache would fill within a day
# of distinct-domain traffic and start prematurely evicting popular
# entries.
HTML_CACHE_MAX_ENTRIES = int(os.environ.get("VENDOR_AUDIT_HTML_CACHE_MAX", "1000"))


# ── In-memory .txt cache ─────────────────────────────────────────────────────
#
# Module-level dict, intentionally simple. FastAPI request handlers run
# on a single asyncio loop thread, so dict access between awaits is
# atomic. The race on concurrent first-cache-misses (two requests both
# run the audit, last one wins on cache_set) is benign — the work is
# idempotent and the wasted audit is bounded to one duplicate per
# domain per TTL window in the worst case.
#
# Entries: {key: (text, headers, expires_at_unix_seconds)}
# Eviction: lazy on read (expired entries are dropped when accessed),
# plus an explicit prune on write when len(_txt_cache) hits the cap.

_txt_cache: dict = {}


def _txt_cache_get(key: str):
    """Return (text, headers) tuple if cached and not expired, else None."""
    entry = _txt_cache.get(key)
    if entry is None:
        return None
    text, headers, expires = entry
    if time.time() >= expires:
        # Lazy eviction — drop and return miss
        _txt_cache.pop(key, None)
        return None
    return (text, headers)


def _txt_cache_set(key: str, value):
    """Store value with TXT_CACHE_TTL_S TTL. Evicts the soonest-to-expire
    entry when at capacity.

    Approximate LRU: dropping the soonest-to-expire entry isn't true
    LRU (which would require tracking access times) but it's close
    enough — that entry was going to be gone shortly anyway, and the
    approximation avoids the complexity of separate access tracking.
    """
    text, headers = value
    expires = time.time() + TXT_CACHE_TTL_S
    if len(_txt_cache) >= TXT_CACHE_MAX_ENTRIES and key not in _txt_cache:
        oldest_key = min(_txt_cache, key=lambda k: _txt_cache[k][2])
        _txt_cache.pop(oldest_key, None)
    _txt_cache[key] = (text, headers, expires)


# Result-page HTML cache. Same shape as the TXT cache (lazy expiry on
# read, prune on write at capacity) but caches rendered HTML strings
# instead of txt+headers pairs. Single-process; shared across all
# requests since rendering happens in the FastAPI parent process, not
# the worker pool.
#
# Entries: {domain: (html_string, audit_timestamp_unix, expires_at_unix_seconds)}
#
# audit_timestamp_unix is when the audit's data was captured. It powers
# the "Scanned N minutes ago" display, which is substituted into the
# cached HTML at serve time so each visitor sees the correct age.

_html_cache: dict = {}


def _html_cache_get(key: str):
    """Return (html, audit_timestamp_unix) tuple if cached and not expired,
    else None."""
    entry = _html_cache.get(key)
    if entry is None:
        return None
    html, audit_ts, expires = entry
    if time.time() >= expires:
        _html_cache.pop(key, None)
        return None
    return (html, audit_ts)


def _html_cache_set(key: str, html: str, audit_ts: float):
    """Store rendered HTML with HTML_CACHE_TTL_S TTL.

    audit_ts is the unix timestamp of the audit (used by _inject_age at
    serve time to compute "scanned N minutes ago").

    Same approximate-LRU eviction as the TXT cache.
    """
    expires = time.time() + HTML_CACHE_TTL_S
    if len(_html_cache) >= HTML_CACHE_MAX_ENTRIES and key not in _html_cache:
        oldest_key = min(_html_cache, key=lambda k: _html_cache[k][2])
        _html_cache.pop(oldest_key, None)
    _html_cache[key] = (html, audit_ts, expires)


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
    current "scanned N ... ago" string.

    Called on every serve path (cache hit and cache miss) so each visitor
    sees the age relative to *their* moment of viewing, not the audit
    runner's. The placeholder pattern lets us cache HTML domain-keyed
    (one entry per domain) rather than per-minute or per-visitor.
    """
    age = time.time() - audit_ts
    return html.replace("<!--AGO-->", f" · {_format_age(age)}")


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

    All our pages are JS-free — the loading page uses meta refresh for
    progressive feedback, not JS — so script-src is uniformly 'none'.
    The strongest possible setting.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'none'; "
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
async def audit_get(request: Request, domain: str = ""):
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

    # Pass the domain straight through. We URL-encode it to be safe
    # against any character that might survive shape validation but
    # confuse the URL parser (none should, but defensive).
    from urllib.parse import quote
    result_url = f"/audit/result?domain={quote(domain.strip())}"
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
async def audit_result(request: Request, domain: str = "", fresh: int = 0):
    """Actual audit-running endpoint. Renders the result page.

    Shape: same as the old /audit GET — validate, run audit, render.
    Reachable directly (e.g. bookmarked from the URL bar) and reached
    via meta refresh from /audit. Also where the form page submits
    its result requests via the GET form.

    fresh=1 bypasses the result-page HTML cache (and refreshes the
    cache entry with the new result). The re-audit form submits with
    fresh=1 so a user explicitly asking for a fresh audit always gets
    one, not a 60-second-old cache hit.
    """
    if not domain or not domain.strip():
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return await _run_audit_and_render(request, domain, fresh=bool(fresh))


async def _run_audit_and_render(request: Request, domain: str, *, fresh: bool = False):
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
    """
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

    # Cache check. Hits return instantly without burning a worker. Skipped
    # when fresh=True (re-audit). The cache key is the validated domain so
    # 'Example.com', ' example.com ', etc. all share a cache entry. Errors
    # are not cached (the user should retry promptly, not wait the full TTL).
    if not fresh:
        cached = _html_cache_get(validated.domain)
        if cached is not None:
            cached_html, cached_audit_ts = cached
            log.info("audit cache hit: domain=%r ip=%s",
                     validated.domain, _client_ip(request))
            return HTMLResponse(content=_inject_age(cached_html, cached_audit_ts))

    log.info(
        "audit request: original=%r normalized=%r addresses=%s ip=%s%s",
        validated.original, validated.domain,
        ",".join(validated.addresses), _client_ip(request),
        " fresh=1" if fresh else "",
    )

    envelope = await _run_audit_in_pool(request.app.state.pool, validated.domain)

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
        # Store in cache regardless of fresh flag — fresh requests should
        # update the cache so subsequent hits get the latest result.
        _html_cache_set(validated.domain, body, audit_ts)
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
async def download_txt(request: Request, domain: str):
    """Plain-text report. Re-runs the audit on cache miss; serves from
    the in-memory cache on cache hit.

    No rate-limit decorator on this endpoint. The cache makes repeat
    downloads free, and the POST /audit endpoint (which is rate-limited)
    is the only other path that triggers an audit. A determined
    attacker could enumerate distinct domains here, but the worker pool
    naturally serializes that work, and the per-client form-page limit
    catches obvious flooding.

    Cache: keyed by lowercased domain path-param; entries live for
    TXT_CACHE_TTL_S (default 300s). Cache survives only as long as the
    process; restart purges it.
    """
    cache_key = domain.lower().strip()
    cached = _txt_cache_get(cache_key)
    if cached is not None:
        text, headers = cached
        return PlainTextResponse(content=text, headers=headers)

    try:
        validated = validate_domain_input(domain)
    except ValidationError as exc:
        return PlainTextResponse(
            content=f"# Vendor Audit\n\nInput rejected: {exc}\n",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    envelope = await _run_audit_in_pool(request.app.state.pool, validated.domain)
    if not envelope["ok"]:
        return PlainTextResponse(
            content=(
                f"# Vendor Audit — {validated.domain}\n\n"
                f"Audit could not be completed: {envelope['error']['message']}\n"
            ),
            status_code=_status_for_error_kind(envelope["error"]["kind"]),
        )

    # Use the existing CLI-quality txt renderer. It writes to a path; we
    # capture into an in-memory buffer to return as the response body.
    text = _render_txt_to_string(
        original_domain=validated.original,
        audit_domain=envelope["audit_domain"],
        results=envelope["results"],
        timestamp=envelope["timestamp"],
    )
    headers = {
        "Content-Disposition": (
            f'attachment; filename="{validated.domain}_'
            f'{envelope["timestamp"].replace(":", "-")}.txt"'
        ),
    }
    # Cache for repeat downloads.
    _txt_cache_set(cache_key, (text, headers))
    return PlainTextResponse(content=text, headers=headers)


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
    '<circle cx="40" cy="40" r="28" fill="none" stroke="#5fa3ff" stroke-width="6"/>'
    '<line x1="60" y1="60" x2="82" y2="82" stroke="#5fa3ff" stroke-width="10" stroke-linecap="round"/>'
    '<circle cx="32" cy="38" r="5" fill="#5fa3ff"/>'
    '<circle cx="46" cy="34" r="5" fill="#5fa3ff"/>'
    '<circle cx="50" cy="48" r="5" fill="#5fa3ff"/>'
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


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _run_audit_in_pool(pool: ProcessPoolExecutor, domain: str) -> dict:
    """Submit the audit to the worker pool with a wall-clock cap.

    Returns the safe_run_audit envelope. On wall-clock timeout we
    synthesize a timeout envelope here rather than waiting for the worker
    to finish; the worker will eventually return its own result, but we
    don't await it.
    """
    loop = asyncio.get_running_loop()
    started_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    started_mono = time.monotonic()
    future = loop.run_in_executor(pool, _worker_audit, domain)
    try:
        return await asyncio.wait_for(future, timeout=AUDIT_TIMEOUT_S)
    except asyncio.TimeoutError:
        log.warning("audit timed out after %ds: domain=%r", AUDIT_TIMEOUT_S, domain)
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
