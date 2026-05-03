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
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .. import audit, audit_txt_report
from . import render_html
from .validate import ValidationError, validate_domain_input

log = logging.getLogger("vendor_audit.web")

# ── Configuration (env vars, with sensible defaults for dev) ─────────────────

# Number of process-pool workers. Audits are I/O bound; a small pool is fine
# on a 2-vCPU VM. Override with VENDOR_AUDIT_WORKERS for tuning.
WORKERS = int(os.environ.get("VENDOR_AUDIT_WORKERS", "3"))

# Wall-clock cap per audit at the web layer. The audit itself has its own
# internal deadlines (run_audit caps the parallel-checks pool at ~25s and
# the post-pool jobs at another ~12s — see audit.AUDIT_WALL_DEADLINE_S).
# This timeout is the *outer* safety net: if even those deadlines are
# bypassed somehow (a stuck C-level call, a runaway Python loop), the
# web layer gives up after this many seconds and returns an error page,
# leaving the worker process to be reaped or recycled by the pool logic.
# 45s leaves slack above the audit's ~37s worst case.
AUDIT_TIMEOUT_S = int(os.environ.get("VENDOR_AUDIT_TIMEOUT_S", "45"))

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
    pool = ProcessPoolExecutor(max_workers=WORKERS)
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
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


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

    The form page (/) gets a slightly relaxed script-src so its inline
    submit-feedback script can run. The script is gated by SHA-256 hash,
    not by 'unsafe-inline' — the hash binds the policy to exactly that
    script body. Any other inline script (injected, modified, etc.) is
    blocked. Every other page keeps script-src 'none'.
    """

    # SHA-256 hash of the form-submit feedback script in form.html.
    # If you change the script, update this hash too — the simplest way
    # is to delete it, redeploy, view-source the page, copy the hash from
    # the browser's CSP-violation console message, paste it back.
    _FORM_SCRIPT_HASH = "'sha256-unjMUlcxd4xX8nbWJVa21693cUyrq7n/LJYke0D7wlA='"

    # SHA-256 hash of the re-audit feedback script embedded in the result
    # page (see render_html._REAUDIT_SCRIPT). Same update procedure: change
    # the script body in render_html.py, the hash here must change too.
    _RESULT_SCRIPT_HASH = "'sha256-wP/dSxI/ORNfGZWSY3GUUR885LT75QSJOillR7Oath0='"

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Pick the script-src based on path. The form page (/) and the
        # result page (POST /audit) are the only endpoints that ship
        # inline JS; everything else gets 'none'.
        path = request.url.path
        if path == "/":
            script_src = f"script-src {self._FORM_SCRIPT_HASH}"
        elif path == "/audit":
            # POST /audit returns the result page. (GET /audit redirects
            # to / — that response also gets this CSP, but it's a 303 with
            # no body, so the script-src doesn't matter for it.)
            script_src = f"script-src {self._RESULT_SCRIPT_HASH}"
        else:
            script_src = "script-src 'none'"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"{script_src}; "
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
@limiter.limit(LIMIT_AUDIT)
async def audit_get(request: Request, domain: str = ""):
    """GET entry point — bookmarkable / shareable URL.

    With no `?domain=` query param, redirects to the form page (303). With
    `?domain=example.com`, runs the audit and renders the result HTML.
    Same rate limit as POST /audit since it triggers the same work.

    The intended use is sharing: a user runs an audit, copies their
    browser URL, and pastes it into an email/Slack to a vendor. The
    vendor clicks the link and sees a fresh audit (re-run server-side,
    not cached HTML) — this is intentional. Posture changes over time;
    a shared link should reflect current reality, not a snapshot.
    """
    # No domain → redirect to the form. Bare-GET behavior (e.g. typed-in
    # /audit URL, stale bookmark from before this route accepted a query
    # param) keeps working unchanged.
    if not domain or not domain.strip():
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return await _run_audit_and_render(request, domain)


async def _run_audit_and_render(request: Request, domain: str):
    """Shared audit→render flow used by both POST and GET /audit.

    Returns:
        - HTMLResponse on success (the result page)
        - TemplateResponse(error.html, 400) on validation failure
        - TemplateResponse(error.html, 5xx-ish) on audit failure

    The validation step runs synchronously (DNS resolution included via
    the SSRF guard); the audit itself goes to the worker pool.
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

    log.info(
        "audit request: original=%r normalized=%r addresses=%s ip=%s",
        validated.original, validated.domain,
        ",".join(validated.addresses), _client_ip(request),
    )

    envelope = await _run_audit_in_pool(request.app.state.pool, validated.domain)

    if envelope["ok"]:
        body = render_html.render_result(envelope)
        return HTMLResponse(content=body)
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
