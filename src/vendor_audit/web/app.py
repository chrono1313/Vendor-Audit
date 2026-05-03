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
from datetime import datetime, timezone

from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
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

# Wall-clock cap per audit, in seconds. Tight enough to keep a single-worker
# stall from cascading; loose enough that a healthy default-mode audit
# (typically 1-3s, occasionally 5s on a slow vendor) finishes comfortably.
AUDIT_TIMEOUT_S = int(os.environ.get("VENDOR_AUDIT_TIMEOUT_S", "30"))

# Per-IP rate limits. Tuned by handoff guidance ("~3 per 10s") but expressed
# as slowapi-compatible strings. The /audit endpoint is the expensive one;
# the form page and healthz are lightly limited just to stop pure flooding.
LIMIT_AUDIT = os.environ.get("VENDOR_AUDIT_LIMIT_AUDIT", "3/10seconds")
LIMIT_TXT   = os.environ.get("VENDOR_AUDIT_LIMIT_TXT",   "1/30seconds")
LIMIT_FORM  = os.environ.get("VENDOR_AUDIT_LIMIT_FORM",  "60/minute")

# When True, the app trusts the X-Forwarded-For / CF-Connecting-IP headers.
# This must be True in production (cloudflared sends connections from
# 127.0.0.1 with the real client IP in headers) and False in local dev.
TRUST_PROXY_HEADERS = os.environ.get("VENDOR_AUDIT_TRUST_PROXY", "1") == "1"


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
    """
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
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


@app.post("/audit", response_class=HTMLResponse)
@limiter.limit(LIMIT_AUDIT)
async def submit_audit(request: Request, domain: str = Form(...)):
    """Validate input, run the audit, render the result page."""
    # Validation must complete before any audit work starts.
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
@limiter.limit(LIMIT_TXT)
async def download_txt(request: Request, domain: str):
    """Plain-text report. Re-runs the audit on each request.

    The handoff calls this 'idempotent enough' — same input gives
    substantially the same output, modulo whatever's actually changed in
    DNS / TLS / HTTP for the audited domain in the meantime. Aggressive
    rate limiting (LIMIT_TXT) keeps this from being a free re-run trigger.
    """
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
