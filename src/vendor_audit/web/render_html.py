"""vendor_audit.web.render_html — HTML renderer for the result page.

ARCHITECTURE
------------
The audit produces one results dict. Three renderers consume it:
  - audit_render.render          terminal (ANSI-colored)
  - audit_txt_report._render_text plain text (100-col, severity-grouped)
  - this module                   HTML (web result page)

This renderer reuses two existing pieces of machinery from the txt report
to honour the project's "add a check once" goal:

  1. ReportData (a.k.a. audit_txt_report._ReportData) is constructed from
     the results dict and provides ALREADY-COMPUTED score breakdowns,
     severity classifications, finding rows, and category subscores. The
     HTML score panel and executive summary read these structured fields
     directly — no re-implementation of scoring or severity logic here.

  2. The detail sections (Email / DNS / TLS / etc.) are NOT re-implemented
     in HTML. Instead, this module runs the existing _render_*_section
     functions in audit_txt_report, captures their plain-text output, and
     transforms each line into HTML based on the severity marker at the
     start of the line. This means: when someone adds a new check, they
     edit the txt-section function ONCE and both renderers update. The
     web view will not need a corresponding code change.

The marker-parsing bridge is a known compromise; the right long-term
answer is to refactor the per-section functions to return a structured
list of Finding objects, and have both txt and HTML render from that
structure. That refactor is a separate task. The bridge keeps v1 small
without violating the single-source-of-truth principle for check logic.

What IS implemented natively in this file:
  - <head> with embedded CSS
  - Header (domain, scan time, redirect notice)
  - Score panel (overall + 6 category bars)
  - Executive summary (severity-grouped findings with anchor links)
  - Footer (txt download link, GitHub link)

What is RENDERED FROM TXT and wrapped in HTML:
  - All detail sections (Email, DNS, Routing, TLS, HTTP, HSTS, etc.)
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone

# ── Imports from sibling modules ─────────────────────────────────────────────
# audit_txt_report._ReportData is a private name by convention. Importing it
# is intentional and is documented as the v1 bridge to a future public
# ReportData class. See module docstring.
from .. import audit_txt_report
from ..audit_txt_report import _ReportData
from ..audit_txt_report import (
    _render_email_section,
    _render_dns_section,
    _render_routing_section,
    _render_tls_section,
    _render_http_section,
    _render_hsts_section,
    _render_server_disclosure_section,
    _render_versioned_libraries_section,
    _render_browser_security_headers_section,
    _render_security_txt_section,
    _render_error_page_section,
    _render_cors_section,
    _render_ssl_labs_section,
    _render_page_analysis_section,
    _render_starttls_section,
)


# ── Brand ────────────────────────────────────────────────────────────────────
# Inline SVG of the Vendor Audit logo: a magnifying glass framing a small
# node graph. Inline (rather than referenced as an external file) because
# (a) it's tiny — 12 lines — and (b) inline SVG inherits `currentColor` from
# its CSS context, so the outline picks up the foreground text color
# automatically, making it work on dark and light themes without modification.
# The blue dots stay blue intentionally; that accent reads as "data inside".
#
# This same SVG is also embedded in form.html and error.html. If you change
# it, change all three places. (Keeping a single canonical copy is a future
# cleanup; for now duplication is cheaper than building an asset pipeline.)
_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" '
    'role="img" aria-labelledby="va-title va-desc">'
    '<title id="va-title">Vendor Audit</title>'
    '<desc id="va-desc">Magnifying glass framing a small node graph, '
    'representing domain posture inspection.</desc>'
    '<circle cx="40" cy="40" r="28" fill="none" stroke="currentColor" stroke-width="3"/>'
    '<line x1="60" y1="60" x2="82" y2="82" stroke="currentColor" stroke-width="5" stroke-linecap="round"/>'
    '<line x1="32" y1="38" x2="46" y2="34" stroke="#7eb6ff" stroke-width="1"/>'
    '<line x1="46" y1="34" x2="50" y2="48" stroke="#7eb6ff" stroke-width="1"/>'
    '<line x1="32" y1="38" x2="50" y2="48" stroke="#7eb6ff" stroke-width="1"/>'
    '<circle cx="32" cy="38" r="3" fill="#7eb6ff"/>'
    '<circle cx="46" cy="34" r="3" fill="#7eb6ff"/>'
    '<circle cx="50" cy="48" r="3" fill="#7eb6ff"/>'
    '</svg>'
)



# ── Constants ────────────────────────────────────────────────────────────────

# Severity marker characters used by audit_txt_report._MARKERS. Mirrored
# here so we don't import a private constant. If the txt report ever
# changes these symbols, the parser below stops finding matches and HTML
# renders without severity classes — degrades gracefully.
_MARKER_TO_SEVERITY = {
    "✓": "pass",
    "!": "warn",
    "✗": "fail",
    "·": "info",
}

# CSS class for each severity. Used in the executive summary and in the
# per-section finding lines after marker parsing.
_SEVERITY_CLASS = {
    "pass": "sev-pass",
    "warn": "sev-warn",
    "fail": "sev-fail",
    "info": "sev-info",
    "critical": "sev-critical",
    "high":     "sev-high",
    "medium":   "sev-medium",
    "low":      "sev-low",
}

ISSUE_SEVERITIES = audit_txt_report.ISSUE_SEVERITIES
SEVERITY_ORDER   = audit_txt_report.SEVERITY_ORDER
_SEV_WORD = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Informational", "pass": "Passed"}

# Inline-marker colorization. Some txt lines pack multiple marker symbols
# inline — most notably the cookie-attributes line:
#     ✓ Secure · ✗ HttpOnly · ✓ SameSite=Strict
# The line as a whole gets a single severity (from the leading marker),
# but the inline markers should each be colored according to their own
# severity so the user can see at a glance which attribute failed.
#
# We match a marker only when it's followed by whitespace, so genuine
# punctuation like "...spoof this domain!" (an SPF warning message)
# doesn't accidentally get colored. The leading marker (already wrapped
# in <span class="finding-marker">) is excluded from this replacement
# because we run it on `message` only — message starts AFTER the leading
# marker per _RE_FINDING_LINE's groups.
_RE_INLINE_MARKER = re.compile(r"([✓✗!·])(?=\s)")

def _colorize_inline_markers(html_message: str) -> str:
    """Wrap each inline marker in a span with its severity class.

    Input is the already-HTML-escaped message text. Output is the same
    string with each ✓/✗/!/· (when followed by whitespace) wrapped in
    <span class="m-{sev}">…</span>.
    """
    def repl(m):
        sym = m.group(1)
        sev = _MARKER_TO_SEVERITY.get(sym, "info")
        return f'<span class="m-{sev}">{sym}</span>'
    return _RE_INLINE_MARKER.sub(repl, html_message)

# Section key → DOM id (for anchor links from executive summary). Mirrors
# the txt-report section ordering.
_SECTION_RENDERERS = [
    ("email",         "Email",                 _render_email_section),
    ("dns",           "DNS",                   _render_dns_section),
    ("routing",       "Routing",               _render_routing_section),
    ("tls",           "TLS",                   _render_tls_section),
    ("http",          "HTTP",                  _render_http_section),
    ("hsts",          "HSTS",                  _render_hsts_section),
    ("disclosure",    "Server Disclosure",     _render_server_disclosure_section),
    ("error_page",    "Default Error Page",    _render_error_page_section),
    ("libraries",     "Client-side Libraries", _render_versioned_libraries_section),
    ("headers",       "Security Headers",      _render_browser_security_headers_section),
    ("cors",          "CORS",                  _render_cors_section),
    ("security_txt",  "security.txt",          _render_security_txt_section),
    ("ssl_labs",      "SSL Labs",              _render_ssl_labs_section),
    ("page_analysis", "Page Analysis",         _render_page_analysis_section),
    ("starttls",      "STARTTLS-MX",           _render_starttls_section),
]

# Heuristics for detecting heading lines emitted by audit_txt_report._heading
# and _subheading. The txt module formats them with horizontal rules; the
# parser detects rule lines and treats the line(s) above as headings.
_RULE_HEAVY_CHAR = "═"
_RULE_LIGHT_CHAR = "─"


# ── Public entry point ───────────────────────────────────────────────────────

def render_result(envelope: dict) -> str:
    """Render the audit-result envelope as a complete HTML document.

    `envelope` is the structure returned by safe_run_audit() with ok=True.
    The web layer routes ok=False to the error template; this function
    assumes a successful audit.
    """
    if not envelope.get("ok"):
        return _render_unexpected(envelope)

    domain        = envelope["domain"]
    audit_domain  = envelope["audit_domain"]
    results       = envelope["results"]
    timestamp     = envelope["timestamp"]
    duration_ms   = envelope["duration_ms"]

    # Build the prepared report data (does scoring, severity classification,
    # finding-row preparation). This is the same object the txt renderer uses.
    data = _ReportData(
        original_domain=envelope.get("original_input") or domain,
        audit_domain=audit_domain,
        results=results,
        timestamp=timestamp,
        report_version=results.get("_scan", {}).get("version", "?"),
    )

    details_html = _render_detail_sections_html(data)
    # Side-navigation entries for the detail sections that actually rendered.
    section_links = re.findall(
        r'<details class="detail-section" id="section-([\w-]+)">\s*<summary>(.*?)</summary>',
        details_html)
    section_links = [(sid, html.unescape(title)) for sid, title in section_links]

    parts: list[str] = []
    parts.append(_DOC_HEAD.replace("__TITLE__",
                                   _h(f"Vendor Audit \u2014 {domain}")))
    parts.append('<body>')
    parts.append(_render_top_bar_html(data, domain))
    parts.append('<div class="shell">')
    parts.append(_render_side_nav_html(data, section_links))
    parts.append('<main class="report">')

    # Partial-results banner. When run_audit hits its wall-clock deadline,
    # results._partial is True. Surfaced first so the report is not read as
    # a complete audit.
    if data.results.get("_partial"):
        parts.append(
            f'<div class="partial-banner" role="alert">'
            f'  <strong>Partial audit:</strong> '
            f'{_h(data.results.get("_partial_reason") or "Some checks did not complete.")}'
            f'</div>'
        )
    # No-web-presence note: an MX-only or DNS-only domain has no website to
    # audit. Informational, not an error.
    if data.results.get("_no_web_note"):
        parts.append(
            f'<div class="info-banner" role="note">'
            f'  <strong>Mail-only / DNS-only domain:</strong> '
            f'{_h(data.results.get("_no_web_note"))}'
            f'</div>'
        )
    parts.append(_render_overview_html(data, domain, audit_domain,
                                       timestamp, duration_ms))
    parts.append(_render_executive_summary_html(data))
    parts.append(details_html)
    parts.append(_render_footer_html(data, domain))

    parts.append('</main>')
    parts.append('</div>')
    # One first-party script, loaded last: expand/collapse-all and opening
    # the section a navigation link points at. The page works without it.
    # The CSP stays at script-src 'self'. The ?v= query busts the browser
    # cache when the script changes; the route ignores it.
    parts.append(f'<script src="/static/result.js?v={_h(audit_txt_report.__version__)}"></script>')
    parts.append('</body></html>')
    return "\n".join(parts)


# ── Header ───────────────────────────────────────────────────────────────────

def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def _short(text):
    """First clause of a finding sentence, for cards and compact lists:
    the part before an em dash, minus any trailing parentheticals.
    A parenthetical in the middle stays ("... (HSTS) not set")."""
    head = (text or "").split(" \u2014 ", 1)[0]
    return re.sub(r"(\s*\([^()]*\))+$", "", head).strip()


def _humanize_left(seconds):
    return audit_txt_report._humanize_seconds(seconds)


def _section_for(row):
    """Detail-section id that explains a finding."""
    label = row.get("label", "")
    if label.startswith("redirect target: "):
        return "email"
    if label.startswith("EOL library"):
        return "libraries"
    if label.startswith("EOL "):
        return "disclosure"
    return _LABEL_SECTION.get(label) or _CATEGORY_SECTION.get(row.get("category", ""), "email")


_CATEGORY_SECTION = {"Email": "email", "DNS": "dns", "Routing": "routing",
                     "TLS": "tls", "HTTP": "http", "Website": "headers"}
_LABEL_SECTION = {
    "HSTS": "hsts", "HSTS preload": "hsts",
    "SSL Labs grade": "ssl_labs",
    "STARTTLS-MX": "starttls",
    "Server header": "disclosure", "X-Powered-By absent": "disclosure",
    "Server clock accuracy": "disclosure",
    "Default error page": "error_page",
    "CORS configuration": "cors",
    "security.txt": "security_txt",
    "Subresource Integrity": "page_analysis", "Mixed content (in-page)": "page_analysis",
}


# ── Top bar ─────────────────────────────────────────────────────────────────

def _render_top_bar_html(data, domain):
    """Brand, the audited domain, the audit-another-domain form and the
    .txt download — one compact bar across the top.

    The hidden `from` field carries the domain on screen. /audit compares
    it with the submitted one and, when they match, bypasses the cache so
    re-submitting the same domain runs a fresh audit.
    """
    deep = bool(data.results.get("_scan", {}).get("deep", False))
    txt_href = f"/audit/{_h(domain)}.txt" + ("?deep=1" if deep else "")
    checked = " checked" if deep else ""
    return "\n".join([
        '<header class="top-bar">',
        '  <a class="brand-link" href="/" aria-label="Vendor Audit home">',
        f'    <span class="logo">{_LOGO_SVG}</span>',
        '    <span class="brand">Vendor Audit</span>',
        '  </a>',
        f'  <span class="top-domain">{_h(domain)}</span>',
        '  <div class="top-action-bar">',
        '  <form class="inline-audit-form" method="get" action="/audit"'
        ' aria-label="Audit another domain">',
        f'    <input type="hidden" name="from" value="{_h(domain)}">',
        '    <input type="text" name="domain" placeholder="example.com"'
        ' aria-label="Domain to audit"'
        ' required autocomplete="off" autocapitalize="off" autocorrect="off"'
        ' spellcheck="false" data-1p-ignore data-lpignore="true"'
        ' data-form-type="other">',
        f'    <label class="inline-deep"><input type="checkbox" name="deep" value="1"{checked}>'
        '<span>Deep</span></label>',
        '    <button type="submit">Audit</button>',
        '  </form>',
        f'  <a class="download-link" href="{txt_href}" download>Download .txt</a>',
        '  </div>',
        '</header>',
    ])


# ── Side navigation ─────────────────────────────────────────────────────────

def _render_side_nav_html(data, section_links):
    """Anchor links to the parts of this one page. No routing, no requests."""
    out = ['<nav class="side-nav" aria-label="Report sections">',
           '  <div class="nav-group">Report</div>',
           '  <a class="nav-link" href="#overview">Overview</a>']
    if data.issue_count:
        out.append(f'  <a class="nav-link" href="#fix-first">Fix first'
                   f'<span class="nav-count nav-count-issues">{data.issue_count}</span></a>')
    out.append(f'  <a class="nav-link" href="#findings">All findings'
               f'<span class="nav-count">{len(data.finding_rows)}</span></a>')
    if section_links:
        out.append('  <div class="nav-group">Details</div>')
        for sid, title in section_links:
            out.append(f'  <a class="nav-link" href="#section-{_h(sid)}">{_h(title)}</a>')
    out.append('  <div class="nav-group">Scan</div>')
    out.append('  <a class="nav-link" href="#scan">Scan details</a>')
    out.append('</nav>')
    return "\n".join(out)


# ── Overview ────────────────────────────────────────────────────────────────

def _headline(data, domain):
    """'example.com has 2 critical and 4 high findings' — a rule on the
    counts: the two most serious severities present."""
    present = [(s, data.counts[s]) for s in ISSUE_SEVERITIES if data.counts[s]]
    if not present:
        return f"{domain} has no findings"
    top = present[:2]
    phrase = " and ".join(f"{n} {s}" for s, n in top)
    noun = "finding" if sum(n for _, n in top) == 1 else "findings"
    return f"{domain} has {phrase} {noun}"


def _stacked_bar_html(counts, total, label):
    """One horizontal bar split by severity. Widths are plain percentages
    computed here; the legend beside it carries the numbers as text."""
    if not total:
        return ""
    segs = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if n:
            segs.append(f'<span class="seg seg-{sev}" style="width: {n * 100.0 / total:.2f}%"></span>')
    return (f'<span class="stacked-bar" role="img" aria-label="{_h(label)}">'
            + "".join(segs) + '</span>')


def _render_overview_html(data, domain, audit_domain, timestamp, duration_ms):
    results = data.results
    counts = data.counts
    total = len(data.finding_rows)
    ranked = data.issues_ranked()
    deep = bool(results.get("_scan", {}).get("deep", False))
    redirect_envelope = results.get("redirect", {}) or {}
    www_fallback = bool(redirect_envelope.get("www_fallback"))
    redirected = bool(audit_domain and audit_domain != domain)

    out = ['<section class="overview" id="overview" aria-label="Overview">']

    # ── Headline ──
    out.append('  <div class="scan-meta">')
    # <!--AGO--> is substituted at serve time with " · N minutes ago", so the
    # HTML can be cached once per domain and still show each visitor the age.
    out.append(f'    <span class="scan-time">Scanned {_h(_format_timestamp(timestamp))}'
               f'<span class="scan-age"><!--AGO--></span></span>')
    out.append(f'    <span class="scan-duration">{duration_ms} ms</span>')
    if deep:
        out.append('    <span class="flag">--deep</span>')
    out.append('  </div>')
    out.append(f'  <h1 class="headline">{_h(_headline(data, domain))}</h1>')
    out.append(f'  <p class="verdict verdict-{data.worst_severity}">'
               f'<span class="verdict-dot" aria-hidden="true"></span>{_h(data.verdict)}</p>')
    if www_fallback:
        fb_host = redirect_envelope.get("www_fallback_host") or audit_domain
        out.append(f'  <p class="redirect-notice">Apex <strong>{_h(domain)}</strong> has no DNS records — '
                   f'web and TLS audited against <strong>{_h(fb_host)}</strong>; '
                   f'email still audited against the apex.</p>')
    elif redirected:
        out.append(f'  <p class="redirect-notice">Redirects to <strong>{_h(audit_domain)}</strong> — '
                   f'email is audited for both domains; web and TLS reflect the destination.</p>')
    if data.issue_count:
        summary = (f'{_plural(data.issue_count, "finding")} across {_plural(total, "check")}: '
                   f'{audit_txt_report.severity_summary(counts, ", ")}. ')
    else:
        summary = f'{_plural(total, "check")} ran and none raised a finding. '
    summary += f'{counts["pass"]} passed'
    if counts["info"]:
        summary += f' and {counts["info"]} {"is" if counts["info"] == 1 else "are"} informational'
    out.append(f'  <p class="summary-line">{_h(summary)}.</p>')

    # ── Severity cards ──
    out.append('  <div class="sev-cards">')
    for sev in ISSUE_SEVERITIES:
        rows = [r for r in ranked if r["severity"] == sev]
        out.append(f'    <a class="sev-card sev-{sev}" href="#findings-{sev}">')
        out.append(f'      <span class="sev-card-label">{_SEV_WORD[sev]}</span>')
        out.append(f'      <span class="sev-card-count">{len(rows)}</span>')
        if rows:
            out.append('      <span class="sev-card-items">')
            for r in rows[:3]:
                out.append(f'        <span class="sev-card-item">{_h(_short(r["display"]))}</span>')
            if len(rows) > 3:
                out.append(f'        <span class="sev-card-more">+{len(rows) - 3} more</span>')
            out.append('      </span>')
        else:
            out.append('      <span class="sev-card-none">None</span>')
        out.append('    </a>')
    out.append('  </div>')

    # ── Checks breakdown + by category ──
    out.append('  <div class="panels">')
    out.append('    <section class="panel" aria-label="All checks">')
    out.append(f'      <h2 class="panel-title">{_plural(total, "check")}</h2>')
    out.append('      ' + _stacked_bar_html(
        counts, total, audit_txt_report.severity_summary(counts, ", ")
        + f', {counts["info"]} informational, {counts["pass"]} passed'))
    out.append('      <ul class="legend">')
    for sev in SEVERITY_ORDER:
        out.append(f'        <li><span class="dot seg-{sev}" aria-hidden="true"></span>'
                   f'<span class="legend-n">{counts[sev]}</span> {_SEV_WORD[sev]}</li>')
    out.append('      </ul>')
    out.append('    </section>')

    out.append('    <section class="panel" aria-label="Findings by category">')
    out.append('      <h2 class="panel-title">By category</h2>')
    out.append('      <div class="cat-rows">')
    for r in data.category_rows:
        sid = _CATEGORY_SECTION.get(r["category"], "email")
        desc = audit_txt_report.severity_summary(r["counts"], ", ")
        out.append(f'        <a class="cat-row" href="#section-{sid}">')
        out.append(f'          <span class="cat-name">{_h(r["category"])}</span>')
        out.append('          ' + _stacked_bar_html(
            r["counts"], r["total"], f'{r["category"]}: {desc}, {r["passed"]} passed'))
        out.append(f'          <span class="cat-desc">{_h(desc)}</span>')
        out.append(f'          <span class="cat-passed">{r["passed"]} passed</span>')
        out.append('        </a>')
    out.append('      </div>')
    out.append('    </section>')
    out.append('  </div>')

    # ── At a glance ──
    glance = _glance_cards(data)
    if glance:
        out.append('  <div class="glance-cards">')
        out.extend(glance)
        out.append('  </div>')

    # ── Fix these first ──
    if ranked:
        out.append('  <section class="fix-first" id="fix-first" aria-label="Fix these first">')
        out.append('    <div class="fix-head"><h2>Fix these first</h2>')
        if len(ranked) > _FIX_FIRST_N:
            out.append(f'      <a href="#findings">All {len(ranked)} findings, ranked →</a>')
        out.append('    </div>')
        out.append('    <ol class="fix-list">')
        for i, r in enumerate(ranked[:_FIX_FIRST_N], 1):
            sev = r["severity"]
            out.append(
                f'      <li><a class="fix-row" href="#section-{_section_for(r)}">'
                f'<span class="fix-n">{i:02d}</span>'
                f'<span class="fix-text">{_h(r["display"])}'
                f'<span class="fix-cat">{_h(r["category"])}</span></span>'
                f'<span class="sev-badge sev-{sev}">{_SEV_WORD[sev]}</span>'
                f'</a></li>')
        out.append('    </ol>')
        out.append('    <p class="fix-note">Ranked by severity, then by how much each practice matters.</p>')
        out.append('  </section>')

    out.append('</section>')
    return "\n".join(out)


_FIX_FIRST_N = 6


def _glance_cards(data):
    """Three fact cards built from results the audit already holds. Each has
    a good state, so a clean domain still gets a card."""
    r = data.results
    cards = []

    def card(title, value, value_cls, lines, href):
        out = [f'    <a class="glance-card" href="{href}">',
               f'      <span class="glance-title">{_h(title)}</span>',
               f'      <span class="glance-value {value_cls}">{_h(value)}</span>']
        for ln in lines:
            out.append(f'      <span class="glance-line">{_h(ln)}</span>')
        out.append('    </a>')
        return "\n".join(out)

    # End of life
    eol = [row for row in data.issues_ranked() if row["label"].startswith("EOL ")]
    if not r.get("_no_web_note"):
        if eol:
            names = [_short(row["display"]).split(": ", 1)[-1] for row in eol]
            cards.append(card("End of life", _plural(len(eol), "item"), "glance-bad",
                              names[:3] + ([f"+{len(names) - 3} more"] if len(names) > 3 else []),
                              f"#section-{_section_for(eol[0])}"))
        else:
            cards.append(card("End of life", "None detected", "glance-good",
                              ["Judged from versions the server discloses"], "#section-disclosure"))

    # Certificate
    tls = r.get("tls") or {}
    if tls and not tls.get("error") and tls.get("cert_remaining_seconds") is not None:
        pct = tls.get("cert_remaining_pct")
        overdue = pct is not None and pct < audit_txt_report._CERT_RENEWAL_MIN_PCT
        lines = []
        if tls.get("cert_lifetime_days") is not None:
            lines.append(f'{tls["cert_lifetime_days"]}-day lifetime')
        if tls.get("cert_issuer"):
            lines.append(f'Issued by {tls["cert_issuer"]}')
        cards.append(card("Certificate expires in", _humanize_left(tls["cert_remaining_seconds"]),
                          "glance-bad" if overdue else "glance-good", lines, "#section-tls"))

    # Email authentication
    spf = (r.get("spf") or {}).get("status")
    dmarc = r.get("dmarc") or {}
    spf_tag = {"hardfail": "-all", "null_sender": "-all (sends no mail)", "softfail": "~all",
               "neutral": "?all", "pass_all_DANGEROUS": "+all", "missing": "not published",
               "no_all_mechanism": "no 'all'", "redirect_no_all": "no 'all'",
               "redirect_target_no_spf": "broken redirect"}.get(spf)
    if spf_tag and not dmarc.get("error"):
        dmarc_tag = (f'p={dmarc.get("policy")}' if dmarc.get("present") and dmarc.get("policy")
                     else "not published")
        rows = {row["label"]: row["severity"] for row in data.finding_rows}
        worst = next((s for s in ISSUE_SEVERITIES
                      if s in (rows.get("SPF policy"), rows.get("DMARC policy"))), "pass")
        value = {"pass": "Enforced", "low": "Mostly enforced"}.get(worst, "Not enforced")
        lines = [f"SPF {spf_tag}", f"DMARC {dmarc_tag}"]
        dkim = r.get("dkim") or {}
        if dkim.get("found"):
            lines.append("DKIM key found")
        cards.append(card("Email authentication", value,
                          "glance-good" if worst in ("pass", "low") else "glance-bad",
                          lines, "#section-email"))
    return cards


# ── All findings ────────────────────────────────────────────────────────────

def _render_executive_summary_html(data):
    """Every finding, one collapsible block per severity. Issue blocks start
    open; informational and passing start closed to keep first paint short."""
    ranked = data.issues_ranked()
    infos  = [r for r in data.finding_rows if r["severity"] == "info"]
    passes = [r for r in data.finding_rows if r["severity"] == "pass"]

    out = ['<section class="exec-summary" id="findings" aria-label="All findings">']
    out.append('  <h2>All findings</h2>')
    for sev in ISSUE_SEVERITIES:
        rows = [r for r in ranked if r["severity"] == sev]
        if rows:
            out.append(_findings_block_html(_SEV_WORD[sev], rows, sev, open_=True))
    if infos:
        out.append(_findings_block_html("Informational", infos, "info", open_=False))
    if passes:
        out.append(_findings_block_html("Passing", passes, "pass", open_=False))
    if not data.finding_rows:
        out.append('  <p class="empty">No findings to display.</p>')
    out.append('</section>')
    return "\n".join(out)


def _findings_block_html(title, rows, sev, *, open_=False):
    """One <details> block of findings."""
    open_attr = " open" if open_ else ""
    marker = audit_txt_report._MARKERS.get(sev, "·")
    cls = _SEVERITY_CLASS.get(sev, "sev-info")
    out = [f'  <details class="findings-block" id="findings-{sev}"{open_attr}>']
    out.append(f'    <summary>{_h(title)} <span class="count">({len(rows)})</span></summary>')
    out.append('    <ul class="findings-list">')
    for r in rows:
        badge = (f'<span class="sev-badge sev-{sev}">{_SEV_WORD[sev]}</span>'
                 if sev in ISSUE_SEVERITIES else '')
        out.append(
            f'      <li class="finding {cls}">'
            f'<span class="finding-marker" aria-hidden="true">{_h(marker)}</span>'
            f'<span class="finding-cat">{_h(r.get("category", ""))}</span>'
            f'<span class="finding-text">{_h(r.get("display", ""))}</span>'
            f'<span class="finding-frac">{badge}</span>'
            f'</li>'
        )
    out.append('    </ul>')
    out.append('  </details>')
    return "\n".join(out)


# ── Detail sections (rendered from txt output) ──────────────────────────────

def _render_detail_sections_html(data):
    """For each section, run the txt renderer and convert its output to HTML.

    The txt renderer returns "" when its source data is absent, so
    sections that don't apply (e.g. SSL Labs without --ssl) are silently
    omitted. We mirror that.

    A pair of expand-all / collapse-all controls sits at the top of the
    Detail section. The buttons toggle every <details> inside the
    section in bulk — both the top-level sections and the subsections
    nested within them. The deeper "More about this check" disclosure
    inside each subsection is NOT toggled by these buttons; it stays
    closed unless the user explicitly clicks it. That's deliberate:
    the long-form prose is opt-in, and a single click shouldn't dump
    thousands of words on the user.
    """
    out = ['<section class="details" aria-label="Detailed findings">']
    out.append('  <h2>Detail</h2>')
    # The controls — two buttons side by side. They have no JS event
    # handlers in the markup; the inline-loaded /static/result.js
    # attaches click handlers on DOMContentLoaded. If JS is disabled
    # the buttons are non-functional but the page still works (each
    # section is independently clickable, and the expand-all / collapse
    # -all is a convenience, not load-bearing).
    out.append(
        '  <div class="detail-controls" role="toolbar" '
        'aria-label="Expand or collapse all detail sections">'
    )
    out.append(
        '    <button type="button" class="detail-btn" data-action="expand-all">'
        'Expand all details</button>'
    )
    out.append(
        '    <button type="button" class="detail-btn" data-action="collapse-all">'
        'Collapse all details</button>'
    )
    out.append('  </div>')

    for section_id, title, renderer_fn in _SECTION_RENDERERS:
        try:
            block_text = renderer_fn(data)
        except Exception as exc:
            # An exception in a single section shouldn't kill the whole
            # page. Render a small notice and keep going.
            out.append(_section_error_html(section_id, title, exc))
            continue
        if not block_text:
            continue
        out.append(_section_html(section_id, title, block_text))

    out.append('</section>')
    return "\n".join(out)


# Sections that have a single section-level explanation (calling
# _section_explanation_lines in audit_txt_report) rather than per-subsection
# explanations. For these, the "More about this check" disclosure goes at
# the section level — directly after the body — with one topic block per
# logically-related EXPLANATIONS key.
#
# Each section maps to a list of (heading, key) tuples. The first tuple's
# heading is used as the disclosure's overall summary; subsequent tuples
# get bold inline subheadings inside the disclosure body. This lets
# closely-related topics (CSP, security headers, cookies — all browser
# hardening; or RPKI, IPv6, routing — all IP-layer reachability) cluster
# under one "More about" rather than scatter into separate disclosures
# the user has to find and click through.
#
# Sections NOT listed here (email, dns) use per-subsection explanations
# instead; their long-form details are emitted inside each subsection's
# closing </details> by the parser. Sections like ssl_labs and starttls
# have no explanation at all.
_SECTION_LEVEL_EXPLANATION_KEY: dict[str, list[tuple[str, str]]] = {
    "routing": [
        ("Routing and reachability", "routing"),
        ("IPv6",                     "ipv6"),
        ("RPKI",                     "rpki"),
    ],
    "tls": [
        ("Transport Layer Security", "tls"),
    ],
    "http": [
        ("HTTP transport",        "http"),
        ("HTTP version",          "http_version"),
        ("HTTPS redirect",        "http_redirect"),
    ],
    "hsts": [
        ("HTTP Strict Transport Security", "hsts"),
    ],
    "disclosure": [
        ("Server identification", "server_disclosure"),
        ("End-of-life operating systems", "eol_os"),
        ("End-of-life server software", "eol_tech"),
    ],
    "error_page": [
        ("Default error page", "error_page"),
    ],
    "libraries": [
        ("End-of-life client-side libraries", "eol_libraries"),
    ],
    "headers": [
        ("Browser security headers", "security_headers"),
        ("Content Security Policy",  "csp"),
        ("Cookies",                  "cookies"),
    ],
    "cors": [
        ("CORS configuration", "cors"),
    ],
    "security_txt": [
        ("security.txt", "security_txt"),
    ],
    "page_analysis": [
        ("Page analysis", "page_analysis"),
    ],
}


def _section_html(section_id, title, txt_block):
    """Wrap one txt-rendered section in HTML with a stable anchor id.

    The txt section starts with a section heading (e.g. "EMAIL") that's
    redundant in HTML — the <summary> already names the section. We
    suppress the first heading to avoid showing the title twice.

    Top-level Detail sections are CLOSED by default (no `open` attribute).
    The expand/collapse-all controls above the Detail section toggle
    every <details> at once. Closing by default keeps the page short
    on first load; the executive summary above carries the headlines,
    and the user clicks into whatever section they want to read.

    For sections that use a single section-level explanation (like TLS,
    HSTS, HTTP — no per-check subsections), we emit the long-form
    "More about this check" disclosure at the section level, right
    after the body. Sections with per-subsection explanations (Email,
    DNS) have the disclosure emitted inside each subsection's wrapper
    by the parser instead.
    """
    body_html = _txt_to_html(txt_block, suppress_first_heading=True)

    # Section-level long-form details (for non-subsection sections). The
    # _SECTION_LEVEL_EXPLANATION_KEY map identifies sections where the
    # body has just one set of What/Why/Fix at the top, with findings
    # below. We emit a single "More about this check" disclosure at the
    # end of the body, containing long-form prose for every key
    # logically belonging to the section. Each topic gets a small
    # heading inside the disclosure.
    topics = _SECTION_LEVEL_EXPLANATION_KEY.get(section_id)
    if topics:
        more_html = _multi_topic_more_about_html(topics)
        if more_html:
            body_html = body_html + "\n" + more_html

    return (
        f'  <details class="detail-section" id="section-{_h(section_id)}">\n'
        f'    <summary>{_h(title)}</summary>\n'
        f'    <div class="detail-body">{body_html}</div>\n'
        f'  </details>'
    )


def _multi_topic_more_about_html(topics: list[tuple[str, str]]) -> str:
    """Render a section-level 'More about this check' disclosure with
    one inline subheading per topic. Returns "" if no topic has any
    long-form content.

    Each topic is (heading_text, explanations_key). Topics whose key
    isn't in EXPLANATIONS or has no 'details' field are silently
    skipped.
    """
    try:
        from .. import audit_txt_report as _atr
    except ImportError:
        from vendor_audit import audit_txt_report as _atr

    chunks = []
    for heading, key in topics:
        entry = _atr.EXPLANATIONS.get(key)
        if not entry or not entry.get("details"):
            continue
        # Show the heading only when there's more than one topic; for a
        # single topic the disclosure summary already names it.
        if len(topics) > 1:
            chunks.append(f'<h5 class="more-about-topic">{_h(heading)}</h5>')
        for p in entry["details"]:
            chunks.append(f'<p>{_h(p)}</p>')

    if not chunks:
        return ""

    return (
        '<details class="more-about">\n'
        '  <summary>More about this check</summary>\n'
        '  <div class="more-about-body">\n    '
        + "\n    ".join(chunks)
        + '\n  </div>\n'
        '</details>'
    )


def _section_error_html(section_id, title, exc):
    return (
        f'  <details class="detail-section detail-section-error" '
        f'id="section-{_h(section_id)}">\n'
        f'    <summary>{_h(title)} (error)</summary>\n'
        f'    <div class="detail-body"><p class="section-error">'
        f'This section failed to render: {_h(str(exc))}</p></div>\n'
        f'  </details>'
    )


# ── Text → HTML translator ──────────────────────────────────────────────────

# A finding line in the txt output looks like:
#     "    ✓  Some message text here"
# with 4 spaces, then the marker, 2 spaces, and the message. Sub-lines
# (continuation / notes) are deeper-indented.
_RE_FINDING_LINE = re.compile(
    r"^(?P<indent>\s+)(?P<marker>[✓!✗·])\s+(?P<message>.*)$"
)

# Explanation lines, emitted by audit_txt_report._explanation_lines_txt:
#   "  What: <body>"
#   "  Why:  <body>"
#   "  Fix:  <body>"
# Continuation lines align under the body text:
#   "        more body"
# We detect the labelled lead line; the parser then greedily absorbs
# the continuation lines that are deeper-indented but not finding lines.
_RE_EXPLANATION_LEAD = re.compile(
    r"^  (?P<label>What|Why|Fix):\s+(?P<body>.+)$"
)
_EXPLANATION_LABELS = {"What", "Why", "Fix"}

# Headings: the txt renderer wraps headings in horizontal rule lines.
# Heavy rule (═) marks top-level section headings; light rule (─) marks
# subheadings. The line ABOVE the rule is the heading text. The bottom
# rule typically immediately follows the heading text.

# Map from subheading text (first word, uppercased) to the EXPLANATIONS
# key. Used by the HTML parser to look up long-form prose for the
# "More about this check" disclosure under each subsection. A single
# lookup table here means zero changes to audit_txt_report.py — the
# txt module continues to emit subheadings with no out-of-band hints,
# and the HTML side does the resolution at render time.
#
# Subheading text typically looks like "SPF — example.com (RFC 7208)";
# we match on the first whitespace-bounded token (uppercased) and a
# few special multi-token cases (MTA-STS, TLS-RPT, MAIL, etc.).
_SUBHEADING_TO_KEY: dict[str, str] = {
    "SPF":     "spf",
    "DMARC":   "dmarc",
    "DKIM":    "dkim",
    "MTA-STS": "mta_sts",
    "TLS-RPT": "tls_rpt",
    "BIMI":    "bimi",
    "MX":      "mx",
    "DNSSEC":  "dnssec",
    "CAA":     "caa",
    "TLS":     "tls",
    "HSTS":    "hsts",
    "HTTP":    "http",  # bare HTTP heading. Most "HTTP/2" etc. headings start with another token.
    "CSP":     "csp",
    "COOKIES": "cookies",
    "IPV6":    "ipv6",
    "RPKI":    "rpki",
    "DANE":    "dane",
}

# Multi-token subheading prefixes — checked before the single-word map.
# Order matters: longer prefixes win (e.g. "MAIL TRANSPORT" before "MAIL").
_SUBHEADING_PREFIX_TO_KEY: list[tuple[str, str]] = [
    ("CERTIFICATION AUTHORITY AUTHORIZATION", "caa"),
    ("CERTIFICATION AUTHORITY AUTHORISATION", "caa"),
    ("MAIL TRANSPORT",      "mail_transport"),
    ("MX RECORDS",          "mx"),
    ("NAME SERVERS",        "nameservers"),
    ("NAMESERVERS",         "nameservers"),
    ("HTTP REDIRECT",       "http_redirect"),
    ("HTTP VERSION",        "http_version"),
    ("PROTOCOL VERSION",    "http_version"),
    ("SERVER DISCLOSURE",   "server_disclosure"),
    ("SERVER",              "server_disclosure"),
    ("SECURITY HEADERS",    "security_headers"),
    ("SECURITY CONTACT",    "security_txt"),
    ("SECURITY.TXT",        "security_txt"),
    ("END-OF-LIFE SERVER SOFTWARE", "eol_tech"),
    ("END-OF-LIFE OS",      "eol_os"),
    ("OPERATING SYSTEM",    "eol_os"),
    ("EOL OS",              "eol_os"),
    ("OS DETECTION",        "eol_os"),
    ("END-OF-LIFE",         "eol_libraries"),
    ("EOL LIBRARIES",       "eol_libraries"),
    ("CLIENT-SIDE LIBRARIES", "eol_libraries"),
    ("LIBRARY DETECTION",   "eol_libraries"),
    ("BIMI BRAND INDICATOR", "bimi"),
    ("BIMI",                "bimi"),
    ("ROUTING",             "routing"),
    ("PAGE ANALYSIS",       "page_analysis"),
    ("PAGE",                "page_analysis"),
]


def _key_for_subheading(text: str) -> str | None:
    """Resolve a subheading line ("SPF — example.com (RFC 7208)") to the
    EXPLANATIONS dict key ("spf"), or None if no match.

    Matching is case-insensitive on the prefix. Multi-word prefixes are
    checked first (longest-first), then the single-word map. A miss is
    fine — the section just won't get a "More about this check"
    disclosure, which is better than a wrong one.
    """
    if not text:
        return None
    head = text.strip().upper()
    # Strip any trailing parenthetical, em-dash detail, or " — ..." suffix
    # so multi-word prefix matching sees the cleanest leading text.
    for sep in [" — ", " - ", " ("]:
        idx = head.find(sep)
        if idx > 0:
            head = head[:idx].strip()
            break
    # Multi-token prefixes
    for prefix, key in _SUBHEADING_PREFIX_TO_KEY:
        if head.startswith(prefix):
            return key
    # Single-word fallback
    first = head.split()[0] if head.split() else ""
    return _SUBHEADING_TO_KEY.get(first)


def _explanation_details_html(key: str | None) -> str:
    """Render the long-form 'More about this check' block as nested
    <details>. Returns "" when no explanation exists for the key.

    The output is a closed-by-default <details class="more-about">
    inside the subsection. CSS styles it as a subtle disclosure rather
    than an attention-grabbing card — the user opted in by clicking,
    they don't need a heavy visual frame.
    """
    if not key:
        return ""
    try:
        from .. import audit_txt_report as _atr
    except ImportError:
        from vendor_audit import audit_txt_report as _atr
    entry = _atr.EXPLANATIONS.get(key)
    if not entry or "details" not in entry:
        return ""
    paras = entry["details"]
    if not paras:
        return ""
    parts = ['<details class="more-about">',
             '  <summary>More about this check</summary>',
             '  <div class="more-about-body">']
    for p in paras:
        parts.append(f'    <p>{_h(p)}</p>')
    parts.append('  </div>')
    parts.append('</details>')
    return "\n".join(parts)


def _txt_to_html(block: str, *, suppress_first_heading: bool = False) -> str:
    """Convert a txt-renderer block to HTML, preserving structure.

    Approach: walk lines, identify each as a heading, finding line, raw
    value, blank, or plain text, and emit appropriate HTML. Output is
    a sequence of <details class="subsection"> blocks (each holding a
    subsection's findings + What/Why/Fix + a nested "More about this
    check" disclosure), plus <h3> for top-level section names that
    weren't suppressed.

    When suppress_first_heading is True, the first <h3>-class heading
    is replaced with nothing — used by detail sections, where the
    <summary> already names the section and a leading <h3> would
    duplicate it.

    Subsections are open by default. The expand/collapse-all controls
    above the Detail section toggle them in bulk. The "More about this
    check" nested <details> inside each subsection is closed by default
    so casual readers see the short What/Why/Fix and findings only;
    deeper readers click to expand the long-form prose.
    """
    lines = block.splitlines()
    out: list[str] = []
    i = 0
    pending_heading: str | None = None  # the line above a rule, if any
    h3_emitted = False                  # tracks whether any <h3> has shipped

    findings_open = False  # are we currently inside a <ul class="findings">?
    subsection_open = False
    subsection_key: str | None = None   # explanation key for the current subsection

    def close_findings():
        nonlocal findings_open
        if findings_open:
            out.append('</ul>')
            findings_open = False

    def close_subsection():
        """Close any open subsection, emitting the long-form 'More about
        this check' nested details before the outer </details>. Called
        when we hit the next subheading (which starts a new subsection)
        or when the parser ends."""
        nonlocal subsection_open, subsection_key
        if subsection_open:
            close_findings()
            details_html = _explanation_details_html(subsection_key)
            if details_html:
                out.append(details_html)
            out.append('</details>')
            subsection_open = False
            subsection_key = None

    def open_subsection(title: str):
        """Open a new <details class="subsection"> block for a subheading.
        Closes any previously-open subsection first. The new block is
        open by default; the expand/collapse-all controls toggle it.
        """
        nonlocal subsection_open, subsection_key
        close_subsection()
        key = _key_for_subheading(title)
        out.append(
            f'<details class="subsection" open>'
            f'<summary>{_h(title)}</summary>'
        )
        subsection_open = True
        subsection_key = key

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Detect rule lines. They're a long run of either ═ or ─ chars.
        # When a heading is "promoted" by an adjacent rule line, the txt
        # renderer's center-padding (it pads section titles to 100 cols)
        # bleeds through as runs of leading whitespace. Strip it here —
        # heading text in HTML doesn't want column-aligned padding.
        #
        # The txt module uses ═ (RULE_HEAVY) only for the document banner
        # at the top and bottom of the report. Section headings ("EMAIL",
        # "DNS", "TLS", etc.) all use ─ (RULE_LIGHT) — see
        # audit_txt_report._heading. So `suppress_first_heading` (which
        # drops the redundant top-of-section title because the <summary>
        # already names the section) keys to the LIGHT rule.
        if stripped and all(ch == _RULE_HEAVY_CHAR for ch in stripped):
            close_subsection()
            if pending_heading:
                out.append(
                    f'<h3 class="section-heading">'
                    f'{_h(pending_heading.strip())}</h3>'
                )
                pending_heading = None
            i += 1
            continue
        if stripped and all(ch == _RULE_LIGHT_CHAR for ch in stripped):
            close_findings()
            if pending_heading:
                if suppress_first_heading and not h3_emitted:
                    # Drop the redundant top-of-section heading; the
                    # detail-section <summary> already names the section
                    # (Email / DNS / TLS / etc.) so emitting another
                    # heading would just duplicate the label.
                    pass
                else:
                    # Subheading promoted by a light rule. Open a new
                    # subsection — collapsible block containing the
                    # subheading's findings + What/Why/Fix + nested
                    # "More about this check".
                    open_subsection(pending_heading.strip())
                h3_emitted = True
                pending_heading = None
            i += 1
            continue

        # Blank line — usually flushes any pending heading candidate as
        # a plain paragraph. Exception: if the next non-blank line is an
        # explanation lead (What:/Why:/Fix:), keep the pending heading
        # so the explanation handler can promote it to <h4>. Without
        # this peek, a "subheading\n\nexplanation" sequence would render
        # the subheading as a generic <p> and lose the heading semantics.
        if not stripped:
            close_findings()
            if pending_heading:
                # Peek for explanation lead in the upcoming non-blank lines.
                k = i + 1
                while k < len(lines) and not lines[k].strip():
                    k += 1
                if k < len(lines) and _RE_EXPLANATION_LEAD.match(lines[k]):
                    # Hold the pending heading; the explanation handler
                    # will consume it. Skip past the blanks.
                    i = k
                    continue
                out.append(f'<p>{_h(pending_heading)}</p>')
                pending_heading = None
            i += 1
            continue

        # Finding line (indented marker)
        m = _RE_FINDING_LINE.match(line)
        if m:
            # Flush any pending heading first.
            if pending_heading:
                out.append(f'<p>{_h(pending_heading)}</p>')
                pending_heading = None
            severity = _MARKER_TO_SEVERITY.get(m.group("marker"), "info")
            cls = _SEVERITY_CLASS[severity]
            message = m.group("message")
            # Look ahead for continuation and sub lines. The txt renderer
            # (_status in audit_txt_report) produces three kinds of deeper-
            # indented lines under a finding:
            #   - BODY CONTINUATIONS (7-space, no bullet): word-wrap overflow
            #     of the finding's own sentence. In HTML these must rejoin
            #     the message so the browser wraps it naturally, instead of
            #     the tail ("browsers. Recommended: ...") being split onto
            #     its own indented line.
            #   - NOTE LINES (7-space, "· " bullet prefix): separate short
            #     remarks (e.g. "· Upgrade to RSA-2048+"). Kept as their own
            #     lines in the sub box.
            #   - SUB-LINES (9-space): raw values (URLs, records) in the box.
            #   - NOTE CONTINUATIONS (9-space): word-wrap overflow of a long
            #     note. A note line is itself parsed as a "·" finding, and
            #     its overflow shares the 9-space indent with raw sub-values.
            #     The two are told apart by replaying the wrap decision: the
            #     txt writer breaks a line only when the next word would not
            #     fit, so an indented line is overflow exactly when its first
            #     word could not have fitted on the line before it.
            cont_parts: list[str] = []
            sub_lines: list[str] = []
            is_note = (m.group("marker") == "·"
                       and len(m.group("indent")) >= 7)
            wrap_width = audit_txt_report.WIDTH - 7
            prev_len = len(lines[i].strip())
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip():
                    break
                if _RE_FINDING_LINE.match(nxt):
                    break
                if all(ch == _RULE_HEAVY_CHAR for ch in nxt.strip()) or \
                   all(ch == _RULE_LIGHT_CHAR for ch in nxt.strip()):
                    break
                s = nxt.strip()
                indent = len(nxt) - len(nxt.lstrip())
                if s.startswith("· "):
                    sub_lines.append(s[2:].strip())      # note line
                elif indent >= 9:
                    first_word = s.split()[0]
                    if (is_note and not sub_lines
                            and prev_len + 1 + len(first_word) > wrap_width):
                        cont_parts.append(s)             # note overflow
                        prev_len = len(s)
                    else:
                        sub_lines.append(s)              # raw sub-value
                else:
                    cont_parts.append(s)                 # wrap continuation
                    prev_len = len(s)
                j += 1

            if cont_parts:
                message = message + " " + " ".join(cont_parts)

            if not findings_open:
                out.append('<ul class="findings">')
                findings_open = True
            sub_html = ""
            if sub_lines:
                sub_html = (
                    '<div class="finding-sub">'
                    + "<br>".join(_h(s) for s in sub_lines)
                    + '</div>'
                )
            out.append(
                f'<li class="finding {cls}">'
                f'<span class="finding-marker" aria-hidden="true">{_h(m.group("marker"))}</span>'
                f'<span class="finding-text">{_colorize_inline_markers(_h(message))}</span>'
                f'{sub_html}'
                f'</li>'
            )
            i = j
            continue

        # Explanation line (What: / Why: / Fix:). When detected, absorb any
        # deeper-indented continuation lines that immediately follow (the
        # txt renderer wraps long explanations to align under the body
        # text). Render as a single <p class="expl-line"> so the CSS can
        # style it as advisory copy distinct from raw values.
        em = _RE_EXPLANATION_LEAD.match(line)
        if em:
            close_findings()
            if pending_heading:
                # The pending line is the subsection heading that
                # introduces this explanation block (e.g. "SPF —
                # example.com (RFC 7208)"). The txt renderer doesn't
                # rule-decorate subheadings that have explanations
                # underneath — the explanation is the visual cue. So we
                # open a new subsection here instead of flushing the
                # heading as a paragraph; the result is a collapsible
                # block with proper semantics.
                open_subsection(pending_heading.strip())
                pending_heading = None
            label = em.group("label")
            body_parts = [em.group("body").rstrip()]
            j = i + 1
            # Continuation lines: deeper-indented than 2 spaces, not a
            # finding marker, not a rule, not blank, not another
            # explanation lead. Stop at any of those.
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip():
                    break
                if _RE_FINDING_LINE.match(nxt):
                    break
                if _RE_EXPLANATION_LEAD.match(nxt):
                    break
                stripped_nxt = nxt.strip()
                if all(ch == _RULE_HEAVY_CHAR for ch in stripped_nxt) or \
                   all(ch == _RULE_LIGHT_CHAR for ch in stripped_nxt):
                    break
                # Continuation lines are indented beyond 2 spaces (the
                # body sits at column 8 — see _explanation_lines_txt).
                # Anything indented less than that isn't a continuation.
                lead_ws = len(nxt) - len(nxt.lstrip(" "))
                if lead_ws < 4:
                    break
                body_parts.append(stripped_nxt)
                j += 1
            full_body = " ".join(body_parts)
            out.append(
                f'<p class="expl-line">'
                f'<strong>{_h(label)}</strong>'
                f'{_h(full_body)}</p>'
            )
            i = j
            continue

        # Generic non-marker, non-blank, non-rule line. Could be a heading
        # candidate (followed by a rule) or a raw value or a plain note.
        # We hold it as a "pending heading" — if the next line is a rule,
        # it gets promoted; otherwise it becomes a paragraph on the next
        # blank/structural line. This matches how the txt renderer formats
        # subheadings.
        close_findings()
        if pending_heading:
            # Two consecutive non-rule lines — flush the prior as plain text.
            out.append(f'<p class="raw-line">{_h(pending_heading)}</p>')
        pending_heading = line.rstrip()
        i += 1

    # Flush trailing state. close_subsection emits the long-form details
    # block (if any) inside the closing </details>, then any final raw
    # paragraph that didn't get consumed.
    close_findings()
    close_subsection()
    if pending_heading:
        out.append(f'<p class="raw-line">{_h(pending_heading)}</p>')

    return "\n".join(out)


# ── Footer ───────────────────────────────────────────────────────────────────

def _render_footer_html(data, domain):
    timings = data.results.get("_scan", {}).get("check_timings", {})
    slow = sorted(
        ((k, v) for k, v in timings.items()
         if not k.startswith("_") and isinstance(v, (int, float)) and v >= 0.5),
        key=lambda kv: -kv[1],
    )[:5]

    deep = bool(data.results.get("_scan", {}).get("deep", False))
    txt_href = f"/audit/{_h(domain)}.txt"
    if deep:
        txt_href += "?deep=1"

    out = ['<footer class="report-footer" id="scan">']
    out.append('  <div class="footer-actions">')
    out.append(
        f'    <a class="download-link" href="{txt_href}" '
        f'download>Download as .txt</a>'
    )
    # The "Re-audit this domain" button used to live here. It was
    # removed once the inline audit form in the top action bar covered
    # the same case (blank input + Audit, with same-domain submission
    # auto-adding fresh=1 to bypass the cache via the result-page JS).
    out.append('    <a href="/">Audit another domain</a>')
    out.append('  </div>')
    out.append('  <div class="footer-info">')
    out.append(
        f'    <span>Vendor Audit v{_h(data.report_version)}</span>'
        f'    <span><a href="https://github.com/chrono1313/Vendor-Audit">'
        f'Source on GitHub</a></span>'
    )
    out.append('  </div>')
    if slow:
        out.append('  <div class="timings">')
        out.append('    <span class="timings-label">Slowest checks:</span>')
        for k, v in slow:
            out.append(f'    <span class="timing">{_h(k)} ({v:.1f}s)</span>')
        out.append('  </div>')
    out.append('</footer>')
    return "\n".join(out)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _h(text) -> str:
    """Shorthand for html.escape with quote=True (default)."""
    if text is None:
        return ""
    return html.escape(str(text))


def _format_timestamp(ts: str) -> str:
    """Convert ISO 8601 to 'Month DD, YYYY at HH:MM:SS UTC' for human display.

    Seconds are useful when re-auditing — without them, two consecutive
    audits of the same domain look identical at a glance because their
    Scanned: lines round to the same minute.
    """
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y at %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return ts or ""


def _render_unexpected(envelope: dict) -> str:
    """Defensive fallback if the caller routes an ok=False envelope here."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<title>Vendor Audit — Error</title></head>'
        '<body><h1>Unexpected response</h1>'
        '<p>The audit engine returned a result that could not be rendered.</p>'
        '</body></html>'
    )


# ── Document head + embedded CSS ─────────────────────────────────────────────

# Result-page JS — small client-side helper that powers the expand-all /
# collapse-all controls and the inline-form blank-submit / same-domain
# bypass-cache shortcuts. Inlined directly into the page response (see
# render_result) rather than loaded from an external <script src>; see
# the comment there for the reasoning. Also exposed at /static/result.js
# in app.py for any client that wants to fetch the source directly.
_RESULT_JS = """\
(function () {
  'use strict';

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

  // ── Open the section a navigation link points at ──────────────────
  // Detail sections are closed <details>. Following "#section-tls" should
  // show it, so open the target and any <details> around it.
  function openTarget() {
    var id = decodeURIComponent((window.location.hash || '').slice(1));
    if (!id) { return; }
    var el = document.getElementById(id);
    if (!el) { return; }
    var node = el;
    while (node) {
      if (node.tagName === 'DETAILS') { node.setAttribute('open', ''); }
      node = node.parentElement;
    }
    el.scrollIntoView();
  }

  function init() {
    initExpandCollapse();
    openTarget();
    window.addEventListener('hashchange', openTarget);
  }

  // Script tag is at the end of <body> so the DOM is already parsed
  // when this runs. The readyState check guards the case where someone
  // loads the script earlier (e.g. via fetch+eval).
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
"""


_DOC_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
:root {
  /* ── Palette ──────────────────────────────────────────────────────────
     Neutral, warm-dark, professional. The previous palette had three
     near-identical grays and a #999 muted text that fell below WCAG AA
     against the page background. This pass:
       - lifts muted text to #bdbdba (~6.6:1) so secondary copy reads
         comfortably at body sizes,
       - keeps primary text at a soft off-white (#ececea) instead of pure
         white (avoids the harsh-on-eyes effect of #fff on dark),
       - settles on a single panel color (--surface) instead of multiple
         near-identical shades that just looked like banding,
       - uses a distinct hover surface (--surface-hover) so interactive
         affordances are obvious without needing animation. */
  --bg:           rgb(34, 34, 33);     /* page background, slightly deeper */
  --surface:      rgb(44, 44, 42);     /* panels and cards */
  --surface-2:    rgb(52, 52, 49);     /* nested elements (raw values, sub) */
  --surface-hover: rgb(56, 56, 53);    /* hover state on summary rows */
  --fg:           #ededeb;             /* primary text, ~14.5:1 on --bg */
  --muted:        #bdbdba;             /* secondary text, ~6.6:1 on --bg */
  --muted-soft:   #98968f;             /* tertiary, only for non-text uses */
  --border:       #57574f;             /* visible dividers */
  --border-soft:  #3e3e3a;             /* subtle dividers within panels */
  --accent:       #7eb6ff;             /* links / focus, brighter for contrast */
  --accent-hover: #a3cbff;
  --pass:         #4ade80;
  --pass-bg:      #1a3a22;
  --warn:         #fbbf24;
  --warn-bg:      #3a2e0e;
  --fail:         #f87171;
  --fail-bg:      #3a1a1a;
  --info:         #bdbdba;
  --info-bg:      #38383a;
}
* { box-sizing: border-box; }
body {
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: var(--fg);
  background: var(--bg);
  margin: 0;
  /* Subtle baseline so dark themes don't look completely flat. The
     gradient is invisible to most viewers — it just gives the page a
     little vertical depth. */
  background-image: linear-gradient(180deg, rgb(36, 36, 35) 0%, rgb(33, 33, 32) 100%);
  background-attachment: fixed;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
.report {
  max-width: 920px;
  margin: 0 auto;
  padding: 1.5rem 1rem 4rem;
}

/* ── Header ───────────────────────────────────────────────────────────── */
.report-header {
  margin-bottom: 1.4rem;
  text-align: center;
}
.brand-link {
  display: inline-block;
  color: inherit;
  text-decoration: none;
}
.brand-link:hover .brand { color: var(--accent); }
.logo {
  display: block;
  width: 48px;
  height: 48px;
  margin: 0 auto 0.5rem;
  color: var(--fg);
}
.logo svg { display: block; width: 100%; height: 100%; }
.brand {
  font-size: 0.78rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 0.2rem;
}
.domain {
  font: 1.6rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
  margin: 0 0 0.4rem;
  color: var(--fg);
  word-break: break-all;
}
.scan-meta {
  display: flex;
  justify-content: center;
  gap: 1.2rem;
  margin-top: 0.6rem;
  color: var(--muted);
  font-size: 0.85rem;
}
.scan-meta .flag {
  font-family: ui-monospace, monospace;
  color: var(--warn);
}
.scan-age {
  font-style: italic;
  opacity: 0.9;
}
.redirect-notice {
  background: var(--warn-bg);
  color: var(--warn);
  padding: 0.5rem 0.85rem;
  margin: 0.6rem 0 0;
  border-left: 3px solid var(--warn);
  border-radius: 0 4px 4px 0;
  font-size: 0.92rem;
}
.redirect-notice strong { font-family: ui-monospace, monospace; }
.partial-banner {
  background: var(--fail-bg);
  color: var(--fail);
  padding: 0.7rem 1rem;
  margin: 0 0 1rem;
  border-left: 4px solid var(--fail);
  border-radius: 0 4px 4px 0;
  font-size: 0.95rem;
}
.partial-banner strong {
  font-weight: 600;
  margin-right: 0.4rem;
}
.info-banner {
  background: var(--info-bg, #eef4fb);
  color: var(--info, #2c5d8f);
  padding: 0.7rem 1rem;
  margin: 0 0 1rem;
  border-left: 4px solid var(--info, #4a86c5);
  border-radius: 0 4px 4px 0;
  font-size: 0.95rem;
}
.info-banner strong {
  font-weight: 600;
  margin-right: 0.4rem;
}

/* ── Score panel ──────────────────────────────────────────────────────── */
.score-panel {
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: 8px;
  padding: 1.1rem 1.3rem;
  margin-bottom: 1.4rem;
}
.score-row {
  display: grid;
  grid-template-columns: 90px 120px 1fr 50px;
  align-items: center;
  gap: 0.8rem;
  padding: 0.35rem 0;
}
.score-overall {
  font-size: 1.05rem;
  font-weight: 600;
  padding-bottom: 0.7rem;
  border-bottom: 1px solid var(--border-soft);
  margin-bottom: 0.4rem;
}
.score-overall .score-label { font-size: 1.05rem; }
.score-categories .score-row { font-size: 0.92rem; }
.score-label { color: var(--fg); }
.score-fraction {
  font: 0.92rem ui-monospace, monospace;
  text-align: right;
  color: var(--muted);
  white-space: nowrap;
}
.score-fraction .num { color: var(--fg); font-weight: 600; }
.score-fraction .sep { padding: 0 0.1rem; }
.score-bar {
  height: 10px;
  background: rgb(60, 60, 57);
  border-radius: 5px;
  overflow: hidden;
}
.score-bar-fill {
  height: 100%;
  border-radius: 5px;
  transition: width 0.3s ease;
}
.sev-pass .score-bar-fill { background: var(--pass); }
.sev-warn .score-bar-fill { background: var(--warn); }
.sev-fail .score-bar-fill { background: var(--fail); }
.sev-info .score-bar-fill { background: var(--info); }
.score-percent {
  font: 0.92rem ui-monospace, monospace;
  text-align: right;
  font-weight: 600;
  color: var(--fg);
}

/* ── Executive summary ──────────────────────────────────────────────── */
.exec-summary { margin-bottom: 1.6rem; }
.exec-summary h2,
.details h2 {
  font-size: 1.05rem;
  margin: 0 0 0.7rem;
  letter-spacing: 0.02em;
  color: var(--fg);
}
.findings-block {
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: 8px;
  margin-bottom: 0.6rem;
  overflow: hidden;
}
.findings-block summary {
  cursor: pointer;
  padding: 0.7rem 1rem;
  font-weight: 600;
  user-select: none;
  background: var(--surface);
  color: var(--fg);
  transition: background-color 0.12s ease;
}
.findings-block summary:hover { background: var(--surface-hover); }
.findings-block summary .count {
  color: var(--muted);
  font-weight: 400;
  margin-left: 0.3rem;
}
.findings-list {
  list-style: none;
  margin: 0;
  padding: 0;
  border-top: 1px solid var(--border-soft);
}
.findings-list .finding {
  display: grid;
  grid-template-columns: 28px 80px 1fr auto;
  gap: 0.5rem;
  align-items: baseline;
  padding: 0.5rem 1rem;
  font-size: 0.92rem;
  border-bottom: 1px solid var(--border-soft);
}
.findings-list .finding:last-child { border-bottom: none; }
.finding-marker {
  font-family: ui-monospace, monospace;
  text-align: center;
  font-weight: 700;
}
.sev-pass .finding-marker { color: var(--pass); }
.sev-warn .finding-marker { color: var(--warn); }
.sev-fail .finding-marker { color: var(--fail); }
.sev-info .finding-marker { color: var(--muted); }
/* Inline markers — used inside multi-attribute lines like cookie flags
   ("✓ Secure · ✗ HttpOnly · ✓ SameSite=Strict") so each attribute's
   marker takes its own color independent of the line's overall severity. */
.m-pass { color: var(--pass); font-weight: 600; }
.m-warn { color: var(--warn); font-weight: 600; }
.m-fail { color: var(--fail); font-weight: 600; }
.m-info { color: var(--muted); }
.finding-cat {
  color: var(--muted);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.finding-text {
  word-break: break-word;
  color: var(--fg);
}
.finding-frac {
  font: 0.85rem ui-monospace, monospace;
  color: var(--muted);
  white-space: nowrap;
}
.empty { color: var(--muted); font-style: italic; }

/* ── Detail sections ─────────────────────────────────────────────────── */
.detail-section {
  background: var(--surface);
  border: 1px solid var(--border-soft);
  border-radius: 8px;
  margin-bottom: 0.6rem;
  overflow: hidden;
}
.detail-section > summary {
  cursor: pointer;
  padding: 0.7rem 1rem;
  font-weight: 600;
  user-select: none;
  font-size: 0.95rem;
  color: var(--fg);
  transition: background-color 0.12s ease;
}
.detail-section > summary:hover { background: var(--surface-hover); }
.detail-section[open] > summary {
  border-bottom: 1px solid var(--border-soft);
}
.detail-body {
  padding: 1rem 1.1rem;
  color: var(--fg);
}
.detail-body h3.section-heading {
  font-size: 0.95rem;
  margin: 0.6rem 0 0.4rem;
  letter-spacing: 0.02em;
  color: var(--fg);
}
.detail-body h4.section-subheading {
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 1.1rem 0 0.5rem;
  font-weight: 600;
}
.detail-body h3.section-heading:first-child,
.detail-body h4.section-subheading:first-child { margin-top: 0; }
.detail-body p.raw-line {
  font: 0.85rem ui-monospace, monospace;
  color: var(--muted);
  margin: 0.2rem 0;
  word-break: break-all;
  white-space: pre-wrap;
}
.detail-body ul.findings {
  list-style: none;
  margin: 0.3rem 0 0.7rem;
  padding: 0;
}
.detail-body ul.findings .finding {
  display: grid;
  grid-template-columns: 24px 1fr;
  gap: 0.5rem;
  align-items: baseline;
  padding: 0.3rem 0;
  font-size: 0.92rem;
  border: none;
  color: var(--fg);
}
.detail-body .finding-sub {
  margin-top: 0.25rem;
  margin-left: 0;
  padding: 0.5rem 0.7rem;
  background: var(--surface-2);
  border-radius: 4px;
  font: 0.85rem ui-monospace, monospace;
  color: var(--fg);
  word-break: break-all;
  white-space: pre-wrap;
  grid-column: 2;
}
/* Internet.nl-style "What / Why / Fix" explanation block. Rendered as
   a small panel with a left accent so it reads as advisory copy
   distinct from the actual findings below it. The text is at full
   foreground brightness (not muted) since it's the substantive
   explanation a vendor will read; the labels (What/Why/Fix) take
   the muted color so they read as labels rather than competing for
   attention with the body text. */
.detail-body p.explanation,
.detail-body p.expl-line {
  font-size: 0.9rem;
  color: var(--fg);
  margin: 0.2rem 0;
  line-height: 1.55;
}
.detail-body p.explanation strong,
.detail-body p.expl-line strong {
  color: var(--muted);
  font-weight: 600;
  margin-right: 0.3rem;
  letter-spacing: 0.02em;
  font-size: 0.78rem;
  text-transform: uppercase;
  display: inline-block;
  min-width: 2.5rem;
}

/* ── Subsection (collapsible block per subheading) ──────────────────
   Each subsection (SPF, DMARC, MX, etc.) is its own <details> inside
   the section's detail-body. Default-open so the user sees content
   when they expand a section. The expand-all/collapse-all buttons
   above the Detail section toggle these in bulk. */
.detail-body details.subsection {
  margin: 0.6rem 0 0;
  padding: 0;
  border-top: 1px solid var(--border-soft);
}
.detail-body details.subsection:first-child {
  margin-top: 0;
  border-top: none;
}
.detail-body details.subsection > summary {
  cursor: pointer;
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  padding: 0.7rem 0 0.5rem;
  font-weight: 600;
  user-select: none;
  list-style: none;  /* hide default disclosure triangle */
  position: relative;
  padding-left: 1.2rem;
}
/* Custom disclosure indicator — small triangle that rotates on open.
   Using a CSS pseudo-element rather than the browser default so it
   stays consistent with our color palette and doesn't fight with the
   uppercase summary text. */
.detail-body details.subsection > summary::before {
  content: "▸";
  position: absolute;
  left: 0;
  top: 0.7rem;
  color: var(--muted);
  font-size: 0.75rem;
  transition: transform 0.15s ease;
  display: inline-block;
}
.detail-body details.subsection[open] > summary::before {
  transform: rotate(90deg);
}
.detail-body details.subsection > summary:hover {
  color: var(--fg);
}
.detail-body details.subsection > summary:hover::before {
  color: var(--fg);
}
/* Hide the legacy <h4 class="section-subheading"> rules — those were
   for the old non-collapsible layout. The summary now plays that role.
   But keep the rule for any subheading that wasn't promoted to a
   subsection (rare edge cases like an error block). */
.detail-body h4.section-subheading {
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 1.1rem 0 0.5rem;
  font-weight: 600;
}

/* ── More about this check (long-form prose disclosure) ────────────
   Nested inside each subsection. Closed by default — opens only when
   the reader explicitly clicks. The expand/collapse-all buttons do
   NOT toggle these; they're a deeper-disclosure layer that should
   stay opt-in. */
.detail-body details.more-about {
  margin: 0.7rem 0 0.4rem;
  padding: 0;
  border-left: 2px solid var(--border-soft);
  padding-left: 0.8rem;
}
.detail-body details.more-about > summary {
  cursor: pointer;
  font-size: 0.82rem;
  color: var(--accent);
  padding: 0.2rem 0;
  user-select: none;
  list-style: none;
  position: relative;
  padding-left: 0.9rem;
}
.detail-body details.more-about > summary::before {
  content: "▸";
  position: absolute;
  left: 0;
  top: 0.2rem;
  color: var(--accent);
  font-size: 0.7rem;
  transition: transform 0.15s ease;
  display: inline-block;
}
.detail-body details.more-about[open] > summary::before {
  transform: rotate(90deg);
}
.detail-body details.more-about > summary:hover {
  color: var(--accent-hover);
}
.detail-body details.more-about .more-about-body {
  padding: 0.5rem 0 0.4rem;
}
.detail-body details.more-about .more-about-body p {
  font-size: 0.9rem;
  color: var(--fg);
  line-height: 1.6;
  margin: 0 0 0.7rem;
}
.detail-body details.more-about .more-about-body p:last-child {
  margin-bottom: 0;
}
/* Inline topic headings inside a multi-topic "More about" disclosure.
   Used when one section's long-form covers multiple related topics
   (e.g. Security headers / CSP / Cookies all under the Headers
   section's disclosure). Light treatment — these are inline within
   the body, not a major heading hierarchy. */
.detail-body details.more-about .more-about-body h5.more-about-topic {
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 1.1rem 0 0.5rem;
  font-weight: 600;
}
.detail-body details.more-about .more-about-body h5.more-about-topic:first-child {
  margin-top: 0;
}

/* ── Expand-all / collapse-all controls ──────────────────────────────
   Two buttons above the Detail section. Visually they're styled like
   the link-buttons in the action bar — the outline is subtle, the
   action is what matters. */
.detail-controls {
  display: flex;
  gap: 0.6rem;
  margin: 0 0 0.8rem;
  flex-wrap: wrap;
}
.detail-btn {
  font: inherit;
  font-size: 0.85rem;
  background: var(--surface);
  color: var(--fg);
  border: 1px solid var(--border-soft);
  padding: 0.4rem 0.85rem;
  border-radius: 5px;
  cursor: pointer;
  transition: background-color 0.12s ease, border-color 0.12s ease;
}
.detail-btn:hover {
  background: var(--surface-hover);
  border-color: var(--border);
}
.detail-btn:active {
  background: var(--surface-2);
}

.section-error {
  color: var(--fail);
  font-size: 0.9rem;
  background: var(--fail-bg);
  padding: 0.5rem 0.7rem;
  border-radius: 3px;
}

/* ── Links ───────────────────────────────────────────────────────────── */
a { color: var(--accent); }
a:hover { color: var(--accent-hover); }

/* ── Footer ──────────────────────────────────────────────────────────── */
.report-footer {
  margin-top: 2rem;
  padding-top: 1.2rem;
  border-top: 1px solid var(--border-soft);
  font-size: 0.85rem;
  color: var(--muted);
}
.top-action-bar {
  margin-bottom: 1.4rem;
  padding-bottom: 0.9rem;
  border-bottom: 1px solid var(--border-soft);
  font-size: 0.88rem;
}
.top-action-bar .footer-actions {
  margin-bottom: 0.7rem;
}

/* Inline audit-another-domain form, sitting under the action links in
   the top action bar. Compact: input + Deep checkbox + Audit button on
   one row. The input takes flex:1 so it expands to fill available
   width, while the checkbox and button stay at their natural sizes. */
.top-action-bar .inline-audit-form {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0;
  flex-wrap: wrap;
}
.top-action-bar .inline-audit-form input[type="text"] {
  flex: 1;
  min-width: 0;  /* allow the input to shrink below its default min */
  font: inherit;
  font-size: 0.92rem;
  padding: 0.45rem 0.7rem;
  border: 1px solid var(--border);
  border-radius: 5px;
  background: var(--surface);
  color: var(--fg);
}
.top-action-bar .inline-audit-form input[type="text"]::placeholder {
  color: var(--muted-soft);
}
.top-action-bar .inline-audit-form input[type="text"]:focus {
  outline: 2px solid var(--accent);
  outline-offset: -1px;
  border-color: var(--accent);
}
.top-action-bar .inline-audit-form .inline-deep {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  cursor: pointer;
  user-select: none;
  color: var(--muted);
  font-size: 0.85rem;
  white-space: nowrap;
  padding: 0.2rem 0.4rem;
  border-radius: 4px;
}
.top-action-bar .inline-audit-form .inline-deep input[type="checkbox"] {
  margin: 0;
  accent-color: var(--accent);
  cursor: pointer;
}
.top-action-bar .inline-audit-form .inline-deep:hover {
  color: var(--fg);
}
.top-action-bar .inline-audit-form button[type="submit"] {
  font: inherit;
  font-size: 0.92rem;
  padding: 0.45rem 1rem;
  background: var(--accent);
  color: rgb(20, 22, 28);
  font-weight: 600;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  transition: background-color 0.12s ease;
}
.top-action-bar .inline-audit-form button[type="submit"]:hover {
  background: var(--accent-hover);
}

.footer-actions { margin-bottom: 0.6rem; }
.footer-actions a {
  margin-right: 1.2rem;
  color: var(--accent);
  text-decoration: none;
}
.footer-actions a:hover {
  color: var(--accent-hover);
  text-decoration: underline;
}
.download-link {
  font-weight: 600;
}
.reaudit-form {
  display: inline;
  margin: 0;
}
.reaudit-form .as-link {
  background: none;
  border: none;
  padding: 0;
  margin: 0 1.2rem 0 0;
  font: inherit;
  color: var(--accent);
  cursor: pointer;
  text-decoration: none;
}
.reaudit-form .as-link:hover {
  color: var(--accent-hover);
  text-decoration: underline;
}
.footer-info span { margin-right: 1.2rem; }
.footer-info a { color: var(--muted); }
.footer-info a:hover { color: var(--fg); }
.timings {
  margin-top: 0.8rem;
  font: 0.8rem ui-monospace, monospace;
  color: var(--muted);
}
.timings-label { color: var(--muted); margin-right: 0.5rem; }
.timings .timing { margin-right: 0.6rem; }

/* ── Focus states ─────────────────────────────────────────────────────
   Keyboard focus needs to be obviously visible — the default browser
   focus ring is invisible against the dark theme on most browsers.
   A 2px accent outline is enough without being heavy-handed. */
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 3px;
}

/* ── Mobile ──────────────────────────────────────────────────────────── */
@media (max-width: 600px) {
  .report { padding: 1rem 0.7rem 3rem; }
  .domain { font-size: 1.25rem; }
  .score-row {
    grid-template-columns: 58px 108px 1fr 38px;
    gap: 0.4rem;
  }
  .findings-list .finding {
    grid-template-columns: 22px 1fr auto;
    grid-template-areas:
      "marker text frac"
      ".      cat  cat";
  }
  .findings-list .finding .finding-marker { grid-area: marker; }
  .findings-list .finding .finding-text   { grid-area: text; }
  .findings-list .finding .finding-frac   { grid-area: frac; }
  .findings-list .finding .finding-cat    {
    grid-area: cat;
    margin-top: 0.1rem;
  }
  .detail-body p.explanation strong,
  .detail-body p.expl-line strong {
    display: block;
    margin-bottom: 0.1rem;
  }
}

/* ── Print ───────────────────────────────────────────────────────────── */
@media print {
  :root {
    --bg: white;
    --surface: white;
    --surface-2: #f5f5f3;
    --surface-hover: white;
    --fg: #1a1a1a;
    --muted: #4a4a47;
    --border: #999;
    --border-soft: #c0c0bc;
    --accent: #1d4ed8;
    --pass-bg: #ddf4e0;
    --warn-bg: #fef0d2;
    --fail-bg: #fdecea;
    --info-bg: #eeece9;
  }
  body { background: white; color: #1a1a1a; }
  .report { max-width: none; padding: 0; }
  .findings-block, .detail-section, .score-panel {
    border: 1px solid #999;
    page-break-inside: avoid;
    background: white;
  }
  /* Force ALL <details> elements open when printing — including the
     top-level Detail sections, the per-subsection collapsibles, and
     the "More about this check" deep-disclosures. The user printing
     to PDF wants the full report; the collapsible UI is for screen
     reading, not paper. The trick is content-visibility plus
     display: contents on the details element itself, then forcing
     the children visible. The CSS-only way (no JS): set the details
     to display:block (default), and override the user agent's
     hidden-when-closed behavior by making the *content* visible
     unconditionally. */
  details > * { display: revert !important; }
  details:not([open]) > *:not(summary) {
    display: revert !important;
    visibility: visible !important;
  }
  details > summary {
    list-style: none;
    cursor: default;
    /* Make the summary look like a heading on print rather than an
       interactive control. */
    font-weight: 600;
  }
  .detail-controls,
  .footer-actions {
    display: none;  /* expand/collapse buttons are screen-only */
  }
  a { color: inherit; text-decoration: none; }
}

/* ── 2.0 layout: top bar, side navigation, overview ──────────────────────
   One server-rendered page. Nothing here loads a file: the ring and bars
   are plain elements sized with percentages computed on the server. */
:root {
  --critical: #f87171;  --critical-bg: #4a2626;
  --high:     #fb923c;  --high-bg:     #4a2f14;
  --medium:   #fbbf24;  --medium-bg:   #4a3a14;
  --low:      #93c5fd;  --low-bg:      #1f3350;
}
.top-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem 1rem;
  padding: 0.55rem 1.2rem;
  border-bottom: 1px solid var(--border-soft);
  background: rgb(38, 38, 37);
}
.top-bar .brand-link { display: flex; align-items: center; gap: 0.55rem; min-height: 44px; }
.top-bar .logo { width: 28px; height: 28px; margin: 0; }
.top-bar .brand {
  font-size: 1.05rem; font-weight: 700; letter-spacing: 0;
  text-transform: none; color: var(--fg); margin: 0;
}
.top-domain {
  font: 600 0.95rem ui-monospace, Menlo, Consolas, monospace;
  padding-left: 1rem;
  border-left: 1px solid var(--border-soft);
  overflow-wrap: anywhere;
}
.top-bar .top-action-bar {
  margin: 0 0 0 auto; padding: 0; border: none;
  display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem;
}
.top-bar .inline-audit-form input[type="text"] { flex: 0 1 240px; min-width: 0; }
.top-bar .download-link { white-space: nowrap; }

.shell { display: flex; align-items: flex-start; max-width: 1280px; margin: 0 auto; }
.shell .report { flex: 1 1 0; min-width: 0; max-width: 1040px; margin: 0; padding: 1.5rem 2rem 4rem; }
.side-nav {
  flex: 0 0 216px;
  position: sticky; top: 0;
  max-height: 100vh; overflow-y: auto;
  padding: 1.2rem 0.7rem 2rem;
  display: flex; flex-direction: column; gap: 2px;
}
.nav-group {
  padding: 0.9rem 0.7rem 0.3rem;
  font: 0.68rem ui-monospace, Menlo, Consolas, monospace;
  letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted);
}
.nav-group:first-child { padding-top: 0; }
.nav-link {
  display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;
  min-height: 36px; padding: 0 0.7rem; border-radius: 7px;
  color: var(--fg); text-decoration: none; font-size: 0.92rem;
}
.nav-link:hover { background: var(--surface-hover); color: var(--fg); }
.nav-count { font: 0.8rem ui-monospace, Menlo, Consolas, monospace; color: var(--muted); }
.nav-count-issues { color: var(--critical); }

.overview { margin-bottom: 2rem; }
.overview .scan-meta { justify-content: flex-start; margin: 0 0 0.5rem; }
.headline { margin: 0 0 0.5rem; font-size: 1.7rem; line-height: 1.2; letter-spacing: -0.01em; overflow-wrap: anywhere; }
.verdict { display: flex; align-items: center; gap: 0.5rem; margin: 0 0 0.6rem; font-weight: 600; }
.verdict-dot { width: 0.65rem; height: 0.65rem; border-radius: 50%; background: var(--pass); }
.verdict-critical .verdict-dot { background: var(--critical); }
.verdict-high .verdict-dot { background: var(--high); }
.verdict-medium .verdict-dot { background: var(--medium); }
.verdict-low .verdict-dot { background: var(--low); }
.overview .redirect-notice { text-align: left; margin: 0 0 0.6rem; }
.summary-line { margin: 0 0 1.3rem; color: var(--muted); max-width: 46rem; }

.sev-cards, .glance-cards, .panels { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.75rem; }
.sev-card, .glance-card {
  flex: 1 1 190px; min-width: 0;
  display: flex; flex-direction: column; gap: 0.35rem;
  padding: 0.95rem 1rem;
  border: 1px solid var(--border-soft); border-radius: 12px;
  background: var(--surface); color: var(--fg); text-decoration: none;
}
.sev-card:hover, .glance-card:hover, .cat-row:hover, .fix-row:hover { background: var(--surface-hover); color: var(--fg); }
.sev-card { border-top: 3px solid var(--border); }
.sev-card.sev-critical { border-top-color: var(--critical); }
.sev-card.sev-high     { border-top-color: var(--high); }
.sev-card.sev-medium   { border-top-color: var(--medium); }
.sev-card.sev-low      { border-top-color: var(--low); }
.sev-card-label, .glance-title { color: var(--muted); font-size: 0.86rem; }
.sev-card-count { font-size: 2rem; font-weight: 700; line-height: 1; }
.sev-card-items { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.84rem; }
.sev-card-item { overflow-wrap: anywhere; }
.sev-card-more, .sev-card-none { color: var(--muted); font-size: 0.84rem; }
.glance-value { font-size: 1.25rem; font-weight: 700; line-height: 1.2; }
.glance-bad  { color: var(--critical); }
.glance-good { color: var(--pass); }
.glance-line { color: var(--muted); font-size: 0.84rem; overflow-wrap: anywhere; }

.panel {
  flex: 1 1 340px; min-width: 0;
  padding: 1.1rem 1.2rem;
  border: 1px solid var(--border-soft); border-radius: 12px; background: var(--surface);
}
.panel-title { margin: 0 0 0.9rem; font-size: 1.02rem; }
.stacked-bar { display: flex; gap: 2px; height: 10px; width: 100%; border-radius: 5px; overflow: hidden; background: var(--surface-2); }
.seg { display: block; height: 100%; min-width: 3px; }
.seg-critical { background: var(--critical); }
.seg-high     { background: var(--high); }
.seg-medium   { background: var(--medium); }
.seg-low      { background: var(--low); }
.seg-info     { background: #8a8a84; }
.seg-pass     { background: var(--pass); }
.legend { list-style: none; margin: 1rem 0 0; padding: 0; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.55rem 1rem; font-size: 0.9rem; color: var(--muted); }
.legend-n { color: var(--fg); font-weight: 700; margin-right: 0.15rem; }
.dot { display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 50%; margin-right: 0.45rem; }
.cat-rows { display: flex; flex-direction: column; }
.cat-row {
  display: grid; grid-template-columns: 4.6rem minmax(60px, 1fr) minmax(0, 1.6fr) auto;
  align-items: center; gap: 0.8rem;
  padding: 0.42rem 0.4rem; margin: 0 -0.4rem; border-radius: 7px;
  color: var(--fg); text-decoration: none; font-size: 0.88rem;
}
.cat-name { font-weight: 600; }
.cat-desc, .cat-passed { color: var(--muted); }
.cat-passed { white-space: nowrap; }

.fix-first { margin-top: 1.5rem; }
.fix-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 0.6rem; }
.fix-head h2 { margin: 0; font-size: 1.15rem; }
.fix-head a { font-size: 0.9rem; text-decoration: none; }
.fix-list { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border-soft); border-radius: 12px; background: var(--surface); overflow: hidden; }
.fix-list li + li { border-top: 1px solid var(--border-soft); }
.fix-row { display: flex; align-items: center; gap: 1rem; padding: 0.8rem 1.1rem; color: var(--fg); text-decoration: none; }
.fix-n { font: 0.82rem ui-monospace, Menlo, Consolas, monospace; color: var(--muted); }
.fix-text { flex: 1 1 auto; min-width: 0; font-weight: 600; }
.fix-cat { display: block; font-weight: 400; font-size: 0.84rem; color: var(--muted); }
.fix-note { margin: 0.6rem 0 0; color: var(--muted); font-size: 0.84rem; }

.sev-badge {
  display: inline-block; padding: 0.12rem 0.55rem; border-radius: 6px;
  font: 600 0.78rem system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  white-space: nowrap;
}
.sev-badge.sev-critical { background: var(--critical-bg); color: #ffb4b4; }
.sev-badge.sev-high     { background: var(--high-bg);     color: #ffc48a; }
.sev-badge.sev-medium   { background: var(--medium-bg);   color: #ffd978; }
.sev-badge.sev-low      { background: var(--low-bg);      color: #c3dcff; }
.sev-critical .finding-marker { color: var(--critical); }
.sev-high .finding-marker     { color: var(--high); }
.sev-medium .finding-marker   { color: var(--medium); }
.sev-low .finding-marker      { color: var(--low); }

@media (max-width: 900px) {
  .shell { display: block; }
  .side-nav {
    position: static; max-height: none;
    flex-direction: row; overflow-x: auto; white-space: nowrap;
    padding: 0.5rem 0.7rem; border-bottom: 1px solid var(--border-soft);
  }
  .nav-group { display: none; }
  .nav-link { flex: 0 0 auto; min-height: 44px; }
  .shell .report { max-width: none; padding: 1.2rem 1rem 3rem; }
  .top-bar .top-action-bar { margin-left: 0; width: 100%; }
  .top-bar .inline-audit-form input[type="text"] { flex: 1 1 140px; }
  .headline { font-size: 1.35rem; }
  .cat-row { grid-template-columns: 4.6rem minmax(0, 1fr) auto; }
  .cat-desc { display: none; }
  .legend { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .fix-row { flex-wrap: wrap; gap: 0.4rem 0.8rem; }
}
@media print {
  .side-nav, .top-bar .top-action-bar { display: none; }
  .shell { display: block; }
  .shell .report { max-width: none; padding: 0; }
}
</style>
</head>
"""
