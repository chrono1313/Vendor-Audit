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
    '<line x1="32" y1="38" x2="46" y2="34" stroke="#5fa3ff" stroke-width="1"/>'
    '<line x1="46" y1="34" x2="50" y2="48" stroke="#5fa3ff" stroke-width="1"/>'
    '<line x1="32" y1="38" x2="50" y2="48" stroke="#5fa3ff" stroke-width="1"/>'
    '<circle cx="32" cy="38" r="3" fill="#5fa3ff"/>'
    '<circle cx="46" cy="34" r="3" fill="#5fa3ff"/>'
    '<circle cx="50" cy="48" r="3" fill="#5fa3ff"/>'
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
}

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
    ("libraries",     "Client-side Libraries", _render_versioned_libraries_section),
    ("headers",       "Security Headers",      _render_browser_security_headers_section),
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

    parts: list[str] = []
    parts.append(_DOC_HEAD.replace("__TITLE__",
                                   _h(f"Vendor Audit — {domain}")))
    parts.append('<body>')
    parts.append('<main class="report">')

    parts.append(_render_header_html(data, domain, audit_domain,
                                     timestamp, duration_ms))
    # Partial-results banner. When run_audit hits its wall-clock
    # deadline, results._partial is True and _partial_reason is a
    # human-readable explanation. We surface this up top so the user
    # doesn't read the report as a complete audit.
    if data.results.get("_partial"):
        parts.append(
            f'<div class="partial-banner" role="alert">'
            f'  <strong>Partial audit:</strong> '
            f'{_h(data.results.get("_partial_reason") or "Some checks did not complete.")}'
            f'</div>'
        )
    parts.append(_render_action_bar_html(data, domain))
    parts.append(_render_score_panel_html(data))
    parts.append(_render_executive_summary_html(data))
    parts.append(_render_detail_sections_html(data))
    parts.append(_render_footer_html(data, domain))

    parts.append('</main>')
    parts.append('</body></html>')
    return "\n".join(parts)


# ── Header ───────────────────────────────────────────────────────────────────

def _render_header_html(data, domain, audit_domain, timestamp, duration_ms):
    redirected = (audit_domain and audit_domain != domain)
    deep = data.results.get("_scan", {}).get("deep", False)
    ts_human = _format_timestamp(timestamp)

    out = ['<header class="report-header">']
    out.append('  <a class="brand-link" href="/" aria-label="Vendor Audit home">')
    out.append(f'    <div class="logo">{_LOGO_SVG}</div>')
    out.append('    <div class="brand">Vendor Audit</div>')
    out.append('  </a>')
    out.append(f'  <h1 class="domain">{_h(domain)}</h1>')
    if redirected:
        out.append(
            f'  <p class="redirect-notice">'
            f'Redirects to <strong>{_h(audit_domain)}</strong> — '
            f'email is audited for both domains; web and TLS reflect the destination.'
            f'</p>'
        )
    out.append('  <div class="scan-meta">')
    out.append(f'    <span class="scan-time">Scanned {_h(ts_human)}</span>')
    out.append(f'    <span class="scan-duration">{duration_ms} ms</span>')
    if deep:
        out.append('    <span class="flag">--deep</span>')
    out.append('  </div>')
    out.append('</header>')
    return "\n".join(out)


# ── Score panel ──────────────────────────────────────────────────────────────

def _render_score_panel_html(data):
    """Overall score + per-category bars. Read from ReportData's already-
    computed fields; no scoring logic lives here."""
    overall_sev = data.score_severity
    out = ['<section class="score-panel" aria-label="Score">']

    # Overall row
    out.append('  <div class="score-row score-overall">')
    out.append('    <div class="score-label">Overall</div>')
    out.append(_score_bar_html(data.earned, data.possible, data.pct, overall_sev))
    out.append('  </div>')

    # Per-category rows
    if data.category_rows:
        out.append('  <div class="score-categories">')
        for r in data.category_rows:
            out.append('  <div class="score-row score-category">')
            out.append(f'    <div class="score-label">{_h(r["category"])}</div>')
            out.append(_score_bar_html(r["earned"], r["possible"],
                                       r["pct"], r["severity"]))
            out.append('  </div>')
        out.append('  </div>')

    out.append('</section>')
    return "\n".join(out)


def _score_bar_html(earned, possible, pct, severity):
    """One score bar — earned/possible fraction + visual bar + percentage."""
    cls = _SEVERITY_CLASS.get(severity, "sev-info")
    earned_disp = _fmt_score_number(earned)
    poss_disp   = _fmt_score_number(possible)
    return (
        f'    <div class="score-fraction">'
        f'<span class="num">{earned_disp}</span>'
        f'<span class="sep"> / </span>'
        f'<span class="den">{poss_disp}</span>'
        f'</div>'
        f'    <div class="score-bar {cls}" '
        f'role="progressbar" aria-valuenow="{int(pct)}" '
        f'aria-valuemin="0" aria-valuemax="100">'
        f'<div class="score-bar-fill" style="width: {int(pct)}%"></div>'
        f'</div>'
        f'    <div class="score-percent">{int(pct)}%</div>'
    )


def _fmt_score_number(n):
    """Mirror audit_txt_report._fmt_int_or_float — show 1.5 not 1.5000000004."""
    if isinstance(n, float):
        return f"{n:g}"
    return str(n)


# ── Executive summary ────────────────────────────────────────────────────────

def _render_executive_summary_html(data):
    """Severity-grouped finding rows. Reads data._finding_rows directly.

    Each row is a (severity, category, display_text, earned, possible)
    tuple. We group fail+warn into "Possible Issues", show info, and
    show passes expanded — passes are evidence the vendor is doing the
    right thing, and the report's value to a vendor is in seeing what
    they got right alongside what needs work. Informational stays
    collapsed by default since it's the lowest-signal group.
    """
    rows = getattr(data, 'finding_rows', None)
    if rows is None:
        # ReportData stores it as _finding_rows in the txt report's actual
        # structure. Fall back to that name.
        rows = getattr(data, '_finding_rows', [])

    # Group by severity
    by_sev = {"fail": [], "warn": [], "info": [], "pass": []}
    for r in rows:
        sev = r.get("severity", "info")
        if sev in by_sev:
            by_sev[sev].append(r)

    out = ['<section class="exec-summary" aria-label="Executive summary">']
    out.append('  <h2>Findings</h2>')

    issues = by_sev["fail"] + by_sev["warn"]
    if issues:
        out.append(_findings_block_html("Possible Issues", issues, open_=True))
    if by_sev["info"]:
        out.append(_findings_block_html("Informational", by_sev["info"],
                                        open_=False))
    if by_sev["pass"]:
        out.append(_findings_block_html(
            "Passing", by_sev["pass"], open_=True,
        ))

    if not (issues or by_sev["info"] or by_sev["pass"]):
        out.append('  <p class="empty">No findings to display.</p>')

    out.append('</section>')
    return "\n".join(out)


def _findings_block_html(title, rows, *, open_=False):
    """One <details> block of findings."""
    open_attr = " open" if open_ else ""
    out = [f'  <details class="findings-block"{open_attr}>']
    out.append(f'    <summary>{_h(title)} <span class="count">({len(rows)})</span></summary>')
    out.append('    <ul class="findings-list">')
    for r in rows:
        sev = r.get("severity", "info")
        cat = r.get("category", "")
        display = r.get("display", "")
        earned = r.get("earned", 0)
        possible = r.get("possible", 0)
        cls = _SEVERITY_CLASS.get(sev, "sev-info")
        marker = {"pass": "✓", "warn": "!", "fail": "✗", "info": "·"}.get(sev, "·")
        frac = f"{_fmt_score_number(earned)} / {_fmt_score_number(possible)}"
        out.append(
            f'      <li class="finding {cls}">'
            f'<span class="finding-marker" aria-hidden="true">{_h(marker)}</span>'
            f'<span class="finding-cat">{_h(cat)}</span>'
            f'<span class="finding-text">{_h(display)}</span>'
            f'<span class="finding-frac">{_h(frac)}</span>'
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
    """
    out = ['<section class="details" aria-label="Detailed findings">']
    out.append('  <h2>Detail</h2>')

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


def _section_html(section_id, title, txt_block):
    """Wrap one txt-rendered section in HTML with a stable anchor id.

    The txt section starts with a section heading (e.g. "EMAIL") that's
    redundant in HTML — the <summary> already names the section. We
    suppress the first heading to avoid showing the title twice.
    """
    body_html = _txt_to_html(txt_block, suppress_first_heading=True)
    return (
        f'  <details class="detail-section" id="section-{_h(section_id)}" open>\n'
        f'    <summary>{_h(title)}</summary>\n'
        f'    <div class="detail-body">{body_html}</div>\n'
        f'  </details>'
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

# Headings: the txt renderer wraps headings in horizontal rule lines.
# Heavy rule (═) marks top-level section headings; light rule (─) marks
# subheadings. The line ABOVE the rule is the heading text. The bottom
# rule typically immediately follows the heading text.

def _txt_to_html(block: str, *, suppress_first_heading: bool = False) -> str:
    """Convert a txt-renderer block to HTML, preserving structure.

    Approach: walk lines, identify each as a heading, finding line, raw
    value, blank, or plain text, and emit appropriate HTML. The output
    is a sequence of <h3>/<h4> headings, <ul>/<li> finding lists, and
    <pre> blocks for raw values.

    When suppress_first_heading is True, the first <h3> is replaced with
    nothing — used by detail sections, where the <summary> already names
    the section and a leading <h3> would duplicate it.
    """
    lines = block.splitlines()
    out: list[str] = []
    i = 0
    pending_heading: str | None = None  # the line above a rule, if any
    h3_emitted = False                  # tracks whether any <h3> has shipped

    findings_open = False  # are we currently inside a <ul class="findings">?

    def close_findings():
        nonlocal findings_open
        if findings_open:
            out.append('</ul>')
            findings_open = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Detect rule lines. They're a long run of either ═ or ─ chars.
        # When a heading is "promoted" by an adjacent rule line, the txt
        # renderer's center-padding (it pads section titles to 100 cols)
        # bleeds through as runs of leading whitespace. Strip it here —
        # heading text in HTML doesn't want column-aligned padding.
        if stripped and all(ch == _RULE_HEAVY_CHAR for ch in stripped):
            close_findings()
            if pending_heading:
                if suppress_first_heading and not h3_emitted:
                    # Drop the redundant top-level heading; <summary>
                    # already serves this role for detail sections.
                    pass
                else:
                    out.append(
                        f'<h3 class="section-heading">'
                        f'{_h(pending_heading.strip())}</h3>'
                    )
                h3_emitted = True
                pending_heading = None
            i += 1
            continue
        if stripped and all(ch == _RULE_LIGHT_CHAR for ch in stripped):
            close_findings()
            if pending_heading:
                out.append(
                    f'<h4 class="section-subheading">'
                    f'{_h(pending_heading.strip())}</h4>'
                )
                pending_heading = None
            i += 1
            continue

        # Blank line — flushes any pending heading candidate.
        if not stripped:
            close_findings()
            if pending_heading:
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
            # Look ahead for continuation/sub lines (deeper-indented,
            # non-marker lines that follow).
            sub_lines: list[str] = []
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
                sub_lines.append(nxt.strip())
                j += 1

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
                f'<span class="finding-text">{_h(message)}</span>'
                f'{sub_html}'
                f'</li>'
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

    # Flush trailing state
    close_findings()
    if pending_heading:
        out.append(f'<p class="raw-line">{_h(pending_heading)}</p>')

    return "\n".join(out)


# ── Footer ───────────────────────────────────────────────────────────────────

def _render_action_bar_html(data, domain):
    """Render the same actions+info as the footer, but as a top-of-report
    element. Lets a reader download the .txt or audit another domain
    without scrolling all the way down past the detail sections.

    Same DOM as the footer (so existing CSS reuses), but with a
    .top-action-bar marker class for any positioning tweaks. The slowest-
    checks panel is omitted up here — that's diagnostic info that belongs
    after the report, not before it. The version line is also omitted up
    top; one footer is enough for that.
    """
    out = ['<aside class="top-action-bar">']
    out.append('  <div class="footer-actions">')
    out.append(
        f'    <a class="download-link" href="/audit/{_h(domain)}.txt" '
        f'download>Download as .txt</a>'
    )
    # Re-audit re-runs against the same domain. Done as a real <form>
    # POST (not a GET link) so it reuses the existing /audit POST
    # endpoint, including its rate limit. Styled as a link via .as-link
    # so it matches the surrounding action-bar items visually.
    out.append(
        f'    <form class="reaudit-form" method="get" action="/audit">'
        f'<input type="hidden" name="domain" value="{_h(domain)}">'
        f'<button type="submit" class="as-link">Re-audit this domain</button>'
        f'</form>'
    )
    out.append('    <a href="/">Audit another domain</a>')
    out.append('  </div>')
    out.append('</aside>')
    return "\n".join(out)


def _render_footer_html(data, domain):
    timings = data.results.get("_scan", {}).get("check_timings", {})
    slow = sorted(
        ((k, v) for k, v in timings.items()
         if not k.startswith("_") and isinstance(v, (int, float)) and v >= 0.5),
        key=lambda kv: -kv[1],
    )[:5]

    out = ['<footer class="report-footer">']
    out.append('  <div class="footer-actions">')
    out.append(
        f'    <a class="download-link" href="/audit/{_h(domain)}.txt" '
        f'download>Download as .txt</a>'
    )
    out.append(
        f'    <form class="reaudit-form" method="get" action="/audit">'
        f'<input type="hidden" name="domain" value="{_h(domain)}">'
        f'<button type="submit" class="as-link">Re-audit this domain</button>'
        f'</form>'
    )
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

_DOC_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
:root {
  --bg: rgb(40, 40, 38);          /* warm dark — the requested page bg */
  --panel: rgb(48, 48, 45);       /* one step lighter than bg for cards */
  --fg: #ececea;                  /* primary text, warm off-white */
  --muted: #999;                  /* secondary text */
  --border: #4a4a47;              /* subtle dividers — just lighter than bg */
  --accent: #5fa3ff;              /* links, brighter than light-mode for contrast */
  --pass: #4ade80;
  --pass-bg: #1a3a22;
  --warn: #fbbf24;
  --warn-bg: #3a2e0e;
  --fail: #f87171;
  --fail-bg: #3a1a1a;
  --info: #999;
  --info-bg: #38383a;
}
* { box-sizing: border-box; }
body {
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: var(--fg);
  background: var(--bg);
  margin: 0;
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
  /* The logo + brand are wrapped in a link to "/" so users can return to
     the form without using the back button. We undo the default link
     coloring here so it doesn't paint the logo blue and the wordmark blue. */
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
  color: var(--fg);  /* drives the magnifying-glass outline via currentColor */
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
  word-break: break-all;
}
.scan-meta {
  /* Override the default left-aligned scan-meta to keep the centered look. */
  display: flex;
  justify-content: center;
  gap: 1.2rem;
}
.redirect-notice {
  background: var(--warn-bg);
  color: var(--warn);
  padding: 0.45rem 0.8rem;
  margin: 0.6rem 0 0;
  border-left: 3px solid var(--warn);
  border-radius: 0 3px 3px 0;
  font-size: 0.92rem;
}
/* Partial-audit banner shown when run_audit hits its wall-clock
   deadline. Higher visibility than the redirect notice — it's a
   warning that the report below is incomplete, and the user should
   know that before they share or score it. */
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
.redirect-notice strong { font-family: ui-monospace, monospace; }
/* .scan-meta layout is centered (see header block above); these are the
   color/typography rules. */
.scan-meta {
  margin-top: 0.6rem;
  color: var(--muted);
  font-size: 0.85rem;
}
.scan-meta .flag {
  font-family: ui-monospace, monospace;
  color: var(--warn);
}

/* ── Score panel ──────────────────────────────────────────────────────── */
.score-panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem 1.2rem;
  margin-bottom: 1.4rem;
}
.score-row {
  display: grid;
  grid-template-columns: 90px 95px 1fr 50px;
  align-items: center;
  gap: 0.8rem;
  padding: 0.35rem 0;
}
.score-overall {
  font-size: 1.05rem;
  font-weight: 600;
  padding-bottom: 0.7rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 0.4rem;
}
.score-overall .score-label { font-size: 1.05rem; }
.score-categories .score-row { font-size: 0.9rem; }
.score-label { color: var(--fg); }
.score-fraction {
  font: 0.92rem ui-monospace, monospace;
  text-align: right;
  color: var(--muted);
}
.score-fraction .num { color: var(--fg); font-weight: 600; }
.score-fraction .sep { padding: 0 0.1rem; }
.score-bar {
  height: 10px;
  background: #38383a;
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
}

/* ── Executive summary ──────────────────────────────────────────────── */
.exec-summary { margin-bottom: 1.6rem; }
.exec-summary h2,
.details h2 {
  font-size: 1.05rem;
  margin: 0 0 0.7rem;
  letter-spacing: 0.02em;
}
.findings-block {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 0.6rem;
  overflow: hidden;
}
.findings-block summary {
  cursor: pointer;
  padding: 0.6rem 0.9rem;
  font-weight: 600;
  user-select: none;
  background: var(--panel);
}
.findings-block summary:hover { background: #3a3a37; }
.findings-block summary .count {
  color: var(--muted);
  font-weight: 400;
  margin-left: 0.3rem;
}
.findings-list {
  list-style: none;
  margin: 0;
  padding: 0;
  border-top: 1px solid var(--border);
}
.findings-list .finding {
  display: grid;
  grid-template-columns: 28px 80px 1fr auto;
  gap: 0.5rem;
  align-items: baseline;
  padding: 0.4rem 0.9rem;
  font-size: 0.92rem;
  border-bottom: 1px solid #3a3a37;
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
.sev-info .finding-marker { color: var(--info); }
.finding-cat {
  color: var(--muted);
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.finding-text { word-break: break-word; }
.finding-frac {
  font: 0.85rem ui-monospace, monospace;
  color: var(--muted);
  white-space: nowrap;
}
.empty { color: var(--muted); font-style: italic; }

/* ── Detail sections ─────────────────────────────────────────────────── */
.detail-section {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 0.6rem;
  overflow: hidden;
}
.detail-section > summary {
  cursor: pointer;
  padding: 0.6rem 0.9rem;
  font-weight: 600;
  user-select: none;
  font-size: 0.95rem;
}
.detail-section > summary:hover { background: #3a3a37; }
.detail-section[open] > summary {
  border-bottom: 1px solid var(--border);
}
.detail-body { padding: 0.9rem 1rem; }
.detail-body h3.section-heading {
  font-size: 0.95rem;
  margin: 0.6rem 0 0.4rem;
  letter-spacing: 0.02em;
}
.detail-body h4.section-subheading {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  margin: 1rem 0 0.4rem;
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
  padding: 0.25rem 0;
  font-size: 0.92rem;
  border: none;
}
.detail-body .finding-sub {
  margin-top: 0.2rem;
  margin-left: 0;
  padding: 0.4rem 0.6rem;
  background: #2c2c2a;
  border-radius: 3px;
  font: 0.85rem ui-monospace, monospace;
  word-break: break-all;
  white-space: pre-wrap;
  grid-column: 2;
}
.section-error {
  color: var(--fail);
  font-size: 0.9rem;
  background: var(--fail-bg);
  padding: 0.5rem 0.7rem;
  border-radius: 3px;
}

/* ── Footer ──────────────────────────────────────────────────────────── */
.report-footer {
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  font-size: 0.85rem;
  color: var(--muted);
}
/* Top action bar — same visual treatment as the footer's actions row,
   inverted (border-bottom rather than border-top) so it reads as a divider
   between the header and the score panel below it. */
.top-action-bar {
  margin-bottom: 1.4rem;
  padding-bottom: 0.8rem;
  border-bottom: 1px solid var(--border);
  font-size: 0.85rem;
}
.top-action-bar .footer-actions { margin-bottom: 0; }
.footer-actions { margin-bottom: 0.6rem; }
.footer-actions a {
  margin-right: 1.2rem;
  color: var(--accent);
  text-decoration: none;
}
.footer-actions a:hover { text-decoration: underline; }
.download-link {
  font-weight: 600;
}
/* The re-audit form is inline so the button sits in line with the
   surrounding link-style action items. The button itself is styled to
   match the links so the row reads as three peers. */
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
.reaudit-form .as-link:hover { text-decoration: underline; }
.footer-info span { margin-right: 1.2rem; }
.footer-info a { color: var(--muted); }
.timings {
  margin-top: 0.6rem;
  font: 0.8rem ui-monospace, monospace;
}
.timings-label { color: var(--muted); margin-right: 0.5rem; }
.timings .timing { margin-right: 0.6rem; }

/* ── Mobile ──────────────────────────────────────────────────────────── */
@media (max-width: 600px) {
  .report { padding: 1rem 0.7rem 3rem; }
  .domain { font-size: 1.25rem; }
  .score-row {
    grid-template-columns: 70px 80px 1fr 42px;
    gap: 0.5rem;
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
}

/* ── Print ───────────────────────────────────────────────────────────── */
@media print {
  /* Dark theme is for screens. Print reverts to a light scheme so vendors
     can print and read the report on paper without burning toner. We
     override the whole palette in scope here rather than redefine each
     component. */
  :root {
    --bg: white;
    --panel: white;
    --fg: #1a1a1a;
    --muted: #555;
    --border: #999;
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
  details { open: open; }
  details > summary { list-style: none; cursor: default; }
  .footer-actions { display: none; }
  a { color: inherit; text-decoration: none; }
}
</style>
</head>
"""
