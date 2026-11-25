"""vendor_audit.web.render_html — HTML renderer for the result page.

ARCHITECTURE
------------
The audit produces one results dict. Three renderers consume it:
  - audit_render.render            terminal
  - audit_txt_report._render_text  plain text
  - this module                    HTML (web result page)

The page is built from two structured sources and nothing else:

  1. _ReportData (audit_txt_report) — the findings, the counts by severity,
     the per-category rows and the verdict.
  2. audit_records.build_records — one record per check: severity,
     category, standard, the one-line explanation, and the evidence that
     was observed.

No renderer output is parsed. Adding a check means adding its outcome to
rubric.json and, when it has evidence worth showing, an evidence builder in
audit_records.py.

PAGE
----
One server-rendered response. One first-party script (/static/result.js).
No stylesheet, image or font is fetched; the ring and the bars are inline
SVG and plain elements sized with numbers computed here.

  top bar      brand, domain, audit-another-domain form, .txt download
  side nav     anchor links
  overview     headline, stat cards, pass-rate ring, findings by severity
  categories   one card per category
  all checks   one table row per check: Findings / All / Passed
  drawers      one detail panel per check, opened from any row or link

The page works without the script: every row is listed, and a check's
detail panel opens through the :target selector. The script adds the
filters, keyboard handling and previous / next.

SAVED COPY
----------
to_standalone() turns a rendered page into the file served by
/audit/<domain>.html: the script is inlined so the copy works from disk,
the parts that only make sense on the site (the audit form, the download
links) are dropped, site links become absolute, and a note says the file
is a snapshot. It is a string transform of the cached page, so a download
costs no audit and no re-render, and always matches the page on screen.
Site-only markup sits between <!--site--> and <!--/site-->.
"""
from __future__ import annotations

import base64
import html
import re
from urllib.parse import quote
from datetime import datetime

from .. import audit_txt_report
from .. import audit_records
from ..audit_txt_report import _ReportData, bot_challenge_note, ipv6_only_note


# ── Brand ────────────────────────────────────────────────────────────────────
# Inline SVG of the Vendor Audit logo. The same SVG is embedded in form.html
# and error.html; change all three together.
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

# Drawer icons, defined once and referenced with <use>: 45 panels would
# otherwise each carry three copies of the same paths.
_ICON_DEFS = (
    '<svg class="icon-defs" aria-hidden="true" width="0" height="0"><defs>'
    '<symbol id="i-prev" viewBox="0 0 16 16"><path d="M10 3 5 8l5 5"/></symbol>'
    '<symbol id="i-next" viewBox="0 0 16 16"><path d="m6 3 5 5-5 5"/></symbol>'
    '<symbol id="i-close" viewBox="0 0 16 16"><path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/></symbol>'
    '</defs></svg>'
)
_ICON_PREV  = '<svg class="icon" aria-hidden="true"><use href="#i-prev"/></svg>'
_ICON_NEXT  = '<svg class="icon" aria-hidden="true"><use href="#i-next"/></svg>'
_ICON_CLOSE = '<svg class="icon" aria-hidden="true"><use href="#i-close"/></svg>'


# ── Constants ────────────────────────────────────────────────────────────────

ISSUE_SEVERITIES = audit_txt_report.ISSUE_SEVERITIES
SEVERITY_ORDER   = audit_txt_report.SEVERITY_ORDER
_SEV_WORD = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Informational", "pass": "Passed"}
_SEV_MEANING = {
    "critical": "Broken or unsupported today.",
    "high":     "An important protection is missing or weak.",
    "medium":   "An expected practice is missing.",
    "low":      "A refinement.",
}
_CATEGORY_ORDER = ["Email", "DNS", "Routing", "TLS", "HTTP", "Website"]


# ── Public entry point ───────────────────────────────────────────────────────

def render_result(envelope: dict) -> str:
    """Render the audit-result envelope as a complete HTML document.

    `envelope` is the structure returned by safe_run_audit() with ok=True.
    The web layer routes ok=False to the error template.
    """
    if not envelope.get("ok"):
        return _render_unexpected(envelope)

    domain       = envelope["domain"]
    audit_domain = envelope["audit_domain"]
    results      = envelope["results"]
    timestamp    = envelope["timestamp"]
    duration_ms  = envelope["duration_ms"]

    data = _ReportData(
        original_domain=envelope.get("original_input") or domain,
        audit_domain=audit_domain,
        results=results,
        timestamp=timestamp,
        report_version=results.get("_scan", {}).get("version", "?"),
    )
    records = audit_records.build_records(data)

    parts = [_DOC_HEAD.replace("__TITLE__", _h(f"Vendor Audit — {domain}")),
             '<body>',
             _render_top_bar_html(data, domain),
             '<div class="shell">',
             _render_side_nav_html(data, records),
             '<main class="report">',
             _render_saved_note_html(data, domain)]
    parts.extend(_render_banners_html(data))
    parts.append(_render_overview_html(data, records, domain, audit_domain,
                                       timestamp, duration_ms))
    parts.append(_render_categories_html(data))
    parts.append(_render_checks_table_html(data, records))
    parts.append(_render_reference_html(records))
    parts.append(_render_footer_html(data, domain))
    parts.append('</main>')
    parts.append('</div>')
    parts.append(_render_drawers_html(records))
    # One first-party script, loaded last. The CSP stays at script-src
    # 'self'. The ?v= query busts the browser cache when the script changes;
    # the route ignores it.
    parts.append(f'<script src="/static/result.js?v={_h(audit_txt_report.__version__)}"></script>')
    parts.append('</body></html>')
    return "\n".join(parts)


# ── Saved copy ──────────────────────────────────────────────────────────────

_SITE_ONLY_RE = re.compile(r"[ \t]*<!--site-->.*?<!--/site-->\n?", re.S)
_SCRIPT_TAG_RE = re.compile(r'<script src="/static/result\.js\?v=[^"]*"></script>')
_FAVICON_LINK = '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'


def to_standalone(page: str, service_url: str, favicon_svg: str = "") -> str:
    """The saved-copy file for a rendered result page.

    `page` is render_result() output, before or after the age placeholder
    is filled. The file needs nothing from the site to display or to work:
    no request is made when it is opened.
    """
    out = _SITE_ONLY_RE.sub("", page)
    out = out.replace("<!--AGO-->", "")
    out = out.replace('<div class="banner banner-saved" hidden>', '<div class="banner banner-saved">', 1)
    icon = ""
    if favicon_svg:
        icon = ('<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,'
                + base64.b64encode(favicon_svg.encode("utf-8")).decode("ascii") + '">')
    out = out.replace(_FAVICON_LINK, icon, 1)
    # Site links: the brand link and "audit again" point at the service.
    base = service_url.rstrip("/")
    out = out.replace('href="/', f'href="{base}/')
    # The script goes in last, so the link rewrite above never touches it.
    # It contains no "</script" (a test checks), so it cannot end the tag early.
    out = _SCRIPT_TAG_RE.sub(lambda _m: "<script>\n" + _RESULT_JS + "</script>", out, count=1)
    return out


# ── Small helpers ────────────────────────────────────────────────────────────

def _h(text) -> str:
    """html.escape with quote=True; None becomes ''."""
    if text is None:
        return ""
    return html.escape(str(text))


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def _short(text):
    """First clause of a finding sentence, for cards: the part before an
    em dash, minus trailing parentheticals."""
    head = (text or "").split(" — ", 1)[0]
    return re.sub(r"(\s*\([^()]*\))+$", "", head).strip()


def _download_hrefs(domain, deep):
    """Site paths of the .txt and .html downloads for this result."""
    q = "?deep=1" if deep else ""
    d = quote(domain)
    return f"/audit/{_h(d)}.txt{q}", f"/audit/{_h(d)}.html{q}"


def _badge(sev):
    return f'<span class="sev-badge sev-{sev}">{_SEV_WORD[sev]}</span>'


def _format_timestamp(ts: str) -> str:
    """ISO 8601 → 'Nov 19, 2026, 14:40:28 UTC'. Seconds stay: two audits of
    one domain in the same minute should not look identical."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y, %H:%M:%S UTC")
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


def _stacked_bar_html(counts, total, label):
    """One horizontal bar split by severity, drawn as SVG.

    SVG geometry attributes rather than style="width: …", so the page needs
    no inline style attributes and the CSP can leave out 'unsafe-inline'.
    The bar is 100 units wide and stretched to fit; each segment is at
    least 1.2 units so a single finding stays visible, and segments are
    separated by a 0.8-unit gap.
    """
    if not total:
        return ""
    present = [(sev, counts.get(sev, 0)) for sev in SEVERITY_ORDER if counts.get(sev, 0)]
    gap = 0.8
    room = 100.0 - gap * (len(present) - 1)
    widths = [max(1.2, room * n / total) for _sev, n in present]
    scale = room / sum(widths)
    rects, x = [], 0.0
    for (sev, _n), w in zip(present, widths):
        w *= scale
        rects.append(f'<rect class="seg-{sev}" x="{x:.2f}" width="{w:.2f}" height="1"/>')
        x += w + gap
    return (f'<svg class="stacked-bar" role="img" aria-label="{_h(label)}" viewBox="0 0 100 1" '
            'preserveAspectRatio="none">' + "".join(rects) + '</svg>')


# ── Top bar ─────────────────────────────────────────────────────────────────

def _render_top_bar_html(data, domain):
    """Brand, the audited domain, the audit-another-domain form and the
    .txt and .html downloads.

    The hidden `from` field carries the domain on screen. /audit compares
    it with the submitted one and, when they match, bypasses the cache so
    re-submitting the same domain runs a fresh audit.
    """
    deep = bool(data.results.get("_scan", {}).get("deep", False))
    txt_href, html_href = _download_hrefs(domain, deep)
    checked = " checked" if deep else ""
    return "\n".join([
        '<header class="top-bar">',
        '  <a class="brand-link" href="/" aria-label="Vendor Audit home">',
        f'    <span class="logo">{_LOGO_SVG}</span>',
        '    <span class="brand">Vendor Audit</span>',
        '  </a>',
        f'  <span class="top-domain">{_h(domain)}</span>',
        '  <!--site-->',
        '  <div class="top-actions">',
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
        '  <span class="downloads">',
        f'  <a class="download-link" href="{txt_href}" download>Download .txt</a>',
        f'  <a class="download-link" href="{html_href}" download>Download .html</a>',
        '  </span>',
        '  </div>',
        '  <!--/site-->',
        '</header>',
    ])


# ── Side navigation ─────────────────────────────────────────────────────────

def _render_side_nav_html(data, records):
    """Anchor links to the parts of this one page. No routing, no requests."""
    out = ['<nav class="side-nav" aria-label="Report sections">',
           '  <div class="nav-group">Report</div>',
           '  <a class="nav-link" href="#overview">Overview</a>']
    if data.issue_count:
        out.append(f'  <a class="nav-link" href="#checks-issues">Findings'
                   f'<span class="nav-count nav-count-issues">{data.issue_count}</span></a>')
    out.append(f'  <a class="nav-link" href="#checks">All checks'
               f'<span class="nav-count">{len(records)}</span></a>')
    if data.category_rows:
        out.append('  <div class="nav-group">Categories</div>')
        for r in data.category_rows:
            n = r["issues"]
            count = (f'<span class="nav-count nav-count-issues">{n}</span>' if n
                     else '<span class="nav-count">0</span>')
            out.append(f'  <a class="nav-link" href="#checks-{_h(r["category"].lower())}">'
                       f'{_h(r["category"])}{count}</a>')
    out.append('  <div class="nav-group">Scan</div>')
    out.append('  <a class="nav-link" href="#scan">Scan details</a>')
    out.append('  <div class="nav-group nav-ext">Other tools</div>')
    for name, url in _other_tools(data):
        out.append(f'  <a class="nav-link nav-ext" href="{_h(url)}" target="_blank" '
                   f'rel="noopener noreferrer">{_h(name)}<span class="nav-count" aria-hidden="true">↗</span>'
                   '<span class="sr-only"> (opens in a new tab)</span></a>')
    out.append('</nav>')
    return "\n".join(out)


def _other_tools(data):
    """(name, url) for other free checkers, pre-filled with this domain.

    The website tools get the audited host (after any redirect); the mail
    and DNS tools get the domain that was entered.
    """
    site = quote(data.audit_domain or data.original_domain, safe="")
    dom = quote(data.original_domain, safe="")
    return [
        ("internet.nl website", f"https://internet.nl/site/{site}/"),
        ("internet.nl email", f"https://internet.nl/mail/{dom}/"),
        ("SSL Labs", f"https://www.ssllabs.com/ssltest/analyze.html?d={site}&hideResults=on"),
        ("MDN Observatory", f"https://developer.mozilla.org/en-US/observatory/analyze?host={site}"),
        ("DNSViz", f"https://dnsviz.net/d/{dom}/dnssec/"),
        ("crt.sh", f"https://crt.sh/?q={site}"),
    ]


# ── Banners ─────────────────────────────────────────────────────────────────

def _render_saved_note_html(data, domain):
    """The note at the top of a saved copy. Rendered hidden on the site;
    to_standalone() shows it. The link runs a new audit on the site."""
    deep = bool(data.results.get("_scan", {}).get("deep", False))
    again = f"/audit/result?domain={quote(domain)}" + ("&deep=1" if deep else "")
    return ('<div class="banner banner-saved" hidden><strong>Saved copy:</strong> '
            f'this file shows the scan of {_h(_format_timestamp(data.timestamp))} and does not update. '
            f'<a href="{_h(again)}">Audit {_h(domain)} again</a> for current results.</div>')


def _render_banners_html(data):
    r = data.results
    out = []
    # Partial results: run_audit hit its wall-clock deadline. Shown first so
    # the report is not read as a complete audit.
    if r.get("_partial"):
        out.append('<div class="banner banner-bad" role="alert"><strong>Partial audit:</strong> '
                   f'{_h(r.get("_partial_reason") or "Some checks did not complete.")}</div>')
    # An MX-only or DNS-only domain has no website to audit.
    if r.get("_no_web_note"):
        out.append('<div class="banner" role="note"><strong>Mail-only / DNS-only domain:</strong> '
                   f'{_h(r.get("_no_web_note"))}</div>')
    # The site answered with a bot challenge, so the page that was read is
    # the challenge, not the site.
    note = bot_challenge_note(r.get("server_header"))
    if note:
        head, lines = note
        out.append(f'<div class="banner banner-warn" role="note"><strong>{_h(head)}:</strong> '
                   f'{_h(" ".join(lines))}</div>')
    note = ipv6_only_note(r)
    if note:
        head, lines = note
        out.append(f'<div class="banner banner-warn" role="note"><strong>{_h(head)}:</strong> '
                   f'{_h(" ".join(lines))}</div>')
    return out


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


def _ring_html(counts):
    """The pass-rate ring: passed checks against the checks that raised a
    finding. Informational rows are in neither. Plain SVG circles; each
    segment's length is its share of a path normalised to 100."""
    assessed = counts["pass"] + sum(counts[s] for s in ISSUE_SEVERITIES)
    pct = audit_txt_report.passed_pct(counts)
    if not assessed or pct is None:
        return ""
    order = ["pass"] + list(ISSUE_SEVERITIES)
    present = [s for s in order if counts[s]]
    gap = 1.2 if len(present) > 1 else 0.0
    segs, start = [], 0.0
    for sev in present:
        share = counts[sev] * 100.0 / assessed
        length = max(share - gap, 0.4)
        segs.append(
            f'<circle class="ring-seg ring-{sev}" cx="60" cy="60" r="50" pathLength="100" '
            f'stroke-dasharray="{length:.2f} {100 - length:.2f}" '
            f'stroke-dashoffset="{-(start + gap / 2):.2f}"/>')
        start += share
    label = f'{pct}% of {assessed} assessed checks passed'
    return (
        '<div class="ring-wrap">'
        f'<svg class="ring" viewBox="0 0 120 120" role="img" aria-label="{_h(label)}">'
        '<circle class="ring-track" cx="60" cy="60" r="50"/>'
        '<g transform="rotate(-90 60 60)">' + "".join(segs) + '</g></svg>'
        '<div class="ring-center" aria-hidden="true">'
        f'<span class="ring-pct">{pct}%</span>'
        f'<span class="ring-sub">passed of {assessed}<br>assessed checks</span>'
        '</div></div>')


def _render_overview_html(data, records, domain, audit_domain, timestamp, duration_ms):
    results = data.results
    counts = data.counts
    total = len(records)
    deep = bool(results.get("_scan", {}).get("deep", False))
    redirect_envelope = results.get("redirect", {}) or {}
    www_fallback = bool(redirect_envelope.get("www_fallback"))
    redirected = bool(audit_domain and audit_domain != domain)

    out = ['<section class="overview" id="overview" aria-label="Overview">']

    # ── Kicker, headline, verdict, summary ──
    # <!--AGO--> is substituted at serve time with " · N minutes ago", so the
    # HTML can be cached once per domain and still show each visitor the age.
    kicker = (f'Vendor Audit report · {_h(_format_timestamp(timestamp))}'
              f'<span class="scan-age"><!--AGO--></span> · {duration_ms} ms')
    if deep:
        kicker += ' · <span class="flag">deep</span>'
    out.append(f'  <p class="kicker">{kicker}</p>')
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
        summary = (f'{_plural(total, "check")} ran. <strong>{data.issue_count} raised a finding</strong>: '
                   f'{_h(audit_txt_report.severity_summary(counts, ", "))}. ')
    else:
        summary = f'{_plural(total, "check")} ran and none raised a finding. '
    summary += f'{counts["pass"]} passed'
    if counts["info"]:
        summary += f' and {counts["info"]} {"is" if counts["info"] == 1 else "are"} informational'
    out.append(f'  <p class="summary-line">{summary}.</p>')

    # ── Stat cards ──
    out.append('  <div class="stat-cards">')
    out.append('    <a class="stat-card" href="#checks-issues">')
    out.append('      <span class="stat-title">Findings</span>')
    out.append(f'      <span class="stat-value">{data.issue_count}</span>')
    chips = [f'<span class="chip-sev sev-{s}"><span class="dot seg-{s}" aria-hidden="true"></span>'
             f'{_SEV_WORD[s]} <b>{counts[s]}</b></span>' for s in ISSUE_SEVERITIES if counts[s]]
    out.append('      <span class="stat-chips">' + ("".join(chips) or
               '<span class="stat-line">Nothing to fix</span>') + '</span>')
    out.append('    </a>')
    out.extend(_glance_cards(data, records))
    out.append('  </div>')

    # ── Ring + findings by severity ──
    out.append('  <div class="panels">')
    out.append('    <section class="panel panel-ring" aria-label="Checks passed">')
    out.append('      ' + _ring_html(counts))
    out.append('      <div class="tiles">')
    for sev in ("pass",) + tuple(ISSUE_SEVERITIES) + ("info",):
        out.append(f'        <a class="tile" href="#checks-{sev}">'
                   f'<span class="tile-n">{counts[sev]}</span>'
                   f'<span class="tile-label"><span class="dot seg-{sev}" aria-hidden="true"></span>'
                   f'{"Info" if sev == "info" else _SEV_WORD[sev]}</span></a>')
    out.append('      </div>')
    out.append('    </section>')

    out.append('    <section class="panel" aria-label="Findings by severity">')
    out.append('      <div class="panel-head"><h2 class="panel-title">Findings by severity</h2>'
               '<a href="#checks-issues">All findings →</a></div>')
    biggest = max((counts[s] for s in ISSUE_SEVERITIES), default=0) or 1
    out.append('      <div class="sev-rows">')
    for sev in ISSUE_SEVERITIES:
        n = counts[sev]
        out.append(f'        <a class="sev-row" href="#checks-{sev}">{_badge(sev)}'
                   f'<svg class="sev-track" viewBox="0 0 100 1" preserveAspectRatio="none" aria-hidden="true">'
                   f'<rect class="seg-{sev}" width="{n * 100.0 / biggest:.1f}" height="1"/></svg>'
                   f'<span class="sev-n">{n}</span></a>')
    out.append('      </div>')
    out.append('      <dl class="sev-defs">')
    for sev in ISSUE_SEVERITIES:
        out.append(f'        <div><dt>{_SEV_WORD[sev]}</dt><dd>{_h(_SEV_MEANING[sev])}</dd></div>')
    out.append('        <div><dt>Informational</dt><dd>Optional or undetermined. Listed, never counted.</dd></div>')
    out.append('      </dl>')
    out.append('    </section>')
    out.append('  </div>')

    out.append('</section>')
    return "\n".join(out)


def _glance_cards(data, records):
    """Three fact cards built from results the audit already holds. Each has
    a good state, so a clean domain still gets a card."""
    r = data.results
    by_label = {rec["label"]: rec for rec in records}
    cards = []

    def card(title, value, value_cls, lines, href):
        out = [f'    <a class="stat-card" href="{href}">',
               f'      <span class="stat-title">{_h(title)}</span>',
               f'      <span class="stat-value stat-value-text {value_cls}">{_h(value)}</span>']
        for ln in lines:
            out.append(f'      <span class="stat-line">{_h(ln)}</span>')
        out.append('    </a>')
        return "\n".join(out)

    def href_for(*labels):
        for label in labels:
            if label in by_label:
                return f'#check-{by_label[label]["id"]}'
        return "#checks"

    # End of life
    eol = [rec for rec in records if rec["label"].startswith("EOL ")]
    if not r.get("_no_web_note"):
        if eol:
            names = [_short(rec["title"]).split(": ", 1)[-1] for rec in eol]
            cards.append(card("End of life", _plural(len(eol), "item"), "stat-bad",
                              names[:3] + ([f"+{len(names) - 3} more"] if len(names) > 3 else []),
                              f'#check-{eol[0]["id"]}'))
        else:
            cards.append(card("End of life", "None detected", "stat-good",
                              ["Judged from versions the server discloses"],
                              href_for("Server header")))

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
        cards.append(card("Certificate expires in",
                          audit_txt_report._humanize_seconds(tls["cert_remaining_seconds"]),
                          "stat-bad" if overdue else "stat-good", lines,
                          href_for("Certificate renewal", "Certificate lifetime")))
    elif tls.get("tls_cert_error"):
        # 3.4.2: verification failed; say why, from the certificate the
        # server sent (read but not trusted).
        from ..audit_records import _days_from_now
        c = tls.get("cert_failed_details") or {}
        reason = tls.get("cert_error_reason")
        days = _days_from_now(c.get("not_after"))
        if reason == "expired" and days is not None:
            value = f"Expired {-days} day{'s' if days != -1 else ''} ago" if days < 0 else "Expired"
        else:
            value = {"self_signed": "Self-signed", "untrusted": "Not trusted",
                     "not_yet_valid": "Not valid yet"}.get(reason, "Not trusted")
        lines = [x for x in (f'Issued by {c["issuer_cn"]}' if c.get("issuer_cn") else None,
                             f'Valid until {c["not_after"][:10]}' if c.get("not_after") else None) if x]
        cards.append(card("Certificate", value, "stat-bad", lines or ["Browsers block the site"],
                          href_for("TLS connection")))

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
        sev = {label: by_label[label]["severity"] for label in ("SPF policy", "DMARC policy")
               if label in by_label}
        worst = next((s for s in ISSUE_SEVERITIES if s in sev.values()), "pass")
        value = {"pass": "Enforced", "low": "Mostly enforced"}.get(worst, "Not enforced")
        # A policy that receivers discard (two records, an include with no
        # SPF record) enforces nothing, whatever it says.
        broken = [label for label in ("SPF single record", "SPF mechanisms", "DMARC single record")
                  if by_label.get(label, {}).get("severity") in ("critical", "high")]
        if broken:
            value, worst = "Broken", "high"
            if "DMARC single record" in broken:
                dmarc_tag = "ignored (more than one record)"
            if "SPF single record" in broken:
                spf_tag = "invalid (more than one record)"
            elif "SPF mechanisms" in broken:
                spf_tag = "invalid (includes a domain with no SPF)"
        lines = [f"SPF {spf_tag}", f"DMARC {dmarc_tag}"]
        if (r.get("dkim") or {}).get("found"):
            lines.append("DKIM key found")
        cards.append(card("Email authentication", value,
                          "stat-good" if worst in ("pass", "low") else "stat-bad",
                          lines, href_for(*(broken or ["DMARC policy", "SPF policy"]))))
    return cards


def _meta_line(rec):
    return " · ".join(b for b in (rec["category"], rec["standard"]) if b)


# ── Categories ──────────────────────────────────────────────────────────────

def _render_categories_html(data):
    if not data.category_rows:
        return ""
    out = ['<section class="block" id="categories" aria-label="Categories">',
           '  <div class="block-head"><h2>Categories</h2></div>',
           '  <div class="cat-cards">']
    for r in data.category_rows:
        if r.get("not_checked"):
            out.append(f'    <div class="cat-card">')
            out.append(f'      <span class="cat-head"><span class="cat-name">{_h(r["category"])}</span>'
                       f'<span class="cat-total">not checked</span></span>')
            out.append('      <span class="cat-desc">Site unreachable from this audit server (no IPv6)</span>')
            out.append('    </div>')
            continue
        desc = audit_txt_report.severity_summary(r["counts"], ", ")
        out.append(f'    <a class="cat-card" href="#checks-{_h(r["category"].lower())}">')
        out.append(f'      <span class="cat-head"><span class="cat-name">{_h(r["category"])}</span>'
                   f'<span class="cat-total">{_plural(r["total"], "check")}</span></span>')
        out.append('      ' + _stacked_bar_html(
            r["counts"], r["total"], f'{r["category"]}: {desc}, {r["passed"]} passed'))
        out.append(f'      <span class="cat-desc">{_h(desc)}'
                   f'<span class="cat-passed">{r["passed"]} passed</span></span>')
        out.append('    </a>')
    out.append('  </div>')
    out.append('</section>')
    return "\n".join(out)


# ── All checks ──────────────────────────────────────────────────────────────

def _render_checks_table_html(data, records):
    """One row per check. Without the script every row is listed. The script
    shows the filter bar and opens on issues only."""
    counts = data.counts
    cats = [r["category"] for r in data.category_rows]
    out = ['<section class="block" id="checks" aria-label="All checks">']
    # Anchors for the filter links, so they still land here without the script.
    for key in ["issues", "all"] + list(SEVERITY_ORDER) + [c.lower() for c in cats]:
        out.append(f'  <span class="anchor" id="checks-{_h(key)}"></span>')
    out.append('  <div class="block-head"><h2>All checks</h2>'
               f'<span class="checks-count" id="checks-count" aria-live="polite">'
               f'{_plural(len(records), "check")}</span></div>')

    # 3.4.8 redesign: three buttons. The category cards, side-nav category
    # links and the overview's severity tiles still filter the table; the
    # filter they set shows as a tag with a clear button.
    out.append(f'  <div class="filters" id="filters" data-cats="{_h("|".join(cats))}">')
    out.append('    <div class="filter-chips" role="group" aria-label="Show checks">')
    chips = [("issues", "Findings", data.issue_count), ("all", "All", len(records)),
             ("pass", "Passed", counts["pass"])]
    for key, word, n in chips:
        out.append(f'      <button type="button" class="filter-chip" data-sev="{key}" '
                   f'aria-pressed="false">{word} <span>{n}</span></button>')
    out.append('      <span class="filter-tag" id="filter-tag" hidden><span id="filter-tag-text"></span>'
               '<button type="button" id="filter-tag-clear" aria-label="Clear this filter">×</button></span>')
    out.append('    </div>')
    out.append('  </div>')

    out.append('  <div class="table-wrap"><table class="checks-table">')
    out.append('    <thead><tr><th scope="col">Severity</th><th scope="col">Check</th>'
               '<th scope="col" class="col-cat">Category</th>'
               '<th scope="col" class="col-std">Standard</th></tr></thead>')
    out.append('    <tbody>')
    for rec in records:
        sev = rec["severity"]
        out.append(
            f'      <tr data-sev="{sev}" data-cat="{_h(rec["category"])}" data-id="{rec["id"]}">'
            f'<td>{_badge(sev)}</td>'
            f'<td><a class="row-link" href="#check-{rec["id"]}">{_h(rec["title"])}</a>'
            f'<span class="row-sub">{_h(rec["label"])}</span></td>'
            f'<td class="col-cat">{_h(rec["category"])}</td>'
            f'<td class="col-std">{_h(rec["standard"])}</td></tr>')
    out.append('    </tbody>')
    out.append('  </table></div>')
    out.append('  <p class="no-match" id="no-match" hidden>No checks match these filters.</p>')
    out.append('</section>')
    return "\n".join(out)


# ── Check detail drawers ────────────────────────────────────────────────────

def _evidence_html(items):
    out = []
    for item in items:
        kind = item[0]
        if kind == "kv":
            out.append('<dl class="kv">')
            for k, v in item[1]:
                if k == "Source" and v.startswith("https://") and " " not in v:
                    value = f'<a href="{_h(v)}" rel="noopener noreferrer">{_h(v)}</a>'
                else:
                    value = _h(v)
                out.append(f'<div><dt>{_h(k)}</dt><dd>{value}</dd></div>')
            out.append('</dl>')
        elif kind == "code":
            out.append(f'<p class="ev-cap">{_h(item[1])}</p><pre class="ev-code">{_h(item[2])}</pre>')
        elif kind == "list":
            out.append(f'<p class="ev-cap">{_h(item[1])}</p><ul class="ev-list">'
                       + "".join(f'<li>{_h(i)}</li>' for i in item[2]) + '</ul>')
        elif kind == "note":
            out.append(f'<p class="ev-note">{_h(item[1])}</p>')
    return "\n".join(out)


def _render_drawers_html(records):
    """One detail panel per check. Hidden until its id is the page target
    (no script) or the script opens it."""
    by_topic = {}
    for rec in records:
        if rec["topic"]:
            by_topic.setdefault(rec["topic"], []).append(rec)

    out = ['<div class="drawers">', _ICON_DEFS]
    total = len(records)
    for i, rec in enumerate(records):
        rid, sev = rec["id"], rec["severity"]
        prev_id = records[i - 1]["id"] if i > 0 else None
        next_id = records[i + 1]["id"] if i + 1 < total else None

        def nav(target, which, label, icon):
            if target:
                return (f'<a class="icon-btn" data-nav="{which}" href="#check-{target}" '
                        f'aria-label="{label}">{icon}</a>')
            return (f'<span class="icon-btn is-disabled" data-nav="{which}" '
                    f'aria-hidden="true">{icon}</span>')

        out.append(f'<div class="drawer" id="check-{rid}">')
        out.append('<a class="drawer-backdrop" href="#checks" data-nav="close" '
                   'aria-hidden="true" tabindex="-1"></a>')
        out.append(f'<article class="drawer-panel" role="dialog" aria-modal="true" '
                   f'aria-labelledby="title-{rid}" tabindex="-1">')
        out.append('<div class="drawer-bar">')
        out.append(f'{_badge(sev)}<span class="drawer-meta">{_h(_meta_line(rec))}</span>')
        out.append(f'<span class="drawer-pos">{i + 1} of {total}</span>')
        out.append(nav(prev_id, "prev", "Previous check", _ICON_PREV))
        out.append(nav(next_id, "next", "Next check", _ICON_NEXT))
        out.append(f'<a class="icon-btn" data-nav="close" href="#checks" '
                   f'aria-label="Close">{_ICON_CLOSE}</a>')
        out.append('</div>')
        out.append(f'<h2 class="drawer-title" id="title-{rid}">{_h(rec["title"])}</h2>')
        out.append(f'<p class="drawer-label">Check: {_h(rec["label"])}</p>')

        evidence = _evidence_html(rec["evidence"])
        if evidence:
            out.append('<section><h3>What Vendor Audit found</h3>')
            out.append(evidence)
            out.append('</section>')
        if rec["what"]:
            out.append(f'<section><h3>What it is</h3><p>{_h(rec["what"])}</p></section>')
        if rec["why"]:
            out.append(f'<section><h3>Why it matters</h3><p>{_h(rec["why"])}</p></section>')
        if rec["fix"] and sev != "pass":
            heading = "How to fix" if sev in ISSUE_SEVERITIES else "How to adopt it"
            out.append(f'<section><h3>{heading}</h3><p>{_h(rec["fix"])}</p></section>')

        related = [r for r in by_topic.get(rec["topic"], []) if r["id"] != rid][:5]
        if related:
            out.append('<section><h3>Related on this domain</h3><ul class="related">')
            for r in related:
                out.append(f'<li><a href="#check-{r["id"]}">{_badge(r["severity"])}'
                           f'<span>{_h(r["title"])}</span></a></li>')
            out.append('</ul></section>')

        topic = rec["topic"]
        if topic and (audit_txt_report.EXPLANATIONS.get(topic) or {}).get("details"):
            name = audit_records.TOPIC_TITLES.get(topic, "this check")
            out.append(f'<p class="more"><a class="more-link" href="#about-{_h(topic)}" '
                       f'data-about="{_h(topic)}">More about {_h(name)}</a></p>')
        out.append('</article>')
        out.append('</div>')
    out.append('</div>')
    return "\n".join(out)


# ── Background reading ──────────────────────────────────────────────────────

def _render_reference_html(records):
    """The long-form explanation for each topic on this page, once. A check's
    panel links here; the script shows the text inside the panel instead and
    hides this section."""
    topics = []
    for rec in records:
        if rec["topic"] and rec["topic"] not in topics:
            topics.append(rec["topic"])
    blocks = []
    for topic in topics:
        paras = (audit_txt_report.EXPLANATIONS.get(topic) or {}).get("details") or []
        if not paras:
            continue
        name = audit_records.TOPIC_TITLES.get(topic, topic)
        blocks.append(f'  <details id="about-{_h(topic)}"><summary>{_h(name)}</summary>'
                      '<div class="about-body">'
                      + "".join(_about_para(p) for p in paras) + '</div></details>')
    if not blocks:
        return ""
    return "\n".join(['<section class="block reference" id="reference" aria-label="Background reading">',
                      '  <div class="block-head"><h2>Background reading</h2></div>']
                     + blocks + ['</section>'])


def _about_para(p):
    """One background paragraph; a (heading, text) pair gets a bold lead-in."""
    if isinstance(p, tuple):
        heading, text = p
        return f'<p><strong>{_h(heading)}</strong> {_h(text)}</p>'
    return f'<p>{_h(p)}</p>'


# ── Footer: scan details ────────────────────────────────────────────────────

def _page_facts(results):
    """Things the audit observed that are not rated as checks."""
    rows = []
    red = results.get("redirect") or {}
    if red.get("elapsed_ms") is not None:
        rows.append(("Response time", f'{red["elapsed_ms"]:.0f} ms (includes DNS, TCP and TLS setup)'))
    sh = results.get("server_header") or {}
    if sh.get("status_code"):
        rows.append(("Home page status", f'HTTP {sh["status_code"]}'))
    p = results.get("page_signals") or {}
    if p.get("parsed"):
        rows.append(("Page inspected", f'{(p.get("body_bytes") or 0) / 1024:.0f} KB, '
                     f'{p.get("scripts_total", 0)} scripts, {p.get("stylesheets_total", 0)} stylesheets, '
                     f'{p.get("iframe_count", 0)} frames'))
        if p.get("third_party_origins"):
            rows.append(("Third-party origins", ", ".join(p["third_party_origins"])))
        a = p.get("a11y") or {}
        if a:
            rows.append(("Page language", a.get("html_lang") or "not declared"))
            rows.append(("Images without alt text", f'{a.get("images_missing_alt", 0)} of {a.get("images_total", 0)}'))
            rows.append(("Form inputs without a label", f'{a.get("inputs_unlabeled", 0)} of {a.get("inputs_total", 0)}'))
            rows.append(("Empty links or buttons", str(a.get("empty_links", 0) + a.get("empty_buttons", 0))))
    return rows


def _render_footer_html(data, domain):
    scan = data.results.get("_scan", {})
    timings = scan.get("check_timings", {})
    slow = sorted(
        ((k, v) for k, v in timings.items()
         if not k.startswith("_") and isinstance(v, (int, float)) and v >= 0.5),
        key=lambda kv: -kv[1],
    )[:5]
    deep = bool(scan.get("deep", False))
    txt_href, html_href = _download_hrefs(domain, deep)

    out = ['<footer class="report-footer" id="scan">',
           '  <div class="block-head"><h2>Scan details</h2></div>']
    facts = _page_facts(data.results)
    if facts:
        out.append('  <dl class="kv facts">')
        for k, v in facts:
            out.append(f'    <div><dt>{_h(k)}</dt><dd>{_h(v)}</dd></div>')
        out.append('  </dl>')
        out.append('  <p class="block-note">Observed for awareness. These are not rated as checks.</p>')
    # On phones the side nav is a single row of section links, so the
    # Other tools links are shown here instead (CSS picks one or the other).
    out.append('  <div class="phone-tools">')
    out.append('    <h3 class="phone-tools-title">Other tools</h3>')
    out.append('    <div class="phone-tools-links">')
    for name, url in _other_tools(data):
        out.append(f'      <a href="{_h(url)}" target="_blank" rel="noopener noreferrer">{_h(name)} ↗'
                   '<span class="sr-only"> (opens in a new tab)</span></a>')
    out.append('    </div>')
    out.append('  </div>')
    out.append('  <!--site-->')
    out.append('  <div class="footer-actions">')
    out.append(f'    <a class="download-link" href="{txt_href}" download>Download as .txt</a>')
    out.append(f'    <a class="download-link" href="{html_href}" download>Download as .html</a>')
    out.append('    <a href="/">Audit another domain</a>')
    out.append('  </div>')
    out.append('  <!--/site-->')
    out.append('  <div class="footer-info">')
    out.append(f'    <span>Vendor Audit v{_h(data.report_version)}</span>'
               f'<span>{"Deep scan" if deep else "Standard scan"}</span>'
               '<span><a href="https://github.com/chrono1313/Vendor-Audit">Source on GitHub</a></span>')
    out.append('  </div>')
    if slow:
        out.append('  <div class="timings"><span class="timings-label">Slowest checks:</span>'
                   + "".join(f'<span class="timing">{_h(k)} ({v:.1f}s)</span>' for k, v in slow)
                   + '</div>')
    out.append('</footer>')
    return "\n".join(out)


# ── Script ───────────────────────────────────────────────────────────────────
# Served by app.py at /static/result.js so the result-page CSP can stay at
# script-src 'self' — own origin only, no inline script, no eval.

_RESULT_JS = """\
(function () {
  'use strict';
  var doc = document, root = doc.documentElement;
  root.className += ' js';

  var ISSUE = { critical: 1, high: 1, medium: 1, low: 1 };
  var SEV_WORD = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' };
  var rows = [].slice.call(doc.querySelectorAll('.checks-table tbody tr'));
  var chips = [].slice.call(doc.querySelectorAll('.filter-chip'));
  var filters = doc.getElementById('filters');
  var cats = filters && filters.getAttribute('data-cats') ? filters.getAttribute('data-cats').split('|') : [];
  var tag = doc.getElementById('filter-tag');
  var tagText = doc.getElementById('filter-tag-text');
  var tagClear = doc.getElementById('filter-tag-clear');
  var countEl = doc.getElementById('checks-count');
  var noMatch = doc.getElementById('no-match');
  var section = doc.getElementById('checks');
  var hasIssues = rows.some(function (tr) { return ISSUE[tr.getAttribute('data-sev')]; });
  // sev: the button pressed (issues / all / pass). only and cat come from
  // the category cards, side-nav links and severity tiles, and show as a tag.
  var state = { sev: hasIssues ? 'issues' : 'all', only: '', cat: '' };

  // -- Filters ---------------------------------------------------------
  function matches(tr) {
    var sev = tr.getAttribute('data-sev');
    if (state.only) {
      if (sev !== state.only) { return false; }
    } else if (state.sev === 'issues' ? !ISSUE[sev] : (state.sev !== 'all' && sev !== state.sev)) {
      return false;
    }
    if (state.cat && tr.getAttribute('data-cat') !== state.cat) { return false; }
    return true;
  }

  function apply() {
    var shown = 0;
    rows.forEach(function (tr) {
      var ok = matches(tr);
      tr.hidden = !ok;
      if (ok) { shown++; }
    });
    chips.forEach(function (b) {
      b.setAttribute('aria-pressed', !state.only && b.getAttribute('data-sev') === state.sev ? 'true' : 'false');
    });
    if (tag) {
      var words = [];
      if (state.cat) { words.push(state.cat); }
      if (state.only) { words.push(SEV_WORD[state.only] || state.only); }
      tag.hidden = !words.length;
      if (tagText) { tagText.textContent = words.join(' \u00b7 '); }
      if (tagClear) { tagClear.setAttribute('aria-label', 'Clear filter: ' + words.join(', ')); }
    }
    if (countEl) {
      countEl.textContent = shown === rows.length
        ? rows.length + ' checks' : 'Showing ' + shown + ' of ' + rows.length;
    }
    if (noMatch) { noMatch.hidden = shown !== 0; }
  }

  chips.forEach(function (b) {
    b.addEventListener('click', function () { state.sev = b.getAttribute('data-sev'); state.only = ''; apply(); });
  });
  if (tagClear) {
    tagClear.addEventListener('click', function () {
      state.only = ''; state.cat = ''; state.sev = hasIssues ? 'issues' : 'all';
      apply();
    });
  }

  // -- Check detail drawer ---------------------------------------------
  var current = null, lastFocus = null, openedHere = false, savedY = 0, routed = null;

  // The page keeps its own scroll position while a panel opens and closes.
  // Handing restoration back on the way out lets the browser restore the
  // position when the reader returns from another page.
  if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
    window.addEventListener('pagehide', function () { history.scrollRestoration = 'auto'; });
  }

  function ids() {
    var visible = rows.filter(function (tr) { return !tr.hidden; })
                      .map(function (tr) { return tr.getAttribute('data-id'); });
    var id = current ? current.id.slice(6) : '';
    if (visible.indexOf(id) !== -1) { return visible; }
    return rows.map(function (tr) { return tr.getAttribute('data-id'); });
  }

  function setNav(el, target) {
    if (!el) { return; }
    if (target) {
      el.setAttribute('href', '#check-' + target);
      el.classList.remove('is-disabled');
      el.removeAttribute('aria-disabled');
    } else {
      el.removeAttribute('href');
      el.classList.add('is-disabled');
      el.setAttribute('aria-disabled', 'true');
    }
  }

  function openDrawer(el) {
    if (current && current !== el) { current.classList.remove('open'); }
    if (!current) { lastFocus = doc.activeElement; savedY = window.pageYOffset; }
    current = el;
    el.classList.add('open');
    root.classList.add('drawer-open');
    var list = ids(), at = list.indexOf(el.id.slice(6));
    var pos = el.querySelector('.drawer-pos');
    if (pos && at !== -1) { pos.textContent = (at + 1) + ' of ' + list.length; }
    var prev = el.querySelector('a[data-nav="prev"]'), next = el.querySelector('a[data-nav="next"]');
    setNav(prev, at > 0 ? list[at - 1] : null);
    setNav(next, at !== -1 && at < list.length - 1 ? list[at + 1] : null);
    var panel = el.querySelector('.drawer-panel');
    if (panel) { panel.scrollTop = 0; panel.focus(); }
  }

  function closeDrawer() {
    if (!current) { return; }
    current.classList.remove('open');
    current = null;
    root.classList.remove('drawer-open');
    if (lastFocus && lastFocus.focus) {
      try { lastFocus.focus({ preventScroll: true }); } catch (e) { lastFocus.focus(); }
    }
    lastFocus = null;
    window.scrollTo(0, savedY);
  }

  function requestClose() {
    if (openedHere) { openedHere = false; history.back(); return; }
    history.replaceState(null, '', location.pathname + location.search);
    routed = '';
    closeDrawer();
  }

  // -- Routing: the hash decides what is shown ---------------------------
  function route(force) {
    var hash = decodeURIComponent((location.hash || '').slice(1));
    // Back and Forward can report one change twice (popstate and hashchange).
    if (force !== true && hash === routed) { return; }
    routed = hash;
    var el = hash.indexOf('check-') === 0 ? doc.getElementById(hash) : null;
    if (el && el.classList.contains('drawer')) { openDrawer(el); return; }
    // Closing a panel can land back on a filter link's hash. That is a
    // return to where the reader was, not a new request to filter and scroll.
    var wasOpen = !!current;
    closeDrawer();
    if (wasOpen) { return; }
    if (hash.indexOf('checks-') === 0) {
      var key = hash.slice(7), found = false;
      chips.forEach(function (b) { if (b.getAttribute('data-sev') === key) { found = true; } });
      if (found) {
        state.sev = key; state.only = ''; state.cat = '';
      } else if (SEV_WORD[key]) {
        state.only = key; state.cat = ''; state.sev = 'all'; found = true;
      } else {
        cats.forEach(function (c) {
          if (c.toLowerCase() === key) { state.cat = c; state.only = ''; state.sev = 'all'; found = true; }
        });
      }
      if (found) {
        apply();
        if (section) { section.scrollIntoView(); }
      }
    }
  }

  doc.addEventListener('click', function (ev) {
    var a = ev.target.closest ? ev.target.closest('a') : null;
    if (!a) { return; }
    var nav = a.getAttribute('data-nav');
    if (nav === 'close') { ev.preventDefault(); requestClose(); return; }
    if (a.classList.contains('is-disabled')) { ev.preventDefault(); return; }
    var href = a.getAttribute('href') || '';
    if (a.classList.contains('more-link')) {
      var src = doc.getElementById('about-' + a.getAttribute('data-about'));
      var body = src ? src.querySelector('.about-body') : null;
      if (body) {
        ev.preventDefault();
        var copy = body.cloneNode(true);
        copy.className = 'about-body about-inline';
        a.parentNode.parentNode.insertBefore(copy, a.parentNode.nextSibling);
        a.parentNode.hidden = true;
      }
      return;
    }
    if (href.indexOf('#check-') === 0) {
      // Opening adds one history entry, so Back closes the panel. Moving
      // between checks replaces it, so one Back still closes.
      ev.preventDefault();
      if (current) {
        history.replaceState(null, '', href);
      } else {
        history.pushState(null, '', href);
        openedHere = true;
      }
      route(true);
    } else if (href.indexOf('#checks-') === 0 && location.hash === href) {
      ev.preventDefault();
      route(true);
    }
  });

  doc.addEventListener('keydown', function (ev) {
    if (!current) { return; }
    var tag = (ev.target.tagName || '').toLowerCase();
    if (ev.key === 'Escape') { ev.preventDefault(); requestClose(); return; }
    if (tag === 'input' || tag === 'select' || tag === 'textarea') { return; }
    if (ev.key === 'ArrowLeft' || ev.key === 'ArrowRight') {
      var link = current.querySelector('a[data-nav="' + (ev.key === 'ArrowLeft' ? 'prev' : 'next') + '"]');
      if (link && link.getAttribute('href')) {
        ev.preventDefault();
        history.replaceState(null, '', link.getAttribute('href'));
        route(true);
      }
      return;
    }
    if (ev.key === 'Tab') {
      // Keep focus inside the open panel.
      var f = [].slice.call(current.querySelectorAll('.drawer-panel a[href], .drawer-panel button'));
      if (!f.length) { return; }
      var first = f[0], last = f[f.length - 1], active = doc.activeElement;
      if (ev.shiftKey && (active === first || !current.contains(active) ||
                          active === current.querySelector('.drawer-panel'))) {
        ev.preventDefault(); last.focus();
      } else if (!ev.shiftKey && (active === last || !current.contains(active))) {
        ev.preventDefault(); first.focus();
      }
    }
  });

  window.addEventListener('hashchange', route);
  window.addEventListener('popstate', route);
  apply();
  route(true);
})();
"""


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
  --bg:            rgb(34, 34, 33);
  --surface:       rgb(44, 44, 42);
  --surface-2:     rgb(52, 52, 49);
  --surface-hover: rgb(56, 56, 53);
  --fg:            #ededeb;   /* ~14.5:1 on --bg */
  --muted:         #bdbdba;   /* ~6.6:1 on --bg */
  --border:        #57574f;
  --border-soft:   #3e3e3a;
  --accent:        #7eb6ff;
  --accent-hover:  #a3cbff;
  --pass:          #4ade80;   --pass-bg:     #1f3d2a;
  --critical:      #f87171;   --critical-bg: #4a2626;
  --high:          #fb923c;   --high-bg:     #4a2f14;
  --medium:        #fbbf24;   --medium-bg:   #4a3a14;
  --low:           #93c5fd;   --low-bg:      #1f3350;
  --info:          #8a8a84;   --info-bg:     #38383a;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { scrollbar-gutter: stable; }
html.drawer-open { overflow: hidden; }
body {
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: var(--fg);
  background: var(--bg);
  margin: 0;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
a { color: var(--accent); }
a:hover { color: var(--accent-hover); }
h1, h2, h3 { text-wrap: balance; }
[hidden] { display: none !important; }
.sr-only {
  position: absolute; width: 1px; height: 1px; overflow: hidden;
  clip-path: inset(50%); white-space: nowrap;
}
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 3px; }

/* ── Top bar ─────────────────────────────────────────────────────────── */
.top-bar {
  display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem;
  padding: 0.55rem 1.2rem;
  border-bottom: 1px solid var(--border-soft);
  background: rgb(38, 38, 37);
}
.brand-link { display: flex; align-items: center; gap: 0.55rem; min-height: 44px; color: inherit; text-decoration: none; }
.brand-link:hover .brand { color: var(--accent); }
.logo { display: block; width: 28px; height: 28px; color: var(--fg); }
.logo svg { display: block; width: 100%; height: 100%; }
.brand { font-size: 1.05rem; font-weight: 700; }
.top-domain {
  font: 600 0.95rem var(--mono);
  padding-left: 1rem; border-left: 1px solid var(--border-soft);
  overflow-wrap: anywhere;
}
.top-actions { margin-left: auto; display: flex; align-items: center; gap: 0.5rem 1rem; }
.inline-audit-form { display: flex; align-items: center; gap: 0.5rem; margin: 0; }
.inline-audit-form input[type="text"] {
  flex: 0 1 240px; min-width: 0; width: 240px;
  font: inherit; font-size: 0.92rem; padding: 0.45rem 0.7rem;
  border: 1px solid var(--border); border-radius: 5px;
  background: var(--surface); color: var(--fg);
}
.inline-audit-form input[type="text"]::placeholder { color: var(--muted); opacity: 0.75; }
.inline-audit-form input[type="text"]:focus { outline: 2px solid var(--accent); outline-offset: -1px; border-color: var(--accent); }
.inline-deep {
  display: inline-flex; align-items: center; gap: 0.35rem; cursor: pointer;
  color: var(--muted); font-size: 0.85rem; white-space: nowrap; padding: 0.2rem 0.4rem;
}
.inline-deep input { margin: 0; accent-color: var(--accent); cursor: pointer; }
.inline-deep:hover { color: var(--fg); }
.inline-audit-form button {
  font: inherit; font-size: 0.92rem; font-weight: 600; padding: 0.45rem 1rem;
  background: var(--accent); color: rgb(20, 22, 28);
  border: none; border-radius: 5px; cursor: pointer; white-space: nowrap;
}
.inline-audit-form button:hover { background: var(--accent-hover); }
.download-link { font-weight: 600; white-space: nowrap; }
.downloads { display: flex; gap: 0.4rem 1rem; flex-wrap: wrap; }
.banner-saved { border-left-color: var(--accent); }

/* ── Shell and side navigation ───────────────────────────────────────── */
.shell { display: flex; align-items: flex-start; max-width: 1360px; margin: 0 auto; }
.report { flex: 1 1 0; min-width: 0; max-width: 1120px; padding: 1.6rem 2rem 4rem; }
.side-nav {
  flex: 0 0 216px; position: sticky; top: 0;
  max-height: 100vh; overflow-y: auto;
  padding: 1.2rem 0.7rem 2rem;
  display: flex; flex-direction: column; gap: 2px;
}
.nav-group {
  padding: 0.9rem 0.7rem 0.3rem;
  font: 0.68rem var(--mono); letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted);
}
.nav-group:first-child { padding-top: 0; }
/* Other tools leave the page, so they sit apart from the section links. */
.nav-group.nav-ext {
  margin: 2.4rem 0.7rem 0; padding: 1.1rem 0 0.3rem;
  border-top: 1px solid var(--border-soft);
}
.nav-link {
  display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;
  min-height: 36px; padding: 0 0.7rem; border-radius: 7px;
  color: var(--fg); text-decoration: none; font-size: 0.92rem;
}
.nav-link:hover { background: var(--surface-hover); color: var(--fg); }
.nav-count { font: 0.8rem var(--mono); color: var(--muted); font-variant-numeric: tabular-nums; }
.nav-count-issues { color: var(--critical); }

/* ── Banners ─────────────────────────────────────────────────────────── */
.banner {
  background: var(--info-bg); color: var(--fg);
  padding: 0.7rem 1rem; margin: 0 0 1rem;
  border-left: 4px solid var(--info); border-radius: 0 6px 6px 0; font-size: 0.95rem;
}
.banner strong { margin-right: 0.3rem; }
.banner-bad  { background: var(--critical-bg); border-left-color: var(--critical); }
.banner-warn { background: var(--medium-bg);   border-left-color: var(--medium); }
.redirect-notice {
  background: var(--medium-bg); color: var(--fg);
  padding: 0.5rem 0.85rem; margin: 0 0 0.6rem;
  border-left: 3px solid var(--medium); border-radius: 0 4px 4px 0; font-size: 0.92rem;
}
.redirect-notice strong { font-family: var(--mono); }

/* ── Overview ────────────────────────────────────────────────────────── */
.overview { margin-bottom: 2.2rem; }
.kicker {
  margin: 0 0 0.6rem;
  font: 0.72rem var(--mono); letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted);
}
.kicker .flag { color: var(--medium); }
.headline { margin: 0 0 0.5rem; font-size: 1.9rem; line-height: 1.15; letter-spacing: -0.015em; overflow-wrap: anywhere; }
.verdict { display: flex; align-items: center; gap: 0.5rem; margin: 0 0 0.6rem; font-weight: 600; }
.verdict-dot { width: 0.65rem; height: 0.65rem; border-radius: 50%; background: var(--pass); }
.verdict-critical .verdict-dot { background: var(--critical); }
.verdict-high .verdict-dot     { background: var(--high); }
.verdict-medium .verdict-dot   { background: var(--medium); }
.verdict-low .verdict-dot      { background: var(--low); }
.summary-line { margin: 0 0 1.3rem; color: var(--muted); max-width: 46rem; }
.summary-line strong { color: var(--fg); }

.stat-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 0.75rem; margin-bottom: 0.75rem; }
.stat-card, .cat-card, .panel {
  border: 1px solid var(--border-soft); border-radius: 12px; background: var(--surface);
}
.stat-card {
  display: flex; flex-direction: column; gap: 0.3rem; min-width: 0;
  padding: 0.95rem 1rem; color: var(--fg); text-decoration: none;
}
.stat-card:hover, .cat-card:hover, .tile:hover, .sev-row:hover { background: var(--surface-hover); color: var(--fg); }
.stat-title { color: var(--muted); font-size: 0.86rem; }
.stat-value { font-size: 2rem; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.stat-value-text { font-size: 1.25rem; line-height: 1.3; padding: 0.25rem 0; }
.stat-bad  { color: var(--critical); }
.stat-good { color: var(--pass); }
.stat-line { color: var(--muted); font-size: 0.84rem; overflow-wrap: anywhere; }
.stat-chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
.chip-sev {
  display: inline-flex; align-items: center; padding: 0.1rem 0.5rem;
  border: 1px solid var(--border-soft); border-radius: 6px; font-size: 0.82rem; white-space: nowrap;
}
.chip-sev b { margin-left: 0.3rem; font-variant-numeric: tabular-nums; }
.dot { display: inline-block; width: 0.55rem; height: 0.55rem; border-radius: 50%; margin-right: 0.4rem; flex: none; }

.panels { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 0.75rem; }
.panel { min-width: 0; padding: 1.2rem 1.3rem; }
.panel-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 0.9rem; }
.panel-head a { font-size: 0.88rem; text-decoration: none; white-space: nowrap; }
.panel-title { margin: 0; font-size: 1.02rem; }
.panel-ring { display: flex; align-items: center; gap: 1.6rem; flex-wrap: wrap; }
.ring-wrap { position: relative; flex: none; width: 168px; height: 168px; }
.ring { display: block; width: 100%; height: 100%; }
.ring-track, .ring-seg { fill: none; stroke-width: 11; }
.ring-track { stroke: var(--surface-2); }
.ring-pass     { stroke: var(--pass); }
.ring-critical { stroke: var(--critical); }
.ring-high     { stroke: var(--high); }
.ring-medium   { stroke: var(--medium); }
.ring-low      { stroke: var(--low); }
.ring-center {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center; text-align: center;
}
.ring-pct { font-size: 2.2rem; font-weight: 700; line-height: 1; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.ring-sub { margin-top: 0.3rem; color: var(--muted); font-size: 0.72rem; line-height: 1.3; }
.tiles { flex: 1 1 240px; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.2rem 0.6rem; }
.tile {
  display: flex; flex-direction: column; gap: 0.1rem; padding: 0.45rem 0.5rem; border-radius: 8px;
  color: var(--fg); text-decoration: none; border-bottom: 1px solid var(--border-soft);
}
.tile-n { font-size: 1.35rem; font-weight: 700; line-height: 1.2; font-variant-numeric: tabular-nums; }
.tile-label { display: flex; align-items: center; color: var(--muted); font-size: 0.82rem; }
.seg-critical { background: var(--critical); }
.seg-high     { background: var(--high); }
.seg-medium   { background: var(--medium); }
.seg-low      { background: var(--low); }
.seg-info     { background: var(--info); }
.seg-pass     { background: var(--pass); }
rect.seg-critical { fill: var(--critical); }
rect.seg-high     { fill: var(--high); }
rect.seg-medium   { fill: var(--medium); }
rect.seg-low      { fill: var(--low); }
rect.seg-info     { fill: var(--info); }
rect.seg-pass     { fill: var(--pass); }

.sev-rows { display: flex; flex-direction: column; gap: 0.15rem; }
.sev-row {
  display: grid; grid-template-columns: 5.2rem 1fr 2rem; align-items: center; gap: 0.9rem;
  padding: 0.3rem 0.4rem; margin: 0 -0.4rem; border-radius: 7px; color: var(--fg); text-decoration: none;
}
.sev-row .sev-badge { text-align: left; }
.sev-track { display: block; width: 100%; height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
.sev-n { text-align: right; font-weight: 700; font-variant-numeric: tabular-nums; }
.sev-defs { margin: 1rem 0 0; display: grid; gap: 0.25rem; font-size: 0.86rem; }
.sev-defs div { display: grid; grid-template-columns: 6.6rem 1fr; gap: 0.6rem; }
.sev-defs dt { font-weight: 600; }
.sev-defs dd { margin: 0; color: var(--muted); }

.sev-badge {
  display: inline-block; padding: 0.12rem 0.55rem; border-radius: 6px;
  font-size: 0.78rem; font-weight: 600; white-space: nowrap;
}
.sev-badge.sev-critical { background: var(--critical-bg); color: #ffb4b4; }
.sev-badge.sev-high     { background: var(--high-bg);     color: #ffc48a; }
.sev-badge.sev-medium   { background: var(--medium-bg);   color: #ffd978; }
.sev-badge.sev-low      { background: var(--low-bg);      color: #c3dcff; }
.sev-badge.sev-info     { background: var(--info-bg);     color: #d6d6d2; }
.sev-badge.sev-pass     { background: var(--pass-bg);     color: #9af0b8; }

/* ── Blocks: fix first, categories, checks ───────────────────────────── */
.block { margin-bottom: 2.2rem; scroll-margin-top: 1rem; }
.block-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 0.7rem; }
.block-head h2 { margin: 0; font-size: 1.15rem; }
.block-head a { font-size: 0.9rem; text-decoration: none; white-space: nowrap; }
.block-note { margin: 0.6rem 0 0; color: var(--muted); font-size: 0.84rem; }

.cat-cards { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.75rem; }
.cat-card { display: flex; flex-direction: column; gap: 0.65rem; padding: 1rem 1.1rem; color: var(--fg); text-decoration: none; min-width: 0; }
.cat-head { display: flex; align-items: baseline; justify-content: space-between; gap: 0.6rem; }
.cat-name { font-weight: 700; font-size: 1.02rem; }
.cat-total { font: 0.8rem var(--mono); color: var(--muted); }
.cat-desc { display: flex; justify-content: space-between; gap: 0.8rem; font-size: 0.86rem; }
.cat-passed { color: var(--muted); white-space: nowrap; }
.stacked-bar { display: block; height: 8px; width: 100%; border-radius: 4px; overflow: hidden; background: var(--surface-2); }

.anchor { display: block; height: 0; }
.checks-count { font: 0.8rem var(--mono); color: var(--muted); }
.filters { display: none; }
html.js .filters { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.6rem 1rem; margin-bottom: 0.7rem; }
.filter-chips { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.filter-chip {
  font: inherit; font-size: 0.86rem; padding: 0.3rem 0.7rem; min-height: 34px;
  border: 1px solid var(--border-soft); border-radius: 999px;
  background: transparent; color: var(--fg); cursor: pointer; white-space: nowrap;
}
.filter-chip span { margin-left: 0.25rem; color: var(--muted); font-variant-numeric: tabular-nums; }
.filter-chip:hover { background: var(--surface-hover); }
.filter-chip[aria-pressed="true"] { background: var(--fg); border-color: var(--fg); color: rgb(28, 28, 27); font-weight: 600; }
.filter-chip[aria-pressed="true"] span { color: rgb(70, 70, 66); }
.filter-tag {
  display: inline-flex; align-items: center; gap: 0.15rem; font-size: 0.86rem; min-height: 34px;
  padding: 0 0.2rem 0 0.75rem; border: 1px solid var(--fg); border-radius: 999px; font-weight: 600;
}
.filter-tag[hidden] { display: none; }
.filter-tag button {
  font: inherit; font-size: 1.05rem; line-height: 1; width: 28px; height: 28px; border: 0; border-radius: 999px;
  background: transparent; color: var(--muted); cursor: pointer;
}
.filter-tag button:hover { background: var(--surface-hover); color: var(--fg); }

.table-wrap { border: 1px solid var(--border-soft); border-radius: 12px; background: var(--surface); overflow: hidden; }
.checks-table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
.checks-table th {
  text-align: left; padding: 0.6rem 1rem;
  font: 0.68rem var(--mono); letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted);
  border-bottom: 1px solid var(--border-soft);
}
.checks-table td { padding: 0.65rem 1rem; vertical-align: top; border-top: 1px solid var(--border-soft); }
.checks-table tbody tr:first-child td { border-top: none; }
.checks-table tbody tr { position: relative; }
.checks-table tbody tr:hover { background: var(--surface-hover); }
.checks-table td:first-child, .checks-table th:first-child { width: 7.6rem; }
.col-cat { width: 6rem; white-space: nowrap; color: var(--muted); }
.col-std { width: 11rem; font: 0.8rem var(--mono); color: var(--muted); }
.row-link { color: var(--fg); font-weight: 600; text-decoration: none; }
.row-link::after { content: ""; position: absolute; inset: 0; }
.row-link:hover { color: var(--fg); }
.row-sub { display: block; margin-top: 0.1rem; color: var(--muted); font-size: 0.82rem; }
.no-match { margin: 0.8rem 0 0; color: var(--muted); }

/* ── Background reading (shown only when the script is not running) ──── */
html.js .reference { display: none; }
.reference details { border: 1px solid var(--border-soft); border-radius: 10px; background: var(--surface); margin-bottom: 0.4rem; }
.reference summary { cursor: pointer; padding: 0.6rem 1rem; font-weight: 600; }
.about-body { padding: 0 1rem 0.6rem; }
.about-body p { margin: 0 0 0.7rem; line-height: 1.6; font-size: 0.92rem; }
.about-inline { padding: 0; }

/* ── Check detail drawer ─────────────────────────────────────────────── */
.drawer { display: none; position: fixed; inset: 0; z-index: 20; }
html:not(.js) .drawer:target, .drawer.open { display: flex; }
.drawer-backdrop { flex: 1 1 auto; background: rgba(10, 10, 10, 0.55); cursor: default; }
.drawer-panel {
  flex: 0 0 auto; width: min(720px, 100%); height: 100%; overflow-y: auto;
  padding: 1.1rem 1.6rem 2.5rem;
  background: rgb(38, 38, 37); border-left: 1px solid var(--border);
  box-shadow: -12px 0 32px rgba(0, 0, 0, 0.35);
  overscroll-behavior: contain;
}
.drawer-panel:focus { outline: none; }
.drawer-bar { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.9rem; }
.drawer-meta { font: 0.78rem var(--mono); color: var(--muted); min-width: 0; overflow-wrap: anywhere; }
.drawer-pos { margin-left: auto; font: 0.78rem var(--mono); color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
.icon-btn {
  flex: none; display: flex; align-items: center; justify-content: center;
  width: 40px; height: 40px; border: 1px solid var(--border); border-radius: 8px;
  color: var(--fg); text-decoration: none;
}
a.icon-btn:hover { background: var(--surface-hover); color: var(--fg); }
.icon-btn.is-disabled { opacity: 0.35; cursor: default; }
.icon { width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.icon-defs { position: absolute; }
.drawer-title { margin: 0 0 0.3rem; font-size: 1.45rem; line-height: 1.25; }
.drawer-label { margin: 0 0 1.3rem; color: var(--muted); font-size: 0.88rem; }
.drawer-panel section { margin-bottom: 1.3rem; }
.drawer-panel h3 {
  margin: 0 0 0.45rem;
  font: 600 0.68rem var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted);
}
.drawer-panel section > p { margin: 0; }
.kv { margin: 0 0 0.5rem; border: 1px solid var(--border-soft); border-radius: 10px; background: var(--surface); overflow: hidden; }
.kv div { display: grid; grid-template-columns: minmax(8rem, 38%) 1fr; gap: 0.8rem; padding: 0.45rem 0.8rem; }
.kv div + div { border-top: 1px solid var(--border-soft); }
.kv dt { color: var(--muted); font-size: 0.88rem; }
.kv dd { margin: 0; font: 0.84rem/1.5 var(--mono); overflow-wrap: anywhere; }
.ev-cap { margin: 0.7rem 0 0.3rem !important; color: var(--muted); font-size: 0.88rem; }
.ev-code, .ev-list {
  margin: 0 0 0.5rem; padding: 0.6rem 0.8rem;
  border: 1px solid var(--border-soft); border-radius: 10px; background: var(--surface);
  font: 0.82rem/1.55 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere;
}
.ev-list { list-style: none; }
.ev-note { color: var(--muted); font-size: 0.9rem; }
.related { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border-soft); border-radius: 10px; background: var(--surface); overflow: hidden; }
.related li + li { border-top: 1px solid var(--border-soft); }
.related a { display: flex; align-items: baseline; gap: 0.7rem; padding: 0.5rem 0.8rem; color: var(--fg); text-decoration: none; font-size: 0.92rem; }
.related a:hover { background: var(--surface-hover); }
.more { margin: 0 0 0.8rem; }

/* ── Footer ──────────────────────────────────────────────────────────── */
.report-footer { padding-top: 1.4rem; border-top: 1px solid var(--border-soft); font-size: 0.88rem; color: var(--muted); scroll-margin-top: 1rem; }
.report-footer .block-head h2 { color: var(--fg); }
.facts { max-width: 46rem; }
.facts dd { color: var(--fg); }
.footer-actions { margin: 1.1rem 0 0.6rem; display: flex; flex-wrap: wrap; gap: 0.4rem 1.2rem; }
.phone-tools { display: none; margin: 1.4rem 0 0.4rem; padding-top: 1rem; border-top: 1px solid var(--border-soft); }
.phone-tools-title {
  margin: 0 0 0.6rem;
  font: 0.68rem var(--mono); letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted);
}
.phone-tools-links { display: flex; flex-wrap: wrap; gap: 0.2rem 1.2rem; }
.phone-tools-links a { display: inline-flex; align-items: center; min-height: 44px; text-decoration: none; }
.footer-actions a { text-decoration: none; }
.footer-info { display: flex; flex-wrap: wrap; gap: 0.3rem 1.2rem; }
.footer-info a { color: var(--muted); }
.timings { margin-top: 0.7rem; font: 0.78rem var(--mono); }
.timings span { margin-right: 0.6rem; }

/* ── Narrow screens ──────────────────────────────────────────────────── */
@media (max-width: 900px) {
  .shell { display: block; }
  .side-nav {
    position: static; max-height: none; flex-direction: row; overflow-x: auto; white-space: nowrap;
    padding: 0.5rem 0.7rem; border-bottom: 1px solid var(--border-soft);
  }
  .nav-group { display: none; }
  .nav-link { flex: 0 0 auto; min-height: 44px; gap: 0.4rem; }
  .nav-link.nav-ext { display: none; }
  .phone-tools { display: block; }
  .report { max-width: none; padding: 1.2rem 1rem 3rem; }
  .top-actions { margin-left: 0; width: 100%; flex-wrap: wrap; }
  .inline-audit-form { flex: 1 1 260px; min-width: 0; }
  .inline-audit-form input[type="text"] { flex: 1 1 6rem; width: 6rem; }
  .headline { font-size: 1.45rem; }
  .panels { grid-template-columns: minmax(0, 1fr); }
  .cat-cards { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
  .panel-ring { justify-content: center; }
  .col-cat, .col-std { display: none; }
  .checks-table td:first-child, .checks-table th:first-child { width: 6.4rem; }
  .checks-table td, .checks-table th { padding-left: 0.7rem; padding-right: 0.7rem; }
  .drawer-panel { padding: 0.9rem 1rem 2rem; }
  .drawer-bar { flex-wrap: wrap; }
  .drawer-meta { order: 9; flex: 0 0 100%; }
  .drawer-title { font-size: 1.25rem; }
  .kv div { grid-template-columns: minmax(0, 1fr); gap: 0.1rem; }
  .icon-btn { width: 44px; height: 44px; }
}

/* ── Print: everything, flat ─────────────────────────────────────────── */
@media print {
  :root {
    --bg: white; --surface: white; --surface-2: #eee; --surface-hover: white;
    --fg: #1a1a1a; --muted: #4a4a47; --border: #999; --border-soft: #c0c0bc; --accent: #1d4ed8;
  }
  body { background: white; }
  .side-nav, .top-actions, .filters, .footer-actions, .phone-tools, .drawer-backdrop, .icon-btn, .drawer-pos, .more { display: none !important; }
  .shell { display: block; }
  .report { max-width: none; padding: 0; }
  .checks-table tr[hidden] { display: table-row !important; }
  .drawer { display: block; position: static; }
  .drawer-panel { width: auto; height: auto; overflow: visible; border: none; box-shadow: none; background: white; padding: 1rem 0; border-top: 1px solid #999; break-inside: avoid; }
  html.js .reference { display: block; }
  .reference details > * { display: revert !important; }
  .sev-badge { border: 1px solid #999; background: white !important; color: #1a1a1a !important; }
  a { color: inherit; text-decoration: none; }
}
@media (prefers-reduced-motion: no-preference) {
  .drawer.open .drawer-panel { animation: drawer-in 0.16s ease-out; }
  @keyframes drawer-in { from { transform: translateX(24px); opacity: 0; } }
}
</style>
</head>
"""
