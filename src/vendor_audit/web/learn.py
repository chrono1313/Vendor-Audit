"""Explainer pages: /learn/<topic>.

One page per topic (SPF, DMARC, HSTS, …), built from text the audit
already has, so the pages can't drift from what the audit checks and says:

  - the topic explanation behind the report's "What this means" section
    (audit_txt_report.EXPLANATIONS: what, why, fix, details)
  - every check in that topic, in rubric order (audit_records.topic_for),
    with its what / why / fix (audit_records._CHECK_TEXT), the standard it
    cites (audit_records._STANDARD, linked), and every result it can give
    with its rating and the exact wording the report uses (rubric.json)

Nothing on these pages runs an audit, so they are safe for search engines
to crawl (robots.txt only closes /audit). Pages are built once and kept.

3.5.14 publishes SPF only, as a first look; TOPICS lists what is live.
"""

import re
from functools import lru_cache

from markupsafe import Markup, escape

from .. import audit_checks, audit_records, audit_txt_report

SITE = "https://vendoraudit.org"

# Live topic pages: slug → page text that isn't in the audit's own data.
TOPICS = {
    "spf": {
        "name": "SPF",
        "title": "SPF records: how they work, the 10-lookup limit, and how to fix them",
        "h1": "SPF (Sender Policy Framework)",
        "description": ("How SPF records work, ~all versus -all, the 10 DNS lookup limit, and the four SPF "
                        "checks Vendor Audit runs, each with the RFC behind it and how to fix what fails."),
        "related": ["dmarc", "dkim", "mx"],
    },
}

_SEVERITY_ORDER = ["pass", "critical", "high", "medium", "low", "info"]
_SEVERITY_LABEL = {"pass": "PASS", "critical": "Critical", "high": "High", "medium": "Medium",
                   "low": "Low", "info": "Info"}

# Standards that aren't RFCs, by the name the report cites them under.
_STANDARD_URLS = {
    "M3AAWG": "https://www.m3aawg.org/published-documents",
    "MDN": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Choosing_between_www_and_non-www_URLs",
    "hstspreload.org": "https://hstspreload.org/",
    "IANA name server requirements": "https://www.iana.org/help/nameserver-requirements",
}

_RFC_RE = re.compile(r"RFC (\d{3,5})((?: §[\d.]+)?)")


def standard_html(text):
    """The cited standard, with each RFC (and its first § if given) and
    each known non-RFC standard linked."""
    if not text:
        return Markup("")
    out, pos = [], 0
    for m in _RFC_RE.finditer(text):
        out.append(escape(text[pos:m.start()]))
        section = m.group(2).strip(" §")
        url = f"https://www.rfc-editor.org/rfc/rfc{m.group(1)}.html" + (f"#section-{section}" if section else "")
        out.append(Markup('<a href="{}">{}</a>').format(url, m.group(0)))
        pos = m.end()
    rest = escape(text[pos:])
    for name, url in _STANDARD_URLS.items():
        rest = Markup(str(rest).replace(str(escape(name)), str(Markup('<a href="{}">{}</a>').format(url, name)), 1))
    out.append(rest)
    return Markup("").join(out)


# Record syntax in running text, shown as code. Matched on the escaped text;
# none of these patterns contain characters that escaping changes.
_CODE_RE = re.compile(
    r"(v=spf1(?: -all)?|v=DMARC1; p=reject|(?<![\w-])[-~?+]all\b|\b(?:include|ip4|ip6|a|mx|ptr|exists):"
    r"|\bredirect=|\b0 \.(?=\s|\)|$))")


def codeify(text):
    """Escape text and set SPF/DMARC record syntax in <code>."""
    html = _CODE_RE.sub(lambda m: f"<code>{m.group(0)}</code>", str(escape(text)))
    # A quoted record ("v=spf1 -all") needs no quotes once it is code.
    return Markup(re.sub(r"&#34;(<code>[^<]*</code>)&#34;", r"\1", html))


def _results(label):
    seen = []
    for severity, text in audit_checks.RUBRIC["findings"][label].values():
        if (severity, text) not in seen:
            seen.append((severity, text))
    seen.sort(key=lambda r: _SEVERITY_ORDER.index(r[0]))
    return [{"severity": s, "label": _SEVERITY_LABEL[s], "text": t} for s, t in seen]


def _checks(topic):
    labels = [label for checks in audit_checks.RUBRIC["categories"].values() for label in checks
              if audit_records.topic_for(label) == topic]
    out = []
    for label in labels:
        what, why, fix = audit_records._CHECK_TEXT.get(label, (None, None, None))
        out.append({"name": label, "anchor": audit_records.slug(label),
                    "standard": standard_html(audit_records._STANDARD.get(label)),
                    "what": codeify(what) if what else None, "why": codeify(why) if why else None,
                    "fix": codeify(fix) if fix else None, "results": _results(label)})
    return out


def _details(explanation):
    """The explanation's paragraphs: (heading or None, paragraph)."""
    out = []
    for d in explanation.get("details") or []:
        if isinstance(d, tuple):
            out.append((d[0].rstrip("."), codeify(d[1])))
        else:
            out.append((None, codeify(d)))
    return out


@lru_cache(maxsize=None)
def page(slug):
    """Everything the learn_topic.html template needs, or None."""
    meta = TOPICS.get(slug)
    expl = audit_txt_report.EXPLANATIONS.get(slug)
    if meta is None or expl is None:
        return None
    return {
        "slug": slug,
        "url": f"{SITE}/learn/{slug}",
        "meta": meta,
        "what": codeify(expl["what"]),
        "why": codeify(expl["why"]),
        "fix": [codeify(line) for line in expl["fix"].split("\n")],
        "details": _details(expl),
        "checks": _checks(slug),
        "related": [(s, TOPICS[s]["name"]) for s in meta["related"] if s in TOPICS],
    }
