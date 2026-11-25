#!/usr/bin/env python3
"""Report tests — one source for the text (.md) and terminal reports.

Since 3.0 each check is worded once, in the text report's detail
sections, and the terminal report prints those same lines. Since 3.5
the text report is Markdown: the same line builders write it, and the
terminal keeps the plain form. These tests hold that in place:

  - no line-kind tag ever reaches the .md file or the terminal
  - every status line that names a check names one that exists in
    rubric.json
  - a status line's word follows the check's finding: a flagged line shows
    the finding's severity, a passing detail shows PASS, an unrated
    observation shows NOTE
  - redirect-target email lines resolve to the redirect-target findings
  - the terminal report shows every status line of the detail, and
    none of the What / Why / Fix paragraphs
  - the Markdown report has a line for every status line, one finding
    per line, and renders as Markdown

Run:  python3 tests/test_reports.py
Exits non-zero on failure.
"""
import ast
import contextlib
import copy
import io
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from vendor_audit import audit_checks as ac          # noqa: E402
from vendor_audit import audit_render                # noqa: E402
from vendor_audit import audit_txt_report as atr     # noqa: E402
from test_findings import sample                     # noqa: E402

_failures = []
SRC = os.path.join(os.path.dirname(__file__), "..", "src", "vendor_audit", "audit_txt_report.py")
TS = "2026-11-19T04:55:32Z"


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def _data(d, domain="example.com", audit=None):
    d.setdefault("_scan", {"deep": True, "version": atr.__version__})
    return atr._ReportData(domain, audit or domain, d, TS, atr.__version__)


def _redirected():
    """The sample, redirecting to a second domain whose email is weak."""
    d = sample()
    d["redirect"] = dict(d.get("redirect") or {}, redirected=True, final="app.example.net")
    d["redirect_target_spf"] = {"status": "missing", "record": None, "lookup_count": 0}
    d["redirect_target_dmarc"] = {"present": True, "policy": "none", "pct": 100, "rua": []}
    d["redirect_target_mx"] = {"entries": [{"priority": 10, "host": "mx.example.net"}], "null_mx": False}
    return d


def _terminal(d, domain="example.com", audit=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        audit_render.render(domain, audit or domain, d, None)
    return buf.getvalue()


def test_no_tags_leak():
    for name, d, aud in (("sample", sample(), None), ("redirected", _redirected(), "app.example.net")):
        txt = atr.render_markdown(_data(d, audit=aud))
        check("\x1e" not in txt and "\x1f" not in txt, f"{name}: a line-kind tag reached the .md")
        term = _terminal(copy.deepcopy(d), audit=aud)
        check("\x1e" not in term and "\x1f" not in term, f"{name}: a line-kind tag reached the terminal")


def test_check_labels_exist():
    """Every check= on a status line names a rubric check."""
    known = set(ac.RUBRIC["findings"])
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    seen = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_status"):
            continue
        for kw in node.keywords:
            if kw.arg != "check":
                continue
            seen += 1
            consts = [c.value for c in ast.walk(kw.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
            if any("EOL " in v for v in consts):
                continue                        # built from the finding's own fields
            for c in ast.walk(kw.value):
                if not (isinstance(c, ast.Constant) and isinstance(c.value, str)) or not c.value.strip():
                    continue
                v = c.value
                if v in ("redirect target: ", "IPv6") or "EOL " in v or v in ("?", " ", ""):
                    continue
                if v.startswith(" "):           # af_label + " RPKI"
                    check({"IPv4" + v, "IPv6" + v} <= known, f'line {node.lineno}: no checks "IPv4/IPv6{v}"')
                else:
                    check(v in known, f'line {node.lineno}: check="{v}" is not a rubric check')
    check(seen > 150, f"expected most status lines to name a check, found {seen}")


def test_words_follow_findings():
    """The word on each status line follows the rule in audit_txt_report."""
    for name, d, aud in (("sample", sample(), None), ("redirected", _redirected(), "app.example.net")):
        data = _data(d, audit=aud)
        found = {r["label"]: r["severity"] for r in data.finding_rows}
        seen = []
        real = atr._status_word

        def spy(severity, chk):
            word = real(severity, chk)
            seen.append((severity, chk, word))
            return word
        atr._status_word = spy
        try:
            atr.render_detail_sections(data)
        finally:
            atr._status_word = real
        check(len(seen) > 40, f"{name}: only {len(seen)} status lines rendered")
        for severity, chk, word in seen:
            f = found.get(chk) if chk else None
            if severity == "pass":
                check(word == ("pass" if chk else ""), f"{name}: passing line of {chk!r} shows {word!r}")
            elif severity in ("warn", "fail"):
                want = (f or "note") if chk else "note"
                check(word == want, f"{name}: flagged line of {chk!r} shows {word!r}, finding is {f!r}")


def test_redirect_target_lines():
    d = _redirected()
    data = _data(d, audit="app.example.net")
    labels = {r["label"]: r["severity"] for r in data.finding_rows}
    check(labels.get("redirect target: SPF policy") == "critical",
          f"sample redirect target should have a critical SPF finding, got {labels.get('redirect target: SPF policy')}")
    detail = atr.strip_tags(atr.render_detail_sections(data))
    target = detail[detail.index("app.example.net"):]
    check(re.search(r"^\s+CRITICAL\s+No SPF record", target, re.M) is not None,
          "redirect-target SPF line should read CRITICAL")
    check(re.search(r"^\s+HIGH\s+Policy: none", target, re.M) is not None,
          "redirect-target DMARC p=none line should read HIGH")


def test_redirect_target_mta_sts():
    """The redirect target's MTA-STS is rated, with its own status line."""
    d = _redirected()
    d["redirect_target_mta_sts"] = {"present": True, "id": "1"}
    d["redirect_target_mta_sts_policy"] = {"fetched": False, "failure": "http_error", "error": "HTTP 404"}
    data = _data(d, audit="app.example.net")
    labels = {r["label"]: r["severity"] for r in data.finding_rows}
    want = ac.RUBRIC["findings"]["MTA-STS"]["policy_broken"][0]
    check(labels.get("redirect target: MTA-STS") == want,
          f"redirect-target MTA-STS should be {want}, got {labels.get('redirect target: MTA-STS')}")
    detail = atr.strip_tags(atr.render_detail_sections(data))
    target = detail[detail.index("app.example.net"):]
    check(re.search(r"^\s+MEDIUM\s+MTA-STS record published but the policy can't be fetched", target, re.M),
          "redirect-target MTA-STS line should read MEDIUM")


def test_redirect_target_tls_rpt():
    d = _redirected()
    d["redirect_target_tls_rpt"] = {"present": False, "rua": None, "record": None}
    data = _data(d, audit="app.example.net")
    labels = {r["label"]: r["severity"] for r in data.finding_rows}
    want = ac.RUBRIC["findings"]["TLS-RPT"]["missing"][0]
    check(labels.get("redirect target: TLS-RPT") == want,
          f"redirect-target TLS-RPT should be {want}, got {labels.get('redirect target: TLS-RPT')}")
    detail = atr.strip_tags(atr.render_detail_sections(data))
    target = detail[detail.index("app.example.net"):]
    check(re.search(rf"^\s+{want.upper()}\s+No TLS-RPT", target, re.M),
          "redirect-target TLS-RPT line should carry the finding's word")


def test_eol_heading():
    d = sample()
    d["tech_eol"] = ac.check_tech_eol({"server": "Microsoft-IIS/10.0", "x_aspnet_version": "2.0.50727"})
    txt = atr.strip_tags(atr.render_detail_sections(_data(d)))
    heading = re.compile(r"^\s+End-of-life server software\s*$", re.M)
    check("Server software support" in txt and not heading.search(txt),
          "an undetermined version alone should get the neutral heading")
    d["tech_eol"] = ac.check_tech_eol({"server": "nginx", "x_powered_by": "PHP/7.4.33"})
    txt = atr.strip_tags(atr.render_detail_sections(_data(d)))
    check(heading.search(txt), "an end-of-life version keeps the heading")


def test_terminal_shows_txt_lines():
    d = sample()
    data = _data(copy.deepcopy(d))
    tagged = atr.render_detail_sections(data)
    term = _terminal(copy.deepcopy(d))
    missing = []
    for line in tagged.split("\n"):
        kind, text = atr.split_tag(line)
        if kind.startswith("S:") and text.strip() and text.strip() not in term:
            missing.append(text.strip()[:70])
    check(not missing, f"terminal is missing {len(missing)} status lines, e.g. {missing[:2]}")
    check(not re.search(r"^\s+(What|Why|Fix): ", term, re.M), "terminal should leave out What / Why / Fix")
    check("Summary of example.com" in term, "terminal summary missing")


_WORD_LINE = re.compile(r"^- \*\*(CRITICAL|HIGH|MEDIUM|LOW|INFO|PASS|NOTE)\*\* ")


def test_markdown_report():
    """3.5.0: the text report is Markdown, written by the same line
    builders as the terminal's plain detail."""
    for name, d, aud in (("sample", sample(), None), ("redirected", _redirected(), "app.example.net")):
        data = _data(d, audit=aud)
        plain_before = atr.render_detail_sections(data)
        md = atr.render_markdown(data)
        check(not atr._md(), f"{name}: Markdown mode left on after rendering")
        check(atr.render_detail_sections(data) == plain_before, f"{name}: rendering Markdown changed the plain detail")
        lines = md.split("\n")
        check(lines[0] == "# Vendor Audit — example.com", f"{name}: title line is {lines[0]!r}")
        summary = md[md.index("## Executive summary"):md.index("\n## Email")]
        check("### Passing" not in summary and "**PASS**" not in summary,
              f"{name}: passing checks should not be repeated in the summary")
        for r in data.finding_rows:
            want = f"- **{atr._STATUS_WORDS[r['severity']]}** {r['category']} — {atr._md_inline(r['display'])}"
            if r["severity"] == "pass":
                continue
            check(want in lines, f"{name}: summary line missing: {want}")

        # One Markdown status line for every plain status line that has a word.
        plain_words = sum(1 for ln in plain_before.split("\n")
                          if atr.split_tag(ln)[0].startswith("S:") and atr.split_tag(ln)[0] != "S:none")
        detail = md[md.index("\n## Email"):].split("\n")
        md_words = sum(1 for ln in detail if _WORD_LINE.match(ln))
        check(md_words == plain_words, f"{name}: {md_words} Markdown status lines for {plain_words} plain ones")
        whats = sum(1 for kind, text in map(atr.split_tag, plain_before.split("\n"))
                    if kind == "E" and text.lstrip().startswith("What: "))
        check(md.count("\n**What:** ") == whats, f"{name}: What / Why / Fix paragraphs differ from the plain form")

        in_fence = False
        for ln in lines:
            if ln == "```" or ln.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            check(not (ln.startswith(" ") and not ln.startswith("    - ")),
                  f"{name}: indented line would render as code: {ln[:60]!r}")
            check(not re.match(r"^\s+\S+\s{3,}\S", ln), f"{name}: column-aligned line: {ln[:60]!r}")
        check(not in_fence, f"{name}: a code block is never closed")

        try:
            import markdown
        except ImportError:
            continue
        html = markdown.markdown(md, extensions=["tables", "fenced_code", "sane_lists"])
        check(html.count("<table>") == md.count("\n| --- |"),
              f"{name}: every table renders")
        check(html.count("<pre>") == sum(1 for ln in lines if ln == "```") // 2,
              f"{name}: only fenced blocks render as code")
        check("<img" not in html and "<html" not in html, f"{name}: a tag name in the text became markup")
        check("<strong>What:</strong>" in html, f"{name}: What / Why / Fix render as paragraphs")


def test_spf_lookup_limit_note():
    """3.5.0: the lookup-limit line explains that included records' own
    lookups count, which is how one include: can use several."""
    d = sample()
    d["spf"] = dict(d["spf"], lookup_count=12)
    data = _data(d)
    plain = " ".join(atr.strip_tags(atr.render_detail_sections(data)).split())
    want = "The limit counts the lookups inside included records too"
    check(want in plain, "terminal detail should explain nested lookups")
    md = atr.render_markdown(data)
    check(re.search(r"^- \*\*HIGH\*\* SPF lookup count: 12 .*\n    - " + want, md, re.M),
          "Markdown: the explanation is a note under the HIGH line")
    from vendor_audit import audit_records
    check("included records count too" in audit_records._CHECK_TEXT["SPF lookup count"][0],
          "the page's check text says the same")


def run():
    for fn in (test_no_tags_leak, test_check_labels_exist, test_words_follow_findings,
               test_redirect_target_lines, test_redirect_target_mta_sts,
               test_redirect_target_tls_rpt, test_eol_heading,
               test_terminal_shows_txt_lines, test_markdown_report, test_spf_lookup_limit_note):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nREPORT FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll report checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
