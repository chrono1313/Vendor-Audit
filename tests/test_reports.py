#!/usr/bin/env python3
"""Report tests — one source for the .txt and terminal reports.

Since 3.0 each check is worded once, in the .txt report's detail
sections, and the terminal report prints those same lines. These tests
hold that in place:

  - no line-kind tag ever reaches the .txt file or the terminal
  - every status line that names a check names one that exists in
    rubric.json
  - a status line's word follows the check's finding: a flagged line shows
    the finding's severity, a passing detail shows PASS, an unrated
    observation shows NOTE
  - redirect-target email lines resolve to the redirect-target findings
  - the terminal report shows every status line of the .txt detail, and
    none of the What / Why / Fix paragraphs

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
        txt = atr._render_text(_data(d, audit=aud))
        check("\x1e" not in txt and "\x1f" not in txt, f"{name}: a line-kind tag reached the .txt")
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


def run():
    for fn in (test_no_tags_leak, test_check_labels_exist, test_words_follow_findings,
               test_redirect_target_lines, test_redirect_target_mta_sts, test_eol_heading,
               test_terminal_shows_txt_lines):
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
