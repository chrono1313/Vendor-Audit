#!/usr/bin/env python3
"""Example report tests (web/example.py, /learn/example-report).

The example report stores only raw results; everything on the page comes
from the live rubric and renderers. These tests keep the raw results in
step with the checks:

  - every check in rubric.json is rated from the example's results, or is
    in example.NOT_RATED with a reason
  - nothing in NOT_RATED is in fact rated (the list can't go stale either)
  - the mix stays a believable vendor: findings at every level, mostly
    passes, exactly one end-of-life item
  - dates are relative: the report looks the same on any day
  - the page says it is an example, has no re-audit field, and its
    downloads point at the example's own routes

Run:  python3 tests/test_example.py
Exits non-zero on failure. Skips itself if the web extras are missing.
"""
import collections
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from vendor_audit import audit_checks as ac
    from vendor_audit.web import example, render_html
except Exception as _exc:                        # web extras not installed
    example = None
    _SKIP = str(_exc)

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def _skip():
    if example is None:
        try:
            import pytest
            pytest.skip(f"web extras not installed: {_SKIP}")
        except ImportError:
            print(f"       (skipped: {_SKIP})")
        return True
    return False


def _rated(now=None):
    return {f["label"]: f for f in ac.assess_results(example.results(now))}


def test_every_check_covered():
    """A new or renamed check fails here until the example rates it or
    NOT_RATED says why it can't."""
    if _skip():
        return
    rubric = set(ac.RUBRIC["findings"])
    rated = set(_rated())
    missing = sorted(rubric - rated - set(example.NOT_RATED))
    check(not missing, "checks the example report doesn't show: add their data to web/example.py, "
                       f"or list them in NOT_RATED with a reason: {missing}")
    wrongly = sorted(set(example.NOT_RATED) & rated)
    check(not wrongly, f"NOT_RATED lists checks the example does rate; remove them: {wrongly}")
    unknown = sorted(set(example.NOT_RATED) - rubric)
    check(not unknown, f"NOT_RATED names checks that aren't in rubric.json: {unknown}")
    for label, reason in example.NOT_RATED.items():
        check(len(reason) > 15, f"NOT_RATED[{label!r}]: give a reason")


def test_mix_is_believable():
    """Mostly passes, something at every level, one end-of-life item."""
    if _skip():
        return
    f = _rated()
    sev = collections.Counter(x["severity"] for x in f.values())
    for s in ("critical", "high", "medium", "low", "pass"):
        check(sev[s], f"no {s} finding in the example: {dict(sev)}")
    check(sev["pass"] > 2 * sum(sev[s] for s in ("critical", "high", "medium", "low")),
          f"the example should be mostly passes: {dict(sev)}")
    eol = [lb for lb in f if lb.startswith("EOL tech:")]
    check(eol == ["EOL tech: php 7.4.33"], f"one end-of-life item, PHP 7.4: {eol}")


def test_dates_are_relative():
    """Ratings are the same today and two years from now."""
    if _skip():
        return
    now = datetime.now(timezone.utc)
    a = {k: (v["severity"], v.get("outcome")) for k, v in _rated(now).items()}
    b = {k: (v["severity"], v.get("outcome")) for k, v in _rated(now + timedelta(days=730)).items()}
    check(a == b, f"ratings change with the date: {sorted(k for k in a if a.get(k) != b.get(k))}")


def test_page():
    if _skip():
        return
    page = render_html.render_result(example.envelope())
    check("<strong>Example report:</strong>" in page and "fictional" in page, "the page says it is an example")
    check('name="from"' not in page, "no re-audit field: the domain is fictional")
    check(f'href="{example.PATH}.md"' in page and f'href="{example.PATH}.html"' in page,
          "downloads point at the example's own routes")
    check("/audit/sample-vendor.example" not in page, "no link audits the fictional domain")
    check('<link rel="canonical" href="https://vendoraudit.org/learn/example-report">' in page,
          "canonical URL")
    check('<meta name="description"' in page, "meta description")
    saved = render_html.to_standalone(page, "https://vendoraudit.org")
    check("See the current example" in saved and "box at the top" not in saved,
          "the saved copy points back to the live example and doesn't mention the audit box")
    md = example.markdown()
    check(md.startswith("# Vendor Audit — sample-vendor.example\n") and example.MARKDOWN_NOTE in md,
          "the text report carries the example note")


def run():
    for fn in (test_every_check_covered, test_mix_is_believable, test_dates_are_relative, test_page):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nEXAMPLE FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll example checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
