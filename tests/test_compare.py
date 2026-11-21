#!/usr/bin/env python3
"""--compare: what changed between two saved scans.

  - files saved with --json load, with or without the banner lines older
    versions printed before the JSON
  - each check lands in the right group: fixed, worse, better, new, no
    longer reported, still open
  - the output is plain text with severity words, and notes a reversed
    order
  - files that aren't scans are refused with a clear message

Run:  python3 tests/test_compare.py
"""
import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from vendor_audit import compare as cmp                # noqa: E402
from test_findings import sample                       # noqa: E402

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def _save(results, ts, banner=False):
    d = {k: v for k, v in results.items() if not k.startswith("_")}
    d.setdefault("redirect", {"redirected": False, "original": "example.com", "final": "example.com"})
    body = json.dumps({"timestamp": ts, **d, "scan": {"version": "3.2.0", "deep": True}})
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        if banner:
            fh.write("vendor_audit.py  v3.2.0   [--deep]\nFree software\nhttps://example\n\n")
        fh.write(body + "\n")
    return path


def _pair():
    before = sample()
    after = copy.deepcopy(before)
    after["dmarc"] = {"present": True, "policy": "quarantine", "pct": 100, "rua": ["mailto:d@example.com"]}
    after["cors"] = {"outcome": "weak_reflective", "details": {}}
    after["versioned_libs"]["libraries"][0]["version"] = "1.12.4"
    return before, after


def _groups(result):
    return {g: {r["label"] for r in rows} for g, rows in result["groups"].items()}


def test_groups():
    before, after = _pair()
    paths = [_save(before, "2026-11-01T10:00:00Z", banner=True), _save(after, "2026-11-20T10:00:00Z")]
    try:
        res = cmp.compare(*(cmp.load_scan(p) for p in paths))
    finally:
        for p in paths:
            os.unlink(p)
    g = _groups(res)
    check("DMARC policy" in g["better"], f"DMARC none → quarantine should be better: {g}")
    check("CORS configuration" in g["worse"], f"CORS pass → reflective should be worse: {g}")
    check("EOL library: jquery 1.9.1" in g["gone"], "the old jQuery version should be no longer reported")
    check("EOL library: jquery 1.12.4" in g["new"], "the new jQuery version should be a new finding")
    check("CAA records" in g["open"], "an unchanged issue should be still open")
    check(not g["fixed"], f"nothing was fixed: {g['fixed']}")
    every = set().union(*g.values())
    check("TLS connection" not in every, "checks passing in both scans are left out")

    text = cmp.render_compare(res, "3.3.0")
    check("Vendor Audit comparison — example.com" in text, "title should name the domain")
    check("2026-11-01 10:00 UTC" in text, "times should be readable")
    check("PASS      →  HIGH" in text, f"a worse line should show the move in words:\n{text}")
    check("BEFORE scan is the newer one" not in text, "time order is right, so no note")
    check("rules of v3.3.0" in text, "the note should name the rating version")


def test_fixed_and_reversed():
    before, after = _pair()
    fixed = copy.deepcopy(before)
    fixed["cors"] = {"outcome": "weak_reflective", "details": {}}
    paths = [_save(fixed, "2026-11-20T10:00:00Z"), _save(before, "2026-11-01T10:00:00Z")]
    try:
        res = cmp.compare(*(cmp.load_scan(p) for p in paths))
    finally:
        for p in paths:
            os.unlink(p)
    check("CORS configuration" in _groups(res)["fixed"], "reflective → no CORS should be fixed")
    check("BEFORE scan is the newer one" in cmp.render_compare(res), "a reversed order should be noted")


def test_bad_files():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    for content, word in (("", "no JSON"), ("{not json", "not valid JSON"), ('{"a": 1}', "not a Vendor Audit scan")):
        with open(path, "w") as fh:
            fh.write(content)
        try:
            cmp.load_scan(path)
            check(False, f"{content!r} should be refused")
        except cmp.CompareError as e:
            check(word in str(e), f"{content!r}: message should say {word!r}, got {e}")
    os.unlink(path)
    try:
        cmp.load_scan(path)
        check(False, "a missing file should be refused")
    except cmp.CompareError:
        pass


def test_command():
    """vendor-audit --compare runs no audit and exits 0 (1 on a bad file)."""
    import subprocess
    before, after = _pair()
    paths = [_save(before, "2026-11-01T10:00:00Z"), _save(after, "2026-11-20T10:00:00Z")]
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    try:
        ok = subprocess.run([sys.executable, "-m", "vendor_audit", "--compare", *paths],
                            capture_output=True, text=True, env=env, timeout=60)
        bad = subprocess.run([sys.executable, "-m", "vendor_audit", "--compare", paths[0], "/no/such.json"],
                             capture_output=True, text=True, env=env, timeout=60)
    finally:
        for p in paths:
            os.unlink(p)
    check(ok.returncode == 0 and "WORSE (1)" in ok.stdout, f"--compare failed: {ok.returncode} {ok.stderr[-300:]}")
    check(bad.returncode == 1 and "--compare:" in bad.stderr, f"a missing file should exit 1: {bad.returncode}")


def run():
    for fn in (test_groups, test_fixed_and_reversed, test_bad_files, test_command):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nCOMPARE FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll compare checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
