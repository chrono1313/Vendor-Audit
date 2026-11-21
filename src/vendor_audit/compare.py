"""vendor_audit.compare — what changed between two scans of a domain.

    vendor-audit example.com --json > before.json
    ... fix things ...
    vendor-audit example.com --json > after.json
    vendor-audit --compare before.json after.json

Both scans are rated with the rules of the version doing the comparison,
not the rules they were saved with, so a difference in the output is a
difference on the site, not a change in Vendor Audit's rubric.

Each check that raised a finding in either scan lands in one group:

  FIXED              an issue before, passing or informational now
  WORSE              passing or informational before, an issue now; or an
                     issue that became more severe
  BETTER             still an issue, but less severe
  NEW FINDING        an issue in a check the first scan didn't have
  NO LONGER REPORTED an issue in a check the second scan doesn't have
                     (an end-of-life finding moves here when the version
                     changes, since the version is part of the check name)
  STILL OPEN         the same issue at the same severity

The output is plain text, one finding per line with its severity words,
so it stays greppable like the .txt report.
"""
from __future__ import annotations

import json
import textwrap

from .audit_checks import ISSUE_SEVERITIES
from .audit_txt_report import SEVERITY_ORDER, WIDTH, _ReportData, passed_pct, severity_summary

_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}     # critical 0 … pass 5
_WORD = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
         "info": "INFO", "pass": "PASS"}

GROUPS = ("fixed", "worse", "better", "new", "gone", "open")
_TITLES = {"fixed": "FIXED", "worse": "WORSE", "better": "BETTER", "new": "NEW FINDING",
           "gone": "NO LONGER REPORTED", "open": "STILL OPEN"}


class CompareError(ValueError):
    """A file that can't be read as a Vendor Audit --json scan."""


def load_scan(path):
    """(original domain, audit domain, results, timestamp) from a --json file.

    The file may start with the banner lines older versions printed to
    stdout before the JSON; everything from the first '{' is decoded, and
    anything after the JSON object is ignored.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as e:
        raise CompareError(f"{path}: {e.strerror or e}") from None
    start = raw.find("{")
    if start < 0:
        raise CompareError(f"{path}: no JSON found (save a scan with --json)")
    try:
        data, _end = json.JSONDecoder().raw_decode(raw[start:])
    except ValueError as e:
        raise CompareError(f"{path}: not valid JSON ({e})") from None
    if not isinstance(data, dict) or "redirect" not in data:
        raise CompareError(f"{path}: not a Vendor Audit scan (save one with --json)")
    results = {k: v for k, v in data.items() if k not in ("findings", "summary", "timestamp", "scan")}
    results["_scan"] = data.get("scan") or {}
    redirect = data.get("redirect") or {}
    original = redirect.get("original") or "?"
    audit = (redirect.get("final") if redirect.get("redirected") else None) or original
    return original, audit, results, data.get("timestamp") or ""


def _rows(scan):
    original, audit, results, ts = scan
    data = _ReportData(original, audit, results, ts, "")
    return data, {r["label"]: r for r in data.finding_rows}


def compare(before, after):
    """The grouped differences between two loaded scans (see load_scan)."""
    b_data, b = _rows(before)
    a_data, a = _rows(after)
    groups = {g: [] for g in GROUPS}
    for label in list(b) + [x for x in a if x not in b]:
        old, new = b.get(label), a.get(label)
        old_sev = old["severity"] if old else None
        new_sev = new["severity"] if new else None
        old_issue = old_sev in ISSUE_SEVERITIES
        new_issue = new_sev in ISSUE_SEVERITIES
        if not old_issue and not new_issue:
            continue
        row = {"label": label, "before": old_sev, "after": new_sev,
               "category": (new or old)["category"],
               "text": (old if old_issue and not new_issue else (new or old))["display"]}
        if old is None:
            group = "new"
        elif new is None:
            group = "gone"
        elif old_issue and not new_issue:
            group = "fixed"
        elif new_issue and not old_issue:
            group = "worse"
        elif _RANK[new_sev] < _RANK[old_sev]:
            group = "worse"
        elif _RANK[new_sev] > _RANK[old_sev]:
            group = "better"
        else:
            group = "open"
        groups[group].append(row)
    for rows in groups.values():
        rows.sort(key=lambda r: (min(_RANK.get(r["before"], 9), _RANK.get(r["after"], 9)), r["label"]))
    return {
        "domain": before[0], "after_domain": after[0],
        "before": {"timestamp": before[3], "version": (before[2].get("_scan") or {}).get("version"),
                   "counts": b_data.counts},
        "after": {"timestamp": after[3], "version": (after[2].get("_scan") or {}).get("version"),
                  "counts": a_data.counts},
        "groups": groups,
    }


def _move(row):
    if row["before"] is None:
        return f"{'':8}  →  {_WORD[row['after']]:<8}"
    if row["after"] is None:
        return f"{_WORD[row['before']]:<8}  →  {'':8}"
    if row["before"] == row["after"]:
        return f"{_WORD[row['after']]:<8}"
    return f"{_WORD[row['before']]:<8}  →  {_WORD[row['after']]:<8}"


def _when(ts):
    """'2026-11-21T01:48:52Z' → '2026-11-21 01:48 UTC'."""
    if len(ts or "") >= 16 and ts[10] == "T":
        return f"{ts[:10]} {ts[11:16]} UTC"
    return ts or "?"


def render_compare(result, version=""):
    """Plain-text report of compare()'s result."""
    def line_for(side):
        s = result[side]
        pct = passed_pct(s["counts"])
        ver = f" · v{s['version']}" if s.get("version") else ""
        return (f"  {side.title():<7} {_when(s['timestamp']):<21} {severity_summary(s['counts'])}"
                + (f" · {pct}% passed" if pct is not None else "") + ver)

    out = [f"Vendor Audit comparison — {result['domain']}", "",
           line_for("before"), line_for("after"), ""]
    b_ts, a_ts = result["before"]["timestamp"], result["after"]["timestamp"]
    if b_ts and a_ts and b_ts > a_ts:
        out += ["  Note: the BEFORE scan is the newer one. Swap the files to see changes",
                "  in time order.", ""]
    if result["after_domain"] != result["domain"]:
        out += [f"  Note: the two scans are of different domains ({result['domain']} and "
                f"{result['after_domain']}).", ""]
    rated = f"v{version}" if version else "this version"
    out += [f"  Both scans are rated with the rules of {rated}, so differences below are",
            "  changes on the site, not changes in the rules.", ""]

    any_rows = False
    for g in GROUPS:
        rows = result["groups"][g]
        if not rows:
            continue
        any_rows = True
        out.append(f"  {_TITLES[g]} ({len(rows)})")
        lead = f"    {'':<22}  {'':<8} "
        for r in rows:
            first = f"    {_move(r):<22}  {r['category']:<8} "
            out.extend(textwrap.wrap(r["text"], width=WIDTH, initial_indent=first,
                                     subsequent_indent=lead, break_on_hyphens=False) or [first])
        out.append("")
    if not any_rows:
        out += ["  No findings in either scan.", ""]
    return "\n".join(out)
