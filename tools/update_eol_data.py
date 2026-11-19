#!/usr/bin/env python3
"""Refresh the end-of-life data files from endoflife.date.

Vendor Audit never contacts endoflife.date while auditing. The three data
files that ship with the package

    src/vendor_audit/library_eol.json   client-side libraries and CMSes
    src/vendor_audit/tech_eol.json      server software disclosed in headers
    src/vendor_audit/os_eol.json        operating systems

carry end-of-life DATES, and the audit compares those dates with today's
date. A release whose EOL date is still in the future flips to "end of life"
on its own when that date passes, so the files only need refreshing to learn
about NEW releases and about dates that upstream has moved.

This script does that refresh. For every entry that has an "endoflife"
block it downloads the product page source from the endoflife.date GitHub
repository and rewrites that entry's "releases" map. Entries without an
"endoflife" block are curated by hand and are left exactly as they are.

Usage (from the repository root):

    python3 tools/update_eol_data.py              # fetch from GitHub
    python3 tools/update_eol_data.py --check      # show changes, write nothing
    python3 tools/update_eol_data.py --source ~/src/endoflife.date/products

Requires PyYAML (apt install python3-yaml / pip install pyyaml). It is a
maintainer tool, not a runtime dependency.

The "endoflife" block
---------------------
    "endoflife": {
        "product":     "nginx",        # endoflife.date product slug
        "field":       "eol",          # optional; date field to use (default "eol")
        "granularity": "major",        # optional; collapse cycles to their major
        "cycle_map":   {"7.5": "2008-r2-sp1"}   # optional; our key -> their cycle
    }

"granularity": "major" is for libraries where we only ever judge the major
version (Vue 3.4 is not treated as end of life just because 3.5 exists). A
major is end of life on the LATEST date among its cycles, and is supported
if any of its cycles is still supported.

"cycle_map" is for products we detect under a different numbering than the
one endoflife.date uses (an IIS version maps to a Windows Server release).
Only the mapped keys are written.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import urllib.request

RAW_URL = ("https://raw.githubusercontent.com/endoflife-date/endoflife.date/"
           "master/products/{slug}.md")

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "src", "vendor_audit")
DATA_FILES = ["library_eol.json", "tech_eol.json", "os_eol.json"]

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*$")


def _load_product(slug: str, source_dir: str | None) -> dict:
    """Return the parsed YAML front matter of one endoflife.date product."""
    import yaml  # imported here so --help works without PyYAML

    if not _SLUG_RE.match(slug):
        raise ValueError(f"refusing odd product slug {slug!r}")
    if source_dir:
        with open(os.path.join(source_dir, f"{slug}.md"), encoding="utf-8") as fh:
            text = fh.read()
    else:
        req = urllib.request.Request(RAW_URL.format(slug=slug),
                                     headers={"User-Agent": "vendor-audit-eol-update"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8")
    if not text.startswith("---"):
        raise ValueError(f"{slug}: no YAML front matter")
    front = text[3:].split("\n---", 1)[0]
    data = yaml.safe_load(front)
    if not isinstance(data, dict) or not isinstance(data.get("releases"), list):
        raise ValueError(f"{slug}: unexpected front matter shape")
    return data


def _norm_date(value):
    """endoflife.date uses a date, true (EOL, date unknown) or false (not EOL).

    Returns an ISO date string, True, or None (not end of life).
    """
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.isoformat()[:10]
    if value is True:
        return True
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return value
    return None


def _later(a, b):
    """The later of two normalised EOL values. None (supported) beats
    everything; True (EOL, date unknown) loses to any real date."""
    if a is None or b is None:
        return None
    if a is True:
        return b
    if b is True:
        return a
    return max(a, b)


def _build_releases(product: dict, cfg: dict) -> dict:
    field = cfg.get("field", "eol")
    rows = {}
    for rel in product["releases"]:
        cycle = str(rel.get("releaseCycle", "")).strip()
        if not cycle:
            continue
        row = {"eol": _norm_date(rel.get(field))}
        latest = rel.get("latest")
        if latest:
            row["latest"] = str(latest)
        # Paid / extended support end date, where upstream tracks one. It
        # never changes the verdict; the report mentions it for fairness.
        ext = _norm_date(rel.get("eoes"))
        if isinstance(ext, str) and field != "eoes":
            row["extended"] = ext
        rows[cycle] = row

    cycle_map = cfg.get("cycle_map")
    if cycle_map:
        out = {}
        for ours, theirs in cycle_map.items():
            if theirs not in rows:
                raise ValueError(f"{cfg['product']}: cycle {theirs!r} not found upstream")
            out[ours] = rows[theirs]
        return out

    if cfg.get("granularity") == "major":
        out = {}
        for cycle, row in rows.items():
            m = re.match(r"^\d+", cycle)
            if not m:
                continue
            major = m.group(0)
            if major not in out:
                out[major] = {"eol": row["eol"]}
                if row.get("latest"):
                    out[major]["latest"] = row["latest"]
            else:
                out[major]["eol"] = _later(out[major]["eol"], row["eol"])
        return out

    return rows


def _sort_key(cycle: str):
    nums = [int(n) for n in re.findall(r"\d+", cycle)]
    return (nums, cycle)


def refresh_file(path: str, source_dir: str | None, check: bool) -> tuple[int, int]:
    """Refresh one data file. Returns (entries refreshed, entries changed)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    refreshed = changed = 0
    for key, entry in data.items():
        if key.startswith("_") or not isinstance(entry, dict):
            continue
        cfg = entry.get("endoflife")
        if not cfg:
            continue
        product = _load_product(cfg["product"], source_dir)
        new = _build_releases(product, cfg)
        new = dict(sorted(new.items(), key=lambda kv: _sort_key(kv[0]), reverse=True))
        refreshed += 1
        if new != entry.get("releases"):
            changed += 1
            old = entry.get("releases") or {}
            for cyc in new:
                if cyc not in old:
                    print(f"  {os.path.basename(path)}: {key} {cyc}: new "
                          f"(eol {new[cyc]['eol']})")
                elif old[cyc].get("eol") != new[cyc].get("eol"):
                    print(f"  {os.path.basename(path)}: {key} {cyc}: eol "
                          f"{old[cyc].get('eol')} -> {new[cyc]['eol']}")
            entry["releases"] = new
        entry.setdefault("source", f"https://endoflife.date/{cfg['product']}")
        if not entry.get("name"):
            entry["name"] = str(product.get("title") or key)

    if refreshed and not check:
        data["_generated_on"] = _dt.date.today().isoformat()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    return refreshed, changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", metavar="DIR",
                    help="read product files from a local clone's products/ "
                         "directory instead of fetching from GitHub")
    ap.add_argument("--check", action="store_true",
                    help="report what would change without writing")
    args = ap.parse_args()

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("PyYAML is required: apt install python3-yaml  (or pip install pyyaml)",
              file=sys.stderr)
        return 2

    total = total_changed = 0
    for name in DATA_FILES:
        path = os.path.normpath(os.path.join(DATA_DIR, name))
        n, c = refresh_file(path, args.source, args.check)
        total += n
        total_changed += c
        print(f"{name}: {n} entries refreshed, {c} changed")
    verb = "would change" if args.check else "changed"
    print(f"Done: {total} entries from endoflife.date, {total_changed} {verb}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
