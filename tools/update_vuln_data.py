#!/usr/bin/env python3
"""Refresh src/vendor_audit/library_vulns.json from retire.js.

Vendor Audit never contacts retire.js while auditing. The data file that
ships with the package lists known vulnerabilities in client-side
JavaScript libraries: for each library, the script-address patterns that
reveal its version, and for each vulnerability the affected version range,
its severity, its CVE numbers and an advisory link.

It is built from retire.js's repository file (jsrepository-v4.json,
https://github.com/RetireJS/retire.js, Apache License 2.0), keeping only
what the audit uses: the "uri" and "filename" extractors (patterns matched
against a script's address; the audit never downloads scripts) and each
vulnerability's range, severity, identifiers and first link.

Usage (from the repository root):

    python3 tools/update_vuln_data.py            # fetch from GitHub
    python3 tools/update_vuln_data.py --check    # show what would change, write nothing
    python3 tools/update_vuln_data.py --source jsrepository-v4.json

A maintainer tool, not a runtime dependency. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
OUT = Path(__file__).resolve().parent.parent / "src" / "vendor_audit" / "library_vulns.json"
SKIP = {"retire-example", "dont check"}
SUMMARY_MAX = 220


def _summary(ids):
    s = " ".join(str(ids.get("summary") or "").split())
    return s if len(s) <= SUMMARY_MAX else s[:SUMMARY_MAX - 1].rstrip() + "…"


def build(repo: dict) -> dict:
    libs = {}
    for name in sorted(repo, key=str.lower):
        if name in SKIP:
            continue
        entry = repo[name]
        ex = entry.get("extractors") or {}
        vulns = []
        for v in entry.get("vulnerabilities") or []:
            if not v.get("below"):
                continue
            ids = v.get("identifiers") or {}
            vulns.append({k: val for k, val in (
                ("atOrAbove", v.get("atOrAbove")),
                ("below", v["below"]),
                ("severity", (v.get("severity") or "medium").lower()),
                ("cve", ids.get("CVE") or []),
                ("id", ids.get("githubID") or (ids.get("CVE") or [None])[0] or ids.get("issue") or ids.get("bug")),
                ("summary", _summary(ids)),
                ("url", (v.get("info") or [None])[0]),
            ) if val not in (None, "", [])})
        uri, filename = ex.get("uri") or [], ex.get("filename") or []
        if vulns and (uri or filename):
            libs[name] = {"uri": uri, "filename": filename, "vulnerabilities": vulns}
        elif vulns:
            libs[name] = {"uri": [], "filename": [], "vulnerabilities": vulns}
    return libs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", help="read jsrepository-v4.json from this file instead of GitHub")
    ap.add_argument("--check", action="store_true", help="show what would change; write nothing")
    args = ap.parse_args(argv)

    if args.source:
        repo = json.loads(Path(args.source).read_text("utf-8"))
    else:
        with urllib.request.urlopen(URL, timeout=30) as r:          # noqa: S310 — fixed https URL
            repo = json.loads(r.read().decode("utf-8"))

    libs = build(repo)
    # Every pattern must compile the way the audit will use it.
    for name, lib in libs.items():
        for p in lib["uri"] + lib["filename"]:
            re.compile(p.replace("§§version§§", r"[0-9][0-9.a-z_\-]+"))

    old = json.loads(OUT.read_text("utf-8")) if OUT.exists() else {"libraries": {}}
    before = {k: len(v["vulnerabilities"]) for k, v in old.get("libraries", {}).items()}
    after = {k: len(v["vulnerabilities"]) for k, v in libs.items()}
    changes = [f"  {k}: {before.get(k, 0)} → {after.get(k, 0)} vulnerabilities"
               for k in sorted(set(before) | set(after), key=str.lower) if before.get(k) != after.get(k)]
    print("\n".join(changes) or "  no change in vulnerability counts")
    if args.check:
        return 0

    out = {
        "_comment": ("Known vulnerabilities in client-side JavaScript libraries, from retire.js "
                     "(https://github.com/RetireJS/retire.js, Apache License 2.0). Regenerate with "
                     "tools/update_vuln_data.py; do not edit by hand. 'uri' and 'filename' are "
                     "retire.js extractors: patterns matched against a script's address, with "
                     "§§version§§ standing for the version. A vulnerability applies to versions "
                     "from 'atOrAbove' (when present) up to, not including, 'below'."),
        "_source": URL,
        "_generated_on": date.today().isoformat(),
        "libraries": libs,
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", "utf-8")
    print(f"wrote {OUT} ({len(libs)} libraries, {sum(after.values())} vulnerabilities)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
