#!/usr/bin/env python3
"""Refresh src/vendor_audit/caa_identifiers.json from CCADB.

Vendor Audit never contacts CCADB while auditing. The data file that ships
with the package maps each publicly trusted CA certificate, by its Subject
Key Identifier, to the domain names its CA recognizes in CAA records
(RFC 8659 §4.2). A website certificate's Authority Key Identifier names the
certificate that issued it, so the audit can tell which CAA names that CA
accepts, and whether the domain's CAA records still allow it.

The source is CCADB's "List of CAA Identifiers" report
(https://www.ccadb.org/resources), the database the browser root programs
run:

    https://ccadb.my.salesforce-sites.com/ccadb/AllCAAIdentifiersReportCSVV2

Usage (from the repository root):

    python3 tools/update_caa_data.py                          # download the CSV
    python3 tools/update_caa_data.py --source AllCAAIdentifiersReport.csv
    python3 tools/update_caa_data.py --check                  # show changes, write nothing

If the download is refused, open the address above in a browser, save the
CSV and pass it with --source. A maintainer tool, standard library only.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCAAIdentifiersReportCSVV2"
OUT = Path(__file__).resolve().parent.parent / "src" / "vendor_audit" / "caa_identifiers.json"


def build(text: str) -> dict:
    """{"sets": [[domain, …]], "by_ski": {ski: set index}, "by_name": {issuer name: set index}}."""
    rows = list(csv.DictReader(io.StringIO(text)))
    need = {"Subject Key Identifier (Hex)", "Intermediate Certificate", "Recognized CAA Domains"}
    if not rows or not need <= set(rows[0]):
        raise SystemExit(f"unexpected CSV columns: {list(rows[0]) if rows else 'no rows'}; expected {sorted(need)}")
    by_ski: dict[str, set] = {}
    by_name: dict[str, set] = {}
    for r in rows:
        domains = {d.strip().lower().rstrip(".") for d in r["Recognized CAA Domains"].replace(";", ",").split(",")}
        domains.discard("")
        if not domains:
            continue
        ski = r["Subject Key Identifier (Hex)"].strip().upper()
        if ski:
            by_ski.setdefault(ski, set()).update(domains)
        name = " ".join(r["Intermediate Certificate"].split()).lower()
        if name:
            by_name.setdefault(name, set()).update(domains)
    sets: list[list[str]] = []
    index: dict[tuple, int] = {}

    def ref(domains):
        key = tuple(sorted(domains))
        if key not in index:
            index[key] = len(sets)
            sets.append(list(key))
        return index[key]
    return {"sets": sets,
            "by_ski": {k: ref(v) for k, v in sorted(by_ski.items())},
            "by_name": {k: ref(v) for k, v in sorted(by_name.items())}}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", help="read the CCADB CSV from this file instead of downloading it")
    ap.add_argument("--check", action="store_true", help="show what would change; write nothing")
    args = ap.parse_args(argv)
    if args.source:
        text = Path(args.source).read_text("utf-8-sig")
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "vendor-audit maintainer tool"})
        with urllib.request.urlopen(req, timeout=60) as r:              # noqa: S310 — fixed https URL
            text = r.read().decode("utf-8-sig")

    data = build(text)
    old = json.loads(OUT.read_text("utf-8")) if OUT.exists() else {"by_ski": {}}
    added = sorted(set(data["by_ski"]) - set(old.get("by_ski", {})))
    gone = sorted(set(old.get("by_ski", {})) - set(data["by_ski"]))
    print(f"  {len(data['by_ski'])} CA certificates ({len(added)} new, {len(gone)} no longer listed), "
          f"{len(data['sets'])} distinct sets of CAA names")
    if args.check:
        return 0
    out = {
        "_comment": ("CAA identifiers by CA certificate, from CCADB's List of CAA Identifiers "
                     "(https://www.ccadb.org/resources). Regenerate with tools/update_caa_data.py; do not "
                     "edit by hand. by_ski maps a CA certificate's Subject Key Identifier (hex) to an index "
                     "into 'sets', the domain names that CA recognizes in CAA issue and issuewild records "
                     "(RFC 8659 §4.2); by_name is the fallback by the certificate's name, lowercased."),
        "_source": URL,
        "_generated_on": date.today().isoformat(),
        **data,
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")).replace('],"', '],\n"')
                   .replace(',"by_', ',\n"by_') + "\n", "utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
