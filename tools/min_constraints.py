#!/usr/bin/env python3
"""Print a pip constraints file that pins every dependency to its floor.

pyproject.toml lists each dependency with a minimum version only
("httpx[http2]>=0.25"), so a normal install gets the newest releases. The
"oldest" CI job installs with these constraints instead, to check that the
minimums the package claims still work:

    python tools/min_constraints.py > constraints.txt
    python -m pip install -c constraints.txt -e '.[web,dev]'

Covers the runtime dependencies and the web and dev extras. A dependency
without a plain ">=" floor is an error, so a new one can't slip past the
job untested. Standard library only (tomllib, Python 3.11+).
"""
import re
import sys
import tomllib
from pathlib import Path

_FLOOR = re.compile(r"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?>=([^,;\s]+)")


def constraints(pyproject):
    project = tomllib.loads(Path(pyproject).read_text(encoding="utf-8"))["project"]
    reqs = list(project["dependencies"])
    for extra in ("web", "dev"):
        reqs += project.get("optional-dependencies", {}).get(extra, [])
    lines, bad = [], []
    for req in reqs:
        m = _FLOOR.fullmatch(req.strip())
        if m:
            lines.append(f"{m[1]}=={m[2]}")
        else:
            bad.append(req)
    return lines, bad


def main():
    root = Path(__file__).resolve().parent.parent
    lines, bad = constraints(root / "pyproject.toml")
    if bad:
        sys.exit("min_constraints: no plain >= floor for: " + ", ".join(bad))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
