#!/usr/bin/env python3
"""End-of-life data and detection tests.

The EOL data files carry DATES and the audit compares them with today's
date. These tests pin that behaviour with a fixed "today" so they do not
depend on when they are run:

  - the three data files are well-formed (schema v2)
  - a release flips to end-of-life on its date, not before
  - distro-backported software is not flagged by upstream's date
  - a distro named without a version is resolved from the package version
  - CentOS Stream is not mistaken for CentOS Linux

One test IS date-dependent on purpose: the staleness check fails when the
data files are more than a year old, as a reminder to run
tools/update_eol_data.py. Already-listed releases keep expiring on schedule
without a refresh; what goes missing is releases published since.

Run:  python3 tests/test_eol_data.py
Exits non-zero on failure.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vendor_audit import audit_checks as ac  # noqa: E402

T = "2026-11-18"          # fixed "today" for every dated assertion below
MAX_DATA_AGE_DAYS = 365

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append("  FAIL " + msg)


def tech(server="", xpb="", banner="", today=T, **extra):
    sh = {"server": server, "x_powered_by": xpb}
    sh.update(extra)
    r = ac.check_tech_eol(sh, {"banner": banner}, today=today)
    return {t["tech"]: t for t in r["techs"]}


def os_(server="", xpb="", banner="", today=T):
    r = ac.check_os_eol(server, None, x_powered_by=xpb, error_banner=banner, today=today)
    return {f["os"]: f for f in r["os_findings"]}


def lib(name, version, today=T):
    return ac._annotate_library_eol(name, version, today=today)["eol_status"]


def test_schema():
    date_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for fname, data in (("library_eol.json", ac.LIBRARY_EOL),
                        ("tech_eol.json", ac.TECH_EOL),
                        ("os_eol.json", ac.OS_EOL)):
        check(bool(data), f"{fname} did not load")
        check(data.get("_schema_version") == 2, f"{fname}: _schema_version is not 2")
        check(bool(date_re.match(str(data.get("_generated_on")))), f"{fname}: bad _generated_on")
        for key, entry in data.items():
            if key.startswith("_"):
                continue
            check(isinstance(entry, dict), f"{fname}:{key} is not an object")
            check(bool(entry.get("source")), f"{fname}:{key} has no source to cite")
            check(any(k in entry for k in ("releases", "retired", "min_supported")),
                  f"{fname}:{key} has nothing to judge with")
            if "endoflife" in entry:
                check(bool(entry.get("releases")), f"{fname}:{key} has an endoflife block but no releases")
            for cycle, row in (entry.get("releases") or {}).items():
                eol = row.get("eol")
                check(eol is None or eol is True or (isinstance(eol, str) and bool(date_re.match(eol))),
                      f"{fname}:{key}:{cycle} eol={eol!r} is not a date, true or null")
            retired = entry.get("retired")
            check(retired is None or retired is True
                  or (isinstance(retired, str) and bool(date_re.match(retired))),
                  f"{fname}:{key} retired={retired!r} is not a date or true")


def test_staleness():
    for fname, data in (("library_eol.json", ac.LIBRARY_EOL),
                        ("tech_eol.json", ac.TECH_EOL),
                        ("os_eol.json", ac.OS_EOL)):
        age = ac._eol_data_age_days(data)
        check(age is not None and age <= MAX_DATA_AGE_DAYS,
              f"{fname} is {age} days old — run: python3 tools/update_eol_data.py")


def test_dates_flip_on_schedule():
    php = ac.TECH_EOL["php"]["releases"]
    cycle, date = next((c, r["eol"]) for c, r in php.items()
                       if isinstance(r.get("eol"), str))
    y, m, d = (int(x) for x in date.split("-"))
    day_before = f"{y - 1:04d}-{m:02d}-{d:02d}"
    check(ac._annotate_tech_eol("php", f"{cycle}.1", today=day_before)["eol_status"] == "ok",
          f"php {cycle} flagged a year before its date {date}")
    check(ac._annotate_tech_eol("php", f"{cycle}.1", today=date)["eol_status"] == "eol",
          f"php {cycle} not flagged on its date {date}")
    # Concrete, human-checkable pair.
    check(ac._annotate_tech_eol("php", "8.2.29", today="2026-11-18")["eol_status"] == "ok",
          "php 8.2 should be supported on 2026-11-18")
    check(ac._annotate_tech_eol("php", "8.2.29", today="2027-01-01")["eol_status"] == "eol",
          "php 8.2 should be end of life on 2027-01-01")
    check(os_("Apache/2.4.52 (Ubuntu)")["ubuntu"]["eol_status"] == "ok",
          "Ubuntu 22.04 should be supported on 2026-11-18")
    check(os_("Apache/2.4.52 (Ubuntu)", today="2027-07-01")["ubuntu"]["eol_status"] == "eol",
          "Ubuntu 22.04 should be end of life on 2027-07-01")


def test_server_software():
    t = tech("Apache/2.2.22 (Unix) mod_ssl/2.2.22 OpenSSL/1.0.1e PHP/5.4.16")
    for k in ("apache", "openssl", "php"):
        check(t.get(k, {}).get("eol_status") == "eol", f"{k} in an Apache 2.2 banner should be EOL")
    check(tech("Apache/2.4.58 (Ubuntu)")["apache"]["eol_status"] == "ok", "Apache 2.4 is supported")
    check(tech("nginx/1.12.2")["nginx"]["eol_status"] == "eol", "nginx 1.12 should be EOL")
    check(tech("", xpb="PHP/8.1.34")["php"]["eol_status"] == "eol", "PHP 8.1 should be EOL")
    check(tech("Werkzeug/0.14.1 Python/2.7.5")["python"]["eol_status"] == "eol", "Python 2.7 should be EOL")
    check(tech("cloudflare", banner="Apache Tomcat/7.0.76")["tomcat"]["eol_status"] == "eol",
          "Tomcat 7 on the error page should be EOL")
    check(tech("", x_aspnetmvc_version="3.0")["asp.net-mvc"]["eol_status"] == "eol", "MVC 3 should be EOL")
    check(tech("", x_aspnetmvc_version="5.2")["asp.net-mvc"]["eol_status"] == "ok", "MVC 5 is supported")
    check(tech("", sharepoint_version="15.0.0.4569")["sharepoint"]["version"] == "2013",
          "SharePoint 15.x is SharePoint 2013")
    check("sharepoint" not in tech("", sharepoint_version="16.0.0.26002"),
          "SharePoint Online / Subscription builds must not be judged")


def test_distro_backports_not_flagged():
    # Upstream-EOL versions that a supported distro still patches.
    check("nginx" not in tech("nginx/1.18.0 (Ubuntu)"), "nginx 1.18 (Ubuntu 22.04) must not be flagged")
    check("nginx" not in tech("nginx/1.22.1"), "nginx 1.22 (Debian 12) must not be flagged")
    check("nginx" not in tech("nginx/1.14.1"), "nginx 1.14 (RHEL 8) must not be flagged")
    check("openssl" not in tech("Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k"),
          "OpenSSL 1.1.1 on RHEL 8 must not be flagged")
    check("python" not in tech("Werkzeug/2.0.1 Python/3.6.8"), "Python 3.6 (RHEL 8) must not be flagged")
    check("php" not in tech("Apache/2.4.52 (Ubuntu)", xpb="PHP/8.1.2-1ubuntu2.22"),
          "Ubuntu 22.04's PHP 8.1 package must not be flagged while 22.04 is supported")
    check("openssl" not in tech("Apache/2.4.62 (Unix) OpenSSL/3.0.15"),
          "OpenSSL 3.0 behind a (Unix) Apache build may be the distro's patched library")
    check("tomcat" not in tech("", banner="Apache Tomcat/9.0.87", today="2028-01-01"),
          "Tomcat 9.0 (RHEL 8/9 package) must not be flagged by upstream's date")
    # ...but where no distro can be backporting, upstream's dates apply.
    check(tech("Apache/2.4.57 (Win64) OpenSSL/1.1.1w")["openssl"]["eol_status"] == "eol",
          "OpenSSL 1.1.1 on a Windows build should be EOL")
    check(tech("", xpb="PHP/8.1.34")["php"]["eol_status"] == "eol",
          "upstream PHP 8.1 should be EOL")


def test_os_inference():
    f = os_("Apache/2.4.29 (Ubuntu)")["ubuntu"]
    check(f["version"] == "18.04" and f["eol_status"] == "eol", "Apache 2.4.29 (Ubuntu) is Ubuntu 18.04, EOL")
    f = os_("Apache/2.4.6 (CentOS)")["centos"]
    check(f["version"] == "7" and f["eol_status"] == "eol", "Apache 2.4.6 (CentOS) is CentOS 7, EOL")
    check(os_("Apache/2.4.99 (CentOS)")["centos"]["eol_status"] == "eol",
          "any CentOS Linux is EOL even when the release cannot be resolved")
    f = os_("nginx", xpb="PHP/7.3.31-1~deb10u5")["debian"]
    check(f["version"] == "10" and f["eol_status"] == "eol", "deb10u PHP package is Debian 10, EOL")
    f = os_("nginx", xpb="PHP/7.2.24-0ubuntu0.18.04.17")["ubuntu"]
    check(f["version"] == "18.04", "ubuntu0.18.04 PHP package is Ubuntu 18.04")
    f = os_("cloudflare", banner="Apache/2.2.22 (Ubuntu)")["ubuntu"]
    check(f["version"] == "12.04" and f["eol_status"] == "eol", "error-page banner resolves Ubuntu 12.04")
    # Shared version: flagged only when every candidate release is EOL.
    check(os_("nginx/1.18.0 (Ubuntu)")["ubuntu"]["eol_status"] == "unknown",
          "nginx 1.18.0 (Ubuntu) is 20.04 or 22.04 — not flagged while 22.04 is supported")
    check(os_("nginx/1.18.0 (Ubuntu)", today="2027-07-01")["ubuntu"]["eol_status"] == "eol",
          "nginx 1.18.0 (Ubuntu) is flagged once both 20.04 and 22.04 are EOL")
    check(os_("Microsoft-IIS/8.5")["iis"]["eol_status"] == "eol", "IIS 8.5 (Server 2012 R2) is EOL")
    check(os_("Microsoft-IIS/10.0", today="2031-01-01")["iis"]["eol_status"] == "ok",
          "IIS 10.0 spans four Windows Server releases and must never be flagged")


def test_centos_stream_is_not_centos():
    f = os_("Apache/2.4.62 (CentOS Stream) OpenSSL/3.5.1")
    check("centos" not in f, "(CentOS Stream) must not match the CentOS Linux entry")
    check(f["centos-stream"]["eol_status"] != "eol", "CentOS Stream 9/10 must not be flagged")
    check(os_("Apache/2.4.37 (CentOS Stream)")["centos-stream"]["eol_status"] == "eol",
          "CentOS Stream 8 (Apache 2.4.37) is EOL")


def test_libraries():
    for name, ver, want in (
            ("jquery", "1.12.4", "eol"), ("jquery", "3.7.1", "ok"),
            ("bootstrap", "3.4.1", "eol"), ("bootstrap", "5.3.0", "ok"),
            ("angular", "8.2.14", "eol"), ("angular", "21.0.0", "ok"),
            ("vue", "2.6.14", "eol"), ("vue", "3.4.21", "ok"),
            ("moment", "2.29.4", "eol"), ("crypto-js", "4.2.0", "eol"),
            ("oidc-client", "1.11.5", "eol"), ("mediawiki", "1.35.2", "eol"),
            ("react", "16.8.0", "unknown")):
        got = lib(name, ver)
        check(got == want, f"{name} {ver}: got {got}, want {want}")
    check(lib("angular", "20.1.0", today="2026-11-18") == "ok", "Angular 20 supported on 2026-11-18")
    check(lib("angular", "20.1.0", today="2026-12-01") == "eol", "Angular 20 end of life on 2026-12-01")


def run():
    for fn in (test_schema, test_staleness, test_dates_flip_on_schedule,
               test_server_software, test_distro_backports_not_flagged,
               test_os_inference, test_centos_stream_is_not_centos, test_libraries):
        before = len(_failures)
        fn()
        print(f"  {'ok  ' if len(_failures) == before else 'FAIL'} {fn.__name__}")
    if _failures:
        print("\nEOL DATA / DETECTION FAILURES:\n" + "\n".join(_failures))
        return 1
    print("\nAll EOL checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
