"""Audit log tests (3.5.3).

The front page says visitor IP and domain are logged for 30 days. The
service logs to its own journal namespace that deletes entries after 30
days, and deploy/vendor-audit-log reads them back. These tests hold the
pieces together:

  - the unit logs to that namespace, and its journald config keeps 30 days
  - the review tool parses exactly the lines the web app writes
"""
import json
import os
import sys
from datetime import timezone
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader

_HERE = os.path.dirname(__file__)
_DEPLOY = os.path.join(_HERE, "..", "deploy")
sys.path.insert(0, os.path.join(_HERE, "..", "src"))

_failures = []


def check(cond, msg):
    if not cond:
        _failures.append(msg)
        print(f"FAIL: {msg}")


def _tool():
    path = os.path.join(_DEPLOY, "vendor-audit-log")
    loader = SourceFileLoader("vendor_audit_log", path)
    mod = module_from_spec(spec_from_loader("vendor_audit_log", loader))
    loader.exec_module(mod)
    return mod


def _settings(path):
    out = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith(("#", "[")) and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_retention_config():
    unit = _settings(os.path.join(_DEPLOY, "vendor-audit.service"))
    check(unit.get("LogNamespace") == "vendor-audit", "the unit logs to the vendor-audit namespace")
    conf = _settings(os.path.join(_DEPLOY, "journald@vendor-audit.conf"))
    check(conf.get("MaxRetentionSec") == "30day", "entries are deleted after 30 days")
    check(conf.get("MaxFileSec") == "1day", "files rotate daily, so deletion is on time")
    check(conf.get("Storage") == "persistent", "kept across reboots")
    check(conf.get("ForwardToSyslog") == "no", "no copy in /var/log/syslog")
    tool = _tool()
    check(tool.NAMESPACE == unit.get("LogNamespace"), "the tool reads the unit's namespace")
    form = open(os.path.join(_HERE, "..", "src", "vendor_audit", "web", "templates", "form.html")).read()
    check("logged for 30 days" in form, "the front page states the retention the config enforces")


def test_tool_parses_app_lines():
    try:
        from vendor_audit.web import app as appmod
    except ImportError:           # web extras not installed
        return
    tool = _tool()
    prefix = "INFO vendor_audit.web: "
    req = appmod.AUDIT_LOG_REQUEST % ("https://Example.com/", "example.com", "192.0.2.1,2001:db8::1",
                                      "203.0.113.7", "", " deep=1")
    row = tool.parse_message(prefix + req)
    check(row == {"ip": "203.0.113.7", "domain": "example.com", "what": "audit (deep)"}, f"request: {row}")
    req = appmod.AUDIT_LOG_REQUEST % ("x.example", "x.example", "", "2001:db8::7", " via=download", "")
    row = tool.parse_message(prefix + req)
    check(row == {"ip": "2001:db8::7", "domain": "x.example", "what": "download"}, f"download: {row}")
    req = appmod.AUDIT_LOG_REQUEST % ("o'brien.example", "obrien.example", "192.0.2.1", "198.51.100.2",
                                      " fresh=1", "")
    row = tool.parse_message(prefix + req)
    check(row and row["domain"] == "obrien.example" and row["what"] == "audit (fresh)",
          f"an input with a quote: {row}")
    hit = appmod.AUDIT_LOG_CACHE_HIT % ("deep-fallback", "example.com", "203.0.113.7", "")
    row = tool.parse_message(prefix + hit)
    check(row == {"ip": "203.0.113.7", "domain": "example.com", "what": "cached"}, f"cache hit: {row}")
    check(tool.parse_message(prefix + "audit joined a run in progress: domain='example.com'") is None,
          "other lines are skipped")

    entry = json.dumps({"MESSAGE": prefix + hit, "__REALTIME_TIMESTAMP": "1795000000000000"})
    row = tool.parse_entry(entry, timezone.utc)
    check(row and f"{row['time']:%Y-%m-%d %H:%M}" == "2026-11-18 11:06", f"journal time: {row}")
    as_bytes = json.dumps({"MESSAGE": list((prefix + hit).encode()), "__REALTIME_TIMESTAMP": "1"})
    check(tool.parse_entry(as_bytes) is not None, "a message journald stored as bytes")
    check(tool.parse_entry("not json") is None, "junk lines are skipped")


def test_reaudit_follow_up_folded():
    """3.5.8: a re-audit's follow-up cache hit is folded into its line."""
    from datetime import datetime, timedelta
    tool = _tool()
    t0 = datetime(2026, 11, 26, 17, 58, 30, tzinfo=timezone.utc)
    row = lambda s, what, ip="198.100.143.113", domain="vendoraudit.org": {
        "time": t0 + timedelta(seconds=s), "ip": ip, "domain": domain, "what": what}
    f = tool.Folder()
    kept = [f.keep(r) for r in (row(0, "audit (deep, fresh)"), row(2, "cached (deep)"),
                                row(30, "cached (deep)"))]
    check(kept == [True, False, True], f"the follow-up is folded, a later visit is not: {kept}")
    f = tool.Folder()
    kept = [f.keep(r) for r in (row(0, "audit (fresh)"), row(2, "cached", ip="203.0.113.9"),
                                row(3, "cached", domain="other.example"), row(20, "cached"))]
    check(kept == [True, True, True, True], f"other visitors, other domains and late hits stay: {kept}")
    f = tool.Folder()
    check([f.keep(r) for r in (row(0, "audit"), row(1, "cached"))] == [True, True],
          "a regular audit has no follow-up to fold")


def run():
    for fn in (test_retention_config, test_tool_parses_app_lines, test_reaudit_follow_up_folded):
        fn()
    print(f"{len(_failures)} failure(s)")
    return not _failures


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
