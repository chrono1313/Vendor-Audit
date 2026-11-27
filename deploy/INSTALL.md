# Deploying the Vendor Audit web service

A walkthrough for installing the web service on the Ubuntu 26.04 VM
described in the project handoff. Assumes you already have:

- The VM up (192.168.7.200, on the DMZ VLAN)
- The VM's hardening done (SSH key-only, ufw default-deny, etc.)
- `cloudflared` installed and configured to forward to `http://localhost:8000`
- The Vendor Audit code laid out under `src/vendor_audit/` in this repo,
  with the `audit.py` and `web/` additions already applied

If those aren't done, do them first. This guide picks up from there.

## 1. System prerequisites

The web service needs Python 3.12+ (Ubuntu 26.04 ships 3.13, fine), a venv,
and a few build tools that some Python deps may want when wheels aren't
available for them.

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git
# build tools — these are usually unneeded on amd64 (everything has wheels)
# but cheap to install and saves a debugging session if a transitive dep
# does need to compile
sudo apt install -y build-essential python3-dev
```

## 2. Create the service user

A dedicated, unprivileged system user. No login shell, no home directory
beyond a placeholder so systemd has somewhere to look.

```bash
sudo useradd \
    --system \
    --no-create-home \
    --home-dir /nonexistent \
    --shell /usr/sbin/nologin \
    --comment "Vendor Audit web service" \
    vendor-audit
```

Verify it has no shell access:

```bash
getent passwd vendor-audit
# vendor-audit:x:998:998:Vendor Audit web service:/nonexistent:/usr/sbin/nologin
sudo -u vendor-audit -i 2>&1 || echo "good — no shell"
```

## 3. Install the code

The project lives at `/opt/vendor-audit/`, owned by root, readable by the
service user. The service user can read but cannot write the install tree.

```bash
# Clone the repo into /opt
sudo git clone https://github.com/chrono1313/Vendor-Audit.git /opt/vendor-audit

# (or rsync from your dev machine if you have unmerged changes)
# rsync -av --delete --exclude .venv --exclude __pycache__ \
#     /home/devnull/projects/Vendor-Audit/ /opt/vendor-audit/

# Make root the owner; vendor-audit can read but not write.
sudo chown -R root:root /opt/vendor-audit
sudo find /opt/vendor-audit -type d -exec chmod 0755 {} \;
sudo find /opt/vendor-audit -type f -exec chmod 0644 {} \;
```

## 4. Create the virtualenv and install dependencies

The venv lives inside the install tree so paths are predictable and the
unit file's absolute path to `uvicorn` is stable.

```bash
sudo python3 -m venv /opt/vendor-audit/.venv
# Run pip as root since the tree is root-owned. Use the venv's pip
# directly to avoid accidentally hitting any system pip.
sudo /opt/vendor-audit/.venv/bin/pip install --upgrade pip
sudo /opt/vendor-audit/.venv/bin/pip install -e '/opt/vendor-audit[web]'
```

The `-e` (editable) install means `pip` symlinks the source instead of
copying. Convenient for updates: a `git pull` in `/opt/vendor-audit`
followed by a service restart picks up code changes without reinstalling.

After install, the venv is also root-owned. The service user just needs
read+execute on the binaries:

```bash
sudo chmod -R o+rX /opt/vendor-audit/.venv
```

Verify the install works manually before wiring systemd:

```bash
# Smoke test 1: CLI still works (we didn't break the existing tool)
sudo /opt/vendor-audit/.venv/bin/vendor-audit example.com

# Smoke test 2: web app imports cleanly
sudo /opt/vendor-audit/.venv/bin/python -c \
    "from vendor_audit.web.app import app; print('app:', app.title)"
# expect: app: Vendor Audit
```

## 5. Install the configuration

The runtime config file `web.env` is committed to the repo at
`deploy/web.env`. Symlink it into `/etc/vendor-audit/` so systemd can
read it; this means a `git pull` updates the live config directly with
no copy step.

```bash
sudo install -d -m 0755 /etc/vendor-audit
sudo ln -s /opt/vendor-audit/deploy/web.env /etc/vendor-audit/web.env
```

Edit `/opt/vendor-audit/deploy/web.env` directly if you want to override
defaults (worker count, rate limits, cache sizes). Commit changes to git
so future `git pull`s preserve them. The defaults are fine for a typical
small VM (4-16GB RAM, 4+ cores).

If you have any host-specific values that genuinely shouldn't go in git
(e.g. a unique SECURITY_CONTACT for your fork), drop them into a file
called `/etc/vendor-audit/web.env.local` — systemd reads this *after*
the symlinked file, so values there win. The unit's EnvironmentFile=
declaration includes both paths.

## 6. Install the systemd unit

```bash
sudo install -m 0644 /opt/vendor-audit/deploy/vendor-audit.service \
    /etc/systemd/system/vendor-audit.service

# The service's own journal, which keeps the audit log for 30 days
# (see "The audit log" below), and the tool that reads it.
sudo install -m 0644 /opt/vendor-audit/deploy/journald@vendor-audit.conf /etc/systemd/
sudo install -m 0755 /opt/vendor-audit/deploy/vendor-audit-log /usr/local/bin/

sudo systemctl daemon-reload
```

## 7. Start and verify

```bash
sudo systemctl start vendor-audit
sudo systemctl status vendor-audit --no-pager
```

Expect to see `active (running)` and recent log lines. If it failed,
the journal will tell you why:

```bash
sudo journalctl --namespace=vendor-audit -u vendor-audit --since "5 minutes ago" --no-pager
```

The service logs to its own journal namespace, so `--namespace=vendor-audit`
is needed to see its output; systemd's own start and stop messages stay in
the system journal (`sudo journalctl -u vendor-audit`).

Smoke test the endpoints from the VM itself:

```bash
# Healthz — does not run an audit
curl -sS http://127.0.0.1:8000/healthz
# expect: ok\nversion=1.0\n

# robots.txt: the front page may be indexed, /audit (which runs audits) may not
curl -sS http://127.0.0.1:8000/robots.txt
# expect: User-agent: *\nDisallow: /audit\n

# The form page
curl -sS http://127.0.0.1:8000/ | head -5
# expect: <!doctype html>...
```

Smoke test from your workstation through cloudflared:

```bash
curl -sS https://vendoraudit.org/healthz
# expect: ok\nversion=1.0\n
```

If any of these fail, see the troubleshooting section below.

## 8. Enable on boot

Once you're confident the service runs cleanly, mark it to start at boot:

```bash
sudo systemctl enable vendor-audit
```

## 9. Verify the hardening took effect

```bash
sudo systemd-analyze security vendor-audit
```

Expected: an exposure level of "SAFE" (numerical score ≤ 3.0). You'll see
a long table of every hardening directive and whether each is in effect.
The score should be around 1.5–2.0 with the unit as written.

If the score is higher than expected, look for "✗" rows — those indicate
hardening directives that aren't applied. The most common reasons are
older systemd versions (Ubuntu 26.04 has 259, which has everything) or
typos in the unit file.

## Updating

When you pull new code to the VM:

```bash
cd /opt/vendor-audit
sudo git pull
# The editable install picks up source changes automatically; no reinstall
# needed unless dependencies changed.
sudo systemctl restart vendor-audit
sudo systemctl status vendor-audit --no-pager
```

If you changed `requirements.txt` or `pyproject.toml`:

```bash
sudo /opt/vendor-audit/.venv/bin/pip install -e '/opt/vendor-audit[web]' --upgrade
sudo systemctl restart vendor-audit
```

## The audit log

Each audit a visitor asks for is logged with their IP address and the
domain: a new audit, a cached result, or a download that ran an audit.
The front page says these are kept for 30 days, and the service's journal
namespace enforces it: `/etc/systemd/journald@vendor-audit.conf` deletes
entries older than 30 days (files rotate daily, so within a day of that),
caps the namespace at 1 GB, and keeps it out of `/var/log/syslog`.

```bash
sudo vendor-audit-log                          # the last 24 hours
sudo vendor-audit-log --since "7 days ago"
sudo vendor-audit-log --ip 203.0.113.7         # one visitor, all 30 days
sudo vendor-audit-log --domain example.com     # one domain, all 30 days
sudo vendor-audit-log --top                    # busiest visitors and domains
sudo vendor-audit-log -f                       # follow live
sudo vendor-audit-log --all                    # include re-audits' follow-up cache hits
sudo vendor-audit-log --tz America/Los_Angeles # times in your zone
```

To check the retention is in force:

```bash
systemd-analyze cat-config systemd/journald@vendor-audit.conf | grep -E 'MaxRetentionSec|MaxFileSec|Storage'
sudo journalctl --namespace=vendor-audit --header | grep -E 'Head timestamp|File path' | head
```

## Audit log page (optional)

The same log as a web page, for reading on a phone:
`deploy/vendor-audit-logview`, a small read-only service on
127.0.0.1:8001 that cloudflared publishes at its own hostname (here
`log.vendoraudit.org`). Cloudflare Access signs you in before a request
reaches the VM (a one-time code by email); the service then checks the
token Access attaches to every request, so nothing that bypassed Access
is answered. It runs as a throwaway user whose only extra right is reading
the journal; the web app itself still can't read its own log.

1. In Cloudflare: **Zero Trust → Access controls → Applications → Add an
   application → Self-hosted and private → Public DNS**. Destination
   `log` . `vendoraudit.org`, no path. Policy: Allow, Include → Emails →
   your address. Login method: One-time PIN. Save, then copy the **AUD
   tag** (Additional settings). Your **team domain** is under
   **Zero Trust → Settings** (`yourteam.cloudflareaccess.com`).

2. On the VM, the settings, the unit, and a check:

   ```bash
   sudo install -m 600 /opt/vendor-audit/deploy/logview.env.example /etc/vendor-audit/logview.env
   sudoedit /etc/vendor-audit/logview.env          # ACCESS_TEAM_DOMAIN and ACCESS_AUD
   sudo install -m 644 /opt/vendor-audit/deploy/vendor-audit-logview.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now vendor-audit-logview
   curl -s http://127.0.0.1:8001/healthz                       # expect: ok
   curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8001/   # expect: 403 (no sign-in)
   ```

3. Publish it through the tunnel. In `/etc/cloudflared/config.yml`, add a
   rule above the catch-all `- service: http_status:404`:

   ```yaml
     - hostname: log.vendoraudit.org
       service: http://127.0.0.1:8001
   ```

   ```bash
   sudo cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate
   sudo cloudflared tunnel --config /etc/cloudflared/config.yml ingress rule https://log.vendoraudit.org
   sudo systemctl restart cloudflared
   ```

4. In Cloudflare **DNS → Records**, add a CNAME: name `log`, target
   `<tunnel UUID>.cfargotunnel.com` (the UUID is the name of the
   credentials file in `/etc/cloudflared`), Proxied.

5. Open `https://log.vendoraudit.org` on your phone. Cloudflare asks for
   your email and sends a code; after that the page shows the last 24
   hours, with 7 and 30 days, a busiest-visitors view, and a search box
   for a domain or visitor IP.

Updating: `git reset` on `/opt/vendor-audit` updates the page too; restart
it with `sudo systemctl restart vendor-audit-logview`.

## Troubleshooting

### Service won't start: "PermissionError" or "Cannot allocate memory"

Almost certainly `MemoryDenyWriteExecute=yes`. Some Python C extension
is doing JIT-style work. Comment out that line in
`/etc/systemd/system/vendor-audit.service`, run
`sudo systemctl daemon-reload && sudo systemctl restart vendor-audit`,
and see if the service starts.

If that fixes it, leave the directive disabled and add a comment in the
unit explaining which dependency required it.

### Service starts but `/audit` requests fail with a 500

Most likely a syscall is being filtered that the audit code needs.
Check the kernel log:

```bash
sudo journalctl -k --since "5 minutes ago" | grep -i seccomp
```

You'll see entries like:
```
audit: type=1326 ... syscall=NN comm="python3" ...
```

Look up the syscall number (`ausyscall NN`) and decide whether to add it
to the filter or remove a `~@group` exclusion that's catching it.

### Service starts but rate limiting is wrong (everyone gets 429s, or no one does)

`VENDOR_AUDIT_TRUST_PROXY` is set incorrectly. If `CF-Connecting-IP` is
trusted but missing, slowapi keys everything to `127.0.0.1` (the proxy)
and one client's burst rate-limits the whole site. If it's not trusted
when it should be, every request appears to come from the proxy and
hits the rate limit immediately.

Verify the value matches your deployment:

```bash
grep TRUST_PROXY /etc/vendor-audit/web.env
# Production behind cloudflared:  VENDOR_AUDIT_TRUST_PROXY=1
# Local testing without proxy:    VENDOR_AUDIT_TRUST_PROXY=0
```

### The CLI works but the web service doesn't (or vice versa)

The two share the same `audit_checks.py`, so a check that works in one
should work in the other unless something configuration-related differs.
The most common gotcha: the web layer runs in a `ProcessPoolExecutor`,
so the worker process sees fresh module state — `set_dns_server()` /
`set_http_timeout()` / `set_deep()` are called inside `safe_run_audit()`
in each worker on every request. Confirm those values are coming through
by checking the audit's `_scan` metadata in a result.

### "Address already in use" on port 8000

Something else is bound to port 8000. The likely candidates are:

```bash
sudo ss -tlnp | grep :8000
```

If it's a leftover dev uvicorn from before systemd took over, kill it.
If it's something else, change the port in
`/etc/systemd/system/vendor-audit.service` (and update cloudflared to
match), or change cloudflared to point at a different local port.

## Uninstalling

```bash
sudo systemctl disable --now vendor-audit vendor-audit-logview
sudo rm /etc/systemd/system/vendor-audit.service /etc/systemd/system/vendor-audit-logview.service
sudo rm /etc/systemd/journald@vendor-audit.conf /usr/local/bin/vendor-audit-log
sudo systemctl daemon-reload

sudo rm -rf /etc/vendor-audit
sudo rm -rf /opt/vendor-audit

sudo userdel vendor-audit
sudo groupdel vendor-audit 2>/dev/null || true
```
