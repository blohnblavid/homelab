# Case Study: Building Out Homeserver Monitoring (Dashboard, Metrics, Dead-Man's-Switch)

## Summary

The homelab had services running but no real answer to two basic questions: "what's my
server's resource usage actually doing right now, historically?" and "if the whole host goes
down, will I find out?" This session filled both gaps — expanded the existing Homepage
dashboard to reflect the full stack, deployed Netdata for host and per-container metrics
(hitting and resolving two real Docker-Desktop-on-Windows networking issues along the way),
and set up an external dead-man's-switch via Healthchecks.io with a push notification to
close the "server dies silently" blind spot.

## Part 1: Homepage dashboard completeness

Homepage (`ghcr.io/gethomepage/homepage`) was already running with a decent base config —
resource widgets, search, weather — but `services.yaml` only listed a subset of the actual
stack. Added the missing pieces:

- **Infrastructure:** Nginx Proxy Manager, Homelable
- **Custom Projects** (new section): Enchantment Checklist, Ave & John PWA
- **Gaming** (new section): Minecraft, Palworld

Existing entries (Jellyfin, qBittorrent, Wazuh, Uptime Kuma, etc.) were left untouched. Result:
one glanceable page that now actually reflects the full running stack, with live widgets
(Uptime Kuma site count/uptime %, qBittorrent stats) alongside static links for services
without a Homepage widget integration.

**Known issue surfaced, not fixed tonight:** the qBittorrent widget authenticates with a
plaintext credential written directly in `services.yaml`. The fix is the same pattern used
everywhere else in this repo: move it into a gitignored `.env` and reference it through
variable substitution (see [`secrets-approach.md`](secrets-approach.md)). Finding the same
credential in a third config file is a good reminder to centralize secrets instead of
patching file by file.

## Part 2: Netdata for host + container metrics

Homepage's resource widget gives a single current-moment CPU/memory number — no history, no
per-container breakdown. Netdata fills that gap: real-time + historical graphs, automatic
per-container resource accounting, and zero required configuration for the basics.

### Attempt 1: Docker socket only — container list without stats

Initial compose file mounted only the Docker socket:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

Result: Netdata's Docker collector connected fine (confirmed in logs: `collector=docker ...
state=running result_status=200`), but no actual per-container CPU/memory numbers appeared —
"Containers & VMs → Docker" in the UI had nothing to show.

**Root cause:** the Docker socket alone tells Netdata *that* containers exist and their
metadata, but not their live resource usage. That data comes from Linux's cgroups accounting,
which requires the host's `/proc` and `/sys` to be mounted into the container — a separate
requirement from socket access.

**Fix:**

```yaml
volumes:
  - /proc:/host/proc:ro
  - /sys:/host/sys:ro
  - /etc/passwd:/host/etc/passwd:ro
  - /etc/group:/host/etc/group:ro
  - /etc/os-release:/host/etc/os-release:ro
```

### Attempt 2: `network_mode: host` — broke external access

Netdata's docs recommend `network_mode: host` so it can see real network interface stats
(rather than the container's own isolated virtual interface). Added it, restarted — and the
dashboard became unreachable at `http://homeserver:19999` and by LAN IP.

**Root cause:** Docker Desktop on Windows runs containers inside a WSL2 VM. `network_mode:
host` on Linux binds a container directly to the *host's* real network stack — but on Windows,
"host" in this context means the WSL2 VM's internal network, not the Windows machine's actual
LAN-facing interface. The container was reachable from inside WSL2, but not from the browser
on the Windows host or anywhere on the LAN.

**Fix:** dropped `network_mode: host`, went back to an explicit port mapping:

```yaml
ports:
  - "19999:19999"
```

This is a real, generalizable limitation, not a one-off: **host networking behaves differently
on Docker Desktop for Windows than on native Linux**, and should be assumed to need an
explicit port-mapping fallback rather than trusted at face value from Linux-oriented
documentation. Container-level cgroups stats still populated correctly with just the
proc/sys/socket mounts — host networking wasn't actually required for the main goal.

### Result

Working dashboard at `http://<homeserver-ip>:19999` showing:
- Host-level CPU (per-core), memory, disk I/O, network — real-time and historical
- Per-container/per-application-group CPU, memory, disk I/O, context switches (Wazuh's Java
  process, individual `*arr` containers, Netdata itself, etc., each broken out separately)
- Built-in anomaly detection and pre-configured health alerts, no manual threshold tuning

One incidental side effect: the CPU chart showed a clear, visible spike corresponding to the
nikto/sqlmap attack traffic run earlier the same session — an unplanned but accurate
confirmation of how much load that traffic put on the host.

## Part 3: External uptime alerting via Healthchecks.io (dead-man's-switch)

Uptime Kuma already monitors individual services, but it runs *on* the homeserver — if the
whole host goes down, the thing meant to alert about it goes down too. This needed something
watching from outside the machine, with zero inbound ports required (consistent with the
stack's existing zero-trust/no-exposed-ports posture).

**Approach:** a dead-man's-switch via Healthchecks.io.
- The homeserver periodically pings an external URL (outbound only, no inbound port needed)
- Healthchecks.io watches for those pings
- If the pings *stop* (because the host is down), Healthchecks.io — not the dead server —
  sends the alert

**Setup:**
- Created a check (`homeserver-alive`) with a 2-minute period / 1-minute grace time — tight
  enough to catch an outage within ~3 minutes, loose enough not to false-alarm on a single slow
  ping.
- Windows Scheduled Task pings the check's unique URL every 2 minutes via a small PowerShell
  script:

```powershell
Invoke-WebRequest -Uri "https://hc-ping.com/<check-uuid>" -UseBasicParsing | Out-Null
```

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -File C:\docker\healthcheck\ping.ps1"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 2) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName "HomeserverHealthcheckPing" -Action $action -Trigger $trigger
```

**Gotcha hit:** `-RepetitionDuration ([TimeSpan]::MaxValue)` (intended to mean "run forever")
failed registration with `The task XML contains a value which is incorrectly formatted or out
of range`. Task Scheduler's underlying XML schema can't represent a truly infinite duration —
`[TimeSpan]::MaxValue` serializes to a duration string outside the valid range. Fixed by using
a long-but-finite duration instead (`New-TimeSpan -Days 3650`, i.e. 10 years) — effectively
indefinite for practical purposes, and well within what the schema accepts.

- Added **ntfy** as the notification channel for an actual phone push alert (rather than
  email, which is easy to miss for hours). ntfy needs no account — just a shared "topic" name
  the phone app subscribes to and Healthchecks.io publishes to.

**Security note on the setup process itself:** Healthchecks.io's *account* magic-link
(`/accounts/check_token/...`) was initially confused with the check's *ping* URL
(`hc-ping.com/<uuid>`) — the former is an authentication credential and should never be shared
or pasted anywhere; the latter is safe to embed in a script, since it only accepts pings, not
account access. Worth remembering generally: not every long-random-token URL from a service is
equally sensitive — the distinction between "this identifies a resource" and "this authenticates
you" matters, and is not always obvious from the URL shape alone.

**Gotcha: silent background task still flashed a terminal window.** Even with
`-WindowStyle Hidden` passed to `powershell.exe` in the task's action, a brief window flash
was still visible on each run. Adding `New-ScheduledTaskSettingsSet -Hidden` (marking the
*task itself* hidden at the scheduler level, not just the process window style) didn't fully
resolve it either. The actual fix was changing the task's execution context entirely:

```powershell
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Limited
Set-ScheduledTask -TaskName "HomeserverHealthcheckPing" -Principal $principal
```

`S4U` ("Service for User") logon type runs the task without attaching to the interactive
desktop session at all, which is a different mechanism than "hide the window of a process
running in my session" — the window-style and scheduler-hidden flags were never going to fully
solve this, since the process was still launching *inside* the visible desktop session either
way. Confirmed via testing: this was the change that actually stopped the flash.

**Verified end-to-end:** disabled the scheduled task, waited past the grace period, and
confirmed the ntfy push notification arrived on the phone as expected — the full alerting
path (missed ping → Healthchecks.io detects → ntfy push) works, not just the ping side.

## Part 4: Cleanup — removing DVWA's auto-restart

With auto-boot/auto-login being planned for the host (so the whole stack comes back up
unattended after a power loss), DVWA's `restart: unless-stopped` policy became a real problem
rather than a convenience: it would mean the intentionally-vulnerable, LAN-exposed target
silently returns after every reboot or crash, contradicting the earlier decision to only run
it during active testing sessions. Removed the restart policy from `docker-compose.yml` so
DVWA now only runs when explicitly brought up with `docker compose up -d`, and stays down
otherwise — including across power loss and reboots.

## Takeaways

- **Docker socket access ≠ resource metrics access.** Seeing containers exist and reading their
  live CPU/memory numbers are two separate capabilities requiring different mounts
  (socket vs. `/proc` + `/sys`) — a distinction easy to miss since the socket alone looks like
  it should be sufficient.
- **Docker Desktop for Windows networking keeps needing separate handling from Linux-native
  Docker**, this time via `network_mode: host` not meaning what the documentation assumes.
  This is now the third distinct instance of Windows/WSL2 networking behaving unexpectedly in
  this homelab (see also: Docker bridge NAT masking source IPs, the `homeserver` DNS race) —
  worth treating as a standing category of gotcha to check for by default when adopting any
  new container that assumes a Linux host.
- **A monitoring system that runs on the thing it's monitoring has a blind spot exactly where
  it matters most** (total host failure). The fix isn't more monitoring on the host — it's
  moving the failure-detection point outside it entirely.
- **Not all secret-looking URLs are the same kind of secret.** Distinguishing an
  authentication link from a submit-only endpoint is a small but real security judgment call,
  and worth pausing on rather than assuming "long random string in a URL" always means the same
  level of sensitivity.
- **"Hide the window" and "don't attach to the desktop session" are different mechanisms**, and
  a scheduled task needs the latter to be truly invisible — window-style flags alone don't
  address where the process actually runs.
- **Auto-restart policies need to be reconsidered whenever the host's own recovery behavior
  changes.** `restart: unless-stopped` was a reasonable default until auto-boot/auto-login
  entered the picture — at that point, "restart unless stopped" on a deliberately temporary,
  vulnerable container stopped being convenient and started being a standing risk. Worth
  auditing all `restart:` policies across the stack with the same lens now that unattended
  recovery is the goal, not just this one container.
