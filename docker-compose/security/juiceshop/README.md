# OWASP Juice Shop (security testing target)

Intentionally vulnerable Node app, run only during active testing sessions.
Standalone compose project — deliberately not wired into the main stack.

    docker compose up -d      # start a session
    docker compose down       # tear down when finished

Reachable at **http://LAN_IP:8082** from the LAN. Not on `localhost`.

`LAN_IP` and `TAILSCALE_IP` below are placeholders for this host's real addresses;
the LAN one is supplied through a gitignored `.env` (see `.env.example`).

## Isolation posture — do not "tidy" these

| Control | Setting | Why |
|---|---|---|
| Restart policy | `restart: "no"` | Must never silently return after a reboot. |
| Port binding | `LAN_IP:8082:3000` | Binds the **LAN interface only**. |
| Network | own `juiceshop-net` bridge | No shared network with production services. |
| Nginx Proxy Manager | no entry | No `.lab` hostname, no TLS, no reverse proxy. |
| Wazuh | not monitored | See below. |

**The `LAN_IP:` prefix on the port is load-bearing.** Writing it as plain
`"8082:3000"` binds `0.0.0.0`, which publishes the app on *every* host interface —
including Tailscale (`TAILSCALE_IP`), exposing a deliberately vulnerable app to every
device on the tailnet. Verified 2026-09-07: with the prefix, `TAILSCALE_IP:8082` is
refused while `LAN_IP:8082` returns 200.

Trade-off: the binding is pinned to a literal IP, so it breaks if this host's DHCP
lease changes. If Juice Shop stops being reachable, re-check the Wi-Fi adapter's
address first.

Port 8082 was chosen to sit beside DVWA's 8081; host port 3000 is Homepage.

## Why Wazuh does not monitor this

DVWA was easy: Apache writes combined-format `access.log` / `error.log`, which
Wazuh decodes out of the box, and a bind mount put them on a Windows path the
agent could tail.

Juice Shop gives neither half:

1. **No access logging.** It emits startup diagnostics to stdout and nothing
   per-request — a product search and a 404 both produced zero log lines.
   There is no security-relevant data to collect.
2. **stdout is unreachable anyway.** The `json-file` log lives at
   `/var/lib/docker/containers/<id>/<id>-json.log` *inside the Docker Desktop
   WSL VM*, which the Windows Wazuh agent cannot see.

Making this useful would mean injecting a morgan-style access logger (custom image
or a proxy sidecar), routing it to a Windows-visible path, then writing custom
decoders and rules. Deferred as a stretch goal.
