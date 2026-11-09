# OWASP Juice Shop (security testing target)

Intentionally vulnerable Node app, run only during active testing sessions. Runs on
ubuntu-lab as a standalone compose project, deliberately not wired into anything else.

    docker compose up -d      # start a session
    docker compose down       # tear down when finished

Reachable at **http://LAN_IP:8082** from the LAN. `LAN_IP` is ubuntu-lab's address, supplied
through a gitignored `.env` (see `.env.example`).

## Isolation posture — do not "tidy" these

| Control | Setting | Why |
|---|---|---|
| Restart policy | `restart: "no"` | Must never silently return after a reboot. |
| Port binding | `LAN_IP:8082:3000` | Binds the **LAN interface only**. |
| Network | its own compose project | No shared network with any other service. |
| Nginx Proxy Manager | no entry | No `.lab` hostname, no TLS, no reverse proxy. |

**The `LAN_IP:` prefix on the port is load-bearing.** Writing it as plain `"8082:3000"` binds
`0.0.0.0`, which publishes the app on every host interface, including Tailscale, and exposes a
deliberately vulnerable app to every device on the tailnet.

Trade-off: the binding is pinned to a literal IP. ubuntu-lab's address is set statically in
netplan, so it doesn't drift the way a DHCP lease can.

## Wazuh monitoring

Juice Shop writes a per-request access log, `access.log.<date>`, in Apache combined format, to
`/juice-shop/logs` inside the container. The compose file mounts that folder at
`/opt/juice-shop/logs` on the host, and the Wazuh agent on ubuntu-lab tails it with a
`<localfile>` entry. Wazuh's stock web rules decode it with no custom decoder: a UNION-based
SQL injection test fired rule 31103.

Two details worth knowing:

- The log folder has to be writable by the container's user (UID 65532), or Juice Shop can't
  create the file.
- Client addresses are logged as IPv4-mapped IPv6 (`::ffff:192.168.1.x`), and Wazuh keeps that
  prefix in `data.srcip`. Any rule or query that matches on source IP needs to allow for it.

This replaces an earlier conclusion, from when Juice Shop ran on the K16, that it had no access
logging. That was based on watching the container's stdout, which shows nothing per request;
the access log goes to the file, not stdout.
