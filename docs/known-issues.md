\# Known issues \& structural gotchas



\## Pi-hole client IP masked by Docker Desktop (Windows/WSL2)



\*\*Root cause:\*\* Docker Desktop on Windows routes all traffic to published container

ports through its internal WSL2/NAT layer. Unlike Docker on native Linux, it does not

preserve the original source IP for external clients connecting to a published port.



\*\*Symptoms this caused:\*\* Pi-hole's dashboard shows every external client on the LAN

as the same internal Docker gateway IP, rather than each device's real LAN address.

Per-client stats and "Top Clients" breakdowns are effectively useless for anything

running as a published Docker container on Windows.



\*\*Not a functional problem:\*\* DNS resolution and ad-blocking both work correctly

per-client — verified directly via `nslookup` from the client machine (queries resolve

via Pi-hole's IP; blocked domains return `0.0.0.0`). This is a dashboard visibility

limitation only, not a blocking failure.



\*\*Not yet resolved:\*\* true per-client visibility would need Pi-hole on a network mode

that preserves real source IPs (e.g. `macvlan`, giving the container its own LAN IP)

— not straightforward with Docker Desktop for Windows the way it is on native Linux.



\*\*Rule of thumb:\*\* don't rely on Pi-hole's per-client dashboard data for anything

running under Docker Desktop on Windows — it will always attribute traffic to the

Docker gateway IP, not the real device.

