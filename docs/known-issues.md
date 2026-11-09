# Known issues & structural gotchas

## Docker Desktop on Windows masks client IPs (fixed by moving to ubuntu-lab)

**Root cause:** Docker Desktop on Windows runs containers inside a WSL2 VM and routes traffic
to published ports through its own NAT layer. Unlike Docker Engine on native Linux, it doesn't
preserve the original source IP: every external client reaches the container as the Docker
bridge gateway address.

**What it broke:**

- **Pi-hole** showed every LAN client as the same gateway IP, so per-client stats and "Top
  Clients" were useless. DNS resolution and blocking still worked per client (verified with
  `nslookup` from a client: queries resolved via Pi-hole, blocked domains returned `0.0.0.0`).
  It was a visibility problem, not a blocking failure.
- **Wazuh** web-attack alerts all carried the gateway address in `data.srcip`, whatever device
  actually sent the traffic. This is the more serious of the two: an alert that can't say where
  the attack came from is much less useful for triage. First seen in the
  [DVWA exercise](case-study-dvwa-attack-detection.md).

**Fix:** the services that need real client IPs moved to ubuntu-lab, an Ubuntu Server box
running native Docker Engine. Same request, same client, both hosts:

| Host | Juice Shop logged the client as |
|---|---|
| K16 (Docker Desktop) | `::ffff:192.168.16.1` — the bridge gateway |
| ubuntu-lab (Docker Engine) | `::ffff:192.168.1.142` — the real client |

Details in [`case-study-wazuh-linux-migration.md`](case-study-wazuh-linux-migration.md).

**Still true on the K16:** anything left on Docker Desktop that logs client IPs is still
affected. `macvlan` is the usual workaround on Linux, but it's awkward on Docker Desktop for
Windows, so the answer here was a second host rather than a network-mode change.

## Pi-hole is running but not in use

Pi-hole runs on ubuntu-lab, but no client sends it queries. The router has never handed it
out as DNS through DHCP, so devices still use the router's DNS. The K16's old Pi-hole
container was in the same state (it served no live traffic) and has been removed. Pointing
the router's DHCP DNS at ubuntu-lab is deferred.

## Wazuh `data.srcip` keeps the IPv4-mapped prefix

Juice Shop logs clients as `::ffff:192.168.1.x`, and Wazuh stores the field as-is. A rule or
dashboard filter written against a plain IPv4 address won't match. Match on the address
without anchoring to the start of the field, or strip the prefix in a custom decoder.
