# Case study: the `homeserver` DNS race condition

## Summary

Three services on the same host started failing in ways that looked completely unrelated:
containers couldn't resolve the host machine by name, a SIEM component was authenticating
with stale credentials, and a security agent was silently talking to the wrong IP address.
All three turned out to share one root cause: a naming collision between the Windows computer
name and the Tailscale MagicDNS name, both set to `homeserver`.

## The setup

The host runs Windows 11 with Docker Desktop, and is also a Tailscale node (for remote access
from anywhere without exposing ports to the internet). Both the Windows computer name and the
Tailscale device name were set to `homeserver` — a reasonable-sounding choice that turned out
to be the actual bug.

With this configuration, the machine has multiple active resolution paths for its own name at
once: the physical NIC via Windows' NetBIOS/LLMNR, the Tailscale virtual adapter via MagicDNS,
and the Docker/WSL2 virtual switch's own resolution behavior. Nothing forces these to agree on
which one wins for a given query at a given moment.

## Symptom 1: Containers losing DNS

Two Docker containers (a dashboard and an uptime monitor) that referenced `homeserver` in their
configuration started intermittently failing to reach it — sometimes on startup, sometimes after
running fine for hours. Restarting the containers would "fix" it temporarily, which was a strong
hint the problem was resolution-order-dependent rather than a static misconfiguration.

**Fix:** explicit `extra_hosts: homeserver:host-gateway` in the affected containers' Docker
Compose files. This pins the container's own `/etc/hosts` entry for `homeserver` to the Docker
host gateway directly, sidestepping the race entirely rather than hoping the "right" resolver
wins.

## Symptom 2: A security tool with the wrong credentials

The SIEM's log-shipping component (Filebeat, bundled with the Wazuh manager) started throwing
authentication errors against the indexer. On the surface this looked like a credentials problem
— and it partly was, once traced back — but the actual trigger was that the tool's entrypoint
regenerates its config from environment variables on every container start. An earlier
environment variable fix hadn't actually been applied yet, because a `docker restart` doesn't
force that regeneration — only `docker compose up -d --force-recreate` does.

**Fix:** corrected the environment variable, then explicitly force-recreated the container
rather than assuming a restart would pick up the change. Worth remembering generally: any tool
whose config gets templated from env vars at container-start time needs a recreate, not a
restart, when those vars change.

## Symptom 3: A security agent silently resolving to the wrong place

The most subtle one. The local instance of the security agent — running natively on the same
Windows host, not in a container — was configured to reach its manager component via the
hostname `homeserver`. Under the DNS race, it sometimes resolved that to a link-local IPv6
address instead of the loopback address, which meant the agent occasionally lost contact with
its own manager on the same machine.

**Fix:** for anything running natively on the host talking to another service on the same host,
skip hostname resolution entirely — use `127.0.0.1` directly. The hostname is only meaningful
for other machines on the network; a service talking to its own host doesn't need to resolve
anything.

## The actual root cause

All three symptoms trace back to the same naming collision. The durable fix was renaming the
Windows computer name to something distinct from the Tailscale MagicDNS name, removing the 
ambiguity at the source rather than continuing to patch around it symptom by symptom. Since
the rename, all three symptoms have stayed resolved — the extra_hosts and 127.0.0.1 patches 
are now belt-and-suspenders rather than load-bearing.

## Takeaways

- **Intermittent bugs that "fix themselves" on restart are often resolution-order or race
  conditions**, not transient glitches — worth treating that pattern as a specific hypothesis
  to test, not just noise.
- **Three symptoms with no obvious surface-level connection can share one root cause.** Chasing
  each one individually (which happened here, initially) costs more time than stepping back and
  asking what's structurally shared across all of them.
- **Patching each symptom is a legitimate short-term move, but isn't the same as fixing the bug.**
  The extra_hosts and 127.0.0.1 fixes were correct and durable on their own, but removing the
  naming collision itself — the actual root cause — was what closed the loop for good.
