# Infrastructure

Core services that everything else depends on. Everything here runs on the K16 except Pi-hole,
which runs on ubuntu-lab.

| Service | Role |
|---|---|
| [Pi-hole](pihole/) | DNS filtering and ad-blocking. Runs on ubuntu-lab, but no clients use it yet: the router doesn't hand it out as DNS |
| [Nginx Proxy Manager](npm/) | Reverse proxy for `.lab` hostnames, with TLS from a self-signed wildcard certificate for `*.lab`. The `.lab` names are currently down; see [known issues](../../docs/known-issues.md) |
| [Portainer](portainer/) | Docker container management and visibility; bound to the Tailscale IP only |
| [Homepage](homepage/) | Unified dashboard for all self-hosted services |
| [Uptime Kuma](uptimekuma/) | Service uptime monitoring and alerting |
| [Netdata](netdata/) | Host and per-container metrics with history; bound to the Tailscale IP only; also the data source for the [homelab assistant](../../docs/case-study-homelab-assistant.md) |
| [Odysseus](odysseus/) | Retired — local-LLM assistant via Ollama (config kept, not running). The K16's Radeon 680M isn't supported by ROCm, so inference was CPU-only and too slow; replaced by the [homelab assistant](../../docs/case-study-homelab-assistant.md) |
| [Nextcloud](nextcloud/) | Self-hosted file sync and sharing — a Google Drive replacement, reached over Tailscale |
| [Immich](immich/) | Self-hosted photo and video backup (server, machine learning, Postgres, Valkey) — a Google Photos replacement |

On a fresh deployment, bring Nginx Proxy Manager up before the services behind it.
