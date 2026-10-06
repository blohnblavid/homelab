# Infrastructure

Core services that everything else depends on.

| Service | Role |
|---|---|
| [Pi-hole](pihole/) | Network-wide DNS filtering and ad-blocking |
| [Nginx Proxy Manager](npm/) | Reverse proxy with automatic Let's Encrypt SSL |
| [Portainer](portainer/) | Docker container management and visibility |
| [Homepage](homepage/) | Unified dashboard for all self-hosted services |
| [Uptime Kuma](uptimekuma/) | Service uptime monitoring and alerting |
| [Odysseus](odysseus/) | Retired — local-LLM assistant via Ollama (config kept, not running). The K16's Radeon 680M isn't supported by ROCm, so inference was CPU-only and too slow; replaced by the [homelab assistant](../../docs/case-study-homelab-assistant.md) |
| [Nextcloud](nextcloud/) | Self-hosted file sync and sharing — a Google Drive replacement, reached over Tailscale |

Bring these up first on a fresh deployment — DNS and reverse proxy need to be live before
anything that depends on them.
