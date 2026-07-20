# Infrastructure

Core services that everything else depends on.

| Service | Role |
|---|---|
| [Pi-hole](pihole/) | Network-wide DNS filtering and ad-blocking |
| [Nginx Proxy Manager](npm/) | Reverse proxy with automatic Let's Encrypt SSL |
| [Portainer](portainer/) | Docker container management and visibility |
| [Homepage](homepage/) | Unified dashboard for all self-hosted services |
| [Uptime Kuma](uptimekuma/) | Service uptime monitoring and alerting |
| [Odysseus](odysseus/) | Self-hosted AI assistant running on local LLMs (Ollama) — no cloud dependency |

Bring these up first on a fresh deployment — DNS and reverse proxy need to be live before
anything that depends on them.
