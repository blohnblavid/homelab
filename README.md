# Homelab

A self-hosted infrastructure project built on a Ryzen 7 mini PC, run as a real production
environment — not a tutorial follow-along. Built for two purposes: a genuinely useful home
server, and hands-on practice for SOC analyst / IT support work (alongside Security+ study).

This repo documents the architecture, the security tooling, and — maybe most usefully — the
actual debugging process behind a gnarly infrastructure bug that touched DNS, Docker
networking, and a SIEM agent all at once. See [`docs/case-study-dns-race.md`](docs/case-study-dns-race.md).

> This is the portfolio version of a larger private setup. Media-management services are
> intentionally excluded here — this repo focuses on infrastructure, networking, and security
> tooling, which is the relevant material for the roles I'm applying to.

## Hardware

- GMKtec NucBox K16 — Ryzen 7 7735HS, 32GB LPDDR5, dual M.2 NVMe, dual 2.5GbE
- Windows 11 Pro host running Docker Desktop
- Remote access via Tailscale (zero-trust overlay network, no exposed ports to the public internet)

## What's running

| Category | Services | Why it's here |
|---|---|---|
| **Security** | [Wazuh](docker-compose/security/) — SIEM/XDR (manager, indexer, dashboard) | Active SOC analyst practice: log ingestion, alert triage, file integrity monitoring, security configuration assessment |
| **Infrastructure** | [Pi-hole](docker-compose/infra/), [Nginx Proxy Manager](docker-compose/infra/), [Portainer](docker-compose/infra/), [Homepage](docker-compose/infra/), [Uptime Kuma](docker-compose/infra/) | Network-wide DNS filtering, reverse proxy, container orchestration visibility, service monitoring |
| **AI/local inference** | [Odysseus](docker-compose/infra/) — self-hosted AI assistant on local LLMs via Ollama | Experimenting with local-first AI infrastructure, no cloud dependency |
| **Gaming** | [Minecraft (Fabric)](docker-compose/gaming/) | Because self-hosting shouldn't be all business |

## Security practices in this repo

- **No secrets in git, ever.** Every credential lives in a gitignored `.env`, referenced via
  Docker Compose variable substitution. See [`docs/secrets-approach.md`](docs/secrets-approach.md)
  for the full reasoning.
- **Pre-commit secret scanning** via [gitleaks](https://github.com/gitleaks/gitleaks) — every
  commit is scanned locally before it's allowed through.
- **Zero-trust remote access** — nothing is port-forwarded to the public internet; all remote
  access goes through Tailscale's WireGuard-based overlay network.

## Featured write-up

**[The `homeserver` DNS race condition](docs/case-study-dns-race.md)** — a multi-layered bug
where the Windows hostname and the Tailscale MagicDNS name collided, causing intermittent
resolution failures across LLMNR/NetBIOS/mDNS depending on which network adapter won the race.
The bug manifested as three unrelated-looking symptoms (broken container DNS, a misconfigured
Wazuh Filebeat credential, and an agent silently resolving to a link-local IPv6 address) before
the actual root cause was identified.
