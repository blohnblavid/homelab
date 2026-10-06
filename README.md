# Homelab

A self-hosted infrastructure project built on a Ryzen 7 mini PC, run as a real production
environment — not a tutorial follow-along. Built for two purposes: a genuinely useful home
server, and hands-on practice for SOC analyst / IT support work (alongside Security+ study).

This repo documents the architecture, the security tooling, and — maybe most usefully — the
debugging and validation work behind it: a gnarly infrastructure bug that touched DNS, Docker
networking, and a SIEM agent all at once ([`docs/case-study-dns-race.md`](docs/case-study-dns-race.md)),
and an attack-detection exercise that tested what the SIEM actually catches
([`docs/case-study-dvwa-attack-detection.md`](docs/case-study-dvwa-attack-detection.md)).

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
| **Security** | [Wazuh](docker-compose/security/) — SIEM/XDR (manager, indexer, dashboard); DVWA — isolated, deliberately vulnerable target, brought up only for test sessions | Active SOC analyst practice: log ingestion, alert triage, file integrity monitoring, security configuration assessment, and validating detections against real attack traffic |
| **Infrastructure** | [Pi-hole](docker-compose/infra/), [Nginx Proxy Manager](docker-compose/infra/), [Portainer](docker-compose/infra/), [Homepage](docker-compose/infra/), [Nextcloud](docker-compose/infra/) | Network-wide DNS filtering, reverse proxy, container orchestration visibility, a single-page dashboard, and self-hosted file sync and sharing as a Google Drive replacement, reached over Tailscale |
| **Monitoring** | [Uptime Kuma](docker-compose/infra/), Netdata, Healthchecks.io dead-man's-switch with ntfy push alerts | Service uptime, host and per-container metrics with history, and an external alert path that still works if the whole host goes down |
| **AI/local inference** | [Odysseus](docker-compose/infra/) — self-hosted AI assistant on local LLMs via Ollama | Experimenting with local-first AI infrastructure, no cloud dependency |
| **Gaming** | [Minecraft (Fabric)](docker-compose/gaming/), [Palworld](docker-compose/gaming/palworld/) (config kept, currently stopped) | Because self-hosting shouldn't be all business |

## Security practices in this repo

- **No secrets in git, ever.** Every credential lives in a gitignored `.env`, referenced via
  Docker Compose variable substitution. See [`docs/secrets-approach.md`](docs/secrets-approach.md)
  for the full reasoning.
- **Pre-commit secret scanning** via [gitleaks](https://github.com/gitleaks/gitleaks) — every
  commit is scanned locally before it's allowed through.
- **Zero-trust remote access** — nothing is port-forwarded to the public internet; all remote
  access goes through Tailscale's WireGuard-based overlay network.
- **Vulnerable-by-design targets stay contained** — the DVWA test target is kept off the
  reverse proxy and Tailscale, and only runs when explicitly started.
- **Monitoring that doesn't share fate with the host** — alerting for total host failure comes
  from outside the machine, using outbound pings only and no inbound ports.

## Write-ups

**[The `homeserver` DNS race condition](docs/case-study-dns-race.md)** — a multi-layered bug
where the Windows hostname and the Tailscale MagicDNS name collided, causing intermittent
resolution failures across LLMNR/NetBIOS/mDNS depending on which network adapter won the race.
The bug manifested as three unrelated-looking symptoms (broken container DNS, a misconfigured
Wazuh Filebeat credential, and an agent silently resolving to a link-local IPv6 address) before
the actual root cause was identified.

**[Building and validating an attack detection pipeline](docs/case-study-dvwa-attack-detection.md)** —
an isolated DVWA target wired into Wazuh, then attacked with nikto, a CSRF-aware brute-force
script, and sqlmap using only the stock ruleset. Reconnaissance and SQL injection were detected
and mapped to MITRE ATT&CK; web-form credential brute-forcing was a real blind spot.

**[Homeserver monitoring: dashboard, metrics, and a dead-man's-switch](docs/case-study-homeserver-monitoring.md)** —
Netdata for host and container metrics, an external Healthchecks.io alert path with phone
push, and the Docker Desktop on Windows gotchas hit along the way (host networking, scheduled
task visibility).

## Known issues

**[`docs/known-issues.md`](docs/known-issues.md)** — smaller structural gotchas worth
knowing about on a rebuild, including a Docker Desktop on Windows networking limitation
that masks real client IPs behind Pi-hole's dashboard.
