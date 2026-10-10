# Security

| Service | Role |
|---|---|
| [Wazuh](wazuh/) | SIEM/XDR — single-node manager, indexer, and dashboard |
| [Vaultwarden](vaultwarden/) | Self-hosted, Bitwarden-compatible password manager, reached over Tailscale only |
| [DVWA](dvwa/) | Deliberately vulnerable web app used as an attack target for detection testing |
| [Juice Shop](juiceshop/) | Second deliberately vulnerable target; see its [README](juiceshop/README.md) for the isolation controls |

## Wazuh SIEM/XDR

Single-node deployment (manager, indexer, dashboard) running Wazuh 4.14.5. Used actively for
SOC analyst practice — log ingestion and analysis, file integrity monitoring, security
configuration assessment (SCA), and alert triage — alongside Security+ study.

This folder shows the deployment pattern: `docker-compose.yml` and `wazuh.yml` reference every
credential via environment variable substitution (`${VAR}`), never a literal value. The full
config set (indexer internal users file, manager ruleset, SSL certs) lives in a private,
non-public backup — certs in particular regenerate per-deployment and aren't meant to be shared
or reused across environments.

`.env.example` shows the variables needed to stand this up; real values go in a gitignored
`.env`, same pattern used across every service in this repo.

## Vaultwarden

A single container with its data in a bind-mounted folder. Its port is bound to loopback only,
so nothing on the LAN or the public internet can reach it directly; clients connect over
Tailscale HTTPS. Signups are disabled. The tailnet hostname in `DOMAIN` is a placeholder.

## Vulnerable targets: DVWA and Juice Shop

Both are brought up by hand for a test session and torn down afterwards. Neither restarts
automatically, so a reboot never brings one back, and each sits on its own bridge network with
no reverse proxy entry. Each publishes its port on the LAN interface only (`LAN_IP`, set in a
gitignored `.env`), which keeps both off Tailscale.

DVWA bind-mounts its Apache logs to a host folder so the Wazuh agent can tail them; the
write-up is in [`docs/case-study-dvwa-attack-detection.md`](../../docs/case-study-dvwa-attack-detection.md).
Juice Shop is not monitored by Wazuh, for the reasons in its README.
