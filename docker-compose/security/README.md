# Security

| Service | Host | Role |
|---|---|---|
| [Wazuh](wazuh/) | ubuntu-lab | SIEM/XDR — single-node manager, indexer, and dashboard |
| [Juice Shop](juiceshop/) | ubuntu-lab | Deliberately vulnerable attack target for detection testing; see its [README](juiceshop/README.md) for the isolation controls |
| [Vaultwarden](vaultwarden/) | K16 | Self-hosted, Bitwarden-compatible password manager, reached over Tailscale only |

DVWA, the first attack target, has been retired in favor of Juice Shop. Its write-up is still
in [`docs/case-study-dvwa-attack-detection.md`](../../docs/case-study-dvwa-attack-detection.md).

## Wazuh SIEM/XDR

Single-node deployment (manager, indexer, dashboard) running Wazuh 4.14.5 on ubuntu-lab, an
Ubuntu Server 24.04 box with native Docker Engine. It moved off the K16 so that container logs
would carry real client IPs; the reasoning and the before/after evidence are in
[`docs/case-study-wazuh-linux-migration.md`](../../docs/case-study-wazuh-linux-migration.md).
The old K16 compose is in [`archive/wazuh-k16/`](../../archive/wazuh-k16/).

Three agents report to it: ubuntu-lab itself, the K16 (`homeserver`), and the desktop PC
(`main-pc`).

This folder shows the deployment pattern: `docker-compose.yml` references every credential via
environment variable substitution (`${VAR}`), never a literal value. The rest of the config set
(indexer internal users file, the dashboard's `wazuh.yml`, the manager config, SSL certs) is
deliberately kept out of the repo and exists only on the host. Certs are regenerated per
deployment and aren't meant to be shared or reused across environments.

`.env.example` shows the variables needed to stand this up; real values go in a gitignored
`.env`, same pattern used across every service in this repo. The indexer needs
`vm.max_map_count=262144` on the host.

### Custom rules

[`wazuh/local_rules.xml`](wazuh/local_rules.xml) is an export of the manager's custom rules.
The live file is in the manager container at `/var/ossec/etc/rules/local_rules.xml`. Changes
are validated with `wazuh-analysisd -t` before restarting the manager. The reasoning behind the
rules is in [`docs/case-study-wazuh-alert-tuning.md`](../../docs/case-study-wazuh-alert-tuning.md).
The rules were carried over unchanged in the move to ubuntu-lab.

## Vaultwarden

A single container with its data in a bind-mounted folder. Its port is bound to loopback only,
so nothing on the LAN or the public internet can reach it directly; clients connect over
Tailscale HTTPS. Signups are disabled. The tailnet hostname in `DOMAIN` is a placeholder.
