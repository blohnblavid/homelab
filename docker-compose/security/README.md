# Wazuh SIEM/XDR

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
