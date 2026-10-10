# Custom projects

Small apps written for this lab rather than pulled from a registry.

| Project | Status | What it is |
|---|---|---|
| [Enchants](enchants/) | Stopped (config kept) | A Minecraft enchantment checklist: a single-page tracker backed by a tiny Node server |
| [Minecraft Dashboard](minecraft-dashboard/) | Running | Live player list, join/leave/death feed parsed from the server log, optional BlueMap embed, and an RCON console |

## Minecraft Dashboard

An Express app that talks to the Minecraft server over RCON and tails its `latest.log` from a
read-only bind mount. It has no compose file of its own: it is built and run as a service in
[`../gaming/minecraft/docker-compose.yml`](../gaming/minecraft/docker-compose.yml), which is
where the shared `RCON_PASSWORD` is substituted in. Its non-secret settings come from a
gitignored `.env` next to the source (see `.env.example`).

The log is polled with `stat()` rather than watched, because inotify events don't cross a
Docker Desktop bind mount from Windows and `fs.watch()` never fires there.

The RCON console endpoint has no authentication of its own. It is meant to be reachable only
from the LAN and over Tailscale, never through a public reverse proxy entry.
