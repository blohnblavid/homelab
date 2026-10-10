# Minecraft server

A Fabric-modded Minecraft server, containerized with `itzg/minecraft-server`. Whitelist and
ops files sync from an existing state on container recreate, so the server can be rebuilt
without losing player permissions.

The server no longer runs around the clock. [lazymc](https://github.com/joesturge/lazymc-docker-proxy)
sits in front of it on port 25565: it starts the server container when a player connects and
stops it again after five idle minutes, so the 4GB of RAM is only held while someone is
actually playing. That is why the `minecraft` service is `restart: "no"` and carries the
`lazymc.*` labels, and why it has a fixed address on the compose network for the proxy to
forward to.

RCON is enabled with a pinned password, pulled from a gitignored `.env`, so the
[Minecraft Dashboard](../custom/minecraft-dashboard/) can read the player list and send
commands. The dashboard is built from `../custom/minecraft-dashboard/` and is defined as a
third service in the same compose project. Status: Stopped (config kept). Its service is
`restart: "no"` and stays down until it is started by hand.

# Palworld server

A dedicated Palworld server, containerized with `thijsvanloef/palworld-server-docker`.
Migrated from a local co-op save using a community save-conversion tool to remap the
host character's placeholder ID to a real player ID. Config (server name, admin password)
is pulled from a gitignored `.env`, following the same secrets pattern as the rest of this repo.
Currently stopped; the config is kept so it can be brought back up.
