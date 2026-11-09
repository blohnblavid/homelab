# Minecraft server

A NeoForge-modded Minecraft server (26.3), containerized with `itzg/minecraft-server` and
running Create: Adapted and AE2. It moved from Fabric to NeoForge to get those mods; the world carried
over.

The server doesn't run around the clock. [lazymc](https://github.com/joesturge/lazymc-docker-proxy)
sits in front of it on port 25565: it starts the server container when a player connects and
stops it again once the server is idle, so the 6 GB of RAM is only held while someone is
actually playing. That is why the `minecraft` service is `restart: "no"` and carries the
`lazymc.*` labels, and why it has a fixed address on the compose network for the proxy to
forward to. The first connection after a sleep takes about a minute while the server boots.

# Palworld server

A dedicated Palworld server, containerized with `thijsvanloef/palworld-server-docker`.
Migrated from a local co-op save using a community save-conversion tool to remap the
host character's placeholder ID to a real player ID. Config (server name, admin password)
is pulled from a gitignored `.env`, following the same secrets pattern as the rest of this repo.
Currently stopped; the config is kept so it can be brought back up.
