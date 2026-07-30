# Minecraft server

A Fabric-modded Minecraft server, containerized with `itzg/minecraft-server`. Whitelist and
ops files sync from an existing state on container recreate, so the server can be rebuilt
without losing player permissions.

# Palworld server

A dedicated Palworld server, containerized with `thijsvanloef/palworld-server-docker`.
Migrated from a local co-op save using a community save-conversion tool to remap the
host character's placeholder ID to a real player ID. Config (server name, admin password)
is pulled from a gitignored `.env`, following the same secrets pattern as the rest of this repo.