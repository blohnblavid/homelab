const express = require("express");
const fs = require("fs");
const path = require("path");
const { Rcon } = require("rcon-client");

const PORT = process.env.PORT || 3070;
const RCON_HOST = process.env.RCON_HOST || "minecraft";
const RCON_PORT = parseInt(process.env.RCON_PORT || "25575", 10);
const RCON_PASSWORD = process.env.RCON_PASSWORD || "";
const LOG_PATH = process.env.LOG_PATH || "/data/logs/latest.log";
const BLUEMAP_URL = process.env.BLUEMAP_URL || "";
const EVENT_BUFFER_SIZE = 200;

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

async function rconSend(command) {
  const rcon = await Rcon.connect({
    host: RCON_HOST,
    port: RCON_PORT,
    password: RCON_PASSWORD,
  });
  try {
    return await rcon.send(command);
  } finally {
    rcon.end();
  }
}

app.get("/api/players", async (req, res) => {
  try {
    const raw = await rconSend("list");
    const match = raw.match(/There are (\d+) of a max of (\d+) players online:?\s*(.*)/i);
    if (!match) {
      return res.json({ online: 0, max: 0, players: [], raw });
    }
    const [, online, max, namesRaw] = match;
    const players = namesRaw
      .split(",")
      .map((n) => n.trim())
      .filter(Boolean);
    res.json({ online: parseInt(online, 10), max: parseInt(max, 10), players });
  } catch (err) {
    res.status(502).json({ error: "RCON unreachable", detail: err.message });
  }
});

app.post("/api/rcon", async (req, res) => {
  const { command } = req.body || {};
  if (!command || typeof command !== "string") {
    return res.status(400).json({ error: "Missing 'command' string in body" });
  }
  try {
    const response = await rconSend(command);
    res.json({ command, response });
  } catch (err) {
    res.status(502).json({ error: "RCON unreachable", detail: err.message });
  }
});

app.get("/api/events", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "50", 10), EVENT_BUFFER_SIZE);
  res.json(events.slice(-limit).reverse());
});

app.get("/api/config", (req, res) => {
  res.json({ blueMapUrl: BLUEMAP_URL });
});

const events = [];

function pushEvent(type, message, timestamp) {
  events.push({ type, message, timestamp: timestamp || new Date().toISOString() });
  if (events.length > EVENT_BUFFER_SIZE) events.shift();
}

const LOG_LINE_RE = /^\[(\d{2}:\d{2}:\d{2})\] \[.*?\]: (.*)$/;
const DEATH_PATTERNS = [
  / was slain by /, / was shot by /, / was fireballed by /, / was killed by /,
  / drowned/, / burned to death/, / went up in flames/, / blew up/,
  / was blown up by /, / fell from a high place/, / fell off /, / hit the ground too hard/,
  / was squashed by /, / starved to death/, / suffocated in a wall/,
  / was pricked to death/, / walked into a cactus/, / froze to death/,
  / died from dehydration/, / was struck by lightning/, / discovered the floor was lava/,
  / walked into fire/, / went out with a bang/, / tried to swim in lava/,
  / was doomed to fall/, / was impaled/, / withered away/, / was poked to death/,
  / experienced kinetic energy/,
];

function classifyLine(msg) {
  if (/ joined the game$/.test(msg)) return "join";
  if (/ left the game$/.test(msg)) return "leave";
  if (/ was kicked from the server/i.test(msg) || /^Kicked /.test(msg)) return "kick";
  if (/^Done \(.*\)! For help/.test(msg)) return "server_start";
  if (/^Stopping the server/.test(msg)) return "server_stop";
  if (DEATH_PATTERNS.some((re) => re.test(msg))) return "death";
  return null;
}

/*
 * The log lives on a Windows bind mount (Docker Desktop). inotify events do not
 * propagate across that mount, so fs.watch() never fires there and the feed would
 * stay permanently empty. Poll stat() instead — that works on any mount.
 */
const LOG_POLL_MS = parseInt(process.env.LOG_POLL_MS || "2000", 10);
const SEED_BYTES = 256 * 1024;

let position = 0;
let inode = null;
let pending = "";
let polling = false;

function ingest(chunk) {
  pending += chunk;
  const lines = pending.split("\n");
  pending = lines.pop(); // trailing partial line; completed by a later read
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const m = line.match(LOG_LINE_RE);
    if (!m) continue;
    const [, time, msg] = m;
    const type = classifyLine(msg);
    if (type) pushEvent(type, msg, time);
  }
}

function readRange(start, end) {
  return new Promise((resolve) => {
    if (end <= start) return resolve();
    const stream = fs.createReadStream(LOG_PATH, {
      start,
      end: end - 1, // fs stream ranges are inclusive
      encoding: "utf8",
    });
    stream.on("data", ingest);
    stream.on("error", () => resolve());
    stream.on("end", resolve);
  });
}

async function pollLog() {
  if (polling) return;
  polling = true;
  try {
    const stats = await fs.promises.stat(LOG_PATH);

    if (inode === null) {
      // First sight: seed from the tail of the file so the panel has history
      // immediately instead of staying blank until the next player event.
      inode = stats.ino;
      pending = "";
      const from = Math.max(0, stats.size - SEED_BYTES);
      await readRange(from, stats.size);
      position = stats.size;
      pending = "";
      console.log(`[dashboard] seeded ${events.length} event(s) from ${LOG_PATH}`);
      return;
    }

    // Minecraft rotates latest.log daily: the old file is gzipped away and a new
    // one starts at zero. A changed inode or a shrunken file means we must restart.
    if (stats.ino !== inode || stats.size < position) {
      console.log("[dashboard] log rotated, reading new file from the start");
      inode = stats.ino;
      position = 0;
      pending = "";
    }

    if (stats.size > position) {
      const from = position;
      position = stats.size;
      await readRange(from, stats.size);
    }
  } catch (err) {
    if (err.code === "ENOENT") {
      // Server not started yet, or mid-rotation. Re-seed when it reappears.
      inode = null;
      position = 0;
      pending = "";
    } else {
      console.warn(`[dashboard] log poll failed: ${err.message}`);
    }
  } finally {
    polling = false;
  }
}

function tailLog() {
  console.log(`[dashboard] polling ${LOG_PATH} every ${LOG_POLL_MS}ms`);
  pollLog();
  setInterval(pollLog, LOG_POLL_MS);
}

tailLog();

app.listen(PORT, () => {
  console.log(`[dashboard] listening on :${PORT}`);
});
