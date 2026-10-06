# homelab-assistant

An interactive CLI that answers plain-English questions about the homelab. On startup it pulls
live data from two sources — Netdata (host alarms plus per-container CPU and memory) and Wazuh
(security alerts via the OpenSearch indexer API: severity levels, MITRE technique tags, rule
groups, attack-related rules, and high-severity operational noise) — and condenses both into a
compact text summary in code. Each question is sent to a Groq-hosted LLM (OpenAI-compatible API)
along with that summary, so the model only ever sees the pre-digested numbers, not raw logs.
Type `refresh` to re-pull data, `quit` to exit.

## Configuration

Secrets follow the repo's [secrets approach](../../docs/secrets-approach.md): copy
`.env.example` to `.env` (gitignored) and fill it in. A variable set in your shell overrides
the value in `.env`.

```
cp .env.example .env
```

| Variable | Required | Default |
|---|---|---|
| `GROQ_API_KEY` | yes | — |
| `WAZUH_PASS` | yes | — |
| `WAZUH_INDEXER_URL` | no | `https://localhost:9200` |
| `WAZUH_USER` | no | `admin` |
| `NETDATA_URL` | no | `http://localhost:19999` |
| `WAZUH_WINDOW` | no | `now-24h` |

## Where it runs

The defaults assume the script runs on the K16 itself, where Netdata and the Wazuh indexer are
reachable on `localhost`. To run it from another device, set `NETDATA_URL` and
`WAZUH_INDEXER_URL` to the K16's tailnet IP instead.

The Wazuh indexer uses a self-signed certificate, so TLS verification is disabled for those
requests — see the comment in the script for the tradeoff.

## Dependencies

Python 3 plus:

```
pip install -r requirements.txt
```

- `openai` — client for Groq's OpenAI-compatible API
- `requests` — Netdata and Wazuh indexer HTTP calls
- `python-dotenv` — loads `.env`
