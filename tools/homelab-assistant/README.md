# homelab-assistant

An interactive CLI that answers plain-English questions about the homelab from two sources:
Netdata (host alarms plus per-container CPU and memory) and Wazuh (security alerts via the
OpenSearch indexer API). Nothing is fetched at startup. Each question fetches only the data it
needs through one or more **skills**. Many questions are answered by printing a skill's output
directly, with no LLM call. The rest send only the chosen skills' output to a Groq-hosted LLM
(OpenAI-compatible API), with host names replaced by aliases. See
[What is sent to Groq](#what-is-sent-to-groq).

## Skills

A skill is a Python function that queries one source and returns a compact text block (one line
per item). They are registered with the `@skill` decorator in `homelab_assistant.py`.

| Skill | Direct | Returns |
|---|---|---|
| `overview` | no | Netdata alarm counts and Wazuh alert counts per level |
| `critical_alerts` | yes | Every Wazuh alert at level 12 or above, with time, agent, rule and description |
| `alerts_by_level(level)` | yes | The `critical_alerts` detail for one level |
| `vulnerabilities` | yes | Vulnerability-detector (CVE) findings at any level |
| `mitre_tags` | yes | Alert count per MITRE technique, with the rule generating most of each |
| `top_rules(n=5)` | yes | The rule IDs with the most alerts, with description and count |
| `attack_alerts` | no | Alerts in the attack-related rule groups, grouped by rule |
| `container_stats` | yes | Top containers by CPU and by memory |
| `netdata_alarms` | yes | Active Netdata alarms (WARNING/CRITICAL) |

Alert detail lines are deduplicated (repeats of the same rule on the same agent become one line
with a count) and capped at 20. CVE findings are grouped into one line per agent and package:
package, installed version, number of CVEs, highest severity, up to three CVE IDs and a fix
status. The fix status is written out in code from Wazuh's condition: "less than X" becomes
"fix: update to X or later", and "less than or equal to X" becomes "no fixed version listed;
affected through X". The model is told to repeat it as written. Findings are labeled as
vulnerability findings — "patch needed", not "attack detected". Wazuh
only alerts on a CVE when it is first detected, so these skills show findings raised inside the
time window, not a full inventory.

## Routing

1. **Keywords, no LLM call.** Regexes in `KEYWORD_ROUTES` pick the skill(s): "level 13" runs
   `alerts_by_level(13)`, "memory" runs `container_stats`, "tag" runs `mitre_tags`, and so on.
   Vague status questions ("anything to note?", "what's up", "status", "how is the server") run
   the bundle `overview` + `critical_alerts` + `netdata_alarms` + `attack_alerts`.
2. **LLM tool-calling.** If no keyword matches, one extra LLM call chooses the skill(s). If the
   model rejects tool-calling, the script says so and sends only `overview` for the rest of the
   session.

A question runs at most three skills (four for the status bundle). Before each answer the script
prints which skills ran and how they were chosen.

## Direct answers

If the keywords route a question to **only direct skills**, the script prints their output and
makes no LLM call:

```
[skills: alerts_by_level(level=13) | routed by: keyword]
ALERTS AT LEVEL 13 (...): total=1, distinct=1
  - ...
[direct: no LLM call, nothing sent]
```

Every other question gets one LLM call for the answer (plus one for routing if no keyword
matched), and ends with the tokens used:

```
[skills: overview(), critical_alerts(), netdata_alarms(), attack_alerts() | routed by: keyword]
Assistant: ...
[tokens: 891 total — router 0, answer 891]
```

Whenever a skill's output is going to the LLM, its vulnerability findings are **redacted**: each
becomes a label, a level and a count, with no package name, version or CVE ID:

```
  - L13 VULNERABILITY FINDING, not an attack: 1 CVE (ask 'cves' for details)
```

That applies to the status bundle, to keyword routes that mix a direct skill with a non-direct
one, and to anything the LLM router picks. If the model's answer does not point to `cves`, the
script prints a one-line hint itself. Asking `cves` runs `vulnerabilities` directly, which shows
the full detail without an LLM call.

## What is sent to Groq

**Nothing**, when a question is answered directly.

**Otherwise, per LLM call:**

- The fixed system prompt from the code.
- Your question, as typed, with agent names aliased.
- For a routing call: each skill's name, description and parameter names. No data.
- For an answer call: the output of the skills that ran, with agent names aliased. Depending on
  the skills, that is:
  - alert counts per level, and Netdata alarm counts, names and values;
  - alert lines: time, agent alias, rule ID, level, Wazuh's rule description and a repeat count;
  - for `attack_alerts`, one example per rule: the request URL or, failing that, the start of
    the log line, cut to 80 characters;
  - container names with CPU and memory figures;
  - MITRE technique names;
  - vulnerability findings in redacted form only: the label, the alert level and the number of
    CVEs at that level.

**Never sent:**

- Vulnerability details: package names, installed versions, CVE IDs and fix status. In
  `top_rules` and `mitre_tags`, the description of a vulnerability-detector rule (which names the
  CVE and package) is replaced with "details withheld".
- Real Wazuh agent names. Each is replaced with an alias (`agent-1`, `agent-2`, ...) taken from
  its Wazuh agent ID, so aliases are the same every session. The reply's aliases are swapped
  back before printing, so you see real names. Direct output shows real names because it never
  leaves the machine.
- The values in `.env`, the indexer and Netdata addresses, and the text of connection errors
  (only the error type, such as `ConnectionError`, goes into skill output).
- Full alert documents or log bodies, beyond the 80-character example above.

**Limits of the aliasing:**

- It covers Wazuh agent names only. Container names, anything inside a rule description or the
  attack example, and anything else you type in a question go out as they are.
- The vulnerability redaction covers vulnerability-detector findings only. Other Wazuh rule
  descriptions can name software too (for example a Windows "application installed" event) and
  are sent as written.
- Names are matched as whole words, ignoring case. If an agent's name is an ordinary word, that
  word is also swapped wherever it appears in a question (and swapped back in the reply).
- The agent list is loaded from the indexer once per session. If that fails the script prints a
  warning; until it loads, an agent name typed in a question is sent as typed.

## Commands

- `refresh` — skill results are reused for 120 seconds; `refresh` drops that cache so the next
  question pulls fresh data. It does not fetch anything itself.
- `quit` (or `exit`, `q`) — leave.

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
| `GROQ_MODEL` | no | `openai/gpt-oss-20b` |

`GROQ_MODEL` should be a model that supports tool-calling; without it, questions that match no
keyword only get the overview.

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
