# homelab-assistant

An interactive CLI that answers plain-English questions about the homelab from two sources:
Netdata (host alarms plus per-container CPU and memory) and Wazuh (security alerts via the
OpenSearch indexer API). Nothing is fetched at startup. Each question fetches only the data it
needs through one or more **skills**. Many questions are answered by printing a skill's output
directly, with no LLM call. The rest send only the chosen skills' output to a Groq-hosted LLM
(OpenAI-compatible API), with host names replaced by aliases. See
[What is sent to Groq](#what-is-sent-to-groq).

## Layout

Run it with `python homelab_assistant.py`.

| File | Contents |
|---|---|
| `homelab_assistant.py` | Entry point: the chat loop and its commands, the answer call (system prompt, LLM call, printing), conversation memory and the token line |
| `router.py` | The non-question check, keyword routes (levels, severity words, agent names), the status bundle and the LLM tool-calling fallback |
| `skills_wazuh.py` | The Wazuh skills and their helpers (alert detail lines, fix status), plus `overview` |
| `skills_netdata.py` | The Netdata skills and their helper |
| `privacy.py` | Agent aliasing, finding agent names in a question, and vulnerability redaction |
| `common.py` | What the others share: `.env` loading and config, the Groq client and the LLM call (reasoning effort, token breakdown), the Wazuh indexer query, the `@skill` registry and the result cache |
| `tests/` | pytest tests for the pure functions (no network) |

The order in which skills are registered is the order of the tool list the LLM router sees, so
it is fixed: `router.py` imports `skills_wazuh` before `skills_netdata`.

## Skills

A skill is a Python function that queries one source and returns a compact text block (one line
per item). They are registered with the `@skill` decorator (defined in `common.py`) in
`skills_wazuh.py` and `skills_netdata.py`.

| Skill | Direct | Returns |
|---|---|---|
| `overview` | no | Netdata alarm counts and Wazuh alert counts per level |
| `critical_alerts` | yes | Every Wazuh alert at level 12 or above, with time, agent, rule and description |
| `alerts_by_level(level)` | yes | The `critical_alerts` detail for one level |
| `alerts_in_range(min, max)` | yes | The same detail for a range of levels |
| `vulnerabilities` | yes | Vulnerability-detector (CVE) findings at any level |
| `mitre_tags` | yes | Alert count per MITRE technique, with the rule generating most of each |
| `top_rules(n=5)` | yes | The rule IDs with the most alerts, with description and count |
| `agent_activity(agent)` | yes | One agent's alert count per level and its top 5 rules |
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

0. **Is it a question?** An input with no "?" that is only acknowledgement words ("ok",
   "thanks"), or that opens like a remark about what you did ("finished that", "patched it",
   "I'll do it later"), gets one fixed line. Nothing is fetched and nothing is sent. The check is
   narrow on purpose: terse queries such as "cves" or "status" still run, and adding a "?" always
   makes an input a question.
1. **Keywords, no LLM call.** Regexes in `router.py` pick the skill(s):
   - **Levels:** "level 13", "lvl 13", "l13", and the plural shorthand "level 8s", "lvl 8s" or
     "the 8s" run `alerts_by_level`. A bare "8s" only counts straight after "the", "level" or
     "lvl", and only for 0 to 16, so "the last 10s" is not a level.
   - **Severity words**, using Wazuh's bands: low 0-6, medium 7-11, high 12-14. "medium alerts"
     runs `alerts_in_range(7, 11)`. The words only count next to "alerts", "events", "ones",
     "severity" or "priority", so "is cpu high?" is not a level.
   - **"critical"** (or "severe") runs `critical_alerts`, which is level 12 and above. The
     exception is "critical alarm", which is Netdata's.
   - **Agent names:** a question that names a known Wazuh agent ("what happened on web-01
     today?") runs `agent_activity` for it. The agent list is loaded from the indexer on the
     first question of a session.
   - **Topics:** "memory" runs `container_stats`, "tag" runs `mitre_tags`, "cves" runs
     `vulnerabilities`, and so on (`KEYWORD_ROUTES`).

   Vague status questions ("anything to note?", "what's up", "status", "how is the server") run
   the bundle `overview` + `critical_alerts` + `netdata_alarms` + `attack_alerts`.
2. **Follow-ups.** If no keyword matches and the question refers back with "that", "it",
   "this", "those" or "them" ("is that worth worrying about?"), the previous question's skills
   run again and the routing line says `follow-up`. No router call is made. The answer always
   comes from the LLM, so the data goes out redacted even if the previous answer was direct.
   With no previous question, it goes to step 3.
3. **LLM tool-calling.** If no keyword matches, one extra LLM call chooses the skill(s). If the
   model rejects tool-calling, the script says so and sends only `overview` for the rest of the
   session.

A question runs at most three skills (four for the status bundle). Before each answer the script
prints which skills ran and how they were chosen.

Skills are not
combined: "critical alerts on web-01" runs `critical_alerts` for every agent and
`agent_activity` for web-01, not a filtered query.

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
[tokens: 720 total — router 0, answer 720: prompt 639, completion 81 (reasoning 19)]
```

The prompt, completion and reasoning counts are printed when the API reports them. Reasoning
tokens are part of the completion count, not extra.

Whenever a skill's output is going to the LLM, its vulnerability findings are **redacted**: each
becomes a label, a level and a count, with no package name, version or CVE ID:

```
  - L13 VULNERABILITY FINDING, not an attack: 1 CVE (ask 'cves' for details)
```

That applies to the status bundle, to keyword routes that mix a direct skill with a non-direct
one, and to anything the LLM router picks. If the model's answer does not point to `cves`, the
script prints a one-line hint itself. Asking `cves` runs `vulnerabilities` directly, which shows
the full detail without an LLM call.

## Conversation memory

The last two question/answer pairs are kept so a follow-up has something to refer to. They are
added to LLM **answer** calls only, never to routing calls. Which data a follow-up fetches is
decided separately, by the follow-up rule under [Routing](#routing). Each question and each answer is aliased first
and then cut to 300 characters. A direct answer is remembered as a note naming the skills that
ran, never as its output, because that output is unredacted. Non-questions and commands are not
remembered.

## Reasoning effort and tokens

Every LLM call sends `reasoning_effort`, set by `GROQ_REASONING_EFFORT` (default `low`). Groq
documents `low`, `medium` and `high` for the GPT-OSS models. Set the variable empty to send
nothing and get the model's own default. If a model rejects the setting, the script says so
and carries on without it for the rest of the session.

Measured on `openai/gpt-oss-20b` with "anything to note?" (three runs each, same 554-token
prompt):

| Setting | Total | Completion | Of which reasoning |
|---|---|---|---|
| not sent (model default) | 818-873 | 264-319 | 51-219 |
| `low` | 622-645 | 68-91 | 4-14 |

## What is sent to Groq

**Nothing**, when a question is answered directly.

**Otherwise, per LLM call:**

- The fixed system prompt from the code.
- Your question, as typed, with agent names aliased.
- The `reasoning_effort` setting, if one is set.
- For a routing call: each skill's name, description and parameter names. No data.
- For an answer call: the last two question/answer pairs (see
  [Conversation memory](#conversation-memory)), aliased and cut to 300 characters each, and the
  output of the skills that ran, with agent names aliased. Depending on the skills, that is:
  - alert counts per level, and Netdata alarm counts, names and values;
  - alert lines: time, agent alias, rule ID, level, Wazuh's rule description and a repeat count;
  - for `attack_alerts`, one example per rule: the request URL or, failing that, the start of
    the log line, cut to 80 characters;
  - for `agent_activity`, the agent's alias, its alert counts per level and its top five rules
    (ID, level, description, count);
  - container names with CPU and memory figures;
  - MITRE technique names;
  - vulnerability findings in redacted form only: the label, the alert level and the number of
    CVEs at that level.

**Never sent:**

- Vulnerability details: package names, installed versions, CVE IDs and fix status. In
  `top_rules`, `mitre_tags` and `agent_activity`, the description of a vulnerability-detector rule (which names the
  CVE and package) is replaced with "details withheld".
- Real Wazuh agent names. Each is replaced with an alias (`agent-1`, `agent-2`, ...) taken from
  its Wazuh agent ID, so aliases are the same every session. The reply's aliases are swapped
  back before printing, so you see real names. Direct output shows real names because it never
  leaves the machine. If the LLM router picks `agent_activity`, it names the agent by alias and
  the script swaps the real name back in before querying.
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
- The agent list is loaded from the indexer once per session, on the first question. If that
  fails the script prints a warning and tries again on the next question; until it loads, agent
  names are not recognised for routing and one typed in a question is sent as typed.

## Commands

- `refresh` — skill results are reused for 120 seconds; `refresh` drops that cache so the next
  question pulls fresh data. It does not fetch anything itself.
- `raw` — print the output of the skills that ran for the last question, as fetched, with real
  agent names. After an LLM answer this is the redacted text the model was given. It fetches
  nothing and sends nothing.
- `quit` (or `exit`, `q`) — leave.

## Configuration

Secrets follow the repo's [secrets approach](../../docs/secrets-approach.md): copy
`.env.example` to `.env` (gitignored) and fill it in. A variable set in your shell overrides
the value in `.env`. The `.env` is read from this folder (next to `common.py`), whatever
directory you run the script from.

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
| `GROQ_REASONING_EFFORT` | no | `low` |

`GROQ_MODEL` should be a model that supports tool-calling; without it, questions that match no
keyword only get the overview.

## Where it runs

The defaults assume the script runs on the K16 itself, where Netdata and the Wazuh indexer are
reachable on `localhost`. To run it from another device, set `NETDATA_URL` and
`WAZUH_INDEXER_URL` to the K16's tailnet IP instead.

The Wazuh indexer uses a self-signed certificate, so TLS verification is disabled for those
requests — see the comment in `common.py` for the tradeoff.

## Dependencies

Python 3 plus:

```
pip install -r requirements.txt
```

- `openai` — client for Groq's OpenAI-compatible API
- `requests` — Netdata and Wazuh indexer HTTP calls
- `python-dotenv` — loads `.env`

## Tests

```
pip install -r requirements-dev.txt
python -m pytest tests
```

The tests cover the pure functions only: keyword routing (levels and their shorthand, severity
bands, agent names), follow-ups, the non-question check, the fix-status wording, alias swap and swap-back,
vulnerability redaction, the agent-activity text, conversation memory and the token line. They make no network calls (`requests` is blocked
in `tests/conftest.py`) and need neither `.env` nor a real `GROQ_API_KEY`.
