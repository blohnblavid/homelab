# Case Study: A Natural-Language Homelab Assistant (v1)

## Summary

Netdata already answers "what is the server doing?", but only if you go and read the
dashboard. The goal here was to ask the homelab questions in plain English, like "is anything
unhealthy?" or "what's eating CPU right now?", and get a plain-English answer back. The first
working version is a Python script running on the K16. It pulls live data from Netdata's REST
API, summarizes it in code, and hands that summary to a hosted LLM (Groq's free,
OpenAI-compatible API), which writes the answer.

The main design rule is **separation of concerns**: my code does the data work (fetching and
summarizing), and the LLM only does the language work (phrasing the answer). The LLM never
decides what's true about the server. It only turns numbers my code already computed into
sentences.

## From Odysseus to the homelab assistant

The first attempt at local AI in the lab was **Odysseus**, a self-hosted assistant running local models through Ollama. It ran into a hard hardware limit: the K16's integrated Radeon 680M (gfx1035) isn't supported by ROCm, which Ollama depends on for AMD GPU acceleration — so inference fell back to CPU and was too slow to be practical. Early testing showed response times far too slow to be usable.

Rather than buy a discrete GPU immediately, the design pivoted: separate the "brain" from the "assistant." The assistant (orchestration code that knows the lab and fetches its live data) runs fine on the K16 — it's lightweight. The brain (the LLM) is a swappable, OpenAI-compatible endpoint, currently Groq's free hosted API. Because the interface is standardized, the brain can later move to a self-hosted model on dedicated GPU hardware with a one-line change — no rewrite. Odysseus was retired; its lesson (local inference needs real GPU hardware this host doesn't have) shaped the architecture that replaced it.

## Part 1: Architecture

```
  question ──► assistant.py ──► Netdata REST API (alarms, per-container CPU/memory)
                    │
                    ▼
            summarize in code
                    │
                    ▼
       LLM "brain" (Groq, OpenAI-compatible API) ──► plain-English answer
```

- **Data layer (my code):** pulls Netdata's alarms (health status) and per-container CPU and
  memory stats, then reduces them to a compact text summary.
- **Language layer (the brain):** gets the summary plus the user's question and phrases the
  answer. Currently `openai/gpt-oss-20b` on Groq's free tier.
- **Interactive loop:** keep asking questions until you type `quit`. Fetched results are reused
  for 120 seconds. `refresh` clears that cache, so the next question fetches fresh data; it
  does not fetch anything itself. (In v1 it re-pulled a startup snapshot; see Part 6 for what
  replaced that.)

### The brain is swappable

Groq, self-hosted model servers, and most other providers all speak the OpenAI-compatible chat
completions API, so changing providers only means changing the `base_url` and `api_key`. Nothing
else in the assistant has to change. That matters for the privacy question in Part 3: moving
to a self-hosted model on future dedicated GPU hardware is a config change, not a rewrite.

## Part 2: What works

- Fetches Netdata alarms and per-container CPU and memory stats.
- Answers free-form questions about current health and resource usage.
- **Catches real anomalies.** Without being asked about any particular container, it flagged
  one running above 120% of a core. That's the behavior that makes this worth building: it
  noticed something I wasn't looking for.
- Runs at zero cost on Groq's free tier.

## Part 3: Privacy note: the brain is a third party

With the free hosted brain, **whatever goes into a prompt goes to Groq.** For resource stats
(container names, CPU percentages, memory usage) that's an acceptable trade-off. For **Wazuh
security data** it's a different question. Security alerts can include hostnames, IPs,
usernames, file paths, and details of what's vulnerable, and sending all of that to an outside
API deserves a deliberate decision rather than happening by default.

The plan had two options: move the brain to a self-hosted model on a future discrete GPU (the
K16's integrated GPU can't do usable local inference; see the Odysseus section above), or
carefully limit what security data goes into the prompt. When Wazuh went in (Part 6), I took
the second. This is what the code does now.

**What is held back:**

- **Direct answers send nothing.** When the keywords route a question only to skills whose
  output is readable as-is (the alerts at a level, CVE findings, top rules, MITRE tags,
  container stats, Netdata alarms), the script prints that output and makes no LLM call.
- **Vulnerability findings go out only as a label, a level and a count.** Whenever a skill's
  output is headed for the LLM, each vulnerability-detector finding is reduced to a line like
  `L13 VULNERABILITY FINDING, not an attack: 1 CVE`. Package names, installed versions and CVE
  IDs stay on the machine. The full detail is one direct question away.
- **Wazuh agent names are replaced by aliases.** Each agent's hostname becomes `agent-N`
  (taken from its Wazuh agent ID) in both the data and the question before anything is sent.
  The aliases in the reply are swapped back before printing, so I see real names and Groq
  never does.
- **Never sent:** the values in `.env`, the indexer and Netdata addresses, and the text of
  connection errors (only the error type goes into skill output).

**What still goes out when an LLM call is made:** the question as typed, alert counts, alert
lines (time, agent alias, rule ID, level, Wazuh's rule description, repeat count), MITRE
technique names, container names with their CPU and memory figures, and Netdata alarm names
and values.

**Remaining limits:**

- **Ordinary rule descriptions are sent as written,** and some of them name software. A
  Windows "application uninstalled" event, for example, carries the product name and version.
  Only vulnerability-detector findings are redacted.
- **The attack view sends one example per rule:** the request URL or, failing that, the first
  80 characters of the log line. That can carry an IP, a username or a path.
- **The aliasing covers Wazuh agent names only.** Container names, and any hostname that
  isn't an agent's name, go out as they are.

This was a deliberate tradeoff for a homelab: one user, my own data, and a free hosted model
I can swap out. In a workplace it would not be my call. Sending SIEM data to an outside LLM
would need approval first, however much of it is redacted. The swappable-brain design keeps
the other option open: a self-hosted model would make most of this section unnecessary.

## Part 4: Gotchas (these cost real time)

### Groq rotates its model catalog

The first model IDs I tried, older `llama-3.x` names, returned 404s. Groq deprecates and
replaces models regularly, so model names from tutorials, blog posts, or an LLM's memory go
stale fast. **Fix:** don't guess. Ask the API for its current list:

```bash
curl -s https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer $GROQ_API_KEY"
```

and pick a model ID from that response.

### Netdata cgroup memory is already in MB

The first version divided container memory by `1024²` to "convert bytes to MB", and every
container showed `0.0` MB. Netdata's cgroup memory values **are already in MB**, so the extra
conversion shrank real numbers to roughly zero. **Fix:** use the values as returned. In general,
check the units in the API response (Netdata includes them in its chart metadata) before
converting anything.

A related lesson: the brain answered just as confidently about all-zero memory as it would
about real data. An LLM can't catch a units bug in the numbers it's given, which is one more
reason to keep the data work in code where it can be checked.

### The API key stays out of the file

The key is read from the `GROQ_API_KEY` environment variable and is never written into the
script. This repo is public, and hardcoded API keys pushed to public GitHub repos get scraped
by bots within minutes. It's the same approach as everywhere else in the repo (see
[`secrets-approach.md`](secrets-approach.md)), and the pre-commit gitleaks hook backs it up.

## Part 5: Known limitations and roadmap

| Limitation | Effect | Next step |
|---|---|---|
| Only the **top 5 containers** by CPU/memory are sent to the brain | Idle services are invisible. "Is Minecraft running?" can't be answered when the lazymc container is idling and doesn't make the top 5 | Use Netdata's `docker:container-ls` function to get the full container list with presence and status |
| **No conversation memory** | Each question stands alone, so follow-ups like "and what about yesterday?" don't work | Keep a short message history in the loop |
| ~~**Data is a snapshot** from startup~~ | ~~Answers go stale unless you type `refresh`~~ | **Resolved; see Part 6.** Nothing is fetched at startup. Each question fetches what it needs, and results are reused for at most 120 seconds |
| ~~**Wazuh** isn't integrated yet~~ | ~~No security view, which is the SOC-portfolio angle~~ | **Resolved; see Part 6.** Wazuh alerts come in through skills, with the privacy limits described in Part 3 |

**Eventual goal: tool calling. Done; see Part 6.** The original plan read: right now the
assistant always fetches the same fixed data set and sends all of it. With tool calling, the
brain chooses what to fetch based on the question: container status for "is X running?", Wazuh
alerts for "anything suspicious today?", and so on. Even then, each tool stays deterministic
code I wrote and checked. The LLM decides *which* tool to call, never *what the data says*.

## Part 6: Skills and hybrid routing

The earlier versions sent one big summary with every question: every count and every section,
whether or not the question needed it. That costs tokens on every call, and the summary only
grew as more data went into it. Asking "what was the level 13 alert?" cost 1,193 tokens, most
of it data the question never touched.

The fix was to split the data work into **skills**: small Python functions that each query one
thing (alert counts per level, the alerts at one level, attack-group alerts, per-container
stats, active Netdata alarms, and so on) and return a few compact lines. A question now fetches
only the skills it needs, and only their output goes to the brain.

```
  question ──► keyword match in code ──► skill(s) ──► LLM writes the answer
                    │ no match                ▲
                    ▼                         │
          LLM tool-calling picks the skill(s) ┘
```

Choosing the skills is **hybrid**:

1. **Keywords first.** A regex match in code picks the skill with no LLM call. "level 13"
   runs `alerts_by_level(13)`; "memory" runs `container_stats`.
2. **LLM tool-calling as the fallback.** If nothing matches, one extra LLM call picks the
   skill(s) through tool calling.

Then a single LLM call writes the answer from the chosen skills' output. The script prints
which skills ran and how they were chosen before each answer, so the routing is visible.

**Result:** the same level 13 question now costs about 700 tokens, down from 1,193.

Keywords go first because the fallback is not free. The routing call spends tokens of its own
(715 in one measured run), so a question that needs it can cost more than the old single call
did. The cheap path has to be the common one.

### Direct answers

Many questions are really list requests: "any CVEs I should patch?", "what are the level 8
alerts?", "what's using the most memory?". A skill's output is already one readable line per
item, so having the LLM rephrase it buys little and costs a call. Skills whose output reads
fine as-is are flagged **direct**. When the keywords route a question only to direct skills,
the script prints the output and stops, with no LLM call.

**Result:** list questions cost 0 tokens and send nothing. That was measured on the three
questions above. The level 13 question is now one of them too: 1,193 tokens at the start,
about 700 with skills, 0 now.

Questions that need the LLM still get it. "Anything to note?" runs four skills and has the
brain write the summary, which cost 891 tokens in one measured run. A question the keywords
can't place goes to the tool-calling fallback. Part 3 covers what those calls do and don't
send.

The rule from the Summary still holds. Every skill is deterministic code I wrote and checked.
The router, whether regex or LLM, decides *which* skill runs, never *what the data says*.

## Takeaways

- **Keep the LLM on language, not facts.** Fetching and summarizing in code makes the
  answers only as good as code I can test. The model's job is to make that output readable.
- **Design for a swappable brain from day one.** Targeting the OpenAI-compatible API made the
  provider a config choice. That keeps costs flexible and turns the privacy decision into a
  config change.
- **Hosted models change underneath you.** Treat model IDs as runtime data to look up from the
  provider's own `/models` endpoint, not constants to remember.
- **Check the units before converting.** The all-zeros memory bug came from assuming bytes
  without reading the API's own metadata.
- **"Free" hosted inference costs privacy.** Fine for CPU graphs, but it needs a deliberate
  decision before security telemetry goes through it.
