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
  output is readable as-is (the alerts at a level or in a range of levels, CVE findings, top
  rules, MITRE tags, one agent's activity, container stats, Netdata alarms), the script prints
  that output and makes no LLM call.
- **Non-questions send nothing.** An input like "ok" or "finished that" gets a fixed reply
  with no data fetched and no LLM call (Part 7).
- **Vulnerability findings go out only as a label, a level and a count.** Whenever a skill's
  output is headed for the LLM, each vulnerability-detector finding is reduced to a line like
  `L13 VULNERABILITY FINDING, not an attack: 1 CVE`. Package names, installed versions and CVE
  IDs stay on the machine. The full detail is one direct question away. Where a skill lists
  rules by description (top rules, MITRE tags, one agent's activity), a vulnerability-detector
  rule's description is replaced with "details withheld".
- **Wazuh agent names are replaced by aliases.** Each agent's hostname becomes `agent-N`
  (taken from its Wazuh agent ID) in the data, the question and the remembered conversation
  before anything is sent. The aliases in the reply are swapped back before printing, so I see
  real names and Groq never does.
- **Direct output never enters the conversation memory.** A direct answer is remembered only
  as a note naming the skills that ran (Part 7).
- **Never sent:** the values in `.env`, the indexer and Netdata addresses, and the text of
  connection errors (only the error type goes into skill output).

**What still goes out when an LLM call is made:** the question as typed, alert counts, alert
lines (time, agent alias, rule ID, level, Wazuh's rule description, repeat count), one agent's
alert counts per level and its top five rules (under its alias), MITRE technique names,
container names with their CPU and memory figures, and Netdata alarm names and values. Two
things were added in Part 7. Answer calls also carry the last two question/answer pairs,
aliased and cut to 300 characters each. Every call carries a `reasoning_effort` setting,
which is a fixed word from my config and holds no data.

**Remaining limits:**

- **Ordinary rule descriptions are sent as written,** and some of them name software. A
  Windows "application uninstalled" event, for example, carries the product name and version.
  Only vulnerability-detector findings are redacted.
- **The attack view sends one example per rule:** the request URL or, failing that, the first
  80 characters of the log line. That can carry an IP, a username or a path.
- **The aliasing covers Wazuh agent names only.** Container names, and any hostname that
  isn't an agent's name, go out as they are.
- **Earlier questions are sent again.** With conversation memory, whatever I typed in the
  last two questions goes out with the next LLM answer call too, along with the model's own
  earlier answers.
- **A follow-up can send what a direct answer kept local.** "Is that worth worrying about?"
  after a direct answer re-runs the same skills for the LLM. The output goes out redacted and
  aliased, but it does go out.

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
| ~~**No conversation memory**~~ | ~~Each question stands alone, so follow-ups like "and what about yesterday?" don't work~~ | **Resolved; see Part 7.** The last two question/answer pairs go with each LLM answer call, and a follow-up such as "is that worth worrying about?" reuses the previous question's skills. "Yesterday" is still out of reach: every skill reads one fixed time window |
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

## Part 7: Modules, tests, memory and reasoning effort

### Split into modules, with tests

The script had grown to about 740 lines in one file. It is now six modules, still started with
`python homelab_assistant.py`:

| File | Contents |
|---|---|
| `homelab_assistant.py` | The chat loop, the answer call, conversation memory |
| `router.py` | The non-question check, keyword routes, follow-ups, the LLM tool-calling fallback |
| `skills_wazuh.py`, `skills_netdata.py` | The skills and their helpers |
| `privacy.py` | Agent aliasing and vulnerability redaction |
| `common.py` | Config, the Groq client, the indexer query, the skill registry and cache |

The split was meant to change nothing. To check that, I ran the same four questions through
the old and new code against the live stack and compared the routing, the output of the
direct answers and the exact text passed to the LLM. They matched.

The pure functions now have pytest tests: 177 of them, covering keyword routing, severity
bands, level shorthand, the non-question check, follow-ups, the fix-status wording, alias swap
and swap-back, and redaction. They make no network calls (the test setup blocks `requests`)
and need neither a `.env` nor a real API key. This is the payoff of keeping the data work in
code: the parts that decide what is fetched and what is sent can be tested without the LLM.

### New skills

- **`alerts_in_range(min, max)`** backs the severity words, using Wazuh's bands: low 0-6,
  medium 7-11, high 12-14. "What were the medium alerts?" runs `alerts_in_range(7, 11)`.
  "Critical" still runs `critical_alerts`, which is level 12 and above.
- **`agent_activity(agent)`** returns one agent's alert count per level and its top five rules.
  A question that names a known Wazuh agent routes to it.
- **Level shorthand.** "The 8s" and "level 8s" now mean level 8.

Both skills are direct, so on their own they cost 0 tokens and send nothing.

### A fixed reply for non-questions

Typing "ok" or "finished that" used to be handled like any other input. In an earlier
session, "finished that" cost 1,353 tokens (828 for routing, 525 for the answer) for a reply
nobody needed. Now an input with no "?" that is only acknowledgement words, or that opens
like a remark about what I did, gets one fixed line. Measured on "finished that" now: no data
call and no LLM call. The check is narrow on purpose.
Terse queries such as "cves" or "status" still run, and adding a "?" always makes an input a
question.

### Conversation memory

The script keeps the last two question/answer pairs.

**What it sends:** on an LLM *answer* call, those pairs go in ahead of the data, each question
and each answer aliased first and then cut to 300 characters.

**What it does not send:**

- Nothing on a routing call. The tool-calling router still sees only the current question.
- Nothing on a direct answer, because there is no call.
- Never a direct answer's output. That output is unredacted, so the memory holds only a note
  naming the skills that ran.
- Non-questions and commands are not remembered at all.

Memory alone did not fix follow-ups. It gave the model the earlier question, but the *data*
for a follow-up was still chosen by the router, which doesn't see the memory. In one run,
"is that worth worrying about?" went to the LLM router, got the overview counts, and cost
1,190 tokens (635 for routing, 555 for the answer) for a muddled reply. The fix was a rule in
code: if a question matches no keyword and refers back with "that", "it", "this", "those" or
"them", it reuses the previous question's skills and skips the router. After "what about the
8s?", the same follow-up now re-runs the level 8 alerts and costs 720 tokens with no routing
call. Its answer always comes from the LLM, so the data goes out redacted (see Part 3).

A new `raw` command prints the skill output behind the last answer, which makes it easy to
see exactly what the model was given.

### Reasoning effort

`openai/gpt-oss-20b` is a reasoning model, and Groq's docs list a `reasoning_effort` setting
for it (`low`, `medium`, `high`). The script now sends it on every call, from the
`GROQ_REASONING_EFFORT` variable, defaulting to `low`. The token line also splits out what the
API reports: prompt, completion, and the reasoning tokens inside the completion count.

Measured on "anything to note?", three runs each, with the same 554-token prompt:

| Setting | Total tokens | Completion | Of which reasoning |
|---|---|---|---|
| Not sent (model default) | 867, 873, 818 | 313, 319, 264 | 97, 219, 51 |
| `low` | 622, 630, 645 | 68, 76, 91 | 8, 14, 4 |

That is roughly a quarter fewer tokens per answer. About half of the drop is reasoning tokens
and about half is the answers themselves getting shorter.

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
