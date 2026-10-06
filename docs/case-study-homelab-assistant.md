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
- **Interactive loop:** keep asking questions until you type `quit`. `refresh` pulls a fresh
  copy of the live data.

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

With the free hosted brain, **every prompt goes to Groq, along with the server data
summarized into it.** For resource stats (container names, CPU percentages, memory usage) that's
an acceptable trade-off. For **Wazuh security data**, which is on the roadmap, it's a different
question. Security alerts can include hostnames, IPs, usernames, file paths, and details of
what's vulnerable, and sending all of that to an outside API deserves a deliberate decision
rather than happening by default.

The swappable-brain design keeps this open. Before the Wazuh integration, the plan is to
either move the brain to a self-hosted model on a future discrete GPU (the K16's integrated
GPU can't do usable local inference; see the Odysseus section above) or carefully limit what
security data goes into the prompt.

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
| **Data is a snapshot** from startup | Answers go stale unless you type `refresh` | Auto-refresh on each question, or when the snapshot gets older than N seconds |
| **Wazuh** isn't integrated yet | No security view, which is the SOC-portfolio angle | Feed Wazuh alerts in, *after* settling the privacy question in Part 3 |

**Eventual goal: tool calling.** Right now the assistant always fetches the same fixed data
set and sends all of it. With tool calling, the brain chooses what to fetch based on the
question: container status for "is X running?", Wazuh alerts for "anything suspicious
today?", and so on. Even then, each tool stays deterministic code I wrote and checked. The
LLM decides *which* tool to call, never *what the data says*.

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
