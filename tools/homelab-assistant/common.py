"""Shared plumbing: config, the Groq client, the Wazuh indexer query and the skill registry.

Everything here is imported by more than one of the other modules, which is why it
lives below them: privacy.py and skills_wazuh.py both query the indexer, and the router
and the entry point both read the registry.
"""
import os
import time
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv
from openai import BadRequestError, OpenAI

# Load secrets from the .env next to this file (gitignored; see .env.example).
# override=False (the default) means a real shell env var still wins over .env.
load_dotenv(Path(__file__).with_name(".env"))

# --- config (env-overridable) ---
NETDATA = os.environ.get("NETDATA_URL", "http://localhost:19999")
WAZUH_INDEXER = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")          # set in env — do NOT hardcode
WAZUH_WINDOW = os.environ.get("WAZUH_WINDOW", "now-24h")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")
# Sent as reasoning_effort on every LLM call (Groq: low/medium/high for the GPT-OSS
# models). Set it empty to leave the model's own default.
GROQ_REASONING_EFFORT = os.environ.get("GROQ_REASONING_EFFORT", "low").strip()

CRIT_LEVEL = 12          # critical_alerts covers every alert at or above this level
DETAIL_MAX_LINES = 20    # cap on alert detail lines sent to the LLM (token budget)
DETAIL_FETCH = 500       # raw docs pulled before dedup; repeats collapse to one line
MAX_SKILLS = 3           # most skills one question may run
CACHE_TTL = 120          # seconds a skill result is reused; 'refresh' clears it

# Wazuh indexer ships a self-signed cert, so we skip TLS verification.
# TRADEOFF (real, not boilerplate): verify=False turns off cert checking entirely.
# Fine for you->your own box over the tailnet/LAN; it means zero protection against a
# man-in-the-middle on that path. Don't reuse this pattern for anything crossing an
# untrusted network. The honest fix later is trusting the indexer's CA instead.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=os.environ["GROQ_API_KEY"])

_effort = GROQ_REASONING_EFFORT     # cleared for the session if the model rejects it


def llm_call(**kwargs):
    """client.chat.completions.create, plus the reasoning effort while the model takes it."""
    global _effort
    if _effort:
        try:
            return client.chat.completions.create(**kwargs, reasoning_effort=_effort)
        except BadRequestError as e:
            if "reasoning_effort" not in str(e):
                raise
            print(f"[llm] model {GROQ_MODEL} rejected reasoning_effort={_effort} ({_clip(e, 160)}). "
                  "Continuing without it for the rest of this session.")
            _effort = ""
    return client.chat.completions.create(**kwargs)


def _usage_breakdown(usage):
    """'prompt 900, completion 251 (reasoning 120)' from an API usage object.

    Only the parts the API reported; '' if none. Reasoning tokens are part of the
    completion count, not extra.
    """
    parts = []
    prompt = getattr(usage, "prompt_tokens", None)
    if prompt is not None:
        parts.append(f"prompt {prompt}")
    completion = getattr(usage, "completion_tokens", None)
    reasoning = getattr(getattr(usage, "completion_tokens_details", None), "reasoning_tokens", None)
    if completion is not None:
        parts.append(f"completion {completion}" + (f" (reasoning {reasoning})" if reasoning is not None else ""))
    elif reasoning is not None:
        parts.append(f"reasoning {reasoning}")
    return ", ".join(parts)


# --- skill registry ---
# A skill is a plain function: simple (integer or string) arguments in, compact text block out —
# one line per item, no raw logs, no JSON. The description and params double as the
# tool schema the LLM router sees, so keep them short: they cost tokens on every
# LLM-routed question.
SKILLS = {}


def skill(description, direct=False, redactable=False, **params):
    """Register a skill. params: name -> (description, required) for an integer,
    or (description, required, "string").

    direct=True: the output is readable as-is, so a question that keyword-routes to
    only direct skills is answered by printing it — no LLM call, nothing sent.
    redactable=True: the skill can show vulnerability findings, so it takes
    redact=True and is always called that way when its output is going to the LLM.
    """
    def register(fn):
        SKILLS[fn.__name__] = {"fn": fn, "description": description, "direct": direct,
                               "redactable": redactable, "params": params}
        return fn
    return register


def _clip(text, n):
    text = " ".join(str(text).split())      # collapse newlines/runs of spaces -> one line
    return text if len(text) <= n else text[:n - 3] + "..."


def _unavailable(what, e):
    # The full error stays on this machine: it can carry the indexer or Netdata
    # address. Only the error type goes into skill output, which may reach the LLM.
    print(f"[error] {what}: {_clip(e, 200)}")
    return f"[{what} unavailable: {type(e).__name__}]\n"


def _wazuh_search(body):
    r = requests.post(f"{WAZUH_INDEXER}/wazuh-alerts-*/_search", json=body,
                      auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=15)
    r.raise_for_status()
    return r.json()


def _in_window(*filters):
    return {"bool": {"filter": [{"range": {"@timestamp": {"gte": WAZUH_WINDOW}}}, *filters]}}


# --- running skills ---
_cache = {}


def _label(name, args):
    return f"{name}({', '.join(f'{k}={v}' for k, v in args.items())})"


def run_skill(name, args, redact=False):
    # redact=True whenever the output is going to the LLM.
    redact = redact and SKILLS[name]["redactable"]
    key = (name, tuple(sorted(args.items())), redact)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    # Each skill is isolated so one source being down doesn't kill the others.
    try:
        text = SKILLS[name]["fn"](**args, **({"redact": True} if redact else {}))
    except Exception as e:
        return _unavailable(name, e)                # not cached — retry next question
    _cache[key] = (time.time(), text)
    return text
