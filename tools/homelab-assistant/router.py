"""Chooses which skill(s) answer a question: keywords first, the LLM only if none match."""
import json
import re

from openai import BadRequestError

import skills_wazuh    # noqa: F401 — importing registers the skills; Wazuh first, then
import skills_netdata  # noqa: F401   Netdata: that is the order of the LLM's tool list
from common import GROQ_MODEL, MAX_SKILLS, SKILLS, _clip, _label, llm_call
from privacy import _agents_named, _from_llm, _known_agents, _to_llm

# Step 0: is it a question at all? "ok", "thanks" or "finished that" gets a fixed reply
# and nothing is fetched or sent. Deliberately narrow: only a "?"-free input that is
# all acknowledgement words, or that opens (after any of those) like a remark about
# what the user did, counts. Everything else — questions, requests, terse queries such
# as "cves", "status" or "disk space" — goes on to routing.
_FILLER_RE = re.compile(
    r"^(?:ok(?:ay)?|kk?|thanks(?: a lot| very much)?|thank you(?: very much)?|thx|ty|cheers|great|good"
    r"|nice|cool|perfect|awesome|got it|gotcha|understood|noted|alright|right|yes|yep|yeah|no|nope"
    r"|sure|fine|hi|hello|hey|well|so|and|then|now|also|please|pls)\b[\s,.!;:-]*")
_STATEMENT_RE = re.compile(
    r"^(?:i|im|ive|we|that's|thats|it's|(?:that|it|this) (?:worked|works|helps|helped|did it)"
    r"|makes sense|sounds good|will do|all (?:good|done|set|sorted)|never ?mind|nvm"
    r"|no (?:worries|problem)|done|finished|fixed|patched|updated|upgraded|restarted|rebooted"
    r"|resolved|sorted|completed|handled|applied)\b")
STATEMENT_REPLY = "Nothing to look up there. Ask a question (end it with '?') when you want data."


def is_statement(text):
    """True for an acknowledgement or a remark about what the user did; False if unsure."""
    q = " ".join(text.lower().replace("’", "'").split())
    if not q or "?" in q:
        return False
    while q:
        if _STATEMENT_RE.match(q):  # checked before the fillers: "no worries", "will do"
            return True
        m = _FILLER_RE.match(q)
        if not m:
            return False            # a question, a request or a terse query
        q = q[m.end():]
    return True                     # nothing but "ok", "thanks", ...


# Step 1: keyword/regex match in code — no LLM call. Every pattern that matches adds
# its skill. Keep these specific: a question that matches nothing still gets routed
# (by the LLM), but a wrong match here silently fetches the wrong data.
# Levels: "level 8", "lvl 8", "l8", and the plural shorthand "level 8s", "lvl 8s",
# "the 8s". A bare "8s" needs "the", "level" or "lvl" in front: "the last 10s" is a
# duration, not a level.
LEVEL_RE = re.compile(r"\b(?:level|lvl)[\s-]*(\d{1,2})(?:'?s)?\b|\bl(\d{1,2})(?:'?s)?\b|\bthe\s+(\d{1,2})'?s\b")
# Severity words, using Wazuh's bands. "low", "medium" and "high" are ordinary words, so
# they only count next to "alerts"/"events"/"ones" or "severity"/"priority" ("high cpu"
# is not a level). "critical" is not a band here: it routes to critical_alerts below.
SEVERITY_BANDS = {"low": (0, 6), "medium": (7, 11), "high": (12, 14)}
_BAND = r"(?:low|medium|high|critical)"   # "critical" only so "high or critical alerts" reads as a list
SEVERITY_RE = re.compile(
    rf"\b{_BAND}(?:(?:\s*[,/&]\s*|\s+(?:and|or)\s+){_BAND})*"
    rf"(?:[\s-]+(?:severity|priority|level))?[\s-]+(?:alerts?|events?|ones)\b"
    rf"|\b{_BAND}[\s-]+(?:severity|priority)\b")
TOP_N_RE = re.compile(r"\btop[\s-]*(\d{1,2})\b")
KEYWORD_ROUTES = [
    (r"\bcritical\b(?!\s+alarm)|\bsevere\b", "critical_alerts"),
    (r"\bcves?\b|vulnerab|\bpatch", "vulnerabilities"),
    (r"attack|intrus|exploit|brute|\bscan|sql ?inj|sqli|hack|breach|compromis|\brecon", "attack_alerts"),
    (r"\bmemory\b|\bram\b|\bcpu\b|container|docker", "container_stats"),
    (r"\balarms?\b|netdata", "netdata_alarms"),
    (r"\bmitre\b|\btechniques?\b|\btags?\b", "mitre_tags"),
    (r"\btop[\s-]*\d*\s*rules?\b|most (?:frequent|common|alerts)|nois(?:y|iest)|which rules?\b", "top_rules"),
]
# Vague "how are things?" questions get a fixed bundle: counts, plus the detail behind
# anything that would be worth mentioning. Cheaper than an LLM router call, and the
# answer can say what the severe alerts actually are. The bundle is the one case
# allowed past MAX_SKILLS. It goes to the LLM, so critical_alerts arrives redacted.
STATUS_RE = re.compile(
    r"anything (?:to note|noteworthy|new|wrong|i should know)|what'?s (?:up|new|going on)"
    r"|\bstatus\b|\bsummary\b|\boverview\b|\bhealth"
    r"|how(?:'s| is| are) (?:the |my |our )?(?:server|homelab|lab|box|host|things|everything)")
STATUS_BUNDLE = ["overview", "critical_alerts", "netdata_alarms", "attack_alerts"]


def levels_in(q):
    """Valid Wazuh levels (0-16) named in a lowercased question, in order."""
    found = (int(m.group(1) or m.group(2) or m.group(3)) for m in LEVEL_RE.finditer(q))
    return [level for level in found if 0 <= level <= 16]


def severity_ranges(q):
    """(min, max) level range for each severity word in a lowercased question, in order."""
    ranges = []
    for m in SEVERITY_RE.finditer(q):
        for word in re.findall(_BAND, m.group(0)):
            if word in SEVERITY_BANDS and SEVERITY_BANDS[word] not in ranges:
                ranges.append(SEVERITY_BANDS[word])
    return ranges


def route_keywords(question, agents=()):
    """agents: the known Wazuh agent names; a question naming one gets its activity."""
    q = question.lower().replace("’", "'")
    picks = [("alerts_by_level", {"level": level}) for level in levels_in(q)]
    picks += [("alerts_in_range", {"min": low, "max": high}) for low, high in severity_ranges(q)]
    picks += [("agent_activity", {"agent": name}) for name in _agents_named(q, agents)]
    for pattern, name in KEYWORD_ROUTES:
        if re.search(pattern, q):
            args = {}
            m = TOP_N_RE.search(q)
            if name == "top_rules" and m:
                args = {"n": int(m.group(1))}
            picks.append((name, args))
    limit = MAX_SKILLS
    if STATUS_RE.search(q):
        picks += [(name, {}) for name in STATUS_BUNDLE]
        limit = max(MAX_SKILLS, len(STATUS_BUNDLE))
    seen, unique = set(), []
    for p in picks:
        k = _label(*p)
        if k not in seen:
            seen.add(k)
            unique.append(p)
    return unique[:limit]


# Step 2: nothing matched — one LLM call with tool-calling chooses the skill(s).
def _param_type(spec):
    return spec[2] if len(spec) > 2 else "integer"


def _tool_schemas():
    return [{
        "type": "function",
        "function": {
            "name": name,
            "description": s["description"],
            "parameters": {
                "type": "object",
                "properties": {p: {"type": _param_type(spec), "description": spec[0]}
                               for p, spec in s["params"].items()},
                "required": [p for p, spec in s["params"].items() if spec[1]],
            },
        },
    } for name, s in SKILLS.items()]


_tools_supported = True     # flipped off for the session if the model rejects tool-calling


def route_llm(question):
    """Returns (picks, tokens used, note). Empty picks = caller falls back to overview."""
    global _tools_supported
    if not _tools_supported:
        return [], 0, "tool-calling unsupported by model"
    try:
        resp = llm_call(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": (
                    "Choose the data needed to answer a question about the user's homelab. "
                    f"Call the fewest tools that cover it (at most {MAX_SKILLS}). Do not answer."
                )},
                {"role": "user", "content": _to_llm(question)},
            ],
            tools=_tool_schemas(),
            tool_choice="required",
        )
    except BadRequestError as e:
        # tool_use_failed = the model tried and produced a bad call (one-off). Any other
        # 400 here means the model/endpoint won't take tools at all: stop trying.
        if "tool_use_failed" in str(e):
            return [], 0, "LLM produced an invalid tool call"
        _tools_supported = False
        print(f"[router] model {GROQ_MODEL} rejected tool-calling ({_clip(e, 160)}). "
              "Unmatched questions will get the overview only for the rest of this session.")
        return [], 0, "tool-calling unsupported by model"
    except Exception as e:
        return [], 0, f"router call failed: {_clip(e, 80)}"

    tokens = resp.usage.total_tokens if resp.usage else 0
    picks = []
    for call in resp.choices[0].message.tool_calls or []:
        name = call.function.name
        if name not in SKILLS:
            continue
        try:
            raw = json.loads(call.function.arguments or "{}")
            # The model only ever saw aliases, so a string (an agent) is swapped back.
            args = {p: _from_llm(str(raw[p])) if _param_type(spec) == "string" else int(raw[p])
                    for p, spec in SKILLS[name]["params"].items() if raw.get(p) is not None}
        except (ValueError, TypeError, AttributeError):
            continue
        if any(spec[1] and p not in args for p, spec in SKILLS[name]["params"].items()):
            continue
        if (name, args) not in picks:
            picks.append((name, args))
    return picks[:MAX_SKILLS], tokens, "" if picks else "LLM chose no valid skill"


# A question with no keyword that points back at the last one ("is that worth worrying
# about?") reuses that question's skills: no router call, and the data is what "that"
# was about. Its answer always comes from the LLM, so the data goes out redacted.
REFERS_BACK_RE = re.compile(r"\b(?:that|it|this|those|them)\b")
_last_picks = []            # the skills the previous question ran


def refers_back(question):
    return bool(REFERS_BACK_RE.search(question.lower().replace("’", "'")))


def route(question):
    """Returns (picks, how they were chosen, router tokens used)."""
    global _last_picks
    picks, how, tokens = route_keywords(question, _known_agents()), "keyword", 0
    if not picks and _last_picks and refers_back(question):
        picks, how = list(_last_picks), "follow-up"
    if not picks:
        picks, tokens, note = route_llm(question)
        how = "LLM tool-call"
        if not picks:
            picks, how = [("overview", {})], f"fallback ({note})"
    _last_picks = list(picks)
    return picks, how, tokens
