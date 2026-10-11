"""What keeps host names and vulnerability details away from the LLM."""
import re

from common import _clip, _wazuh_search

# --- agent aliases ---
# Real Wazuh agent (host) names never go to the LLM. Everything sent passes through
# _to_llm(), which swaps each name for a stable alias; the reply passes through
# _from_llm(), which swaps them back before printing. Aliases come from the Wazuh
# agent ID (agent 001 -> agent-1), so they stay the same between sessions.
_aliases = {}               # real agent name -> alias
_aliases_loaded = False


def _add_alias(name, agent_id=None):
    if not name or name == "?" or name in _aliases:
        return
    used = set(_aliases.values())
    alias = f"agent-{int(agent_id)}" if str(agent_id).isdigit() else None
    if alias is None or alias in used:
        n = 1
        while f"agent-{n}" in used:
            n += 1
        alias = f"agent-{n}"
    _aliases[name] = alias


def _load_aliases():
    # Every agent name the indexer has ever seen (no time window), once per session.
    global _aliases_loaded
    if _aliases_loaded:
        return
    try:
        res = _wazuh_search({
            "size": 0,
            "aggs": {
                "agents": {
                    "terms": {"field": "agent.name", "size": 1000},
                    "aggs": {"id": {"terms": {"field": "agent.id", "size": 1}}},
                }
            },
        })
        found = []
        for b in res["aggregations"]["agents"]["buckets"]:
            ids = b["id"]["buckets"]
            found.append((ids[0]["key"] if ids else "", b["key"]))
        for agent_id, name in sorted(found):
            _add_alias(name, agent_id)
        _aliases_loaded = True
    except Exception as e:
        print(f"[aliases] could not load the agent list ({_clip(e, 80)}). Agent names typed "
              "in a question will be sent as typed until it loads.")


def _known_agents():
    """Real agent names, loading the list from the indexer if this session hasn't yet."""
    _load_aliases()
    return list(_aliases)


def _agent_pattern(names):
    # Whole names only, ignoring case; longest first: "pc-2" before "pc".
    names = sorted(names, key=len, reverse=True)
    return re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in names) + r")(?![A-Za-z0-9])",
                      re.IGNORECASE)


def _agents_named(text, names):
    """The names from `names` that appear in text, as spelled in `names`, in order of appearance."""
    if not names:
        return []
    by_lower = {n.lower(): n for n in names}
    found = []
    for m in _agent_pattern(names).finditer(text):
        name = by_lower[m.group(1).lower()]
        if name not in found:
            found.append(name)
    return found


def _to_llm(text):
    _load_aliases()
    if not _aliases:
        return text
    by_lower = {n.lower(): a for n, a in _aliases.items()}
    return _agent_pattern(_aliases).sub(lambda m: by_lower[m.group(1).lower()], text)


def _from_llm(text):
    back = {alias: name for name, alias in _aliases.items()}
    # The model often writes a non-breaking or en hyphen, so accept those too.
    return re.sub(r"\bagent[-‐-―]\s?(\d+)\b",
                  lambda m: back.get(f"agent-{m.group(1)}", m.group(0)), text, flags=re.IGNORECASE)


# --- vulnerability redaction ---
# Whenever a skill's output is going to the LLM, a vulnerability finding is reduced to
# a label, a level and a count: no package, version or CVE ID.
VULN_HINT = "(ask 'cves' for details)"


def _desc(rule, redact=False):
    # A vulnerability-detector rule's description names the CVE and the package.
    desc = rule.get("description", "?")
    if redact and ("vulnerability-detector" in (rule.get("groups") or []) or re.match(r"CVE-\d", str(desc))):
        return f"VULNERABILITY FINDING, not an attack: details withheld {VULN_HINT}"
    return _clip(desc, 120)


def _redacted_vuln_lines(vuln_levels):
    # vuln_levels: rule level -> number of CVE findings. One line per level, highest first.
    return [f"  - L{lvl} VULNERABILITY FINDING, not an attack: {n} CVE{'s' if n != 1 else ''} {VULN_HINT}"
            for lvl, n in sorted(vuln_levels.items(), key=lambda kv: str(kv[0]).zfill(3), reverse=True)]
