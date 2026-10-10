import json
import os
import re
import time
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv
from openai import BadRequestError, OpenAI

# Load secrets from the .env next to this script (gitignored; see .env.example).
# override=False (the default) means a real shell env var still wins over .env.
load_dotenv(Path(__file__).with_name(".env"))

# --- config (env-overridable) ---
NETDATA = os.environ.get("NETDATA_URL", "http://localhost:19999")
WAZUH_INDEXER = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")          # set in env — do NOT hardcode
WAZUH_WINDOW = os.environ.get("WAZUH_WINDOW", "now-24h")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

# Groups we treat as "attack-related" for the SOC view. Wazuh tags web-attack rules
# (31xxx: 400 probes, traversal, sqli, sqlmap-success) with the "attack" group, so this
# catches them regardless of alert level — which is why the old level>=7 filter missed
# every level-5 web alert. The extras are belt-and-suspenders.
ATTACK_GROUPS = ["attack", "web_scan", "sql_injection", "recon"]

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


# --- skill registry ---
# A skill is a plain function: simple (integer) arguments in, compact text block out —
# one line per item, no raw logs, no JSON. The description and params double as the
# tool schema the LLM router sees, so keep them short: they cost tokens on every
# LLM-routed question.
SKILLS = {}


def skill(description, direct=False, redactable=False, **params):
    """Register a skill. params: name -> (description, required).

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


def _to_llm(text):
    _load_aliases()
    if not _aliases:
        return text
    names = sorted(_aliases, key=len, reverse=True)       # longest first: "pc-2" before "pc"
    by_lower = {n.lower(): a for n, a in _aliases.items()}
    pattern = r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in names) + r")(?![A-Za-z0-9])"
    return re.sub(pattern, lambda m: by_lower[m.group(1).lower()], text, flags=re.IGNORECASE)


def _from_llm(text):
    back = {alias: name for name, alias in _aliases.items()}
    # The model often writes a non-breaking or en hyphen, so accept those too.
    return re.sub(r"\bagent[-‐-―]\s?(\d+)\b",
                  lambda m: back.get(f"agent-{m.group(1)}", m.group(0)), text, flags=re.IGNORECASE)


def _netdata_alarms():
    alarms = requests.get(f"{NETDATA}/api/v1/alarms", timeout=15).json().get("alarms", {})
    counts, problems = {}, []
    for name, a in alarms.items():
        s = a.get("status", "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1
        if s in ("CRITICAL", "WARNING"):
            problems.append(f"  - {name}: {s} (value: {a.get('value_string', 'n/a')})")
    return counts, problems


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _fix_status(conditions):
    # A package's CVEs each carry their own "Package less than X" condition. Use the
    # one naming the highest version: updating past it clears the others too. The
    # result states the action in words, so the LLM has nothing to interpret.
    if not conditions:
        return "fix: not stated"

    def version(cond):
        found = re.findall(r"\d+(?:\.\d+)*", cond)
        return tuple(int(p) for p in found[-1].split(".")) if found else ()
    cond = max(conditions, key=version)
    # "less than or equal to X" means X itself is still vulnerable: Wazuh knows of no
    # fixed release. Say that outright, or the LLM reads X as the version to install.
    m = re.search(r"less than or equal to\s+(\S+)", cond, re.IGNORECASE)
    if m:
        return f"no fixed version listed; affected through {m.group(1)}"
    m = re.search(r"less than\s+(\S+)", cond, re.IGNORECASE)
    if m:
        return f"fix: update to {m.group(1)} or later"
    return f"affected: {_clip(cond, 60)}"       # unrecognised wording: pass it through


VULN_HINT = "(ask 'cves' for details)"


def _desc(rule, redact=False):
    # A vulnerability-detector rule's description names the CVE and the package.
    desc = rule.get("description", "?")
    if redact and ("vulnerability-detector" in (rule.get("groups") or []) or re.match(r"CVE-\d", str(desc))):
        return f"VULNERABILITY FINDING, not an attack: details withheld {VULN_HINT}"
    return _clip(desc, 120)


def _alert_details(alert_filter, title, redact=False):
    # The individual alerts, not just a count. _source is limited to the handful of
    # fields we print — no full_log, no raw doc. Sorted level desc then newest first,
    # so the first doc seen for each group is its most severe/recent one and dict order
    # is already display order. Ordinary alerts group by rule+agent; vulnerability
    # findings group by agent+package, so a package with 10 CVEs is one line, not 10.
    # redact=True (always, when the output is going to the LLM) replaces the
    # vulnerability lines with a label, level and count: no package, version or CVE ID.
    _load_aliases()
    res = _wazuh_search({
        "size": DETAIL_FETCH,
        "track_total_hits": True,
        "query": _in_window(alert_filter),
        "sort": [{"rule.level": {"order": "desc"}}, {"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp", "agent.name", "agent.id", "rule.id", "rule.level", "rule.description",
            "rule.groups",
            "data.vulnerability.cve", "data.vulnerability.severity",
            "data.vulnerability.package.name", "data.vulnerability.package.version",
            "data.vulnerability.package.condition",
        ],
    })
    total = res["hits"]["total"]["value"]
    fetched = len(res["hits"]["hits"])
    found = {}
    vuln_levels = {}        # rule level -> number of CVE findings first seen at that level
    for h in res["hits"]["hits"]:
        src = h["_source"]
        rule = src.get("rule", {})
        vuln = src.get("data", {}).get("vulnerability") or {}
        agent = src.get("agent", {}).get("name", "?")
        _add_alias(agent, src.get("agent", {}).get("id"))      # agent registered mid-session
        pkg = vuln.get("package") or {}
        is_vuln = bool(vuln) or "vulnerability-detector" in (rule.get("groups") or [])
        key = ("vuln", agent, pkg.get("name"), pkg.get("version")) if is_vuln else ("rule", agent, rule.get("id"))
        g = found.get(key)
        if g is None:
            g = found[key] = {
                "ts": str(src.get("@timestamp", "?"))[:16],      # to the minute, UTC
                "agent": agent,
                "rule": rule,
                "pkg": pkg,
                "is_vuln": is_vuln,
                "count": 0,
                "rule_ids": [],
                "cves": {},             # CVE id -> severity
                "conditions": [],
            }
        g["count"] += 1
        if is_vuln:
            cve = vuln.get("cve", "CVE n/a")
            if cve not in g["cves"]:
                g["cves"][cve] = vuln.get("severity", "n/a")
                vuln_levels[rule.get("level", "?")] = vuln_levels.get(rule.get("level", "?"), 0) + 1
            if rule.get("id") and rule["id"] not in g["rule_ids"]:
                g["rule_ids"].append(rule["id"])
            if pkg.get("condition") and pkg["condition"] not in g["conditions"]:
                g["conditions"].append(pkg["condition"])
    groups = list(found.values())
    if redact:
        groups = [g for g in groups if not g["is_vuln"]]
    lines = []
    for g in groups[:DETAIL_MAX_LINES]:
        rule = g["rule"]
        if g["is_vuln"]:
            # Worst severity first (sort is stable, so newest-first within a severity).
            cves = sorted(g["cves"].items(), key=lambda kv: -_SEVERITY_RANK.get(str(kv[1]).lower(), 0))
            ids = ", ".join(c for c, _ in cves[:3]) + (f" +{len(cves) - 3} more" if len(cves) > 3 else "")
            lines.append(
                f"  - {g['ts']}Z {g['agent']} rule {'/'.join(g['rule_ids']) or '?'} L{rule.get('level', '?')} "
                f"VULNERABILITY FINDING, not an attack: package {g['pkg'].get('name', 'n/a')} "
                f"{g['pkg'].get('version', 'n/a')}; {len(cves)} CVE{'s' if len(cves) != 1 else ''}, "
                f"highest severity {cves[0][1]}; {ids}; {_fix_status(g['conditions'])}")
        else:
            lines.append(
                f"  - {g['ts']}Z {g['agent']} rule {rule.get('id', '?')} L{rule.get('level', '?')} "
                f"\"{_clip(rule.get('description', '?'), 120)}\" x{g['count']}")

    out = (f"{title} (window {WAZUH_WINDOW}; times UTC; xN = repeats of same rule+agent; "
           + ("CVE findings counted per level, details withheld" if redact
              else "CVE findings grouped per agent+package")
           + f"): total={total}" + ("" if redact else f", distinct={len(found)}") + "\n")
    if redact:
        for lvl, n in sorted(vuln_levels.items(), key=lambda kv: str(kv[0]).zfill(3), reverse=True):
            lines.append(f"  - L{lvl} VULNERABILITY FINDING, not an attack: {n} CVE{'s' if n != 1 else ''} {VULN_HINT}")
    out += ("\n".join(lines) if lines else "  none") + "\n"
    if len(groups) > DETAIL_MAX_LINES:
        out += f"  ... {len(groups) - DETAIL_MAX_LINES} more distinct alerts not shown (cap {DETAIL_MAX_LINES})\n"
    if total > fetched:
        out += f"  ... {total - fetched} older alerts not examined (fetch limit {DETAIL_FETCH})\n"
    return out


@skill("Short current status: Netdata alarm counts and Wazuh alert counts per level.")
def overview():
    # Each source is isolated so one being down doesn't kill the other.
    try:
        counts, _ = _netdata_alarms()
        out = "NETDATA ALARMS: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none") + "\n"
    except Exception as e:
        out = "NETDATA ALARMS: " + _unavailable("Netdata", e)
    try:
        # size:0 = buckets only, no raw docs.
        res = _wazuh_search({
            "size": 0,
            "track_total_hits": True,
            "query": _in_window(),
            "aggs": {"by_level": {"terms": {"field": "rule.level", "size": 20}}},
        })
        levels = {b["key"]: b["doc_count"] for b in res["aggregations"]["by_level"]["buckets"]}
        out += f"WAZUH ALERTS (window {WAZUH_WINDOW}): total={res['hits']['total']['value']}\n"
        out += "BY LEVEL: " + (", ".join(f"L{k}={v}" for k, v in sorted(levels.items(), reverse=True)) or "none") + "\n"
    except Exception as e:
        out += "WAZUH ALERTS: " + _unavailable("Wazuh", e)
    return out


@skill(f"Details of every Wazuh alert at level {CRIT_LEVEL}+ (the most severe), "
       "including vulnerability/CVE findings.", direct=True, redactable=True)
def critical_alerts(redact=False):
    return _alert_details({"range": {"rule.level": {"gte": CRIT_LEVEL}}},
                          f"CRITICAL ALERTS (level>={CRIT_LEVEL})", redact)


@skill("Details of the Wazuh alerts at one specific level.", direct=True, redactable=True,
       level=("Wazuh rule level, 0-16", True))
def alerts_by_level(level, redact=False):
    level = int(level)
    if not 0 <= level <= 16:
        return f"ALERTS AT LEVEL {level}: not a valid Wazuh level (0-16)\n"
    return _alert_details({"term": {"rule.level": level}}, f"ALERTS AT LEVEL {level}", redact)


@skill("Vulnerability-detector (CVE) findings at any level, one line per package needing a patch.",
       direct=True, redactable=True)
def vulnerabilities(redact=False):
    return _alert_details({"exists": {"field": "data.vulnerability.cve"}}, "VULNERABILITY FINDINGS", redact)


@skill("Wazuh alert count per MITRE ATT&CK technique tag, with the rule generating most of each.",
       direct=True, redactable=True)
def mitre_tags(redact=False):
    # Per technique: the single rule.id contributing the most alerts, plus one doc for
    # its description.
    res = _wazuh_search({
        "size": 0,
        "query": _in_window(),
        "aggs": {
            "by_mitre": {
                "terms": {"field": "rule.mitre.technique", "size": 10},
                "aggs": {
                    "top_rule": {
                        "terms": {"field": "rule.id", "size": 1},
                        "aggs": {
                            "sample": {"top_hits": {"size": 1, "_source": [
                                "rule.description", "rule.level", "rule.groups"]}}
                        },
                    }
                },
            }
        },
    })
    # MITRE labels are rule TAGS (what a rule could indicate), not confirmed attacks — say so.
    out = f"MITRE TECHNIQUE TAGS (tags on rules, not confirmed attacks; top 10; window {WAZUH_WINDOW}):\n"
    buckets = res["aggregations"]["by_mitre"]["buckets"]
    for b in buckets:
        out += f"  - {b['key']} x{b['doc_count']}"
        top = b["top_rule"]["buckets"]
        if top:
            hits = top[0]["sample"]["hits"]["hits"]
            rule = hits[0]["_source"].get("rule", {}) if hits else {}
            out += (f": mostly rule {top[0]['key']} L{rule.get('level', '?')} "
                    f"\"{_desc(rule, redact)}\" x{top[0]['doc_count']}")
        out += "\n"
    if not buckets:
        out += "  none\n"
    return out


@skill("The Wazuh rule IDs with the most alerts, with description, count and MITRE tags.",
       direct=True, redactable=True, n=("How many rules, default 5", False))
def top_rules(n=5, redact=False):
    n = max(1, min(int(n), 20))
    # We aggregate on rule.id (keyword — safe) rather than rule.description, whose
    # mapping varies by version and can reject terms aggs. A top_hits sub-agg pulls one
    # real doc per rule for the human-readable description.
    res = _wazuh_search({
        "size": 0,
        "query": _in_window(),
        "aggs": {
            "top_rules": {
                "terms": {"field": "rule.id", "size": n},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["rule.description", "rule.level", "rule.groups",
                                        "rule.mitre.technique"],
                        }
                    }
                },
            }
        },
    })
    out = f"TOP RULES (the {n} rule IDs with the most alerts, any level; window {WAZUH_WINDOW}):\n"
    buckets = res["aggregations"]["top_rules"]["buckets"]
    for b in buckets:
        hits = b["sample"]["hits"]["hits"]
        rule = hits[0]["_source"].get("rule", {}) if hits else {}
        # MITRE labels are rule TAGS (what a rule could indicate), not confirmed attacks.
        tags = rule.get("mitre", {}).get("technique") or []
        out += (f"  - rule {b['key']} L{rule.get('level', '?')} \"{_desc(rule, redact)}\""
                f" x{b['doc_count']}" + (f" (MITRE tag: {', '.join(tags)})" if tags else "") + "\n")
    if not buckets:
        out += "  none\n"
    return out


@skill("Attack-related Wazuh alerts (web attacks, scans, SQL injection, recon), grouped by rule.")
def attack_alerts():
    # Filter to attack-related groups, aggregate by rule.id so we see WHAT KIND of attack
    # and HOW MANY, regardless of level. top_hits gives one real doc per rule for the
    # description + example URL.
    atk = _wazuh_search({
        "size": 0,
        "track_total_hits": True,
        "query": _in_window({"terms": {"rule.groups": ATTACK_GROUPS}}),
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id", "size": 15},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["rule.description", "rule.level", "data.url", "full_log"],
                            "sort": [{"@timestamp": {"order": "desc"}}],
                        }
                    }
                },
            }
        },
    })
    out = (f"ATTACK-RELATED ALERTS (groups: {'/'.join(ATTACK_GROUPS)}; window {WAZUH_WINDOW}): "
           f"total={atk['hits']['total']['value']}\n")
    buckets = atk["aggregations"]["by_rule"]["buckets"]
    for b in buckets:
        src = b["sample"]["hits"]["hits"][0]["_source"] if b["sample"]["hits"]["hits"] else {}
        rule = src.get("rule", {})
        example = src.get("data", {}).get("url") or src.get("full_log", "")
        out += (f"  - rule {b['key']} L{rule.get('level', '?')} \"{_clip(rule.get('description', '?'), 120)}\""
                f" x{b['doc_count']}" + (f" (e.g. {_clip(example, 80)})" if example else "") + "\n")
    if not buckets:
        out += "  none\n"

    # High-severity NON-attack events (level>=7 but not in attack groups). These are
    # almost all operational noise — app crashes, Windows application errors — that
    # would otherwise masquerade as "high severity security." Counted and labeled, not
    # dumped, so they stop being mistaken for attacks.
    noise = _wazuh_search({
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": WAZUH_WINDOW}}},
                    {"range": {"rule.level": {"gte": 7}}},
                ],
                "must_not": [{"terms": {"rule.groups": ATTACK_GROUPS}}],
            }
        },
    })
    out += (f"NON-ATTACK high-severity (level>=7, e.g. app crashes/errors, vulnerability findings): "
            f"{noise['hits']['total']['value']} — not attacks\n")
    # NOTE: data.srcip deliberately not summarized. Docker bridge NAT rewrites every
    # external client IP to the Docker bridge gateway IP, so source-IP is not meaningful yet.
    return out


@skill("Per-container CPU and memory usage from Netdata (top 5 of each).", direct=True)
def container_stats():
    charts = requests.get(f"{NETDATA}/api/v1/charts", timeout=15).json().get("charts", {})
    cpu, mem = [], []
    for cid in charts:
        if cid.startswith("cgroup_") and cid.endswith(".cpu"):
            v = requests.get(f"{NETDATA}/api/v1/data?chart={cid}&after=-1&points=1", timeout=15).json()
            try:
                total = sum(x for x in v["data"][0][1:] if isinstance(x, (int, float)))
                cpu.append((cid.replace("cgroup_", "").replace(".cpu", ""), round(total, 1)))
            except (KeyError, IndexError):
                pass
        if cid.startswith("cgroup_") and cid.endswith(".mem_usage"):
            v = requests.get(f"{NETDATA}/api/v1/data?chart={cid}&after=-1&points=1", timeout=15).json()
            try:
                mem.append((cid.replace("cgroup_", "").replace(".mem_usage", ""), round(v["data"][0][1], 1)))
            except (KeyError, IndexError, TypeError):
                pass

    cpu.sort(key=lambda x: x[1], reverse=True)
    mem.sort(key=lambda x: x[1], reverse=True)
    out = f"CONTAINERS: {len(mem) or len(cpu)} seen\n"
    out += "TOP CONTAINERS BY CPU (%): " + (", ".join(f"{n}={v}" for n, v in cpu[:5]) or "none") + "\n"
    out += "TOP CONTAINERS BY MEMORY (MB): " + (", ".join(f"{n}={v}" for n, v in mem[:5]) or "none") + "\n"
    return out


@skill("Active Netdata alarms (WARNING/CRITICAL) for host and containers, with current values.",
       direct=True)
def netdata_alarms():
    counts, problems = _netdata_alarms()
    out = "NETDATA ALARM COUNTS: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none") + "\n"
    out += "ACTIVE ALARMS (WARNING/CRITICAL):\n" + ("\n".join(problems) if problems else "  none") + "\n"
    return out


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


# --- router ---
# Step 1: keyword/regex match in code — no LLM call. Every pattern that matches adds
# its skill. Keep these specific: a question that matches nothing still gets routed
# (by the LLM), but a wrong match here silently fetches the wrong data.
LEVEL_RE = re.compile(r"\b(?:level|lvl)[\s-]*(\d{1,2})\b|\bl(\d{1,2})\b")
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


def route_keywords(question):
    q = question.lower().replace("’", "'")
    picks = []
    for m in LEVEL_RE.finditer(q):
        level = int(m.group(1) or m.group(2))
        if 0 <= level <= 16:
            picks.append(("alerts_by_level", {"level": level}))
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
def _tool_schemas():
    return [{
        "type": "function",
        "function": {
            "name": name,
            "description": s["description"],
            "parameters": {
                "type": "object",
                "properties": {p: {"type": "integer", "description": d} for p, (d, _) in s["params"].items()},
                "required": [p for p, (_, req) in s["params"].items() if req],
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
        resp = client.chat.completions.create(
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
            args = {p: int(raw[p]) for p in SKILLS[name]["params"] if raw.get(p) is not None}
        except (ValueError, TypeError):
            continue
        if any(req and p not in args for p, (_, req) in SKILLS[name]["params"].items()):
            continue
        if (name, args) not in picks:
            picks.append((name, args))
    return picks[:MAX_SKILLS], tokens, "" if picks else "LLM chose no valid skill"


def route(question):
    """Returns (picks, how they were chosen, router tokens used)."""
    picks = route_keywords(question)
    if picks:
        return picks, "keyword", 0
    picks, tokens, note = route_llm(question)
    if picks:
        return picks, "LLM tool-call", tokens
    return [("overview", {})], f"fallback ({note})", tokens


SYSTEM_PROMPT = (
    "You are the user's homelab assistant. Answer concisely using only the data provided, "
    "which was fetched for this question from Netdata (host/container metrics and "
    "alarms) and Wazuh (security alerts). When you refer to a Wazuh rule, quote its "
    "description EXACTLY as written — never paraphrase, rename, or infer what a rule "
    "ID means. MITRE tags describe what a rule could indicate, not confirmed attacks — "
    "only alerts listed under ATTACK-RELATED ALERTS count as attack activity. If the "
    "data has no ATTACK-RELATED ALERTS section, do not say whether or not there were "
    "attacks. Lines "
    "marked VULNERABILITY FINDING come from Wazuh's vulnerability detector: installed "
    "software has known CVEs and needs patching — it is NOT an attack or exploit. "
    "Their details are withheld from you: report only the level and the count, and "
    "tell the user to ask 'cves' for details. Hosts "
    "appear under aliases such as agent-1; write an alias exactly as given. If the "
    "answer is not in the data, say so rather than guessing."
)


def answer(question):
    picks, how, tokens = route(question)
    print(f"[skills: {', '.join(_label(n, a) for n, a in picks)} | routed by: {how}]")
    if how == "keyword" and all(SKILLS[n]["direct"] for n, _ in picks):
        # Readable as-is: print it. Real agent names are fine here — nothing leaves.
        print("\n" + "\n".join(run_skill(n, a) for n, a in picks), end="")
        print("[direct: no LLM call, nothing sent]\n")
        return
    # Going to the LLM: vulnerability findings are redacted to label, level and count.
    data = "\n".join(f"=== {_label(n, a)} ===\n{run_skill(n, a, redact=True)}" for n, a in picks)
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _to_llm(f"Data:\n{data}\nQuestion: {question}")},
        ],
    )
    text = _from_llm(response.choices[0].message.content or "")
    print("\nAssistant:", text)
    # The vulnerability hint must reach the user, but only once: print it if the
    # model's answer doesn't already point at 'cves' (quoted, or "ask/see ... cves").
    mentions = re.search(r"['\"`‘’“”]cves['\"`‘’“”]"
                         r"|\b(?:ask|see|type|run|use|enter)\b[^.\n]{0,25}\bcves\b", text, re.IGNORECASE)
    if VULN_HINT in data and not mentions:
        print("Vulnerability details were not sent to the LLM. Ask 'cves' to see them.")
    used = response.usage.total_tokens if response.usage else 0
    print(f"[tokens: {tokens + used} total — router {tokens}, answer {used}]\n")


def main():
    print("Ready. Ask about your server (type 'quit' to exit, 'refresh' to drop cached data).\n")
    while True:
        try:
            question = input("You: ").strip()
        except EOFError:
            break
        if question.lower() in ("quit", "exit", "q"):
            break
        if question.lower() == "refresh":
            _cache.clear()
            print("Cache cleared — the next question pulls fresh data.\n")
            continue
        if not question:
            continue
        answer(question)


if __name__ == "__main__":
    main()
