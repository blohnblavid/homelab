"""Wazuh skills (security alerts via the indexer) and their helpers."""
import re

from common import (CRIT_LEVEL, DETAIL_FETCH, DETAIL_MAX_LINES, WAZUH_WINDOW, _clip, _in_window,
                    _unavailable, _wazuh_search, skill)
from privacy import _add_alias, _desc, _known_agents, _load_aliases, _redacted_vuln_lines

# Groups we treat as "attack-related" for the SOC view. Wazuh tags web-attack rules
# (31xxx: 400 probes, traversal, sqli, sqlmap-success) with the "attack" group, so this
# catches them regardless of alert level — which is why the old level>=7 filter missed
# every level-5 web alert. The extras are belt-and-suspenders.
ATTACK_GROUPS = ["attack", "web_scan", "sql_injection", "recon"]

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


def _alert_details(alert_filter, title, redact=False):
    # The individual alerts, not just a count. _source is limited to the handful of
    # fields we print — no full_log, no raw doc. Sorted level desc then newest first,
    # so the first doc seen for each group is its most severe/recent one and dict order
    # is already display order.
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
    return _render_alert_details(res, title, redact)


def _render_alert_details(res, title, redact=False):
    # Turns the search response into the text block; no network. Ordinary alerts group
    # by rule+agent; vulnerability findings group by agent+package, so a package with
    # 10 CVEs is one line, not 10.
    # redact=True (always, when the output is going to the LLM) replaces the
    # vulnerability lines with a label, level and count: no package, version or CVE ID.
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
        lines += _redacted_vuln_lines(vuln_levels)
    out += ("\n".join(lines) if lines else "  none") + "\n"
    if len(groups) > DETAIL_MAX_LINES:
        out += f"  ... {len(groups) - DETAIL_MAX_LINES} more distinct alerts not shown (cap {DETAIL_MAX_LINES})\n"
    if total > fetched:
        out += f"  ... {total - fetched} older alerts not examined (fetch limit {DETAIL_FETCH})\n"
    return out


@skill("Short current status: Netdata alarm counts and Wazuh alert counts per level.")
def overview():
    # Imported here, not at the top: skills_netdata registers its skills on import,
    # and they must come after the Wazuh ones (registration order is the order of the
    # tool list the LLM router sees).
    from skills_netdata import _netdata_alarms
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


@skill("Details of the Wazuh alerts in a range of levels (low 0-6, medium 7-11, high 12-14).",
       direct=True, redactable=True,
       min=("Lowest Wazuh rule level, 0-16", True), max=("Highest Wazuh rule level, 0-16", True))
def alerts_in_range(min, max, redact=False):
    low, high = int(min), int(max)
    if not 0 <= low <= high <= 16:
        return f"ALERTS AT LEVELS {low}-{high}: not a valid range of Wazuh levels (0-16)\n"
    return _alert_details({"range": {"rule.level": {"gte": low, "lte": high}}},
                          f"ALERTS AT LEVELS {low}-{high}", redact)


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


AGENT_TOP_RULES = 5


@skill("One agent's (host's) Wazuh alerts: count per level and its top 5 rules.",
       direct=True, redactable=True, agent=("Agent name", True, "string"))
def agent_activity(agent, redact=False):
    # agent.name is matched exactly, so use Wazuh's own spelling of the name.
    known = _known_agents()
    name = next((n for n in known if n.lower() == str(agent).strip().lower()), None)
    if name is None:
        if known:
            return f"AGENT ACTIVITY for {_clip(agent, 60)}: no agent by that name is known to Wazuh\n"
        name = str(agent).strip()       # agent list not loaded: try the name as given
    res = _wazuh_search({
        "size": 0,
        "track_total_hits": True,
        "query": _in_window({"term": {"agent.name": name}}),
        "aggs": {
            "by_level": {"terms": {"field": "rule.level", "size": 20}},
            "top_rules": {
                "terms": {"field": "rule.id", "size": AGENT_TOP_RULES},
                "aggs": {
                    "sample": {"top_hits": {"size": 1, "_source": [
                        "rule.description", "rule.level", "rule.groups"]}}
                },
            },
        },
    })
    return _render_agent_activity(res, name, redact)


def _render_agent_activity(res, agent, redact=False):
    # Turns the search response into the text block; no network. redact=True withholds
    # the description of a vulnerability-detector rule, as in top_rules.
    levels = {b["key"]: b["doc_count"] for b in res["aggregations"]["by_level"]["buckets"]}
    out = f"AGENT ACTIVITY for {agent} (window {WAZUH_WINDOW}): total={res['hits']['total']['value']}\n"
    out += "BY LEVEL: " + (", ".join(f"L{k}={v}" for k, v in sorted(levels.items(), reverse=True)) or "none") + "\n"
    out += f"TOP {AGENT_TOP_RULES} RULES (most alerts on this agent, any level):\n"
    buckets = res["aggregations"]["top_rules"]["buckets"]
    for b in buckets:
        hits = b["sample"]["hits"]["hits"]
        rule = hits[0]["_source"].get("rule", {}) if hits else {}
        out += f"  - rule {b['key']} L{rule.get('level', '?')} \"{_desc(rule, redact)}\" x{b['doc_count']}\n"
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
