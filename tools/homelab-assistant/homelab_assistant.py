import os
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv
from openai import OpenAI

# Load secrets from the .env next to this script (gitignored; see .env.example).
# override=False (the default) means a real shell env var still wins over .env.
load_dotenv(Path(__file__).with_name(".env"))

# --- config (env-overridable) ---
NETDATA = os.environ.get("NETDATA_URL", "http://localhost:19999")
WAZUH_INDEXER = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")          # set in env — do NOT hardcode
WAZUH_WINDOW = os.environ.get("WAZUH_WINDOW", "now-24h")

# Groups we treat as "attack-related" for the SOC view. Wazuh tags web-attack rules
# (31xxx: 400 probes, traversal, sqli, sqlmap-success) with the "attack" group, so this
# catches them regardless of alert level — which is why the old level>=7 filter missed
# every level-5 web alert. The extras are belt-and-suspenders.
ATTACK_GROUPS = ["attack", "web_scan", "sql_injection", "recon"]

# Wazuh indexer ships a self-signed cert, so we skip TLS verification.
# TRADEOFF (real, not boilerplate): verify=False turns off cert checking entirely.
# Fine for you->your own box over the tailnet/LAN; it means zero protection against a
# man-in-the-middle on that path. Don't reuse this pattern for anything crossing an
# untrusted network. The honest fix later is trusting the indexer's CA instead.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=os.environ["GROQ_API_KEY"])


def get_netdata_data():
    # --- alarms ---
    alarms_data = requests.get(f"{NETDATA}/api/v1/alarms").json()
    status_counts = {}
    problems = []
    for name, a in alarms_data.get("alarms", {}).items():
        s = a.get("status", "UNKNOWN")
        status_counts[s] = status_counts.get(s, 0) + 1
        if s in ("CRITICAL", "WARNING"):
            problems.append(f"{name}: {s} (value: {a.get('value_string', 'n/a')})")

    # --- per-container CPU + memory ---
    charts = requests.get(f"{NETDATA}/api/v1/charts").json().get("charts", {})
    cpu, mem = [], []
    for cid, c in charts.items():
        if cid.startswith("cgroup_") and cid.endswith(".cpu"):
            v = requests.get(f"{NETDATA}/api/v1/data?chart={cid}&after=-1&points=1").json()
            try:
                total = sum(x for x in v["data"][0][1:] if isinstance(x, (int, float)))
                cpu.append((cid.replace("cgroup_", "").replace(".cpu", ""), round(total, 1)))
            except (KeyError, IndexError):
                pass
        if cid.startswith("cgroup_") and cid.endswith(".mem_usage"):
            v = requests.get(f"{NETDATA}/api/v1/data?chart={cid}&after=-1&points=1").json()
            try:
                mem.append((cid.replace("cgroup_", "").replace(".mem_usage", ""), round(v["data"][0][1], 1)))
            except (KeyError, IndexError, TypeError):
                pass

    cpu.sort(key=lambda x: x[1], reverse=True)
    mem.sort(key=lambda x: x[1], reverse=True)

    summary = f"ALARM COUNTS: {status_counts}\n"
    summary += ("PROBLEMS: " + "; ".join(problems) if problems else "PROBLEMS: none") + "\n"
    summary += "TOP CONTAINERS BY CPU (%): " + ", ".join(f"{n}={v}" for n, v in cpu[:5]) + "\n"
    summary += "TOP CONTAINERS BY MEMORY (MB): " + ", ".join(f"{n}={v}" for n, v in mem[:5]) + "\n"
    return summary


def get_wazuh_data():
    auth = (WAZUH_USER, WAZUH_PASS)
    base = f"{WAZUH_INDEXER}/wazuh-alerts-*/_search"

    # 1) Overview aggregations over the window: total count, severity levels, MITRE
    #    techniques, rule groups. size:0 = buckets only, no raw docs.
    agg_body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WAZUH_WINDOW}}},
        "aggs": {
            "by_level": {"terms": {"field": "rule.level", "size": 20}},
            "by_mitre": {"terms": {"field": "rule.mitre.technique", "size": 10}},
            "by_group": {"terms": {"field": "rule.groups", "size": 10}},
        },
    }
    r = requests.post(base, json=agg_body, auth=auth, verify=False, timeout=15)
    r.raise_for_status()
    agg = r.json()
    total = agg["hits"]["total"]["value"]
    levels = {b["key"]: b["doc_count"] for b in agg["aggregations"]["by_level"]["buckets"]}
    mitre = {b["key"]: b["doc_count"] for b in agg["aggregations"]["by_mitre"]["buckets"]}
    groups = {b["key"]: b["doc_count"] for b in agg["aggregations"]["by_group"]["buckets"]}

    # 2) ATTACK-FOCUSED query: filter to attack-related groups, aggregate by rule.id so
    #    we see WHAT KIND of attack and HOW MANY, regardless of level. A top_hits sub-agg
    #    pulls one real doc per rule for the human-readable description + example URL.
    #    We aggregate on rule.id (keyword — safe) rather than rule.description, whose
    #    mapping varies by version and can reject terms aggs.
    atk_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": WAZUH_WINDOW}}},
                    {"terms": {"rule.groups": ATTACK_GROUPS}},
                ]
            }
        },
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
    }
    ra = requests.post(base, json=atk_body, auth=auth, verify=False, timeout=15)
    ra.raise_for_status()
    atk = ra.json()
    atk_total = atk["hits"]["total"]["value"]
    atk_rules = []
    for b in atk["aggregations"]["by_rule"]["buckets"]:
        src = b["sample"]["hits"]["hits"][0]["_source"] if b["sample"]["hits"]["hits"] else {}
        rule = src.get("rule", {})
        example = src.get("data", {}).get("url") or (src.get("full_log", "")[:80])
        atk_rules.append((
            b["key"],                               # rule id
            rule.get("level", "?"),                 # level
            rule.get("description", "?"),           # description
            b["doc_count"],                         # count
            example,                                # example url / log snippet
        ))

    # 3) High-severity NON-attack events (level>=7 but not in attack groups). These are
    #    almost all operational noise — app crashes, Windows application errors — that
    #    would otherwise masquerade as "high severity security." Counted and labeled, not
    #    dumped, so they stop being mistaken for attacks.
    noise_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": WAZUH_WINDOW}}},
                    {"range": {"rule.level": {"gte": 7}}},
                ],
                "must_not": [{"terms": {"rule.groups": ATTACK_GROUPS}}],
            }
        },
    }
    rn = requests.post(base, json=noise_body, auth=auth, verify=False, timeout=15)
    rn.raise_for_status()
    noise_total = rn.json()["hits"]["total"]["value"]

    # --- build compact summary ---
    summary = f"WAZUH ALERTS (window {WAZUH_WINDOW}): total={total}\n"
    summary += "BY LEVEL: " + (", ".join(f"L{k}={v}" for k, v in sorted(levels.items(), reverse=True)) or "none") + "\n"
    # MITRE labels are rule TAGS (what a rule could indicate), not confirmed attacks — say so.
    summary += "BY MITRE TECHNIQUE (tags, not confirmed attacks): " + (", ".join(f"{k}={v}" for k, v in mitre.items()) or "none") + "\n"
    summary += "BY RULE GROUP: " + (", ".join(f"{k}={v}" for k, v in groups.items()) or "none") + "\n"
    summary += f"\nATTACK-RELATED ALERTS (groups: {'/'.join(ATTACK_GROUPS)}): total={atk_total}\n"
    if atk_rules:
        for rid, lvl, desc, cnt, ex in atk_rules:
            summary += f"  - rule {rid} L{lvl} \"{desc}\" x{cnt}" + (f" (e.g. {ex})" if ex else "") + "\n"
    else:
        summary += "  none\n"
    summary += f"\nNON-ATTACK high-severity (level>=7, e.g. app crashes/errors): {noise_total} — operational, not security\n"
    # NOTE: data.srcip deliberately not summarized. Docker bridge NAT rewrites every
    # external client IP to the Docker bridge gateway IP, so source-IP is not meaningful yet.
    return summary


def get_all_data():
    parts = []
    # Each source is isolated so one being down doesn't kill the other.
    try:
        parts.append("=== HOST / CONTAINER METRICS (Netdata) ===\n" + get_netdata_data())
    except Exception as e:
        parts.append(f"=== HOST / CONTAINER METRICS (Netdata) ===\n[unavailable: {e}]")
    try:
        parts.append("=== SECURITY ALERTS (Wazuh) ===\n" + get_wazuh_data())
    except Exception as e:
        parts.append(f"=== SECURITY ALERTS (Wazuh) ===\n[unavailable: {e}]")
    return "\n\n".join(parts)


# --- fetch once at startup ---
print("Fetching server data...")
data = get_all_data()
print("Ready. Ask about your server (type 'quit' to exit, 'refresh' to re-pull data).\n")

# --- the loop ---
while True:
    question = input("You: ").strip()
    if question.lower() in ("quit", "exit", "q"):
        break
    if question.lower() == "refresh":
        print("Re-fetching...")
        data = get_all_data()
        print("Updated.\n")
        continue
    if not question:
        continue

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {"role": "system", "content": (
                "You are John's homelab assistant. You have two data sources: Netdata "
                "(host and per-container resource metrics) and Wazuh (security alerts, "
                "with severity levels and MITRE ATT&CK technique tags). Answer concisely "
                "using only the data provided. When you refer to a Wazuh rule, use its "
                "description EXACTLY as written in the data — quote it verbatim, never "
                "paraphrase, rename, or infer what a rule ID means. If a rule's description "
                "is not in the data, give only its ID and say the description isn't shown. "
                "MITRE tags and rule groups describe what a rule could indicate, not "
                "confirmed attacks — don't assert an attack is happening unless the "
                "ATTACK-RELATED section shows relevant alerts. If asked about something not "
                "in the data, say so rather than guessing."
            )},
            {"role": "user", "content": f"Current server data:\n{data}\n\nQuestion: {question}"},
        ],
    )
    print("\nAssistant:", response.choices[0].message.content, "\n")