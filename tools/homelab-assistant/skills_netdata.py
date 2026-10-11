"""Netdata skills (host alarms, per-container CPU and memory) and their helpers."""
import requests

import skills_wazuh  # noqa: F401 — registers the Wazuh skills first; see overview() there
from common import NETDATA, skill


def _netdata_alarms():
    alarms = requests.get(f"{NETDATA}/api/v1/alarms", timeout=15).json().get("alarms", {})
    counts, problems = {}, []
    for name, a in alarms.items():
        s = a.get("status", "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1
        if s in ("CRITICAL", "WARNING"):
            problems.append(f"  - {name}: {s} (value: {a.get('value_string', 'n/a')})")
    return counts, problems


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
