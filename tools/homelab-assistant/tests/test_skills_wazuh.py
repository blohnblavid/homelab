import pytest

from skills_wazuh import (_fix_status, _render_agent_activity, _render_alert_details, agent_activity,
                          alerts_in_range)


@pytest.mark.parametrize("conditions, expected", [
    ([], "fix: not stated"),
    (["Package less than 1.136.2"], "fix: update to 1.136.2 or later"),
    (["Package Less Than 5.1"], "fix: update to 5.1 or later"),
    (["Package less than or equal to 3.14.4"], "no fixed version listed; affected through 3.14.4"),
    # the condition naming the highest version wins, compared numerically (1.10 > 1.9)
    (["Package less than 1.2.10", "Package less than 1.10.0", "Package less than 1.9"],
     "fix: update to 1.10.0 or later"),
    (["Package less than 2.0", "Package less than or equal to 3.0"],
     "no fixed version listed; affected through 3.0"),
    (["Package less than or equal to 2.0", "Package less than 3.0"], "fix: update to 3.0 or later"),
    (["Package unfixed"], "affected: Package unfixed"),
])
def test_fix_status(conditions, expected):
    assert _fix_status(conditions) == expected


def _hit(level, rule_id, description, groups=(), vuln=None, ts="2026-01-02T03:04:05.678Z"):
    src = {"@timestamp": ts, "agent": {"name": "testbox", "id": "001"},
           "rule": {"id": rule_id, "level": level, "description": description, "groups": list(groups)}}
    if vuln:
        src["data"] = {"vulnerability": vuln}
    return {"_source": src}


def _vuln(cve, severity, condition):
    return {"cve": cve, "severity": severity,
            "package": {"name": "examplepkg", "version": "1.2.3", "condition": condition}}


RESPONSE = {"hits": {"total": {"value": 4}, "hits": [
    _hit(13, "23506", "CVE-2026-0001 affects examplepkg", ["vulnerability-detector"],
         _vuln("CVE-2026-0001", "Critical", "Package less than 1.3.0")),
    _hit(10, "23505", "CVE-2026-0002 affects examplepkg", ["vulnerability-detector"],
         _vuln("CVE-2026-0002", "High", "Package less than 1.2.9")),
    _hit(8, "60227", "A new external device was recognized by the system"),
    _hit(8, "60227", "A new external device was recognized by the system"),
]}}


def test_vulnerability_line_in_full():
    lines = _render_alert_details(RESPONSE, "TITLE").splitlines()
    assert lines[0].startswith("TITLE (")
    assert lines[0].endswith("CVE findings grouped per agent+package): total=4, distinct=2")
    assert lines[1] == (
        "  - 2026-01-02T03:04Z testbox rule 23506/23505 L13 VULNERABILITY FINDING, not an attack: "
        "package examplepkg 1.2.3; 2 CVEs, highest severity Critical; "
        "CVE-2026-0001, CVE-2026-0002; fix: update to 1.3.0 or later")
    assert lines[2] == ('  - 2026-01-02T03:04Z testbox rule 60227 L8 '
                        '"A new external device was recognized by the system" x2')
    assert len(lines) == 3


def test_vulnerability_line_redacted():
    out = _render_alert_details(RESPONSE, "TITLE", redact=True)
    lines = out.splitlines()
    assert lines[0].endswith("CVE findings counted per level, details withheld): total=4")
    assert lines[1:] == [
        '  - 2026-01-02T03:04Z testbox rule 60227 L8 '
        '"A new external device was recognized by the system" x2',
        "  - L13 VULNERABILITY FINDING, not an attack: 1 CVE (ask 'cves' for details)",
        "  - L10 VULNERABILITY FINDING, not an attack: 1 CVE (ask 'cves' for details)",
    ]
    for secret in ("examplepkg", "1.2.3", "CVE-2026", "1.3.0", "23506", "Critical"):
        assert secret not in out


def test_alerts_in_range_rejects_bad_ranges():
    # Returns before any query (the network is blocked in these tests).
    assert alerts_in_range(12, 7) == "ALERTS AT LEVELS 12-7: not a valid range of Wazuh levels (0-16)\n"
    assert "not a valid range" in alerts_in_range(0, 17)


AGENT_RESPONSE = {
    "hits": {"total": {"value": 30}},
    "aggregations": {
        "by_level": {"buckets": [{"key": 3, "doc_count": 20}, {"key": 13, "doc_count": 1},
                                 {"key": 8, "doc_count": 9}]},
        "top_rules": {"buckets": [
            {"key": "60227", "doc_count": 9, "sample": {"hits": {"hits": [{"_source": {"rule": {
                "level": 8, "description": "A new external device was recognized by the system"}}}]}}},
            {"key": "23506", "doc_count": 1, "sample": {"hits": {"hits": [{"_source": {"rule": {
                "level": 13, "description": "CVE-2026-0001 affects examplepkg",
                "groups": ["vulnerability-detector"]}}}]}}},
        ]},
    },
}


def test_agent_activity():
    lines = _render_agent_activity(AGENT_RESPONSE, "testbox").splitlines()
    assert lines[0].startswith("AGENT ACTIVITY for testbox (window ") and lines[0].endswith("): total=30")
    assert lines[1] == "BY LEVEL: L13=1, L8=9, L3=20"
    assert lines[2] == "TOP 5 RULES (most alerts on this agent, any level):"
    assert lines[3:] == [
        '  - rule 60227 L8 "A new external device was recognized by the system" x9',
        '  - rule 23506 L13 "CVE-2026-0001 affects examplepkg" x1',
    ]


def test_agent_activity_redacted():
    out = _render_agent_activity(AGENT_RESPONSE, "testbox", redact=True)
    assert out.splitlines()[4] == ('  - rule 23506 L13 "VULNERABILITY FINDING, not an attack: '
                                   "details withheld (ask 'cves' for details)\" x1")
    assert "examplepkg" not in out and "CVE-2026" not in out


def test_agent_activity_with_no_alerts():
    res = {"hits": {"total": {"value": 0}},
           "aggregations": {"by_level": {"buckets": []}, "top_rules": {"buckets": []}}}
    assert _render_agent_activity(res, "testbox").splitlines()[1:] == [
        "BY LEVEL: none", "TOP 5 RULES (most alerts on this agent, any level):", "  none"]


def test_agent_activity_unknown_agent(aliases):
    aliases["testbox"] = "agent-1"
    assert agent_activity("nosuchbox") == (
        "AGENT ACTIVITY for nosuchbox: no agent by that name is known to Wazuh\n")


def test_no_alerts():
    out = _render_alert_details({"hits": {"total": {"value": 0}, "hits": []}}, "TITLE")
    assert out.splitlines()[1:] == ["  none"]
