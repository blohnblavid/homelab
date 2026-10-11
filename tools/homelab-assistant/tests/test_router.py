import pytest

from common import SKILLS
import router
from router import (STATUS_BUNDLE, _tool_schemas, is_statement, levels_in, refers_back, route,
                    route_keywords, severity_ranges)

BUNDLE = [(name, {}) for name in STATUS_BUNDLE]
LOW, MEDIUM, HIGH = (0, 6), (7, 11), (12, 14)


def in_range(band):
    return ("alerts_in_range", {"min": band[0], "max": band[1]})


@pytest.mark.parametrize("question, expected", [
    # the four questions used for the live check of the refactor
    ("anything to note?", BUNDLE),
    ("any CVEs I should patch?", [("vulnerabilities", {})]),
    ("what are the level 8 alerts?", [("alerts_by_level", {"level": 8})]),
    ("is the level 13 alert an attack?", [("alerts_by_level", {"level": 13}), ("attack_alerts", {})]),
    # status bundle
    ("status", BUNDLE),
    ("How is the server doing?", BUNDLE),
    ("what’s up?", BUNDLE),                        # curly apostrophe
    # single skills
    ("anything severe?", [("critical_alerts", {})]),
    ("any critical alerts?", [("critical_alerts", {})]),   # level 12 and above, not a band
    ("anything critical?", [("critical_alerts", {})]),
    ("any critical alarms?", [("netdata_alarms", {})]),    # "critical alarm" is Netdata's
    ("is anything vulnerable?", [("vulnerabilities", {})]),
    ("was I hacked or scanned?", [("attack_alerts", {})]),
    ("how much memory is docker using?", [("container_stats", {})]),
    ("anything from netdata?", [("netdata_alarms", {})]),
    ("which MITRE techniques show up?", [("mitre_tags", {})]),
    ("which rules are the noisiest?", [("top_rules", {})]),
    ("show me the top 3 rules", [("top_rules", {"n": 3})]),
    # levels
    ("lvl 10 and L12", [("alerts_by_level", {"level": 10}), ("alerts_by_level", {"level": 12})]),
    ("level 8 and level 8 again", [("alerts_by_level", {"level": 8})]),      # deduplicated
    ("what about the 8s?", [("alerts_by_level", {"level": 8})]),
    ("level 17 alerts", []),                            # not a Wazuh level
    # severity words
    ("what were the medium alerts?", [in_range(MEDIUM)]),
    ("any high or critical alerts?", [in_range(HIGH), ("critical_alerts", {})]),
    ("the last 10s", []),                               # a duration, not level 10
    ("is cpu high?", [("container_stats", {})]),        # "high" alone is not a severity
    # no keyword: left for the LLM router
    ("tell me a joke", []),
    ("", []),
])
def test_route_keywords(question, expected):
    assert route_keywords(question) == expected


def test_at_most_three_skills():
    picks = route_keywords("level 5, level 6, critical cves under attack")
    assert picks == [("alerts_by_level", {"level": 5}), ("alerts_by_level", {"level": 6}),
                     ("critical_alerts", {})]


def test_status_bundle_raises_the_cap_to_four():
    picks = route_keywords("how is the server? any cves?")
    assert picks == [("vulnerabilities", {}), ("overview", {}), ("critical_alerts", {}),
                     ("netdata_alarms", {})]


# --- severity bands ---

@pytest.mark.parametrize("question, expected", [
    ("what were the low alerts", [LOW]),
    ("what were the medium alerts", [MEDIUM]),
    ("show the high alerts", [HIGH]),
    ("high severity alerts", [HIGH]),
    ("anything high severity", [HIGH]),
    ("low-level events", [LOW]),
    ("high-priority ones", [HIGH]),
    ("medium and high alerts", [MEDIUM, HIGH]),
    ("low, medium or high alerts", [LOW, MEDIUM, HIGH]),
    ("high alerts and more high alerts", [HIGH]),       # deduplicated
    # not severities
    ("is cpu high", []),
    ("memory is low", []),
    ("any critical alarms", []),
    ("any critical alerts", []),                        # "critical" is critical_alerts, not a band
    ("critical severity", []),
    ("highlight the alerts", []),
    ("alerts", []),
])
def test_severity_ranges(question, expected):
    assert severity_ranges(question) == expected


# --- level shorthand ---

@pytest.mark.parametrize("question, expected", [
    ("what about the 8s", [8]),
    ("level 8s", [8]),
    ("lvl 8", [8]),
    ("lvl 8s", [8]),
    ("the 8's", [8]),
    ("the 0s and the 16s", [0, 16]),
    ("level 8", [8]),
    ("level-12", [12]),
    ("l3 and l5s", [3, 5]),
    ("level 0", [0]),
    # not levels
    ("level 17", []),
    ("the 30s", []),
    ("the 17s", []),
    # a bare "Ns" only counts after "the", "level" or "lvl"
    ("8s", []),
    ("10s and 12s", []),
    ("the last 10s", []),
    ("every 5s", []),
    ("8 alerts", []),
    ("top 5 rules", []),
    ("in 2026", []),
    ("123s", []),
])
def test_levels_in(question, expected):
    assert levels_in(question) == expected


# --- non-questions ---

@pytest.mark.parametrize("text", [
    "ok", "OK.", "thanks", "Thanks!", "thank you", "ok thanks", "great, thanks", "got it",
    "finished that", "done", "fixed it", "patched vscode", "ok, updated pip",
    "I'll patch it tonight", "i restarted the container", "that worked", "it's fine now",
    "will do", "never mind", "no worries",
])
def test_statements(text):
    assert is_statement(text)


@pytest.mark.parametrize("text", [
    "anything to note?", "finished that?", "ok?",       # a "?" always makes it a question
    "what happened on web-01 today", "is the level 13 alert an attack", "show me the cves",
    "ok what about the 8s", "thanks, now show me the cves", "and the 8s",
    "cves", "status", "level 8", "memory", "disk space", "web-01", "the 8s", "raw",
    "failed logins", "",
])
def test_not_statements(text):
    assert not is_statement(text)


# --- follow-ups ---

@pytest.mark.parametrize("question", [
    "is that worth worrying about?", "should I fix it?", "what does this mean?",
    "are those new?", "can I ignore them?", "Is THAT bad?", "that’s bad, right?",
])
def test_refers_back(question):
    assert refers_back(question)


@pytest.mark.parametrize("question", [
    "tell me a joke", "the last 10s", "anything else?", "what about these?",
    "is the item there?", "thatch and italics",
])
def test_does_not_refer_back(question):
    assert not refers_back(question)


@pytest.fixture
def llm_router(monkeypatch):
    """Stands in for the LLM router call and records the questions it was asked."""
    asked = []

    def fake(question):
        asked.append(question)
        return [("top_rules", {})], 50, ""
    monkeypatch.setattr(router, "route_llm", fake)
    monkeypatch.setattr(router, "_last_picks", [])
    return asked


def test_follow_up_reuses_the_previous_skills(llm_router):
    assert route("what about the 8s?") == ([("alerts_by_level", {"level": 8})], "keyword", 0)
    assert route("is that worth worrying about?") == ([("alerts_by_level", {"level": 8})], "follow-up", 0)
    assert route("and should I fix it?") == ([("alerts_by_level", {"level": 8})], "follow-up", 0)
    assert llm_router == []                             # the LLM router was never called


def test_follow_up_with_no_previous_question_goes_to_the_llm_router(llm_router):
    assert route("is that worth worrying about?") == ([("top_rules", {})], "LLM tool-call", 50)
    assert llm_router == ["is that worth worrying about?"]


def test_follow_up_after_an_llm_routed_question(llm_router):
    route("tell me a joke")
    assert route("explain that") == ([("top_rules", {})], "follow-up", 0)
    assert llm_router == ["tell me a joke"]


def test_keywords_win_over_a_follow_up(llm_router):
    route("what about the 8s?")
    assert route("is that an attack?") == ([("attack_alerts", {})], "keyword", 0)


def test_no_reference_back_goes_to_the_llm_router(llm_router):
    route("what about the 8s?")
    assert route("the last 10s") == ([("top_rules", {})], "LLM tool-call", 50)
    assert route("is that normal?") == ([("top_rules", {})], "follow-up", 0)


def test_fallback_when_the_llm_router_picks_nothing(monkeypatch):
    monkeypatch.setattr(router, "_last_picks", [])
    monkeypatch.setattr(router, "route_llm", lambda q: ([], 7, "LLM chose no valid skill"))
    assert route("tell me a joke") == ([("overview", {})], "fallback (LLM chose no valid skill)", 7)


# --- agent names ---

AGENTS = ["web-01", "nas", "pc", "pc-2"]


@pytest.mark.parametrize("question, expected", [
    ("what happened on web-01 today?", [("agent_activity", {"agent": "web-01"})]),
    ("What happened on WEB-01 today?", [("agent_activity", {"agent": "web-01"})]),
    ("compare nas and web-01", [("agent_activity", {"agent": "nas"}),
                                 ("agent_activity", {"agent": "web-01"})]),
    ("anything on pc-2?", [("agent_activity", {"agent": "pc-2"})]),     # not "pc"
    ("level 8 alerts on nas", [("alerts_by_level", {"level": 8}), ("agent_activity", {"agent": "nas"})]),
    ("is the nasty one gone?", []),                     # whole names only
    ("what happened today?", []),
])
def test_agent_name_routing(question, expected):
    assert route_keywords(question, AGENTS) == expected


def test_agent_names_are_not_matched_without_the_agent_list():
    assert route_keywords("what happened on web-01 today?") == []


# --- skill registry and tool schemas ---

def test_skill_registration_order():
    # This is the order of the tool list sent to the LLM router.
    assert list(SKILLS) == [
        "overview", "critical_alerts", "alerts_by_level", "alerts_in_range", "vulnerabilities",
        "mitre_tags", "top_rules", "agent_activity", "attack_alerts", "container_stats",
        "netdata_alarms",
    ]


def test_new_skills_are_direct_and_redactable():
    for name in ("alerts_in_range", "agent_activity"):
        assert SKILLS[name]["direct"] and SKILLS[name]["redactable"]


def test_tool_schemas():
    schemas = {s["function"]["name"]: s["function"] for s in _tool_schemas()}
    assert list(schemas) == list(SKILLS)
    assert schemas["alerts_by_level"]["parameters"] == {
        "type": "object",
        "properties": {"level": {"type": "integer", "description": "Wazuh rule level, 0-16"}},
        "required": ["level"],
    }
    assert schemas["alerts_in_range"]["parameters"]["required"] == ["min", "max"]
    assert schemas["agent_activity"]["parameters"] == {
        "type": "object",
        "properties": {"agent": {"type": "string", "description": "Agent name"}},
        "required": ["agent"],
    }
    assert schemas["top_rules"]["parameters"]["required"] == []
    assert schemas["overview"]["parameters"] == {"type": "object", "properties": {}, "required": []}
