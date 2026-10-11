from privacy import VULN_HINT, _add_alias, _agents_named, _desc, _from_llm, _redacted_vuln_lines, _to_llm


# --- agent aliases ---

def test_alias_comes_from_agent_id(aliases):
    _add_alias("web-01", "001")
    _add_alias("db", "003")
    assert aliases == {"web-01": "agent-1", "db": "agent-3"}


def test_alias_without_usable_id_takes_lowest_free_number(aliases):
    _add_alias("web-01", "001")
    _add_alias("db", "003")
    _add_alias("no-id")
    _add_alias("same-id", "001")
    assert aliases["no-id"] == "agent-2"
    assert aliases["same-id"] == "agent-4"


def test_alias_ignores_blanks_and_repeats(aliases):
    _add_alias("web-01", "001")
    _add_alias("web-01", "007")
    _add_alias("")
    _add_alias("?")
    assert aliases == {"web-01": "agent-1"}


def test_swap_to_aliases(aliases):
    aliases.update({"web-01": "agent-1", "db": "agent-3"})
    assert _to_llm("Is web-01 ok? WEB-01 talks to db.") == "Is agent-1 ok? agent-1 talks to agent-3."


def test_swap_matches_whole_words_only(aliases):
    aliases.update({"db": "agent-3"})
    assert _to_llm("dbx, mydb and db2 are not db") == "dbx, mydb and db2 are not agent-3"


def test_swap_prefers_the_longest_name(aliases):
    aliases.update({"pc": "agent-1", "pc-2": "agent-2"})
    assert _to_llm("pc-2 and pc") == "agent-2 and agent-1"


def test_swap_without_aliases_leaves_text_alone():
    assert _to_llm("Is web-01 ok?") == "Is web-01 ok?"


def test_swap_back(aliases):
    aliases.update({"web-01": "agent-1", "db": "agent-3"})
    assert _from_llm("agent-1 is fine; Agent-3 is not.") == "web-01 is fine; db is not."


def test_swap_back_accepts_other_hyphens(aliases):
    aliases.update({"web-01": "agent-1"})
    # non-breaking hyphen, en dash, and a space after the hyphen
    assert _from_llm("agent‑1, agent–1, agent- 1") == "web-01, web-01, web-01"


def test_swap_back_leaves_unknown_aliases(aliases):
    aliases.update({"web-01": "agent-1"})
    assert _from_llm("agent-9 and agent-12") == "agent-9 and agent-12"


def test_round_trip(aliases):
    aliases.update({"web-01": "agent-1", "db": "agent-3", "pc": "agent-4", "pc-2": "agent-5"})
    text = "web-01 saw 3 alerts, db saw none; pc-2 and pc are quiet."
    sent = _to_llm(text)
    assert not any(name in sent.replace("agent-", "") for name in ("web-01", "db", "pc"))
    assert _from_llm(sent) == text


def test_agents_named():
    names = ["web-01", "pc", "pc-2", "NAS"]
    assert _agents_named("what happened on Web-01 and nas, then web-01 again?", names) == ["web-01", "NAS"]
    assert _agents_named("pc-2 then pc", names) == ["pc-2", "pc"]
    assert _agents_named("nasty pcs", names) == []
    assert _agents_named("anything on web-01?", []) == []


# --- vulnerability redaction ---

WITHHELD = "VULNERABILITY FINDING, not an attack: details withheld (ask 'cves' for details)"


def test_desc_redacts_vulnerability_detector_rule():
    rule = {"description": "examplepkg 1.2.3 is affected", "groups": ["vulnerability-detector"]}
    assert _desc(rule, redact=True) == WITHHELD
    assert VULN_HINT in WITHHELD


def test_desc_redacts_cve_description_without_the_group():
    assert _desc({"description": "CVE-2026-0001 affects examplepkg"}, redact=True) == WITHHELD


def test_desc_keeps_details_when_not_redacting():
    rule = {"description": "CVE-2026-0001 affects examplepkg", "groups": ["vulnerability-detector"]}
    assert _desc(rule) == "CVE-2026-0001 affects examplepkg"


def test_desc_leaves_ordinary_rules_alone():
    rule = {"description": "sshd: authentication failed", "groups": ["syslog", "sshd"]}
    assert _desc(rule, redact=True) == "sshd: authentication failed"
    assert _desc({}, redact=True) == "?"


def test_redacted_lines_highest_level_first():
    assert _redacted_vuln_lines({7: 6, 13: 1, 10: 14}) == [
        "  - L13 VULNERABILITY FINDING, not an attack: 1 CVE (ask 'cves' for details)",
        "  - L10 VULNERABILITY FINDING, not an attack: 14 CVEs (ask 'cves' for details)",
        "  - L7 VULNERABILITY FINDING, not an attack: 6 CVEs (ask 'cves' for details)",
    ]
