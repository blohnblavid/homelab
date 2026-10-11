from types import SimpleNamespace

import homelab_assistant
from common import _usage_breakdown
from homelab_assistant import HISTORY_CHARS, _history_block, _remember, _token_line


def usage(prompt, completion, reasoning=None, details=True):
    return SimpleNamespace(
        prompt_tokens=prompt, completion_tokens=completion, total_tokens=prompt + completion,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=reasoning) if details else None)


# --- tokens ---

def test_usage_breakdown_with_reasoning():
    assert _usage_breakdown(usage(900, 251, 120)) == "prompt 900, completion 251 (reasoning 120)"


def test_usage_breakdown_without_reasoning():
    assert _usage_breakdown(usage(900, 251)) == "prompt 900, completion 251"
    assert _usage_breakdown(usage(900, 251, details=False)) == "prompt 900, completion 251"


def test_usage_breakdown_when_nothing_is_reported():
    assert _usage_breakdown(None) == ""
    assert _usage_breakdown(SimpleNamespace(total_tokens=5)) == ""


def test_token_line():
    assert _token_line(40, usage(900, 251, 120)) == (
        "[tokens: 1191 total — router 40, answer 1151: prompt 900, completion 251 (reasoning 120)]")
    assert _token_line(0, None) == "[tokens: 0 total — router 0, answer 0]"


# --- conversation memory ---

def test_history_block_is_empty_without_history():
    assert _history_block([]) == ""


def test_history_block():
    block = _history_block([("q one?", "a one"), ("q two?", "a two")])
    assert block.splitlines()[1:] == ["Q: q one?", "A: a one", "Q: q two?", "A: a two", ""]
    assert block.endswith("\n\n")


def test_remember_aliases_truncates_and_keeps_two(aliases, monkeypatch):
    aliases["web-01"] = "agent-1"
    monkeypatch.setattr(homelab_assistant, "_history", type(homelab_assistant._history)(maxlen=2))
    _remember("first?", "one")
    _remember("what happened on web-01 today?", "web-01 " + "x" * 400)
    _remember("and on WEB-01 yesterday?", "nothing")
    pairs = list(homelab_assistant._history)
    assert [q for q, _ in pairs] == ["what happened on agent-1 today?", "and on agent-1 yesterday?"]
    assert pairs[0][1].startswith("agent-1 xxx") and len(pairs[0][1]) == HISTORY_CHARS
    assert "web-01" not in _history_block(pairs).lower()
