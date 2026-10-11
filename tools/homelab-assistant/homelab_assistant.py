"""Entry point: the chat loop and the answer call. Run with `python homelab_assistant.py`."""
import re
from collections import deque

from common import GROQ_MODEL, SKILLS, _cache, _clip, _label, _usage_breakdown, llm_call, run_skill
from privacy import VULN_HINT, _from_llm, _to_llm
from router import STATEMENT_REPLY, is_statement, route

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


# --- conversation memory ---
# The last few question/answer pairs, so a follow-up ("is that an attack?") has
# something to refer to. Sent on LLM answer calls only, never on routing calls. Each
# side is aliased first and then cut to HISTORY_CHARS, so nothing is stored that could
# not be sent. A direct answer is remembered as a note naming the skills, never as its
# output: that output is unredacted and stays on this machine.
HISTORY_PAIRS = 2
HISTORY_CHARS = 300
_history = deque(maxlen=HISTORY_PAIRS)      # (question, answer), aliased and truncated
_last_fetch = None                          # (skill output as fetched, where it went), for 'raw'


def _remember(question, reply):
    _history.append((_clip(_to_llm(question), HISTORY_CHARS), _clip(_to_llm(reply), HISTORY_CHARS)))


def _history_block(pairs):
    if not pairs:
        return ""
    lines = ["Earlier in this conversation (context for what the question refers to; not current data):"]
    for q, a in pairs:
        lines += [f"Q: {q}", f"A: {a}"]
    return "\n".join(lines) + "\n\n"


def _token_line(router_tokens, usage):
    used = usage.total_tokens if usage else 0
    breakdown = _usage_breakdown(usage)
    return (f"[tokens: {router_tokens + used} total — router {router_tokens}, answer {used}"
            + (f": {breakdown}" if breakdown else "") + "]")


def answer(question):
    global _last_fetch
    if is_statement(question):
        # Not a question: no routing, no data, no LLM call.
        print(STATEMENT_REPLY + "\n")
        return
    picks, how, tokens = route(question)
    labels = ", ".join(_label(n, a) for n, a in picks)
    print(f"[skills: {labels} | routed by: {how}]")
    if how == "keyword" and all(SKILLS[n]["direct"] for n, _ in picks):
        # Readable as-is: print it. Real agent names are fine here — nothing leaves.
        outputs = [run_skill(n, a) for n, a in picks]
        print("\n" + "\n".join(outputs), end="")
        print("[direct: no LLM call, nothing sent]\n")
        _last_fetch = ("\n".join(f"=== {_label(n, a)} ===\n{out}" for (n, a), out in zip(picks, outputs)),
                       "shown directly; nothing was sent")
        _remember(question, f"[answered on the user's screen from {labels}; that output was not sent to you]")
        return
    # Going to the LLM: vulnerability findings are redacted to label, level and count.
    data = "\n".join(f"=== {_label(n, a)} ===\n{run_skill(n, a, redact=True)}" for n, a in picks)
    _last_fetch = (data, "sent to the LLM in this form, with agent names replaced by aliases")
    response = llm_call(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _to_llm(f"{_history_block(_history)}Data:\n{data}\nQuestion: {question}")},
        ],
    )
    reply = response.choices[0].message.content or ""
    _remember(question, reply)
    text = _from_llm(reply)
    print("\nAssistant:", text)
    # The vulnerability hint must reach the user, but only once: print it if the
    # model's answer doesn't already point at 'cves' (quoted, or "ask/see ... cves").
    mentions = re.search(r"['\"`‘’“”]cves['\"`‘’“”]"
                         r"|\b(?:ask|see|type|run|use|enter)\b[^.\n]{0,25}\bcves\b", text, re.IGNORECASE)
    if VULN_HINT in data and not mentions:
        print("Vulnerability details were not sent to the LLM. Ask 'cves' to see them.")
    print(_token_line(tokens, response.usage) + "\n")


def main():
    print("Ready. Ask about your server (type 'quit' to exit, 'refresh' to drop cached data, "
          "'raw' to see the last data fetched).\n")
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
        if question.lower() == "raw":
            if _last_fetch:
                print("\n" + _last_fetch[0], end="")
                print(f"[raw: {_last_fetch[1]}]\n")
            else:
                print("Nothing fetched yet.\n")
            continue
        if not question:
            continue
        answer(question)


if __name__ == "__main__":
    main()
