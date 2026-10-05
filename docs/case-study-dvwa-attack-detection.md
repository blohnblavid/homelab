# Case Study: Building and Validating an Attack Detection Pipeline

## Summary

Wazuh had been running in the homelab for weeks, ingesting host-level telemetry — but it had
never actually been tested against real attack traffic. This exercise built a disposable,
isolated attack target (DVWA), wired its logs into the existing Wazuh deployment, and ran a
full attack chain against it — reconnaissance, credential attack, and exploitation — to find
out what the SIEM actually catches, what it misses, and why.

Along the way, two unrelated infrastructure bugs surfaced and got root-caused: a Windows
Firewall rule-precedence misunderstanding, and a Docker networking issue that turned out to
share a root cause with an already-known problem elsewhere in the stack.

## Setup

- **Target:** `vulnerables/web-dvwa` (Damn Vulnerable Web App), deployed as an isolated Docker
  container, port 8081, intentionally excluded from the reverse proxy and Tailscale.
- **Attacker:** Kali Linux VM (VMware, bridged networking), same LAN segment as the homelab host.
- **Detection:** Existing Wazuh agent on the homeserver host, extended to watch DVWA's Apache
  `access.log` / `error.log` via a Docker volume mount and a new `<localfile>` block in
  `ossec.conf`.

```yaml
volumes:
  - C:\docker\dvwa\logs:/var/log/apache2
```

```xml
<localfile>
  <log_format>apache</log_format>
  <location>C:\docker\dvwa\logs\access.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>C:\docker\dvwa\logs\error.log</location>
</localfile>
```

No custom decoders or rules were written for any part of this exercise — everything below is
Wazuh's out-of-the-box ruleset.

## Attack Chain

### 1. Reconnaissance — nikto

A standard `nikto -h http://<target>:8081` scan (8,069 requests, ~6.5 minutes) surfaced 16
real findings: outdated Apache (2.4.25, current is 2.4.66+), missing security headers,
directory indexing on `/config/` and `/docs/`, an exposed `.gitignore`, and a discovered admin
login page.

**Wazuh detection:** Full coverage, with no tuning required.

- Rule `31101` ("Web server 400 error code") fired on every malformed probe request.
- Rule `31151` ("Multiple web server 400 error codes from same source IP") correlated the
  burst into a single higher-severity alert, auto-tagged to **MITRE ATT&CK T1595.002
  (Vulnerability Scanning)**.
- A separate rule (`31104`, "Common web attack") caught nikto's directory-traversal probes
  (e.g. `GET /../../../../etc/shadow`), tagged to **T1083 (File and Directory Discovery)** and
  **T1190 (Exploit Public-Facing Application)**.

### 2. Credential Attack — Hydra, then custom Python

Attempted a straightforward `hydra ... http-post-form` brute force against DVWA's login form.
Initial runs returned unreliable results — every password (including obviously wrong ones)
reported as "valid." Root cause: DVWA's login form embeds a per-request CSRF token
(`user_token`) that Hydra's static form-replay doesn't account for; the malformed submissions
were producing a non-standard response that broke Hydra's failure-string matching.

Worked around this with a small Python script that fetches a fresh token and session cookie
before every attempt:

```python
resp = session.get(LOGIN_URL)
token = extract_token(resp.text)
session.post(LOGIN_URL, data={"username": "admin", "password": pwd,
                               "Login": "Login", "user_token": token})
```

This correctly identified `admin:password` (DVWA's known default) as valid, and correctly
rejected everything else — a legitimate, working brute-force against a CSRF-protected form.

**Wazuh detection:** None. Zero alerts across ~5 login attempts spanning both the Hydra runs
and the working Python script. DVWA returns HTTP 200 on both successful and failed logins
(the difference is only in the response body), so none of Wazuh's default HTTP-status-based
web rules had anything to trigger on. This is a genuine, specific gap: **Wazuh's default
ruleset does not detect application-layer credential brute-forcing against arbitrary web
login forms** — unlike SSH, which has dedicated auth-failure rules out of the box. Closing
this gap would require a custom decoder matching on response content (e.g. presence/absence
of "Login failed" in the body) or a request-rate rule scoped to `/login.php`.

### 3. Exploitation — sqlmap

Using the authenticated session, ran `sqlmap` against DVWA's classic SQLi endpoint
(`/vulnerabilities/sqli/?id=1`). Confirmed injection via all four standard techniques in a
single 146-request run:

- Boolean-based blind
- Error-based (`EXTRACTVALUE`)
- Time-based blind (`SLEEP`)
- UNION-based (2-column)

Backend fingerprinted as MySQL/MariaDB on Debian 9 (stretch) / Apache 2.4.25.

**Wazuh detection:** Full coverage — 49 alerts, all mapped to **T1190 (Exploit Public-Facing
Application) / Initial Access**. Notably, the specific rule that fired (`31106`) is described
as *"A web attack returned code 200 (success)"* — meaning Wazuh isn't just flagging attack
*attempts*, it's specifically distinguishing payloads that got a successful response from ones
that didn't. That's a meaningfully stronger signal than attempt-detection alone.

## Infrastructure Findings (unplanned, but worth documenting)

**Windows Firewall rule precedence.** Attempted to scope DVWA's exposed port to the Kali VM's
IP using two rules: a scoped Allow and a generic Block. Assumed (incorrectly) that a more
specific Allow rule would take precedence over a generic Block, similar to an ACL. In Windows
Filtering Platform, **Block always wins over Allow regardless of rule specificity** — the
scoped Allow rule and the unscoped Block rule both matched Kali's traffic, and Kali got
blocked along with everyone else. Removing the redundant Block rule (Windows already
default-denies unmatched inbound traffic) fixed the immediate issue, but a follow-up test
showed an unrelated device on the LAN could still reach the container — root cause not yet
identified, left open.

**Docker bridge NAT masking source IPs.** Every alert generated during this exercise showed
the same `data.srcip`: `192.168.0.1`, regardless of whether the actual traffic came from Kali,
a phone, or elsewhere. Docker Desktop on Windows rewrites all external client IPs to the
bridge gateway address before traffic reaches a container — this is the same root cause
already documented for Pi-hole's broken per-client attribution, now confirmed to affect
**Wazuh-visible attack telemetry** as well. A real fix requires macvlan networking (a known
pain point on Docker Desktop for Windows — host-to-container communication typically breaks)
or, more durably, a Linux-based Docker host. Deferred, but now clearly connected to the
existing Pi-hole issue rather than treated as a separate problem.

## Takeaways

- Wazuh's default ruleset, with zero custom tuning, correctly detected and MITRE-mapped both
  reconnaissance (nikto) and exploitation (sqlmap) traffic.
- It has a specific, real blind spot around web-application login brute-forcing — a good
  candidate for a future custom rule.
- Two separate debugging detours (Windows Firewall precedence, Docker NAT) turned into their
  own small, legitimate findings — and the second one revealed that an already-known issue
  (Pi-hole attribution) has a wider blast radius than previously scoped.
