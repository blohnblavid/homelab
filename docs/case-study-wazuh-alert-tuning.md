# Case Study: Tuning Wazuh Alert Noise (Scheduled-Task Logons and a USB Switcher)

## Summary

Wazuh was producing about 2,800 alerts in 24 hours, and most of them came from two sources
that had nothing to do with an attack: a scheduled task on the server that logs on every
2 minutes, and USB and audio devices on the desktop PC that re-register every time an input
is switched. This session traced each source to its cause, fixed one of them outside Wazuh
entirely, and wrote four custom rules for the rest.

The rules are in [`local_rules.xml`](../docker-compose/security/wazuh/local_rules.xml). Every
one of them trades some visibility for less noise, and those tradeoffs are listed below
rather than left implied. So are two mistakes made while verifying the work.

## Starting point

- About 2,800 alerts in 24 hours.
- Three rules (`67022`, `67028`, `67023`) fired every 2 minutes on the server.
- Rule `60227` (new external device, level 8) fired about 590 times in 24 hours on the
  desktop PC, tagged "Communication Through Removable Media".

## Source 1: the Healthchecks.io ping task

### Cause

The server pings Healthchecks.io from a Windows scheduled task every 2 minutes (set up in the
[monitoring case study](case-study-homeserver-monitoring.md)). The task runs without
attaching to the desktop session, so Windows performs a full logon for each run and writes
three Security events:

| Event | What it is | Wazuh rule |
|---|---|---|
| `4624` | Batch logon: `logonType` 4, logon process `.UBPM` | `67022` |
| `4672` | Special privileges assigned to the new logon | `67028` |
| `4634` | Logoff | `67023` |

720 runs a day × 3 events is about 2,160 alerts.

### Fix: three child rules at level 1

The manager's `log_alert_level` is 3, so a rule at level 1 still matches but is not written
as an alert. Each of the three stock rules got a child rule at level 1 that matches only the
scheduled-task case.

The logon and the logoff both carry a logon type, so they match on `logonType` 4 and the
account:

```xml
<rule id="100100" level="1">
  <if_sid>67022</if_sid>
  <field name="win.eventdata.logonType">^4$</field>
  <field name="win.eventdata.targetUserName">^John$</field>
  <field name="win.eventdata.logonProcessName">UBPM</field>
  <description>Scheduled task logon for John (expected, not alerted).</description>
</rule>
```

The `4672` event has no logon type, so there is nothing in the event itself that separates a
scheduled-task logon from any other. It is matched only when the batch-logon rule fired on
the same computer within 5 seconds:

```xml
<rule id="100101" level="1" timeframe="5">
  <if_sid>67028</if_sid>
  <if_matched_sid>100100</if_matched_sid>
  <same_field>win.system.computer</same_field>
  <field name="win.eventdata.subjectUserName">^John$</field>
  <description>Special privileges for the scheduled task logon (expected, not alerted).</description>
</rule>
```

### Verification

- The ping alerts stopped after the manager restart.
- A real unlock still produced rule `60118` (Windows Workstation Logon Success) and `67023`,
  so interactive logons and logoffs are still alerted.

## Source 2: rule 60227 on the desktop PC

The roughly 590 "new external device" alerts had two separate causes, and they got two
different fixes.

### Monitor audio endpoints: fixed at the source

Part of the volume was three monitors' audio endpoints re-registering when a display
switched inputs. This was fixed at the source by disabling the NVIDIA HD Audio controller,
so no Wazuh rule was needed for it.

### USB switcher: lowered to level 3

The rest was a USB switcher re-registering the keyboard, the mouse receiver, the webcam and
its own hub, about 17 to 20 events per switch. A child rule lowers these to level 3 by
matching those devices' vendor and product IDs:

```xml
<rule id="100110" level="3">
  <if_sid>60227</if_sid>
  <field name="win.eventdata.deviceId" type="pcre2">(?i)VID_(046D.{1,5}PID_(0892|C539)|320F.{1,5}PID_5064|35D6.{1,5}PID_(2510|3510))</field>
  <description>Known USB switcher device re-registered (keyboard, mouse receiver, webcam or hub).</description>
</rule>
```

Any other device still alerts at level 8 through rule `60227`.

## Tradeoffs

- **Scheduled-task logons for that account are no longer alerted.** This also hides the logon
  trail of a malicious task running as the same account.
- **A device spoofing a known vendor/product ID would be lowered too.** The USB rule matches
  on IDs the device reports about itself.
- **The 5-second correlation window could hide one real privileges event.** A genuine `4672`
  for the same account, on the same computer, within 5 seconds of a ping run would be matched
  by rule `100101`.

## Mistakes

- **Concluding the rules worked from absence of alerts alone.** I first decided the rules
  were working because the alerts had stopped, before confirming the agent was still
  reporting. A disconnected agent produces the same silence.
- **Testing for the wrong rule ID.** My unlock test looked for the wrong rule ID, so the first
  check for "real logons still alert" was not checking what I thought it was.

## Result

<!-- TODO: fill in "after" totals (24-hour alert count after tuning). -->
**TODO: "after" totals to be added.**

## Takeaways

- **Find the cause before writing a rule.** Part of the device noise was removed by disabling
  a controller, which needed no rule at all.
- **Silence is not proof of a working suppression rule.** It needs a positive check alongside
  it: the agent is still reporting, and an event the rule should not match still alerts.
- **Match as narrowly as the event allows.** Where the event has distinguishing fields, use
  them; where it doesn't (`4672`), tie it to an event that does, and write down what that
  correlation could hide.
- **Every lowered rule is a recorded blind spot.** Keeping the rules file and its tradeoffs
  in the repo means the blind spots are documented where the rules are.
