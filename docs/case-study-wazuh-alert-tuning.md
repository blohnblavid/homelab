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

The logoff rule is the same match without the logon process, which `4634` does not carry:

```xml
<rule id="100102" level="1">
  <if_sid>67023</if_sid>
  <field name="win.eventdata.logonType">^4$</field>
  <field name="win.eventdata.targetUserName">^John$</field>
  <description>Scheduled task logoff for John (expected, not alerted).</description>
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

Measured over 24 hours, 2026-10-12 00:05 to 2026-10-13 00:05 (Central), two days after the
rules went in. That window includes an evening of server maintenance, so it is not a quiet day.

| | Before | After |
|---|---|---|
| All alerts | about 2,800 | 501 |
| Ping-task rules (`67022`, `67028`, `67023`) | about 2,160 | 11 |
| `60227` new external device | about 590 | 6 |

- None of the 11 remaining logon and logoff alerts follow the 2-minute pattern. They cluster
  around real sessions on both machines, which is the expected result.
- Both agents reported throughout the window, so the drop is not a disconnected agent.
- One burst of 168 alerts from the server around 01:35 was the scheduled file-integrity scan
  reporting registry changes in bulk (rules `594` and `750`) from a Windows Update servicing
  run (TrustedInstaller, Volume Shadow Copy and System Restore keys) plus routine Defender,
  Windows Time and TPM maintenance. Not related to the tuning. This was confirmed by checking
  `syscheck.path` on the burst rather than assuming it was benign.

A switch test on 2026-10-13 produced 33 alerts under rule `100110` at level 3, which is
about two switches. Known switcher devices are still matched.

### A gap found while measuring

The 6 remaining `60227` alerts are a Logitech device (`046D:4079`) re-registering through
the Windows virtual HID framework. In these events `deviceId` is a virtual path
(`HID\HID_DEVICE_SYSTEM_VHF\...`) and the vendor and product IDs appear only in `vendorIds`,
so rule `100110` cannot match them. At about 6 a day they are left at level 8 rather than
widening the rule.

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
- **Explain the outliers in the "after" numbers too.** A burst that makes up a third of the
  day needs a cause on record. Checking which registry paths it touched took a minute and
  turned "probably Windows Update" into a stated fact.
