# Case Study: Moving Wazuh Off Docker Desktop to Fix Source-IP Masking

## Summary

Every attack run against the homelab's test targets showed up in Wazuh as coming from the
Docker bridge gateway instead of the real attacker. The cause was Docker Desktop for Windows,
not Wazuh. This exercise stood up a second host (`ubuntu-lab`, bare-metal Ubuntu Server with
native Docker Engine), migrated the Wazuh stack to it, and then ran a controlled before/after
test with the same app and the same payload on both hosts to prove where the masking happens.

Two things surfaced along the way that changed the plan: moving the *manager* does not unmask
traffic to apps that still run on the old host, and the new host's spinning disk is a real
performance constraint.

## The setup

| Node | Hardware | OS | Network |
|---|---|---|---|
| `homeserver` (K16) | Ryzen 7 7735HS, 32GB RAM, NVMe | Windows 11 Pro, Docker Desktop (WSL2) | Wi-Fi |
| `ubuntu-lab` | ASUS Vivo AiO, Core i5-8250U, ~8GB RAM, 1TB 5,400 RPM SMR HDD | Ubuntu Server 24.04 LTS, native Docker Engine | Wi-Fi, static IP (netplan) |

Both machines are on Wi-Fi. `ubuntu-lab` has an unused wired NIC and is managed headless over
SSH.

## The problem

In the [earlier attack-detection exercise](case-study-dvwa-attack-detection.md) (nikto, Hydra,
sqlmap against an isolated target), every alert carried the same `data.srcip`: the Docker bridge
gateway, regardless of whether the traffic came from the attacker VM or a phone. Docker Desktop
on Windows rewrites external client IPs to the bridge gateway before traffic reaches a
container, so anything inside the container, including its access logs, only ever sees the
gateway. A SIEM can't attribute an attack it can't see the source of.

The usual Linux workaround, `macvlan` networking, is awkward on Docker Desktop for Windows. The
K16 runs most of the lab and stays on Windows, so the fix was a second host alongside it rather
than a replacement.

## Migration

- Deployed the official Wazuh single-node stack (manager, indexer, dashboard, Wazuh 4.14.5) on
  `ubuntu-lab` using Docker Engine from Docker's official apt repository. The compose file is in
  [`docker-compose/security/wazuh/`](../docker-compose/security/wazuh/); the old K16 copy is in
  [`archive/wazuh-k16/`](../archive/wazuh-k16/).
- Set the kernel parameter OpenSearch requires: `sysctl -w vm.max_map_count=262144`. On Docker
  Desktop this lives inside the WSL2 VM; here it's set on the host itself.
- Compared with the K16 deployment, the indexer heap is 2GB instead of 1GB, and the dashboard is
  published on 443 instead of 8443.
- Re-homed all three agents (`ubuntu-lab`, `homeserver`, `main-pc`) to register with the new
  manager.
- Ported the custom suppression rules (IDs `100100`-`100102` and `100110`) into `local_rules.xml`
  on the new manager, so the [noise tuning](case-study-wazuh-alert-tuning.md) from earlier work
  carried over.

## Verification: a controlled before/after

The goal was to show where the masking happens, not just assume it. Juice Shop (OWASP's
intentionally vulnerable app) was run on both hosts, with its access log mounted out of the
container so Wazuh could read it. The same request was sent from the same PC to each:

```bash
curl "http://<host>:8082/rest/products/search?q=test'%20UNION%20SELECT%20null,null--"
```

Client IP recorded in each app's own access log:

| Host | Client IP in the access log |
|---|---|
| K16 (Docker Desktop) | `::ffff:192.168.16.1` (a Docker network gateway) |
| `ubuntu-lab` (native Docker) | `::ffff:192.168.1.142` (the PC that sent the request) |

Same app version, same payload, same user agent (`curl/8.21.0`). The only difference is the
Docker runtime. That isolates the masking to Docker Desktop's networking layer.

**Detection on the new host.** Wazuh's out-of-the-box ruleset flagged the request as rule
`31103` ("SQL injection attempt", level 7, MITRE T1190 Exploit Public-Facing Application), with
`data.srcip` carrying the real client address (`::ffff:192.168.1.142` on both PC-originated alerts). Log line to alert took about one second on an earlier test request sent from `ubuntu-lab` itself (access
log entry at 06:53:45, alert at 06:53:46.627). The target returned HTTP 500 rather than 200, so
rule `31106` ("web attack returned code 200") from the earlier exercise did not apply here. The
injection string `1' OR 1=1--` alone only raised the generic 500-error rule (`31122`); rule
`31103` matched once the payload contained SQL keywords (`UNION SELECT`).

## Juice Shop's access log, and an earlier wrong conclusion

When Juice Shop first ran on the K16, its README recorded it as unmonitorable because it
produced no per-request logging. That was wrong. The conclusion came from watching the
container's stdout, which is empty per request. Juice Shop writes its access log to a file,
`access.log.<date>`, in `/juice-shop/logs` inside the container, in Apache combined format, so
Wazuh's stock web rules decode it with no custom decoder.

On `ubuntu-lab` the compose file mounts that folder at `/opt/juice-shop/logs` on the host, and
the agent tails it with a `<localfile>` entry. The host folder has to be owned by UID 65532,
the container's user, or Juice Shop can't write to it. Isolation is unchanged from the K16: no
restart policy, published on the LAN interface only, no reverse proxy entry
([details](../docker-compose/security/juiceshop/README.md)).

## What moving the manager did not fix

Moving the Wazuh manager fixed the manager side. It did not change anything for apps that still
run in Docker Desktop on the K16. Their access logs still record the bridge gateway, and the
agent forwards those logs as written, so alerts about them keep the masked IP. That is why the
test target itself had to move to `ubuntu-lab`. The earlier attack target (DVWA) was retired
rather than migrated; Juice Shop replaced it.

## Quirk: the `::ffff:` prefix

Both hosts log client addresses as IPv4-mapped IPv6 (`::ffff:192.168.1.142`), and Wazuh stores
the field as written. Since it appears on both hosts, it comes from the application (Node's
dual-stack listener), not from Docker. Effect: `data.srcip` searches need a wildcard
(`data.srcip:*192.168.1.142`), and features keyed on plain IPv4 values (GeoIP, CDB lists,
allowlists) likely won't match. Left as documented rather than patched with a custom decoder.

## Pi-hole: deployed, but not put into use

Pi-hole was a migration candidate too. On the K16, inspection showed the container served 0.00
queries per minute and logged only its own Docker healthchecks, because no device used it as
DNS: it was never pushed through router DHCP. Pi-hole now runs on `ubuntu-lab`, but nothing is
routed through it. Pointing the household at it would mean router-level DHCP changes and DNS
risk for every device, with no existing usage to preserve, so that step was deferred. The K16
container has since been removed.

That review missed one dependency. No LAN device used the K16 Pi-hole as DNS, but Tailscale
Split DNS sent tailnet `.lab` lookups to it, and its Local DNS Records were what made the `.lab`
names for Nginx Proxy Manager work. Removing it took those names down. They'll come back once
the records are recreated on ubuntu-lab's Pi-hole and Split DNS is repointed
([known issues](known-issues.md)).

## Dead-man's-switch tuning on slower hardware

`ubuntu-lab` reports to an external Healthchecks.io check, mirroring the K16 setup. It sent
false-positive push alerts even though the machine was up. Two causes:

1. **Timing mismatch.** The check was configured for a 2-minute period with 1-minute grace
   (3-minute window), but the host's cron job ran every 5 minutes. Every cycle exceeded the
   window, so a failure was guaranteed.
2. **Latency headroom.** The K16 tolerated 1-minute grace; the AIO needed more.

Final configuration: cron every 2 minutes, check set to 2-minute period and 2-minute grace
(4-minute maximum before alerting). The cron line is in
[`tools/healthcheck/ubuntu-lab.cron`](../tools/healthcheck/ubuntu-lab.cron):

```cron
*/2 * * * * curl -fsS -m 20 --retry 3 https://hc-ping.com/<check-uuid> > /dev/null 2>&1
```

**Why more grace was needed.** A live `vmstat` sample on `ubuntu-lab` showed I/O wait of 30%,
37%, 39% and 17% across four one-second samples (the first line, an average since boot, showed
91%), with 2-4 processes blocked on I/O and the CPU mostly idle. The indexer's write pattern on
a 5,400 RPM SMR drive is the most likely source of the latency (about 70% confidence from this
evidence; the cause wasn't isolated further). The 2/2 configuration absorbs it, and
`curl -m 20 --retry 3` covers a slow single ping.

## Incidental finding: routine updates look like package installs

After the migration, Wazuh raised paired `dpkg` alerts (rules `2902` and `2904`, level 7)
every couple of seconds. `/var/log/apt/history.log` showed `unattended-upgrade` applying
routine security updates. These rules are the ones that would catch an unauthorized package
install, so they were left unsuppressed. If noise tuning is needed later, a narrow rule scoped
to updates run by `unattended-upgrade` is safer than disabling them.

## Takeaways

- **Verify the claim with a controlled test.** "Native Docker fixes IP masking" is plausible,
  but one app, one payload, and two hosts turns it into evidence, and exposed the nuance that
  the manager move alone fixes nothing for apps left on the old host.
- **Re-check old conclusions when the environment changes.** "Juice Shop has no access log"
  was a reasonable reading of stdout and was still wrong. The move forced a second look.
- **Measure before blaming a cause.** The alert false positives had two causes: a config
  mismatch, and slow hardware. A `vmstat` sample put a number on the second (high I/O wait on
  a spinning disk) instead of leaving it as a guess.
- **An audit can end in "don't flip the switch yet," and still miss something.** The Pi-hole
  review correctly avoided a household-wide DNS change, but it only checked LAN usage. It
  missed the tailnet's Split DNS path, so removing the old container broke `.lab` names.
- **Alerts caused by normal maintenance are signal, not noise to delete.** The package-install
  rules fire on routine updates because they can't tell routine from malicious; suppressing
  them blind would remove the detection.
- **Open items:**
  - the `::ffff:` prefix (documented, not fixed)
  - the SMR disk as the host's main performance limit; an SSD is the real fix, and the indexer
    data has no backup yet
  - running the SIEM manager over Wi-Fi
  - the static IP is set in netplan rather than reserved on the router, so it should be
    confirmed to sit outside the router's DHCP pool
