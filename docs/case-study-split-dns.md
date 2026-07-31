# The Split DNS Saga: When Every Layer Was Almost Right

## The goal

Get every device on the tailnet resolving `.lab` hostnames (`homepage.lab`, `sonarr.lab`, etc.) through Pi-hole, as the foundation for a reverse proxy setup with Nginx Proxy Manager. The plan: use Tailscale's DNS settings to point client devices at Pi-hole, running on the K16 mini PC.

This should have been a fifteen-minute config change. It took six distinct fixes, each one masking the next, before it actually worked end to end — plus a seventh, once the reverse proxy entered the picture.

## Symptom 1: DNS timeouts that made no sense

With a Global nameserver override configured in the Tailscale admin console (pointing at Pi-hole's Tailscale IP) and the override toggle switched on, `nslookup homepage.lab` from a client machine just... timed out. Every time. No error, no fallback, just silence from `magicdns.localhost-tailscale-daemon`.

The obvious troubleshooting path — is Tailscale connected? Is the service running? Is the firewall blocking something? — all came back clean:

- `tailscale status` showed an active, healthy connection to the K16 device
- `Get-Service Tailscale` showed `Running`
- `Get-DnsClientNrptPolicy` showed the DNS interception policy registered correctly
- `Test-NetConnection` to Tailscale's local DNS proxy on port 53 succeeded

Every individual layer looked fine. And yet nothing resolved.

## Root cause #1: a stale Tailscale IP

The actual problem was embarrassingly simple, once found: the Global nameserver override had been configured with the *wrong device's* Tailscale IP. Two machines' addresses had been mixed up at some point — likely when noting IPs down during earlier setup — so client DNS queries were being told to route through themselves rather than through the actual Pi-hole host.

**Lesson:** Tailscale IPs aren't guaranteed to stay static forever (device re-registration, key expiry and reauth, factory resets can all reassign them). Don't assume a written-down IP is still current — verify against `tailscale status` before troubleshooting anything downstream of it.

## Symptom 2: fixed the IP, still broken — and now everything's slow

With the correct IP in place, `nslookup` *still* timed out. But something new showed up: normal web browsing became noticeably slower on every device connected to Tailscale, and reverted to normal the instant Tailscale was disconnected.

## Root cause #2: the wrong tool for the job

A **Global nameserver override** doesn't just handle the domains you care about — it redirects *every* DNS query, for *every* domain, through the configured nameserver. That meant every lookup — `google.com`, streaming services, everything — was being routed through Pi-hole over Tailscale and then out to an upstream resolver, adding a real round-trip delay to all normal browsing, not just `.lab` names.

The right tool was **Split DNS**: a nameserver entry scoped to a specific domain (`lab`), so only queries for that domain get redirected, and everything else resolves the way it always has.

**Lesson:** "override all DNS" and "override DNS for one domain" are very different operations with very different blast radii. Confirm which one you actually need before flipping it on tailnet-wide.

## Symptom 3: Split DNS configured, still resolving to the wrong address

With Split DNS properly scoped to `.lab` and NRPT confirmed registered correctly (`Namespace: .lab`), queries were *finally* being routed correctly — confirmed using `Resolve-DnsName`, which follows Windows' real DNS Client resolution path (unlike `nslookup`, which turned out to be an unreliable diagnostic tool for this scenario the whole time, since it doesn't consistently honor NRPT policy).

But the answer coming back was still the old, stale IP.

## Root cause #3 and #4: a stale record, then a stale cache

Two more layers, stacked on top of each other:

1. Pi-hole's own **Local DNS Record** for `homepage.lab` was still pointing at the same stale IP from root cause #1 — a separate leftover from the same earlier mix-up, unrelated to the Tailscale-side fix.
2. After correcting that record, Pi-hole's DNS engine (dnsmasq/FTL, running inside its Docker container) kept serving the *old* cached answer anyway. Querying Pi-hole directly — bypassing every client-side cache — still returned the stale IP, which ruled out the client entirely and pointed squarely at Pi-hole's own cache.

A `docker restart pihole` forced a clean reload, and the correct answer finally came back — verified directly against Pi-hole, and then through the full path (client → NRPT → Tailscale → Pi-hole → back).

## Symptom 4: DNS was perfect, and the page still wouldn't load

With resolution fully confirmed end to end, hitting the service directly in a browser produced a new error: `Host validation failed`. Not a DNS issue at all — the request had correctly reached the right container, on the right port, over the right hostname. This was the *application* rejecting the request.

## Root cause #5: the app didn't trust its own new hostname

Some self-hosted dashboards validate the incoming `Host` header against an explicit allow-list, as a defense against DNS rebinding attacks. The dashboard in question only trusted its original internal hostname — the new `.lab` hostname wasn't on that list, so it got rejected outright, DNS correctness notwithstanding.

The fix was to add the new hostname to the app's own allowed-hosts environment variable and recreate the container so the change actually took effect (a plain restart doesn't always reload environment variables, depending on how an app reads them at startup).

A tempting alternative existed: configure the upcoming reverse proxy to rewrite the `Host` header on its way to each backend, so every app would keep seeing only the hostname it already trusted, regardless of what the client actually typed. That would have solved this one case with zero app-side config. It was deliberately set aside — a blanket header rewrite hides a real mismatch rather than resolving it, and it assumes every backend is indifferent to the Host header it receives, which isn't true across every self-hosted app (some use it for callback URLs or absolute links). The safer, more explicit path was to update each app's own allow-list as needed, and only when a given app actually enforces one — most don't.

## Symptom 5: the proxy itself couldn't reach the backend

With DNS and the app's host validation both sorted, the last step was pointing Nginx Proxy Manager at the service so it could be reached without a port number. The first attempt returned a clean `502 Bad Gateway` — a different kind of failure than anything before it. A 502 means the proxy itself is up and answering requests, but couldn't successfully connect to whatever it was told to forward to.

## Root cause #6: containers don't inherit the host's hostnames for free

The proxy was configured to forward to `homeserver`, the same hostname used elsewhere in the stack. But `homeserver` only resolves correctly on the host machine and on containers that have been explicitly told about it — which, in other compose files, was handled with an `extra_hosts: homeserver:host-gateway` entry. The proxy's own container didn't have that mapping, so from its point of view, `homeserver` was just an unresolvable name, and the connection failed before it ever reached the backend.

Pointing the proxy at K16's Tailscale IP directly, instead of the hostname, sidestepped the problem entirely — no name resolution required, no container-specific DNS mapping to remember to add.

**Lesson:** a hostname that resolves fine on the host, or even in one container, doesn't necessarily resolve in another. Each container's DNS view is its own; don't assume a name is portable across the stack just because it's been added once.

## The finish line

With all six fixes in place — the corrected Tailscale IP, Split DNS instead of a global override, the corrected Local DNS Record, a fresh Pi-hole cache, the app's own allowed-hosts entry, and a proxy pointed at an IP rather than an unresolvable hostname — the service loaded cleanly at its plain `.lab` address, no port required. Exactly the outcome the project set out for, six unrelated-looking problems later.

## What made this hard

No single step in this chain was actually difficult to diagnose in isolation. What made it slow was that **each fix revealed the next problem only after being applied** — the stale IP masked the Global-vs-Split-DNS issue, which masked the stale DNS record, which masked the caching issue. Every "clean" diagnostic result (service running, firewall fine, NRPT registered, port reachable) was individually true and collectively misleading, because the actual fault was never in any of the layers being checked — it was in the *data* those layers were correctly relaying.

**Takeaways for next time:**
- Verify current state (IPs, config values) directly rather than trusting notes or memory, especially for anything that can silently change (dynamic addresses, DHCP leases, reassigned identifiers)
- Match the scope of a fix to the actual problem — a global override is not a substitute for a scoped one, even if it technically "works"
- When a config change doesn't seem to take effect, check for a cache at every layer in the chain, not just the client — DNS resolvers, proxies, and containerized services all cache independently
- A tool's absence of error (a clean timeout, a "successful" test) doesn't mean that layer isn't the problem — it just means it isn't *lying*
- Getting DNS right doesn't mean the job is done — the application layer can have its own opinions about what hostnames it's willing to accept, entirely independent of whether the name resolves correctly
