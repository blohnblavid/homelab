# Secrets approach

Every service in this repo follows the same pattern: credentials are referenced via Docker
Compose environment variable substitution (`${VAR}`), never hardcoded. Real values live in a
`.env` file that's gitignored and never committed; each service folder ships a `.env.example`
showing exactly which variables it needs, with placeholder values.

```
# Committed — shows what's needed, no real value
PIHOLE_WEBPASSWORD=changeme

# Real .env — gitignored, never committed
PIHOLE_WEBPASSWORD=<actual value, lives only on the host>
```

## Why this matters even for a "just a homelab" project

The habit is the point. Treating every deployment — hobby project or production — as if a
credential leak has real consequences is the practice that transfers directly to professional
security work. A homelab repo with hardcoded passwords "because it doesn't matter, it's just my
house" is the same failure mode as a production leak, just lower stakes.

## Verification, not assumption

Every commit in this repo's history passed through a pre-commit [gitleaks](https://github.com/gitleaks/gitleaks)
scan before being allowed through — nothing here is "probably fine," it's checked. A full-tree
scan (`gitleaks detect --source .`) was also run before the initial push, to catch anything that
might have predated the pre-commit hook.
