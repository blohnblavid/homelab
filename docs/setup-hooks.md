# Pre-commit secret scanning setup

This repo uses [gitleaks](https://github.com/gitleaks/gitleaks) to block any commit containing
something that looks like a key, password, or token — before it ever reaches git history.

## Install

```powershell
winget install gitleaks
```

## Add the hook

From the repo root, after `git init`, create `.git/hooks/pre-commit` (no file extension):

```bash
#!/bin/sh
gitleaks protect --staged --verbose
if [ $? -ne 0 ]; then
  echo "gitleaks found a potential secret in staged changes. Commit blocked."
  exit 1
fi
```

## One-time full audit

Before pushing for the first time, scan the whole working tree — not just staged changes:

```powershell
gitleaks detect --source . --verbose
```
