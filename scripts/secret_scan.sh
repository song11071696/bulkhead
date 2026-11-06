#!/usr/bin/env bash
# Fails if anything that looks like a real credential is tracked by git.
# Synthetic demo keys are marked EXAMPLE and are allowed.
set -uo pipefail
cd "$(dirname "$0")/.."
patterns='(sk_(live|test)_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[bpa]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer [A-Za-z0-9._-]{24,}|ck_(live|test)_[A-Za-z0-9]{12,})'
hits=$(git ls-files -z | xargs -0 grep -nEI "$patterns" 2>/dev/null | grep -v 'EXAMPLE' | grep -v 'scripts/secret_scan.sh' || true)
if [ -n "${CLOCKED_API_KEY:-}" ] && [ "${#CLOCKED_API_KEY}" -gt 16 ]; then
  if git ls-files -z | xargs -0 grep -nF "$CLOCKED_API_KEY" >/dev/null 2>&1; then hits="$hits
CLOCKED_API_KEY value found in tracked files"; fi
fi
if git ls-files | grep -qE '(^|/)\.env$'; then hits="$hits
.env is tracked"; fi
if [ -n "$hits" ]; then echo "SECRET SCAN FAILED:"; echo "$hits"; exit 1; fi
echo "secret scan: clean ($(git ls-files | wc -l) tracked files)"
