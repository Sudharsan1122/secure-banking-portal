#!/usr/bin/env bash
set -euo pipefail

PATTERNS=(
  'password\s*=\s*["\x27][^"\x27]{8,}'
  'api[_-]?key\s*=\s*["\x27][A-Za-z0-9]{20,}'
  'secret\s*=\s*["\x27][A-Za-z0-9]{20,}'
  'BEGIN RSA PRIVATE KEY'
  'BEGIN OPENSSH PRIVATE KEY'
  'ghp_[A-Za-z0-9]{36}'
  'AKIA[0-9A-Z]{16}'
)

fail=0
for pat in "${PATTERNS[@]}"; do
  if grep -rEn "$pat" --include="*.php" --include="*.js" \
      --include="*.env*" --exclude-dir=vendor --exclude-dir=.git --exclude-dir=tests . ; then
    echo "❌ Possible secret leak with pattern: $pat"
    fail=1
  fi
done

if [ $fail -eq 1 ]; then exit 1; fi
echo "✅ No obvious secrets detected"
