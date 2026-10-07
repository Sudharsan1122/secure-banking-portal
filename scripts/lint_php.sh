#!/usr/bin/env bash
set -euo pipefail

fail=0
while IFS= read -r -d '' file; do
  if ! php -l "$file" > /dev/null 2>&1; then
    echo "❌ Syntax error: $file"
    php -l "$file"
    fail=1
  fi
done < <(find . -type f -name "*.php" \
          -not -path "./vendor/*" \
          -not -path "./tests/*" \
          -print0)

if [ $fail -eq 1 ]; then exit 1; fi
echo "✅ All PHP files pass syntax check"
