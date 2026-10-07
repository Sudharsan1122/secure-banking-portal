#!/usr/bin/env bash
set -euo pipefail

RESULT=$(curl -fsS http://127.0.0.1:8080/admin/verify_log_chain.php?format=json \
         -H "Cookie: ${ADMIN_SESSION:-}" 2>/dev/null || echo '{"status":"unreachable"}')

if [ -z "$RESULT" ] || echo "$RESULT" | grep -q 'unreachable' || ! echo "$RESULT" | grep -q '"status"'; then
  # Fallback to direct PHP CLI hash chain verification for headless CI environments
  RESULT=$(php -r "
    require_once 'config/database.php';
    require_once 'security/logger.php';
    \$res = verify_log_chain();
    echo json_encode([
      'status' => (!empty(\$res['verified']) ? 'valid' : 'invalid'),
      'verified' => \$res['verified'] ?? false,
      'total_records' => \$res['total_records'] ?? 0,
      'message' => \$res['message'] ?? ''
    ]);
  " 2>/dev/null || echo '{"status":"unreachable"}')
fi

echo "Chain verification: $RESULT"

if echo "$RESULT" | grep -q '"status":"valid"'; then
  echo "✅ Hash chain intact"
  exit 0
else
  echo "❌ Hash chain broken or unreachable"
  exit 1
fi
