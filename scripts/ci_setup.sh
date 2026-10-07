#!/usr/bin/env bash
set -euo pipefail

EXPECTED_USERS=2
EXPECTED_TABLES=20

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-root}"
DB_NAME="${DB_NAME:-banking}"

AUTH_ARGS=("-h" "$DB_HOST" "-P" "$DB_PORT" "-u$DB_USER")
if [ -n "$DB_PASS" ]; then
  AUTH_ARGS+=("-p$DB_PASS")
fi

USERS=$(mysql "${AUTH_ARGS[@]}" "$DB_NAME" -sN \
        -e "SELECT COUNT(*) FROM users;")
TABLES=$(mysql "${AUTH_ARGS[@]}" "$DB_NAME" -sN \
        -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_NAME';")

echo "Users:  $USERS (expected ≥ $EXPECTED_USERS)"
echo "Tables: $TABLES (expected ≥ $EXPECTED_TABLES)"

if [ "$USERS" -lt "$EXPECTED_USERS" ]; then
  echo "❌ Insufficient seed users"; exit 1
fi
if [ "$TABLES" -lt "$EXPECTED_TABLES" ]; then
  echo "❌ Insufficient seed tables"; exit 1
fi
echo "✅ Seed data verified"
