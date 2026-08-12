#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

AML_INSIGHTS_BASE_URL="${AML_INSIGHTS_BASE_URL:-http://127.0.0.1:8000}"
AML_USER_EMAIL="${AML_USER_EMAIL:-investigator@tenant1.com}"
PYTHON_BIN="${PYTHON_BIN:-$PROJECT_ROOT/.venv/bin/python}"
SKIP_HEALTH_CHECK="${SKIP_HEALTH_CHECK:-0}"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "Python interpreter not found or not executable: $PYTHON_BIN" >&2
  echo "Set PYTHON_BIN or recreate the local virtualenv." >&2
  exit 1
fi

cd "$PROJECT_ROOT"

if [ "$SKIP_HEALTH_CHECK" != "1" ]; then
  "$PROJECT_ROOT/scripts/check_local_exposure_apps.sh"
fi

exec "$PYTHON_BIN" -m tests.exposure_interpretation.runner \
  --base-url "$AML_INSIGHTS_BASE_URL" \
  --user-email "$AML_USER_EMAIL" \
  "$@"
