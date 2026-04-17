#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSIGHTS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REDFLAGS_ROOT="$(cd "$INSIGHTS_ROOT/../amlredflags" && pwd)"

DB_INPUT="${1:-$INSIGHTS_ROOT/app.db}"

if [[ "$DB_INPUT" = /* ]]; then
  DB_PATH="$DB_INPUT"
else
  DB_PATH="$INSIGHTS_ROOT/$DB_INPUT"
fi
DB_PATH="$(realpath "$DB_PATH")"
DB_URL="sqlite:///$DB_PATH"

run_with_repo_venv() {
  local repo_root="$1"
  local cmd="$2"
  if [ -d "$repo_root/.venv" ]; then
    (
      cd "$repo_root"
      # shellcheck disable=SC1091
      source .venv/bin/activate
      eval "$cmd"
    )
  else
    (
      cd "$repo_root"
      eval "$cmd"
    )
  fi
}

echo "Using shared local DB: $DB_URL"

if [ -d "$REDFLAGS_ROOT" ]; then
  echo "Migrating amlredflags..."
  run_with_repo_venv "$REDFLAGS_ROOT" "DATABASE_URL='$DB_URL' alembic upgrade head"
else
  echo "Skipping amlredflags migration; repo not found at $REDFLAGS_ROOT"
fi

echo "Migrating amlInsights..."
run_with_repo_venv "$INSIGHTS_ROOT" "DATABASE_URL='$DB_URL' alembic upgrade head"

echo "Done."
