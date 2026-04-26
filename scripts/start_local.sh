#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

DB_INPUT="${1:-}"
PORT="${2:-8000}"

# Load .env values, then intentionally override DATABASE_URL for local runs.
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [ -z "${SECRET_KEY:-}" ]; then
  export SECRET_KEY="local-dev-secret-key"
fi

resolve_sqlite_url() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf 'sqlite:///%s\n' "$path"
  else
    printf 'sqlite:///%s/%s\n' "$PROJECT_ROOT" "$path"
  fi
}

if [ -n "$DB_INPUT" ]; then
  if [[ "$DB_INPUT" == *"://"* ]]; then
    export DATABASE_URL="$DB_INPUT"
  else
    export DATABASE_URL="$(resolve_sqlite_url "$DB_INPUT")"
  fi
elif [ -n "${LOCAL_DATABASE_URL:-}" ]; then
  export DATABASE_URL="$LOCAL_DATABASE_URL"
else
  export DATABASE_URL="sqlite:///$PROJECT_ROOT/app.db"
fi

cat <<MSG
Starting amlInsights locally with DATABASE_URL override:
  DATABASE_URL=$DATABASE_URL
  SECRET_KEY=(set)
  PORT=$PORT
MSG

cd "$PROJECT_ROOT"
if [ -x "$PROJECT_ROOT/.venv/bin/uvicorn" ]; then
  exec "$PROJECT_ROOT/.venv/bin/uvicorn" main:app --host 127.0.0.1 --port "$PORT" --reload
fi

if command -v uvicorn >/dev/null 2>&1; then
  exec uvicorn main:app --host 127.0.0.1 --port "$PORT" --reload
fi

cat <<MSG
uvicorn was not found.

Recreate/install the local virtualenv, then rerun this script:
  cd "$PROJECT_ROOT"
  /opt/homebrew/bin/python3.13 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip setuptools wheel
  pip install -r requirements.txt
MSG
exit 1
