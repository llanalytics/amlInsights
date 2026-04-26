#!/bin/bash
# Migrate amlInsights database safely.
# Usage:
#   ./scripts/migrate_db.sh [local|remote|database-url] [auto|upgrade|stamp|repair]
#
# Examples:
#   ./scripts/migrate_db.sh local
#   ./scripts/migrate_db.sh remote
#   ./scripts/migrate_db.sh remote upgrade
#   ./scripts/migrate_db.sh sqlite:////tmp/amlinsights.db stamp
#   ./scripts/migrate_db.sh local repair

set -euo pipefail

TARGET="${1:-local}"
ACTION="${2:-auto}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"
PATH="$PROJECT_ROOT/.venv/bin:$PATH"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if ! command -v alembic >/dev/null 2>&1; then
  echo -e "${RED}Error: alembic is required in PATH.${NC}"
  exit 1
fi

# Load only required keys from .env without shell-sourcing.
if [ -f "$ENV_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue
        ;;
    esac

    key="${line%%=*}"
    value="${line#*=}"
    key="$(printf '%s' "$key" | tr -d '[:space:]')"
    value="${value%$'\r'}"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi

    case "$key" in
      DATABASE_URL)
        if [ -z "${DATABASE_URL:-}" ]; then DATABASE_URL="$value"; fi
        ;;
      LOCAL_DATABASE_URL)
        if [ -z "${LOCAL_DATABASE_URL:-}" ]; then LOCAL_DATABASE_URL="$value"; fi
        ;;
      DB_SCHEMA)
        if [ -z "${DB_SCHEMA:-}" ]; then DB_SCHEMA="$value"; fi
        ;;
    esac
  done < "$ENV_FILE"
fi

resolve_db_url() {
  case "$TARGET" in
    local)
      if [ -n "${LOCAL_DATABASE_URL:-}" ]; then
        printf '%s\n' "$LOCAL_DATABASE_URL"
      elif [ -n "${DATABASE_URL:-}" ] && [[ "${DATABASE_URL:-}" == sqlite* ]]; then
        printf '%s\n' "$DATABASE_URL"
      else
        printf 'sqlite:///%s/app.db\n' "$PROJECT_ROOT"
      fi
      ;;
    remote)
      if [ -z "${DATABASE_URL:-}" ]; then
        return 1
      fi
      printf '%s\n' "$DATABASE_URL"
      ;;
    *)
      if [[ "$TARGET" == *"://"* ]]; then
        printf '%s\n' "$TARGET"
      else
        return 1
      fi
      ;;
  esac
}

if ! DB_URL="$(resolve_db_url)"; then
  echo -e "${RED}Error: could not resolve DATABASE_URL for target '$TARGET'.${NC}"
  echo "Set DATABASE_URL/LOCAL_DATABASE_URL in .env, or pass a full database URL."
  exit 1
fi

export DATABASE_URL="$DB_URL"
if [ "$TARGET" = "local" ] && [ -n "${LOCAL_DATABASE_URL:-}" ]; then
  export DATABASE_URL="$LOCAL_DATABASE_URL"
fi

DECIDE_ACTION_PY='
import os
from sqlalchemy import create_engine, inspect

url = os.environ["DATABASE_URL"]
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg://", 1)
elif url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)

schema = os.environ.get("DB_SCHEMA", "").strip() or None
engine = create_engine(url)
insp = inspect(engine)

has_version = insp.has_table("alembic_version", schema=schema)
required_tables = [
    "users",
    "auth_users",
    "auth_roles",
    "auth_platform_user_roles",
    "ten_tenants",
    "ten_module_entitlements",
]
missing_required = [t for t in required_tables if not insp.has_table(t, schema=schema)]
has_all_required = len(missing_required) == 0
has_any_core = insp.has_table("users", schema=schema) or insp.has_table("auth_users", schema=schema)

if has_version and has_all_required:
    print("upgrade")
elif has_version and not has_all_required:
    print("repair")
elif has_any_core and has_all_required:
    print("stamp")
else:
    print("upgrade")
'

if [ "$ACTION" = "auto" ]; then
  if ACTION_RESOLVED="$(python -c "$DECIDE_ACTION_PY" 2>/dev/null)"; then
    ACTION="$ACTION_RESOLVED"
  else
    ACTION="upgrade"
  fi
fi

if [ "$ACTION" != "upgrade" ] && [ "$ACTION" != "stamp" ] && [ "$ACTION" != "repair" ]; then
  echo -e "${RED}Error: action must be one of auto|upgrade|stamp|repair.${NC}"
  exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}AML Insights - DB Migration${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Target: $TARGET"
echo "DATABASE_URL: $DATABASE_URL"
echo "DB_SCHEMA: ${DB_SCHEMA:-"(default)"}"
echo "Action: $ACTION"
echo ""

cd "$PROJECT_ROOT"
if [ "$ACTION" = "stamp" ]; then
  echo -e "${YELLOW}Stamping current schema as head...${NC}"
  alembic stamp head
elif [ "$ACTION" = "repair" ]; then
  echo -e "${YELLOW}Repairing missing tables with SQLAlchemy metadata...${NC}"
  python - <<'PY'
from database import Base, engine
import models  # noqa: F401
import platform_models  # noqa: F401
Base.metadata.create_all(bind=engine, checkfirst=True)
print("metadata create_all complete")
PY
  echo -e "${GREEN}Applying migrations after repair...${NC}"
  alembic upgrade head
else
  echo -e "${GREEN}Applying migrations...${NC}"
  alembic upgrade head
fi

echo ""
echo -e "${GREEN}Done.${NC}"
