#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
BASE_URL="http://$HOST:$PORT"
SERVER_LOG="$(mktemp)"
SERVER_PID=""

AML_USER_EMAIL="${AML_USER_EMAIL:-}"
AML_TENANT_ID="${AML_TENANT_ID:-}"
AML_SESSION_COOKIE="${AML_SESSION_COOKIE:-}"
SKIP_SERVER_START="${SKIP_SERVER_START:-0}"
HAS_AUTH_CONTEXT="0"
HAS_SESSION_CONTEXT="0"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$SERVER_LOG"
}

fail() {
  echo "FAIL: $1"
  if [[ -f "$SERVER_LOG" ]]; then
    echo
    echo "Server log:"
    cat "$SERVER_LOG"
  fi
  cleanup
  exit 1
}

assert_status() {
  local actual="$1"
  shift
  local expected_list=("$@")
  local expected
  for expected in "${expected_list[@]}"; do
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

build_header_args() {
  HEADER_ARGS=()
  if [[ -n "$AML_USER_EMAIL" ]]; then
    HEADER_ARGS+=(-H "x-user-email: $AML_USER_EMAIL")
    HAS_AUTH_CONTEXT="1"
  fi
  if [[ -n "$AML_TENANT_ID" ]]; then
    HEADER_ARGS+=(-H "x-tenant-id: $AML_TENANT_ID")
  fi
  if [[ -n "$AML_SESSION_COOKIE" ]]; then
    HEADER_ARGS+=(-H "Cookie: $AML_SESSION_COOKIE")
    HAS_SESSION_CONTEXT="1"
  fi
}

request_status() {
  local path="$1"
  shift
  local method="${1:-GET}"
  shift || true
  curl -sS -o /dev/null -w "%{http_code}" "${HEADER_ARGS[@]}" -X "$method" "$BASE_URL$path"
}

request_location() {
  local path="$1"
  curl -sS -D - -o /dev/null "${HEADER_ARGS[@]}" "$BASE_URL$path" \
    | awk 'tolower($1)=="location:" {sub(/\r$/, "", $2); print $2; exit}'
}

normalize_location_path() {
  local location="$1"
  # Handle absolute redirects like http://127.0.0.1:8000/path?x=y
  location="$(printf "%s" "$location" | sed -E 's#^https?://[^/]+##')"
  printf "%s" "$location"
}

trap cleanup EXIT

if [[ ! -x "$VENV_PYTHON" ]]; then
  fail "Expected virtualenv Python at $VENV_PYTHON"
fi

echo "Using Python: $("$VENV_PYTHON" --version 2>&1)"

if [[ "$SKIP_SERVER_START" == "1" ]]; then
  echo "Using existing server at $BASE_URL (SKIP_SERVER_START=1)"
else
  echo "Starting app from $ROOT_DIR on $BASE_URL"
  cd "$ROOT_DIR" || fail "Unable to cd into project root"

  if [[ -f "$ROOT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.env"
    set +a
  fi

  "$VENV_PYTHON" -m uvicorn main:app --host "$HOST" --port "$PORT" >"$SERVER_LOG" 2>&1 &
  SERVER_PID="$!"

  for _ in {1..80}; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      fail "Uvicorn exited before the app became ready (try another PORT or SKIP_SERVER_START=1)"
    fi
    if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
fi

if ! curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
  fail "App was not ready within timeout at $BASE_URL"
fi

build_header_args

echo
echo "== Smoke: Health =="
status="$(request_status "/health")"
assert_status "$status" 200 || fail "/health status=$status expected=200"
echo "PASS /health status=$status"

echo
echo "== Smoke: Legacy Redirects =="
sel_status="$(request_status "/ui/red-flags/selections")"
appr_status="$(request_status "/ui/red-flags/approvals")"
audit_status="$(request_status "/ui/red-flags/audit")"
assert_status "$sel_status" 303 || fail "selections redirect status=$sel_status expected=303"
assert_status "$appr_status" 303 || fail "approvals redirect status=$appr_status expected=303"
assert_status "$audit_status" 303 || fail "audit redirect status=$audit_status expected=303"
echo "PASS legacy redirects return 303"

sel_loc="$(normalize_location_path "$(request_location "/ui/red-flags/selections")")"
appr_loc="$(normalize_location_path "$(request_location "/ui/red-flags/approvals")")"
audit_loc="$(normalize_location_path "$(request_location "/ui/red-flags/audit")")"
if [[ "$HAS_SESSION_CONTEXT" == "1" ]]; then
  [[ "$sel_loc" == "/ui/red-flags/workspace?view=selections" ]] || fail "Unexpected selections location: $sel_loc"
  [[ "$appr_loc" == "/ui/red-flags/workspace?view=approvals&status=pending_approval" ]] || fail "Unexpected approvals location: $appr_loc"
  [[ "$audit_loc" == "/ui/red-flags/workspace?view=audit" ]] || fail "Unexpected audit location: $audit_loc"
else
  [[ "$sel_loc" == "/login" || "$sel_loc" == /login\?* ]] || fail "Unexpected selections location (unauthenticated): $sel_loc"
  [[ "$appr_loc" == "/login" || "$appr_loc" == /login\?* ]] || fail "Unexpected approvals location (unauthenticated): $appr_loc"
  [[ "$audit_loc" == "/login" || "$audit_loc" == /login\?* ]] || fail "Unexpected audit location (unauthenticated): $audit_loc"
fi
echo "PASS legacy redirect targets"

echo
echo "== Smoke: Unified Workspace Endpoint =="
workspace_status="$(request_status "/ui/red-flags/workspace")"
if [[ "$HAS_SESSION_CONTEXT" == "1" ]]; then
  if ! assert_status "$workspace_status" 200 401 403; then
    fail "workspace status=$workspace_status expected in {200,401,403}"
  fi
else
  if ! assert_status "$workspace_status" 303 401 403; then
    fail "workspace status=$workspace_status expected in {303,401,403} when unauthenticated"
  fi
fi
echo "PASS /ui/red-flags/workspace status=$workspace_status"

echo
echo "== Smoke: Workspace APIs =="
policy_status="$(request_status "/api/red-flags/workspace-policy")"
data_status="$(request_status "/api/red-flags/workspace-data")"
if ! assert_status "$policy_status" 200 401 403; then
  fail "workspace-policy status=$policy_status expected in {200,401,403}"
fi
if ! assert_status "$data_status" 200 401 403 422; then
  fail "workspace-data status=$data_status expected in {200,401,403,422}"
fi
echo "PASS /api/red-flags/workspace-policy status=$policy_status"
echo "PASS /api/red-flags/workspace-data status=$data_status"

echo
echo "All red flags workspace smoke checks passed."
echo "Tip: set AML_USER_EMAIL and AML_TENANT_ID to validate API role behavior."
echo "Tip: set AML_SESSION_COOKIE='session=<value>' to validate authenticated UI redirect behavior."
