#!/usr/bin/env bash
set -euo pipefail

AML_INSIGHTS_BASE_URL="${AML_INSIGHTS_BASE_URL:-http://127.0.0.1:8000}"
DATA_HUB_BASE_URL="${DATA_HUB_BASE_URL:-http://127.0.0.1:8100}"

check_json_endpoint() {
  local label="$1"
  local url="$2"
  local expected="$3"
  local body

  if ! body="$(curl -fsS "$url")"; then
    echo "FAIL $label: could not reach $url" >&2
    return 1
  fi

  if [[ "$body" != *"$expected"* ]]; then
    echo "FAIL $label: expected response to contain $expected" >&2
    echo "Response: $body" >&2
    return 1
  fi

  echo "OK   $label: $url"
}

check_json_endpoint "amlInsights health" "${AML_INSIGHTS_BASE_URL%/}/health" '"status":"ok"'
check_json_endpoint "amlInsightsDataHub health" "${DATA_HUB_BASE_URL%/}/health" '"ok":true'
check_json_endpoint "amlInsightsDataHub capabilities" "${DATA_HUB_BASE_URL%/}/api/graph/capabilities" '"version"'

echo "Local exposure apps are reachable."
