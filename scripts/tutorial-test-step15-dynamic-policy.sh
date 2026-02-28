#!/usr/bin/env bash
set -euo pipefail

# Step 15 dynamic policy tests (PEP Proxy + OPAL realtime sync) with summary.
# Prerequisites:
# - kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80
# - jq installed
# - Mgmt plane policies enabled (Step 14.5)
# - Env vars exported: ACME_CLIENT_ID, ACME_CLIENT_SECRET

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
HOST_HEADER="${HOST_HEADER:-www.example.com}"
TENANT_ID="${TENANT_ID:-acme}"
TENANT_ADMIN_USERNAME="${TENANT_ADMIN_USERNAME:-alice}"
TENANT_ADMIN_PASSWORD="${TENANT_ADMIN_PASSWORD:-password}"
ACME_CLIENT_ID="${ACME_CLIENT_ID:-}"
ACME_CLIENT_SECRET="${ACME_CLIENT_SECRET:-}"
MASTER_CLIENT_ID="${MASTER_CLIENT_ID:-}"
MASTER_CLIENT_SECRET="${MASTER_CLIENT_SECRET:-}"
TOKEN_URL="${TOKEN_URL:-${GATEWAY_URL%/}/realms/${TENANT_ID}/protocol/openid-connect/token}"

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required binary: $1" >&2
    exit 1
  }
}

require_env() {
  local k="$1"
  if [[ -z "${!k:-}" ]]; then
    echo "Missing required env var: $k" >&2
    exit 1
  fi
}

require_bin curl
require_bin jq
require_env ACME_CLIENT_ID
require_env ACME_CLIENT_SECRET

ACCESS_TOKEN_ALICE="$(
  curl -sS -X POST "$TOKEN_URL" \
    -H "Host: ${HOST_HEADER}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${ACME_CLIENT_ID}" \
    -d "client_secret=${ACME_CLIENT_SECRET}" \
    -d "username=${TENANT_ADMIN_USERNAME}" \
    -d "password=${TENANT_ADMIN_PASSWORD}" | jq -r '.access_token'
)"
if [[ -z "$ACCESS_TOKEN_ALICE" || "$ACCESS_TOKEN_ALICE" == "null" ]]; then
  echo "Failed to get tenant-admin token." >&2
  exit 1
fi

# Superadmin token for endpoints without tenant_id in path (healthz, simulate, opal/*)
ACCESS_TOKEN_SUPERADMIN=""
if [[ -n "${MASTER_CLIENT_ID}" && -n "${MASTER_CLIENT_SECRET}" ]]; then
  MASTER_TOKEN_URL="${GATEWAY_URL%/}/realms/master/protocol/openid-connect/token"
  ACCESS_TOKEN_SUPERADMIN="$(
    curl -sS -X POST "$MASTER_TOKEN_URL" \
      -H "Host: ${HOST_HEADER}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=password" \
      -d "client_id=${MASTER_CLIENT_ID}" \
      -d "client_secret=${MASTER_CLIENT_SECRET}" \
      -d "username=superadmin" \
      -d "password=superadmin123" | jq -r '.access_token'
  )"
  if [[ -z "$ACCESS_TOKEN_SUPERADMIN" || "$ACCESS_TOKEN_SUPERADMIN" == "null" ]]; then
    echo "WARNING: Failed to get superadmin token; some tests may fail." >&2
    ACCESS_TOKEN_SUPERADMIN=""
  fi
fi

PASS_COUNT=0
FAIL_COUNT=0
BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

run_http_case() {
  local id="$1"
  local expect="$2"
  local method="$3"
  local path="$4"
  local data="${5:-}"
  local ctype="${6:-application/json}"
  local token="${7:-$ACCESS_TOKEN_ALICE}"
  local status
  if [[ -n "$data" ]]; then
    status="$(curl -sS -o "$BODY_FILE" -w "%{http_code}" -X "$method" "${GATEWAY_URL%/}${path}" \
      -H "Host: ${HOST_HEADER}" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: ${ctype}" \
      --data "$data")"
  else
    status="$(curl -sS -o "$BODY_FILE" -w "%{http_code}" -X "$method" "${GATEWAY_URL%/}${path}" \
      -H "Host: ${HOST_HEADER}" \
      -H "Authorization: Bearer ${token}")"
  fi
  if [[ "$status" == "$expect" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS  %-6s %s %s -> %s\n' "$id" "$method" "$path" "$status"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL  %-6s %s %s -> got %s, expected %s\n' "$id" "$method" "$path" "$status" "$expect"
    sed -n '1,10p' "$BODY_FILE" | sed 's/^/      body: /'
  fi
}

run_json_assert() {
  local id="$1"
  local query="$2"
  local expected="$3"
  local got
  got="$(jq -r "$query" "$BODY_FILE")"
  if [[ "$got" == "$expected" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS  %-6s jq(%s) -> %s\n' "$id" "$query" "$got"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL  %-6s jq(%s) -> got %s, expected %s\n' "$id" "$query" "$got" "$expected"
  fi
}

POLICY_VERSION="step15-$(date +%s)"
POLICY_PACKAGE="$(jq -nc --arg ver "$POLICY_VERSION" --arg tenant "$TENANT_ID" '{
  version:$ver,
  metadata:{source:"tutorial-step15-dynamic-policy.sh", tenant:$tenant},
  policies:[
    {
      name:"order-read-policy",
      effect:"allow",
      resource_kind:"api",
      subjects:["role:analyst","group:users"],
      resources:["/api/v1/tenants/" + $tenant + "/apps/order-service/**"],
      actions:["read"]
    },
    {
      name:"order-write-deny",
      effect:"deny",
      resource_kind:"api",
      subjects:["group:users"],
      resources:["/api/v1/tenants/" + $tenant + "/apps/order-service/**"],
      actions:["create","update","delete","write","post"]
    }
  ]
}')"

SIM_ALLOW='{
  "input": {
    "attributes": {
      "request": { "http": { "method": "GET", "path": "/api/v1/tenants/acme/apps/order-service/orders" } },
      "metadataContext": {
        "filterMetadata": {
          "envoy.filters.http.jwt_authn": {
            "jwt_payload": {
              "preferred_username": "bob",
              "tenant_id": "acme",
              "roles": ["analyst"],
              "groups": ["users"]
            }
          }
        }
      }
    }
  }
}'

SIM_DENY='{
  "input": {
    "attributes": {
      "request": { "http": { "method": "POST", "path": "/api/v1/tenants/acme/apps/order-service/orders" } },
      "metadataContext": {
        "filterMetadata": {
          "envoy.filters.http.jwt_authn": {
            "jwt_payload": {
              "preferred_username": "bob",
              "tenant_id": "acme",
              "roles": ["analyst"],
              "groups": ["users"]
            }
          }
        }
      }
    }
  }
}'

# Paths without tenant_id (/healthz, /simulate, /opal/*) require super_admin token
ADMIN_TOKEN="${ACCESS_TOKEN_SUPERADMIN:-$ACCESS_TOKEN_ALICE}"
echo "Running Step 15 dynamic policy test suite..."
run_http_case "15.1a" "200" "GET" "/proxy/pep/healthz" "" "application/json" "$ADMIN_TOKEN"
run_http_case "15.1b" "200" "PUT" "/proxy/pep/tenants/${TENANT_ID}/policies" "$POLICY_PACKAGE"
run_http_case "15.2a" "200" "GET" "/proxy/pep/tenants/${TENANT_ID}/policy-package"
run_json_assert "15.2b" ".version" "$POLICY_VERSION"
run_json_assert "15.2c" ".policies | length | tostring" "2"
run_http_case "15.3a" "200" "POST" "/proxy/pep/simulate" "$SIM_ALLOW" "application/json" "$ADMIN_TOKEN"
run_json_assert "15.3b" ".result.allowed | tostring" "true"
run_http_case "15.3c" "200" "POST" "/proxy/pep/simulate" "$SIM_DENY" "application/json" "$ADMIN_TOKEN"
run_json_assert "15.3d" ".result.allowed | tostring" "false"
# Wait for OPAL async sync to propagate to PEP Proxy snapshot
sleep 3
run_http_case "15.4a" "200" "GET" "/proxy/pep/opal/snapshots/tenant_policies" "" "application/json" "$ADMIN_TOKEN"
run_json_assert "15.4b" ".\"${TENANT_ID}\".version" "$POLICY_VERSION"

echo
echo "========== Step 15 Summary =========="
echo "PASS: ${PASS_COUNT}"
echo "FAIL: ${FAIL_COUNT}"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
