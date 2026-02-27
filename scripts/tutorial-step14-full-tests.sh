#!/usr/bin/env bash
set -euo pipefail

# Step 14 full test suite (from 14.2 onward) with summary output.
# Prerequisites:
# - kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80
# - jq installed
# - Env vars exported from earlier tutorial steps:
#   MASTER_CLIENT_ID, MASTER_CLIENT_SECRET, ACME_CLIENT_ID, ACME_CLIENT_SECRET

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
KEYCLOAK_URL="${KEYCLOAK_URL:-$GATEWAY_URL}"
HOST_HEADER="${HOST_HEADER:-www.example.com}"
TENANT_ID="${TENANT_ID:-acme}"
TENANT_OTHER_ID="${TENANT_OTHER_ID:-other-corp}"
ALICE_USERNAME="${ALICE_USERNAME:-alice}"
ALICE_PASSWORD="${ALICE_PASSWORD:-password}"
BOB_USERNAME="${BOB_USERNAME:-bob}"
BOB_PASSWORD="${BOB_PASSWORD:-password}"
SUPERADMIN_USERNAME="${SUPERADMIN_USERNAME:-superadmin}"
SUPERADMIN_PASSWORD="${SUPERADMIN_PASSWORD:-superadmin123}"

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
require_env MASTER_CLIENT_ID
require_env MASTER_CLIENT_SECRET
require_env ACME_CLIENT_ID
require_env ACME_CLIENT_SECRET

get_token() {
  local realm="$1"
  local client_id="$2"
  local client_secret="$3"
  local username="$4"
  local password="$5"
  curl -sS -X POST "${KEYCLOAK_URL%/}/realms/${realm}/protocol/openid-connect/token" \
    -H "Host: ${HOST_HEADER}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${client_id}" \
    -d "client_secret=${client_secret}" \
    -d "username=${username}" \
    -d "password=${password}" | jq -r '.access_token'
}

REQUEST_BODY="$(mktemp)"
trap 'rm -f "$REQUEST_BODY"' EXIT

request_status() {
  local method="$1"
  local path="$2"
  local auth="${3:-}"
  local data="${4:-}"
  local content_type="${5:-application/json}"
  local url="${GATEWAY_URL%/}${path}"
  if [[ -n "$data" ]]; then
    if [[ -n "$auth" ]]; then
      curl -sS -o "$REQUEST_BODY" -w "%{http_code}" -X "$method" "$url" \
        -H "Host: ${HOST_HEADER}" \
        -H "Authorization: Bearer ${auth}" \
        -H "Content-Type: ${content_type}" \
        --data "$data"
    else
      curl -sS -o "$REQUEST_BODY" -w "%{http_code}" -X "$method" "$url" \
        -H "Host: ${HOST_HEADER}" \
        -H "Content-Type: ${content_type}" \
        --data "$data"
    fi
  else
    if [[ -n "$auth" ]]; then
      curl -sS -o "$REQUEST_BODY" -w "%{http_code}" -X "$method" "$url" \
        -H "Host: ${HOST_HEADER}" \
        -H "Authorization: Bearer ${auth}"
    else
      curl -sS -o "$REQUEST_BODY" -w "%{http_code}" -X "$method" "$url" \
        -H "Host: ${HOST_HEADER}"
    fi
  fi
}

PASS_COUNT=0
FAIL_COUNT=0

run_case() {
  local id="$1"
  local expect="$2"
  local method="$3"
  local path="$4"
  local auth="${5:-}"
  local data="${6:-}"
  local content_type="${7:-application/json}"
  local got
  got="$(request_status "$method" "$path" "$auth" "$data" "$content_type")"
  if [[ "$got" == "$expect" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS  %-4s %s %s -> %s\n' "$id" "$method" "$path" "$got"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL  %-4s %s %s -> got %s, expected %s\n' "$id" "$method" "$path" "$got" "$expect"
    sed -n '1,8p' "$REQUEST_BODY" | sed 's/^/      body: /'
  fi
}

echo "Acquiring fresh tokens..."
ACCESS_TOKEN_SUPERADMIN="$(get_token "master" "$MASTER_CLIENT_ID" "$MASTER_CLIENT_SECRET" "$SUPERADMIN_USERNAME" "$SUPERADMIN_PASSWORD")"
ACCESS_TOKEN_ALICE="$(get_token "$TENANT_ID" "$ACME_CLIENT_ID" "$ACME_CLIENT_SECRET" "$ALICE_USERNAME" "$ALICE_PASSWORD")"
ACCESS_TOKEN_BOB="$(get_token "$TENANT_ID" "$ACME_CLIENT_ID" "$ACME_CLIENT_SECRET" "$BOB_USERNAME" "$BOB_PASSWORD")"

for t in ACCESS_TOKEN_SUPERADMIN ACCESS_TOKEN_ALICE ACCESS_TOKEN_BOB; do
  if [[ -z "${!t}" || "${!t}" == "null" ]]; then
    echo "Failed to acquire token: $t" >&2
    exit 1
  fi
done

echo "Running Step 14 suite..."
TEST_TENANT_ID="e2e-tenant-$(date +%s)"
ADMIN_CREATE_PAYLOAD="$(jq -nc --arg tid "$TEST_TENANT_ID" '{"display_name":"E2E Tenant","client_id":("client-"+$tid)}')"
TENANT_POLICY_PAYLOAD='{"name":"allow-demo","effect":"allow","subjects":["role:tenant_admin"],"resources":["/api/v1/tenants/acme/apps/order-service/**"],"actions":["read"]}'
APP_POST_PAYLOAD='{"order_id":"o-1001","amount":120}'

run_case "0a" "200" "GET" "/realms/master/.well-known/openid-configuration"
run_case "0b" "200" "POST" "/realms/master/protocol/openid-connect/token" "" \
  "grant_type=password&client_id=${MASTER_CLIENT_ID}&client_secret=${MASTER_CLIENT_SECRET}&username=${SUPERADMIN_USERNAME}&password=${SUPERADMIN_PASSWORD}" \
  "application/x-www-form-urlencoded"
run_case "1"  "401" "POST" "/api/v1/admin/tenants" "" "$ADMIN_CREATE_PAYLOAD"
run_case "2"  "401" "POST" "/api/v1/admin/tenants" "this.is.fake" "$ADMIN_CREATE_PAYLOAD"
run_case "3"  "200" "POST" "/api/v1/admin/tenants" "$ACCESS_TOKEN_SUPERADMIN" "$ADMIN_CREATE_PAYLOAD"
run_case "4"  "403" "POST" "/api/v1/admin/tenants" "$ACCESS_TOKEN_BOB" "$ADMIN_CREATE_PAYLOAD"
run_case "5"  "200" "GET"  "/api/v1/tenants/${TENANT_ID}/roles" "$ACCESS_TOKEN_ALICE"
run_case "6"  "200" "POST" "/api/v1/tenants/${TENANT_ID}/policies" "$ACCESS_TOKEN_ALICE" "$TENANT_POLICY_PAYLOAD"
run_case "7"  "403" "POST" "/api/v1/tenants/${TENANT_ID}/policies" "$ACCESS_TOKEN_BOB" "$TENANT_POLICY_PAYLOAD"
run_case "8"  "403" "GET"  "/api/v1/tenants/${TENANT_OTHER_ID}/roles" "$ACCESS_TOKEN_ALICE"
run_case "9"  "200" "GET"  "/api/v1/tenants/${TENANT_ID}/apps/order-service/orders" "$ACCESS_TOKEN_BOB"
run_case "10" "403" "POST" "/api/v1/tenants/${TENANT_ID}/apps/order-service/orders" "$ACCESS_TOKEN_BOB" "$APP_POST_PAYLOAD"

echo
echo "========== Step 14 Summary =========="
echo "PASS: ${PASS_COUNT}"
echo "FAIL: ${FAIL_COUNT}"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
