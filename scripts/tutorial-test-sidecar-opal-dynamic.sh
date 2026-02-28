#!/usr/bin/env bash
set -euo pipefail

# Validate sidecar OPA dynamic rego update without restarting gateway.
# Linux replacement for tutorial-test-sidecar-opal-dynamic.ps1.

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required binary: $1" >&2
    exit 1
  }
}

require_bin kubectl
require_bin curl
require_bin jq
require_bin envsubst

BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
OPA_URL="${OPA_URL:-http://127.0.0.1:18182}"
HOST_HEADER="${HOST_HEADER:-www.example.com}"

AGW_NS="${AGW_NS:-agentgateway-system}"

pf_gateway_pid=""
pf_opa_pid=""

cleanup() {
  if [[ -n "$pf_gateway_pid" ]]; then
    kill "$pf_gateway_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$pf_opa_pid" ]]; then
    kill "$pf_opa_pid" >/dev/null 2>&1 || true
  fi
  rm -f "${TMP_MGMT_POLICY_FILE:-}"
}
trap cleanup EXIT

kubectl -n "$AGW_NS" port-forward service/agentgateway-proxy 18080:80 >/tmp/agw-pf.log 2>&1 &
pf_gateway_pid=$!
kubectl -n "$AGW_NS" port-forward service/agentgateway-opa-sidecar 18182:8181 >/tmp/opa-pf.log 2>&1 &
pf_opa_pid=$!
sleep 4

echo "Cleaning previous dynamic policy module if exists..."
curl -sS -o /dev/null -w "%{http_code}" -X DELETE "${OPA_URL}/v1/policies/dynamic-test" | grep -Eq "^(200|404)$"

echo "Temporarily disabling mgmt policies for bootstrap window..."
kubectl -n "$AGW_NS" delete agentgatewaypolicy mgmt-jwt-auth-policy mgmt-opa-ext-auth-policy --ignore-not-found=true >/dev/null
sleep 2

echo "Bootstrapping master realm and acme tenant..."
MASTER_BODY='{"client_id":"master-gateway-client","super_admin_username":"superadmin","super_admin_password":"superadmin123","super_admin_email":"superadmin@gateway.local"}'
MASTER_RESP="$(curl -sS -X POST "${BASE_URL}/proxy/idb/bootstrap/master" \
  -H "Host: ${HOST_HEADER}" -H "Content-Type: application/json" \
  --data "$MASTER_BODY")"
MASTER_CLIENT_SECRET="$(jq -r '.client_secret // empty' <<<"$MASTER_RESP")"
if [[ -z "$MASTER_CLIENT_SECRET" ]]; then
  echo "bootstrap master failed: $MASTER_RESP" >&2
  exit 1
fi

TENANT_BODY='{"display_name":"Acme Corp","client_id":"acme-frontend","tenant_admin":{"username":"alice","password":"password","email":"alice@acme.local","groups":["admin"],"roles":["tenant_admin"]},"users":[]}'
TENANT_RESP="$(curl -sS -X POST "${BASE_URL}/proxy/idb/tenants/acme/bootstrap" \
  -H "Host: ${HOST_HEADER}" -H "Content-Type: application/json" \
  --data "$TENANT_BODY")"
ACME_CLIENT_SECRET="$(jq -r '.client_secret // empty' <<<"$TENANT_RESP")"
if [[ -z "$ACME_CLIENT_SECRET" ]]; then
  echo "bootstrap tenant failed: $TENANT_RESP" >&2
  exit 1
fi

echo "Re-enabling mgmt JWT + OPA policies..."
export MASTER_ISSUER="http://www.example.com/realms/master"
export MASTER_JWKS_PATH="/realms/master/protocol/openid-connect/certs"
export ACME_ISSUER="http://www.example.com/realms/acme"
export ACME_JWKS_PATH="/realms/acme/protocol/openid-connect/certs"
TMP_MGMT_POLICY_FILE="$(mktemp)"
if [[ -n "${MSYSTEM:-}" ]]; then
  MSYS_NO_PATHCONV=1 envsubst < manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml > "$TMP_MGMT_POLICY_FILE"
else
  envsubst < manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml > "$TMP_MGMT_POLICY_FILE"
fi
kubectl apply -f "$TMP_MGMT_POLICY_FILE" >/dev/null
kubectl apply -f manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml >/dev/null
sleep 2

echo "Getting alice token..."
TOKEN_RESP="$(curl -sS -X POST "${BASE_URL}/realms/acme/protocol/openid-connect/token" \
  -H "Host: ${HOST_HEADER}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=acme-frontend" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=alice" \
  -d "password=password")"
ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$TOKEN_RESP")"
if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "get token failed: $TOKEN_RESP" >&2
  exit 1
fi

call_business() {
  local status
  status="$(curl -sS -o /tmp/business_resp.json -w "%{http_code}" \
    "${BASE_URL}/api/v1/tenants/acme/apps/myapp" \
    -H "Host: ${HOST_HEADER}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")"
  echo "$status"
}

before="$(call_business)"
if [[ "$before" != "200" ]]; then
  echo "baseline business request failed: expected 200, got $before" >&2
  exit 1
fi

echo "Pushing dynamic deny rego module..."
DYNAMIC_MODULE='package envoy.authz

import future.keywords.if

_has_dynamic_policy_rules if {
  true
}

_envoy_dynamic_deny if {
  _is_app_path
}'
put_code="$(curl -sS -o /tmp/opa_put.txt -w "%{http_code}" -X PUT \
  "${OPA_URL}/v1/policies/dynamic-test" \
  -H "Content-Type: text/plain" \
  --data "$DYNAMIC_MODULE")"
if [[ "$put_code" != "200" ]]; then
  echo "OPA policy push failed: $(cat /tmp/opa_put.txt)" >&2
  exit 1
fi
sleep 3

during="$(call_business)"
if [[ "$during" != "403" ]]; then
  echo "dynamic update not effective: expected 403, got $during" >&2
  exit 1
fi

echo "Removing dynamic deny rego module..."
del_code="$(curl -sS -o /tmp/opa_del.txt -w "%{http_code}" -X DELETE "${OPA_URL}/v1/policies/dynamic-test")"
if [[ "$del_code" != "200" ]]; then
  echo "OPA policy delete failed: $(cat /tmp/opa_del.txt)" >&2
  exit 1
fi
sleep 3

after="$(call_business)"
if [[ "$after" != "200" ]]; then
  echo "policy restore not effective: expected 200, got $after" >&2
  exit 1
fi

echo "PASS sidecar+dynamic-rego: baseline=${before}, updated=${during}, restored=${after}"
