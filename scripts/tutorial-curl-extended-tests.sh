#!/usr/bin/env bash
set -euo pipefail

# Extended curl smoke tests for the multi-tenant tutorial.
# Covers:
# - Group CRUD + user membership updates (IDB Proxy)
# - SAML IdP create/update/enable/cert-rotate/list/delete (IDB Proxy)
# - DB policy package + /authorize/db (PEP Proxy + OPA)
# - Audit events + replay (PEP Proxy)
#
# Prerequisites:
# - kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80
# - jq installed
# - Tutorial baseline components already deployed
# - Tenant bootstrap already run (default tenant/user: acme/alice)

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
HOST_HEADER="${HOST_HEADER:-www.example.com}"
TENANT_ID="${TENANT_ID:-acme}"
TENANT_USER="${TENANT_USER:-alice}"
GROUP_NAME="${GROUP_NAME:-finance}"
SAML_ALIAS="${SAML_ALIAS:-corp-saml-demo}"
CLEANUP_SAML="${CLEANUP_SAML:-true}"

IDB_BASE="${GATEWAY_URL%/}/proxy/idb"
PEP_BASE="${GATEWAY_URL%/}/proxy/pep"

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required binary: $1" >&2
    exit 1
  }
}

require_bin curl
require_bin jq

log() {
  printf '\n== %s ==\n' "$*"
}

curl_json() {
  local method="$1"
  local url="$2"
  local body="${3:-}"
  local response
  if [[ -n "$body" ]]; then
    response="$(curl -fsS -X "$method" "$url" \
      -H "Host: ${HOST_HEADER}" \
      -H "Content-Type: application/json" \
      --data "$body")"
  else
    response="$(curl -fsS -X "$method" "$url" \
      -H "Host: ${HOST_HEADER}")"
  fi
  if jq -e . >/dev/null 2>&1 <<<"$response"; then
    jq . <<<"$response"
  else
    printf '%s\n' "$response"
  fi
}

curl_raw() {
  local method="$1"
  local url="$2"
  local body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "$url" \
      -H "Host: ${HOST_HEADER}" \
      -H "Content-Type: application/json" \
      --data "$body"
  else
    curl -fsS -X "$method" "$url" \
      -H "Host: ${HOST_HEADER}"
  fi
}

SAML_METADATA_XML="${SAML_METADATA_XML:-<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"urn:demo:idp:${TENANT_ID}\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.com/${TENANT_ID}/sso\"/><SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.com/${TENANT_ID}/slo\"/></IDPSSODescriptor></EntityDescriptor>}"

log "Health checks"
curl_json GET "${IDB_BASE}/healthz"
curl_json GET "${PEP_BASE}/healthz"

log "Create/list group"
group_create_body="$(jq -nc --arg name "$GROUP_NAME" '{name:$name, attributes:{env:["tutorial"], owner:["platform"]}}')"
curl_json POST "${IDB_BASE}/tenants/${TENANT_ID}/groups" "$group_create_body"
groups_json="$(curl_raw GET "${IDB_BASE}/tenants/${TENANT_ID}/groups")"
jq '. | map({id,name,path})' <<<"$groups_json"

log "Add user to group"
user_group_body="$(jq -nc --arg group "$GROUP_NAME" '{mode:"add", group_names:[$group]}')"
curl_json PUT "${IDB_BASE}/tenants/${TENANT_ID}/users/${TENANT_USER}/groups" "$user_group_body"
curl_json GET "${IDB_BASE}/tenants/${TENANT_ID}/users/${TENANT_USER}/groups"

log "Create/update SAML IdP"
saml_create_body="$(jq -nc --arg alias "$SAML_ALIAS" --arg xml "$SAML_METADATA_XML" '{
  alias:$alias,
  display_name:($alias + " display"),
  metadata_xml:$xml,
  enabled:true,
  trust_email:true,
  store_token:false,
  sync_mode:"IMPORT"
}')"
curl_json POST "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps" "$saml_create_body"
curl_json GET "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps"

saml_update_body="$(jq -nc --arg xml "$SAML_METADATA_XML" '{
  display_name:"Updated demo SAML IdP",
  enabled:false,
  metadata_xml:$xml,
  config_updates:{"allowCreate":"true"}
}')"
curl_json PUT "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps/${SAML_ALIAS}" "$saml_update_body"
curl_json PUT "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps/${SAML_ALIAS}/enabled" '{"enabled":true}'

log "SAML cert rotate endpoint (using metadata refresh)"
saml_rotate_body="$(jq -nc --arg xml "$SAML_METADATA_XML" '{metadata_xml:$xml, update_endpoints:false}')"
curl_json POST "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps/${SAML_ALIAS}/certificates/rotate" "$saml_rotate_body"

log "Create SAML IdP mapper (optional mapping config example)"
saml_mapper_body='{
  "name": "email-attribute-importer",
  "identity_provider_mapper": "saml-user-attribute-idp-mapper",
  "config": {
    "attribute.name": "email",
    "attribute.friendly.name": "email",
    "user.attribute": "email"
  }
}'
set +e
mapper_resp="$(curl -sS -X POST "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps/${SAML_ALIAS}/mappers" \
  -H "Host: ${HOST_HEADER}" \
  -H "Content-Type: application/json" \
  --data "$saml_mapper_body")"
mapper_rc=$?
set -e
if [[ $mapper_rc -eq 0 ]]; then
  if jq -e . >/dev/null 2>&1 <<<"$mapper_resp"; then
    jq . <<<"$mapper_resp"
  else
    printf '%s\n' "$mapper_resp"
  fi
else
  echo "Mapper create skipped/failed (Keycloak mapper type can vary by version):"
  printf '%s\n' "$mapper_resp"
fi

log "Upsert DB policy package"
POLICY_VERSION="demo-db-$(date +%s)"
db_policy_pkg="$(jq -nc --arg ver "$POLICY_VERSION" --arg tenant "$TENANT_ID" --arg group "$GROUP_NAME" '{
  version:$ver,
  metadata:{source:"tutorial-curl-extended-tests", tenant:$tenant},
  policies:[
    {
      name:"allow-db-query-by-group",
      effect:"allow",
      resource_kind:"database",
      subjects:["group:" + $group],
      resources:["db1.sales.*"],
      actions:["query"]
    },
    {
      name:"deny-db-admin-by-group",
      effect:"deny",
      resource_kind:"database",
      subjects:["group:" + $group],
      resources:["db1.sales.*"],
      actions:["admin"]
    }
  ]
}')"
curl_json PUT "${PEP_BASE}/tenants/${TENANT_ID}/policies" "$db_policy_pkg"
curl_json GET "${PEP_BASE}/tenants/${TENANT_ID}/policy-package"

log "DB authorize allow/deny checks"
db_allow_req="$(jq -nc --arg tenant "$TENANT_ID" --arg user "$TENANT_USER" --arg group "$GROUP_NAME" '{
  tenant_id:$tenant,
  user:$user,
  roles:["analyst"],
  groups:[$group],
  action:"query",
  resource_kind:"database",
  resource:"db1.sales.orders"
}')"
curl_json POST "${PEP_BASE}/authorize/db" "$db_allow_req"

db_deny_req="$(jq -nc --arg tenant "$TENANT_ID" --arg user "$TENANT_USER" --arg group "$GROUP_NAME" '{
  tenant_id:$tenant,
  user:$user,
  roles:["analyst"],
  groups:[$group],
  action:"admin",
  resource_kind:"database",
  resource:"db1.sales.orders"
}')"
curl_json POST "${PEP_BASE}/authorize/db" "$db_deny_req"

log "Audit replay (PEP policy upsert event)"
audit_events_json="$(curl_raw GET "${PEP_BASE}/audit/events?tenant_id=${TENANT_ID}&action=upsert_tenant_policies&limit=20")"
upsert_event_id="$(jq -r 'if length > 0 then .[-1].id else "" end' <<<"$audit_events_json")"
if [[ -z "$upsert_event_id" || "$upsert_event_id" == "null" ]]; then
  echo "No upsert_tenant_policies audit event found; cannot replay." >&2
  exit 1
fi
echo "Using audit event id: ${upsert_event_id}"

log "Delete policies then replay"
curl_json DELETE "${PEP_BASE}/tenants/${TENANT_ID}/policies"
curl_json GET "${PEP_BASE}/tenants/${TENANT_ID}/policy-package"
curl_json POST "${PEP_BASE}/audit/replay/${upsert_event_id}" '{}'
curl_json GET "${PEP_BASE}/tenants/${TENANT_ID}/policy-package"

if [[ "${CLEANUP_SAML}" == "true" ]]; then
  log "Cleanup demo SAML IdP"
  curl_json DELETE "${IDB_BASE}/tenants/${TENANT_ID}/saml/idps/${SAML_ALIAS}"
fi

log "Done"
echo "Extended tutorial curl tests completed."
