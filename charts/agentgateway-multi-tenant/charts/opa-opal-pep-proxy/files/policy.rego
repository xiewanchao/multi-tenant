package envoy.authz

import future.keywords.if
import future.keywords.in
import input.attributes.request.http as http_request

default allow := false

allow if {
    _allow_core
}

decision := {
    "allowed": true,
    "request_headers_to_remove": _spoofable_request_headers,
} if {
    _is_health_request
}

decision := {
    "allowed": true,
    "headers": _trusted_upstream_headers,
    "request_headers_to_remove": _spoofable_request_headers,
} if {
    _allow_core
    not _is_health_request
}

decision := {
    "allowed": false,
    "http_status": _deny_status,
    "request_headers_to_remove": _spoofable_request_headers,
} if {
    not _allow_core
}

app_decision := {
    "allow": _app_allow,
    "deny": _app_deny,
    "tenant_id": _app_tenant_id,
    "policy_version": _app_policy_version,
    "matched_policy_names": sort([name | _app_matched_policy_name[name]]),
    "denied_by_policy_names": sort([name | _app_denied_policy_name[name]]),
} if {
    true
}

_spoofable_request_headers := [
    "x-tenant-id",
    "x-user",
    "x-roles",
    "x-groups",
    "x-client-id",
    "x-authz-policy-version",
]

_deny_status := 401 if {
    not _jwt_payload
}

_deny_status := 403 if {
    _jwt_payload
}

_trusted_upstream_headers := {
    "x-tenant-id": _token_tenant_id,
    "x-user": _username,
    "x-roles": _roles_csv,
    "x-groups": _groups_csv,
    "x-client-id": _client_id,
    "x-authz-policy-version": _tenant_policy_version,
}

# ============================================
# Envoy JWT metadata extraction
# ============================================

_jwt_payload := payload if {
    payload := input.attributes.metadataContext.filterMetadata["envoy.filters.http.jwt_authn"].jwt_payload
}

_token_tenant_id := object.get(_jwt_payload, "tenant_id", "")
_username := object.get(_jwt_payload, "preferred_username", object.get(_jwt_payload, "sub", ""))
_client_id := object.get(_jwt_payload, "azp", object.get(_jwt_payload, "client_id", ""))

_roles[role] {
    some role in _jwt_payload.roles
}

_roles[role] {
    not _jwt_payload.roles
    some role in _jwt_payload.realm_access.roles
}

_roles_csv := concat(",", sort([role | _roles[role]]))

_groups[group] {
    some raw in _jwt_payload.groups
    group := _normalize_group_name(raw)
    group != ""
}

_groups[group] {
    not _jwt_payload.groups
    raw := object.get(_jwt_payload, "group", "")
    raw != ""
    group := _normalize_group_name(raw)
    group != ""
}

_groups_csv := concat(",", sort([group | _groups[group]]))

_normalize_group_name(raw) = out if {
    startswith(raw, "/")
    parts := split(raw, "/")
    out := parts[count(parts)-1]
}

_normalize_group_name(raw) = raw if {
    not startswith(raw, "/")
}

# ============================================
# Path parsing
# ============================================

_path_parts := split(http_request.path, "/")

_path_tenant_id := _path_parts[4] if {
    count(_path_parts) > 4
    _path_parts[1] == "api"
    _path_parts[2] == "v1"
    _path_parts[3] == "tenants"
}

_path_resource_type := _path_parts[5] if {
    count(_path_parts) > 5
}

_tenant_match if {
    _token_tenant_id == _path_tenant_id
}

_is_app_path if {
    _path_resource_type == "apps"
}

_admin_resource_types := {"saml", "roles", "groups", "users", "policies"}

# ============================================
# Tenant policy package helpers (backward compatible)
# ============================================

_tenant_policy_raw := data.tenant_policies[_token_tenant_id]

_tenant_policy_version := object.get(_tenant_policy_raw, "version", "legacy-list") if {
    is_object(_tenant_policy_raw)
}

_tenant_policy_version := "legacy-list" if {
    is_array(_tenant_policy_raw)
}

_tenant_policy_version := "static-fallback" if {
    not _tenant_policy_raw
}

_tenant_policy_rules := object.get(_tenant_policy_raw, "policies", []) if {
    is_object(_tenant_policy_raw)
}

_tenant_policy_rules := _tenant_policy_raw if {
    is_array(_tenant_policy_raw)
}

_tenant_policy_rules := [] if {
    not _tenant_policy_raw
}

_has_dynamic_policy_rules if {
    count(_tenant_policy_rules) > 0
}

# ============================================
# Envoy ext_authz decisions
# ============================================

_allow_core if {
    _is_health_request
}

_is_health_request if {
    http_request.path == "/health"
    http_request.method == "GET"
}

_allow_core if {
    http_request.method == "POST"
    http_request.path == "/api/v1/admin/tenants"
    _token_tenant_id == "master"
    "super_admin" in _roles
}

_allow_core if {
    http_request.method == "GET"
    http_request.path == "/api/v1/admin/tenants"
    _token_tenant_id == "master"
    "super_admin" in _roles
}

_allow_core if {
    _tenant_match
    "tenant_admin" in _roles
    _path_resource_type in _admin_resource_types
}

_allow_core if {
    _is_app_path
    _tenant_match
    not _envoy_dynamic_deny
    _envoy_dynamic_allow
}

_allow_core if {
    _is_app_path
    _tenant_match
    not _has_dynamic_policy_rules
    some group in _groups
    some permission in _static_group_permissions[group]
    permission.method == http_request.method
    glob.match(permission.path_pattern, ["/"], http_request.path)
}

_envoy_dynamic_allow if {
    policy := _tenant_policy_rules[_]
    lower(object.get(policy, "resource_kind", "api")) == "api"
    lower(object.get(policy, "effect", "allow")) == "allow"
    _subject_match(object.get(policy, "subjects", []))
    _resource_match_api(object.get(policy, "resources", []))
    _action_match_http(object.get(policy, "actions", []))
}

_envoy_dynamic_deny if {
    policy := _tenant_policy_rules[_]
    lower(object.get(policy, "resource_kind", "api")) == "api"
    lower(object.get(policy, "effect", "")) == "deny"
    _subject_match(object.get(policy, "subjects", []))
    _resource_match_api(object.get(policy, "resources", []))
    _action_match_http(object.get(policy, "actions", []))
}

_subject_match(subjects) if {
    some subject in subjects
    startswith(subject, "role:")
    role := substring(subject, 5, -1)
    role in _roles
}

_subject_match(subjects) if {
    some subject in subjects
    startswith(subject, "group:")
    group := substring(subject, 6, -1)
    group in _groups
}

_subject_match(subjects) if {
    some subject in subjects
    startswith(subject, "user:")
    user := substring(subject, 5, -1)
    user == _username
}

_resource_match_api(resources) if {
    some resource in resources
    glob.match(resource, ["/"], http_request.path)
}

_action_match_http(actions) if {
    method_action_map := {
        "GET": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }
    action := method_action_map[http_request.method]
    action in actions
}

_action_match_http(actions) if {
    lower(http_request.method) in actions
}

_static_group_permissions := {
    "admin": [
        {"method": "GET", "path_pattern": "/api/v1/tenants/*/apps/**"},
        {"method": "POST", "path_pattern": "/api/v1/tenants/*/apps/**"},
    ],
    "users": [
        {"method": "GET", "path_pattern": "/api/v1/tenants/*/apps/**"},
    ],
}

# ============================================
# Non-gateway PEP decision (e.g., DB/data layer)
# input shape:
# {
#   "tenant_id": "acme",
#   "subject": {"user": "...", "roles": [...], "groups": [...]},
#   "request": {"resource_kind": "database", "resource": "db.schema.table", "action": "query"}
# }
# ============================================

_app_tenant_id := object.get(input, "tenant_id", "")
_app_subject := object.get(input, "subject", {})
_app_request := object.get(input, "request", {})

_app_policy_raw := data.tenant_policies[_app_tenant_id]

_app_policy_version := object.get(_app_policy_raw, "version", "legacy-list") if {
    is_object(_app_policy_raw)
}

_app_policy_version := "legacy-list" if {
    is_array(_app_policy_raw)
}

_app_policy_version := "not-found" if {
    not _app_policy_raw
}

_app_policy_rules := object.get(_app_policy_raw, "policies", []) if {
    is_object(_app_policy_raw)
}

_app_policy_rules := _app_policy_raw if {
    is_array(_app_policy_raw)
}

_app_policy_rules := [] if {
    not _app_policy_raw
}

_app_request_kind := lower(object.get(_app_request, "resource_kind", "api"))
_app_request_action := lower(object.get(_app_request, "action", ""))
_app_request_resource := object.get(_app_request, "resource", "")

_app_allow if {
    not _app_deny
    some _ in _app_policy_rules
    _app_matched_policy_name[_]
}

_app_deny if {
    some _ in _app_policy_rules
    _app_denied_policy_name[_]
}

_app_matched_policy_name[name] {
    policy := _app_policy_rules[_]
    lower(object.get(policy, "effect", "allow")) == "allow"
    lower(object.get(policy, "resource_kind", "api")) == _app_request_kind
    _app_subject_match(object.get(policy, "subjects", []))
    _app_action_match(object.get(policy, "actions", []))
    _app_resource_match(lower(object.get(policy, "resource_kind", "api")), object.get(policy, "resources", []))
    name := object.get(policy, "name", "")
    name != ""
}

_app_denied_policy_name[name] {
    policy := _app_policy_rules[_]
    lower(object.get(policy, "effect", "")) == "deny"
    lower(object.get(policy, "resource_kind", "api")) == _app_request_kind
    _app_subject_match(object.get(policy, "subjects", []))
    _app_action_match(object.get(policy, "actions", []))
    _app_resource_match(lower(object.get(policy, "resource_kind", "api")), object.get(policy, "resources", []))
    name := object.get(policy, "name", "")
    name != ""
}

_app_subject_match(subjects) if {
    some subject in subjects
    startswith(subject, "role:")
    role := substring(subject, 5, -1)
    role in object.get(_app_subject, "roles", [])
}

_app_subject_match(subjects) if {
    some subject in subjects
    startswith(subject, "group:")
    group := substring(subject, 6, -1)
    group in [g | raw := object.get(_app_subject, "groups", [])[_]; g := _normalize_group_name(raw)]
}

_app_subject_match(subjects) if {
    some subject in subjects
    startswith(subject, "user:")
    user := substring(subject, 5, -1)
    user == object.get(_app_subject, "user", "")
}

_app_action_match(actions) if {
    _app_request_action in [lower(a) | a := actions[_]]
}

_app_action_match(actions) if {
    _app_request_action == "query"
    "read" in [lower(a) | a := actions[_]]
}

_app_action_match(actions) if {
    _app_request_action == "write"
    some alias in {"create", "update", "delete", "write"}
    alias in [lower(a) | a := actions[_]]
}

_app_resource_match("api", resources) if {
    some pattern in resources
    glob.match(pattern, ["/"], _app_request_resource)
}

_app_resource_match("database", resources) if {
    some pattern in resources
    glob.match(pattern, ["."], _app_request_resource)
}
